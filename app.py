import json
import os
import secrets
from datetime import timedelta
from functools import wraps
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request as URLRequest, urlopen

import boto3
import firebase_admin
from botocore.config import Config
from dotenv import load_dotenv
from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from firebase_admin import credentials, firestore
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from werkzeug.exceptions import HTTPException

load_dotenv()

base_dir = os.path.dirname(os.path.abspath(__file__))
template_dir = os.path.join(base_dir, 'templates')
static_dir = os.path.join(base_dir, 'static')

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv(
        'SESSION_COOKIE_SECURE', 'true' if os.getenv('VERCEL') else 'false'
    ).lower()
    in {'1', 'true', 'yes'},
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    MAX_CONTENT_LENGTH=4 * 1024 * 1024 + 64 * 1024,
)

db = None
try:
    if not firebase_admin._apps:
        firebase_env = os.getenv('FIREBASE_CREDENTIALS')
        if firebase_env:
            cred = credentials.Certificate(json.loads(firebase_env))
        else:
            cred = credentials.Certificate(os.path.join(base_dir, 'firebase-key.json'))
        firebase_admin.initialize_app(cred)

    db = firestore.client()
    app.logger.info('Firebase initialized')
except Exception as error:
    app.logger.error('Firebase initialization failed (%s)', type(error).__name__)

R2_ACCOUNT_ID = os.getenv('R2_ACCOUNT_ID')
R2_ACCESS_KEY = os.getenv('R2_ACCESS_KEY')
R2_SECRET_KEY = os.getenv('R2_SECRET_KEY')
R2_BUCKET_NAME = os.getenv('R2_BUCKET_NAME')
R2_PUBLIC_URL = os.getenv('R2_PUBLIC_URL', '').rstrip('/')

if all((R2_ACCOUNT_ID, R2_ACCESS_KEY, R2_SECRET_KEY, R2_BUCKET_NAME, R2_PUBLIC_URL)):
    s3_client = boto3.client(
        's3',
        endpoint_url=f'https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com',
        aws_access_key_id=R2_ACCESS_KEY,
        aws_secret_access_key=R2_SECRET_KEY,
        config=Config(signature_version='s3v4'),
        region_name='auto',
    )
else:
    s3_client = None
    app.logger.warning('R2 storage is not configured')

DATA_COLLECTIONS = {
    'listings',
    'requests',
    'global_chat',
    'chat_meta',
    'lost_found',
    'pyq_vault',
    'project_mates',
}


def current_user():
    return session.get('user')


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return jsonify({'error': 'Authentication required'}), 401
        return view(*args, **kwargs)

    return wrapped


def csrf_error_response():
    expected = session.get('csrf_token', '')
    supplied = request.headers.get('X-CSRF-Token', '')
    if not expected or not secrets.compare_digest(expected, supplied):
        return jsonify({'error': 'Invalid request token'}), 403
    return None


def csrf_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        error = csrf_error_response()
        return error if error else view(*args, **kwargs)

    return wrapped


@app.errorhandler(HTTPException)
def handle_http_error(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': error.description}), error.code
    return error


def require_database():
    if db is None:
        return jsonify({'error': 'Database service is unavailable'}), 503
    return None


def json_safe(value):
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if hasattr(value, 'isoformat'):
        return value.isoformat()
    return value


def collection_ref(name):
    if name not in DATA_COLLECTIONS:
        abort(404)
    return db.collection(name)


def require_object_body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        abort(400, description='A JSON object is required')
    return data


def required_text(data, field, max_length=500):
    value = data.get(field)
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        abort(400, description=f'Invalid {field}')
    return value.strip()


def create_document(name, payload, user):
    timestamp = firestore.SERVER_TIMESTAMP

    if name == 'listings':
        price = payload.get('price')
        if isinstance(price, bool) or not isinstance(price, (int, float)) or price < 0:
            abort(400, description='Invalid price')
        data = {
            'title': required_text(payload, 'title', 120),
            'price': price,
            'category': required_text(payload, 'category', 80),
            'whatsapp': required_text(payload, 'whatsapp', 30),
            'imageUrl': required_text(payload, 'imageUrl', 2048),
            'sellerName': user['displayName'],
            'sellerEmail': user['email'],
            'sellerPhoto': user.get('photoURL', ''),
            'createdAt': timestamp,
            'status': 'available',
        }
    elif name == 'requests':
        data = {
            'title': required_text(payload, 'title', 200),
            'whatsapp': required_text(payload, 'whatsapp', 30),
            'requesterName': user['displayName'],
            'requesterEmail': user['email'],
            'requesterPhoto': user.get('photoURL', ''),
            'createdAt': timestamp,
        }
    elif name == 'global_chat':
        data = {
            'text': required_text(payload, 'text', 2000),
            'name': user['displayName'],
            'email': user['email'],
            'createdAt': timestamp,
            'isEdited': False,
        }
    elif name == 'lost_found':
        item_type = required_text(payload, 'type', 20)
        if item_type not in {'Lost', 'Found'}:
            abort(400, description='Invalid type')
        data = {
            'title': required_text(payload, 'title', 200),
            'type': item_type,
            'whatsapp': required_text(payload, 'whatsapp', 30),
            'name': user['displayName'],
            'createdAt': timestamp,
        }
    elif name == 'pyq_vault':
        data = {
            'title': required_text(payload, 'title', 200),
            'sem': required_text(payload, 'sem', 40),
            'link': required_text(payload, 'link', 2048),
            'name': user['displayName'],
            'createdAt': timestamp,
        }
    elif name == 'project_mates':
        data = {
            'title': required_text(payload, 'title', 200),
            'skills': required_text(payload, 'skills', 500),
            'whatsapp': required_text(payload, 'whatsapp', 30),
            'name': user['displayName'],
            'createdAt': timestamp,
        }
    else:
        abort(403)

    return data


def get_owned_document(name, doc_id, owner_field, user):
    snapshot = collection_ref(name).document(doc_id).get()
    if not snapshot.exists:
        abort(404)
    if snapshot.to_dict().get(owner_field) != user['email']:
        abort(403)
    return snapshot.reference


@app.route('/')
def index():
    return render_template('index.html', login_error=request.args.get('error'))


@app.route('/auth/google')
def google_login():
    client_id = os.getenv('GOOGLE_CLIENT_ID')
    client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
    redirect_uri = os.getenv('GOOGLE_REDIRECT_URI')
    if not client_id or not client_secret or not redirect_uri or not app.secret_key:
        return 'Google sign-in is not configured on the server.', 503

    state = secrets.token_urlsafe(32)
    session.clear()
    session['oauth_state'] = state
    params = urlencode(
        {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'openid email profile',
            'state': state,
            'prompt': 'select_account',
        }
    )
    return redirect(f'https://accounts.google.com/o/oauth2/v2/auth?{params}')


@app.route('/auth/google/callback')
def google_callback():
    expected_state = session.pop('oauth_state', '')
    supplied_state = request.args.get('state', '')
    if not expected_state or not secrets.compare_digest(expected_state, supplied_state):
        return redirect(url_for('index', error='oauth'))
    if request.args.get('error') or not request.args.get('code'):
        return redirect(url_for('index', error='oauth'))

    client_id = os.getenv('GOOGLE_CLIENT_ID')
    client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
    redirect_uri = os.getenv('GOOGLE_REDIRECT_URI')
    if not client_id or not client_secret or not redirect_uri or not app.secret_key:
        return 'Google sign-in is not configured on the server.', 503

    token_request = URLRequest(
        'https://oauth2.googleapis.com/token',
        data=urlencode(
            {
                'code': request.args['code'],
                'client_id': client_id,
                'client_secret': client_secret,
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code',
            }
        ).encode(),
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        method='POST',
    )

    try:
        with urlopen(token_request, timeout=10) as response:
            token_data = json.loads(response.read())
        claims = id_token.verify_oauth2_token(
            token_data['id_token'], GoogleRequest(), client_id
        )
    except (HTTPError, URLError, TimeoutError, ValueError, KeyError, GoogleAuthError):
        app.logger.warning('Google sign-in verification failed')
        return redirect(url_for('index', error='oauth'))

    email = claims.get('email')
    if not email or not claims.get('email_verified'):
        return redirect(url_for('index', error='oauth'))

    session.clear()
    session['user'] = {
        'id': claims['sub'],
        'email': email,
        'displayName': claims.get('name') or email,
        'photoURL': claims.get('picture', ''),
    }
    session['csrf_token'] = secrets.token_urlsafe(32)
    session.permanent = True
    return redirect(url_for('dashboard'))


@app.route('/api/auth/me')
@login_required
def auth_me():
    return jsonify({'user': current_user(), 'csrfToken': session['csrf_token']})


@app.route('/api/auth/logout', methods=['POST'])
@login_required
@csrf_required
def auth_logout():
    session.clear()
    return '', 204


@app.route('/dashboard')
def dashboard():
    if not current_user():
        return redirect(url_for('index'))
    return render_template('dashboard.html')


@app.route('/api/data/<name>', methods=['GET', 'POST'])
@login_required
def collection_api(name):
    unavailable = require_database()
    if unavailable:
        return unavailable
    ref = collection_ref(name)

    if request.method == 'GET':
        filters = request.args.get('filters', '[]')
        try:
            filters = json.loads(filters)
        except ValueError:
            abort(400, description='Invalid filters')
        if (
            not isinstance(filters, list)
            or len(filters) > 1
            or any(not isinstance(item, dict) for item in filters)
        ):
            abort(400, description='Invalid filters')

        query_ref = ref
        if filters:
            filter_data = filters[0]
            user = current_user()
            if (
                name == 'listings'
                and filter_data.get('field') == 'sellerEmail'
                and filter_data.get('op') == '=='
            ):
                query_ref = query_ref.where('sellerEmail', '==', user['email'])
            elif (
                name == 'listings'
                and filter_data.get('field') == 'savedBy'
                and filter_data.get('op') == 'array-contains'
            ):
                query_ref = query_ref.where('savedBy', 'array_contains', user['email'])
            else:
                abort(400, description='Unsupported filter')

        order_field = request.args.get('order')
        if order_field:
            if order_field != 'createdAt':
                abort(400, description='Unsupported ordering')
            direction = request.args.get('direction', 'asc')
            if direction not in {'asc', 'desc'}:
                abort(400, description='Unsupported ordering')
            query_ref = query_ref.order_by(
                order_field,
                direction=firestore.Query.DESCENDING
                if direction == 'desc'
                else firestore.Query.ASCENDING,
            )

        documents = [
            {'id': snapshot.id, **json_safe(snapshot.to_dict())}
            for snapshot in query_ref.stream()
        ]
        return jsonify({'documents': documents})

    if request.method == 'POST':
        csrf_error = csrf_error_response()
        if csrf_error:
            return csrf_error
        payload = require_object_body()
        document = create_document(name, payload, current_user())
        result = ref.add(document)
        return jsonify({'id': result[1].id}), 201


@app.route('/api/data/<name>/<doc_id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
@login_required
def document_api(name, doc_id):
    unavailable = require_database()
    if unavailable:
        return unavailable
    ref = collection_ref(name).document(doc_id)
    user = current_user()

    if request.method == 'GET':
        snapshot = ref.get()
        if not snapshot.exists:
            if name == 'chat_meta' and doc_id == 'typing':
                return jsonify({'id': doc_id, 'exists': False})
            abort(404)
        return jsonify(
            {'id': snapshot.id, 'exists': True, **json_safe(snapshot.to_dict())}
        )

    csrf_error = csrf_error_response()
    if csrf_error:
        return csrf_error

    if request.method == 'DELETE':
        owner_field = {
            'listings': 'sellerEmail',
            'requests': 'requesterEmail',
            'global_chat': 'email',
        }.get(name)
        if not owner_field:
            abort(403)
        owned_ref = get_owned_document(name, doc_id, owner_field, user)
        owned_ref.delete()
        return '', 204

    payload = require_object_body()
    if name == 'chat_meta' and doc_id == 'typing':
        data = {
            'name': user['displayName'] if payload.get('time', 0) else '',
            'email': user['email'] if payload.get('time', 0) else '',
            'time': payload.get('time', 0),
        }
        if isinstance(data['time'], bool) or not isinstance(data['time'], (int, float)):
            abort(400, description='Invalid typing status')
        ref.set(data)
        return jsonify({'ok': True})

    if name == 'listings':
        allowed = {'title', 'price', 'category', 'whatsapp', 'imageUrl', 'status', 'savedBy'}
        if set(payload) - allowed:
            abort(400, description='Unsupported listing field')
        if set(payload) == {'savedBy'}:
            if not ref.get().exists:
                abort(404)
            owned_ref = ref
        else:
            owned_ref = get_owned_document(name, doc_id, 'sellerEmail', user)
        updates = {}
        for field in {'title', 'category', 'whatsapp', 'imageUrl'} & payload.keys():
            updates[field] = required_text(payload, field, 2048 if field == 'imageUrl' else 500)
        if 'price' in payload:
            price = payload['price']
            if isinstance(price, bool) or not isinstance(price, (int, float)) or price < 0:
                abort(400, description='Invalid price')
            updates['price'] = price
        if 'status' in payload:
            if payload['status'] not in {'available', 'sold'}:
                abort(400, description='Invalid status')
            updates['status'] = payload['status']
        if 'savedBy' in payload:
            operation = payload['savedBy']
            if not isinstance(operation, dict) or operation.get('__op') not in {
                'arrayUnion',
                'arrayRemove',
            }:
                abort(400, description='Invalid wishlist update')
            transform = (
                firestore.ArrayUnion([user['email']])
                if operation['__op'] == 'arrayUnion'
                else firestore.ArrayRemove([user['email']])
            )
            owned_ref.update({'savedBy': transform})
        if updates:
            owned_ref.update(updates)
    elif name == 'global_chat':
        owned_ref = get_owned_document(name, doc_id, 'email', user)
        if set(payload) - {'text', 'isEdited'}:
            abort(400, description='Unsupported message field')
        updates = {'text': required_text(payload, 'text', 2000)}
        updates['isEdited'] = True
        owned_ref.update(updates)
    else:
        abort(403)

    return jsonify({'ok': True})


@app.route('/api/upload', methods=['POST'])
@login_required
@csrf_required
def upload_image():
    if not s3_client:
        return jsonify({'error': 'Server storage configuration missing'}), 500

    uploaded_file = request.files.get('file')
    if not uploaded_file or not uploaded_file.filename:
        abort(400, description='Invalid upload')

    extension_by_type = {
        'image/jpeg': '.jpg',
        'image/png': '.png',
        'image/webp': '.webp',
        'image/gif': '.gif',
    }
    file_type = uploaded_file.mimetype
    extension = extension_by_type.get(file_type)
    if not extension:
        abort(400, description='Unsupported image type')

    filename = f'listings/{secrets.token_hex(16)}{extension}'
    try:
        s3_client.upload_fileobj(
            uploaded_file.stream,
            R2_BUCKET_NAME,
            filename,
            ExtraArgs={'ContentType': file_type},
        )
    except Exception as error:
        app.logger.error('Image upload failed (%s)', type(error).__name__)
        return jsonify({'error': 'Unable to upload image'}), 500

    return jsonify({'publicUrl': f'{R2_PUBLIC_URL}/{filename}'})


if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', '').lower() == 'true', port=5000)

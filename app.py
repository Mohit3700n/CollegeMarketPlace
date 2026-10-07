import os
import json
from flask import Flask, render_template, request, jsonify
import firebase_admin
from firebase_admin import credentials, firestore
from dotenv import load_dotenv
import boto3
from botocore.config import Config

load_dotenv()

app = Flask(__name__)

# --- FIREBASE SETUP ---
try:
    # Vercel Cache Issue Fix: Check if app already initialized
    if not firebase_admin._apps:
        # Security Fix: Use Environment Variable on Vercel, fallback to local JSON
        firebase_env = os.getenv('FIREBASE_CREDENTIALS')
        if firebase_env:
            cred_dict = json.loads(firebase_env)
            cred = credentials.Certificate(cred_dict)
        else:
            # Local development ke liye absolute path use karo
            base_dir = os.path.dirname(os.path.abspath(__file__))
            cred = credentials.Certificate(os.path.join(base_dir, 'firebase-key.json'))
            
        firebase_admin.initialize_app(cred)
    
    db = firestore.client()
    print("✅ Firebase Initialized")
except Exception as e:
    print(f"❌ Firebase Error: {e}")

# --- CLOUDFLARE R2 SETUP ---
# Security Fix: Removed hardcoded original keys
R2_ACCOUNT_ID = os.getenv('R2_ACCOUNT_ID')
R2_ACCESS_KEY = os.getenv('R2_ACCESS_KEY')
R2_SECRET_KEY = os.getenv('R2_SECRET_KEY')
R2_BUCKET_NAME = 'expresso'
R2_PUBLIC_URL = 'https://pub-01a3f73690894fc39cec4138ac040a14.r2.dev' 

# Initialize S3 Client only if keys are present (prevents crash on build step)
if R2_ACCOUNT_ID and R2_ACCESS_KEY and R2_SECRET_KEY:
    s3_client = boto3.client(
        's3',
        endpoint_url=f'https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com',
        aws_access_key_id=R2_ACCESS_KEY,
        aws_secret_access_key=R2_SECRET_KEY,
        config=Config(signature_version='s3v4'),
        region_name='auto'
    )
else:
    s3_client = None
    print("⚠️ R2 Credentials missing in environment.")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# --- PRESIGNED URL GENERATOR ---
@app.route('/api/get-upload-url', methods=['POST'])
def get_upload_url():
    if not s3_client:
        return jsonify({'error': 'Server storage configuration missing'}), 500

    try:
        data = request.json
        filename = data.get('filename')
        file_type = data.get('contentType')

        presigned_url = s3_client.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': R2_BUCKET_NAME,
                'Key': filename,
                'ContentType': file_type
            },
            ExpiresIn=3600
        )
        
        public_url = f"{R2_PUBLIC_URL}/{filename}"
        
        return jsonify({
            'uploadUrl': presigned_url,
            'publicUrl': public_url
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
import os
from flask import Flask, request, jsonify, session, redirect, send_from_directory
from google.oauth2 import id_token
from google.auth.transport import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder='.', static_url_path='')

# Secure key for sessions (in production, use a strong, random, and secret key)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_secret_key_123")

# Ensure secure cookie configurations
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False  # Set to True in production with HTTPS
)

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")

@app.route('/')
def index():
    if 'user' in session:
        return redirect('/dashboard.html')
    return send_from_directory('.', 'index.html')

@app.route('/dashboard.html')
def dashboard():
    if 'user' not in session:
        return redirect('/')
    return send_from_directory('.', 'dashboard.html')

@app.route('/api/config')
def get_config():
    return jsonify({"client_id": GOOGLE_CLIENT_ID})

@app.route('/api/auth/google', methods=['POST'])
def auth_google():
    data = request.json
    token = data.get('credential')
    
    if not token:
        return jsonify({"error": "Missing credential"}), 400

    try:
        # Verify the token
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), GOOGLE_CLIENT_ID)
        
        # Check issuer
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')
            
        if not idinfo.get('email_verified', False):
            raise ValueError('Email not verified.')

        # Store minimal user info in session
        session['user'] = {
            'sub': idinfo['sub'],
            'name': idinfo.get('name'),
            'email': idinfo.get('email'),
            'picture': idinfo.get('picture')
        }
        
        return jsonify({"success": True})
        
    except ValueError as e:
        # Invalid token
        print(f"Token verification failed: {e}")
        return jsonify({"error": "Invalid token"}), 401

@app.route('/api/me')
def api_me():
    if 'user' in session:
        return jsonify(session['user'])
    return jsonify({"error": "Unauthorized"}), 401

@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    session.clear()
    return jsonify({"success": True})

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

if __name__ == '__main__':
    # Run the server on port 8080, binding to localhost so Werkzeug resolves it natively
    app.run(host='localhost', port=8080, debug=True)

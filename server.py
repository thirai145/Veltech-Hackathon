import os
import requests
import re
import html
from flask import Flask, request, jsonify, session, redirect, send_from_directory
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_secret_key_123")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False  # Set to True in production with HTTPS
)

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

def analyze_phishing(subject, sender, body_snippet):
    subject_lower = subject.lower()
    body_lower = body_snippet.lower()
    sender_lower = sender.lower()
    
    score = 0
    signs = []
    
    # 1. Suspicious keywords
    urgent_words = ['urgent', 'immediate action required', 'suspended', 'locked', 'verify your account']
    money_words = ['bank', 'invoice', 'payment', 'winner', 'claim', 'lottery', 'refund']
    password_words = ['password', 'otp', 'login credential', 'auth code']
    
    for word in urgent_words:
        if word in subject_lower or word in body_lower:
            score += 30
            signs.append(f"Urgent language detected: '{word}'")
            
    for word in money_words:
        if word in subject_lower or word in body_lower:
            score += 20
            signs.append(f"Financial/Money keyword: '{word}'")
            
    for word in password_words:
        if word in subject_lower or word in body_lower:
            score += 40
            signs.append(f"Request for credentials: '{word}'")
            
    # 2. Sender checks (simple mock)
    if not sender_lower.endswith('>'):
        pass # just a name
    else:
        # extract domain
        match = re.search(r'@([\w.-]+)>', sender_lower)
        if match:
            domain = match.group(1)
            # basic check: if it says it's from google/paypal but domain is wrong
            if ('paypal' in sender_lower or 'google' in sender_lower or 'apple' in sender_lower) and domain not in ['paypal.com', 'google.com', 'apple.com']:
                score += 50
                signs.append(f"Suspicious sender domain ({domain}) pretending to be a major brand.")
                
    # Cap score
    score = min(score, 100)
    
    if score >= 60:
        status = "PHISHING"
        explanation = "High probability of being a phishing attempt or scam."
        action = "Do not click any links, download attachments, or reply. Delete immediately."
    elif score >= 20:
        status = "SUSPICIOUS"
        explanation = "Contains suspicious language or requests. Proceed with caution."
        action = "Verify the sender's identity before interacting."
    else:
        status = "SAFE"
        explanation = "No major phishing indicators detected."
        action = "Safe to open, but always remain vigilant."
        
    return {
        "status": status,
        "score": score,
        "explanation": explanation,
        "signs": list(set(signs)),
        "action": action
    }

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
    code = data.get('code')
    
    if not code:
        return jsonify({"error": "Missing authorization code"}), 400

    try:
        # Exchange code for tokens
        token_url = "https://oauth2.googleapis.com/token"
        token_data = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": "postmessage",
            "grant_type": "authorization_code"
        }
        token_resp = requests.post(token_url, data=token_data)
        if not token_resp.ok:
            print(token_resp.text)
            raise ValueError('Failed to exchange auth code for tokens. Make sure GOOGLE_CLIENT_SECRET is set correctly.')
            
        token_json = token_resp.json()
        access_token = token_json.get('access_token')

        # Fetch user info using the access token
        user_info_resp = requests.get(
            'https://www.googleapis.com/oauth2/v3/userinfo',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        
        if not user_info_resp.ok:
            raise ValueError('Failed to fetch user info.')

        user_info = user_info_resp.json()

        # Store user info and access token in session
        session['user'] = {
            'sub': user_info.get('sub'),
            'name': user_info.get('name'),
            'email': user_info.get('email'),
            'picture': user_info.get('picture')
        }
        session['access_token'] = access_token
        
        return jsonify({"success": True})
        
    except Exception as e:
        print(f"Auth failed: {e}")
        return jsonify({"error": str(e)}), 401

@app.route('/api/me')
def api_me():
    if 'user' in session:
        return jsonify(session['user'])
    return jsonify({"error": "Unauthorized"}), 401

@app.route('/api/emails')
def api_emails():
    if 'access_token' not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    access_token = session['access_token']
    
    try:
        headers = {'Authorization': f'Bearer {access_token}'}
        list_resp = requests.get(
            'https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10',
            headers=headers
        )
        
        if not list_resp.ok:
            if list_resp.status_code == 403:
                return jsonify({"error": "Gmail API Access Denied. Ensure the API is enabled and scopes are granted."}), 403
            return jsonify({"error": "Failed to fetch emails"}), 500
            
        messages_list = list_resp.json().get('messages', [])
        
        results = []
        for msg in messages_list:
            msg_id = msg['id']
            msg_resp = requests.get(
                f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?format=full',
                headers=headers
            )
            msg_data = msg_resp.json()
            
            payload = msg_data.get('payload', {})
            msg_headers = payload.get('headers', [])
            
            body_snippet = html.unescape(msg_data.get('snippet', 'No content available.'))
            
            subject = "No Subject"
            sender = "Unknown Sender"
            recipient = "Unknown"
            date = ""
            
            for h in msg_headers:
                name = h['name'].lower()
                if name == 'subject':
                    subject = h['value']
                elif name == 'from':
                    sender = h['value']
                elif name == 'to':
                    recipient = h['value']
                elif name == 'date':
                    date = h['value']
                    
            analysis = analyze_phishing(subject, sender, body_snippet)
            
            results.append({
                "id": msg_id,
                "subject": subject,
                "sender": sender,
                "recipient": recipient,
                "date": date,
                "body": body_snippet,
                "analysis": analysis
            })
            
        return jsonify({"emails": results})
        
    except Exception as e:
        print(f"Error fetching emails: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    session.clear()
    return jsonify({"success": True})

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

if __name__ == '__main__':
    app.run(host='localhost', port=8080, debug=True)

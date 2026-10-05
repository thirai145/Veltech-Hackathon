import os
import re
import html
import base64
import requests
import hashlib
from urllib.parse import urlparse
from flask import Flask, request, jsonify, session, redirect, send_from_directory, Response
import concurrent.futures
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder=".", static_url_path="")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_secret_key_123")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

# ─── Phishing Analysis Engine ──────────────────────────────────────────────────

URGENCY_PHRASES = [
    "urgent", "immediate action", "act now", "verify now",
    "account suspended", "account locked", "account disabled",
    "limited time", "expires soon", "final notice", "last chance",
    "click here immediately", "response required", "your account will be",
    "confirm your identity",
]

CREDENTIAL_PHRASES = [
    "enter your password", "confirm your password", "reset your password",
    "enter your otp", "one-time password", "verification code",
    "login credentials", "banking details", "credit card", "card number",
    "social security", "national id",
]

FINANCIAL_PHRASES = [
    "bank account", "wire transfer", "western union", "money order",
    "bitcoin", "crypto payment", "gift card", "itunes card",
    "outstanding invoice", "payment required", "overdue", "irs",
    "tax refund", "unclaimed funds", "lottery winner", "you have won",
]

BRAND_IMPERSONATION = {
    "paypal":        ["paypal.com"],
    "google":        ["google.com", "gmail.com", "googlemail.com"],
    "apple":         ["apple.com", "icloud.com"],
    "microsoft":     ["microsoft.com", "outlook.com", "live.com", "hotmail.com"],
    "amazon":        ["amazon.com", "amazon.co.uk", "amazon.in"],
    "facebook":      ["facebook.com", "fb.com"],
    "netflix":       ["netflix.com"],
    "bank of america": ["bankofamerica.com"],
    "chase":         ["chase.com"],
    "wells fargo":   ["wellsfargo.com"],
}

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".loan", ".work",
                   ".gq", ".cf", ".tk", ".ml", ".ga"]

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)


def extract_urls(text):
    return URL_PATTERN.findall(text or "")


def get_domain(url):
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        return parsed.netloc.lower().lstrip("www.")
    except Exception:
        return ""


def analyze_phishing(subject, sender, body, reply_to=""):
    subject_l = (subject or "").lower()
    body_l    = (body or "").lower()
    sender_l  = (sender or "").lower()

    score = 0
    reasons = []
    conf_factors = []

    # Extract sender domain
    sender_domain = ""
    m = re.search(r"@([\w.-]+)>?", sender_l)
    if m:
        sender_domain = m.group(1).strip().strip(">")

    # Brand impersonation check
    for brand, legit_domains in BRAND_IMPERSONATION.items():
        if brand in sender_l or brand in subject_l:
            if sender_domain and sender_domain not in legit_domains:
                score += 45
                reasons.append(
                    f"Sender claims to be {brand.title()} but uses domain '{sender_domain}'"
                )
                conf_factors.append(0.9)

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if sender_domain.endswith(tld):
            score += 25
            reasons.append(f"Sender uses suspicious TLD: {tld}")
            conf_factors.append(0.75)
            break

    # Reply-To mismatch
    if reply_to and sender_domain:
        rt_domain = get_domain(reply_to)
        if rt_domain and rt_domain != sender_domain:
            score += 20
            reasons.append(
                f"Reply-To domain ({rt_domain}) differs from sender domain ({sender_domain})"
            )
            conf_factors.append(0.7)

    # Urgency language
    urgency_hits = [p for p in URGENCY_PHRASES if p in subject_l or p in body_l]
    if urgency_hits:
        score += min(len(urgency_hits) * 15, 35)
        reasons.append(f"Urgency/threat language: \"{urgency_hits[0]}\"")
        conf_factors.append(0.65)

    # Credential harvesting
    cred_hits = [p for p in CREDENTIAL_PHRASES if p in body_l or p in subject_l]
    if cred_hits:
        score += min(len(cred_hits) * 20, 40)
        reasons.append(f"Requests sensitive information: \"{cred_hits[0]}\"")
        conf_factors.append(0.85)

    # Financial bait
    fin_hits = [p for p in FINANCIAL_PHRASES if p in body_l or p in subject_l]
    if fin_hits:
        score += min(len(fin_hits) * 15, 30)
        reasons.append(f"Financial/money bait language: \"{fin_hits[0]}\"")
        conf_factors.append(0.7)

    # URL analysis
    urls = extract_urls(body)
    suspicious_urls = []
    url_domains = []
    for url in urls[:10]:
        d = get_domain(url)
        if not d:
            continue
        url_domains.append(d)
        for tld in SUSPICIOUS_TLDS:
            if d.endswith(tld):
                suspicious_urls.append(url[:70])
                break
        # IP-based URL
        if re.match(r"\d+\.\d+\.\d+\.\d+", d):
            score += 20
            reasons.append("Email contains an IP-based URL (common in phishing)")
            conf_factors.append(0.8)

    if suspicious_urls:
        score += min(len(suspicious_urls) * 15, 30)
        reasons.append(f"Suspicious URL detected: {suspicious_urls[0][:60]}")
        conf_factors.append(0.8)

    score = min(score, 100)

    # Risk thresholds
    if score >= 91:
        risk_level = "CRITICAL"; status = "PHISHING"
        explanation = "Very high probability of phishing. Multiple strong indicators found."
        action = "Do NOT click links or attachments. Report and delete immediately."
    elif score >= 71:
        risk_level = "HIGH"; status = "PHISHING"
        explanation = "High probability of phishing. Several indicators detected."
        action = "Do not click links or provide any information. Verify through official channels."
    elif score >= 41:
        risk_level = "MEDIUM"; status = "SUSPICIOUS"
        explanation = "Suspicious elements detected. Treat with caution."
        action = "Verify the sender independently before clicking any link."
    elif score >= 21:
        risk_level = "LOW"; status = "SUSPICIOUS"
        explanation = "Minor indicators present. Low probability of phishing."
        action = "Exercise normal caution. Verify sender if unexpected."
    else:
        risk_level = "SAFE"; status = "SAFE"
        explanation = "No significant phishing indicators detected."
        action = "Email appears safe. Always remain vigilant."

    confidence = round(
        sum(conf_factors) / max(len(conf_factors), 1), 2
    ) if conf_factors else 0.05
    confidence = min(confidence, 0.99)

    deduped_reasons = list(dict.fromkeys(reasons))

    return {
        "status":       status,
        "riskLevel":    risk_level,
        "score":        score,
        "confidence":   confidence,
        "isPhishing":   status == "PHISHING",
        "explanation":  explanation,
        "action":       action,
        "reasons":      deduped_reasons,
        "detectedUrls": url_domains[:10],
        # legacy alias
        "signs":        deduped_reasons,
    }


# ─── Email body extractor ──────────────────────────────────────────────────────

def decode_base64url(data):
    data = data.replace("-", "+").replace("_", "/")
    pad = 4 - len(data) % 4
    if pad != 4:
        data += "=" * pad
    try:
        return base64.b64decode(data).decode("utf-8", errors="replace")
    except Exception:
        return ""


def extract_body(payload):
    result = {"html": "", "plain": ""}
    mime_type = payload.get("mimeType", "")
    parts = payload.get("parts", [])
    body_data = payload.get("body", {}).get("data", "")

    if mime_type == "text/plain" and body_data:
        result["plain"] = decode_base64url(body_data)
    elif mime_type == "text/html" and body_data:
        result["html"] = decode_base64url(body_data)

    for part in parts:
        sub_res = extract_body(part)
        if sub_res["html"]:
            result["html"] = sub_res["html"]
        if sub_res["plain"]:
            result["plain"] = sub_res["plain"]

    return result

def extract_attachments(payload):
    attachments = []
    parts = payload.get("parts", [])
    for part in parts:
        filename = part.get("filename", "")
        if filename:
            attachments.append({
                "filename": filename,
                "mimeType": part.get("mimeType", ""),
                "size": part.get("body", {}).get("size", 0)
            })
        if "parts" in part:
            attachments.extend(extract_attachments(part))
    return attachments

def extract_ip(headers):
    # Search specific IP headers
    for h in headers:
        name = h["name"].lower()
        val = h["value"]
        if name in ["x-originating-ip", "x-client-ip", "x-sender-ip"]:
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", val)
            if m: return m.group(1), name, "Originating Network"
    
    # Check Received headers for the earliest public IP
    received_ips = []
    for h in headers:
        if h["name"].lower() == "received":
            m = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", h["value"])
            if m:
                ip = m.group(1)
                if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127.") or re.match(r"172\.(1[6-9]|2[0-9]|3[0-1])\.", ip)):
                    received_ips.append((ip, h["value"]))
    if received_ips:
        return received_ips[-1][0], "Received header", "Mail Relay / Submission Server"
        
    return None, None, None

IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "5cf617e03d02ec")

def get_geolocation(ip):
    if not ip: return None
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}", timeout=2)
        if r.ok:
            d = r.json()
            if "bogon" in d and d["bogon"]:
                return None
            
            # ipinfo.io returns "org" which contains both ASN and Org name (e.g., "AS15169 Google LLC")
            org_str = d.get("org", "")
            asn = ""
            org_name = org_str
            if org_str.startswith("AS"):
                parts = org_str.split(" ", 1)
                asn = parts[0]
                if len(parts) > 1:
                    org_name = parts[1]
                else:
                    org_name = ""
                    
            return {
                "country": d.get("country"),
                "region": d.get("region"),
                "city": d.get("city"),
                "isp": org_name,
                "org": org_name,
                "asn": asn
            }
    except Exception:
        pass
    return None

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "user" in session:
        return redirect("/dashboard.html")
    return send_from_directory(".", "index.html")

@app.route("/dashboard.html")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return send_from_directory(".", "dashboard.html")

@app.route("/api/config")
def get_config():
    return jsonify({"client_id": GOOGLE_CLIENT_ID})

@app.route("/api/auth/google", methods=["POST"])
def auth_google():
    data = request.json or {}
    code = data.get("code")
    if not code:
        return jsonify({"error": "Missing authorization code"}), 400
    try:
        token_resp = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code":          code,
                "client_id":     GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri":  "postmessage",
                "grant_type":    "authorization_code",
            },
        )
        if not token_resp.ok:
            print("Token exchange error:", token_resp.text)
            return jsonify({"error": "Auth failed. Check GOOGLE_CLIENT_SECRET."}), 401

        token_json   = token_resp.json()
        access_token = token_json.get("access_token")

        user_info = requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        ).json()

        session["user"] = {
            "sub":     user_info.get("sub"),
            "name":    user_info.get("name"),
            "email":   user_info.get("email"),
            "picture": user_info.get("picture"),
        }
        session["access_token"] = access_token
        return jsonify({"success": True})

    except Exception as e:
        print(f"Auth error: {e}")
        return jsonify({"error": str(e)}), 401

@app.route("/api/me")
def api_me():
    if "user" in session:
        return jsonify(session["user"])
    return jsonify({"error": "Unauthorized"}), 401

@app.route("/api/geolocation/<ip>")
def api_geolocation(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}", timeout=2)
        if not r.ok:
            return jsonify({"error": "Failed to fetch"}), 500
        d = r.json()
        if "bogon" in d and d["bogon"]:
            return jsonify({"error": "Bogon IP"}), 400
            
        org_str = d.get("org", "")
        asn = ""
        org_name = org_str
        if org_str.startswith("AS"):
            parts = org_str.split(" ", 1)
            asn = parts[0]
            org_name = parts[1] if len(parts) > 1 else ""
            
        lat, lon = "", ""
        if d.get("loc"):
            loc_parts = d["loc"].split(",")
            if len(loc_parts) == 2:
                lat, lon = loc_parts[0], loc_parts[1]
                
        is_cloud = any(x in org_name.lower() for x in ["google", "microsoft", "amazon", "cloudflare", "fastly", "akamai", "aws"])
        
        # Validation Logic
        validation = "VALIDATED"
        if is_cloud:
            validation = "PARTIALLY VALIDATED"
        
        return jsonify({
            "country": d.get("country"),
            "region": d.get("region"),
            "city": d.get("city"),
            "isp": org_name,
            "org": org_name,
            "asn": asn,
            "lat": lat,
            "lon": lon,
            "timezone": d.get("timezone"),
            "privacy": d.get("privacy", {}),
            "is_cloud": is_cloud,
            "validation": validation,
            "accuracy_radius": "Approx. 25 km radius" if d.get("city") else "Approx. 100 km radius"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/emails/list")
def api_emails_list():
    if "access_token" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    access_token = session["access_token"]
    hdrs = {"Authorization": f"Bearer {access_token}"}
    
    max_res = request.args.get("maxResults", "100")
    page_token = request.args.get("pageToken", "")
    url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults={max_res}"
    if page_token:
        url += f"&pageToken={page_token}"
        
    resp = requests.get(url, headers=hdrs)
    if resp.status_code == 401:
        session.pop("access_token", None)
        return jsonify({"error": "Session expired."}), 401
    if not resp.ok:
        return jsonify({"error": "Failed to contact Gmail API."}), 500
        
    data = resp.json()
    return jsonify({
        "messages": [m["id"] for m in data.get("messages", [])],
        "nextPageToken": data.get("nextPageToken")
    })

@app.route("/api/emails/batch", methods=["POST"])
def api_emails_batch():
    if "access_token" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    access_token = session["access_token"]
    hdrs = {"Authorization": f"Bearer {access_token}"}
    
    msg_ids = request.json.get("ids", [])
    if not msg_ids: return jsonify({"emails": []})
    
    user_email = session.get("user", {}).get("email", "").lower()
    
    def fetch_one(mid):
        try:
            msg_resp = requests.get(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}?format=full", headers=hdrs)
            if not msg_resp.ok: return None
            
            msg_data = msg_resp.json()
            payload  = msg_data.get("payload", {})
            hdrs_map = {h["name"].lower(): h["value"] for h in payload.get("headers", [])}

            subject   = hdrs_map.get("subject", "(No Subject)")
            sender    = hdrs_map.get("from",    "Unknown")
            recipient = hdrs_map.get("to",      "")
            cc        = hdrs_map.get("cc",      "")
            date      = hdrs_map.get("date",    "")
            reply_to  = hdrs_map.get("reply-to", "")
            message_id = hdrs_map.get("message-id", "")
            auth_res  = hdrs_map.get("authentication-results", "")

            snippet   = html.unescape(msg_data.get("snippet", ""))
            body_dict = extract_body(payload)
            html_body = body_dict["html"]
            plain_body = body_dict["plain"]
            
            analysis_body = plain_body
            if not analysis_body and html_body:
                import re as regex
                analysis_body = regex.sub(r"(?i)<style.*?>.*?</style>", " ", html_body, flags=regex.DOTALL)
                analysis_body = regex.sub(r"<[^>]+>", " ", analysis_body)
            
            analysis_body = (analysis_body.strip() or snippet)[:3000]
            
            content_hash = hashlib.sha256(analysis_body.encode("utf-8")).hexdigest()
            attachments = extract_attachments(payload)
            
            ip, source, role = extract_ip(payload.get("headers", []))
            geo_info = None
            if ip:
                geo_info = {
                    "ip": ip,
                    "source": source,
                    "role": role,
                    "geo": None
                }

            is_unread = "UNREAD" in msg_data.get("labelIds", [])
            analysis  = analyze_phishing(subject, sender, analysis_body, reply_to)

            direction = "UNKNOWN"
            if user_email:
                sender_l = sender.lower()
                recipient_l = recipient.lower()
                if user_email in sender_l and user_email in recipient_l:
                    direction = "REPLY"
                elif user_email in sender_l:
                    direction = "OUTGOING"
                else:
                    direction = "INCOMING"

            return {
                "id":        mid,
                "threadId":  msg_data.get("threadId", ""),
                "messageId": message_id,
                "subject":   subject,
                "sender":    sender,
                "recipient": recipient,
                "cc":        cc,
                "date":      date,
                "snippet":   snippet,
                "htmlBody":  html_body,
                "plainBody": plain_body,
                "body":      analysis_body,
                "isUnread":  is_unread,
                "analysis":  analysis,
                "direction": direction,
                "authResults": auth_res,
                "contentHash": content_hash,
                "attachments": attachments,
                "geolocation": geo_info
            }
        except Exception as inner:
            print(f"Skipping message {mid}: {inner}")
            return None

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futs = [executor.submit(fetch_one, mid) for mid in msg_ids]
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if r: results.append(r)
            
    return jsonify({"emails": results})

@app.route("/api/emails/<msg_id>/raw")
def api_email_raw(msg_id):
    if "access_token" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    access_token = session["access_token"]
    hdrs = {"Authorization": f"Bearer {access_token}"}

    try:
        resp = requests.get(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?format=raw",
            headers=hdrs,
        )
        if not resp.ok:
            return jsonify({"error": "Failed to fetch raw email."}), resp.status_code

        raw_data = resp.json().get("raw", "")
        eml_content = decode_base64url(raw_data)
        
        return Response(
            eml_content,
            mimetype="message/rfc822",
            headers={"Content-Disposition": f"attachment;filename=email_{msg_id}.eml"}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/<path:path>")
def serve_static(path):
    return send_from_directory(".", path)

if __name__ == "__main__":
    app.run(host="localhost", port=8080, debug=True)

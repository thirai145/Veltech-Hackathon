import re
with open("server.py", "r", encoding="utf-8") as f:
    content = f.read()

start_idx = content.find('@app.route("/api/emails")')
end_idx = content.find('def extract_attachments(payload):', start_idx)
if end_idx == -1:
    end_idx = content.find('@app.route("/api/', start_idx + 30)

if start_idx != -1:
    new_api = """@app.route("/api/emails/list")
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
            geo_data = get_geolocation(ip)
            geo_info = None
            if ip:
                geo_info = {
                    "ip": ip,
                    "source": source,
                    "role": role,
                    "geo": geo_data
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

"""
    if end_idx != -1:
        content = content[:start_idx] + new_api + content[end_idx:]
    else:
        content = content[:start_idx] + new_api
    with open("server.py", "w", encoding="utf-8") as f:
        f.write(content)

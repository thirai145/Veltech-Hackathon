import re

with open("server.py", "r", encoding="utf-8") as f:
    content = f.read()

pattern = re.compile(r'@app\.route\("/api/auth/google", methods=\["POST"\]\)\s*def auth_google\(\):.*?return jsonify\(\{"error": str\(e\)\}\), 401', re.DOTALL)
replacement = """@app.route("/api/auth/google", methods=["POST"])
def auth_google():
    # Bypass authentication for testing
    session["user"] = {
        "sub":     "1234567890",
        "name":    "Demo User",
        "email":   "demo@example.com",
        "picture": "",
    }
    session["access_token"] = "demo_access_token"
    return jsonify({"success": True})"""

new_content = pattern.sub(replacement, content)

with open("server.py", "w", encoding="utf-8") as f:
    f.write(new_content)

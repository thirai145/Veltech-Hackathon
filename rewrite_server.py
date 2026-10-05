import re

with open("server.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Add the new /api/geolocation endpoint
geo_api = """@app.route("/api/geolocation/<ip>")
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
"""

# inject before @app.route("/api/emails/list")
idx = content.find('@app.route("/api/emails/list")')
if idx != -1:
    content = content[:idx] + geo_api + "\n" + content[idx:]

# 2. Modify api_emails_batch to NOT call get_geolocation
old_geo_call = """            geo_data = get_geolocation(ip)
            geo_info = None
            if ip:
                geo_info = {
                    "ip": ip,
                    "source": source,
                    "role": role,
                    "geo": geo_data
                }"""

new_geo_call = """            geo_info = None
            if ip:
                geo_info = {
                    "ip": ip,
                    "source": source,
                    "role": role,
                    "geo": None
                }"""

content = content.replace(old_geo_call, new_geo_call)

with open("server.py", "w", encoding="utf-8") as out:
    out.write(content)

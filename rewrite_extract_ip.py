import re

with open("server.py", "r", encoding="utf-8") as f:
    content = f.read()

def rewrite_extract_ip():
    start_idx = content.find('def extract_ip(headers):')
    end_idx = content.find('IPINFO_TOKEN =', start_idx)
    
    new_extract_ip = """def extract_ip(headers):
    # 1. Check explicit client/origin IPs
    for h in headers:
        name = h["name"].lower()
        val = h["value"]
        if name in ["x-originating-ip", "x-client-ip", "x-sender-ip"]:
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", val)
            if m: 
                ip = m.group(1)
                if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127.") or re.match(r"172\.(1[6-9]|2[0-9]|3[0-1])\.", ip)):
                    return ip, name, "Originating Client"

    # 2. Parse complete Received header chain
    # Received headers are added top-down by each MTA.
    # The last one added (topmost) is the final receiving server.
    # The first one added (bottommost) is the original sender.
    received_chain = []
    for h in headers:
        if h["name"].lower() == "received":
            val = h["value"]
            # Try to find IPv4
            m = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", val)
            if not m:
                # sometimes it's just "from hostname (1.2.3.4)"
                m = re.search(r"\(.*?(\d+\.\d+\.\d+\.\d+).*?\)", val)
            
            if m:
                ip = m.group(1)
                # Ignore internal/private IPs
                if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127.") or re.match(r"172\.(1[6-9]|2[0-9]|3[0-1])\.", ip)):
                    received_chain.append(ip)

    # received_chain is in order of headers (top to bottom).
    # Since headers are prepended, the bottom-most public IP is the closest to the origin.
    if received_chain:
        candidate_ip = received_chain[-1]
        
        # Determine role based on depth
        if len(received_chain) == 1:
            role = "Mail Relay / Submission Server"
        else:
            role = "Originating Mail Server / Relay"
            
        return candidate_ip, "Received chain (originmost)", role

    return None, None, None

"""
    return content[:start_idx] + new_extract_ip + content[end_idx:]

new_content = rewrite_extract_ip()
with open("server.py", "w", encoding="utf-8") as f:
    f.write(new_content)

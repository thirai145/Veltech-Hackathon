import re
with open("dashboard.html", "r", encoding="utf-8") as f:
    content = f.read()

start_idx = content.find('<div class="d-sec-title">Email Origin & Geolocation</div>')
end_idx = content.find('<div class="action-card ${isRisky?\'warning\':\'safe\'}">', start_idx)

new_html = """<div class="d-sec-title">Email Origin & Geolocation</div>
    <div class="analysis-card" style="margin-bottom:20px;" id="geo-card-${email.id}">
      ${email.geolocation ? `
        <div class="d-meta" id="geo-inner-${email.id}">
          <div class="d-meta-row"><span class="d-meta-lbl">Origin IP</span><span class="d-meta-val" style="font-family:monospace;">${esc(email.geolocation.ip)}</span></div>
          <div class="d-meta-row"><span class="d-meta-lbl">IP Role</span><span class="d-meta-val">${esc(email.geolocation.role)}</span></div>
          <div class="d-meta-row" style="margin-top:10px;"><span class="d-meta-val" style="color:#666; font-style:italic;">Validating geolocation...</span></div>
        </div>
      ` : `
        <div class="d-meta">
          <div class="d-meta-row"><span class="d-meta-lbl">Origin IP</span><span class="d-meta-val">Not available</span></div>
          <div class="d-meta-row"><span class="d-meta-lbl">Location</span><span class="d-meta-val">Unavailable</span></div>
          <div class="d-meta-row" style="margin-top:10px;"><span class="d-meta-val" style="color:#666; font-style:italic;">No reliable network-origin IP was available in the email headers.</span></div>
        </div>
      `}
    </div>

    """

if start_idx != -1 and end_idx != -1:
    content = content[:start_idx] + new_html + content[end_idx:]

# Now inject the JS logic at the end of openDetail
end_fn_idx = content.find('document.getElementById(\'d-overlay\').classList.add(\'open\');')
async_logic = """
  if(email.geolocation && email.geolocation.ip) {
    // Fetch geo dynamically
    fetch('/api/geolocation/' + email.geolocation.ip)
      .then(r => r.json())
      .then(geo => {
        email.geolocation.geo = geo; // cache it
        const c = document.getElementById('geo-inner-' + email.id);
        if(!c) return;
        
        let loc = "Unavailable / Low confidence";
        if(geo.city && geo.country) {
          loc = `${esc(geo.city)}, ${esc(geo.region)}, ${esc(geo.country)}`;
        } else if (geo.country) {
          loc = esc(geo.country);
        }
        
        let disclaimer = "IP geolocation represents an approximate network location and does not establish the physical location or identity of the sender.";
        let cloudStr = geo.is_cloud ? `<div class="d-meta-row" style="margin-top:8px;"><span class="d-meta-val" style="color:#d97706; font-weight:bold;">Note: This IP belongs to ${esc(geo.org || 'a cloud provider')}. The location represents the network/server location rather than the sender's physical location.</span></div>` : '';

        c.innerHTML = `
          <div class="d-meta-row"><span class="d-meta-lbl">Origin IP</span><span class="d-meta-val" style="font-family:monospace;">${esc(email.geolocation.ip)}</span></div>
          <div class="d-meta-row"><span class="d-meta-lbl">IP Role</span><span class="d-meta-val">${esc(email.geolocation.role)}</span></div>
          <div class="d-meta-row"><span class="d-meta-lbl">Validation</span><span class="d-meta-val" style="font-weight:bold;">${esc(geo.validation || 'UNAVAILABLE')}</span></div>
          <div class="d-meta-row"><span class="d-meta-lbl">Location</span><span class="d-meta-val">${loc}</span></div>
          <div class="d-meta-row"><span class="d-meta-lbl">Accuracy</span><span class="d-meta-val">${esc(geo.accuracy_radius || 'Unknown')}</span></div>
          <div class="d-meta-row"><span class="d-meta-lbl">ISP/Network</span><span class="d-meta-val">${esc(geo.isp||'Unknown')} ${geo.org ? `(${esc(geo.org)})`:''}</span></div>
          <div class="d-meta-row"><span class="d-meta-lbl">ASN</span><span class="d-meta-val" style="font-family:monospace;">${esc(geo.asn||'Unknown')}</span></div>
          <div class="d-meta-row"><span class="d-meta-lbl">Timezone</span><span class="d-meta-val">${esc(geo.timezone||'Unknown')}</span></div>
          ${geo.lat ? `<div class="d-meta-row"><span class="d-meta-lbl">Coordinates</span><span class="d-meta-val">${esc(geo.lat)}, ${esc(geo.lon)}</span></div>` : ''}
          <div class="d-meta-row"><span class="d-meta-lbl">Source</span><span class="d-meta-val">${esc(email.geolocation.source)}</span></div>
          ${cloudStr}
          <div class="d-meta-row" style="margin-top:10px; padding-top:10px; border-top:1px solid var(--border);"><span class="d-meta-val" style="color:#666; font-style:italic; font-size:11px;">${disclaimer}</span></div>
        `;
      })
      .catch(e => {
        const c = document.getElementById('geo-inner-' + email.id);
        if(c) c.innerHTML += `<div class="d-meta-row" style="color:var(--high);"><span class="d-meta-val">Failed to validate geolocation.</span></div>`;
      });
  }
  
  """
if end_fn_idx != -1:
    content = content[:end_fn_idx] + async_logic + content[end_fn_idx:]

with open("dashboard.html", "w", encoding="utf-8") as out:
    out.write(content)

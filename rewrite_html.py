import re
with open("dashboard.html", "r", encoding="utf-8") as f:
    content = f.read()

start_idx = content.find('async function fetchEmails(manual=false){')
end_idx = content.find('function manualRefresh(){', start_idx)

new_js = """let isFetching = false;
async function fetchEmails(manual=false) {
  if(isFetching) return;
  isFetching = true;
  const refBtn = document.getElementById('ref-btn');
  if(manual){ refBtn.disabled=true; refBtn.classList.add('spinning'); }
  
  try {
    document.getElementById('email-list').innerHTML = `
      <div class="state-box">
        <div class="spinner"></div>
        <div class="state-title">Connecting to Gmail…</div>
        <div class="state-msg" id="fetch-progress">Fetching message list...</div>
      </div>
    `;

    const res = await fetch('/api/emails/list?maxResults=150');
    const data = await res.json();
    
    if(data.error) {
      document.getElementById('email-list').innerHTML = `<div class="state-box"><div class="state-title">Error</div><div class="state-msg">${esc(data.error)}</div></div>`;
      if(res.status===401) setTimeout(()=>location.href='/index.html',2000);
      return;
    }
    
    const msgIds = data.messages || [];
    if(msgIds.length === 0) {
      document.getElementById('email-list').innerHTML = `<div class="state-box"><div class="state-title">No emails found</div></div>`;
      return;
    }

    // Process in batches
    allEmails = [];
    const BATCH_SIZE = 15;
    const total = msgIds.length;
    let processed = 0;
    
    const pEl = document.getElementById('fetch-progress');
    if(pEl) pEl.textContent = `Fetching emails: 0/${total}`;
    
    for (let i = 0; i < msgIds.length; i += BATCH_SIZE) {
      const batchIds = msgIds.slice(i, i + BATCH_SIZE);
      const bRes = await fetch('/api/emails/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: batchIds })
      });
      
      if(bRes.ok) {
        const bData = await bRes.json();
        const newEmails = bData.emails || [];
        allEmails.push(...newEmails);
        processed += batchIds.length;
        
        updateStats(allEmails);
        renderList();
        
        // Show progress via a toast if it's taking a while, or just update the UI silently
        if(pEl && i === 0) {
           // once first batch renders, the spinner is gone because renderList() overwrites email-list
           // so we use toast for subsequent progress
           toast(`Analyzed ${processed} of ${total} emails...`, 1500);
        } else if (i > 0) {
           toast(`Analyzed ${processed} of ${total} emails...`, 1500);
        }
      }
    }
    
    if(manual) toast(`Refreshed – ${allEmails.length} emails loaded`);
  } catch(err) {
    console.error(err);
    if(manual) toast('Network error. Please try again.');
  } finally {
    isFetching = false;
    if(manual){ refBtn.disabled=false; refBtn.classList.remove('spinning'); }
  }
}
"""

if start_idx != -1 and end_idx != -1:
    content = content[:start_idx] + new_js + content[end_idx:]
    with open("dashboard.html", "w", encoding="utf-8") as out:
        out.write(content)

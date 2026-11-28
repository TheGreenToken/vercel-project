(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const CTRL_RE = /[^\x20-\x7E\u00A0-\uFFFF]/g;
  function san(str, max) { return String(str || '').replace(CTRL_RE, '').slice(0, max || 200); }
  function esc(str) { return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;'); }

  // ---- Tool tab router ----
  const tabs = Array.from(document.querySelectorAll('.tool-tab[data-tool]'));
  const panels = { github: $('toolGithub'), email: $('toolEmail'), exposure: $('toolExposure'), ipExposure: $('toolIpExposure'), ip: $('toolIp'), domain: $('toolDomain'), username: $('toolUsername'), file: $('toolFile'), history: $('toolHistory') };
  function activateTool(name) {
    tabs.forEach(t => t.classList.toggle('active', t.dataset.tool === name));
    Object.entries(panels).forEach(([k, el]) => { if (el) el.classList.toggle('active', k === name); });
    try { localStorage.setItem('mono_tool', name); } catch (_) {}
    try { window.dispatchEvent(new CustomEvent('mono:tool-activated', { detail: name })); } catch (_) {}
  }
  tabs.forEach(t => t.addEventListener('click', () => activateTool(t.dataset.tool)));
  try { const saved = localStorage.getItem('mono_tool'); if (saved && panels[saved]) activateTool(saved); } catch (_) {}

  // ---- Email tool ----
  const emailInput = $('emailInput');
  const scanBtn = $('emailScanBtn');
  const progressBlock = $('emailProgressBlock');
  const statusText = $('emailStatusText');
  const pctText = $('emailPctText');
  const progressFill = $('emailProgressFill');
  const subFill = $('emailSubFill');
  const logBlock = $('emailLogBlock');
  const errorBlock = $('emailErrorBlock');
  const errorMsg = $('emailErrorMsg');
  const errorHint = $('emailErrorHint');
  const resultsBlock = $('emailResultsBlock');
  const emailTarget = $('emailTarget');
  const emailMeta = $('emailMeta');
  const emailFoundCount = $('emailFoundCount');
  const emailCheckedCount = $('emailCheckedCount');
  const emailResultsCount = $('emailResultsCount');
  const emailTableBody = $('emailTableBody');
  const emailHistorySection = $('emailHistorySection');
  const emailHistoryList = $('emailHistoryList');

  let currentResults = [];
  let currentFilter = 'all';
  let currentEmail = '';

  function showError(msg, hint) {
    errorMsg.textContent = san(msg, 200);
    errorHint.textContent = hint ? san(hint, 200) : '';
    errorBlock.classList.add('show');
  }
  function clearError() { errorBlock.classList.remove('show'); errorMsg.textContent=''; errorHint.textContent=''; }
  function setProgress(pct, status) {
    const p = Math.max(0, Math.min(100, pct));
    progressFill.style.width = p + '%';
    pctText.textContent = Math.round(p) + '%';
    if (status) statusText.textContent = san(status, 120);
  }
  function log(line, cls) {
    const d = document.createElement('div');
    d.className = 'log-line' + (cls ? ' ' + cls : '');
    d.textContent = san(line, 300);
    logBlock.appendChild(d);
    logBlock.scrollTop = logBlock.scrollHeight;
  }

  function validateEmail(v) {
    const e = String(v || '').trim().toLowerCase();
    return /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/.test(e) ? e : '';
  }

  function statusLabel(s) {
    if (s === 'found') return 'Found';
    if (s === 'not_found') return 'Not Found';
    if (s === 'rate_limit') return 'Rate Limit';
    if (s === 'inconclusive') return 'Inconclusive';
    return 'Error';
  }
  function statusClass(s) {
    if (s === 'found') return 'found';
    if (s === 'not_found') return 'notfound';
    if (s === 'rate_limit') return 'ratelimit';
    if (s === 'inconclusive') return 'inconclusive';
    return 'error';
  }

  function filteredResults() {
    if (currentFilter === 'found') return currentResults.filter(r => r.status === 'found');
    if (currentFilter === 'not_found') return currentResults.filter(r => r.status === 'not_found');
    if (currentFilter === 'error') return currentResults.filter(r => r.status === 'error' || r.status === 'rate_limit' || r.status === 'inconclusive');
    return currentResults;
  }

  function renderResults() {
    const rows = filteredResults();
    emailTableBody.innerHTML = '';
    if (!rows.length) {
      emailTableBody.innerHTML = '<div class="table-empty">// no results for this filter</div>';
      emailResultsCount.textContent = '0 shown';
      return;
    }
    rows.forEach(r => {
      const div = document.createElement('div');
      div.className = 'email-row';
      div.innerHTML = `
        <div class="email-service">${esc(r.name || 'Unknown')}</div>
        <div><span class="email-status ${statusClass(r.status)}">${esc(statusLabel(r.status))}</span></div>
        <div class="email-detail" title="${esc(r.detail || '')}">${esc(r.detail || '—')}</div>
        <div class="email-cat">${esc(r.category || '—')}</div>
      `;
      emailTableBody.appendChild(div);
    });
    const found = currentResults.filter(r => r.status === 'found').length;
    emailResultsCount.textContent = `${rows.length} shown · ${found} found · ${currentResults.length} checked`;
  }

  function setFilter(f) {
    currentFilter = f;
    ['All','Found','NotFound','Error'].forEach(name => {
      const id = 'emailFilter' + name;
      const btn = $(id);
      if (btn) btn.classList.toggle('active', name.toLowerCase().replace('notfound','not_found') === f || (name==='All' && f==='all') || (name==='Found' && f==='found') || (name==='NotFound' && f==='not_found') || (name==='Error' && f==='error'));
    });
    renderResults();
  }

  $('emailFilterAll').addEventListener('click', () => setFilter('all'));
  $('emailFilterFound').addEventListener('click', () => setFilter('found'));
  $('emailFilterNotFound').addEventListener('click', () => setFilter('not_found'));
  $('emailFilterError').addEventListener('click', () => setFilter('error'));

  function saveHistory(entry) {
    try {
      const key = 'mono_email_history';
      const list = JSON.parse(localStorage.getItem(key) || '[]');
      const filtered = list.filter(x => x.email !== entry.email);
      filtered.unshift(entry);
      localStorage.setItem(key, JSON.stringify(filtered.slice(0, 20)));
    } catch (_) {}
  }
  function loadHistory() {
    try {
      const list = JSON.parse(localStorage.getItem('mono_email_history') || '[]');
      if (!Array.isArray(list) || !list.length) { emailHistorySection.style.display = 'none'; return; }
      emailHistorySection.style.display = 'block';
      emailHistoryList.innerHTML = '';
      list.forEach(item => {
        const row = document.createElement('div');
        row.className = 'history-row';
        const when = item.ts ? new Date(item.ts).toLocaleString() : '';
        row.innerHTML = `
          <div class="history-info">
            <div class="history-login">${esc(item.email || '')}</div>
            <div class="history-meta">${Number(item.found||0)} found · ${Number(item.checked||0)} checked</div>
          </div>
          <div class="history-time">${esc(when)}</div>
          <button class="history-rescan" type="button" title="Recheck">↻</button>
        `;
        row.querySelector('.history-rescan').addEventListener('click', (e) => { e.stopPropagation(); emailInput.value = item.email || ''; runCheck(); });
        row.addEventListener('click', () => { emailInput.value = item.email || ''; runCheck(); });
        emailHistoryList.appendChild(row);
      });
    } catch (_) { emailHistorySection.style.display = 'none'; }
  }

  async function runCheck() {
    clearError();
    const email = validateEmail(emailInput.value);
    if (!email) { showError('Enter a valid email address.', 'Example: name@example.com'); return; }
    currentEmail = email;
    scanBtn.disabled = true;
    progressBlock.classList.add('show');
    resultsBlock.classList.remove('show');
    logBlock.innerHTML = '';
    setProgress(8, 'Checking session...');
    log(`Target: ${email}`, 'ok');
    try {
      setProgress(20, 'Running account presence checks across 119 services...');
      log('Dispatching checks to server modules...', 'ok');
      let fake = 20;
      const timer = setInterval(() => { fake = Math.min(72, fake + 2); setProgress(fake, 'Checking services...'); }, 900);
      let res, text;
      try {
        res = await fetch('/api/email-check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email }),
        });
        text = await res.text();
      } finally { clearInterval(timer); }
      setProgress(75, 'Processing results...');
      let data;
      try { data = JSON.parse(text); } catch { throw new Error(text.slice(0, 160) || 'Invalid server response'); }
      if (!res.ok || data.error) {
        const msg = data.error || `HTTP ${res.status}`;
        if (res.status === 401) { showError(msg, 'Please login with Discord first.'); }
        else if (res.status === 429) { showError(msg, 'Please wait a moment and try again.'); }
        else showError(msg, 'Try again in a moment.');
        setProgress(100, 'Failed');
        return;
      }
      currentResults = Array.isArray(data.results) ? data.results : [];
      currentFilter = 'all';
      setFilter('all');
      emailTarget.textContent = san(email, 254);
      emailFoundCount.textContent = String(data.found ?? currentResults.filter(r=>r.status==='found').length);
      emailCheckedCount.textContent = String(data.checked ?? currentResults.length);
      const foundNames = currentResults.filter(r=>r.status==='found').map(r=>r.name).slice(0,6);
      const inconclusive = data.inconclusive ?? currentResults.filter(r=>r.status==='inconclusive').length;
      emailMeta.textContent = foundNames.length
        ? `Found on: ${foundNames.join(', ')}${currentResults.filter(r=>r.status==='found').length>6?'…':''}${inconclusive ? ` · ${inconclusive} inconclusive` : ''}`
        : `No public account presence detected by current modules${inconclusive ? ` · ${inconclusive} inconclusive` : ''}`;
      setProgress(100, 'Complete');
      log(`Done: ${data.found}/${data.checked} found in ${data.durationMs}ms`, 'hit');
      resultsBlock.classList.add('show');
      try { window.dispatchEvent(new CustomEvent('mono:lookup-done', { detail: { tool: 'email', query: email, status: (data.found > 0) ? 'found' : 'none' } })); } catch (_) {}
      saveHistory({ email, found: data.found || 0, checked: data.checked || 0, ts: Date.now() });
      loadHistory();
    } catch (e) {
      showError(e.message || 'Email check failed', 'Check your connection and try again.');
      setProgress(100, 'Failed');
    } finally {
      scanBtn.disabled = false;
    }
  }

  scanBtn.addEventListener('click', runCheck);
  emailInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); runCheck(); } });

  $('emailBtnNew').addEventListener('click', () => {
    resultsBlock.classList.remove('show');
    progressBlock.classList.remove('show');
    clearError();
    emailInput.focus();
  });

  function copyText(text, lblId) {
    navigator.clipboard.writeText(text).then(() => {
      const el = $(lblId); if (!el) return; const old = el.textContent; el.textContent = 'Copied!'; setTimeout(() => el.textContent = old, 1400);
    }).catch(() => {});
  }
  $('emailBtnCopy').addEventListener('click', () => {
    const found = currentResults.filter(r=>r.status==='found').map(r=>r.name);
    copyText(found.join('\n'), 'emailLblCopy');
  });
  $('emailBtnTxt').addEventListener('click', () => {
    const lines = [`Email: ${currentEmail}`, `Found: ${currentResults.filter(r=>r.status==='found').length}/${currentResults.length}`, '', ...currentResults.map(r=>`${r.name}\t${statusLabel(r.status)}\t${r.detail||''}`)];
    const blob = new Blob([lines.join('\n')], {type:'text/plain'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-email-${currentEmail.replace(/[^a-z0-9]/gi,'_')}.txt`; a.click(); URL.revokeObjectURL(a.href);
    if (window.monoUI) window.monoUI.toast('Downloaded TXT report');
  });
  $('emailBtnJson').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify({email:currentEmail, results:currentResults}, null, 2)], {type:'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-email-${currentEmail.replace(/[^a-z0-9]/gi,'_')}.json`; a.click(); URL.revokeObjectURL(a.href);
    if (window.monoUI) window.monoUI.toast('Downloaded JSON report');
  });
  $('emailBtnCsv').addEventListener('click', () => {
    const escCsv = (v) => '"' + String(v||'').replace(/"/g,'""') + '"';
    const rows = [['service','status','detail','category'], ...currentResults.map(r=>[r.name,statusLabel(r.status),r.detail||'',r.category||''])];
    const blob = new Blob([rows.map(r=>r.map(escCsv).join(',')).join('\n')], {type:'text/csv'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-email-${currentEmail.replace(/[^a-z0-9]/gi,'_')}.csv`; a.click(); URL.revokeObjectURL(a.href);
    if (window.monoUI) window.monoUI.toast('Downloaded CSV report');
  });

  loadHistory();
})();

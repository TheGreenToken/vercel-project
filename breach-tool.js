(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const CTRL_RE = /[^\x20-\x7E -￿]/g;
  function san(str, max) { return String(str || '').replace(CTRL_RE, '').slice(0, max || 200); }
  function esc(str) { return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;'); }

  // ---- Breach tool ----
  const input = $('breachInput');
  const scanBtn = $('breachScanBtn');
  const progressBlock = $('breachProgressBlock');
  const statusText = $('breachStatusText');
  const pctText = $('breachPctText');
  const progressFill = $('breachProgressFill');
  const logBlock = $('breachLogBlock');
  const errorBlock = $('breachErrorBlock');
  const errorMsg = $('breachErrorMsg');
  const errorHint = $('breachErrorHint');
  const resultsBlock = $('breachResultsBlock');
  const target = $('breachTarget');
  const meta = $('breachMeta');
  const countEl = $('breachCount');
  const resultsCount = $('breachResultsCount');
  const tableBody = $('breachTableBody');

  const pwInput = $('breachPwInput');
  const pwBtn = $('breachPwBtn');
  const pwResult = $('breachPwResult');

  let currentEmail = '';
  let currentBreaches = [];

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

  function renderResults() {
    tableBody.innerHTML = '';
    if (!currentBreaches.length) {
      tableBody.innerHTML = '<div class="table-empty">// no breach records found</div>';
      resultsCount.textContent = '0 records';
      return;
    }
    currentBreaches.forEach(b => {
      const div = document.createElement('div');
      div.className = 'exp-row';
      div.style.gridTemplateColumns = '1fr 110px';
      div.style.minWidth = 'unset';
      div.innerHTML = `
        <div class="exp-origin" data-label="Breach" title="${esc(b)}">${esc(b)}</div>
        <div data-label="Records"><span class="exp-badge hit">1</span></div>
      `;
      tableBody.appendChild(div);
    });
    resultsCount.textContent = `${currentBreaches.length} record(s)`;
  }

  async function runSearch() {
    clearError();
    const email = validateEmail(input.value);
    if (!email) { showError('Enter a valid email address.', 'Example: name@example.com'); return; }
    currentEmail = email;
    scanBtn.disabled = true;
    progressBlock.classList.add('show');
    resultsBlock.classList.remove('show');
    logBlock.innerHTML = '';
    setProgress(10, 'Checking session...');
    log(`Target: ${email}`, 'ok');
    try {
      setProgress(40, 'Querying breach records...');
      log('Requesting breach records...', 'ok');
      let res, text;
      try {
        res = await fetch('/api/breach-check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email }),
        });
        text = await res.text();
      } catch (e) { throw new Error(e.message || 'Network error'); }
      setProgress(75, 'Processing results...');
      let data;
      try { data = JSON.parse(text); } catch { throw new Error(text.slice(0, 160) || 'Invalid server response'); }
      if (!res.ok || data.error) {
        const msg = data.error || `HTTP ${res.status}`;
        if (res.status === 401) showError(msg, 'Please login with Discord first.');
        else if (res.status === 429) showError(msg, 'Please wait a moment and try again.');
        else showError(msg, 'Try again in a moment.');
        setProgress(100, 'Failed');
        return;
      }
      currentBreaches = Array.isArray(data.breaches) ? data.breaches : [];
      target.textContent = san(email, 254);
      countEl.textContent = String(data.count ?? currentBreaches.length);
      if (data.status === 'not_found' || !currentBreaches.length) {
        meta.textContent = 'No known breach records found for this address.';
      } else {
        meta.textContent = `Found in ${currentBreaches.length} breach record(s)`;
      }
      renderResults();
      setProgress(100, 'Complete');
      log(`Done: ${currentBreaches.length} record(s) in ${data.durationMs}ms`, currentBreaches.length ? 'hit' : 'ok');
      resultsBlock.classList.add('show');
    } catch (e) {
      showError(e.message || 'Breach check failed', 'Check your connection and try again.');
      setProgress(100, 'Failed');
    } finally {
      scanBtn.disabled = false;
    }
  }

  scanBtn.addEventListener('click', runSearch);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); runSearch(); } });

  $('breachBtnNew').addEventListener('click', () => {
    resultsBlock.classList.remove('show');
    progressBlock.classList.remove('show');
    clearError();
    input.focus();
  });

  function copyText(text, lblId) {
    navigator.clipboard.writeText(text).then(() => {
      const el = $(lblId); if (!el) return; const old = el.textContent; el.textContent = 'Copied!'; setTimeout(() => el.textContent = old, 1400);
    }).catch(() => {});
  }
  $('breachBtnCopy').addEventListener('click', () => copyText(currentBreaches.join('\n'), 'breachLblCopy'));
  $('breachBtnTxt').addEventListener('click', () => {
    const lines = [`Email: ${currentEmail}`, `Breaches: ${currentBreaches.length}`, '', ...currentBreaches];
    const blob = new Blob([lines.join('\n')], {type:'text/plain'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-breach-${currentEmail.replace(/[^a-z0-9]/gi,'_')}.txt`; a.click(); URL.revokeObjectURL(a.href);
  });
  $('breachBtnJson').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify({email:currentEmail, breaches:currentBreaches}, null, 2)], {type:'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-breach-${currentEmail.replace(/[^a-z0-9]/gi,'_')}.json`; a.click(); URL.revokeObjectURL(a.href);
  });

  // ---- Password breach check ----
  function renderPasswordResult(data) {
    pwResult.classList.add('show');
    let html = '';
    if (data.found) {
      html += `<div class="hash-result-row"><div class="hash-result-label">Result</div><div class="hash-result-val">Breached</div></div>`;
      html += `<div class="hash-result-row"><div class="hash-result-label">Occurrences</div><div class="hash-result-val">${esc(data.count)}</div></div>`;
    } else {
      html += `<div class="hash-result-row"><div class="hash-result-label">Result</div><div class="hash-result-val">Not found in breach corpus</div></div>`;
    }
    pwResult.innerHTML = html;
  }
  async function runPasswordCheck() {
    clearError();
    const password = String(pwInput.value || '');
    if (!password) { showError('Enter a password to check.', 'The password is hashed locally; only a 5-char hash prefix is sent.'); return; }
    pwBtn.disabled = true;
    pwResult.classList.add('show');
    pwResult.innerHTML = '<div class="hash-result-row"><div class="hash-result-label">Status</div><div class="hash-result-val">Checking…</div></div>';
    try {
      const res = await fetch('/api/breach-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      const text = await res.text();
      let data;
      try { data = JSON.parse(text); } catch { throw new Error(text.slice(0, 160) || 'Invalid server response'); }
      if (res.ok && !data.error) {
        renderPasswordResult(data);
      } else {
        const msg = data.error || `HTTP ${res.status}`;
        if (res.status === 401) showError(msg, 'Please login with Discord first.');
        else if (res.status === 429) showError(msg, 'Please wait a moment and try again.');
        else showError(msg, 'Try again in a moment.');
        pwResult.classList.remove('show');
      }
    } catch (e) {
      showError(e.message || 'Password check failed', 'Check your connection and try again.');
      pwResult.classList.remove('show');
    } finally {
      pwBtn.disabled = false;
    }
  }
  pwBtn.addEventListener('click', runPasswordCheck);
  pwInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); runPasswordCheck(); } });
})();

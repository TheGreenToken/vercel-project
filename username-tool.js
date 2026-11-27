(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const CTRL_RE = /[^\x20-\x7E -￿]/g;
  function san(str, max) { return String(str || '').replace(CTRL_RE, '').slice(0, max || 200); }
  function esc(str) { return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;'); }

  const input = $('usernameInput');
  const scanBtn = $('usernameScanBtn');
  const progressBlock = $('usernameProgressBlock');
  const statusText = $('usernameStatusText');
  const pctText = $('usernamePctText');
  const progressFill = $('usernameProgressFill');
  const logBlock = $('usernameLogBlock');
  const errorBlock = $('usernameErrorBlock');
  const errorMsg = $('usernameErrorMsg');
  const errorHint = $('usernameErrorHint');
  const resultsBlock = $('usernameResultsBlock');
  const target = $('usernameTarget');
  const meta = $('usernameMeta');
  const resultsCount = $('usernameResultsCount');
  const gridBody = $('usernameGridBody');
  const stat1 = $('usernameStat1');
  const stat2 = $('usernameStat2');

  let currentData = null;
  let currentQuery = '';

  const STATUS_LABEL = {
    found: 'found', not_found: 'none', error: 'error',
    rate_limit: 'limited', inconclusive: 'unknown',
  };

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

  function validateUsername(v) {
    const q = String(v || '').trim().replace(/^@/, '').replace(/^https?:\/\/[^/]+\//i, '').replace(/\/.*$/, '').slice(0, 64);
    return /^[a-zA-Z0-9._-]{1,64}$/.test(q) ? q : '';
  }

  function renderResults() {
    const d = currentData;
    if (!d) { gridBody.innerHTML = ''; resultsCount.textContent = ''; return; }
    gridBody.innerHTML = '';
    const found = (d.results || []).filter(r => r.status === 'found');
    const foundSet = new Set(found.map(r => r.name));

    // Summary strip: found chips
    const summary = document.createElement('div');
    summary.className = 'ip-cell';
    summary.style.gridColumn = '1/-1';
    if (found.length) {
      summary.innerHTML = `
        <div class="ip-cell-label">Accounts found · ${found.length}/${d.total}</div>
        <div class="badge-row">${found.map(r => '<span class="badge cdn">' + esc(r.name) + '</span>').join('')}</div>`;
    } else {
      summary.innerHTML = `<div class="ip-cell-label">No accounts found</div><div class="ip-cell-val dim">No profile found across ${d.total} platforms for “${esc(d.username)}”</div>`;
    }
    gridBody.appendChild(summary);

    // Per-platform rows
    (d.results || []).forEach(r => {
      const cell = document.createElement('div');
      cell.className = 'ip-cell';
      let badgeCls = '';
      if (r.status === 'found') badgeCls = 'hosting';
      else if (r.status === 'not_found') badgeCls = '';
      else if (r.status === 'rate_limit') badgeCls = 'proxy';
      else if (r.status === 'error') badgeCls = 'proxy';
      const badgeText = STATUS_LABEL[r.status] || r.status;
      cell.innerHTML = `
        <div class="ip-cell-label">${esc(r.name)} · <span style="color:var(--text-faint);letter-spacing:0">${esc(r.domain)}</span></div>
        <div class="badge-row"><span class="badge ${badgeCls}">${esc(badgeText)}</span>${r.status === 'found' && r.detail ? '<span class="ip-cell-val dim" style="font-size:.62rem">' + esc(r.detail) + '</span>' : ''}</div>
      `;
      gridBody.appendChild(cell);
    });

    resultsCount.textContent = `${found.length} found · ${d.total} platforms`;
  }

  async function runLookup() {
    clearError();
    const username = validateUsername(input.value);
    if (!username) { showError('Enter a valid username.', 'Use letters, numbers, dots, dashes or underscores — no spaces.'); return; }
    currentQuery = username;
    scanBtn.disabled = true;
    progressBlock.classList.add('show');
    resultsBlock.classList.remove('show');
    logBlock.innerHTML = '';
    setProgress(8, 'Checking session...');
    log(`Target: ${username}`, 'ok');
    try {
      setProgress(30, 'Scanning platforms...');
      log('Probing platforms for account presence...', 'ok');
      let fake = 30;
      const timer = setInterval(() => { fake = Math.min(90, fake + 5); setProgress(fake, 'Scanning platforms...'); }, 600);
      let res, text;
      try {
        res = await fetch('/api/username-check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username }),
        });
        text = await res.text();
      } finally { clearInterval(timer); }
      setProgress(95, 'Processing results...');
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
      currentData = data;
      target.textContent = san(username, 64);
      const found = (data.results || []).filter(r => r.status === 'found');
      meta.textContent = `${found.length} account(s) found across ${data.total} platforms`;
      stat1.textContent = found.length;
      stat2.textContent = data.total;
      setProgress(100, 'Complete');
      log(`Done: ${data.status} · ${found.length} found in ${data.durationMs}ms`, found.length ? 'hit' : 'ok');
      renderResults();
      resultsBlock.classList.add('show');
      try { window.dispatchEvent(new CustomEvent('mono:lookup-done', { detail: { tool: 'username', query: data.username, status: data.status } })); } catch (_) {}
    } catch (e) {
      showError(e.message || 'Username lookup failed', 'Check your connection and try again.');
      setProgress(100, 'Failed');
    } finally {
      scanBtn.disabled = false;
    }
  }

  scanBtn.addEventListener('click', runLookup);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); runLookup(); } });

  $('usernameBtnNew').addEventListener('click', () => {
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
  $('usernameBtnCopy').addEventListener('click', () => {
    if (!currentData) return;
    const lines = (currentData.results || []).map(r => `${r.status}\t${r.name}\t${r.domain}`);
    copyText(lines.join('\n'), 'usernameLblCopy');
  });
  $('usernameBtnTxt').addEventListener('click', () => {
    if (!currentData) return;
    const lines = [`Username: ${currentQuery}`, `Found: ${(currentData.results||[]).filter(r=>r.status==='found').length}/${currentData.total}`, '', ...(currentData.results||[]).map(r => `${r.status}\t${r.name}\t${r.domain}`)];
    const blob = new Blob([lines.join('\n')], {type:'text/plain'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-username-${currentQuery.replace(/[^a-z0-9]/gi,'_')}.txt`; a.click(); URL.revokeObjectURL(a.href);
  });
  $('usernameBtnJson').addEventListener('click', () => {
    if (!currentData) return;
    const blob = new Blob([JSON.stringify(currentData, null, 2)], {type:'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-username-${currentQuery.replace(/[^a-z0-9]/gi,'_')}.json`; a.click(); URL.revokeObjectURL(a.href);
  });
})();

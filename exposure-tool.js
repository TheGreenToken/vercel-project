(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const CTRL_RE = /[^\x20-\x7E -￿]/g;
  function san(str, max) { return String(str || '').replace(CTRL_RE, '').slice(0, max || 200); }
  function esc(str) { return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;'); }

  // ---- Exposure tool ----
  const input = $('exposureInput');
  const scanBtn = $('exposureScanBtn');
  const progressBlock = $('exposureProgressBlock');
  const statusText = $('exposureStatusText');
  const pctText = $('exposurePctText');
  const progressFill = $('exposureProgressFill');
  const subFill = $('exposureSubFill');
  const logBlock = $('exposureLogBlock');
  const errorBlock = $('exposureErrorBlock');
  const errorMsg = $('exposureErrorMsg');
  const errorHint = $('exposureErrorHint');
  const resultsBlock = $('exposureResultsBlock');
  const target = $('exposureTarget');
  const meta = $('exposureMeta');
  const foundCount = $('exposureFoundCount');
  const totalCount = $('exposureTotalCount');
  const resultsCount = $('exposureResultsCount');
  const tableBody = $('exposureTableBody');
  const historySection = $('exposureHistorySection');
  const historyList = $('exposureHistoryList');

  let currentHits = [];
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

  function filteredHits() {
    if (currentFilter === 'origin') return currentHits.filter(h => h.origin && !/^https?:\/\/stealerlogs/.test(h.origin));
    if (currentFilter === 'source') return currentHits.filter(h => h.source);
    return currentHits;
  }

  function renderResults() {
    const rows = filteredHits();
    tableBody.innerHTML = '';
    if (!rows.length) {
      tableBody.innerHTML = '<div class="table-empty">// no hits for this filter</div>';
      resultsCount.textContent = '0 shown';
      return;
    }
    rows.forEach(h => {
      const div = document.createElement('div');
      div.className = 'exp-row';
      div.innerHTML = `
        <div class="exp-origin" title="${esc(h.origin || '')}">${esc(h.origin || '—')}</div>
        <div class="exp-cell" title="${esc(h.login || '')}">${esc(h.login || '—')}</div>
        <div class="exp-cell dim" title="${esc(h.password || '')}">${esc(h.password || '—')}</div>
        <div class="exp-cell" title="${esc(h.posted || '')}">${esc(h.posted || '—')}</div>
        <div><span class="exp-badge ${h.source ? 'hit' : ''}">${esc(h.source || '—')}</span></div>
      `;
      tableBody.appendChild(div);
    });
    resultsCount.textContent = `${rows.length} shown · ${currentHits.length} hits`;
  }

  function setFilter(f) {
    currentFilter = f;
    ['All','Origin','Source'].forEach(name => {
      const btn = $('exposureFilter' + name);
      if (!btn) return;
      const map = { All: 'all', Origin: 'origin', Source: 'source' };
      btn.classList.toggle('active', map[name] === f);
    });
    renderResults();
  }

  $('exposureFilterAll').addEventListener('click', () => setFilter('all'));
  $('exposureFilterOrigin').addEventListener('click', () => setFilter('origin'));
  $('exposureFilterSource').addEventListener('click', () => setFilter('source'));

  function saveHistory(entry) {
    try {
      const key = 'mono_exposure_history';
      const list = JSON.parse(localStorage.getItem(key) || '[]');
      const filtered = list.filter(x => x.email !== entry.email);
      filtered.unshift(entry);
      localStorage.setItem(key, JSON.stringify(filtered.slice(0, 20)));
    } catch (_) {}
  }
  function loadHistory() {
    try {
      const list = JSON.parse(localStorage.getItem('mono_exposure_history') || '[]');
      if (!Array.isArray(list) || !list.length) { historySection.style.display = 'none'; return; }
      historySection.style.display = 'block';
      historyList.innerHTML = '';
      list.forEach(item => {
        const row = document.createElement('div');
        row.className = 'history-row';
        const when = item.ts ? new Date(item.ts).toLocaleString() : '';
        row.innerHTML = `
          <div class="history-info">
            <div class="history-login">${esc(item.email || '')}</div>
            <div class="history-meta">${Number(item.hits||0)} hits · ${Number(item.total||0)} in index</div>
          </div>
          <div class="history-time">${esc(when)}</div>
          <button class="history-rescan" type="button" title="Recheck">↻</button>
        `;
        row.querySelector('.history-rescan').addEventListener('click', (e) => { e.stopPropagation(); input.value = item.email || ''; runSearch(); });
        row.addEventListener('click', () => { input.value = item.email || ''; runSearch(); });
        historyList.appendChild(row);
      });
    } catch (_) { historySection.style.display = 'none'; }
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
    setProgress(8, 'Checking session...');
    log(`Target: ${email}`, 'ok');
    try {
      setProgress(30, 'Querying exposure index...');
      log('Requesting exposure search results...', 'ok');
      let fake = 30;
      const timer = setInterval(() => { fake = Math.min(80, fake + 2); setProgress(fake, 'Looking up hits...'); }, 700);
      let res, text;
      try {
        res = await fetch('/api/stealer-check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email }),
        });
        text = await res.text();
      } finally { clearInterval(timer); }
      setProgress(85, 'Processing results...');
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
      currentHits = Array.isArray(data.hits) ? data.hits : [];
      currentFilter = 'all';
      setFilter('all');
      target.textContent = san(email, 254);
      foundCount.textContent = String(data.hitCount ?? currentHits.length);
      const totalVal = Number(data.total) > 0 ? data.total : (data.hitCount ?? currentHits.length);
      totalCount.textContent = String(totalVal);
      const sources = [...new Set(currentHits.map(h => h.source).filter(Boolean))].slice(0, 4);
      if (data.status === 'not_found' || currentHits.length === 0) {
        meta.textContent = 'No publicly indexed stealer-log hits found for this address.';
      } else {
        meta.textContent = `${currentHits.length} hit${currentHits.length>1?'s':''} found${sources.length ? ' · sources: ' + sources.join(', ') : ''}`;
      }
      setProgress(100, 'Complete');
      log(`Done: ${currentHits.length} hit(s) in ${data.durationMs}ms`, currentHits.length ? 'hit' : 'ok');
      resultsBlock.classList.add('show');
      saveHistory({ email, hits: data.hitCount || 0, total: data.total || 0, ts: Date.now() });
      loadHistory();
    } catch (e) {
      showError(e.message || 'Exposure search failed', 'Check your connection and try again.');
      setProgress(100, 'Failed');
    } finally {
      scanBtn.disabled = false;
    }
  }

  scanBtn.addEventListener('click', runSearch);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); runSearch(); } });

  $('exposureBtnNew').addEventListener('click', () => {
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
  $('exposureBtnCopy').addEventListener('click', () => {
    const lines = currentHits.map(h => `${h.origin}\t${h.login}\t${h.password}\t${h.posted}\t${h.source}`);
    copyText(lines.join('\n'), 'exposureLblCopy');
  });
  $('exposureBtnTxt').addEventListener('click', () => {
    const lines = [`Email: ${currentEmail}`, `Hits: ${currentHits.length}`, `In index: ${totalCount.textContent}`, '', ...currentHits.map(h=>`${h.origin}\t${h.login}\t${h.password}\t${h.posted}\t${h.source}`)];
    const blob = new Blob([lines.join('\n')], {type:'text/plain'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-exposure-${currentEmail.replace(/[^a-z0-9]/gi,'_')}.txt`; a.click(); URL.revokeObjectURL(a.href);
  });
  $('exposureBtnJson').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify({email:currentEmail, total: totalCount.textContent, hits:currentHits}, null, 2)], {type:'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-exposure-${currentEmail.replace(/[^a-z0-9]/gi,'_')}.json`; a.click(); URL.revokeObjectURL(a.href);
  });
  $('exposureBtnCsv').addEventListener('click', () => {
    const escCsv = (v) => '"' + String(v||'').replace(/"/g,'""') + '"';
    const rows = [['origin','login','password','posted','source'], ...currentHits.map(h=>[h.origin,h.login,h.password,h.posted,h.source])];
    const blob = new Blob([rows.map(r=>r.map(escCsv).join(',')).join('\n')], {type:'text/csv'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-exposure-${currentEmail.replace(/[^a-z0-9]/gi,'_')}.csv`; a.click(); URL.revokeObjectURL(a.href);
  });

  loadHistory();
})();

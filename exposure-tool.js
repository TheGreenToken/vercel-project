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

  // ---- additional exposure sources ----
  const srcStealer = $('expSrcStealer');
  const srcComb = $('expSrcComb');
  const srcXon = $('expSrcXon');
  const hashInput = $('exposureHashInput');
  const hashBtn = $('exposureHashBtn');
  const hashResult = $('exposureHashResult');

  function syncSourceBar() {
    [srcStealer, srcComb, srcXon].forEach(cb => { if (!cb) return; const lbl = cb.closest('.source-check'); if (lbl) lbl.classList.toggle('on', cb.checked); });
  }
  function selectedSources() {
    const s = [];
    if (srcStealer && srcStealer.checked) s.push('stealerlogs');
    if (srcComb && srcComb.checked) s.push('comb');
    if (srcXon && srcXon.checked) s.push('xposedornot');
    return s;
  }
  [srcStealer, srcComb, srcXon].forEach(cb => { if (cb) cb.addEventListener('change', syncSourceBar); });
  syncSourceBar();

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
        <div class="exp-origin" data-label="Origin" title="${esc(h.origin || '')}">${esc(h.origin || '—')}</div>
        <div class="exp-cell" data-label="Login" title="${esc(h.login || '')}">${esc(h.login || '—')}</div>
        <div class="exp-cell pw" data-label="Password" title="${esc(h.password || '')}">${esc(h.password || '—')}</div>
        <div class="exp-cell posted" data-label="Posted" title="${esc(h.posted || '')}">${esc(h.posted || '—')}</div>
        <div data-label="Source"><span class="exp-badge ${h.source ? 'hit' : ''}">${esc(h.source || '—')}</span></div>
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
    const sources = selectedSources();
    if (!sources.length) { showError('Select at least one source.', 'Toggle a source above to search.'); return; }
    scanBtn.disabled = true;
    progressBlock.classList.add('show');
    resultsBlock.classList.remove('show');
    logBlock.innerHTML = '';
    setProgress(8, 'Checking session...');
    log(`Target: ${email}`, 'ok');
    log(`Sources: ${sources.join(', ')}`, 'ok');

    const merged = [];
    const errors = [];
    const usedSources = [];
    let totalInIndex = 0;
    let stealerTotal = 0;

    // --- StealerLogs (existing endpoint) ---
    if (sources.includes('stealerlogs')) {
      usedSources.push('StealerLogs');
      setProgress(24, 'Querying stealer-log index...');
      log('Requesting stealer-log hits...', 'ok');
      try {
        const res = await fetch('/api/stealer-check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email }),
        });
        const text = await res.text();
        let data;
        try { data = JSON.parse(text); } catch { throw new Error(text.slice(0, 160) || 'Invalid server response'); }
        if (res.ok && !data.error) {
          const hits = Array.isArray(data.hits) ? data.hits : [];
          hits.forEach(h => merged.push({ origin: h.origin, login: h.login, password: h.password, posted: h.posted, source: h.source }));
          stealerTotal = Number(data.total) || 0;
          totalInIndex += stealerTotal;
          log(`StealerLogs: ${hits.length} hit(s)`, hits.length ? 'hit' : 'ok');
        } else {
          const msg = data.error || `HTTP ${res.status}`;
          errors.push(`StealerLogs: ${msg}`);
          log(`StealerLogs: ${msg}`, 'err');
        }
      } catch (e) {
        errors.push(`StealerLogs: ${e.message || 'failed'}`);
        log(`StealerLogs failed: ${e.message || 'failed'}`, 'err');
      }
    }

    // --- COMB + XposedOrNot (new endpoint) ---
    const extSources = sources.filter(s => s === 'comb' || s === 'xposedornot');
    if (extSources.length) {
      setProgress(55, 'Querying breach sources...');
      log('Requesting breach-source hits...', 'ok');
      try {
        const res = await fetch('/api/exposure-sources', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, sources: extSources }),
        });
        const text = await res.text();
        let data;
        try { data = JSON.parse(text); } catch { throw new Error(text.slice(0, 160) || 'Invalid server response'); }
        if (res.ok && !data.error && Array.isArray(data.hits)) {
          data.hits.forEach(h => merged.push({ origin: h.origin, login: h.login, password: h.password, posted: h.posted, source: h.source, breaches: h.breaches }));
          if (data.results && data.results.comb && data.results.comb.ok) totalInIndex += Number(data.results.comb.total) || 0;
          if (data.results && data.results.xposedornot && data.results.xposedornot.ok) totalInIndex += Number(data.results.xposedornot.total) || 0;
          if (extSources.includes('comb')) { const c = data.results && data.results.comb; log(`ProxyNova COMB: ${c && c.ok ? c.hitCount : 0} credential(s)`, 'ok'); }
          if (extSources.includes('xposedornot')) { const x = data.results && data.results.xposedornot; log(`XposedOrNot: ${x && x.ok ? x.total : 0} breach(es)`, 'ok'); }
        } else if (res.status === 401) {
          errors.push(`Breach sources: ${data.error || 'Login required'}`);
          log(`Breach sources: ${data.error || 'Login required'}`, 'err');
        } else if (res.status === 429) {
          errors.push(`Breach sources: ${data.error || 'Rate limited'}`);
          log(`Breach sources: ${data.error || 'Rate limited'}`, 'err');
        } else {
          errors.push(`Breach sources: ${data.error || ('HTTP ' + res.status)}`);
          log(`Breach sources: ${data.error || ('HTTP ' + res.status)}`, 'err');
        }
      } catch (e) {
        errors.push(`Breach sources: ${e.message || 'failed'}`);
        log(`Breach sources failed: ${e.message || 'failed'}`, 'err');
      }
    }

    // --- assemble results ---
    setProgress(85, 'Processing results...');
    currentHits = merged;
    currentFilter = 'all';
    setFilter('all');
    target.textContent = san(email, 254);
    foundCount.textContent = String(merged.length);
    const totalVal = totalInIndex > 0 ? totalInIndex : merged.length;
    totalCount.textContent = String(totalVal);

    if (merged.length === 0) {
      meta.textContent = errors.length
        ? `No hits returned${errors.length ? ' · ' + errors.length + ' source error(s)' : ''}.`
        : 'No publicly indexed hits found for this address across the selected sources.';
    } else {
      const srcs = [...new Set(merged.map(h => h.source).filter(Boolean))].slice(0, 4);
      meta.textContent = `${merged.length} hit${merged.length > 1 ? 's' : ''} found${srcs.length ? ' · ' + srcs.join(', ') : ''}`;
    }
    if (errors.length) log(`Note: ${errors.length} source(s) reported issues.`, 'err');
    setProgress(100, 'Complete');
    log(`Done: ${merged.length} hit(s) across ${usedSources.join(', ') || 'sources'}`, merged.length ? 'hit' : 'ok');
    resultsBlock.classList.add('show');
    saveHistory({ email, hits: merged.length, total: totalInIndex, ts: Date.now() });
    loadHistory();
    scanBtn.disabled = false;
  }

  scanBtn.addEventListener('click', runSearch);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); runSearch(); } });

  function renderHashResult(data) {
    hashResult.classList.add('show');
    let html = '';
    if (data.found && data.pass) {
      html += `<div class="hash-result-row"><div class="hash-result-label">Type</div><div class="hash-result-val">${esc(data.type || 'unknown')}</div></div>`;
      html += `<div class="hash-result-row"><div class="hash-result-label">Hash</div><div class="hash-result-val">${esc(data.hash || '')}</div></div>`;
      html += `<div class="hash-result-row"><div class="hash-result-label">Plaintext</div><div class="hash-result-val">${esc(data.pass)}</div></div>`;
    } else {
      html += `<div class="hash-result-row"><div class="hash-result-label">Result</div><div class="hash-result-val">${esc(data.detail || (data.status === 'not_found' ? 'No plaintext found for this hash.' : 'Lookup failed.'))}</div></div>`;
      if (data.type) html += `<div class="hash-result-row"><div class="hash-result-label">Type</div><div class="hash-result-val">${esc(data.type)}</div></div>`;
    }
    hashResult.innerHTML = html;
  }

  async function runHashLookup() {
    clearError();
    const hash = String(hashInput.value || '').trim();
    if (!hash) { showError('Enter a hash to look up.', 'MD5 / NTLM / SHA1 / SHA256 supported.'); return; }
    hashBtn.disabled = true;
    hashResult.classList.remove('show');
    hashResult.innerHTML = '<div class="hash-result-row"><div class="hash-result-label">Status</div><div class="hash-result-val">Looking up…</div></div>';
    hashResult.classList.add('show');
    try {
      const res = await fetch('/api/exposure-sources', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash }),
      });
      const text = await res.text();
      let data;
      try { data = JSON.parse(text); } catch { throw new Error(text.slice(0, 160) || 'Invalid server response'); }
      if (res.ok && !data.error) {
        renderHashResult(data);
      } else {
        const msg = data.error || `HTTP ${res.status}`;
        if (res.status === 401) showError(msg, 'Please login with Discord first.');
        else if (res.status === 429) showError(msg, 'Please wait a moment and try again.');
        else showError(msg, 'Try again in a moment.');
        hashResult.classList.remove('show');
      }
    } catch (e) {
      showError(e.message || 'Hash lookup failed', 'Check your connection and try again.');
      hashResult.classList.remove('show');
    } finally {
      hashBtn.disabled = false;
    }
  }

  hashBtn.addEventListener('click', runHashLookup);
  hashInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); runHashLookup(); } });

  $('exposureBtnNew').addEventListener('click', () => {
    resultsBlock.classList.remove('show');
    progressBlock.classList.remove('show');
    hashResult.classList.remove('show');
    hashResult.innerHTML = '';
    hashInput.value = '';
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

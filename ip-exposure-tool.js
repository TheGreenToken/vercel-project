(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const CTRL_RE = /[^\x20-\x7E -￿]/g;
  function san(str, max) { return String(str || '').replace(CTRL_RE, '').slice(0, max || 200); }
  function esc(str) { return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;'); }

  const input = $('ipExposureInput');
  const scanBtn = $('ipExposureScanBtn');
  const progressBlock = $('ipExposureProgressBlock');
  const statusText = $('ipExposureStatusText');
  const pctText = $('ipExposurePctText');
  const progressFill = $('ipExposureProgressFill');
  const subFill = $('ipExposureSubFill');
  const logBlock = $('ipExposureLogBlock');
  const errorBlock = $('ipExposureErrorBlock');
  const errorMsg = $('ipExposureErrorMsg');
  const errorHint = $('ipExposureErrorHint');
  const resultsBlock = $('ipExposureResultsBlock');
  const target = $('ipExposureTarget');
  const meta = $('ipExposureMeta');
  const foundCount = $('ipExposureFoundCount');
  const totalCount = $('ipExposureTotalCount');
  const resultsCount = $('ipExposureResultsCount');
  const tableBody = $('ipExposureTableBody');

  let currentHits = [];
  let currentFilter = 'all';
  let currentIp = '';

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

  function validateIp(v) {
    const s = String(v || '').trim().slice(0, 64);
    if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(s)) return s;
    if (/^[0-9a-fA-F:]+$/.test(s) && s.indexOf(':') >= 0) return s.toLowerCase();
    return '';
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
      const btn = $('ipExposureFilter' + name);
      if (!btn) return;
      const map = { All: 'all', Origin: 'origin', Source: 'source' };
      btn.classList.toggle('active', map[name] === f);
    });
    renderResults();
  }

  $('ipExposureFilterAll').addEventListener('click', () => setFilter('all'));
  $('ipExposureFilterOrigin').addEventListener('click', () => setFilter('origin'));
  $('ipExposureFilterSource').addEventListener('click', () => setFilter('source'));

  async function runSearch() {
    clearError();
    const ip = validateIp(input.value);
    if (!ip) { showError('Enter a valid IPv4 or IPv6 address.', 'Example: 8.8.8.8'); return; }
    currentIp = ip;
    scanBtn.disabled = true;
    progressBlock.classList.add('show');
    resultsBlock.classList.remove('show');
    logBlock.innerHTML = '';
    setProgress(8, 'Checking session...');
    log(`Target: ${ip}`, 'ok');
    try {
      setProgress(30, 'Querying exposure index...');
      log('Requesting IP exposure search results...', 'ok');
      let fake = 30;
      const timer = setInterval(() => { fake = Math.min(80, fake + 2); setProgress(fake, 'Looking up hits...'); }, 700);
      let res, text;
      try {
        res = await fetch('/api/ip-exposure', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip }),
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
      target.textContent = san(ip, 64);
      foundCount.textContent = String(data.hitCount ?? currentHits.length);
      const totalVal = Number(data.total) > 0 ? data.total : (data.hitCount ?? currentHits.length);
      totalCount.textContent = String(totalVal);
      const sources = [...new Set(currentHits.map(h => h.source).filter(Boolean))].slice(0, 4);
      if (data.status === 'not_found' || currentHits.length === 0) {
        meta.textContent = 'No publicly indexed stealer-log hits found for this IP.';
      } else {
        meta.textContent = `${currentHits.length} hit${currentHits.length>1?'s':''} found${sources.length ? ' · sources: ' + sources.join(', ') : ''}`;
      }
      setProgress(100, 'Complete');
      log(`Done: ${currentHits.length} hit(s) in ${data.durationMs}ms`, currentHits.length ? 'hit' : 'ok');
      resultsBlock.classList.add('show');
      try { window.dispatchEvent(new CustomEvent('mono:lookup-done', { detail: { tool: 'ip_exposure', query: ip, status: data.status } })); } catch (_) {}
    } catch (e) {
      showError(e.message || 'IP exposure search failed', 'Check your connection and try again.');
      setProgress(100, 'Failed');
    } finally {
      scanBtn.disabled = false;
    }
  }

  scanBtn.addEventListener('click', runSearch);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); runSearch(); } });

  $('ipExposureBtnNew').addEventListener('click', () => {
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
  $('ipExposureBtnCopy').addEventListener('click', () => {
    const lines = currentHits.map(h => `${h.origin}\t${h.login}\t${h.password}\t${h.posted}\t${h.source}`);
    copyText(lines.join('\n'), 'ipExposureLblCopy');
  });
  $('ipExposureBtnTxt').addEventListener('click', () => {
    const lines = [`IP: ${currentIp}`, `Hits: ${currentHits.length}`, `In index: ${totalCount.textContent}`, '', ...currentHits.map(h=>`${h.origin}\t${h.login}\t${h.password}\t${h.posted}\t${h.source}`)];
    const blob = new Blob([lines.join('\n')], {type:'text/plain'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-ip-exposure-${currentIp.replace(/[^a-z0-9]/gi,'_')}.txt`; a.click(); URL.revokeObjectURL(a.href);
  });
  $('ipExposureBtnJson').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify({ip:currentIp, total: totalCount.textContent, hits:currentHits}, null, 2)], {type:'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-ip-exposure-${currentIp.replace(/[^a-z0-9]/gi,'_')}.json`; a.click(); URL.revokeObjectURL(a.href);
  });
  $('ipExposureBtnCsv').addEventListener('click', () => {
    const escCsv = (v) => '"' + String(v||'').replace(/"/g,'""') + '"';
    const rows = [['origin','login','password','posted','source'], ...currentHits.map(h=>[h.origin,h.login,h.password,h.posted,h.source])];
    const blob = new Blob([rows.map(r=>r.map(escCsv).join(',')).join('\n')], {type:'text/csv'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-ip-exposure-${currentIp.replace(/[^a-z0-9]/gi,'_')}.csv`; a.click(); URL.revokeObjectURL(a.href);
  });
})();

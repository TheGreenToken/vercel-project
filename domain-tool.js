(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const CTRL_RE = /[^\x20-\x7E -￿]/g;
  function san(str, max) { return String(str || '').replace(CTRL_RE, '').slice(0, max || 200); }
  function esc(str) { return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;'); }

  const input = $('domainInput');
  const scanBtn = $('domainScanBtn');
  const progressBlock = $('domainProgressBlock');
  const statusText = $('domainStatusText');
  const pctText = $('domainPctText');
  const progressFill = $('domainProgressFill');
  const logBlock = $('domainLogBlock');
  const errorBlock = $('domainErrorBlock');
  const errorMsg = $('domainErrorMsg');
  const errorHint = $('domainErrorHint');
  const resultsBlock = $('domainResultsBlock');
  const target = $('domainTarget');
  const meta = $('domainMeta');
  const resultsCount = $('domainResultsCount');
  const gridBody = $('domainGridBody');
  const stat1 = $('domainStat1');
  const stat2 = $('domainStat2');

  let currentData = null;
  let currentQuery = '';

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

  function validateDomain(v) {
    const q = String(v || '').trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
    if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(q)) return '';
    return q;
  }

  function val(v) { return (v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length)) ? '—' : esc(v); }

  function buildCells(d) {
    const w = d.whois || {};
    const ce = d.cert || {};
    const dn = d.dns || {};
    const cells = [];
    const push = (label, value, cls) => cells.push({ label, value: val(value), cls: cls || '' });

    push('Domain', d.domain);
    push('Registrar', w.registrar);
    push('Status', (w.status && w.status.length) ? w.status.join(', ') : '—', 'dim');
    push('Registered', (w.events && w.events.registration) ? String(w.events.registration).slice(0, 10) : '—');
    push('Expires', (w.events && w.events.expiration) ? String(w.events.expiration).slice(0, 10) : '—');
    push('Updated', (w.events && w.events['last changed']) ? String(w.events['last changed']).slice(0, 10) : '—');
    push('Nameservers', (w.nameservers && w.nameservers.length) ? w.nameservers.join(', ') : '—', 'mono-break');
    push('DNSSEC', w.secureDNS && w.secureDNS.delegationSigned ? 'enabled' : 'disabled', w.secureDNS && w.secureDNS.delegationSigned ? 'dim' : '');
    push('A Records', (dn.A && dn.A.length) ? dn.A.join(', ') : '—', 'mono-break');
    push('AAAA Records', (dn.AAAA && dn.AAAA.length) ? dn.AAAA.join(', ') : '—', 'mono-break');
    push('MX Records', (dn.MX && dn.MX.length) ? dn.MX.join(', ') : '—', 'mono-break');
    push('TXT Records', (dn.TXT && dn.TXT.length) ? dn.TXT.slice(0, 3).join(' | ') : '—', 'mono-break');
    push('Cert Issuer', ce.issuer);
    push('Cert Validity', (ce.validFrom && ce.validTo) ? ce.validFrom + ' → ' + ce.validTo : '—');
    return cells;
  }

  function renderResults() {
    const d = currentData;
    if (!d) { gridBody.innerHTML = ''; resultsCount.textContent = ''; return; }
    const cells = buildCells(d);
    gridBody.innerHTML = '';
    cells.forEach(c => {
      const cell = document.createElement('div');
      cell.className = 'ip-cell';
      cell.innerHTML = `
        <div class="ip-cell-label">${esc(c.label)}</div>
        <div class="ip-cell-val ${c.cls}">${c.value}</div>
      `;
      gridBody.appendChild(cell);
    });

    const ce = d.cert || {};
    const dn = d.dns || {};
    const sub = ce.subdomains || [];
    const subcell = document.createElement('div');
    subcell.className = 'ip-cell';
    subcell.style.gridColumn = '1/-1';
    subcell.innerHTML = `
      <div class="ip-cell-label">Subdomains (CT logs)</div>
      <div class="badge-row">${sub.length ? sub.map(s => '<span class="badge">' + esc(s) + '</span>').join('') : '<span class="ip-cell-val dim">none found</span>'}</div>
    `;
    gridBody.appendChild(subcell);

    resultsCount.textContent = `${cells.length} fields · ${sub.length} subdomains`;
  }

  async function runLookup() {
    clearError();
    const domain = validateDomain(input.value);
    if (!domain) { showError('Enter a valid domain.', 'Example: example.com'); return; }
    currentQuery = domain;
    scanBtn.disabled = true;
    progressBlock.classList.add('show');
    resultsBlock.classList.remove('show');
    logBlock.innerHTML = '';
    setProgress(8, 'Checking session...');
    log(`Target: ${domain}`, 'ok');
    try {
      setProgress(30, 'Querying RDAP / DNS / certificates...');
      log('Resolving registration + DNS + certificates...', 'ok');
      let fake = 30;
      const timer = setInterval(() => { fake = Math.min(85, fake + 4); setProgress(fake, 'Aggregating results...'); }, 600);
      let res, text;
      try {
        res = await fetch('/api/domain-lookup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain }),
        });
        text = await res.text();
      } finally { clearInterval(timer); }
      setProgress(90, 'Processing results...');
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
      target.textContent = san(domain, 253);
      const w = data.whois || {};
      const ce = data.cert || {};
      meta.textContent = [w.registrar ? 'Registrar: ' + w.registrar : '', data.dns && (data.dns.A.length || data.dns.AAAA.length) ? (data.dns.A[0] || data.dns.AAAA[0]) : 'No IP', ce.subdomains ? ce.subdomains.length + ' subdomains' : ''].filter(Boolean).join(' · ');
      stat1.textContent = w.registrar || '—';
      stat2.textContent = ce.subdomains ? ce.subdomains.length : '—';
      setProgress(100, 'Complete');
      log(`Done: ${data.status} in ${data.durationMs}ms`, 'hit');
      renderResults();
      resultsBlock.classList.add('show');
    } catch (e) {
      showError(e.message || 'Domain lookup failed', 'Check your connection and try again.');
      setProgress(100, 'Failed');
    } finally {
      scanBtn.disabled = false;
    }
  }

  scanBtn.addEventListener('click', runLookup);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); runLookup(); } });

  $('domainBtnNew').addEventListener('click', () => {
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
  $('domainBtnCopy').addEventListener('click', () => {
    if (!currentData) return;
    const lines = buildCells(currentData).map(c => `${c.label}\t${c.value}`);
    copyText(lines.join('\n'), 'domainLblCopy');
  });
  $('domainBtnTxt').addEventListener('click', () => {
    if (!currentData) return;
    const lines = [`Domain: ${currentQuery}`, `Status: ${currentData.status}`, '', ...buildCells(currentData).map(c => `${c.label}\t${c.value}`)];
    const blob = new Blob([lines.join('\n')], {type:'text/plain'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-domain-${currentQuery.replace(/[^a-z0-9]/gi,'_')}.txt`; a.click(); URL.revokeObjectURL(a.href);
  });
  $('domainBtnJson').addEventListener('click', () => {
    if (!currentData) return;
    const blob = new Blob([JSON.stringify(currentData, null, 2)], {type:'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-domain-${currentQuery.replace(/[^a-z0-9]/gi,'_')}.json`; a.click(); URL.revokeObjectURL(a.href);
  });
})();

(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const CTRL_RE = /[^\x20-\x7E -￿]/g;
  function san(str, max) { return String(str || '').replace(CTRL_RE, '').slice(0, max || 200); }
  function esc(str) { return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;'); }

  // ---- IP / Host Lookup tool ----
  const input = $('ipInput');
  const scanBtn = $('ipScanBtn');
  const progressBlock = $('ipProgressBlock');
  const statusText = $('ipStatusText');
  const pctText = $('ipPctText');
  const progressFill = $('ipProgressFill');
  const subFill = $('ipSubFill');
  const logBlock = $('ipLogBlock');
  const errorBlock = $('ipErrorBlock');
  const errorMsg = $('ipErrorMsg');
  const errorHint = $('ipErrorHint');
  const resultsBlock = $('ipResultsBlock');
  const target = $('ipTarget');
  const meta = $('ipMeta');
  const ipValue = $('ipValue');
  const ipType = $('ipType');
  const resultsCount = $('ipResultsCount');
  const ipGridBody = $('ipGridBody');
  const mapPin = $('ipMapPin');
  const mapEmpty = $('ipMapEmpty');
  const mapOverlay = $('ipMapOverlay');
  const pinLabel = $('ipPinLabel');
  const cdnNote = $('ipCdnNote');
  const ipCountry = $('ipCountry');

  // Equirectangular projection (viewBox 1000x500): map lat/lon to %.
  function project(lat, lon) {
    const x = ((Number(lon) + 180) / 360) * 100;
    const y = ((90 - Number(lat)) / 180) * 100;
    return { x: Math.max(0, Math.min(100, x)), y: Math.max(0, Math.min(100, y)) };
  }

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

  function validateQuery(v) {
    const q = String(v || '').trim().slice(0, 253);
    if (!q) return '';
    if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(q)) return q;
    if (/^[0-9a-fA-F:]+$/.test(q) && q.indexOf(':') >= 0) return q;
    if (/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/.test(q)) return q;
    return '';
  }

  // Small inline icon per field label (keeps it monochrome, on-theme).
  const IP_ICONS = {
    'IP Address': '&#9679;',
    'All IPs': '&#9679;',
    'CDN / Edge': '&#9675;',
    'Type': '&#9670;',
    'Country': '&#9680;',
    'Region': '&#9680;',
    'City': '&#9678;',
    'Coordinates': '&#9681;',
    'Timezone': '&#9681;',
    'ISP': '&#9677;',
    'Organization': '&#9677;',
    'ASN': '&#9679;',
    'AS Name': '&#9679;',
    'Reverse DNS': '&#9673;',
  };
  function iconFor(k) { return IP_ICONS[k] ? '<span class="ic">' + IP_ICONS[k] + '</span>' : ''; }

  // Returns array of cell objects: { label, value, cls, big }
  function buildCells(d) {
    const g = d.geo || {};
    const cells = [];
    const push = (label, value, cls, big) => cells.push({ label, value, cls: cls || '', big: !!big });

    push('IP Address', d.ip || '—', 'big', true);
    const allIps = Array.isArray(d.allIps) ? d.allIps : (d.ip ? [d.ip] : []);
    if (allIps.length > 1) {
      push('All IPs', allIps.length + ' resolved · ' + allIps.slice(0, 3).join(', ') + (allIps.length > 3 ? '…' : ''), 'dim mono-break');
    }
    if (d.cdn) push('CDN / Edge', d.cdn.cdn + ' · AS' + d.cdn.asn, 'dim');
    push('Type', (d.type || '—').toUpperCase());
    push('Country', [g.country, g.countryCode].filter(Boolean).join(' / ') || '—');
    push('Region', g.region || '—');
    push('City', [g.city, g.zip].filter(Boolean).join(', ') || '—');
    push('Coordinates', (g.lat != null && g.lon != null) ? g.lat + ', ' + g.lon : '—');
    push('Timezone', g.timezone || '—');
    push('ISP', g.isp || '—');
    push('Organization', g.org || '—');
    push('ASN', g.as || '—');
    if (g.asname) push('AS Name', g.asname, 'dim');
    const rev = Array.isArray(d.reverse) ? d.reverse.filter(Boolean) : [];
    push('Reverse DNS', rev.length ? rev.join(', ') : '—', 'mono-break');
    return cells;
  }

  function buildBadges(d) {
    const g = d.geo || {};
    const out = [];
    if (d.cdn) out.push('<span class="badge cdn">' + esc(d.cdn.cdn) + '</span>');
    if (g.hosting) out.push('<span class="badge hosting">hosting</span>');
    if (g.proxy) out.push('<span class="badge proxy">proxy/vpn</span>');
    if (g.mobile) out.push('<span class="badge mobile">mobile</span>');
    return out;
  }

  function renderResults() {
    const d = currentData;
    if (!d) { ipGridBody.innerHTML = ''; resultsCount.textContent = ''; return; }
    const g = d.geo || {};
    if (d.status === 'found' && g.lat != null && g.lon != null) {
      const p = project(g.lat, g.lon);
      mapPin.style.left = p.x + '%';
      mapPin.style.top = p.y + '%';
      const label = [g.city, g.country].filter(Boolean).join(' · ') || d.ip;
      pinLabel.textContent = san(label, 80);
      mapPin.classList.add('show');
      mapEmpty.style.display = 'none';
      const ov = [];
      ov.push('<div class="map-chip"><b>' + esc(g.lat) + ',' + esc(g.lon) + '</b></div>');
      if (d.cdn) ov.push('<div class="map-chip">' + esc(d.cdn.cdn) + '</div>');
      mapOverlay.innerHTML = ov.join('');
    } else {
      mapPin.classList.remove('show');
      mapEmpty.style.display = 'flex';
      mapOverlay.innerHTML = '';
    }
    if (d.cdn) {
      cdnNote.style.display = 'block';
      cdnNote.innerHTML = '<b>CDN edge</b> · This host resolves to <b>' + esc(d.cdn.cdn) + '</b> (AS' + esc(d.cdn.asn) + '). The location and ASN above describe the CDN edge, not the origin server — so multiple sites behind the same CDN share identical edge data. The distinguishing signals are the resolved IP(s) and reverse DNS.';
    } else {
      cdnNote.style.display = 'none';
      cdnNote.innerHTML = '';
    }
    const cells = buildCells(d);
    ipGridBody.innerHTML = '';
    cells.forEach(c => {
      const cell = document.createElement('div');
      cell.className = 'ip-cell';
      cell.innerHTML = `
        <div class="ip-cell-label">${iconFor(c.label)}${esc(c.label)}</div>
        <div class="ip-cell-val ${c.cls}${c.big ? ' big' : ''}">${esc(c.value)}</div>
      `;
      ipGridBody.appendChild(cell);
    });
    const badges = buildBadges(d);
    if (badges.length) {
      const bcell = document.createElement('div');
      bcell.className = 'ip-cell';
      bcell.style.gridColumn = '1/-1';
      bcell.innerHTML = '<div class="ip-cell-label">' + iconFor('Type') + 'Flags</div><div class="badge-row">' + badges.join('') + '</div>';
      ipGridBody.appendChild(bcell);
    }
    resultsCount.textContent = cells.length + ' fields';
  }

  async function runLookup() {
    clearError();
    const query = validateQuery(input.value);
    if (!query) { showError('Enter a valid IP address or hostname.', 'Example: 8.8.8.8 or example.com'); return; }
    currentQuery = query;
    scanBtn.disabled = true;
    progressBlock.classList.add('show');
    resultsBlock.classList.remove('show');
    logBlock.innerHTML = '';
    setProgress(8, 'Checking session...');
    log(`Target: ${query}`, 'ok');
    try {
      setProgress(30, 'Resolving target...');
      log('Resolving IP / hostname...', 'ok');
      let fake = 30;
      const timer = setInterval(() => { fake = Math.min(80, fake + 3); setProgress(fake, 'Querying geolocation...'); }, 600);
      let res, text;
      try {
        res = await fetch('/api/ip-lookup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query }),
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
      currentData = data;
      target.textContent = san(query, 253);
      ipValue.textContent = data.ip || '—';
      ipType.textContent = (data.type || '—').toUpperCase();
      ipCountry.textContent = (data.geo && data.geo.country) ? data.geo.country : '—';
      const g = data.geo || {};
      if (data.status === 'not_found') {
        meta.textContent = 'No DNS resolution found for this target.';
      } else if (data.status === 'found') {
        const allIps = Array.isArray(data.allIps) ? data.allIps : (data.ip ? [data.ip] : []);
        const bits = [g.country, g.city].filter(Boolean).slice(0, 2);
        let metaText = bits.length ? bits.join(' · ') + (g.isp ? ' · ' + g.isp : '') : 'Lookup complete';
        if (allIps.length > 1) metaText += ' · ' + allIps.length + ' IPs';
        if (data.cdn) metaText += ' · ' + data.cdn.cdn;
        meta.textContent = metaText;
      } else {
        meta.textContent = data.detail || 'Lookup complete';
      }
      setProgress(100, 'Complete');
      log(`Done: ${data.status} in ${data.durationMs}ms`, data.status === 'found' ? 'hit' : 'ok');
      renderResults();
      resultsBlock.classList.add('show');
    } catch (e) {
      showError(e.message || 'IP lookup failed', 'Check your connection and try again.');
      setProgress(100, 'Failed');
    } finally {
      scanBtn.disabled = false;
    }
  }

  scanBtn.addEventListener('click', runLookup);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); runLookup(); } });

  $('ipBtnNew').addEventListener('click', () => {
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
  $('ipBtnCopy').addEventListener('click', () => {
    if (!currentData) return;
    const lines = buildCells(currentData).map(c => `${c.label}\t${c.value}`);
    copyText(lines.join('\n'), 'ipLblCopy');
  });
  $('ipBtnTxt').addEventListener('click', () => {
    if (!currentData) return;
    const lines = [`Query: ${currentQuery}`, `IP: ${currentData.ip || '—'}`, `Status: ${currentData.status}`, '', ...buildCells(currentData).map(c => `${c.label}\t${c.value}`)];
    const blob = new Blob([lines.join('\n')], {type:'text/plain'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-ip-${currentQuery.replace(/[^a-z0-9]/gi,'_')}.txt`; a.click(); URL.revokeObjectURL(a.href);
  });
  $('ipBtnJson').addEventListener('click', () => {
    if (!currentData) return;
    const blob = new Blob([JSON.stringify(currentData, null, 2)], {type:'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-ip-${currentQuery.replace(/[^a-z0-9]/gi,'_')}.json`; a.click(); URL.revokeObjectURL(a.href);
  });
})();

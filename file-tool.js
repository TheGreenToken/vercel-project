(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const CTRL_RE = /[^\x20-\x7E -￿]/g;
  function san(str, max) { return String(str || '').replace(CTRL_RE, '').slice(0, max || 200); }
  function esc(str) { return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;').replace(/'/g,'&#x27;'); }

  const dropZone = $('fileDropZone');
  const fileInput = $('fileInput');
  const scanBtn = $('fileScanBtn');
  const progressBlock = $('fileProgressBlock');
  const statusText = $('fileStatusText');
  const pctText = $('filePctText');
  const progressFill = $('fileProgressFill');
  const logBlock = $('fileLogBlock');
  const errorBlock = $('fileErrorBlock');
  const errorMsg = $('fileErrorMsg');
  const errorHint = $('fileErrorHint');
  const resultsBlock = $('fileResultsBlock');
  const target = $('fileTarget');
  const meta = $('fileMeta');
  const resultsCount = $('fileResultsCount');
  const gridBody = $('fileGridBody');
  const stat1 = $('fileStat1');
  const stat2 = $('fileStat2');

  let currentData = null;
  let currentFile = null;

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

  function val(v) { return (v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length)) ? '—' : esc(v); }

  function setFile(file) {
    currentFile = file || null;
    if (!currentFile) {
      dropZone.classList.remove('has-file');
      const label = $('fileDropLabel');
      if (label) label.textContent = '// drop a file here or click to browse · images (EXIF) & PDFs';
      if (target) target.textContent = '';
      return;
    }
    dropZone.classList.add('has-file');
    const label = $('fileDropLabel');
    if (label) label.textContent = '✓ ' + san(file.name, 60) + ' · ' + (file.size / 1024).toFixed(1) + ' KB';
    if (target) target.textContent = san(file.name, 120);
  }

  function openPicker() { fileInput.click(); }

  function buildCells(d) {
    const cells = [];
    const push = (label, value, cls) => cells.push({ label, value: val(value), cls: cls || '' });
    push('Filename', d.filename, 'mono-break');
    push('MIME type', d.mimeType);
    push('File type', d.fileType);
    push('Extension', d.fileExt ? '.' + d.fileExt : '—');
    push('Size', d.sizeHuman);
    push('SHA-256', d.sha256, 'mono-break');
    const m = d.metadata || {};
    if (d.fileType === 'image' && m) {
      push('Camera Make', m.cameraMake);
      push('Camera Model', m.cameraModel);
      push('Lens', m.lens);
      push('Software', m.software);
      push('Artist / Author', m.artist);
      push('Copyright', m.copyright);
      push('Description', m.description, 'mono-break');
      push('Date Taken', m.dateTime);
      push('Date Digitized', m.dateTimeDigitized);
      push('Orientation', m.orientation);
      push('ISO', m.iso);
      push('Exposure', m.exposure);
      push('Aperture', m.aperture);
      push('Focal Length', m.focalLength);
      push('Flash', m.flash);
      push('Dimensions', m.dimensions);
      if (m.gpsMap) {
        push('GPS Latitude', m.latitude);
        push('GPS Longitude', m.longitude);
        push('GPS Altitude', m.gpsAltitude);
      } else if (m.latitude != null || m.longitude != null) {
        push('GPS Latitude', m.latitude);
        push('GPS Longitude', m.longitude);
      }
    } else if (d.fileType === 'pdf' && m) {
      push('Author', m.author);
      push('Title', m.title);
      push('Subject', m.subject);
      push('Keywords', m.keywords);
      push('Creator', m.creator);
      push('Producer', m.producer);
      push('Created', m.creationDate);
      push('Modified', m.modDate);
      push('Pages', m.pageCount);
      push('PDF Version', m.pdfVersion);
      push('Encrypted', m.encryption != null ? String(m.encryption) : '—');
    }
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

    const m = d.metadata || {};
    const extras = [];
    if (m.gpsMap) {
      const lat = m.latitude, lon = m.longitude;
      const mapLink = `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=15/${lat}/${lon}`;
      extras.push({ label: '📍 Open on Map', value: `<a class="map-link" href="${esc(mapLink)}" target="_blank" rel="noopener noreferrer">openstreetmap.org</a>`, html: true });
    }
    if (d.fileType === 'image' && !m.gpsMap) {
      // note when image has no location
    }
    extras.forEach(c => {
      const cell = document.createElement('div');
      cell.className = 'ip-cell';
      cell.style.gridColumn = '1/-1';
      cell.innerHTML = `
        <div class="ip-cell-label">${esc(c.label)}</div>
        <div class="ip-cell-val">${c.value}</div>
      `;
      gridBody.appendChild(cell);
    });

    const fieldCount = cells.length + extras.length;
    resultsCount.textContent = `${fieldCount} fields extracted`;
  }

  async function runExtract() {
    clearError();
    if (!currentFile) {
      showError('Choose a file first.', 'Drop an image or PDF, or click to browse.');
      return;
    }
    scanBtn.disabled = true;
    progressBlock.classList.add('show');
    resultsBlock.classList.remove('show');
    logBlock.innerHTML = '';
    setProgress(10, 'Reading file...');
    log(`Target: ${currentFile.name}`, 'ok');
    try {
      setProgress(35, 'Uploading & analyzing...');
      log('Extracting metadata from file...', 'ok');
      let fake = 35;
      const timer = setInterval(() => { fake = Math.min(85, fake + 4); setProgress(fake, 'Parsing metadata...'); }, 500);
      let res;
      try {
        const fd = new FormData();
        fd.append('file', currentFile, currentFile.name);
        res = await fetch('/api/file-metadata', { method: 'POST', body: fd });
      } finally { clearInterval(timer); }
      setProgress(90, 'Processing results...');
      let data;
      try { data = JSON.parse(await res.text()); } catch { throw new Error('Invalid server response'); }
      if (!res.ok || data.error) {
        const msg = data.error || `HTTP ${res.status}`;
        if (res.status === 401) showError(msg, 'Please login with Discord first.');
        else if (res.status === 429) showError(msg, 'Please wait a moment and try again.');
        else showError(msg, 'Try again in a moment.');
        setProgress(100, 'Failed');
        return;
      }
      currentData = data;
      target.textContent = san(data.filename, 120);
      const m = data.metadata || {};
      const bits = [data.fileType, data.sizeHuman];
      if (data.fileType === 'image' && m) bits.push(m.dimensions ? m.dimensions : 'image');
      if (data.fileType === 'pdf' && m) bits.push(m.pageCount + ' pages');
      if (m.gpsMap) bits.push('GPS tracked');
      meta.textContent = bits.filter(Boolean).join(' · ');
      stat1.textContent = data.fileType === 'image' ? 'Image' : data.fileType === 'pdf' ? 'PDF' : (data.fileType || '—');
      stat2.textContent = data.sizeHuman;
      setProgress(100, 'Complete');
      log(`Done: ${data.status} in ${data.durationMs}ms`, 'hit');
      renderResults();
      resultsBlock.classList.add('show');
      try { window.dispatchEvent(new CustomEvent('mono:lookup-done', { detail: { tool: 'file', query: data.filename, status: data.status } })); } catch (_) {}
    } catch (e) {
      showError(e.message || 'Metadata extraction failed', 'Check your connection and try again.');
      setProgress(100, 'Failed');
    } finally {
      scanBtn.disabled = false;
    }
  }

  // ---- file picker ----
  fileInput.addEventListener('change', (e) => {
    const f = e.target.files && e.target.files[0];
    if (f) setFile(f);
    fileInput.value = '';
  });

  // ---- drag & drop ----
  ['dragenter', 'dragover'].forEach(ev => {
    dropZone.addEventListener(ev, (e) => { e.preventDefault(); e.stopPropagation(); dropZone.classList.add('drag'); });
  });
  ['dragleave', 'drop'].forEach(ev => {
    dropZone.addEventListener(ev, (e) => { e.preventDefault(); e.stopPropagation(); dropZone.classList.remove('drag'); });
  });
  dropZone.addEventListener('drop', (e) => {
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) setFile(f);
  });
  dropZone.addEventListener('click', (e) => {
    // don't open picker if clicking a result link
    if (e.target.tagName === 'A') return;
    openPicker();
  });

  scanBtn.addEventListener('click', runExtract);

  $('fileBtnNew').addEventListener('click', () => {
    resultsBlock.classList.remove('show');
    progressBlock.classList.remove('show');
    clearError();
    setFile(null);
    dropZone.focus();
  });

  function copyText(text, lblId) {
    navigator.clipboard.writeText(text).then(() => {
      const el = $(lblId); if (!el) return; const old = el.textContent; el.textContent = 'Copied!'; setTimeout(() => el.textContent = old, 1400);
    }).catch(() => {});
  }
  $('fileBtnCopy').addEventListener('click', () => {
    if (!currentData) return;
    const lines = buildCells(currentData).map(c => `${c.label}\t${c.value}`);
    copyText(lines.join('\n'), 'fileLblCopy');
    if (window.monoUI) window.monoUI.flashBtn('fileLblCopy', 'Copied!');
  });
  $('fileBtnTxt').addEventListener('click', () => {
    if (!currentData) return;
    const lines = [
      `File: ${currentData.filename}`,
      `Type: ${currentData.fileType}`,
      `Size: ${currentData.sizeHuman}`,
      `SHA-256: ${currentData.sha256}`,
      '',
      ...buildCells(currentData).map(c => `${c.label}\t${c.value}`)
    ];
    const blob = new Blob([lines.join('\n')], {type:'text/plain'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-file-${currentData.filename.replace(/[^a-z0-9]/gi,'_')}.txt`; a.click(); URL.revokeObjectURL(a.href);
    if (window.monoUI) window.monoUI.toast('Downloaded TXT report');
  });
  $('fileBtnJson').addEventListener('click', () => {
    if (!currentData) return;
    const blob = new Blob([JSON.stringify(currentData, null, 2)], {type:'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-file-${currentData.filename.replace(/[^a-z0-9]/gi,'_')}.json`; a.click(); URL.revokeObjectURL(a.href);
    if (window.monoUI) window.monoUI.toast('Downloaded JSON report');
  });

  // support keyboard: Enter on dropzone opens picker
  dropZone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openPicker(); } });
})();

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
  const highlights = $('fileHighlights');
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
    // hash fingerprints
    if (d.hashes) {
      push('MD5', d.hashes.md5, 'mono-break');
      push('SHA-1', d.hashes.sha1, 'mono-break');
      push('SHA-256', d.hashes.sha256, 'mono-break');
      push('SHA-384', d.hashes.sha384, 'mono-break');
      push('SHA-512', d.hashes.sha512, 'mono-break');
      push('CRC32', d.hashes.crc32);
    }
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
    } else if ((d.fileType === 'office' || d.fileType === 'epub') && m) {
      push('Title', m.title);
      push('Author', m.author);
      push('Subject', m.subject);
      push('Keywords', m.keywords);
      push('Last Modified By', m.creator);
      push('Created', m.created);
      push('Modified', m.modified);
      push('Application', m.application);
      push('Company', m.company);
      push('Format', m.format);
    } else if (d.fileType === 'archive' && m) {
      push('File Count', m.fileCount);
      push('Total Uncompressed', m.totalUncompressedHuman);
      if (m.files && m.files.length) {
        push('Contents', m.files.map(f => f.name).join(', '), 'mono-break');
      }
    } else if (d.fileType === 'video' && m) {
      push('Duration', m.duration);
      push('Dimensions', m.dimensions);
      push('Video Codec', m.videoCodec);
      push('Audio Codec', m.audioCodec);
      push('Created', m.creationDate);
      push('Modified', m.modifiedDate);
      push('Timescale', m.timescale);
    } else if (d.fileType === 'audio' && m) {
      push('Format', m.format);
      push('Title', m.title);
      push('Artist', m.artist);
      push('Album', m.album);
      push('Album Artist', m.albumArtist);
      push('Year', m.year);
      push('Genre', m.genre);
      push('Track', m.track);
      push('Comment', m.comment);
    }
    return cells;
  }

  function renderResults() {
    const d = currentData;
    if (!d) { gridBody.innerHTML = ''; resultsCount.textContent = ''; highlights.innerHTML = ''; return; }
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

    // intelligence highlights
    highlights.innerHTML = '';
    if (d.highlights && d.highlights.length) {
      d.highlights.forEach(h => {
        const b = document.createElement('span');
        b.className = 'badge';
        b.textContent = san(h, 80);
        highlights.appendChild(b);
      });
    }

    // GPS map link
    const m = d.metadata || {};
    if (m.gpsMap) {
      const lat = m.latitude, lon = m.longitude;
      const mapLink = `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=15/${lat}/${lon}`;
      const cell = document.createElement('div');
      cell.className = 'ip-cell';
      cell.style.gridColumn = '1/-1';
      cell.innerHTML = `
        <div class="ip-cell-label">📍 Open on Map</div>
        <div class="ip-cell-val"><a class="map-link" href="${esc(mapLink)}" target="_blank" rel="noopener noreferrer">openstreetmap.org</a></div>
      `;
      gridBody.appendChild(cell);
    }

    // archive contents as badges
    if (d.fileType === 'archive' && m.files && m.files.length) {
      const cell = document.createElement('div');
      cell.className = 'ip-cell';
      cell.style.gridColumn = '1/-1';
      cell.innerHTML = `
        <div class="ip-cell-label">Archive Contents</div>
        <div class="badge-row">${m.files.map(f => '<span class="badge">' + esc(f.name) + '</span>').join('')}</div>
      `;
      gridBody.appendChild(cell);
    }

    const fieldCount = cells.length + (m.gpsMap ? 1 : 0) + (d.fileType === 'archive' && m.files && m.files.length ? 1 : 0);
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
      if (data.fileType === 'office' && m) bits.push(m.application || 'office doc');
      if (data.fileType === 'archive' && m) bits.push(m.fileCount + ' files');
      if (data.fileType === 'video' && m) bits.push(m.duration || 'video');
      if (data.fileType === 'audio' && m) bits.push(m.artist || 'audio');
      if (m.gpsMap) bits.push('GPS tracked');
      meta.textContent = bits.filter(Boolean).join(' · ');
      // type label for stats
      const typeLabel = { image:'Image', pdf:'PDF', office:'Office', epub:'EPUB', archive:'Archive', video:'Video', audio:'Audio', svg:'SVG', xml:'XML' }[data.fileType] || data.fileType || '—';
      stat1.textContent = typeLabel;
      stat2.textContent = data.sizeHuman;
      // thumbnail into the avatar slot
      const avatar = $('fileAvatar');
      if (data.thumbnail && avatar) {
        avatar.innerHTML = `<img src="${esc(data.thumbnail)}" alt="preview" style="width:100%;height:100%;object-fit:cover;border-radius:6px;" />`;
      }
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
    const avatar = $('fileAvatar');
    if (avatar) avatar.innerHTML = 'FILE';
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
  $('fileBtnCsv').addEventListener('click', () => {
    if (!currentData) return;
    const rows = [['Field', 'Value']];
    buildCells(currentData).forEach(c => rows.push([c.label, c.value.replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&#x27;/g,"'")]));
    const csv = rows.map(r => r.map(v => '"' + String(v).replace(/"/g, '""') + '"').join(',')).join('\n');
    const blob = new Blob([csv], {type:'text/csv'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `mono-file-${currentData.filename.replace(/[^a-z0-9]/gi,'_')}.csv`; a.click(); URL.revokeObjectURL(a.href);
    if (window.monoUI) window.monoUI.toast('Downloaded CSV report');
  });

  // support keyboard: Enter on dropzone opens picker
  dropZone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openPicker(); } });
})();

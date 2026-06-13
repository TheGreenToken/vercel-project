(function () {
  'use strict';

  const KEY_TOKEN    = 'antisec_auth_token';
  const KEY_UID      = 'antisec_discord_uid';
  const KEY_FAILS    = 'antisec_fails';
  const KEY_LOCK     = 'antisec_lock';
  const KEY_HISTORY  = 'antisec_scan_history';
  const HISTORY_MAX  = 10;
  const MAX_FAILS    = 5;
  const LOCK_MS      = 15 * 60 * 1000;
  const USERNAME_RE  = /^[a-zA-Z0-9-]{1,39}$/;
  const AVATAR_RE    = /^https:\/\/avatars\.githubusercontent\.com\//;
  const CTRL_RE      = /[^\x20-\x7E]/g;
  const DISCORD_ID_RE = /^\d{17,19}$/;

  function sanitize(str, max) {
    if (str === null || str === undefined) return '';
    return String(str).replace(CTRL_RE, '').slice(0, max || 512);
  }

  function sanitizeUsername(raw) {
    const s = String(raw || '').replace(/^@/, '').trim();
    if (!USERNAME_RE.test(s)) return null;
    return s;
  }

  function safeAvatar(url) {
    if (!url || !AVATAR_RE.test(url)) return '';
    return url;
  }

  function loadHistory() {
    try { return JSON.parse(localStorage.getItem(KEY_HISTORY) || '[]'); } catch { return []; }
  }

  function saveHistory(entries) {
    try { localStorage.setItem(KEY_HISTORY, JSON.stringify(entries)); } catch {}
  }

  function pushHistory(data) {
    const entries = loadHistory();
    const entry = {
      id:         Date.now(),
      login:      sanitize(data.user.login, 39),
      avatar:     safeAvatar(data.user.avatar),
      emailCount: data.emails.length,
      realCount:  data.emails.filter(e => !e.noreply).length,
      repoCount:  Number(data.repoCount) || 0,
      scannedAt:  Date.now(),
      data:       data,
    };
    const filtered = entries.filter(e => e.login !== entry.login);
    filtered.unshift(entry);
    saveHistory(filtered.slice(0, HISTORY_MAX));
    renderHistory();
  }

  function renderHistory() {
    const wrap = document.getElementById('historyList');
    if (!wrap) return;
    const entries = loadHistory();
    const section = document.getElementById('historySection');
    if (entries.length === 0) {
      wrap.innerHTML = '<div class="history-empty">// no scans yet</div>';
      if (section) section.style.display = 'none';
      return;
    }
    if (section) section.style.display = '';
    wrap.innerHTML = '';
    entries.forEach(function (e) {
      const row = document.createElement('div');
      row.className = 'history-row';
      row.title = 'Load scan for @' + e.login;
      row.innerHTML =
        '<img class="history-avatar" src="' + (e.avatar || '') + '" alt="" onerror="this.style.visibility=\'hidden\'">' +
        '<div class="history-info">' +
          '<span class="history-login">@' + sanitize(e.login, 39) + '</span>' +
          '<span class="history-meta">' + e.realCount + ' emails · ' + e.repoCount + ' repos</span>' +
        '</div>' +
        '<div class="history-time">' + timeAgo(e.scannedAt) + '</div>' +
        '<button class="history-rescan" title="Force new scan" type="button">↺</button>';

      const rescanBtn = row.querySelector('.history-rescan');
      if (rescanBtn) {
        rescanBtn.addEventListener('click', function (evt) {
          evt.stopPropagation();
          const input = document.getElementById('usernameInput');
          if (input) input.value = e.login;
          forcedRescan = true;
          document.getElementById('scanBtn')?.click();
        });
      }
      row.addEventListener('click', function () {
        scanResult   = e.data;
        activeFilter = 'all';
        hide('errorBlock');
        hide('progressBlock');
        const lb = document.getElementById('logBlock');
        if (lb) lb.innerHTML = '';
        renderResults(e.data);
        document.getElementById('resultsBlock')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
      wrap.appendChild(row);
    });
  }

  function timeAgo(ts) {
    const diff = Date.now() - ts;
    const mins = Math.floor(diff / 60000);
    if (mins < 1)  return 'just now';
    if (mins < 60) return mins + 'm ago';
    const hrs = Math.floor(mins / 60);
    if (hrs < 24)  return hrs + 'h ago';
    return Math.floor(hrs / 24) + 'd ago';
  }

  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = sanitize(value, 512);
  }

  function show(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add('show');
  }

  function hide(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove('show');
  }

  function showEl(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = '';
  }

  function hideEl(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
  }

  let failCount    = parseInt(localStorage.getItem(KEY_FAILS) || '0', 10);
  let lockUntil    = parseInt(localStorage.getItem(KEY_LOCK)  || '0', 10);
  let lockTimer    = null;
  let pendingUid   = localStorage.getItem(KEY_UID) || null;
  let scanResult   = null;
  let activeFilter = 'all';
  let scanDepth    = 'normal';
  let sortCol      = 'count';
  let sortDir      = 'desc';
  let forcedRescan = false;

  function getToken() {
    return localStorage.getItem(KEY_TOKEN) || null;
  }

  function isLoggedIn() {
    const t = getToken();
    if (!t) return false;
    try {
      const decoded   = atob(t.replace(/-/g, '+').replace(/_/g, '/'));
      const lastPipe  = decoded.lastIndexOf('|');
      const payload   = decoded.slice(0, lastPipe);
      const parts     = payload.split('|');
      if (parts.length !== 3) return false;
      const expiresAt = parseInt(parts[1], 10);
      if (Date.now() > expiresAt) { localStorage.removeItem(KEY_TOKEN); return false; }
    } catch { return false; }
    return true;
  }

  function showAuthError(msg, showRetry) {
    const el = document.getElementById('authError');
    if (!el) return;
    el.innerHTML = '';
    const text = document.createElement('div');
    text.textContent = sanitize(msg, 300);
    el.appendChild(text);
    if (showRetry) {
      const btn = document.createElement('button');
      btn.textContent = '↺ Try Again';
      btn.style.cssText = 'margin-top:10px;background:transparent;border:1px solid #2a0003;color:#e8000f;font-family:Share Tech Mono,monospace;font-size:0.58rem;letter-spacing:0.15em;padding:6px 14px;cursor:pointer;width:100%;';
      btn.addEventListener('click', function () { goStep(1); });
      el.appendChild(btn);
    }
    el.classList.add('show');
    el.style.animation = 'none';
    void el.offsetWidth;
    el.style.animation = 'shake 0.4s ease';
  }

  function clearAuthError() {
    hide('authError');
  }

  function showSuspended() {
    hideEl('step1'); hideEl('step2'); hideEl('step3');
    const steps = document.getElementById('authSteps');
    if (steps) steps.style.display = 'none';
    const box = document.getElementById('suspendedBox');
    if (box) { box.style.display = ''; }
  }

  function updateLockLabel() {
    const el = document.getElementById('attemptsLabel');
    if (!el) return;
    const remaining = MAX_FAILS - failCount;
    if (remaining <= 0) {
      const secs = Math.max(0, Math.ceil((lockUntil - Date.now()) / 1000));
      el.textContent = '// System locked — retry in ' + secs + 's';
    } else if (failCount > 0) {
      el.textContent = '// ' + remaining + ' attempt' + (remaining !== 1 ? 's' : '') + ' remaining';
    } else {
      el.textContent = '';
    }
  }

  let countdownTimer = null;

  function startConfirmCountdown() {
    const el = document.getElementById('confirmCountdown');
    if (!el) return;
    let secs = 10 * 60;
    if (countdownTimer) clearInterval(countdownTimer);
    function tick() {
      const m = Math.floor(secs / 60);
      const s = secs % 60;
      el.textContent = '// link expires in ' + m + ':' + String(s).padStart(2, '0');
      if (secs <= 0) {
        clearInterval(countdownTimer);
        el.textContent = '// link expired — please resend';
        el.style.color = '#e8000f';
        const resend = document.getElementById('resendBtn');
        if (resend) { resend.style.opacity = '1'; resend.style.borderColor = 'rgba(232,0,15,0.4)'; resend.style.color = '#e8000f'; }
      }
      secs--;
    }
    tick();
    countdownTimer = setInterval(tick, 1000);
  }

  function stopConfirmCountdown() {
    if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }
  }

  function updateStepDots(n) {
    for (let i = 1; i <= 2; i++) {
      const dot  = document.getElementById('stepDot' + i);
      const line = document.getElementById('stepLine' + i);
      if (dot) {
        dot.classList.remove('active', 'done');
        if (i < n)   dot.classList.add('done');
        if (i === n) dot.classList.add('active');
        const lbl = dot.parentElement?.querySelector('.auth-step-label');
        if (lbl) lbl.style.color = i === n ? 'rgba(232,0,15,0.55)' : '';
      }
      if (line) line.classList.toggle('done', i < n);
    }
  }

  function slideToStep(n) {
    const ids    = ['step1','step2','step3'];
    const current = ids.map(id => document.getElementById(id)).find(el => el && el.style.display !== 'none' && el.style.display !== '');
    const next   = document.getElementById('step' + n);
    if (!next) return;
    if (current && current !== next && current.style.display !== 'none') {
      current.style.transition = 'opacity 0.18s ease, transform 0.18s ease';
      current.style.opacity    = '0';
      current.style.transform  = 'translateX(-10px)';
      setTimeout(function () {
        current.style.display    = 'none';
        current.style.transition = '';
        current.style.opacity    = '';
        current.style.transform  = '';
        next.style.display       = '';
        next.style.opacity       = '0';
        next.style.transform     = 'translateX(10px)';
        requestAnimationFrame(function () {
          next.style.transition  = 'opacity 0.22s ease, transform 0.22s ease';
          next.style.opacity     = '1';
          next.style.transform   = 'translateX(0)';
          setTimeout(function () {
            next.style.transition = '';
            next.style.opacity    = '';
            next.style.transform  = '';
          }, 230);
        });
      }, 190);
    } else {
      hideEl('step1'); hideEl('step2'); hideEl('step3');
      showEl('step' + n);
    }
  }

  function goStep(n) {
    slideToStep(n);
    updateStepDots(n);
    clearAuthError();
    if (n === 1) {
      stopConfirmCountdown();
      setTimeout(function () { const el = document.getElementById('userIdInput'); if (el) { el.value = ''; el.focus(); } }, 320);
    }
    if (n === 2) startConfirmCountdown();
  }

  async function doVerify() {
    const uidEl = document.getElementById('userIdInput');
    const uid   = uidEl ? uidEl.value.trim() : '';
    if (!uid) { showAuthError('// Please enter your Discord User ID'); return; }
    if (!DISCORD_ID_RE.test(uid)) { showAuthError('// Invalid Discord User ID format'); return; }

    const btn      = document.getElementById('verifyBtn');
    const scanning = document.getElementById('authScanning');
    if (btn) btn.disabled = true;
    if (scanning) scanning.classList.add('show');
    clearAuthError();

    try {
      const res = await fetch('/api/verify', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', 'X-Request-Time': String(Date.now()) },
        body:    JSON.stringify({ userId: uid }),
      });
      let data;
      try { data = await res.json(); } catch { data = {}; }
      if (res.ok && data.ok === true) {
        localStorage.setItem(KEY_UID, uid);
        pendingUid = uid;
        goStep(2);
      } else if (data.suspended) {
        showSuspended();
      } else {
        showAuthError(sanitize(data.error || 'Requirements not met. Check your display name.', 400), true);
      }
    } catch {
      showAuthError('// Network error — cannot reach verification endpoint');
    } finally {
      if (scanning) scanning.classList.remove('show');
      if (btn) btn.disabled = false;
    }
  }

  function doConfirm() {
    if (!pendingUid) { goStep(1); return; }
    doLogin();
  }

  async function doLogin() {
    const uid = pendingUid || localStorage.getItem(KEY_UID);
    if (!uid) { showAuthError('// Session expired — please restart'); goStep(1); return; }

    const btn      = document.getElementById('checkConfirmBtn');
    const scanning = document.getElementById('authScanning');
    if (btn) btn.disabled = true;
    clearAuthError();
    if (scanning) scanning.classList.add('show');

    try {
      const res = await fetch('/api/auth', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', 'X-Request-Time': String(Date.now()) },
        body:    JSON.stringify({ userId: uid }),
      });
      let data;
      try { data = await res.json(); } catch { data = {}; }

      if (res.ok && data.ok === true && typeof data.token === 'string' && data.token.length > 0) {
        localStorage.setItem(KEY_TOKEN, data.token);
        localStorage.removeItem(KEY_UID);
        pendingUid = null;
        stopConfirmCountdown();
        const overlay = document.getElementById('authOverlay');
        if (overlay) {
          overlay.style.transition = 'opacity 0.5s ease';
          overlay.style.opacity = '0';
          setTimeout(() => overlay.classList.add('hidden'), 500);
        }
        updateAccountBar();
        renderHistory();
      } else {
        showAuthError(sanitize(data.error || 'Could not verify — did you click the DM link?', 300), true);
      }
    } catch {
      showAuthError('// Network error — cannot reach auth endpoint');
    } finally {
      if (scanning) scanning.classList.remove('show');
      if (btn) btn.disabled = false;
    }
  }

  async function doLogout() {
    stopConfirmCountdown();
    const token = getToken();
    if (token) {
      try {
        await fetch('/api/logout', {
          method:  'POST',
          headers: { 'X-Session-Token': token, 'X-Request-Time': String(Date.now()) },
        });
      } catch {}
    }
    localStorage.removeItem(KEY_TOKEN);
    localStorage.removeItem(KEY_UID);
    scanResult = null;
    hide('resultsBlock');
    hide('errorBlock');
    hide('progressBlock');
    const lb = document.getElementById('logBlock');
    const tb = document.getElementById('tableBody');
    if (lb) lb.innerHTML = '';
    if (tb) tb.innerHTML = '';
    updateProgress(0);
    updateAccountBar();
    const overlay = document.getElementById('authOverlay');
    if (overlay) {
      overlay.classList.remove('hidden');
      overlay.style.opacity = '1';
      overlay.style.transition = '';
    }
    goStep(1);
  }

  function updateAccountBar() {
    const bar = document.getElementById('accountBar');
    if (!bar) return;
    bar.style.display = isLoggedIn() ? 'flex' : 'none';
  }

  function appendLog(msg, type) {
    const el = document.getElementById('logBlock');
    if (!el) return;
    const d = document.createElement('div');
    d.className = 'log-line' + (type ? ' ' + type : '');
    d.textContent = '> ' + sanitize(msg, 200);
    el.appendChild(d);
    el.scrollTop = el.scrollHeight;
  }

  function updateProgress(pct, status) {
    const fill   = document.getElementById('progressFill');
    const sub    = document.getElementById('subFill');
    const pctEl  = document.getElementById('pctText');
    const statEl = document.getElementById('statusText');
    const safe   = Math.min(100, Math.max(0, Number(pct) || 0));
    if (fill)  fill.style.width  = safe + '%';
    if (sub)   sub.style.width   = Math.min(safe + 15, 100) + '%';
    if (pctEl) pctEl.textContent = safe + '%';
    if (status && statEl) statEl.textContent = sanitize(status, 100);
  }

  function showScanError(msg) {
    setText('errorMsg', msg);
    show('errorBlock');
    hide('progressBlock');
    const scanBtn = document.getElementById('scanBtn');
    if (scanBtn) scanBtn.disabled = false;
  }

  function resetScan() {
    hide('errorBlock');
    hide('resultsBlock');
    hide('progressBlock');
    const lb = document.getElementById('logBlock');
    const tb = document.getElementById('tableBody');
    if (lb) lb.innerHTML = '';
    if (tb) tb.innerHTML = '';
    updateProgress(0);
    const input = document.getElementById('usernameInput');
    if (input) input.value = '';
    const scanBtn = document.getElementById('scanBtn');
    if (scanBtn) scanBtn.disabled = false;
    scanResult   = null;
    activeFilter = 'all';
  }

  function togglePwVisibility() {
    const input = document.getElementById('pwInput');
    const btn   = document.getElementById('pwToggle');
    if (!input || !btn) return;
    const shown = input.type === 'text';
    input.type  = shown ? 'password' : 'text';
    btn.textContent = shown ? '○' : '●';
    btn.title = shown ? 'Show password' : 'Hide password';
  }

  function setDepth(d) {
    scanDepth = d;
    ['depthNormal', 'depthDeep'].forEach(function (id) {
      const btn = document.getElementById(id);
      if (btn) btn.classList.toggle('active', id === 'depth' + d.charAt(0).toUpperCase() + d.slice(1));
    });
  }

  function setSort(col) {
    if (sortCol === col) {
      sortDir = sortDir === 'desc' ? 'asc' : 'desc';
    } else {
      sortCol = col;
      sortDir = col === 'count' ? 'desc' : 'asc';
    }
    updateSortHeaders();
    if (scanResult) renderTable(scanResult.emails);
  }

  function updateSortHeaders() {
    const arrow = { asc: ' ↑', desc: ' ↓' };
    const colMap = { address: 'thAddress', count: 'thHits' };
    Object.entries(colMap).forEach(function ([col, id]) {
      const el = document.getElementById(id);
      if (!el) return;
      el.textContent = (col === 'address' ? 'Address' : 'Hits') + (sortCol === col ? arrow[sortDir] : '');
      el.classList.toggle('sort-active', sortCol === col);
    });
  }
  function updateDownloadLabels() {
    const count = getFilteredEmails().length;
    const lbl  = document.getElementById('lblTxt');
    const lbl3 = document.getElementById('lblCsv');
    if (lbl)  lbl.textContent  = count + ' Email' + (count !== 1 ? 's' : '') + ' (.txt)';
    if (lbl3) lbl3.textContent = count + ' Email' + (count !== 1 ? 's' : '') + ' (.csv)';
  }

  function setFilter(f) {
    activeFilter = f;
    ['filterAll', 'filterReal', 'filterSystem'].forEach(function (id) {
      const btn = document.getElementById(id);
      if (btn) btn.classList.toggle('active', id === 'filter' + f.charAt(0).toUpperCase() + f.slice(1));
    });
    if (scanResult) renderTable(scanResult.emails);
    updateDownloadLabels();
  }

  function renderTable(emails) {
    const tbody = document.getElementById('tableBody');
    if (!tbody) return;
    tbody.textContent = '';

    let filtered = emails.filter(function (item) {
      if (!item || typeof item.email !== 'string') return false;
      if (activeFilter === 'real')   return !item.noreply;
      if (activeFilter === 'system') return  item.noreply;
      return true;
    });

    filtered = filtered.slice().sort(function (a, b) {
      if (sortCol === 'address') {
        const cmp = a.email.localeCompare(b.email);
        return sortDir === 'asc' ? cmp : -cmp;
      }
      const cmp = (Number(b.count) || 0) - (Number(a.count) || 0);
      return sortDir === 'asc' ? -cmp : cmp;
    });

    if (filtered.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'table-empty';
      empty.textContent = '// no results for this filter';
      tbody.appendChild(empty);
      return;
    }

    filtered.forEach(function (item, i) {
      const row = document.createElement('div');
      row.className = 'row';
      row.style.animationDelay = (i * 0.03) + 's';

      const emailDiv = document.createElement('div');
      emailDiv.className = 'row-email' + (item.noreply ? ' dim' : '');
      emailDiv.textContent = sanitize(item.email, 254);
      if (item.noreply) {
        const tag = document.createElement('span');
        tag.className = 'tag-nr';
        tag.textContent = 'SYSTEM';
        emailDiv.appendChild(tag);
      }

      const nameDiv = document.createElement('div');
      nameDiv.className = 'row-name';
      nameDiv.textContent = sanitize(item.name, 100);

      const reposDiv = document.createElement('div');
      reposDiv.className = 'row-repos';
      const repoList = Array.isArray(item.repos) ? item.repos : [];
      reposDiv.textContent = repoList.map(r => sanitize(r, 100)).join(', ');

      const countDiv = document.createElement('div');
      const cnt = Number(item.count) || 0;
      countDiv.className = 'row-count' + (cnt >= 10 ? ' hot' : '');
      countDiv.textContent = String(cnt);

      row.appendChild(emailDiv);
      row.appendChild(nameDiv);
      row.appendChild(reposDiv);
      row.appendChild(countDiv);
      tbody.appendChild(row);
    });
  }

  async function doScan() {
    if (!isLoggedIn()) {
      const overlay = document.getElementById('authOverlay');
      if (overlay) { overlay.classList.remove('hidden'); overlay.style.opacity = '1'; }
      return;
    }

    const inputEl  = document.getElementById('usernameInput');
    const rawInput = inputEl ? inputEl.value.trim() : '';
    const username = sanitizeUsername(rawInput);

    if (!username) {
      showScanError('Invalid username — only letters, numbers and hyphens allowed (max 39 chars).');
      return;
    }

    const scanBtn = document.getElementById('scanBtn');
    if (scanBtn) scanBtn.disabled = true;
    hide('errorBlock');
    hide('resultsBlock');
    const lb = document.getElementById('logBlock');
    const tb = document.getElementById('tableBody');
    if (lb) lb.innerHTML = '';
    if (tb) tb.innerHTML = '';
    activeFilter = 'all';
    updateProgress(0);
    show('progressBlock');

    appendLog('Establishing connection to OSINT backend...');
    updateProgress(5, 'Verifying target...');

    try {
      appendLog('Sending target to server...', 'ok');
      updateProgress(10, 'Querying intelligence sources...');

      const sessionToken = getToken();
      let csrfToken = '';
      try {
        const csrfRes  = await fetch('/api/csrf', {
          method:  'GET',
          headers: { 'X-Session-Token': sessionToken, 'X-Request-Time': String(Date.now()) },
        });
        const csrfData = await csrfRes.json().catch(() => ({}));
        csrfToken = csrfData.csrfToken || '';
      } catch {}

      const isForced = forcedRescan;
      forcedRescan   = false;

      const res = await fetch('/api/scan', {
        method:  'POST',
        headers: {
          'Content-Type':    'application/json',
          'X-Session-Token': sessionToken,
          'X-CSRF-Token':    csrfToken,
          'X-Request-Time':  String(Date.now()),
          'X-Force-Refresh': isForced ? '1' : '0',
          'X-Scan-Depth':    scanDepth,
        },
        body: JSON.stringify({ username }),
      });

      updateProgress(40, 'Processing identity data...');
      appendLog('Response received. Parsing...', 'ok');

      let data;
      try { data = await res.json(); } catch { throw new Error('Server returned invalid data.'); }

      if (!res.ok) {
        if (res.status === 401 || res.status === 403) {
          if (data.tagRemoved) {
            showScanError(sanitize(data.error || 'Tag removed — role revoked.', 200));
            throw new Error(sanitize(data.error, 200));
          }
          localStorage.removeItem(KEY_TOKEN);
          updateAccountBar();
          const overlay = document.getElementById('authOverlay');
          if (overlay) { overlay.classList.remove('hidden'); overlay.style.opacity = '1'; }
          goStep(1);
          throw new Error(sanitize(data.error || 'Session expired — please log in again.', 200));
        }
        throw new Error(sanitize(data.error || 'Unknown error', 200));
      }

      if (!data || typeof data !== 'object' || typeof data.user !== 'object' || !Array.isArray(data.emails)) {
        throw new Error('Unexpected response format from server.');
      }

      updateProgress(85, 'Building report...');
      appendLog('Target confirmed: ' + sanitize(data.user.login, 39), 'ok');
      appendLog('Repositories indexed: ' + (Number(data.repoCount) || 0), 'hit');
      appendLog('Email addresses extracted: ' + data.emails.length, 'hit');
      if (data.limitReached) appendLog('Repo limit reached — results may be incomplete', 'err');

      scanResult = data;
      pushHistory(data);
      updateProgress(100, 'Complete.');

      setTimeout(function () {
        hide('progressBlock');
        renderResults(data);
      }, 600);

    } catch (err) {
      appendLog('Operation failed: ' + sanitize(err.message, 200), 'err');
      showScanError(sanitize(err.message, 300));
    }
  }

  function renderResults(data) {
    const user      = data.user      || {};
    const emails    = data.emails    || [];
    const repoCount = Number(data.repoCount) || 0;

    const pAvatar = document.getElementById('pAvatar');
    if (pAvatar) {
      pAvatar.src = safeAvatar(user.avatar);
      pAvatar.alt = sanitize(user.login, 39) + ' avatar';
    }

    const pLogin = document.getElementById('pLogin');
    if (pLogin) pLogin.textContent = sanitize(user.login, 39);

    const sEmails = document.getElementById('sEmails');
    if (sEmails) sEmails.textContent = String(emails.length);

    const sRepos = document.getElementById('sRepos');
    if (sRepos) sRepos.textContent = String(repoCount);

    const realCount   = emails.filter(e => !e.noreply).length;
    const systemCount = emails.filter(e =>  e.noreply).length;
    const rcEl = document.getElementById('resultsCount');
    if (rcEl) rcEl.textContent = realCount + ' real · ' + systemCount + ' system';

    const limitWarn = document.getElementById('limitWarning');
    if (limitWarn) limitWarn.style.display = data.limitReached ? '' : 'none';

    const metaParts = [user.name, user.company, user.location].filter(Boolean);
    const pMeta = document.getElementById('pMeta');
    if (pMeta) {
      pMeta.textContent = '';
      if (metaParts.length === 0) {
        pMeta.textContent = 'No public metadata';
      } else {
        metaParts.forEach(function (part, idx) {
          const span = document.createElement('span');
          span.textContent = sanitize(part, 100);
          pMeta.appendChild(span);
          if (idx < metaParts.length - 1) {
            const sep = document.createElement('span');
            sep.className = 'sep';
            sep.textContent = '·';
            pMeta.appendChild(sep);
          }
        });
      }
    }

    const fa = document.getElementById('filterAll');
    const fr = document.getElementById('filterReal');
    const fs = document.getElementById('filterSystem');
    if (fa) fa.classList.add('active');
    if (fr) fr.classList.remove('active');
    if (fs) fs.classList.remove('active');

    renderTable(emails);
    updateDownloadLabels();
    updateSortHeaders();
    show('resultsBlock');
    const scanBtn = document.getElementById('scanBtn');
    if (scanBtn) scanBtn.disabled = false;
  }

  function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = filename.replace(/[^a-zA-Z0-9._\-]/g, '_');
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Downloaded: ' + a.download);
  }

  function timestamp() {
    return new Date().toISOString().slice(0, 19).replace(/:/g, '-');
  }

  function scanTargetSlug() {
    return (scanResult && scanResult.user && scanResult.user.login)
      ? sanitize(scanResult.user.login, 39).replace(/[^a-zA-Z0-9\-]/g, '')
      : 'unknown';
  }

  function getFilteredEmails() {
    if (!scanResult) return [];
    return scanResult.emails.filter(function (e) {
      if (!e || typeof e.email !== 'string') return false;
      if (activeFilter === 'real')   return !e.noreply;
      if (activeFilter === 'system') return  e.noreply;
      return true;
    });
  }

  function downloadTxt() {
    if (!scanResult) return;
    const lines = getFilteredEmails().map(e => sanitize(e.email, 254)).join('\n');
    downloadFile(lines, 'antisec_emails_' + scanTargetSlug() + '_' + timestamp() + '.txt', 'text/plain');
    flashBtn('btnCopyEmails', '\u2714 Downloaded');
  }

  function downloadJson() {
    if (!scanResult) return;
    downloadFile(JSON.stringify(scanResult, null, 2), 'antisec_report_' + scanTargetSlug() + '_' + timestamp() + '.json', 'application/json');
    flashBtn('btnCopyJSON', '\u2714 Downloaded');
  }

  function downloadCsv() {
    if (!scanResult) return;
    const rows = [['email', 'name', 'count', 'noreply'].join(',')];
    getFilteredEmails().forEach(function (e) {
      const esc = v => '"' + String(v).replace(/"/g, '""') + '"';
      rows.push([esc(sanitize(e.email, 254)), esc(sanitize(e.name, 100)), Number(e.count) || 0, e.noreply ? 'true' : 'false'].join(','));
    });
    downloadFile(rows.join('\n'), 'antisec_emails_' + scanTargetSlug() + '_' + timestamp() + '.csv', 'text/csv');
    flashBtn('btnCopyCSV', '\u2714 Downloaded');
  }

  function showToast(msg) {
    const t = document.createElement('div');
    t.textContent = sanitize(msg, 100);
    Object.assign(t.style, {
      position: 'fixed', bottom: '80px', left: '50%', transform: 'translateX(-50%)',
      background: '#000', color: '#e8000f', padding: '8px 20px',
      fontFamily: 'Share Tech Mono,monospace', fontSize: '11px',
      border: '1px solid #e8000f', zIndex: '10000',
      letterSpacing: '1px', pointerEvents: 'none',
      maxWidth: '90vw', textAlign: 'center',
    });
    document.body.appendChild(t);
    setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 2000);
  }

  function flashBtn(btnId, label) {
    const btn = document.getElementById(btnId);
    if (!btn) return;
    const orig = btn.textContent;
    btn.textContent = label;
    setTimeout(function () { btn.textContent = orig; }, 2000);
  }

  window.addEventListener('DOMContentLoaded', function () {
    updateLockLabel();
    updateAccountBar();
    renderHistory();

    if (Date.now() < lockUntil) {
      showAuthError('// LOCKED — Retry after cooldown');
      updateLockLabel();
      if (!lockTimer) lockTimer = setInterval(updateLockLabel, 1000);
    }

    if (isLoggedIn()) {
      const overlay = document.getElementById('authOverlay');
      if (overlay) overlay.classList.add('hidden');
    } else {
      goStep(1);
    }

    document.getElementById('verifyBtn')?.addEventListener('click', doVerify);
    document.getElementById('userIdInput')?.addEventListener('keydown', e => { if (e.key === 'Enter') doVerify(); });

    const reqToggle = document.getElementById('reqToggle');
    const reqBody   = document.getElementById('reqBody');
    if (reqToggle && reqBody) {
      function toggleReq(e) {
        e.preventDefault();
        const open = reqBody.classList.toggle('open');
        reqToggle.classList.toggle('open', open);
      }
      reqToggle.addEventListener('click',    toggleReq);
      reqToggle.addEventListener('touchend', toggleReq, { passive: false });
    }
    document.getElementById('checkConfirmBtn')?.addEventListener('click', doConfirm);
    if (resendBtn) resendBtn.addEventListener('click', async () => {
      const uid = pendingUid || localStorage.getItem(KEY_UID);
      if (!uid) { goStep(1); return; }
      resendBtn.disabled = true;
      resendBtn.querySelector('span').textContent = '↺ Sending...';
      clearAuthError();
      try {
        const res = await fetch('/api/verify', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json', 'X-Request-Time': String(Date.now()) },
          body:    JSON.stringify({ userId: uid }),
        });
        let data;
        try { data = await res.json(); } catch { data = {}; }
        if (res.ok && data.ok) {
          resendBtn.querySelector('span').textContent = '✓ DM Sent!';
          setTimeout(() => { resendBtn.querySelector('span').textContent = '↺ Resend DM'; resendBtn.disabled = false; }, 5000);
        } else {
          showAuthError(sanitize(data.error || 'Could not resend DM.', 300));
          resendBtn.querySelector('span').textContent = '↺ Resend DM';
          resendBtn.disabled = false;
        }
      } catch {
        showAuthError('// Network error — could not resend DM');
        resendBtn.querySelector('span').textContent = '↺ Resend DM';
        resendBtn.disabled = false;
      }
    });

    document.getElementById('backBtn')?.addEventListener('click', () => {
      pendingUid = null;
      localStorage.removeItem(KEY_UID);
      goStep(1);
    });

    document.getElementById('logoutBtn')?.addEventListener('click', doLogout);
    document.getElementById('scanBtn')?.addEventListener('click', doScan);

    const usernameInput = document.getElementById('usernameInput');
    if (usernameInput) {
      usernameInput.addEventListener('keydown', e => { if (e.key === 'Enter') doScan(); });
      usernameInput.addEventListener('input', function () {
        this.value = this.value.replace(/[^a-zA-Z0-9\-@]/g, '');
      });
    }

    document.getElementById('filterAll')?.addEventListener('click',    () => setFilter('all'));
    document.getElementById('filterReal')?.addEventListener('click',   () => setFilter('real'));
    document.getElementById('filterSystem')?.addEventListener('click', () => setFilter('system'));

    document.getElementById('depthNormal')?.addEventListener('click', () => setDepth('normal'));
    document.getElementById('depthDeep')?.addEventListener('click',   () => setDepth('deep'));

    document.getElementById('thAddress')?.addEventListener('click', () => setSort('address'));
    document.getElementById('thHits')?.addEventListener('click',    () => setSort('count'));

    document.getElementById('btnCopyEmails')?.addEventListener('click', downloadTxt);
    document.getElementById('btnCopyJSON')?.addEventListener('click',   downloadJson);
    document.getElementById('btnCopyCSV')?.addEventListener('click',    downloadCsv);
    document.getElementById('btnNewScan')?.addEventListener('click',    resetScan);
  });

})();

(function () {
  'use strict';

  const KEY_HISTORY  = 'mono_scan_history';
  const AUTH_KEY     = 'mono_auth_token';
  const HISTORY_MAX  = 10;
  const USERNAME_RE  = /^[a-zA-Z0-9-]{1,39}$/;
  const AVATAR_RE    = /^https:\/\/(avatars\.githubusercontent\.com|cdn\.discordapp\.com)\//;
  const CTRL_RE      = /[^\x20-\x7E]/g;

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
    if (!url || !AVATAR_RE.test(String(url))) return '';
    return String(url);
  }

  function loadHistory() {
    try { return JSON.parse(localStorage.getItem(KEY_HISTORY) || '[]'); } catch { return []; }
  }

  function saveHistory(entries) {
    try { localStorage.setItem(KEY_HISTORY, JSON.stringify(entries)); } catch {}
  }

  function getAuthToken() {
    try { return localStorage.getItem(AUTH_KEY) || ''; } catch { return ''; }
  }
  function setAuthToken(token) {
    try {
      if (token) localStorage.setItem(AUTH_KEY, String(token));
      else localStorage.removeItem(AUTH_KEY);
    } catch {}
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
          const input = document.getElementById('githubInput');
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


  let scanResult   = null;
  let activeFilter = 'all';
  let scanDepth    = 'normal';
  let sortCol      = 'count';
  let sortDir      = 'desc';
  let forcedRescan = false;
  let currentUser  = null;

  function setAuthUI(user) {
    currentUser = user || null;
    const loginBtn  = document.getElementById('loginBtn');
    const userWrap  = document.getElementById('authUser');
    const avatar    = document.getElementById('authAvatar');
    const nameEl    = document.getElementById('authName');
    if (user) {
      if (loginBtn) loginBtn.hidden = true;
      if (userWrap) userWrap.classList.add('visible');
      if (avatar) {
        avatar.onerror = function () { avatar.style.visibility = 'hidden'; };
        avatar.onload = function () { avatar.style.visibility = 'visible'; };
        const src = safeAvatar(user.avatar);
        if (src) { avatar.style.visibility = 'visible'; avatar.src = src; }
        else { avatar.removeAttribute("src"); avatar.style.visibility = 'hidden'; }
        avatar.alt = "";
      }
      if (nameEl) nameEl.textContent = sanitize(user.username || user.handle || 'User', 100);
    } else {
      if (loginBtn) loginBtn.hidden = false;
      if (userWrap) userWrap.classList.remove('visible');
      if (avatar) avatar.removeAttribute('src');
      if (nameEl) nameEl.textContent = '';
    }
  }

  async function refreshAuth() {
    try {
      const res = await fetch('/api/auth/me', { credentials: 'include' });
      const data = await res.json().catch(() => ({}));
      if (data && data.authenticated && data.user) {
        if (data.token) setAuthToken(data.token);
        setAuthUI(data.user);
      } else {
        setAuthToken('');
        setAuthUI(null);
      }
    } catch {
      setAuthToken('');
      setAuthUI(null);
    }
  }

  async function doLogout() {
    try {
      const token = getAuthToken();
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
        headers: token ? { 'X-Session-Token': token } : {},
      });
    } catch {}
    setAuthToken('');
    setAuthUI(null);
    showToast('Logged out');
  }

  function handleAuthCallbackParams() {
    const params = new URLSearchParams(window.location.search);
    const err = params.get('auth_error');
    const ok = params.get('auth');
    if (err) showToast('Login failed: ' + sanitize(err, 60));
    if (ok === 'ok') showToast('Logged in with Discord');
    if (err || ok) {
      params.delete('auth_error');
      params.delete('auth');
      const next = window.location.pathname + (params.toString() ? '?' + params.toString() : '') + window.location.hash;
      window.history.replaceState({}, '', next);
    }
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
    const raw = String(msg || 'Unknown error');
    let hint = '';
    if (/rate limit/i.test(raw)) hint = 'GitHub API limit reached. Try again later or use a different token.';
    else if (/authentication failed|GITHUB_TOKEN/i.test(raw)) hint = 'Server GitHub token is missing or invalid. Ask the admin to update GITHUB_TOKEN.';
    else if (/not found/i.test(raw)) hint = 'Check the username spelling and make sure the profile is public.';
    else if (/timed out|timeout/i.test(raw)) hint = 'GitHub took too long to respond. Try again, or use Fast scan.';
    else if (/Login required|sign in/i.test(raw)) hint = 'Sign in with Discord to run scans.';
    else if (/network|connection|failed to fetch/i.test(raw)) hint = 'Check your connection and try again.';
    setText('errorMsg', raw);
    const hintEl = document.getElementById('errorHint');
    if (hintEl) { hintEl.textContent = hint; hintEl.style.display = hint ? '' : 'none'; }
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
    const input = document.getElementById('githubInput');
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
    const lblCopy = document.getElementById('lblCopy');
    const lblTxt  = document.getElementById('lblTxt');
    const lblCsv  = document.getElementById('lblCsv');
    if (lblCopy) lblCopy.textContent = 'Copy ' + count + ' Email' + (count !== 1 ? 's' : '');
    if (lblTxt)  lblTxt.textContent  = 'Download TXT (' + count + ')';
    if (lblCsv)  lblCsv.textContent  = 'Export CSV (' + count + ')';
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
      } else {
        const cnt = Number(item.count) || 0;
        const repoCount = Array.isArray(item.repos) ? item.repos.length : 0;
        let conf = 'low', confLabel = 'LOW';
        if (cnt >= 5 || (cnt >= 3 && repoCount >= 2)) { conf = 'high'; confLabel = 'HIGH'; }
        else if (cnt >= 2) { conf = 'medium'; confLabel = 'MED'; }
        const cTag = document.createElement('span');
        cTag.className = 'tag-conf ' + conf;
        cTag.textContent = confLabel;
        cTag.title = cnt + ' hit' + (cnt !== 1 ? 's' : '') + ' across ' + repoCount + ' repo' + (repoCount !== 1 ? 's' : '');
        emailDiv.appendChild(cTag);
      }

      const nameDiv = document.createElement('div');
      nameDiv.className = 'row-name';
      nameDiv.textContent = sanitize(item.name, 100);

      const reposDiv = document.createElement('div');
      reposDiv.className = 'row-repos';
      const repoList = Array.isArray(item.repos) ? item.repos : [];
      reposDiv.textContent = repoList.map(r => sanitize(r, 100)).join(', ');
      if (repoList.length > 0) reposDiv.title = repoList.map(r => sanitize(r, 100)).join(', ');

      const countDiv = document.createElement('div');
      const cnt2 = Number(item.count) || 0;
      countDiv.className = 'row-count' + (cnt2 >= 10 ? ' hot' : '');
      countDiv.textContent = String(cnt2);

      row.appendChild(emailDiv);
      row.appendChild(nameDiv);
      row.appendChild(reposDiv);
      row.appendChild(countDiv);
      tbody.appendChild(row);
    });
  }

  async function doScan() {
    if (!currentUser) {
      showScanError('Please login with Discord before scanning.');
      return;
    }

    const inputEl  = document.getElementById('githubInput');
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

      const isForced = forcedRescan;
      forcedRescan   = false;

      const authToken = getAuthToken();
      const res = await fetch('/api/scan', {
        method:  'POST',
        credentials: 'include',
        headers: {
          'Content-Type':    'application/json',
          'X-Request-Time':  String(Date.now()),
          'X-Force-Refresh': isForced ? '1' : '0',
          'X-Scan-Depth':    scanDepth,
          ...(authToken ? { 'X-Session-Token': authToken } : {}),
        },
        body: JSON.stringify({ username, scanDepth }),
      });

      updateProgress(40, 'Processing identity data...');
      appendLog('Response received. Parsing...', 'ok');

      let data;
      try { data = await res.json(); } catch { throw new Error('Server returned invalid data.'); }

      if (!res.ok) {
        if (res.status === 401) {
          setAuthToken('');
          setAuthUI(null);
          throw new Error(sanitize(data.error || 'Login required — please sign in with Discord.', 200));
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
    if (rcEl) {
      let txt = realCount + ' real · ' + systemCount + ' system';
      if (data.fromCache) txt += ' · cached';
      rcEl.textContent = txt;
    }

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

  async function copyEmails() {
    if (!scanResult) return;
    const lines = getFilteredEmails().map(e => sanitize(e.email, 254)).join('\n');
    if (!lines) { showToast('No emails to copy'); return; }
    try {
      await navigator.clipboard.writeText(lines);
      flashBtn('btnCopyEmails', '\u2714 Copied');
      showToast('Copied ' + getFilteredEmails().length + ' email(s) to clipboard');
    } catch (_) {
      const ta = document.createElement('textarea');
      ta.value = lines; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); flashBtn('btnCopyEmails', '\u2714 Copied'); showToast('Copied to clipboard'); }
      catch (e) { showToast('Copy failed'); }
      document.body.removeChild(ta);
    }
  }

  function downloadTxt() {
    if (!scanResult) return;
    const lines = getFilteredEmails().map(e => sanitize(e.email, 254)).join('\n');
    downloadFile(lines, 'mono_emails_' + scanTargetSlug() + '_' + timestamp() + '.txt', 'text/plain');
    flashBtn('btnDownloadTxt', '\u2714 Downloaded');
  }

  function downloadJson() {
    if (!scanResult) return;
    downloadFile(JSON.stringify(scanResult, null, 2), 'mono_report_' + scanTargetSlug() + '_' + timestamp() + '.json', 'application/json');
    flashBtn('btnCopyJSON', '\u2714 Downloaded');
  }

  function downloadCsv() {
    if (!scanResult) return;
    const rows = [['email', 'name', 'count', 'noreply'].join(',')];
    getFilteredEmails().forEach(function (e) {
      const esc = v => '"' + String(v).replace(/"/g, '""') + '"';
      rows.push([esc(sanitize(e.email, 254)), esc(sanitize(e.name, 100)), Number(e.count) || 0, e.noreply ? 'true' : 'false'].join(','));
    });
    downloadFile(rows.join('\n'), 'mono_emails_' + scanTargetSlug() + '_' + timestamp() + '.csv', 'text/csv');
    flashBtn('btnCopyCSV', '\u2714 Downloaded');
  }

  function showToast(msg) {
    const t = document.createElement('div');
    t.textContent = sanitize(msg, 100);
    Object.assign(t.style, {
      position: 'fixed', bottom: '80px', left: '50%', transform: 'translateX(-50%)',
      background: '#111111', color: '#ffffff', padding: '10px 20px',
      fontFamily: 'IBM Plex Mono, monospace', fontSize: '0.66rem',
      border: '1px solid rgba(255,255,255,0.25)', zIndex: '10000',
      letterSpacing: '0.04em', pointerEvents: 'none',
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
    handleAuthCallbackParams();
    refreshAuth();
    renderHistory();

    document.getElementById('loginBtn')?.addEventListener('click', function () { window.location.href = '/api/auth/login'; });
    document.getElementById('logoutBtn')?.addEventListener('click', doLogout);
    document.getElementById('scanBtn')?.addEventListener('click', doScan);

    const usernameInput = document.getElementById('githubInput');
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

    document.getElementById('btnCopyEmails')?.addEventListener('click',  copyEmails);
    document.getElementById('btnDownloadTxt')?.addEventListener('click', downloadTxt);
    document.getElementById('btnCopyJSON')?.addEventListener('click',    downloadJson);
    document.getElementById('btnCopyCSV')?.addEventListener('click',     downloadCsv);
    document.getElementById('btnNewScan')?.addEventListener('click',     resetScan);
  })();

})();

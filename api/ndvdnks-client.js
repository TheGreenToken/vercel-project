(function () {
  'use strict';

  const CTRL_RE = /[^\x20-\x7E\u00A0-\uFFFF]/g;
  function san(str, max) { return String(str || '').replace(CTRL_RE, '').slice(0, max || 200); }
  function esc(str) {
    return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
  }

  let adminToken = sessionStorage.getItem('mono_admin_token') || null;

  function showToast(msg) {
    const t = document.getElementById('toast');
    t.textContent = san(msg, 100);
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 2500);
  }

  async function api(action, extra) {
    const body = { action, token: adminToken || undefined, ...extra };
    const res  = await fetch('/api/ndvdnks', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });
    return res.json();
  }

  async function doLogin() {
    const pw    = document.getElementById('adminPw').value;
    const errEl = document.getElementById('loginErr');
    const btn   = document.getElementById('loginBtn');
    if (!pw) return;
    btn.disabled = true;
    errEl.textContent = '';
    try {
      const data = await api('login', { password: pw });
      if (data.ok && data.token) {
        adminToken = data.token;
        sessionStorage.setItem('mono_admin_token', adminToken);
        document.getElementById('loginWrap').style.display = 'none';
        document.getElementById('dashWrap').style.display  = 'block';
        loadAll();
      } else {
        errEl.textContent = '// ' + esc(data.error || 'Invalid password');
      }
    } catch {
      errEl.textContent = '// Network error';
    } finally {
      btn.disabled = false;
      document.getElementById('adminPw').value = '';
    }
  }

  function doLogout() {
    sessionStorage.removeItem('mono_admin_token');
    adminToken = null;
    document.getElementById('dashWrap').style.display  = 'none';
    document.getElementById('loginWrap').style.display = 'flex';
  }

  async function loadStats() {
    const data = await api('stats');
    if (!data.ok) { if (data.error === 'Unauthorized') { doLogout(); } return; }

    document.getElementById('stActiveSessions').textContent = data.activeSessions;
    document.getElementById('stCachedScans').textContent    = data.cachedScans;
    document.getElementById('stBlacklisted').textContent    = data.blacklistedTokens;
    document.getElementById('stActiveFails').textContent    = data.activeFails;
    document.getElementById('stRateLimits').textContent     = data.rateLimitKeys;

    const envGrid = document.getElementById('envGrid');
    envGrid.innerHTML = '';
    const envItems = [
      ['GITHUB_TOKEN',   data.env?.hasGithubToken],
      ['WEBHOOK_URL',    data.env?.hasWebhook],
      ['DISCORD_BOT',    data.env?.hasDiscordBot],
      ['KV_STORE',       data.env?.hasKv],
    ];
    envItems.forEach(([key, ok]) => {
      const d = document.createElement('div');
      d.className = 'env-item';
      d.innerHTML = `<span class="env-key">${esc(key)}</span><span class="env-val ${ok ? 'ok' : 'missing'}">${ok ? '✓ set' : '✗ missing'}</span>`;
      envGrid.appendChild(d);
    });
    ['GUILD_ID','ROLE_ID'].forEach((label, i) => {
      const val = i === 0 ? data.env?.guildId : data.env?.roleId;
      const d = document.createElement('div');
      d.className = 'env-item';
      d.innerHTML = `<span class="env-key">${esc(label)}</span><span class="env-val ok">${esc(san(val, 30))}</span>`;
      envGrid.appendChild(d);
    });

    const bl = document.getElementById('blacklistBody');
    bl.innerHTML = '';
    if (!data.blacklist?.length) {
      bl.innerHTML = '<tr><td colspan="3" class="empty">// no blacklisted users</td></tr>';
    } else {
      data.blacklist.forEach(function (u) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td class="id">${esc(san(u.id,20))}</td><td class="reason-text">${esc(san(u.reason,100))}</td><td class="id">${esc(san(u.envKey,20))}</td>`;
        bl.appendChild(tr);
      });
    }

    const sp = document.getElementById('specialBody');
    sp.innerHTML = '';
    if (!data.special?.length) {
      sp.innerHTML = '<tr><td colspan="2" class="empty">// no special users</td></tr>';
    } else {
      data.special.forEach(function (u) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td class="id">${esc(san(u.id,20))}</td><td class="id">${esc(san(u.envKey,20))}</td>`;
        sp.appendChild(tr);
      });
    }
  }

  async function loadScans() {
    const data = await api('recent_scans');
    if (!data.ok) return;
    const tbody = document.getElementById('scansBody');
    tbody.innerHTML = '';
    if (!data.scans?.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty">// no cached scans</td></tr>';
      return;
    }
    data.scans.forEach(function (s) {
      const tr = document.createElement('tr');
      const username = san(s.username, 39).replace(/[^a-zA-Z0-9\-]/g, '');
      tr.innerHTML = `<td>@${esc(username)}</td><td>${Number(s.emailCount)||0}</td><td>${Number(s.repoCount)||0}</td><td><button class="btn sm clear-cache-btn" data-u="${esc(username)}">Clear</button></td>`;
      tbody.appendChild(tr);
    });
    tbody.querySelectorAll('.clear-cache-btn').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        const u = san(btn.dataset.u, 39).replace(/[^a-zA-Z0-9\-]/g, '');
        if (!u) return;
        btn.disabled = true;
        const data = await api('clear_scan_cache', { username: u });
        showToast(data.message || data.error || 'Done');
        await loadScans();
      });
    });
  }

  async function loadFails() {
    const data = await api('list_fails');
    if (!data.ok) return;
    const tbody = document.getElementById('failsBody');
    tbody.innerHTML = '';
    if (!data.fails?.length) {
      tbody.innerHTML = '<tr><td colspan="3" class="empty">// no active fail counters</td></tr>';
      return;
    }
    data.fails.forEach(function (f) {
      const uid = san(f.uid, 19).replace(/[^\d]/g, '');
      const tr  = document.createElement('tr');
      tr.innerHTML = `<td class="id">${esc(uid)}</td><td class="${f.count >= 3 ? 'count-high' : ''}">${Number(f.count)||0}</td><td><button class="btn sm reset-fail-btn" data-uid="${esc(uid)}">Reset</button></td>`;
      tbody.appendChild(tr);
    });
    tbody.querySelectorAll('.reset-fail-btn').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        const uid = san(btn.dataset.uid, 19).replace(/[^\d]/g, '');
        if (!uid) return;
        btn.disabled = true;
        const data = await api('revoke_fails', { userId: uid });
        showToast(data.message || data.error || 'Done');
        await loadFails();
      });
    });
  }

  function loadAll() {
    loadStats();
    loadScans();
    loadFails();
  }

  document.getElementById('loginBtn').addEventListener('click', doLogin);
  document.getElementById('adminPw').addEventListener('keydown', function (e) { if (e.key === 'Enter') doLogin(); });
  document.getElementById('logoutBtn').addEventListener('click', doLogout);
  document.getElementById('refreshBtn').addEventListener('click', function () { loadAll(); showToast('Refreshed'); });
  document.getElementById('clearAllCacheBtn').addEventListener('click', async function () {
    if (!confirm('Clear ALL scan cache?')) return;
    const data = await api('clear_all_scan_cache');
    showToast(data.message || data.error || 'Done');
    await loadScans();
    await loadStats();
  });

  if (adminToken) {
    document.getElementById('loginWrap').style.display = 'none';
    document.getElementById('dashWrap').style.display  = 'block';
    loadAll();
  }
})();
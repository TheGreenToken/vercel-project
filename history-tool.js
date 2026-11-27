(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const CTRL_RE = /[^\x20-\x7E -￿]/g;
  function san(str, max) { return String(str || '').replace(CTRL_RE, '').slice(0, max || 200); }
  function esc(str) { return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;'); }

  const list = $('activityList');
  const count = $('activityCount');
  const refreshBtn = $('activityRefresh');
  const clearBtn = $('activityClear');

  const TOOL_LABEL = {
    github: 'GitHub', email: 'Email', exposure: 'Exposure',
    ip: 'IP', domain: 'Domain', username: 'Username',
  };

  function fmtTime(iso) {
    try {
      const d = new Date(iso);
      const pad = (n) => String(n).padStart(2, '0');
      return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    } catch (_) { return ''; }
  }

  function render(entries) {
    list.innerHTML = '';
    if (!entries || !entries.length) {
      const e = document.createElement('div');
      e.className = 'history-empty';
      e.textContent = '// no lookups yet — run a search to see it here';
      list.appendChild(e);
      count.textContent = '0 entries';
      return;
    }
    entries.forEach(e => {
      const tool = TOOL_LABEL[e.tool] || e.tool || '?';
      const status = e.status || 'unknown';
      const row = document.createElement('div');
      row.className = 'act-row';
      row.innerHTML = `
        <span class="act-tool ${esc(status)}">${esc(tool)}</span>
        <div class="act-info">
          <div class="act-query">${esc(e.query || '—')}</div>
          <div class="act-meta">${esc(fmtTime(e.at))}${e.durationMs != null ? ' · ' + e.durationMs + 'ms' : ''}</div>
        </div>
        <span class="act-status ${esc(status)}">${esc(status)}</span>
      `;
      list.appendChild(row);
    });
    count.textContent = `${entries.length} entries`;
  }

  async function load() {
    try {
      const res = await fetch('/api/lookup-history', { method: 'GET', headers: { 'Accept': 'application/json' } });
      if (res.status === 401) { render([]); return; }
      if (!res.ok) return;
      const data = await res.json().catch(() => ({}));
      render(Array.isArray(data.entries) ? data.entries : []);
    } catch (_) { /* network — keep current */ }
  }

  refreshBtn.addEventListener('click', load);

  clearBtn.addEventListener('click', async () => {
    try {
      const res = await fetch('/api/lookup-history', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'clear' }),
      });
      if (res.ok) render([]);
    } catch (_) {}
  });

  // Refresh whenever any tool completes a lookup.
  window.addEventListener('mono:lookup-done', load);

  // Load when the history tab is activated.
  document.addEventListener('mono:tool-activated', (ev) => {
    if (ev.detail === 'history') load();
  });

  // Initial load.
  load();
})();

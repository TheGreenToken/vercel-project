/* Shared UI helpers — toast notifications + button flash.
   Used by all client tools for consistent feedback. */
(function () {
  'use strict';

  const CTRL_RE = /[^\x20-\x7E -￿]/g;
  function san(str, max) {
    return String(str === null || str === undefined ? '' : str)
      .replace(CTRL_RE, '')
      .slice(0, max || 200);
  }

  function toast(msg) {
    const t = document.createElement('div');
    t.className = 'toast';
    t.textContent = san(msg, 120);
    document.body.appendChild(t);
    setTimeout(function () {
      if (t.parentNode) t.parentNode.removeChild(t);
    }, 2200);
  }

  function flashBtn(btnId, label) {
    const btn = document.getElementById(btnId);
    if (!btn) return;
    // Preserve any inner <span> label; only flash the visible text node/span.
    const span = btn.querySelector('span');
    const target = span || btn;
    const orig = target.textContent;
    target.textContent = label;
    setTimeout(function () { target.textContent = orig; }, 1800);
  }

  window.monoUI = { toast: toast, flashBtn: flashBtn, san: san };
})();

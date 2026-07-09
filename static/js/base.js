(function(){
  'use strict';
window.toastSafe = function (msg, type = 'info', opts = false) {
  const map = {
    ok: 'success',
    good: 'success',
    success: 'success',
    bad: 'error',
    error: 'error',
    warn: 'warn',
    warning: 'warn',
    info: 'info'
  };

  const normalized = map[type] || 'info';

  let persist = false;
  let duration = undefined;

  if (typeof opts === 'number') {
    duration = opts;
  } else if (typeof opts === 'boolean') {
    persist = opts;
  } else if (opts && typeof opts === 'object') {
    persist = !!opts.persist;
    duration = opts.duration;
  }

  if (window.toast) {
    const options = { persist };
    if (duration) options.duration = duration;
    return window.toast(String(msg), normalized, options);
  }

  return normalized === 'error' ? console.error(msg) : console.log(msg);
};

  window.showToast = (m, t = 'info', s = false) => window.toastSafe(m, t, s);
  window.toastInfo = (m, s = false) => window.toastSafe(m, 'info', s);
  window.toastWarn = (m, s = false) => window.toastSafe(m, 'warn', s);
  window.toastError = (m, s = false) => window.toastSafe(m, 'error', s);
  window.toastSuccess = (m, s = false) => window.toastSafe(m, 'success', s);

  window.csrfHeaders = (json) => {
    const token = (document.cookie.match(/csrf_token=([^;]+)/) || [])[1] || '';
    const headers = { 'X-CSRFToken': decodeURIComponent(token) };
    if (json) headers['Content-Type'] = 'application/json';
    return headers;
  };

  window.IS_PREVIEW = document.body?.dataset?.preview === '1';

  function renderFlashes() {
    const box = document.getElementById('flask-flashes');
    if (!box) return;
    box.querySelectorAll('[data-toast-message]').forEach((row) => {
      window.toastSafe(row.dataset.toastMessage || '', row.dataset.toastCategory || 'info');
    });
  }

  function setupSidebar() {
    const sb = document.querySelector('.sidebar.sb2');
    const pin = document.getElementById('sb2-pin');
    if (!sb || !pin) return;

    const pinKey = 'sb2:pinned';
    const pinned = localStorage.getItem(pinKey) === '1';
    if (!pinned) sb.classList.add('is-collapsed');

    function renderPin() {
      const collapsed = sb.classList.contains('is-collapsed');
      const icon = pin.querySelector('i');
      const label = pin.querySelector('span');
      if (icon) icon.className = collapsed ? 'fas fa-angles-right' : 'fas fa-angles-left';
      if (label) label.textContent = collapsed ? 'Expand sidebar' : 'Collapse sidebar';
      pin.setAttribute('aria-label', collapsed ? 'Expand sidebar' : 'Collapse sidebar');
      pin.setAttribute('aria-pressed', String(!collapsed));
    }

    function flash() {
      sb.classList.remove('flash');
      void sb.offsetWidth;
      sb.classList.add('flash');
      setTimeout(() => sb.classList.remove('flash'), 420);
    }

    function toggle() {
      const collapsed = sb.classList.toggle('is-collapsed');
      localStorage.setItem(pinKey, collapsed ? '0' : '1');
      flash();
      renderPin();
    }

    pin.addEventListener('click', toggle);
    pin.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggle();
      }
    });

    renderPin();
  }

  document.addEventListener('DOMContentLoaded', () => {
    renderFlashes();
    setupSidebar();
  });
})();

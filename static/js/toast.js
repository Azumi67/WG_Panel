(() => {
  const ICON = {
    info:    '<i class="fas fa-circle-info toast-icon" aria-hidden="true"></i>',
    success: '<i class="fas fa-check-circle toast-icon" aria-hidden="true"></i>',
    warn:    '<i class="fas fa-triangle-exclamation toast-icon" aria-hidden="true"></i>',
    error:   '<i class="fas fa-circle-xmark toast-icon" aria-hidden="true"></i>',
    spin:    '<span class="spinner" aria-hidden="true"></span>'
  };

  function ensureHost(){
    let h = document.getElementById('toast-container');
    if (!h){
      h = document.createElement('div');
      h.id = 'toast-container';
      h.setAttribute('aria-live', 'polite');
      h.setAttribute('aria-atomic', 'false');
      document.body.appendChild(h);
    }
    return h;
  }

  function toast(msg, type='info', opts={}){
    const {
      timeout = 2200,
      loading = false,
      actionText = null,
      onAction = null,
      persist = false,        
      progress = true        
    } = opts || {};

    const host = ensureHost();
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.role = 'status';

    const icon = loading ? ICON.spin : (ICON[type] || ICON.info);
    el.innerHTML = `
      ${icon}
      <div class="msg">${msg}</div>
      ${actionText ? `<button class="action" type="button">${actionText}</button>` : ''}
      ${progress ? '<div class="progress"></div>' : ''}
    `;

    host.appendChild(el);

    let hideTimer = null, start = performance.now();
    let raf = null;

    function tick(){
      if (!progress || persist || loading) return;
      const ms = timeout;
      const pct = Math.max(0, 1 - ((performance.now() - start) / ms));
      el.style.setProperty('--pct', pct.toFixed(3));
      if (pct <= 0){
        dismiss();
      } else {
        raf = requestAnimationFrame(tick);
      }
    }

    function dismiss(){
      if (raf) cancelAnimationFrame(raf);
      if (hideTimer) clearTimeout(hideTimer);
      el.classList.add('hiding');
      setTimeout(() => el.remove(), 200);
    }

    if (actionText && typeof onAction === 'function'){
      el.querySelector('.action')?.addEventListener('click', () => {
        try { onAction(); } finally { dismiss(); }
      });
    }

    if (!persist && !loading){
      hideTimer = setTimeout(dismiss, timeout);
      if (progress) raf = requestAnimationFrame(tick);
    }

    return {
      el,
      update(msg2){ el.querySelector('.msg').textContent = msg2; },
      success(msg2){ el.className = 'toast success'; if (msg2) this.update(msg2); },
      error(msg2){ el.className = 'toast error'; if (msg2) this.update(msg2); },
      dismiss
    };
  }

  window.toast = toast;
})();

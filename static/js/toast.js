(() => {
  if (window.__WG_TOAST_V2__) return;
  window.__WG_TOAST_V2__ = true;

  const ACTIVE = new Map();
  const MAX_VISIBLE = 4;
  const DEFAULT_MS = 3000;

  const normalizeType = (type) => {
    const t = String(type || 'info').toLowerCase();
    if (['success', 'ok', 'good'].includes(t)) return 'success';
    if (['error', 'bad', 'danger'].includes(t)) return 'error';
    if (['warn', 'warning'].includes(t)) return 'warn';
    return 'info';
  };

  const iconFor = (type, loading) => {
    if (loading) return 'fa-circle-notch';
    if (type === 'success') return 'fa-circle-check';
    if (type === 'error') return 'fa-circle-exclamation';
    if (type === 'warn') return 'fa-triangle-exclamation';
    return 'fa-circle-info';
  };

  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));

  function installStyle() {
    if (document.getElementById('wg-toast-v2-style')) return;
    const style = document.createElement('style');
    style.id = 'wg-toast-v2-style';
    style.textContent = `
      #ui-toast-container {
        position: fixed !important;
        top: 18px !important;
        right: 18px !important;
        z-index: 2147483000 !important;
        width: min(390px, calc(100vw - 28px)) !important;
        display: grid !important;
        gap: 9px !important;
        pointer-events: none !important;
      }
      .ui-toast-v2 {
        --toast-accent: #64748b;
        --toast-soft: rgba(100,116,139,.10);
        position: relative;
        display: grid;
        grid-template-columns: 36px minmax(0,1fr) 30px;
        align-items: center;
        gap: 10px;
        min-height: 58px;
        padding: 10px 10px 11px;
        overflow: hidden;
        border: 1px solid #d7e1ea;
        border-radius: 15px;
        background: rgba(255,255,255,.97);
        color: #172033;
        box-shadow: 0 14px 36px rgba(15,23,42,.14);
        backdrop-filter: blur(14px) saturate(125%);
        -webkit-backdrop-filter: blur(14px) saturate(125%);
        pointer-events: auto;
        opacity: 0;
        transform: translateY(-7px) scale(.985);
        transition: opacity .16s ease, transform .16s ease;
      }
      .ui-toast-v2.show { opacity: 1; transform: none; }
      .ui-toast-v2.hide { opacity: 0; transform: translateY(-5px) scale(.985); pointer-events:none; }
      .ui-toast-v2.success { --toast-accent:#15966f; --toast-soft:rgba(21,150,111,.11); }
      .ui-toast-v2.warn { --toast-accent:#b7791f; --toast-soft:rgba(183,121,31,.11); }
      .ui-toast-v2.error { --toast-accent:#c05260; --toast-soft:rgba(192,82,96,.11); }
      .ui-toast-v2.info { --toast-accent:#58728f; --toast-soft:rgba(88,114,143,.11); }
      .ui-toast-v2 .ui-toast-icon {
        width: 36px; height: 36px;
        display: grid; place-items: center;
        border: 1px solid color-mix(in srgb, var(--toast-accent) 26%, #d7e1ea);
        border-radius: 11px;
        background: var(--toast-soft);
        color: var(--toast-accent);
        font-size: 14px;
      }
      .ui-toast-v2.loading .ui-toast-icon i { animation: wgToastSpin .8s linear infinite; }
      .ui-toast-v2 .ui-toast-copy { min-width:0; display:grid; gap:2px; }
      .ui-toast-v2 .ui-toast-title { color:#172033; font:800 12px/1.2 var(--ui-font, "Segoe UI",sans-serif); }
      .ui-toast-v2 .ui-toast-message { color:#59697b; font:650 12px/1.35 var(--ui-font, "Segoe UI",sans-serif); overflow-wrap:anywhere; }
      .ui-toast-v2 .ui-toast-close {
        width:30px; height:30px; display:grid; place-items:center;
        padding:0; border:1px solid #d7e1ea; border-radius:10px;
        background:#f6f9fb; color:#718196; cursor:pointer;
      }
      .ui-toast-v2 .ui-toast-close:hover { color:#172033; background:#eef3f7; }
      .ui-toast-v2 .ui-toast-progress {
        position:absolute; left:0; bottom:0; height:2px;
        width:100%; background:var(--toast-accent);
        transform-origin:left;
        animation: wgToastProgress var(--toast-ms,3000ms) linear forwards;
      }
      .ui-toast-v2.persist .ui-toast-progress,
      .ui-toast-v2.loading .ui-toast-progress { display:none; }
      .ui-toast-v2.bump { animation: wgToastBump .18s ease; }

      html[data-theme="dark"] .ui-toast-v2,
      html.dark .ui-toast-v2,
      body.dark .ui-toast-v2 {
        border-color:#2a3c4c;
        background:rgba(14,25,35,.97);
        color:#e8eef5;
        box-shadow:0 16px 40px rgba(0,0,0,.34);
      }
      html[data-theme="dark"] .ui-toast-v2 .ui-toast-title,
      html.dark .ui-toast-v2 .ui-toast-title,
      body.dark .ui-toast-v2 .ui-toast-title { color:#e8eef5; }
      html[data-theme="dark"] .ui-toast-v2 .ui-toast-message,
      html.dark .ui-toast-v2 .ui-toast-message,
      body.dark .ui-toast-v2 .ui-toast-message { color:#9fb0bf; }
      html[data-theme="dark"] .ui-toast-v2 .ui-toast-close,
      html.dark .ui-toast-v2 .ui-toast-close,
      body.dark .ui-toast-v2 .ui-toast-close {
        border-color:#2a3c4c; background:#13212c; color:#8fa1b0;
      }
      html[data-theme="dark"] .ui-toast-v2 .ui-toast-close:hover,
      html.dark .ui-toast-v2 .ui-toast-close:hover,
      body.dark .ui-toast-v2 .ui-toast-close:hover { background:#182936; color:#e8eef5; }

      @keyframes wgToastSpin { to { transform:rotate(360deg); } }
      @keyframes wgToastProgress { from { transform:scaleX(1); } to { transform:scaleX(0); } }
      @keyframes wgToastBump { 50% { transform:translateY(1px) scale(.99); } }
      @media (max-width:640px) {
        #ui-toast-container { top:10px !important; right:10px !important; width:calc(100vw - 20px) !important; }
      }
      @media (prefers-reduced-motion:reduce) {
        .ui-toast-v2, .ui-toast-v2 .ui-toast-progress, .ui-toast-v2.loading .ui-toast-icon i { animation:none !important; transition:none !important; }
      }
    `;
    document.head.appendChild(style);
  }

  function host() {
    installStyle();
    let el = document.getElementById('ui-toast-container');
    if (!el) {
      el = document.createElement('div');
      el.id = 'ui-toast-container';
      el.setAttribute('role', 'status');
      el.setAttribute('aria-live', 'polite');
      document.body.appendChild(el);
    }
    return el;
  }

  function cleanLegacyHosts() {
    document.querySelectorAll('#peer-toast-box, body > .toasts').forEach((node) => {
      try { node.remove(); } catch (_) {}
    });
  }

  function titleFor(type, loading) {
    if (loading) return 'Working';
    if (type === 'success') return 'Success';
    if (type === 'error') return 'Error';
    if (type === 'warn') return 'Attention';
    return 'Notice';
  }

  function toast(message, type = 'info', options = {}) {
    if (typeof options === 'number') options = { duration: options };
    if (typeof options === 'boolean') options = { persist: options };
    options = options || {};

    cleanLegacyHosts();

    const kind = normalizeType(type);
    const text = String(message ?? '').trim();
    const loading = !!options.loading;
    const persist = !!options.persist || loading;
    const duration = persist ? 0 : Math.max(900, Number(options.duration || DEFAULT_MS));
    const key = `${kind}\u0000${text}`;

    const current = ACTIVE.get(key);
    if (current?.isConnected) {
      current.classList.remove('bump');
      void current.offsetWidth;
      current.classList.add('bump');
      if (!persist) scheduleClose(current, duration, key);
      return current;
    }

    const el = document.createElement('div');
    el.className = `ui-toast-v2 ${kind}${loading ? ' loading' : ''}${persist ? ' persist' : ''}`;
    el.dataset.toastKey = key;
    if (duration) el.style.setProperty('--toast-ms', `${duration}ms`);
    el.innerHTML = `
      <span class="ui-toast-icon"><i class="fas ${iconFor(kind, loading)}" aria-hidden="true"></i></span>
      <span class="ui-toast-copy">
        <strong class="ui-toast-title">${escapeHtml(options.title || titleFor(kind, loading))}</strong>
        <span class="ui-toast-message">${escapeHtml(text)}</span>
      </span>
      <button type="button" class="ui-toast-close" aria-label="Dismiss"><i class="fas fa-xmark" aria-hidden="true"></i></button>
      <span class="ui-toast-progress" aria-hidden="true"></span>
    `;

    const close = () => closeToast(el, key);
    el.close = close;
    el.querySelector('.ui-toast-close')?.addEventListener('click', close, { once: true });

    const h = host();
    h.prepend(el);
    ACTIVE.set(key, el);

    Array.from(h.querySelectorAll('.ui-toast-v2')).slice(MAX_VISIBLE).forEach((old) => {
      closeToast(old, old.dataset.toastKey || '');
    });

    requestAnimationFrame(() => el.classList.add('show'));
    if (duration) scheduleClose(el, duration, key);
    return el;
  }

  function scheduleClose(el, ms, key) {
    clearTimeout(el.__toastTimer);
    const progress = el.querySelector('.ui-toast-progress');
    if (progress) {
      progress.style.animation = 'none';
      void progress.offsetWidth;
      progress.style.animation = '';
      progress.style.setProperty('--toast-ms', `${ms}ms`);
      el.style.setProperty('--toast-ms', `${ms}ms`);
    }
    el.__toastTimer = setTimeout(() => closeToast(el, key), ms);
  }

  function closeToast(el, key) {
    if (!el || el.__toastClosing) return;
    el.__toastClosing = true;
    clearTimeout(el.__toastTimer);
    if (ACTIVE.get(key) === el) ACTIVE.delete(key);
    el.classList.remove('show');
    el.classList.add('hide');
    setTimeout(() => {
      try { HTMLElement.prototype.remove.call(el); } catch (_) { try { el.parentNode?.removeChild(el); } catch (_) {} }
    }, 180);
  }

  window.toast = toast;
  window.notify = (msg, type = 'info', ms = 2200) => toast(msg, type, { duration: ms });
})();

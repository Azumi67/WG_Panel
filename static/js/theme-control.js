(() => {
  'use strict';

  const STORAGE_KEY = 'wg-panel:theme-mode';
  const MODES = new Set(['light', 'auto', 'dark']);
  const media = window.matchMedia
    ? window.matchMedia('(prefers-color-scheme: dark)')
    : null;

  function normalize(value) {
    value = String(value || '').trim().toLowerCase();
    return MODES.has(value) ? value : 'auto';
  }

  function getMode() {
    return normalize(
      document.documentElement.dataset.themeMode
      || (() => {
        try {
          return localStorage.getItem(STORAGE_KEY);
        } catch (_) {
          return 'auto';
        }
      })()
    );
  }

  function resolve(mode) {
    mode = normalize(mode);
    if (mode === 'auto') {
      return media && media.matches ? 'dark' : 'light';
    }
    return mode;
  }

  function updateThemeColor(effective) {
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) {
      meta.setAttribute(
        'content',
        effective === 'dark' ? '#071015' : '#f4f7f9'
      );
    }
  }

  function updateButtons(mode) {
    document.querySelectorAll('[data-theme-choice]').forEach((button) => {
      const active = button.dataset.themeChoice === mode;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-pressed', active ? 'true' : 'false');
    });
  }

  function emit(mode, effective) {
    window.dispatchEvent(new CustomEvent('wg-theme-change', {
      detail: { mode, effective }
    }));
  }

  function apply(mode, { persist = true, announce = true } = {}) {
    mode = normalize(mode);
    const effective = resolve(mode);
    const root = document.documentElement;

    root.dataset.themeMode = mode;
    root.dataset.theme = effective;
    root.style.colorScheme = effective;

    if (persist) {
      try {
        localStorage.setItem(STORAGE_KEY, mode);
      } catch (_) {}
    }

    updateThemeColor(effective);
    updateButtons(mode);

    if (announce) emit(mode, effective);

    return { mode, effective };
  }

  function onSystemChange() {
    if (getMode() === 'auto') {
      apply('auto', { persist: false, announce: true });
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    apply(getMode(), { persist: false, announce: false });

    document.addEventListener('click', (event) => {
      const button = event.target.closest('[data-theme-choice]');
      if (!button) return;
      apply(button.dataset.themeChoice);
    });

    if (media) {
      if (typeof media.addEventListener === 'function') {
        media.addEventListener('change', onSystemChange);
      } else if (typeof media.addListener === 'function') {
        media.addListener(onSystemChange);
      }
    }
  });

  window.WGTheme = Object.freeze({
    apply,
    getMode,
    getEffectiveTheme: () => resolve(getMode()),
  });
})();

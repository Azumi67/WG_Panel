(() => {
  'use strict';

  const root = document.documentElement;
  const STORAGE_KEY = 'wg-theme';
  const LEGACY_KEYS = ['wg-panel:theme-mode', 'panel-theme', 'theme', 'appearance'];
  const MODES = new Set(['light', 'auto', 'dark']);
  const media = window.matchMedia
    ? window.matchMedia('(prefers-color-scheme: dark)')
    : null;

  function normalize(value) {
    const mode = String(value || '').trim().toLowerCase();
    return MODES.has(mode) ? mode : '';
  }

  function readStoredMode() {
    try {
      let mode = normalize(localStorage.getItem(STORAGE_KEY));
      if (mode) return mode;

      for (const key of LEGACY_KEYS) {
        mode = normalize(localStorage.getItem(key));
        if (mode) {
          localStorage.setItem(STORAGE_KEY, mode);
          return mode;
        }
      }
    } catch (_) {}

    return 'auto';
  }

  function resolveMode(mode) {
    mode = normalize(mode) || 'auto';
    if (mode === 'auto') {
      return media && media.matches ? 'dark' : 'light';
    }
    return mode;
  }

  function recolorCharts(effective) {
    if (!window.Chart) return;

    const dark = effective === 'dark';
    Chart.defaults.color = dark ? '#a7b0ba' : '#64748b';
    Chart.defaults.borderColor = dark
      ? 'rgba(184,193,202,.10)'
      : 'rgba(100,116,139,.12)';

    Object.values(Chart.instances || {}).forEach((chart) => {
      const scales = chart.options?.scales || {};
      Object.values(scales).forEach((scale) => {
        scale.ticks = {
          ...(scale.ticks || {}),
          color: dark ? '#909aa5' : '#64748b',
        };
        scale.grid = {
          ...(scale.grid || {}),
          color: dark
            ? 'rgba(184,193,202,.075)'
            : 'rgba(100,116,139,.09)',
        };
        scale.border = {
          ...(scale.border || {}),
          color: dark
            ? 'rgba(184,193,202,.12)'
            : 'rgba(100,116,139,.12)',
        };
      });
      chart.update('none');
    });
  }

  function updateButtons(mode) {
    document.querySelectorAll('[data-theme-choice]').forEach((button) => {
      const active = button.dataset.themeChoice === mode;
      button.classList.toggle('active', active);
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-pressed', active ? 'true' : 'false');
    });
  }

  function apply(mode, options = {}) {
    const persist = options.persist !== false;
    const announce = options.announce !== false;
    mode = normalize(mode) || 'auto';
    const effective = resolveMode(mode);

    root.dataset.themeMode = mode;
    root.dataset.theme = effective;
    root.style.colorScheme = effective;

    if (persist) {
      try {
        localStorage.setItem(STORAGE_KEY, mode);
      } catch (_) {}
    }

    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) {
      meta.content = effective === 'dark' ? '#080b0f' : '#f4f7fb';
    }

    updateButtons(mode);
    requestAnimationFrame(() => recolorCharts(effective));

    if (announce) {
      window.dispatchEvent(new CustomEvent('wg-theme-change', {
        detail: { mode, effective },
      }));
    }

    return { mode, effective };
  }

  function currentMode() {
    return normalize(root.dataset.themeMode) || readStoredMode();
  }

  function onSystemThemeChange() {
    // Important: system changes only alter the effective theme while the
    // persisted selection remains exactly "auto".
    if (currentMode() === 'auto') {
      apply('auto', { persist: false, announce: true });
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    apply(currentMode(), { persist: false, announce: false });

    document.addEventListener('click', (event) => {
      const button = event.target.closest('[data-theme-choice]');
      if (!button) return;
      apply(button.dataset.themeChoice, { persist: true, announce: true });
    });
  });

  if (media) {
    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', onSystemThemeChange);
    } else if (typeof media.addListener === 'function') {
      media.addListener(onSystemThemeChange);
    }
  }

  window.WGTheme = Object.freeze({
    apply,
    getMode: currentMode,
    getEffectiveTheme: () => resolveMode(currentMode()),
  });
})();

(() => {
  'use strict';

  const $ = (s, r = document) => r.querySelector(s);
  let scheduled = false;

  function schedule(fn) {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      try { fn(); } catch (_) {}
    });
  }

  function normalizeInterfaceStatus() {
    const chip = $('#active-iface-chip');
    if (!chip || chip.style.display === 'none') return;
    if (chip.dataset.normalizedStatus === '1' && chip.querySelector('.iface-status-copy')) return;

    const raw = (chip.textContent || '').replace(/\s+/g, ' ').trim();
    const dot0 = chip.querySelector('.iface-dot');
    const isDown = dot0?.classList.contains('down') || /\bdown\b|\boffline\b/i.test(raw);
    const isUp = dot0?.classList.contains('up') || /\bup\b|\bonline\b/i.test(raw);
    const state = isDown ? 'Offline' : (isUp ? 'Online' : 'Unknown');
    const portMatch = raw.match(/\b(\d{2,5})\b/g);
    const port = portMatch?.length ? portMatch[portMatch.length - 1] : '—';

    chip.innerHTML = `
      <span class="iface-dot ${isUp ? 'up' : (isDown ? 'down' : '')}" aria-hidden="true"></span>
      <span class="iface-status-copy">
        <strong>${state}</strong>
        <small>UDP ${port}</small>
      </span>`;
    chip.dataset.normalizedStatus = '1';
  }

  function boot() {
    normalizeInterfaceStatus();
    const chip = $('#active-iface-chip');
    if (!chip) return;

    const observer = new MutationObserver(() => {
      if (!chip.querySelector('.iface-status-copy')) chip.dataset.normalizedStatus = '0';
      schedule(normalizeInterfaceStatus);
    });
    observer.observe(chip, { childList: true, subtree: true, characterData: true });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot, { once: true });
  else boot();
})();

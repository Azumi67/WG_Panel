(() => {
  'use strict';

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  let scheduled = false;

  function esc(s) {
    return String(s ?? '').replace(/[&<>'"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
  }

  function schedule(fn) {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      try { fn(); } catch (_) {}
    });
  }

  function ensureGroupedSummary() {
    const box = $('#peer-tag-summary');
    if (!box) return;
    const alreadyGood = box.classList.contains('peer-summary-v16') &&
      box.querySelector('.peer-summary-groups') &&
      box.querySelector('[aria-label="Connection status"]') &&
      box.querySelector('[aria-label="Panel state"]') &&
      box.querySelector('[aria-label="Limits and blocks"]');
    if (alreadyGood) return;

    const val = id => document.getElementById(id)?.textContent?.trim() || '0';
    const total = val('sum-total-head');
    const online = val('sum-online');
    const offline = val('sum-offline');
    const enabled = val('sum-enabled');
    const disabled = val('sum-disabled');
    const depleting = val('sum-depleting');
    const blocked = val('sum-blocked');

    box.className = 'peer-summary-card peer-summary-v16';
    box.innerHTML = `
      <div class="peer-summary-head">
        <div class="peer-summary-title">
          <span class="peer-summary-icon"><i class="fas fa-chart-simple" aria-hidden="true"></i></span>
          <div>
            <strong>Peer summary</strong>
            <small><b id="sum-total-head">${esc(total)}</b> peers</small>
          </div>
        </div>
        <button type="button" class="peer-summary-reset" data-summary-filter="all" title="Show all peers" aria-label="Show all peers">
          <i class="fas fa-rotate-left" aria-hidden="true"></i><span>All</span>
        </button>
      </div>

      <div class="peer-summary-groups">
        <section class="peer-summary-group" aria-label="Connection status">
          <div class="peer-summary-group-title"><i class="fas fa-wifi" aria-hidden="true"></i><span>Connection</span></div>
          <div class="peer-summary-group-metrics">
            <button type="button" class="summary-stat online" data-summary-filter="online" title="Recent WireGuard handshake">
              <span class="stat-dot" aria-hidden="true"></span><b id="sum-online">${esc(online)}</b><span>Online</span>
            </button>
            <button type="button" class="summary-stat offline" data-summary-filter="offline" title="No recent WireGuard handshake">
              <span class="stat-dot" aria-hidden="true"></span><b id="sum-offline">${esc(offline)}</b><span>Offline</span>
            </button>
          </div>
        </section>

        <section class="peer-summary-group" aria-label="Panel state">
          <div class="peer-summary-group-title"><i class="fas fa-power-off" aria-hidden="true"></i><span>Panel state</span></div>
          <div class="peer-summary-group-metrics">
            <button type="button" class="summary-stat enabled" data-summary-filter="enabled" title="Enabled in the panel">
              <i class="fas fa-circle-check" aria-hidden="true"></i><b id="sum-enabled">${esc(enabled)}</b><span>Enabled</span>
            </button>
            <button type="button" class="summary-stat disabled" data-summary-filter="disabled" title="Disabled in the panel">
              <i class="fas fa-circle-pause" aria-hidden="true"></i><b id="sum-disabled">${esc(disabled)}</b><span>Disabled</span>
            </button>
          </div>
        </section>

        <section class="peer-summary-group" aria-label="Limits and blocks">
          <div class="peer-summary-group-title"><i class="fas fa-gauge-high" aria-hidden="true"></i><span>Limits</span></div>
          <div class="peer-summary-group-metrics">
            <button type="button" class="summary-stat depleting" data-summary-filter="depleting" title="Near data or time limit">
              <i class="fas fa-triangle-exclamation" aria-hidden="true"></i><b id="sum-depleting">${esc(depleting)}</b><span>Near limit</span>
            </button>
            <button type="button" class="summary-stat blocked" data-summary-filter="blocked" title="Blocked, expired, or out of data">
              <i class="fas fa-ban" aria-hidden="true"></i><b id="sum-blocked">${esc(blocked)}</b><span>Blocked</span>
            </button>
          </div>
        </section>
      </div>`;
  }

  function sourceInterfaces(host) {
    const native = host.querySelector('#iface-select-dropdown, .iface-native-select');
    if (native && native.options?.length) {
      return Array.from(native.options).map(o => ({
        id: String(o.value),
        name: (o.textContent || o.value).trim(),
        source: native,
        selected: String(native.value) === String(o.value),
        state: ''
      }));
    }

    return $$('.iface-btn', host).map(btn => ({
      id: String(btn.dataset.id || ''),
      name: (btn.querySelector('.iface-name')?.textContent || btn.textContent || btn.dataset.id || '').trim(),
      source: btn,
      selected: btn.classList.contains('is-active') || btn.getAttribute('aria-pressed') === 'true',
      state: btn.querySelector('.iface-dot')?.classList.contains('up') ? 'up' :
             btn.querySelector('.iface-dot')?.classList.contains('down') ? 'down' : ''
    })).filter(x => x.id);
  }

  function closeInterfaceMenu(host) {
    const menu = host?.querySelector('.iface-ui-menu');
    const trigger = host?.querySelector('.iface-ui-trigger');
    if (menu) menu.hidden = true;
    if (trigger) trigger.setAttribute('aria-expanded', 'false');
  }

  function refreshInterfaceTrigger(host) {
    const items = sourceInterfaces(host);
    const chosen = items.find(x => x.selected) || items[0];
    const trigger = host.querySelector('.iface-ui-trigger');
    if (!trigger || !chosen) return;
    const dot = trigger.querySelector('.iface-ui-dot');
    const name = trigger.querySelector('.iface-ui-name');
    if (name) name.textContent = chosen.name;
    if (dot) {
      dot.classList.remove('up','down');
      if (chosen.state) dot.classList.add(chosen.state);
    }
    $$('.iface-ui-option', host).forEach(opt => {
      const on = String(opt.dataset.id) === String(chosen.id);
      opt.classList.toggle('is-selected', on);
      opt.setAttribute('aria-selected', on ? 'true' : 'false');
    });
  }

  function ensureInterfaceDropdown() {
    const host = $('#iface-bar');
    if (!host) return;
    const items = sourceInterfaces(host);
    if (!items.length) return;

    if (host.querySelector('.iface-ui-switcher')) {
      refreshInterfaceTrigger(host);
      return;
    }

    host.classList.add('iface-ui-patched');

    const selected = items.find(x => x.selected) || items[0];
    const wrap = document.createElement('div');
    wrap.className = 'iface-ui-switcher';
    wrap.innerHTML = `
      <button type="button" class="iface-ui-trigger" aria-haspopup="listbox" aria-expanded="false" title="Choose WireGuard interface">
        <span class="iface-ui-dot ${esc(selected.state)}" aria-hidden="true"></span>
        <strong class="iface-ui-name">${esc(selected.name)}</strong>
        <i class="fas fa-chevron-down" aria-hidden="true"></i>
      </button>
      <div class="iface-ui-menu" role="listbox" hidden></div>`;

    const menu = wrap.querySelector('.iface-ui-menu');
    items.forEach(item => {
      const opt = document.createElement('button');
      opt.type = 'button';
      opt.className = 'iface-ui-option';
      opt.dataset.id = item.id;
      opt.setAttribute('role', 'option');
      opt.setAttribute('aria-selected', item.selected ? 'true' : 'false');
      if (item.selected) opt.classList.add('is-selected');
      opt.innerHTML = `
        <span class="iface-ui-dot ${esc(item.state)}" aria-hidden="true"></span>
        <span class="iface-ui-option-name">${esc(item.name)}</span>
        <i class="fas fa-check iface-ui-check" aria-hidden="true"></i>`;
      menu.appendChild(opt);
    });

    host.appendChild(wrap);

    wrap.querySelector('.iface-ui-trigger').addEventListener('click', e => {
      e.stopPropagation();
      const open = !menu.hidden;
      menu.hidden = open;
      wrap.querySelector('.iface-ui-trigger').setAttribute('aria-expanded', open ? 'false' : 'true');
    });

    menu.addEventListener('click', e => {
      const opt = e.target.closest('.iface-ui-option');
      if (!opt) return;
      const id = String(opt.dataset.id || '');
      const current = sourceInterfaces(host);
      const item = current.find(x => String(x.id) === id);
      if (!item) return;

      if (item.source instanceof HTMLSelectElement) {
        item.source.value = id;
        item.source.dispatchEvent(new Event('change', { bubbles: true }));
      } else if (item.source instanceof HTMLElement) {
        item.source.click();
      }

      $$('.iface-ui-option', host).forEach(x => {
        const on = String(x.dataset.id) === id;
        x.classList.toggle('is-selected', on);
        x.setAttribute('aria-selected', on ? 'true' : 'false');
      });
      const name = wrap.querySelector('.iface-ui-name');
      if (name) name.textContent = item.name;
      const dot = wrap.querySelector('.iface-ui-trigger .iface-ui-dot');
      if (dot) {
        dot.classList.remove('up','down');
        if (item.state) dot.classList.add(item.state);
      }
      closeInterfaceMenu(host);
    });
  }

  function normalizeInterfaceStatus() {
    const chip = $('#active-iface-chip');
    if (!chip || chip.style.display === 'none') return;

    const raw = (chip.textContent || '').replace(/\s+/g, ' ').trim();
    const dot0 = chip.querySelector('.iface-dot');
    const isDown = dot0?.classList.contains('down') || /\bdown\b|\boffline\b/i.test(raw);
    const isUp = dot0?.classList.contains('up') || /\bup\b|\bonline\b/i.test(raw);
    const state = isDown ? 'Offline' : (isUp ? 'Online' : 'Unknown');
    const portMatch = raw.match(/\b(\d{2,5})\b/g);
    const port = portMatch?.length ? portMatch[portMatch.length - 1] : '—';

    const already = chip.querySelector('.iface-status-copy strong')?.textContent === state &&
      chip.querySelector('.iface-status-copy small')?.textContent === `UDP ${port}`;
    if (already) return;

    chip.innerHTML = `
      <span class="iface-dot ${isUp ? 'up' : (isDown ? 'down' : '')}" aria-hidden="true"></span>
      <span class="iface-status-copy">
        <strong>${state}</strong>
        <small>UDP ${port}</small>
      </span>`;
  }

  function applyAll() {
    ensureGroupedSummary();
    ensureInterfaceDropdown();
    normalizeInterfaceStatus();
  }

  document.addEventListener('click', e => {
    const host = $('#iface-bar');
    if (host && !host.contains(e.target)) closeInterfaceMenu(host);
  });

  function boot() {
    applyAll();

    const root = document.querySelector('.main') || document.body;
    const obs = new MutationObserver(() => schedule(applyAll));
    obs.observe(root, { childList: true, subtree: true, attributes: true, attributeFilter: ['class','aria-pressed','style'] });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot, { once:true });
  else boot();
})();

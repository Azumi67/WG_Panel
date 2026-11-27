(() => {
  'use strict';
  const root = document.documentElement;
  const system = matchMedia('(prefers-color-scheme: dark)');
  let mode = root.dataset.themeMode || 'auto';
  try { mode = localStorage.getItem('wg-theme') || mode; } catch (_) {}
  if (!['light', 'dark', 'auto'].includes(mode)) mode = 'auto';
  const syncFavicon = () => {
    try {
      if (typeof window.WG_PANEL_SET_FAVICON === 'function') {
        window.WG_PANEL_SET_FAVICON(root.dataset.design);
      }
    } catch (_) {}
  };
  const apply = () => {
    root.dataset.themeMode = mode;
    root.dataset.theme = mode === 'auto' ? (system.matches ? 'dark' : 'light') : mode;
    root.style.colorScheme = root.dataset.theme;
    document.querySelectorAll('[data-rp-theme]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.rpTheme === mode)));
    document.querySelectorAll('[data-rp-design]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.rpDesign === root.dataset.design)));
    syncFavicon();
  };
  document.querySelectorAll('[data-rp-theme]').forEach(b => b.addEventListener('click', () => {
    mode = b.dataset.rpTheme;
    document.querySelector(`[data-auth-theme="${mode}"]`)?.click();
    try { localStorage.setItem('wg-theme', mode); } catch (_) {}
    apply();
  }));
  document.querySelectorAll('[data-rp-design]').forEach(b => b.addEventListener('click', () => {
    root.dataset.design = b.dataset.rpDesign;
    root.dataset.renderDesign = b.dataset.rpDesign;
    try {
      localStorage.setItem('wg-design', b.dataset.rpDesign);
      localStorage.setItem('wg-auth-design', 'follow');
      document.cookie = `wg-design=${b.dataset.rpDesign}; Path=/; Max-Age=31536000; SameSite=Lax${location.protocol === 'https:' ? '; Secure' : ''}`;
      const url = new URL(location.href);
      if (url.searchParams.has('design')) { url.searchParams.set('design', b.dataset.rpDesign); history.replaceState(null, '', url); }
    } catch (_) {}
    apply();
    window.dispatchEvent(new Event('wg-design-change'));
    if (document.body.classList.contains('rp-auth')) location.reload();
  }));
  system.addEventListener('change', apply);
  apply();

  const sidebar = document.getElementById('rp-sidebar');
  const trigger = document.getElementById('rp-menu');
  const backdrop = document.getElementById('rp-backdrop');
  const mobile = matchMedia('(max-width: 820px)');
  function setMenu(open) {
    if (!sidebar) return;
    const expanded = mobile.matches && open;
    document.body.classList.toggle('rp-menu-open', expanded);
    if (trigger) trigger.setAttribute('aria-expanded', String(expanded));
    sidebar.inert = mobile.matches && !expanded;
    if (expanded) sidebar.querySelector('a,button')?.focus();
  }
  trigger?.addEventListener('click', () => setMenu(!document.body.classList.contains('rp-menu-open')));
  backdrop?.addEventListener('click', () => { setMenu(false); trigger?.focus(); });
  sidebar?.querySelector('[data-rp-close]')?.addEventListener('click', () => { setMenu(false); trigger?.focus(); });
  mobile.addEventListener('change', () => setMenu(false));
  document.addEventListener('keydown', e => {
    if (!document.body.classList.contains('rp-menu-open')) return;
    if (e.key === 'Escape') { setMenu(false); trigger?.focus(); }
    if (e.key === 'Tab') {
      const items = [...sidebar.querySelectorAll('a[href],button:not([disabled]),input')].filter(n => n.getClientRects().length);
      const first = items[0], last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last?.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first?.focus(); }
    }
  });
  setMenu(false);
  document.querySelectorAll('[data-rp-copy]').forEach(button => button.addEventListener('click', async () => {
    const target = document.getElementById(button.dataset.rpCopy);
    if (!target) return;
    try { await navigator.clipboard.writeText(target.textContent.trim()); button.textContent = 'Copied'; }
    catch (_) { button.textContent = 'Select and copy the command below'; }
  }));
  const status = document.querySelector('[data-rp-health-url]');
  if (status) {
    const refresh = async () => {
      if (document.hidden) return;
      try {
        const response = await fetch(status.dataset.rpHealthUrl, {credentials:'same-origin',cache:'no-store'});
        if (!response.ok) throw new Error('Health refresh failed');
        const health = await response.json();
        ['worker','shop_worker','monitor','provision','telegram'].forEach(key => {
          const node = document.querySelector(`[data-rp-health="${key}"]`);
          if (!node) return;
          node.className = `rp-status ${health[key].state}`;
          node.textContent = [node.dataset.label, health[key].label].filter(Boolean).join(' · ');
          node.title = [health[key].at || 'No heartbeat', ...(health[key].unhealthy || [])].join(' · ');
          const detail = document.querySelector(`[data-rp-health-detail="${key}"]`);
          if (detail) detail.textContent = health[key].at ? `Last seen ${health[key].age}s ago · ${health[key].at}` : 'No heartbeat received';
        });
      } catch (_) {
        document.querySelectorAll('[data-rp-health]').forEach(node => {
          node.className = 'rp-status stale';
          node.textContent = [node.dataset.label,'Status unavailable'].filter(Boolean).join(' · ');
        });
      }
    };
    setInterval(() => { if (!document.hidden) refresh(); }, 20000);
  }
})();
(() => {
 const controls=['rp-peer-search','rp-peer-interface','rp-peer-status'].map(id=>document.getElementById(id));
 if(controls.some(x=>!x))return;
 const rows=[...document.querySelectorAll('[data-rp-peer]')];
 const filter=()=>{let visible=0;for(const row of rows){row.hidden=!(row.dataset.search.includes(controls[0].value.trim().toLowerCase())&&(!controls[1].value||row.dataset.interface===controls[1].value)&&(!controls[2].value||row.dataset.connection===controls[2].value));if(!row.hidden)visible++;}document.getElementById('rp-peer-no-match').hidden=visible>0||!rows.length;};
 controls.forEach(el=>el.addEventListener('input',filter));
})();

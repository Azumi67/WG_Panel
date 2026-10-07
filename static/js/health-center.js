(() => {
  const strip = document.getElementById('health-center-strip');
  if (!strip) return;
  const drawer = document.getElementById('health-center-drawer');
  const openBtn = document.getElementById('health-center-open');
  const refreshBtn = document.getElementById('health-center-refresh');
  const list = document.getElementById('hc-list');
  const overall = document.getElementById('hc-overall');
  let lastFocus = null;
  let controller = null;

  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const iconFor = (state) => state === 'healthy' ? 'fa-check' : state === 'attention' ? 'fa-triangle-exclamation' : state === 'review' ? 'fa-eye' : 'fa-circle-question';
  const labelFor = (state) => state === 'healthy' ? 'Healthy' : state === 'attention' ? 'Attention' : state === 'review' ? 'Review' : 'Unknown';

  function setOpen(open) {
    if (!drawer) return;
    if (open) {
      lastFocus = document.activeElement;
      drawer.hidden = false;
      drawer.setAttribute('aria-hidden', 'false');
      openBtn?.setAttribute('aria-expanded', 'true');
      document.body.classList.add('hc-open');
      requestAnimationFrame(() => drawer.querySelector('[data-hc-close]')?.focus());
    } else {
      drawer.hidden = true;
      drawer.setAttribute('aria-hidden', 'true');
      openBtn?.setAttribute('aria-expanded', 'false');
      document.body.classList.remove('hc-open');
      if (lastFocus && typeof lastFocus.focus === 'function') lastFocus.focus();
    }
  }

  function render(data) {
    const counts = data?.counts || {};
    const headline = data?.headline || 'Health summary unavailable';
    document.getElementById('health-center-headline').textContent = headline;
    document.getElementById('hc-count-healthy').textContent = counts.healthy ?? 0;
    document.getElementById('hc-count-review').textContent = (counts.review ?? 0) + (counts.unknown ?? 0);
    document.getElementById('hc-count-attention').textContent = counts.attention ?? 0;
    if (overall) overall.dataset.state = data?.state || 'unknown';
    const ot = document.getElementById('hc-overall-title');
    if (ot) ot.textContent = headline;
    const meta = document.getElementById('hc-overall-meta');
    if (meta) meta.textContent = data?.state === 'healthy' ? 'Core panel services report healthy.' : 'Review the items below; Health Center itself makes no changes.';

    if (!list) return;
    list.innerHTML = (data?.items || []).map(item => {
      const href = item.href ? `<a class="hc-item-open" href="${esc(item.href)}" aria-label="Open ${esc(item.label)}"><i class="fas fa-arrow-right"></i></a>` : '';
      return `<article class="hc-item" data-state="${esc(item.state)}">
        <span class="hc-item-state"><i class="fas ${iconFor(item.state)}"></i></span>
        <div class="hc-item-copy"><div class="hc-item-title"><b>${esc(item.label)}</b><span class="hc-state-pill">${labelFor(item.state)}</span></div><p>${esc(item.summary)}</p>${item.detail ? `<small>${esc(item.detail)}</small>` : ''}</div>${href}</article>`;
    }).join('') || '<div class="hc-item"><div class="hc-item-copy"><b>No health data</b><p>Refresh the Health Center.</p></div></div>';
  }

  async function load() {
    if (controller) controller.abort();
    controller = new AbortController();
    refreshBtn?.classList.add('busy');
    try {
      const res = await fetch('/api/health-center', {credentials:'same-origin', signal:controller.signal});
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.ok === false) throw new Error(data.error || `HTTP ${res.status}`);
      render(data);
    } catch (err) {
      if (err?.name === 'AbortError') return;
      render({state:'unknown', headline:'Health Center could not refresh', counts:{healthy:0,review:0,attention:0,unknown:1}, items:[{label:'Health Center',state:'unknown',summary:'The read-only health endpoint did not respond.',detail:'Open panel logs or Operations for more detail.',href:'/operations'}]});
    } finally {
      refreshBtn?.classList.remove('busy');
    }
  }

  openBtn?.addEventListener('click', () => { setOpen(true); load(); });
  refreshBtn?.addEventListener('click', load);
  drawer?.addEventListener('click', e => { if (e.target.closest('[data-hc-close]')) setOpen(false); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && drawer && !drawer.hidden) setOpen(false); });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) load(); });
  load();
  setInterval(() => { if (!document.hidden) load(); }, 60000);
})();

(() => {
  'use strict';
  const root = document.getElementById('panel-notifications');
  if (!root) return;
  const desktop = root.parentNode, anchor = root.nextSibling;
  const mobile = document.getElementById('wg-mobile-topbar'), sidebar = document.querySelector('.sb2-bottom');
  const media = matchMedia('(max-width:760px)'), bell = root.querySelector('button'), menu = root.querySelector('section');
  const badge = root.querySelector('[data-review-count]'), purchases = root.querySelector('[data-purchase-list]');
  const health = root.querySelector('[data-alert-list]'), refresh = root.querySelector('[data-alert-refresh]');
  const purchasePath = '/resellers/api/purchase-alerts', healthPath = '/resellers/api/health-alert-reads';
  let version = 0, healthBusy = false, healthLoaded = 0;
  function place() {
    if (media.matches && mobile) mobile.append(root);
    else if (document.documentElement.dataset.design === 'legacy' && sidebar) sidebar.prepend(root);
    else desktop.insertBefore(root, anchor);
  }
  media.addEventListener('change', place);
  new MutationObserver(place).observe(document.documentElement, {attributes:true, attributeFilter:['data-design']});
  place();
  async function api(path, body) {
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 11000);
    const headers = {'X-Panel-Viewer':root.dataset.admin};
    const options = {credentials:'same-origin', cache:'no-store', signal:controller.signal, headers};
    if (body) {
      options.method = 'POST'; headers['Content-Type'] = 'application/json';
      headers['X-CSRFToken'] = root.dataset.csrf; options.body = JSON.stringify(body);
    }
    try {
      const res = await fetch(path, options);
      if (!res.ok) throw Error();
      return await res.json();
    } finally { clearTimeout(timer); }
  }
  function link(href, title, description, label) {
    const row = document.createElement('a');
    row.className = 'panel-alert-item';
    row.href = typeof href === 'string' && /^\/(?!\/)/.test(href) ? href : '/logs';
    const name = document.createElement('b'); name.textContent = title; row.append(name);
    if (label) {
      const tag = document.createElement('span');
      tag.className = 'panel-alert-state'; tag.textContent = label; row.append(tag);
    }
    if (description) {
      const detail = document.createElement('p'); detail.textContent = description; row.append(detail);
    }
    return row;
  }
  function showBadge(count) {
    badge.hidden = !count; badge.textContent = count > 99 ? '99+' : count;
    bell.setAttribute('aria-label', count ? 'Panel alerts, '+count+' unread' : 'Panel alerts');
  }
  function markRow(row) {
    row.classList.remove('unread');
    const tag = row.querySelector('.panel-alert-state');
    if (tag) tag.textContent = 'Read';
  }
  const observePurchases = window.observeInbox(menu, async rows => {
    const result = await api(purchasePath, {ids:rows.map(row => Number(row.dataset.order))});
    rows.forEach(markRow); showBadge(result.unread);
  });
  const observeHealth = window.observeInbox(menu, async rows => {
    await api(healthPath, Object.fromEntries(rows.map(row => [row.dataset.health, row.dataset.signature])));
    rows.forEach(markRow);
  });
  async function loadPurchases() {
    if (document.hidden) return;
    const current = ++version, detailed = !menu.hidden;
    try {
      const data = await api(purchasePath+(detailed ? '' : '?summary=1'));
      if (current !== version) return;
      showBadge(data.unread);
      if (!detailed || menu.hidden) return;
      purchases.replaceChildren(); purchases.hidden = !data.count;
      if (!data.count) return;
      const label = data.count === 1 ? '1 receipt awaiting review' : data.count+' receipts awaiting review';
      purchases.append(link(data.href, label, '', 'View queue'));
      for (const item of data.items) {
        const unread = !data.read.includes(item.id);
        const row = link(item.href, 'Order #'+item.id+' · '+item.plan, item.amount, unread ? 'New' : 'Read');
        row.dataset.order = item.id; row.classList.toggle('unread', unread); purchases.append(row);
      }
      observePurchases(purchases.querySelectorAll('.unread'));
    } catch (_) {
      if (!menu.hidden && current === version) {
        purchases.hidden = false;
        purchases.replaceChildren(link('/resellers?tab=orders&status=review','Open purchase reviews','Could not refresh the receipt count.'));
      }
    }
  }
  async function loadHealth(force) {
    if (healthBusy) return;
    if (!force && Date.now()-healthLoaded < 30000) { observeHealth(health.querySelectorAll('.unread')); return; }
    healthBusy = true; refresh.disabled = true; health.setAttribute('aria-busy','true');
    try {
      const [data, seen] = await Promise.all([api('/api/health-center'), api(healthPath)]);
      if (menu.hidden) return;
      const recovered = {}, rows = [];
      for (const item of data.items || []) {
        if (item.state === 'healthy') { if (seen[item.id]) recovered[item.id] = null; continue; }
        const signature = item.state+' '+item.summary;
        const unread = seen[item.id] !== signature;
        const row = link(item.href, item.label, item.summary, unread ? 'New' : 'Read');
        row.dataset.health = item.id; row.dataset.signature = signature;
        row.classList.toggle('unread', unread); rows.push(row);
      }
      health.replaceChildren(...rows);
      if (!rows.length) health.textContent = 'No current panel health alerts.';
      if (Object.keys(recovered).length) await api(healthPath, recovered);
      healthLoaded = Date.now();
      observeHealth(health.querySelectorAll('.unread'));
    } catch (_) { health.textContent = 'Could not check panel health. Use Refresh to try again.'; }
    finally { healthBusy = false; refresh.disabled = false; health.setAttribute('aria-busy','false'); }
  }
  async function acknowledgeOrder(details) {
    if (!details.open || document.hidden) return;
    const order = details.closest('.rp-inbox-order[data-reviewable]');
    if (!order || order.dataset.read === 'yes') return;
    try {
      const result = await api(purchasePath, {ids:[Number(order.dataset.reviewable)]});
      order.dataset.read = 'yes'; showBadge(result.unread);
    } catch (_) {}
  }
  document.addEventListener('toggle', e => {
    if (e.target.matches('.rp-order-details')) acknowledgeOrder(e.target);
  }, true);
  document.querySelectorAll('.rp-order-details[open]').forEach(acknowledgeOrder);
  function close() { menu.hidden = true; bell.setAttribute('aria-expanded','false'); observePurchases([]); observeHealth([]); }
  bell.onclick = () => {
    if (!menu.hidden) return close();
    menu.hidden = false; bell.setAttribute('aria-expanded','true'); loadPurchases(); loadHealth(false);
  };
  refresh.onclick = () => { loadPurchases(); loadHealth(true); };
  document.addEventListener('click', e => { if (!root.contains(e.target) && !menu.hidden) close(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && !menu.hidden) { close(); bell.focus(); } });
  document.addEventListener('purchase-reviewed', loadPurchases);
  document.addEventListener('visibilitychange', () => { if (!document.hidden && menu.hidden) loadPurchases(); });
  loadPurchases();
  setInterval(() => { if (!document.hidden && menu.hidden) loadPurchases(); }, 45000);
})();

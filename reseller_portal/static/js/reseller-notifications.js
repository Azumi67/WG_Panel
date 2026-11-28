(() => {
  'use strict';
  document.addEventListener('DOMContentLoaded', () => {
    const root = document.querySelector('[data-notification-account]');
    if (!root) return;
    const desktop = root.parentNode, anchor = root.nextSibling;
    const mobile = document.getElementById('wg-mobile-topbar'), media = matchMedia('(max-width:760px)');
    function place() { if (media.matches && mobile) mobile.append(root); else desktop.insertBefore(root, anchor); }
    media.addEventListener('change', place);
    place();
    const byId = id => document.getElementById(id);
    const bell = byId('rp-bell'), menu = byId('rp-notification-menu'), list = byId('rp-notification-list');
    const prev = byId('rp-notice-prev'), next = byId('rp-notice-next'), read = byId('rp-mark-read');
    const path = '/r/api/notifications';
    let page = 1, pages = 1, latest = 0, unread = 0, generation = 0;
    async function api(query, body) {
      const headers = {'X-Reseller-Account': root.dataset.notificationAccount};
      const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 10000);
      const options = {credentials:'same-origin', cache:'no-store', signal:controller.signal, headers};
      if (body) {
        options.method = 'POST';
        headers['Content-Type'] = 'application/json';
        headers['X-CSRFToken'] = document.querySelector('meta[name="csrf-token"]')?.content || '';
        options.body = JSON.stringify(body);
      }
      try {
        const response = await fetch(path+query, options);
        if (!response.ok) throw Error();
        return await response.json();
      } finally { clearTimeout(timer); }
    }
    function badge(count) {
      unread = count;
      byId('rp-unread').hidden = !count;
      byId('rp-unread').textContent = count > 99 ? '99+' : count;
      bell.setAttribute('aria-label', count ? 'Notifications, '+count+' unread' : 'Notifications');
      read.disabled = !count;
    }
    const observe = window.observeInbox(menu, async rows => {
      const data = await api('', {ids: rows.map(row => Number(row.dataset.id))});
      rows.forEach(row => row.classList.remove('unread'));
      badge(data.unread);
    });
    function article(item) {
      const row = document.createElement('article'), icon = document.createElement('i');
      row.dataset.id = item.id;
      row.className = item.unread ? 'unread' : '';
      icon.className = 'fas '+({expiry:'fa-clock', usage:'fa-chart-simple', admin:'fa-envelope'}[item.kind] || 'fa-bell');
      icon.setAttribute('aria-hidden','true');
      const content = document.createElement('div'), title = document.createElement('b');
      const body = document.createElement('p'), time = document.createElement('time');
      title.textContent = {expiry:'Plan expiry', usage:'Usage alert', admin:'Account message'}[item.kind] || 'Notification';
      body.textContent = item.body;
      time.dateTime = item.at;
      time.dataset.rpTime = '';
      time.textContent = window.rpHumanDate?.(item.at) || new Date(item.at).toLocaleString();
      content.append(title, body, time);
      row.append(icon, content);
      return row;
    }
    async function load(target=page) {
      if (document.hidden) return;
      const current = ++generation, detailed = !menu.hidden;
      try {
        const data = await api(detailed ? '?page='+target : '?summary=1');
        if (current !== generation) return;
        badge(data.unread);
        if (!detailed || menu.hidden) return;
        latest = data.latest;
        page = data.pager.page; pages = data.pager.pages;
        list.replaceChildren(...data.items.map(article));
        if (!data.items.length) list.textContent = 'You’re all caught up.';
        list.scrollTop = 0;
        byId('rp-notice-page').textContent = page+' / '+pages;
        prev.disabled = page <= 1; next.disabled = page >= pages;
        window.rpRefreshDates?.();
        observe(list.querySelectorAll('.unread'));
      } catch (_) {
        if (current === generation && !menu.hidden) {
          list.textContent = 'Notifications could not be loaded. ';
          const retry = document.createElement('button');
          retry.textContent = 'Retry'; retry.onclick = () => load(target); list.append(retry);
        }
      }
    }
    function close() { menu.hidden = true; bell.setAttribute('aria-expanded','false'); observe([]); }
    bell.onclick = () => {
      if (!menu.hidden) return close();
      menu.hidden = false; bell.setAttribute('aria-expanded','true');
      load(1);
    };
    prev.onclick = () => load(page-1); next.onclick = () => load(page+1);
    read.onclick = async () => {
      try { await api('', {through: latest}); await load(); }
      catch (_) { list.textContent = 'Could not save read status. Reopen notifications to retry.'; }
    };
    document.addEventListener('click', e => { if (!root.contains(e.target) && !menu.hidden) close(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape' && !menu.hidden) { close(); bell.focus(); } });
    document.addEventListener('visibilitychange', () => { if (menu.hidden) load(); });
    if (document.body.dataset.page !== 'reseller.reseller_security') load();
    setInterval(() => { if (menu.hidden) load(); }, 60000);
  });
})();

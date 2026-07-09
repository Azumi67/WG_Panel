(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const on = (el, ev, fn, opts) => el && el.addEventListener(ev, fn, opts);

  const TBody = $('#nodes-body');
  const Empty = $('#nodes-empty');
  if (!TBody) return;

  const Modal = $('#node-mini-modal');
  const OpenBtn = $('#open-node-modal');
  const EmptyAddBtn = $('#empty-add-node');
  const RefreshBtn = $('#nodes-refresh');
  const CloseBtn = $('#node-mini-close');
  const CancelBtn = $('#node-mini-cancel');
  const Form = $('#node-form');
  const InName = $('#n-name');
  const InURL = $('#n-url');
  const InKey = $('#n-key');

  const stats = {
    total: $('#nodes-total'),
    online: $('#nodes-online'),
    enabled: $('#nodes-enabled'),
    peers: $('#nodes-peers'),
    syncDot: $('#nodes-sync-dot'),
    syncText: $('#nodes-sync-text'),
  };

  let editingId = null;
  let lastNodes = [];
  let loading = false;

  const toast = (m, t = 'info', sticky = false) => {
    let msg = m;
    if (m && typeof m === 'object') {
      const title = m.title || '';
      const body = m.body || '';
      msg = title && body ? `${title}: ${body}` : (title || body || JSON.stringify(m));
    }
    if (window.toastSafe) return window.toastSafe(msg, t, sticky);
    if (window.toast) return window.toast(msg, t);
    console.log('[toast]', t, msg);
  };

  const confirmBox = (opts) =>
    (window.uiConfirm ? window.uiConfirm(opts) : Promise.resolve(confirm(opts?.body || 'Are you sure?')));

  function esc(v) {
    return String(v ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
  }

  function readCookie(name) {
    return document.cookie.split('; ').map(x => x.split('=')).find(([k]) => k === name)?.[1] || '';
  }

  function csrfHeaders(extra = {}) {
    return {
      'X-CSRFToken': readCookie('csrf_token') || ($('meta[name="csrf-token"]')?.content || ''),
      ...extra,
    };
  }

  async function api(path, opts = {}) {
    const res = await fetch(path, { credentials: 'same-origin', ...opts });
    const text = await res.text();
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch {}
    if (!res.ok) {
      const msg = (body && (body.error || body.message || body.detail)) || text || `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return body;
  }

  function setSync(state, text) {
    if (stats.syncDot) stats.syncDot.className = `np-status-dot ${state}`;
    if (stats.syncText) stats.syncText.textContent = text;
    const icon = RefreshBtn?.querySelector('i');
    if (icon) icon.classList.toggle('syncing', state === 'loading');
  }

  function setText(el, value) { if (el) el.textContent = String(value); }

  function timeAgoISO(iso) {
    if (!iso) return 'Never';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return 'Never';
    const sec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
    if (sec < 45) return 'just now';
    const min = Math.floor(sec / 60);
    if (min < 60) return `${min}m ago`;
    const hrs = Math.floor(min / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
  }

  function refreshTime() {
    $$('.time-ago').forEach(el => { el.textContent = timeAgoISO(el.getAttribute('data-iso')); });
  }

  function pill(type, icon, label, value = null, title = '') {
    const val = value === null || value === undefined ? '' : ` <b>${esc(value)}</b>`;
    return `<span class="np-pill ${type}" title="${esc(title)}"><i class="fas ${icon}"></i> ${esc(label)}${val}</span>`;
  }

  function healthPills(n) {
    if (!n.enabled) {
      return `<div class="np-badges">${pill('disabled', 'fa-pause', 'Disabled', null, 'This node is disabled in the panel')}</div>`;
    }
    if (n.online) {
      return `<div class="np-badges">${pill('online', 'fa-signal', 'Online')}${pill('enabled', 'fa-toggle-on', 'Enabled')}</div>`;
    }
    return `<div class="np-badges">${pill('offline', 'fa-circle-xmark', 'Offline')}${pill('enabled', 'fa-toggle-on', 'Enabled')}</div>`;
  }

  function peerSummaryHTML(pc = {}) {
    const total = Number(pc.total || 0);
    const online = Number(pc.online || 0);
    const blocked = Number(pc.blocked || 0);
    const depleting = Number(pc.depleting || 0);
    return `<div class="node-peer-tags">
      ${pill('offline', 'fa-users', 'All', total)}
      ${pill('online', 'fa-signal', 'On', online)}
      ${blocked ? pill('blocked', 'fa-ban', 'Blocked', blocked) : ''}
      ${depleting ? pill('depleting', 'fa-hourglass-half', 'Low', depleting) : ''}
    </div>`;
  }

  function ifaceSummaryHTML(ic = {}) {
    const total = Number(ic.count ?? ic.total ?? 0);
    const up = Number(ic.up || 0);
    const down = Number(ic.down ?? Math.max(0, total - up));
    return `<div class="node-peer-tags">
      ${pill('online', 'fa-network-wired', 'Up', up)}
      ${down ? pill('offline', 'fa-circle-xmark', 'Down', down) : ''}
      ${pill('disabled', 'fa-layer-group', 'Total', total)}
    </div>`;
  }

  function renderRows(nodes) {
    lastNodes = nodes || [];
    if (!lastNodes.length) {
      TBody.innerHTML = '';
      if (Empty) Empty.style.display = 'block';
      updateTopStats();
      return;
    }

    if (Empty) Empty.style.display = 'none';
    TBody.innerHTML = lastNodes.map(n => `
      <tr data-id="${esc(n.id)}">
        <td>
          <div class="node-title">
            <div class="node-avatar"><i class="fas fa-server"></i></div>
            <div>
              <div class="node-name">${esc(n.name || `Node ${n.id}`)}</div>
              <div class="node-id">ID ${esc(n.id)}</div>
            </div>
          </div>
        </td>
        <td><div class="node-url" title="${esc(n.base_url || '')}">${esc(n.base_url || '—')}</div></td>
        <td class="status" data-id="${esc(n.id)}">${healthPills(n)}</td>
        <td class="node-peers" data-id="${esc(n.id)}">${peerSummaryHTML(n.summary?.peers || {})}</td>
        <td class="node-ifaces" data-id="${esc(n.id)}">${ifaceSummaryHTML(n.summary?.interfaces || {})}</td>
        <td><span class="node-last time-ago" data-iso="${esc(n.last_seen || '')}">${timeAgoISO(n.last_seen)}</span></td>
        <td class="nodes-actions-cell">
          <label class="toggle-switch" title="Enable or disable node">
            <input type="checkbox" class="n-enabled" data-id="${esc(n.id)}" ${n.enabled ? 'checked' : ''}>
            <span class="toggle-switch-track"></span><span class="toggle-switch-thumb"></span>
          </label>
          <button class="icon-btn ghost n-open-peers" type="button" title="Open node peers"><i class="fas fa-users"></i></button>
          <button class="icon-btn ghost n-edit" type="button" title="Edit node"><i class="fas fa-pen"></i></button>
          <button class="icon-btn danger n-del" type="button" title="Delete node"><i class="fas fa-trash"></i></button>
        </td>
      </tr>
    `).join('');
    updateTopStats();
  }

  function updateTopStats(extraPeerTotal = null) {
    const total = lastNodes.length;
    const online = lastNodes.filter(n => n.online && n.enabled).length;
    const enabled = lastNodes.filter(n => n.enabled).length;
    const peers = extraPeerTotal ?? lastNodes.reduce((sum, n) => sum + Number(n.summary?.peers?.total || 0), 0);
    setText(stats.total, total);
    setText(stats.online, online);
    setText(stats.enabled, enabled);
    setText(stats.peers, peers);
  }

  async function updateHealth() {
    const rows = $$('tr[data-id]', TBody);
    await Promise.all(rows.map(async tr => {
      const id = tr.dataset.id;
      const enabled = !!tr.querySelector('.n-enabled')?.checked;
      const n = lastNodes.find(x => String(x.id) === String(id)) || { id, enabled };
      n.enabled = enabled;
      if (!enabled) {
        n.online = false;
      } else {
        try {
          const j = await api(`/api/nodes/${id}/health`);
          n.online = !!j?.online;
          if (n.online && j?.last_seen) n.last_seen = j.last_seen;
        } catch {
          n.online = false;
        }
      }
      const cell = $(`.status[data-id="${CSS.escape(String(id))}"]`, TBody);
      if (cell) cell.innerHTML = healthPills(n);
    }));
    updateTopStats();
  }

  async function updateSummaries() {
    const rows = $$('tr[data-id]', TBody);
    let peerTotal = 0;
    await Promise.all(rows.map(async tr => {
      const id = tr.dataset.id;
      const n = lastNodes.find(x => String(x.id) === String(id));
      const peerCell = $(`.node-peers[data-id="${CSS.escape(String(id))}"]`, TBody);
      const ifaceCell = $(`.node-ifaces[data-id="${CSS.escape(String(id))}"]`, TBody);
      try {
        const j = await api(`/api/nodes/${id}/summary`);
        const summary = { peers: j?.peers || {}, interfaces: j?.interfaces || {} };
        if (n) n.summary = summary;
        peerTotal += Number(summary.peers.total || 0);
        if (peerCell) peerCell.innerHTML = peerSummaryHTML(summary.peers);
        if (ifaceCell) ifaceCell.innerHTML = ifaceSummaryHTML(summary.interfaces);
      } catch {
        if (peerCell) peerCell.innerHTML = peerSummaryHTML(n?.summary?.peers || {});
        if (ifaceCell) ifaceCell.innerHTML = ifaceSummaryHTML(n?.summary?.interfaces || {});
      }
    }));
    updateTopStats(peerTotal || null);
  }

  async function load() {
    if (loading) return;
    loading = true;
    setSync('loading', 'Syncing…');
    try {
      const j = await api('/api/nodes');
      const rows = Array.isArray(j) ? j : (j?.nodes || j?.data || []);
      renderRows(rows);
      await Promise.all([updateHealth(), updateSummaries()]);
      refreshTime();
      setSync('ok', rows.length ? 'Updated now' : 'Ready');
    } catch (err) {
      console.error('Failed to load nodes:', err);
      TBody.innerHTML = '';
      if (Empty) Empty.style.display = 'block';
      setSync('bad', 'Failed');
      toast({ title: 'Failed to load nodes', body: err?.message || String(err) }, 'error');
    } finally {
      loading = false;
    }
  }

  function modalClassMode() {
    if (Modal && Modal.hasAttribute('hidden')) Modal.removeAttribute('hidden');
  }

  function openModal() {
    if (!Modal) return;
    modalClassMode();
    Modal.classList.add('open');
    document.body.classList.add('modal-open');
    setTimeout(() => InName?.focus(), 30);
  }

  function closeModal() {
    if (!Modal) return;
    Modal.classList.remove('open');
    document.body.classList.remove('modal-open');
  }

  function onCreate() {
    editingId = null;
    Form?.reset();
    if (InKey) {
      InKey.value = '';
      InKey.required = true;
    }
    const title = $('#node-mini-title');
    if (title) title.innerHTML = '<i class="fas fa-circle-plus"></i> Add node';
    openModal();
  }

  on(OpenBtn, 'click', onCreate);
  on(EmptyAddBtn, 'click', onCreate);
  on(RefreshBtn, 'click', load);
  on(CloseBtn, 'click', closeModal);
  on(CancelBtn, 'click', closeModal);
  on(Modal, 'click', (e) => { if (e.target?.dataset?.close) closeModal(); });
  on(document, 'keydown', (e) => {
    if (Modal?.classList.contains('open') && e.key === 'Escape') closeModal();
  });
  window.addEventListener('hashchange', closeModal);

  on(Form, 'submit', async (e) => {
    e.preventDefault();
    const name = (InName?.value || '').trim();
    const base_url = (InURL?.value || '').trim();
    const api_key = (InKey?.value || '').trim();
    if (!name || !base_url || (!editingId && !api_key)) {
      toast({ title: 'Missing fields', body: 'Please fill in the node name, base URL, and API key.' }, 'warn');
      return;
    }
    const payload = { name, base_url };
    if (!editingId || api_key) payload.api_key = api_key;
    const url = editingId ? `/api/nodes/${editingId}` : '/api/nodes';
    const method = editingId ? 'PATCH' : 'POST';
    try {
      await api(url, {
        method,
        headers: csrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(payload),
      });
      closeModal();
      await load();
      toast({ title: editingId ? 'Node updated' : 'Node added', body: `"${name}" is ready.` }, 'success');
    } catch (err) {
      toast({ title: editingId ? 'Failed to update node' : 'Failed to add node', body: err?.message || String(err) }, 'error');
    }
  });

  on(TBody, 'click', async (e) => {
    const btnOpen = e.target.closest('.n-open-peers');
    const btnDel = e.target.closest('.n-del');
    const btnEdit = e.target.closest('.n-edit');
    if (!btnOpen && !btnDel && !btnEdit) return;

    const tr = e.target.closest('tr');
    const id = tr?.dataset?.id;
    if (!id) return;
    const node = lastNodes.find(n => String(n.id) === String(id));
    const nodeName = node?.name || tr.querySelector('.node-name')?.textContent?.trim() || `Node #${id}`;

    if (btnOpen) {
      try { localStorage.setItem('peer_scope', String(id)); } catch {}
      window.location.href = '/users';
      return;
    }

    if (btnEdit) {
      editingId = id;
      if (InName) InName.value = node?.name || tr.querySelector('.node-name')?.textContent?.trim() || '';
      if (InURL) InURL.value = node?.base_url || tr.querySelector('.node-url')?.textContent?.trim() || '';
      if (InKey) {
        InKey.value = '';
        InKey.required = false;
      }
      const title = $('#node-mini-title');
      if (title) title.innerHTML = '<i class="fas fa-pen"></i> Edit node';
      openModal();
      return;
    }

    if (btnDel) {
      const ok = await confirmBox({
        title: 'Delete node',
        body: `Delete node "${nodeName}"? This removes it from the panel.`,
        okText: 'Delete',
        cancelText: 'Cancel',
      });
      if (!ok) return;
      try {
        await api(`/api/nodes/${id}`, { method: 'DELETE', headers: csrfHeaders() });
        await load();
        toast({ title: 'Node deleted', body: `"${nodeName}" was removed.` }, 'success');
      } catch (err) {
        toast({ title: 'Failed to delete node', body: err?.message || String(err) }, 'error');
      }
    }
  });

  on(TBody, 'change', async (e) => {
    const chk = e.target.closest('.n-enabled');
    if (!chk) return;
    const tr = chk.closest('tr');
    const id = tr?.dataset?.id;
    if (!id) return;
    const enabled = chk.checked;
    const node = lastNodes.find(n => String(n.id) === String(id));
    const nodeName = node?.name || `Node #${id}`;
    try {
      await api(`/api/nodes/${id}`, {
        method: 'PATCH',
        headers: csrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ enabled }),
      });
      if (node) node.enabled = enabled;
      await updateHealth();
      toast({ title: enabled ? 'Node enabled' : 'Node disabled', body: `"${nodeName}" was updated.` }, 'success');
    } catch (err) {
      chk.checked = !enabled;
      toast({ title: 'Failed to update node', body: err?.message || String(err) }, 'error');
    }
  });

  load();
  setInterval(refreshTime, 30000);
  setInterval(updateHealth, 60000);
})();

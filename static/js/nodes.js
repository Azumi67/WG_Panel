(() => {
  const $  = (sel, root=document) => root.querySelector(sel);
  const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));
    const on = (el, ev, fn, opts) => el && el.addEventListener(ev, fn, opts);

  const toast = (m, t = 'info', sticky = false) => {
    let msg = m;

    if (m && typeof m === 'object') {
      const title = m.title || '';
      const body  = m.body  || '';
      if (title && body)       msg = `${title}: ${body}`;
      else if (title || body) msg = title || body;
      else {
        try { msg = JSON.stringify(m); }
        catch { msg = String(m); }
      }
    }

    if (window.toastSafe) {
      return window.toastSafe(msg, t, sticky);
    }
    if (window.toast) {
      return window.toast(msg, t);
    }
    console.log('[toast]', t, msg);
    return null;
  };

  const confirmBox = (opts) =>
    (window.uiConfirm ? window.uiConfirm(opts)
                      : Promise.resolve(confirm(opts?.body || 'Are you sure?')));

  const TBody  = $('#nodes-body');
  const Empty  = $('#nodes-empty');
  const Header = $('.page-header');
  if (!TBody) {
    return;
  }

  const Modal     = $('#node-mini-modal');
  const OpenBtn   = $('#open-node-modal');
  const CloseBtn  = $('#node-mini-close');
  const CancelBtn = $('#node-mini-cancel');
  const Form      = $('#node-form');
  const InName    = $('#n-name');
  const InURL     = $('#n-url');
  const InKey     = $('#n-key');
  let editingId = null;

  const FabBtn    = $('#fab-add-node');
  window.addEventListener('hashchange', () => {
  document.querySelectorAll('.modal.open').forEach(m => m.classList.remove('open'));
  document.body.classList.remove('modal-open');
});

  function readCookie(name) {
    return document.cookie
      .split('; ')
      .map(x => x.split('='))
      .find(([k]) => k === name)?.[1] || '';
  }

  async function api(path, opts = {}) {
    const res  = await fetch(path, { credentials: 'same-origin', ...opts });
    const text = await res.text();
    let body   = null; try { body = text ? JSON.parse(text) : null; } catch {}
    if (!res.ok) {
      const msg = (body && (body.error || body.message)) || text || `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return body;
  }

  function statusP(status) {
    const s = (status || '').toLowerCase();
    const cls = s === 'online'   ? 'status-online'
              : s === 'offline'  ? 'status-offline'
              : s === 'disabled' ? 'status-disabled'
              : 'status-unknown';
    return `<span class="status-pill ${cls}"><span class="dot"></span>${s || 'unknown'}</span>`;
  }

  function timeAgoISO(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    const sec = Math.max(0, (Date.now() - d.getTime()) / 1000);
    if (sec < 60) return 'just now';
    const m = Math.floor(sec / 60); if (m < 60) return `${m} min${m>1?'s':''} ago`;
    const h = Math.floor(m / 60);   if (h < 24)  return `${h} hour${h>1?'s':''} ago`;
    const days = Math.floor(h / 24); return `${days} day${days>1?'s':''} ago`;
  }

  function refreshTime() {
    $$('.time-ago').forEach(el => {
      el.textContent = timeAgoISO(el.getAttribute('data-iso'));
    });
  }

  function modalClassMode() {
    if (!Modal) return;
    if (Modal.hasAttribute('hidden')) Modal.removeAttribute('hidden');
  }

  function openModal() {
    if (!Modal) return;
    modalClassMode();
    Modal.classList.add('open');
    document.body.classList.add('modal-open');
    InName && InName.focus();
  }

  function onCreate() {
    editingId = null;
    if (Form) Form.reset();
    if (InKey) {
      InKey.value = '';
      InKey.required = true;
    }
    const title = $('#node-mini-title');
    if (title) {
      title.innerHTML = '<i class="fas fa-circle-plus"></i> Add node';
    }
    openModal();
  }

  function closeModal() {
    if (!Modal) return;
    Modal.classList.remove('open');      
    document.body.classList.remove('modal-open');
  }

  on(OpenBtn, 'click', onCreate);
  on(FabBtn,  'click', onCreate);


  on(OpenBtn, 'click', openModal);
  on(FabBtn,  'click', openModal);        
  on(CloseBtn,  'click', closeModal);
  on(CancelBtn, 'click', closeModal);
  on(Modal, 'click', (e) => { if (e.target?.dataset?.close) closeModal(); });
  on(document, 'keydown', (e) => {
    if (!Modal || !Modal.classList.contains('open')) return;
    if (e.key === 'Escape') closeModal();
  });

    function renderizeRows(nodes) {
    if (!TBody) return;

    if (!nodes || !nodes.length) {
      TBody.innerHTML = '';
      if (Empty) Empty.style.display = 'block';
      return;
    }
    if (Empty) Empty.style.display = 'none';

    TBody.innerHTML = nodes.map(n => `
      <tr data-id="${n.id}">
        <td>${n.name || ''}</td>
        <td class="nodes-url" title="${n.base_url || ''}">${n.base_url || ''}</td>
        <td>
          <label class="toggle-switch">
            <input type="checkbox"
                   class="n-enabled"
                   data-id="${n.id}"
                   ${n.enabled ? 'checked' : ''}>
            <span class="toggle-switch-track"></span>
            <span class="toggle-switch-thumb"></span>
          </label>
        </td>
        <td class="node-peers" data-id="${n.id}">—</td>
        <td class="node-ifaces" data-id="${n.id}">—</td>
        <td class="status" data-id="${n.id}">
          ${statusP(n.enabled && n.online ? 'online' : (n.enabled ? 'offline' : 'disabled'))}
        </td>
        <td>
          <span class="time-ago"
                data-iso="${n.last_seen || ''}">
            ${timeAgoISO(n.last_seen)}
          </span>
        </td>
        <td class="nodes-actions-cell">
          <button class="icon-btn ghost n-edit" type="button" title="Edit node">
            <i class="fas fa-pen"></i>
          </button>
          <button class="icon-btn danger n-del" type="button" title="Delete node">
            <i class="fas fa-trash"></i>
          </button>
        </td>
      </tr>
    `).join('');
  }

    async function updateHealth() {
    const slots = $$('.status', TBody);
    await Promise.all(slots.map(async el => {
      const tr = el.closest('tr');
      const enabledEl = tr ? tr.querySelector('.n-enabled') : null;

      if (enabledEl && !enabledEl.checked) {
        el.innerHTML = statusP('disabled');
        return;
      }

      const nid = el.dataset.id;
      try {
        const j = await api(`/api/nodes/${nid}/health`);
        el.innerHTML = statusP(j && j.online ? 'online' : 'offline');
      } catch {
        el.innerHTML = statusP('offline');
      }
    }));
  }

    async function updateSummaries() {
    const peerCells = $$('.node-peers', TBody);

    await Promise.all(peerCells.map(async cell => {
      const nid = cell.dataset.id;
      const ifaceCell = $(`.node-ifaces[data-id="${nid}"]`, TBody);

      try {
        const j = await api(`/api/nodes/${nid}/summary`);

        const pc = j && j.peers ? j.peers : {};
        const total  = pc.total  || 0;
        const online = pc.online || 0;
        const offline = pc.offline || 0;
        const blocked = pc.blocked || 0;

        cell.textContent = `${online}/${total} online`;
        cell.title = `${online} online, ${offline} offline, ${blocked} blocked`;

        if (ifaceCell && j && j.interfaces) {
          const c  = j.interfaces.count || 0;
          const up = j.interfaces.up    || 0;
          ifaceCell.textContent = c ? `${up}/${c} up` : '—';
        } else if (ifaceCell) {
          ifaceCell.textContent = '—';
        }
      } catch (err) {
        console.error('Failed to load node summary', err);
        cell.textContent = '—';
        if (ifaceCell) ifaceCell.textContent = '—';
      }
    }));
  }

    async function load() {
    try {
      const j = await api('/api/nodes');
      const rows = (j && (j.nodes || j.data || j)) || [];
      renderizeRows(rows);
      updateHealth();
      updateSummaries();
      refreshTime();
    } catch (e) {
      console.error('Failed to load nodes:', e);
      if (Empty) Empty.style.display = 'block';
    }
  }

    on(Form, 'submit', async (e) => {
    e.preventDefault();

    const name     = (InName?.value || '').trim();
    const base_url = (InURL?.value || '').trim();
    const api_key  = (InKey?.value || '').trim();

    if (!name || !base_url || (!editingId && !api_key)) {
      toast({
      title: 'Missing fields',
      body: 'Please fill in name, URL and API key.',
      }, 'warn');
      return;
    }

    const payload = { name, base_url };
    if (!editingId || api_key) {
      payload.api_key = api_key;
    }

    const url    = editingId ? `/api/nodes/${editingId}` : '/api/nodes';
    const method = editingId ? 'PATCH' : 'POST';

    try {
      await api(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': readCookie('csrf_token') || ($('meta[name="csrf-token"]')?.content || '')
        },
        body: JSON.stringify(payload)
      });
      closeModal();
      await load();
      toast({
      title: editingId ? 'Node updated' : 'Node added',
      body: editingId
      ? `Node "${name}" was updated successfully.`
      : `Node "${name}" was added to your nodes list.`,
      }, 'success');
        } catch (err) {
      console.error(err);
      toast({
        title: editingId ? 'Failed to update node' : 'Failed to create node',
        body: err?.message || String(err),
      }, 'error');
    }

  });

    on(TBody, 'click', async (e) => {
    const btnDel  = e.target.closest('.n-del');
    const btnEdit = e.target.closest('.n-edit');
    if (!btnDel && !btnEdit) return;

    const tr = e.target.closest('tr');
    const id = tr?.dataset?.id;
    if (!id) return;

    if (btnDel) {
      const nameCell = tr.querySelector('td:nth-child(1)');
      const nodeName = nameCell ? nameCell.textContent.trim() : `Node #${id}`;

      const ok = await confirmBox({
        title: 'Delete node',
        body:  `Delete node "${nodeName}"?`,
        okText: 'Delete',
        cancelText: 'Cancel',
        tone: 'danger'
      });
      if (!ok) return;

      try {
        await api(`/api/nodes/${id}`, {
          method: 'DELETE',
          headers: {
            'X-CSRFToken': readCookie('csrf_token') || ($('meta[name="csrf-token"]')?.content || '')
          }
        });
        await load();
        toast({
          title: 'Node deleted',
          body:  `"${nodeName}" has been removed from your nodes list.`,
        }, 'success');
      } catch (err) {
        console.error(err);
        toast({
          title: 'Failed to delete node',
          body:  err?.message || String(err),
        }, 'error');
      }
      return;
    }

    if (btnEdit) {
      editingId = id;

      const nameCell = tr.querySelector('td:nth-child(1)');
      const urlCell  = tr.querySelector('.nodes-url');

      if (InName && nameCell) InName.value = nameCell.textContent.trim();
      if (InURL  && urlCell)  InURL.value  = urlCell.textContent.trim();

      if (InKey) {
        InKey.value = '';
        InKey.required = false; 
      }

      const title = $('#node-mini-title');
      if (title) {
        title.innerHTML = '<i class="fas fa-pen"></i> Edit node';
      }

      openModal();
    }
  });

    on(TBody, 'change', async (e) => {
    const chk = e.target.closest('.n-enabled');
    if (!chk) return;

    const tr = chk.closest('tr');
    const id = tr?.dataset?.id;
    if (!id) return;

    const enabled = chk.checked;
    const nameCell = tr.querySelector('td:nth-child(1)');
    const nodeName = nameCell ? nameCell.textContent.trim() : `Node #${id}`;

    try {
      await api(`/api/nodes/${id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': readCookie('csrf_token') || ($('meta[name="csrf-token"]')?.content || '')
        },
        body: JSON.stringify({ enabled })
      });

      toast({
        title: enabled ? 'Node enabled' : 'Node disabled',
        body: enabled
          ? `"${nodeName}" is now active and will be used by the panel.`
          : `"${nodeName}" has been disabled and will be skipped.`,
      }, 'success');

      updateHealth();
      updateSummaries();
    } catch (err) {
      console.error(err);
      chk.checked = !enabled; 
      toast({
        title: 'Failed to update node',
        body: err?.message || String(err),
      }, 'error');
    }
  });

  if (Header) Header.style.minHeight = '48px';
  load();
  setInterval(refreshTime, 30000);
  setInterval(updateHealth, 60000);
})();

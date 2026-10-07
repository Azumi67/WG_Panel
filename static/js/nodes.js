(() => {
  'use strict';

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  const grid = $('#nodes-grid');
  const empty = $('#nodes-empty');
  const emptyCopy = $('#nodes-empty-copy');
  const search = $('#nodes-search');
  const refreshButton = $('#nodes-refresh');
  const openButton = $('#open-node-modal');
  const emptyAddButton = $('#empty-add-node');
  const modal = $('#node-mini-modal');
  const closeButton = $('#node-mini-close');
  const cancelButton = $('#node-mini-cancel');
  const form = $('#node-form');
  const nameInput = $('#n-name');
  const urlInput = $('#n-url');
  const keyInput = $('#n-key');
  const keyToggle = $('#node-key-toggle');
  const keyHelp = $('#node-key-help');
  const modalTitle = $('#node-mini-title');

  const stats = {
    total: $('#nodes-total'),
    reachable: $('#nodes-reachable'),
    online: $('#nodes-online'),
    offline: $('#nodes-offline'),
    disabled: $('#nodes-disabled'),
    peers: $('#nodes-peers'),
    interfaces: $('#nodes-interfaces'),
    attention: $('#nodes-attention'),
    healthLabel: $('#nodes-health-label'),
    healthFill: $('#nodes-health-fill'),
    peerNote: $('#nodes-peer-note'),
    ifaceNote: $('#nodes-iface-note'),
    attentionNote: $('#nodes-attention-note'),
    syncText: $('#nodes-sync-text'),
    syncDot: $('#nodes-sync-dot'),
    filterAll: $('#nodes-filter-all'),
    filterOnline: $('#nodes-filter-online'),
    filterOffline: $('#nodes-filter-offline'),
    filterDisabled: $('#nodes-filter-disabled'),
    filterPeers: $('#nodes-filter-peers'),
  };

  let nodes = [];
  let activeFilter = 'all';
  let searchText = '';
  let editingId = null;
  let loading = false;

  const escapeHtml = (value) => String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');

  function csrfHeaders(json = false) {
    const headers = typeof window.csrfHeaders === 'function'
      ? window.csrfHeaders(json)
      : {};
    if (json) headers['Content-Type'] = 'application/json';
    return headers;
  }

  function notify(message, type = 'info') {
    if (typeof window.toastSafe === 'function') {
      window.toastSafe(message, type);
      return;
    }
    const fn = type === 'success' ? window.toastSuccess
      : type === 'error' ? window.toastError
      : type === 'warn' ? window.toastWarn
      : window.toastInfo;
    if (typeof fn === 'function') fn(message);
  }

  async function api(url, options = {}) {
    const response = await fetch(url, {
      credentials: 'same-origin',
      cache: 'no-store',
      ...options,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.message || payload.error || `Request failed (${response.status})`);
    }
    return payload;
  }

  function setSync(state, text) {
    if (stats.syncText) stats.syncText.textContent = text;
    if (stats.syncDot) {
      stats.syncDot.className = `nodes-sync-dot ${state === 'loading' ? 'is-loading' : state === 'ok' ? 'is-ok' : state === 'bad' ? 'is-bad' : 'is-idle'}`;
    }
    refreshButton?.classList.toggle('is-loading', state === 'loading');
  }

  function parseISO(value) {
    if (!value) return null;
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  function timeAgo(value) {
    const date = parseISO(value);
    if (!date) return 'Never';
    const seconds = Math.max(0, Math.round((Date.now() - date.getTime()) / 1000));
    if (seconds < 45) return 'Just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    if (seconds < 86400 * 30) return `${Math.floor(seconds / 86400)}d ago`;
    return date.toLocaleDateString();
  }

  function nodeStatus(node) {
    if (!node.enabled) return { key: 'disabled', label: 'Disabled' };
    if (node.online) return { key: 'online', label: 'Online' };
    return { key: 'offline', label: 'Offline' };
  }

  function peerCounts(node) {
    const peers = node.summary?.peers || {};
    return {
      total: Number(peers.total || 0),
      online: Number(peers.online || 0),
      blocked: Number(peers.blocked || 0),
    };
  }

  function interfaceCounts(node) {
    const interfaces = node.summary?.interfaces || {};
    return {
      total: Number(interfaces.count || 0),
      up: Number(interfaces.up || 0),
    };
  }

  function visibleNodes() {
    const query = searchText.trim().toLowerCase();
    return nodes.filter((node) => {
      const peers = peerCounts(node);
      const info = node.summary?.info || {};
      const haystack = [
        node.id,
        node.name,
        node.base_url,
        info.host,
        info.public_ipv4,
        nodeStatus(node).label,
      ].join(' ').toLowerCase();

      if (query && !haystack.includes(query)) return false;
      if (activeFilter === 'online' && !(node.enabled && node.online)) return false;
      if (activeFilter === 'offline' && !(node.enabled && !node.online)) return false;
      if (activeFilter === 'disabled' && node.enabled) return false;
      if (activeFilter === 'with-peers' && peers.total <= 0) return false;
      return true;
    });
  }

  function endpointHost(url) {
    try {
      return new URL(url).hostname || '';
    } catch (_) {
      return '';
    }
  }

  function cardHtml(node) {
    const status = nodeStatus(node);
    const peers = peerCounts(node);
    const interfaces = interfaceCounts(node);
    const info = node.summary?.info || {};
    const lastSeen = node.summary?.last_seen || node.last_seen || '';
    const host = info.host || endpointHost(node.base_url || '');
    const publicIpv4 = info.public_ipv4 || '';
    const publicIpv6 = info.public_ipv6 || '';
    const publicIp = publicIpv4 || publicIpv6;
    const peerHealth = peers.total ? Math.round((peers.online / peers.total) * 100) : 0;
    const ifaceHealth = interfaces.total ? Math.round((interfaces.up / interfaces.total) * 100) : 0;
    const seenNote = status.key === 'online'
      ? 'Agent responded successfully'
      : status.key === 'disabled'
        ? 'Health checks are paused'
        : 'Agent could not be reached';

    return `
      <article class="node-card is-${status.key}" data-node-id="${escapeHtml(node.id)}">
        <div class="node-card__head">
          <div class="node-card__identity">
            <span class="node-card__avatar" aria-hidden="true"><i class="fas fa-server"></i></span>
            <div class="node-card__title">
              <span class="node-card__name" title="${escapeHtml(node.name || '')}">${escapeHtml(node.name || `Node ${node.id}`)}</span>
              <span class="node-card__id">Node #${escapeHtml(node.id)}${host ? ` · ${escapeHtml(host)}` : ''}</span>
            </div>
          </div>
          <span class="node-status is-${status.key}"><i class="fas fa-circle"></i>${status.label}</span>
        </div>

        <div class="node-card__endpoint">
          <div class="node-endpoint-main">
            <i class="fas fa-link" aria-hidden="true"></i>
            <code title="${escapeHtml(node.base_url || '')}">${escapeHtml(node.base_url || 'No endpoint')}</code>
            <button class="nodes-icon-btn node-copy-endpoint" type="button" title="Copy endpoint" aria-label="Copy endpoint"><i class="fas fa-copy"></i></button>
          </div>
          <div class="node-endpoint-meta">
            ${publicIp ? `<span><i class="fas fa-globe"></i><b title="${escapeHtml(publicIp)}">${escapeHtml(publicIp)}</b></span>` : '<span><i class="fas fa-globe"></i><b>Public IP unavailable</b></span>'}
            ${publicIpv4 && publicIpv6 ? `<span><i class="fas fa-code-branch"></i><b title="${escapeHtml(publicIpv6)}">IPv4 + IPv6</b></span>` : ''}
            <span><i class="fas ${node.enabled ? 'fa-shield-halved' : 'fa-pause'}"></i><b>${node.enabled ? 'Monitoring enabled' : 'Monitoring paused'}</b></span>
          </div>
        </div>

        <div class="node-card__metrics">
          <div class="node-card__metric">
            <small>Peers</small>
            <strong>${peers.total}</strong>
            <span>${peers.total ? `${peers.online} online${peers.blocked ? ` · ${peers.blocked} blocked` : ''}` : 'No peers reported'}</span>
            <div class="node-mini-track"><i style="width:${peerHealth}%"></i></div>
          </div>
          <div class="node-card__metric">
            <small>Interfaces</small>
            <strong>${interfaces.total}</strong>
            <span>${interfaces.total ? `${interfaces.up} up` : 'No interfaces reported'}</span>
            <div class="node-mini-track is-blue"><i style="width:${ifaceHealth}%"></i></div>
          </div>
          <div class="node-card__metric">
            <small>Last seen</small>
            <strong class="node-last-seen" data-iso="${escapeHtml(lastSeen)}">${escapeHtml(timeAgo(lastSeen))}</strong>
            <span>${escapeHtml(seenNote)}</span>
          </div>
        </div>

        <div class="node-card__footer">
          <label class="node-enable" title="Enable or disable this node">
            <input class="node-enable-input" type="checkbox" ${node.enabled ? 'checked' : ''}>
            <span class="node-enable__track" aria-hidden="true"></span>
            <span>${node.enabled ? 'Enabled' : 'Paused'}</span>
          </label>
          <button class="nodes-btn nodes-btn--primary node-open-peers" type="button"><i class="fas fa-users"></i> Peers</button>
          <button class="nodes-btn nodes-btn--quiet node-edit" type="button"><i class="fas fa-pen"></i> Edit</button>
          <button class="nodes-icon-btn is-danger node-delete" type="button" title="Delete node" aria-label="Delete node"><i class="fas fa-trash"></i></button>
        </div>
      </article>`;
  }

  function render() {
    if (!grid || !empty) return;
    const list = visibleNodes();
    grid.innerHTML = list.map(cardHtml).join('');
    empty.hidden = list.length > 0;
    grid.hidden = list.length === 0;

    if (!nodes.length) {
      const title = empty.querySelector('h3');
      if (title) title.textContent = 'No remote nodes configured';
      if (emptyCopy) emptyCopy.textContent = 'Install the node agent on another server, then add its URL and API key here.';
      if (emptyAddButton) emptyAddButton.hidden = false;
    } else if (!list.length) {
      const title = empty.querySelector('h3');
      if (title) title.textContent = 'No matching nodes';
      if (emptyCopy) emptyCopy.textContent = 'Change the search text or choose a different status filter.';
      if (emptyAddButton) emptyAddButton.hidden = true;
    }
    updateStats();
  }

  function updateStats() {
    const total = nodes.length;
    const online = nodes.filter((node) => node.enabled && node.online).length;
    const offline = nodes.filter((node) => node.enabled && !node.online).length;
    const disabled = nodes.filter((node) => !node.enabled).length;
    const peerTotal = nodes.reduce((sum, node) => sum + peerCounts(node).total, 0);
    const peerOnline = nodes.reduce((sum, node) => sum + peerCounts(node).online, 0);
    const peerBlocked = nodes.reduce((sum, node) => sum + peerCounts(node).blocked, 0);
    const interfaceTotal = nodes.reduce((sum, node) => sum + interfaceCounts(node).total, 0);
    const interfaceUp = nodes.reduce((sum, node) => sum + interfaceCounts(node).up, 0);
    const nodesWithPeers = nodes.filter((node) => peerCounts(node).total > 0).length;
    const interfaceDown = Math.max(0, interfaceTotal - interfaceUp);
    const attention = offline + peerBlocked + interfaceDown;
    const monitored = Math.max(0, total - disabled);
    const availability = monitored ? Math.round((online / monitored) * 100) : 0;

    if (stats.total) stats.total.textContent = String(total);
    if (stats.reachable) stats.reachable.textContent = String(online);
    if (stats.online) stats.online.textContent = String(online);
    if (stats.offline) stats.offline.textContent = String(offline);
    if (stats.disabled) stats.disabled.textContent = String(disabled);
    if (stats.peers) stats.peers.textContent = String(peerTotal);
    if (stats.interfaces) stats.interfaces.textContent = String(interfaceTotal);
    if (stats.attention) stats.attention.textContent = String(attention);
    if (stats.healthFill) stats.healthFill.style.width = `${availability}%`;
    if (stats.filterAll) stats.filterAll.textContent = String(total);
    if (stats.filterOnline) stats.filterOnline.textContent = String(online);
    if (stats.filterOffline) stats.filterOffline.textContent = String(offline);
    if (stats.filterDisabled) stats.filterDisabled.textContent = String(disabled);
    if (stats.filterPeers) stats.filterPeers.textContent = String(nodesWithPeers);

    if (stats.healthLabel) {
      stats.healthLabel.textContent = total === 0
        ? 'No nodes configured'
        : monitored === 0
          ? `${disabled} paused · no active monitoring`
          : `${online} online · ${offline} offline${disabled ? ` · ${disabled} paused` : ''}`;
    }
    if (stats.peerNote) stats.peerNote.textContent = peerTotal ? `${peerOnline} online${peerBlocked ? ` · ${peerBlocked} blocked` : ''}` : 'No remote peers';
    if (stats.ifaceNote) stats.ifaceNote.textContent = interfaceTotal ? `${interfaceUp} up${interfaceDown ? ` · ${interfaceDown} down` : ''}` : 'No interfaces';
    if (stats.attentionNote) {
      stats.attentionNote.textContent = attention === 0
        ? 'Nothing needs attention'
        : [offline ? `${offline} unreachable` : '', interfaceDown ? `${interfaceDown} interface down` : '', peerBlocked ? `${peerBlocked} blocked peer${peerBlocked === 1 ? '' : 's'}` : ''].filter(Boolean).join(' · ');
    }
  }

  async function enrichNode(node) {
    if (!node.enabled) {
      node.online = false;
      return node;
    }
    try {
      const summary = await api(`/api/nodes/${node.id}/summary`);
      node.summary = summary || {};
      node.online = Boolean(summary?.online);
      if (summary?.last_seen) node.last_seen = summary.last_seen;
    } catch (_) {
      node.online = false;
    }
    return node;
  }

  async function load() {
    if (loading) return;
    loading = true;
    setSync('loading', 'Refreshing');
    try {
      const payload = await api('/api/nodes');
      nodes = (Array.isArray(payload) ? payload : payload.nodes || []).map((node) => ({ ...node, summary: node.summary || null }));
      render();
      await Promise.all(nodes.map(enrichNode));
      render();
      setSync('ok', nodes.length ? 'Up to date' : 'Ready');
    } catch (error) {
      console.error('Node load failed:', error);
      nodes = [];
      render();
      setSync('bad', 'Unavailable');
      notify(error.message || 'Could not load nodes.', 'error');
    } finally {
      loading = false;
    }
  }

  function setKeyVisibility(visible) {
    if (!keyInput || !keyToggle) return;
    keyInput.type = visible ? 'text' : 'password';
    keyToggle.setAttribute('aria-pressed', String(visible));
    keyToggle.setAttribute('aria-label', visible ? 'Hide API key' : 'Show API key');
    const icon = keyToggle.querySelector('i');
    if (icon) icon.className = visible ? 'fas fa-eye-slash' : 'fas fa-eye';
  }

  function openModal(mode = 'add', node = null) {
    if (!modal || !form) return;
    editingId = mode === 'edit' && node ? node.id : null;
    form.reset();
    setKeyVisibility(false);

    if (editingId && node) {
      if (modalTitle) modalTitle.textContent = 'Edit node';
      if (nameInput) nameInput.value = node.name || '';
      if (urlInput) urlInput.value = node.base_url || '';
      if (keyInput) {
        keyInput.value = '';
        keyInput.required = false;
      }
      if (keyHelp) keyHelp.textContent = 'Leave this blank to keep the existing API key.';
    } else {
      if (modalTitle) modalTitle.textContent = 'Add node';
      if (keyInput) keyInput.required = true;
      if (keyHelp) keyHelp.textContent = 'Required when adding a node. The key is stored by the panel and is not displayed again.';
    }

    modal.hidden = false;
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');
    setTimeout(() => nameInput?.focus(), 30);
  }

  function closeModal() {
    if (!modal) return;
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
    modal.hidden = true;
    document.body.classList.remove('modal-open');
    editingId = null;
    setKeyVisibility(false);
  }

  async function copyText(value) {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      notify('Endpoint copied.', 'success');
    } catch (_) {
      notify('Could not copy endpoint.', 'error');
    }
  }

  openButton?.addEventListener('click', () => openModal('add'));
  emptyAddButton?.addEventListener('click', () => openModal('add'));
  refreshButton?.addEventListener('click', load);
  closeButton?.addEventListener('click', closeModal);
  cancelButton?.addEventListener('click', closeModal);
  keyToggle?.addEventListener('click', () => setKeyVisibility(keyInput?.type === 'password'));
  modal?.addEventListener('click', (event) => {
    if (event.target?.dataset?.close) closeModal();
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && modal?.classList.contains('open')) {
      closeModal();
      return;
    }
    if (event.key === '/' && !modal?.classList.contains('open')) {
      const active = document.activeElement;
      const typing = active && ['INPUT', 'TEXTAREA', 'SELECT'].includes(active.tagName);
      if (!typing) {
        event.preventDefault();
        search?.focus();
      }
    }
  });

  search?.addEventListener('input', () => {
    searchText = search.value || '';
    render();
  });

  $$('.nodes-filters [data-node-filter]').forEach((button) => {
    button.addEventListener('click', () => {
      activeFilter = button.dataset.nodeFilter || 'all';
      $$('.nodes-filters [data-node-filter]').forEach((item) => item.classList.toggle('is-active', item === button));
      render();
    });
  });

  form?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const name = String(nameInput?.value || '').trim();
    const baseUrl = String(urlInput?.value || '').trim();
    const apiKey = String(keyInput?.value || '').trim();

    if (!name || !baseUrl || (!editingId && !apiKey)) {
      notify('Complete the node name, base URL, and API key.', 'warn');
      return;
    }

    try {
      const parsed = new URL(baseUrl);
      if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('bad protocol');
    } catch (_) {
      notify('Base URL must start with http:// or https://.', 'warn');
      urlInput?.focus();
      return;
    }

    const payload = { name, base_url: baseUrl.replace(/\/+$/, '') };
    if (apiKey) payload.api_key = apiKey;

    const submit = form.querySelector('button[type="submit"]');
    if (submit) submit.disabled = true;
    try {
      await api(editingId ? `/api/nodes/${editingId}` : '/api/nodes', {
        method: editingId ? 'PATCH' : 'POST',
        headers: csrfHeaders(true),
        body: JSON.stringify(payload),
      });
      const wasEditing = Boolean(editingId);
      closeModal();
      await load();
      notify(wasEditing ? 'Node updated.' : 'Node added.', 'success');
    } catch (error) {
      notify(error.message || 'Could not save node.', 'error');
    } finally {
      if (submit) submit.disabled = false;
    }
  });

  grid?.addEventListener('click', async (event) => {
    const row = event.target.closest('.node-card');
    if (!row) return;
    const id = Number(row.dataset.nodeId);
    const node = nodes.find((item) => Number(item.id) === id);
    if (!node) return;

    if (event.target.closest('.node-copy-endpoint')) {
      await copyText(node.base_url || '');
      return;
    }
    if (event.target.closest('.node-open-peers')) {
      try { localStorage.setItem('peer_scope', String(id)); } catch (_) {}
      window.location.href = '/users';
      return;
    }
    if (event.target.closest('.node-edit')) {
      openModal('edit', node);
      return;
    }
    if (event.target.closest('.node-delete')) {
      const confirmed = typeof window.uiConfirm === 'function'
        ? await window.uiConfirm({
            title: 'Delete node',
            body: `Delete “${node.name || `Node ${id}`}” from this panel? This removes the saved node record; it does not uninstall the agent on the remote server.`,
            okText: 'Delete',
            cancelText: 'Cancel',
          })
        : await window.wgConfirm(`Delete ${node.name || `Node ${id}`}?`);
      if (!confirmed) return;
      try {
        await api(`/api/nodes/${id}`, { method: 'DELETE', headers: csrfHeaders() });
        nodes = nodes.filter((item) => Number(item.id) !== id);
        render();
        notify('Node deleted.', 'success');
      } catch (error) {
        notify(error.message || 'Could not delete node.', 'error');
      }
    }
  });

  grid?.addEventListener('change', async (event) => {
    const input = event.target.closest('.node-enable-input');
    if (!input) return;
    const row = input.closest('.node-card');
    const id = Number(row?.dataset?.nodeId);
    const node = nodes.find((item) => Number(item.id) === id);
    if (!node) return;

    const enabled = input.checked;
    input.disabled = true;
    try {
      await api(`/api/nodes/${id}`, {
        method: 'PATCH',
        headers: csrfHeaders(true),
        body: JSON.stringify({ enabled }),
      });
      node.enabled = enabled;
      node.online = false;
      render();
      if (enabled) {
        await enrichNode(node);
        render();
      }
      notify(enabled ? 'Node enabled.' : 'Node disabled.', 'success');
    } catch (error) {
      input.checked = !enabled;
      notify(error.message || 'Could not update node.', 'error');
    } finally {
      input.disabled = false;
    }
  });

  function refreshRelativeTimes() {
    $$('.node-last-seen[data-iso]', grid).forEach((element) => {
      element.textContent = timeAgo(element.dataset.iso || '');
    });
  }

  load();
  setInterval(refreshRelativeTimes, 30000);
})();

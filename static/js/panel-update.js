
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const modal = $('panel-update-modal');
  if (!modal) return;

  const state = {
    local: null,
    nodes: [],
    polling: new Map(),
  };

  function apiError(payload, status) {
    if (payload && typeof payload === 'object') {
      return payload.detail || payload.message || payload.error || `HTTP ${status}`;
    }
    return (typeof payload === 'string' && payload.trim()) || `HTTP ${status}`;
  }

  async function api(url, options = {}) {
    const response = await fetch(url, {
      credentials: 'same-origin',
      cache: 'no-store',
      ...options,
      headers: {
        ...(options.body ? {'Content-Type': 'application/json'} : {}),
        ...(window.csrfHeaders ? window.csrfHeaders(!!options.body) : {}),
        ...(options.headers || {}),
      },
    });

    const type = (response.headers.get('content-type') || '').toLowerCase();
    let payload;
    try {
      payload = type.includes('application/json')
        ? await response.json()
        : await response.text();
    } catch (_) {
      payload = null;
    }

    if (!response.ok) throw new Error(apiError(payload, response.status));
    return payload;
  }

  function log(message, kind = 'info') {
    const output = $('pu-log-output');
    if (!output) return;
    if (output.textContent === 'No update activity yet.') output.textContent = '';
    const stamp = new Date().toLocaleTimeString();
    output.textContent += `[${stamp}] ${kind.toUpperCase()}  ${message}\n`;
    output.scrollTop = output.scrollHeight;
  }

  function open() {
    modal.hidden = false;
    modal.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');
    refreshAll();
  }

  function close() {
    modal.hidden = true;
    modal.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('modal-open');
  }

  function setPill(el, text, tone = '') {
    if (!el) return;
    el.textContent = text;
    el.className = `pu-pill ${tone}`.trim();
  }

  function statusTone(status) {
    if (['completed','current','ready'].includes(status)) return 'ready';
    if (['available','update_available'].includes(status)) return 'update';
    if (['queued','running','downloading','installing','validating','restarting'].includes(status)) return 'busy';
    if (['failed','rollback_failed'].includes(status)) return 'error';
    return '';
  }

  function localBusy() {
    return !!(state.local && ['queued','running','downloading','installing','validating','restarting'].includes(state.local.update_status));
  }

  function updateAnnouncementKey(version, kind = 'panel') {
    return `wg-panel:update-announced:${kind}:${version || 'unknown'}`;
  }

  function announceUpdateOnce(message, version, kind = 'panel') {
    const key = updateAnnouncementKey(version, kind);

    try {
      if (localStorage.getItem(key) === '1') return;
      localStorage.setItem(key, '1');
    } catch (_) {}

    if (typeof window.toastSafe === 'function') {
      window.toastSafe(
        message,
        'warn',
        {
          duration: 9000,
        },
      );
    }
  }

  function renderSidebarPanelVersion(version) {
    const card = $('sb2-update-open');
    const stateElement = $('sb2-version-state');
    const currentElement = $('sb2-version-current');
    const latestElement = $('sb2-version-latest');
    const directionElement = $('sb2-version-direction');
    const hintElement = $('sb2-update-hint');
    const icon = card?.querySelector('.sb2-update-icon i');

    const busy = localBusy();
    const available = !!version.update_available;

    if (currentElement) {
      currentElement.textContent = `v${version.current || '—'}`;
    }

    if (latestElement) {
      latestElement.textContent = version.latest
        ? `v${version.latest}`
        : '';
      latestElement.hidden = !available;
    }

    if (directionElement) {
      directionElement.hidden = !available;
    }

    card?.classList.toggle(
      'has-update',
      available && !busy,
    );

    if (stateElement) {
      stateElement.textContent = busy
        ? 'updating'
        : (
          available
            ? 'update'
            : 'current'
        );

      stateElement.classList.toggle(
        'update',
        available && !busy,
      );

      stateElement.classList.toggle(
        'busy',
        busy,
      );
    }

    if (hintElement) {
      hintElement.textContent = busy
        ? 'Installation in progress'
        : (
          available
            ? `Update to v${version.latest}`
            : 'Latest release installed'
        );
    }

    if (icon) {
      icon.className = busy
        ? 'fas fa-spinner fa-spin'
        : (
          available
            ? 'fas fa-cloud-arrow-down'
            : 'fas fa-code-branch'
        );
    }

    if (available && !busy) {
      announceUpdateOnce(
        `WG Panel v${version.latest} is available. Open Update Center to review and install it.`,
        version.latest,
        'panel',
      );
    }
  }

  async function loadLocal() {
    const version = await api('/api/panel/version?fresh=1');
    let update = {};
    try { update = await api('/api/panel/update/status'); } catch (_) {}

    state.local = {
      ...version,
      update_status: update.status || 'idle',
      update_detail: update,
    };

    $('pu-local-current').textContent = `v${version.current || '—'}`;
    $('pu-local-latest').textContent = version.latest ? `v${version.latest}` : 'Unavailable';
    $('pu-local-summary').textContent = version.update_available ? 'Update available' : 'Current';
    setPill(
      $('pu-local-state'),
      update.status && update.status !== 'idle'
        ? update.status.replaceAll('_',' ')
        : (version.update_available ? 'Update available' : 'Current'),
      statusTone(update.status !== 'idle' ? update.status : (version.update_available ? 'available' : 'current'))
    );

    const button = $('pu-update-local');
    button.disabled = !version.update_available || localBusy();
    button.querySelector('span').textContent = localBusy() ? 'Updating…' : 'Update local';

    renderSidebarPanelVersion(version);

    if (update.status && update.status !== 'idle') renderProgress('local', update);
    if (localBusy()) startPoll('local');
  }

  function nodeRow(node) {
    const current = node.version?.current || node.agent_version || '—';
    const latest = node.version?.latest || state.local?.latest || '—';
    const available = !!node.version?.update_available;
    const status = node.update?.status || (node.online ? (available ? 'available' : 'current') : 'offline');
    const disabled = !node.online || !available || ['queued','running','downloading','installing','validating','restarting'].includes(status);

    return `
      <article class="pu-node-row" data-node-id="${node.id}">
        <div class="pu-node-main">
          <span class="pu-node-icon"><i class="fas fa-server"></i></span>
          <div>
            <div class="pu-node-name">
              <span>${escapeHtml(node.name || `Node ${node.id}`)}</span>
              <span class="pu-pill ${statusTone(status)}" data-node-state>${escapeHtml(status.replaceAll('_',' '))}</span>
            </div>
            <div class="pu-node-meta">
              Current v${escapeHtml(current)} · Latest v${escapeHtml(latest)} · ${escapeHtml(node.base_url || '')}
            </div>
          </div>
          <div class="pu-node-actions">
            <button class="pu-node-btn update" type="button" data-node-update ${disabled ? 'disabled' : ''}>
              <i class="fas fa-download"></i> ${disabled && status !== 'current' && status !== 'offline' ? 'Updating…' : 'Update'}
            </button>
          </div>
        </div>
        <div class="pu-progress" data-node-progress hidden>
          <div class="pu-progress-top"><span data-node-stage>Preparing…</span><b data-node-percent>0%</b></div>
          <div class="pu-track"><i data-node-bar></i></div>
        </div>
      </article>`;
  }

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, ch => ({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'
    })[ch]);
  }

  function resetNodeUpdateBadge() {
    const badge = $('sb2-node-update-count');
    const card = $('sb2-update-open');

    if (badge) {
      badge.classList.remove('is-visible');
      badge.hidden = true;
      badge.textContent = '';
    }

    card?.classList.remove('has-node-updates');
  }

  async function loadNodes() {
    resetNodeUpdateBadge();

    const payload = await api('/api/panel/update/targets');
    state.nodes = Array.isArray(payload.nodes) ? payload.nodes : [];
    $('pu-node-count').textContent = String(state.nodes.length);

    const nodeUpdates = state.nodes.filter(
      node => (
        node.online
        && node.version?.update_available
      )
    );

    const updateCount = $('sb2-node-update-count');
    const updateCard = $('sb2-update-open');
    const hintElement = $('sb2-update-hint');

    if (updateCount) {
      if (nodeUpdates.length > 0) {
        updateCount.textContent = (
          `${nodeUpdates.length} node`
          + (
            nodeUpdates.length === 1
              ? ''
              : 's'
          )
        );

        updateCount.hidden = false;

        requestAnimationFrame(() => {
          updateCount.classList.add('is-visible');
        });
      } else {
        updateCount.classList.remove('is-visible');
        updateCount.hidden = true;
        updateCount.textContent = '';
      }
    }

    updateCard?.classList.toggle(
      'has-node-updates',
      nodeUpdates.length > 0,
    );

    if (
      nodeUpdates.length > 0
      && !state.local?.update_available
      && hintElement
    ) {
      hintElement.textContent = (
        `${nodeUpdates.length} node update`
        + (
          nodeUpdates.length === 1
            ? ''
            : 's'
        )
      );
    }

    if (
      nodeUpdates.length > 0
      && !state.local?.update_available
    ) {
      const latest = (
        payload.latest
        || state.local?.latest
        || 'latest'
      );

      announceUpdateOnce(
        `${nodeUpdates.length} node${nodeUpdates.length === 1 ? '' : 's'} can be updated to v${latest}.`,
        `${latest}:${nodeUpdates.length}`,
        'nodes',
      );
    }

    const list = $('pu-node-list');
    if (!state.nodes.length) {
      list.innerHTML = '<div class="pu-empty"><i class="fas fa-circle-info"></i> No registered nodes.</div>';
      $('pu-update-all').disabled = true;
      return;
    }

    list.innerHTML = state.nodes.map(nodeRow).join('');
    $('pu-update-all').disabled = !state.nodes.some(n => n.online && n.version?.update_available);

    for (const node of state.nodes) {
      const status = node.update?.status || '';
      if (status && status !== 'idle') renderProgress(`node:${node.id}`, node.update);
      if (['queued','running','downloading','installing','validating','restarting'].includes(status)) {
        startPoll(`node:${node.id}`);
      }
    }
  }

  async function refreshAll() {
    $('pu-refresh')?.classList.add('is-loading');
    try {
      await loadLocal();
      await loadNodes();
    } catch (error) {
      log(error.message, 'error');
      window.toastError?.(error.message);
    } finally {
      $('pu-refresh')?.classList.remove('is-loading');
    }
  }

  function renderProgress(key, data) {
    const isLocal = key === 'local';
    const root = isLocal
      ? $('pu-local-progress')
      : document.querySelector(`[data-node-id="${CSS.escape(key.split(':')[1])}"] [data-node-progress]`);
    if (!root) return;

    const percent = Math.max(0, Math.min(100, Number(data.percent || 0)));
    root.hidden = false;

    const stage = isLocal ? $('pu-local-stage') : root.querySelector('[data-node-stage]');
    const pct = isLocal ? $('pu-local-percent') : root.querySelector('[data-node-percent]');
    const bar = isLocal ? $('pu-local-bar') : root.querySelector('[data-node-bar]');

    if (stage) stage.textContent = data.message || data.stage || data.status || 'Working…';
    if (pct) pct.textContent = `${percent}%`;
    if (bar) bar.style.width = `${percent}%`;

    if (Array.isArray(data.log) && data.log.length) {
      const last = data.log[data.log.length - 1];
      if (last && last !== root.dataset.lastLog) {
        root.dataset.lastLog = last;
        log(`${key}: ${last}`);
      }
    }
  }

  async function startLocalUpdate() {
    if (!confirm('Update the local panel now? A code backup will be created before files are replaced.')) return;
    try {
      modal.classList.add('is-busy');
      $('pu-update-local').disabled = true;
      const result = await api('/api/panel/update', {
        method: 'POST',
        body: JSON.stringify({target: 'latest'}),
      });
      log(result.message || 'Local update queued.');
      renderProgress('local', result.status || {status:'queued',percent:2,message:'Update queued'});
      startPoll('local');
    } catch (error) {
      modal.classList.remove('is-busy');
      log(error.message, 'error');
      window.toastError?.(error.message);
    }
  }

  async function startNodeUpdate(id) {
    if (!confirm(`Update node ${id} now? Its agent will restart when installation completes.`)) return;
    try {
      const result = await api(`/api/nodes/${id}/update`, {
        method: 'POST',
        body: JSON.stringify({target: 'latest'}),
      });
      log(result.message || `Node ${id} update queued.`);
      renderProgress(`node:${id}`, result.status || {status:'queued',percent:2,message:'Update queued'});
      startPoll(`node:${id}`);
    } catch (error) {
      log(`Node ${id}: ${error.message}`, 'error');
      window.toastError?.(error.message);
    }
  }

  function startPoll(key) {
    if (state.polling.has(key)) return;

    const timer = setInterval(async () => {
      try {
        const data = key === 'local'
          ? await api('/api/panel/update/status')
          : await api(`/api/nodes/${key.split(':')[1]}/update/status`);

        renderProgress(key, data);

        if (['completed','failed','rollback_completed','rollback_failed'].includes(data.status)) {
          clearInterval(timer);
          state.polling.delete(key);
          modal.classList.remove('is-busy');
          log(`${key}: ${data.message || data.status}`, data.status.includes('failed') ? 'error' : 'success');
          setTimeout(refreshAll, data.status === 'completed' ? 4500 : 800);
        }
      } catch (error) {
        log(`${key}: status check failed: ${error.message}`, 'error');
      }
    }, 1500);

    state.polling.set(key, timer);
  }

  $('sb2-update-open')?.addEventListener('click', open);
  modal.querySelectorAll('[data-pu-close]').forEach(el => el.addEventListener('click', close));
  $('pu-refresh')?.addEventListener('click', refreshAll);
  $('pu-update-local')?.addEventListener('click', startLocalUpdate);
  $('pu-node-list')?.addEventListener('click', (event) => {
    const button = event.target.closest('[data-node-update]');
    if (!button) return;
    const row = button.closest('[data-node-id]');
    if (row) startNodeUpdate(row.dataset.nodeId);
  });
  $('pu-update-all')?.addEventListener('click', async () => {
    const targets = state.nodes.filter(n => n.online && n.version?.update_available);
    if (!targets.length) return;
    if (!confirm(`Queue updates for ${targets.length} node(s)?`)) return;
    for (const node of targets) await startNodeUpdate(node.id);
  });
  $('pu-log-toggle')?.addEventListener('click', () => {
    const drawer = $('pu-log-drawer');
    drawer.hidden = !drawer.hidden;
  });
  $('pu-log-clear')?.addEventListener('click', () => {
    $('pu-log-output').textContent = 'No update activity yet.';
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !modal.hidden) close();
  });

  document.addEventListener('DOMContentLoaded', () => {
    loadLocal().catch(() => {});
  });
})();

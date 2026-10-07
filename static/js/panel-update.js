(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);

  const state = {
    opened: false,
    polling: null,
    reconnecting: false,
    reconnectTimer: null,
    reconnectDelay: 1000,
    reconnectStartedAt: 0,
    panelReachableAfterRestart: false,
    finalStatusPolls: 0,
    lastStatus: null,
    lastTerminalNotice: '',
    localVersion: null,
    targets: [],
  };

  const BUSY = new Set([
    'queued',
    'running',
    'backup',
    'downloading',
    'download',
    'extract',
    'install',
    'installing',
    'dependencies',
    'validate',
    'validating',
    'restart',
    'restarting',
  ]);

  const TERMINAL_OK = new Set([
    'completed',
    'success',
    'updated',
    'rollback_completed',
  ]);

  const TERMINAL_BAD = new Set([
    'failed',
    'error',
    'rollback_failed',
  ]);

  function toast(message, type = 'info', persist = false) {
    const fn = window.toastSafe || window.toast;
    if (typeof fn === 'function') {
      try {
        fn(message, type, { persist });
      } catch (_) {
        try { fn(message, type); } catch (_) {}
      }
    }
  }

  function apiHeaders(json = false) {
    if (typeof window.csrfHeaders === 'function') {
      return window.csrfHeaders(json);
    }

    const headers = {};
    const csrf = (document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/) || [])[1];

    if (csrf) {
      headers['X-CSRFToken'] = decodeURIComponent(csrf);
    }

    if (json) {
      headers['Content-Type'] = 'application/json';
    }

    return headers;
  }

  async function api(url, options = {}) {
    const method = String(options.method || 'GET').toUpperCase();
    const hasBody = options.body !== undefined;
    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      Number(options.timeout || 15000),
    );

    try {
      const response = await fetch(url, {
        method,
        credentials: 'same-origin',
        cache: 'no-store',
        headers: {
          ...apiHeaders(hasBody),
          ...(options.headers || {}),
        },
        body: hasBody
          ? JSON.stringify(options.body)
          : undefined,
        signal: controller.signal,
      });

      let payload = null;

      try {
        payload = await response.json();
      } catch (_) {
        payload = {};
      }

      if (!response.ok) {
        const error = new Error(
          payload?.detail
          || payload?.message
          || payload?.error
          || `HTTP ${response.status}`,
        );
        error.status = response.status;
        error.payload = payload;
        throw error;
      }

      return payload || {};
    } finally {
      clearTimeout(timeout);
    }
  }

  function ensureConfirmDialog() {
    if ($('pu-confirm-overlay')) return;

    const style = document.createElement('style');
    style.id = 'pu-confirm-style';
    style.textContent = `

      .pu-confirm-overlay[hidden] {
        display: none !important;
      }

      .pu-confirm-overlay {
        position: fixed;
        inset: 0;
        z-index: 12050;

        display: grid;
        place-items: center;

        padding: 20px;

        background: rgba(2, 8, 18, .72);
        backdrop-filter: blur(7px);
        -webkit-backdrop-filter: blur(7px);
      }

      .pu-confirm-card {
        width: min(400px, calc(100vw - 28px));

        border: 1px solid rgba(148, 163, 184, .24);
        border-radius: 17px;

        background: var(--card, #111f2e);
        color: var(--text, #f8fafc);

        box-shadow:
          0 30px 90px rgba(0, 0, 0, .48);

        overflow: hidden;
      }

      .pu-confirm-main {
        padding: 18px 19px 15px;
      }

      .pu-confirm-icon {
        width: 40px;
        height: 40px;

        display: grid;
        place-items: center;

        margin-bottom: 12px;

        border-radius: 12px;

        background: rgba(45, 212, 191, .14);
        color: #5eead4;

        font-size: 17px;
      }

      .pu-confirm-card h3 {
        margin: 0 0 6px;

        color: inherit;

        font-size: 18px;
        font-weight: 700;
        line-height: 1.25;
      }

      .pu-confirm-card p {
        margin: 0;

        color: #a9b8ca;

        font-size: 13px;
        line-height: 1.45;
      }

      .pu-confirm-notice {
        margin-top: 12px;
        padding: 10px 11px;

        border: 1px solid rgba(245, 158, 11, .20);
        border-radius: 11px;

        background: rgba(245, 158, 11, .08);
        color: #f8d59a;

        font-size: 12px;
        line-height: 1.4;
      }

      .pu-confirm-actions {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 10px;

        padding: 11px 14px 14px;

        border-top: 1px solid rgba(148, 163, 184, .16);
      }

      .pu-confirm-actions button {
        min-height: 39px;

        border: 1px solid rgba(148, 163, 184, .22);
        border-radius: 10px;

        background: rgba(148, 163, 184, .08);
        color: inherit;

        font: inherit;
        font-weight: 700;

        cursor: pointer;

        transition:
          background .16s ease,
          border-color .16s ease,
          color .16s ease,
          box-shadow .16s ease,
          transform .16s ease;
      }

      .pu-confirm-actions button:hover {
        background: rgba(148, 163, 184, .14);
      }

      .pu-confirm-actions button:active {
        transform: translateY(1px);
      }

      .pu-confirm-actions .primary {
        border-color: transparent;

        background: linear-gradient(
          135deg,
          #14b8a6,
          #0ea5a4
        );

        color: #ffffff;

        box-shadow:
          0 5px 14px rgba(20, 184, 166, .18);
      }

      .pu-confirm-actions .primary:hover {
        background: linear-gradient(
          135deg,
          #18c3b0,
          #10b3b0
        );

        box-shadow:
          0 7px 18px rgba(20, 184, 166, .24);
      }

      .pu-confirm-actions button:focus-visible {
        outline: 3px solid rgba(45, 212, 191, .28);
        outline-offset: 2px;
      }

      .pu-reconnect-note {
        display: inline-flex;
        align-items: center;
        gap: 8px;

        color: #cbd5e1;
      }

      .pu-reconnect-note i {
        color: #5eead4;
      }


      html[data-theme="light"] .pu-confirm-overlay {
        background: rgba(15, 23, 42, .58);
        backdrop-filter: blur(7px);
        -webkit-backdrop-filter: blur(7px);
      }

      html[data-theme="light"] .pu-confirm-card {
        background: #ffffff;
        color: #172033;

        border-color: #dce3eb;

        box-shadow:
          0 28px 70px rgba(15, 23, 42, .18),
          0 5px 18px rgba(15, 23, 42, .08);
      }

      html[data-theme="light"] .pu-confirm-card h3 {
        color: #172033;
      }

      html[data-theme="light"] .pu-confirm-card p {
        color: #718198;
      }

      html[data-theme="light"] .pu-confirm-icon {
        background: #ddf8f4;
        color: #14b8a6;

        box-shadow:
          inset 0 0 0 1px rgba(20, 184, 166, .04);
      }

      html[data-theme="light"] .pu-confirm-notice {
        background: #fff8ed;
        border-color: #f5d5a2;
        color: #a85d08;
      }

      html[data-theme="light"] .pu-confirm-actions {
        background: #fbfcfd;
        border-top-color: #e7ebf0;
      }

      html[data-theme="light"] .pu-confirm-actions button:not(.primary) {
        background: #f8fafc;
        border-color: #dce3eb;
        color: #172033;

        box-shadow:
          0 1px 2px rgba(15, 23, 42, .02);
      }

      html[data-theme="light"] .pu-confirm-actions button:not(.primary):hover {
        background: #f1f5f9;
        border-color: #cbd5e1;
        color: #0f172a;
      }

      html[data-theme="light"] .pu-confirm-actions .primary {
        background: linear-gradient(
          135deg,
          #18b7aa,
          #0fa6a4
        );

        border-color: transparent;
        color: #ffffff;

        box-shadow:
          0 5px 14px rgba(15, 166, 164, .20);
      }

      html[data-theme="light"] .pu-confirm-actions .primary:hover {
        background: linear-gradient(
          135deg,
          #14aa9e,
          #0c9797
        );

        box-shadow:
          0 7px 18px rgba(15, 166, 164, .26);
      }

      html[data-theme="light"] .pu-reconnect-note {
        color: #64748b;
      }

      html[data-theme="light"] .pu-reconnect-note i {
        color: #0f9f95;
      }


      @media (max-width: 480px) {
        .pu-confirm-overlay {
          padding: 14px;
        }

        .pu-confirm-card {
          width: min(100%, 400px);
          border-radius: 15px;
        }

        .pu-confirm-main {
          padding: 17px 17px 14px;
        }

        .pu-confirm-actions {
          padding: 10px 12px 12px;
          gap: 8px;
        }

        .pu-confirm-actions button {
          min-height: 41px;
        }
      }
    `;

    document.head.appendChild(style);

    const overlay = document.createElement('div');
    overlay.id = 'pu-confirm-overlay';
    overlay.className = 'pu-confirm-overlay';
    overlay.hidden = true;

    overlay.innerHTML = `
      <section
        class="pu-confirm-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="pu-confirm-title"
        aria-describedby="pu-confirm-message"
      >
        <div class="pu-confirm-main">

          <div class="pu-confirm-icon" aria-hidden="true">
            <i class="fas fa-cloud-arrow-down"></i>
          </div>

          <h3 id="pu-confirm-title">
            Update local panel?
          </h3>

          <p id="pu-confirm-message">
            A rollback backup will be created before panel files are replaced.
          </p>

          <div class="pu-confirm-notice">
            The panel will be unavailable briefly while its service restarts.
            This page will wait and reconnect automatically.
          </div>

        </div>

        <div class="pu-confirm-actions">

          <button
            type="button"
            id="pu-confirm-cancel"
          >
            Cancel
          </button>

          <button
            type="button"
            class="primary"
            id="pu-confirm-accept"
          >
            Start update
          </button>

        </div>
      </section>
    `;

    document.body.appendChild(overlay);
}
  function askConfirmation({
    title,
    message,
    acceptLabel = 'Continue',
  }) {
    ensureConfirmDialog();

    const overlay = $('pu-confirm-overlay');
    const titleEl = $('pu-confirm-title');
    const messageEl = $('pu-confirm-message');
    const accept = $('pu-confirm-accept');
    const cancel = $('pu-confirm-cancel');

    titleEl.textContent = title;
    messageEl.textContent = message;
    accept.textContent = acceptLabel;
    overlay.hidden = false;

    return new Promise((resolve) => {
      let done = false;

      const finish = (answer) => {
        if (done) return;
        done = true;
        overlay.hidden = true;
        accept.removeEventListener('click', yes);
        cancel.removeEventListener('click', no);
        overlay.removeEventListener('click', backdrop);
        document.removeEventListener('keydown', keydown);
        resolve(answer);
      };

      const yes = () => finish(true);
      const no = () => finish(false);
      const backdrop = (event) => {
        if (event.target === overlay) finish(false);
      };
      const keydown = (event) => {
        if (event.key === 'Escape') finish(false);
      };

      accept.addEventListener('click', yes);
      cancel.addEventListener('click', no);
      overlay.addEventListener('click', backdrop);
      document.addEventListener('keydown', keydown);

      setTimeout(() => accept.focus(), 0);
    });
  }

  function setText(id, value) {
    const el = $(id);
    if (el) el.textContent = value;
  }

  function setDisabled(id, disabled) {
    const el = $(id);
    if (el) el.disabled = !!disabled;
  }

  function statusName(status) {
    return String(status?.status || status?.stage || 'idle').toLowerCase();
  }

  function isBusy(status) {
    return BUSY.has(statusName(status));
  }

  function updateProgress(status) {
    state.lastStatus = status || {};

    const name = statusName(status);
    const percent = Math.max(
      0,
      Math.min(100, Number(status?.percent || 0)),
    );
    const message = String(
      status?.message
      || (
        name === 'idle'
          ? 'Ready'
          : name.replaceAll('_', ' ')
      ),
    );

    const progress = $('pu-local-progress');
    const bar = $('pu-local-bar');

    if (progress) {
      progress.hidden = !isBusy(status)
        && !TERMINAL_OK.has(name)
        && !TERMINAL_BAD.has(name);
    }

    setText('pu-local-stage', message);
    setText('pu-local-percent', `${percent}%`);

    if (bar) {
      bar.style.width = `${percent}%`;
    }

    const localButton = $('pu-update-local');

    if (localButton) {
      localButton.disabled = isBusy(status) || state.reconnecting;
    }

    if (
      (name === 'restarting' || name === 'restart')
      && !state.panelReachableAfterRestart
    ) {
      enterReconnectMode();
    }

    if (TERMINAL_OK.has(name)) {
      stopPoll();
      state.panelReachableAfterRestart = false;
      state.reconnecting = false;
      window.WG_PANEL_UPDATING = false;
      window.WG_PANEL_RESTARTING = false;

      setText('pu-local-stage', status?.message || 'Update completed.');
      setText('pu-local-percent', '100%');

      if (bar) bar.style.width = '100%';

      const noticeKey = [
        name,
        String(status?.updated_at || ''),
        String(status?.message || ''),
      ].join('|');

      if (state.lastTerminalNotice !== noticeKey) {
        state.lastTerminalNotice = noticeKey;

        toast(
          name === 'rollback_completed'
            ? 'Update was not installed. Previous code was restored safely.'
            : 'Panel update completed successfully.',
          name === 'rollback_completed' ? 'warn' : 'success',
          false,
        );
      }

      setDisabled('pu-refresh', false);

      setTimeout(() => {
        refreshCenter().catch(() => {});
      }, 900);
    }

    if (TERMINAL_BAD.has(name)) {
      stopPoll();
      state.panelReachableAfterRestart = false;
      state.reconnecting = false;
      window.WG_PANEL_UPDATING = false;
      window.WG_PANEL_RESTARTING = false;
      const noticeKey = [
        name,
        String(status?.updated_at || ''),
        String(status?.message || ''),
      ].join('|');

      if (state.lastTerminalNotice !== noticeKey) {
        state.lastTerminalNotice = noticeKey;
        toast(
          status?.message || 'Panel update failed.',
          'error',
          false,
        );
      }
    }

    renderLog(status);
  }

  function renderLog(status) {
    const output = $('pu-log-output');
    if (!output) return;

    const lines = Array.isArray(status?.log)
      ? status.log
      : [];

    const header = [
      status?.message || '',
      status?.backup ? `Backup: ${status.backup}` : '',
      status?.service ? `Service: ${status.service}` : '',
    ].filter(Boolean);

    output.textContent = [...header, ...lines].join('\n')
      || 'No update activity yet.';
  }

  function setReconnectUI(attemptText = '') {
    const progress = $('pu-local-progress');
    const bar = $('pu-local-bar');

    if (progress) progress.hidden = false;

    setText(
      'pu-local-stage',
      attemptText || 'Panel is restarting. Waiting for it to return…',
    );
    setText('pu-local-percent', '99%');

    if (bar) {
      bar.style.width = '99%';
    }

    setDisabled('pu-update-local', true);
    setDisabled('pu-refresh', true);
  }

  function enterReconnectMode() {
    if (state.reconnecting) return;

    state.reconnecting = true;
    state.panelReachableAfterRestart = false;
    state.finalStatusPolls = 0;
    state.reconnectDelay = 1000;
    state.reconnectStartedAt = Date.now();
    window.WG_PANEL_UPDATING = true;
    window.WG_PANEL_RESTARTING = true;

    stopPoll();
    setReconnectUI();
    scheduleReconnect(600);
  }

  function scheduleReconnect(delay = state.reconnectDelay) {
    clearTimeout(state.reconnectTimer);
    state.reconnectTimer = setTimeout(probePanel, delay);
  }

  async function probePanel() {
    if (!state.reconnecting) return;

    const elapsed = Math.floor(
      (Date.now() - state.reconnectStartedAt) / 1000,
    );

    setReconnectUI(
      `Panel is restarting. Reconnecting… ${elapsed}s`,
    );

    try {
      const response = await fetch('/api/healthz', {
        credentials: 'same-origin',
        cache: 'no-store',
        signal: AbortSignal.timeout
          ? AbortSignal.timeout(4000)
          : undefined,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      state.reconnecting = false;
      state.panelReachableAfterRestart = true;
      state.finalStatusPolls = 0;
      clearTimeout(state.reconnectTimer);

      setDisabled('pu-refresh', true);
      setText(
        'pu-local-stage',
        'Panel is online. Finalizing update…',
      );
      setText('pu-local-percent', '99%');

      window.WG_PANEL_RESTARTING = false;
      document.dispatchEvent(
        new CustomEvent('wg-panel:restart-complete'),
      );
      await pollFinalStatus();
      return;
    } catch (_) {
    }

    if (elapsed >= 120) {
      state.reconnecting = false;
      window.WG_PANEL_UPDATING = false;
      window.WG_PANEL_RESTARTING = false;
      setDisabled('pu-refresh', false);
      setText(
        'pu-local-stage',
        'The panel has not returned yet. Check the systemd service log.',
      );
      toast(
        'The panel did not reconnect within two minutes.',
        'error',
        true,
      );
      return;
    }

    state.reconnectDelay = Math.min(
      8000,
      Math.round(state.reconnectDelay * 1.55),
    );
    scheduleReconnect();
  }

  async function pollFinalStatus() {
    if (!state.panelReachableAfterRestart) return;

    state.finalStatusPolls += 1;

    try {
      const status = await api(
        '/api/panel/update/status',
        { timeout: 7000 },
      );

      const name = statusName(status);

      updateProgress(status);

      if (TERMINAL_OK.has(name) || TERMINAL_BAD.has(name)) {
        state.panelReachableAfterRestart = false;
        window.WG_PANEL_UPDATING = false;
        window.WG_PANEL_RESTARTING = false;
        setDisabled('pu-refresh', false);
        window.dispatchEvent(new CustomEvent('wg-panel-update-finished'));
        if (name !== 'rollback_completed') {
          setTimeout(() => window.location.reload(), 1200);
        }
        return;
      }

      if (state.finalStatusPolls >= 12) {
        state.panelReachableAfterRestart = false;
        window.WG_PANEL_UPDATING = false;
        window.WG_PANEL_RESTARTING = false;
        setDisabled('pu-refresh', false);

        setText(
          'pu-local-stage',
          'Panel restarted, but the updater did not report a final result.',
        );

        toast(
          'Panel is online. The previous updater ended without a final status, so the update controls were restored.',
          'warn',
          false,
        );

        await refreshCenter().catch(() => {});

        const localButton = $('pu-update-local');
        if (
          localButton
          && state.localVersion?.update_available
        ) {
          localButton.disabled = false;
        }

        return;
      }

      setText(
        'pu-local-stage',
        status?.message || 'Finalizing update…',
      );

      setTimeout(pollFinalStatus, 1200);

    } catch (_) {
      if (state.finalStatusPolls < 12) {
        setTimeout(pollFinalStatus, 1500);
        return;
      }

      state.panelReachableAfterRestart = false;
      window.WG_PANEL_UPDATING = false;
      window.WG_PANEL_RESTARTING = false;
      setDisabled('pu-refresh', false);
    }
  }


  async function pollStatus() {
    if (
      state.reconnecting
      || state.panelReachableAfterRestart
    ) {
      return;
    }

    try {
      const status = await api(
        '/api/panel/update/status',
        { timeout: 7000 },
      );

      updateProgress(status);
    } catch (error) {
      if (
        window.WG_PANEL_UPDATING
        || isBusy(state.lastStatus)
      ) {
        enterReconnectMode();
        return;
      }

      toast(
        `Could not read update status: ${error.message}`,
        'error',
      );
    }
  }

  function startPoll() {
    stopPoll();
    pollStatus();
    state.polling = setInterval(pollStatus, 1400);
  }

  function stopPoll() {
    if (state.polling) {
      clearInterval(state.polling);
      state.polling = null;
    }
  }

  function renderLocalVersion(version) {
    state.localVersion = version || {};

    const current = version?.current
      ? `v${String(version.current).replace(/^v/i, '')}`
      : '—';

    const latestRevision = String(
      version?.latest_revision_short
      || version?.latest_revision
      || ''
    ).slice(0, 8);

    const latestVersion = version?.latest
      ? `v${String(version.latest).replace(/^v/i, '')}`
      : '';

    const latest = latestRevision
      ? `main · ${latestRevision}`
      : (latestVersion || 'main');

    setText('pu-local-current', current);
    setText('pu-local-latest', latest);

    const available = !!version?.update_available;
    const stateEl = $('pu-local-state');

    if (stateEl) {
      stateEl.textContent = available
        ? 'Update available'
        : 'Current';
      stateEl.classList.toggle('is-current', !available);
    }

    setText(
      'pu-local-summary',
      available ? 'Update available' : 'Up to date',
    );

    const button = $('pu-update-local');

    if (button) {
      button.disabled = !available || isBusy(state.lastStatus);
      button.dataset.target = String(
        version?.target
        || version?.latest
        || 'main',
      );
    }
  }

  function escapeHtml(value) {
    return String(value ?? '').replace(
      /[&<>"']/g,
      (char) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;',
      })[char],
    );
  }

  function renderNodes(payload) {
    const list = $('pu-node-list');
    const nodes = Array.isArray(payload?.nodes)
      ? payload.nodes
      : [];

    state.targets = nodes;
    setText('pu-node-count', String(nodes.length));

    if (!list) return;

    if (!nodes.length) {
      list.innerHTML = `
        <div class="pu-empty">
          No remote nodes are registered.
        </div>
      `;
      return;
    }

    list.innerHTML = nodes.map((node) => {
      const online = !!node.online;
      const version = node.version || {};
      const current = version.current
        ? `v${String(version.current).replace(/^v/i, '')}`
        : '—';
      const latestRevision = String(
        version.latest_revision_short
        || version.latest_revision
        || ''
      ).slice(0, 8);

      const latestVersion = version.latest
        ? `v${String(version.latest).replace(/^v/i, '')}`
        : '';

      const latest = latestRevision
        ? `main · ${latestRevision}`
        : (latestVersion || 'main');

      const available = (
        online
        && !!version.update_available
      );
      const detail = String(
        node.error
        || node.detail
        || version.detail
        || '',
      );

      return `
        <section class="pu-target pu-node" data-node-id="${escapeHtml(node.id)}">
          <div class="pu-target-main">
            <span class="pu-target-icon">
              <i class="fas fa-server"></i>
            </span>
            <div class="pu-target-copy">
              <div class="pu-target-title">
                <strong>${escapeHtml(node.name || `Node ${node.id}`)}</strong>
                <span class="pu-pill">${online ? 'Online' : 'Offline'}</span>
              </div>
              <div class="pu-versions">
                <span>Current <b>${escapeHtml(current)}</b></span>
                <i class="fas fa-arrow-right"></i>
                <span>Latest <b>${escapeHtml(latest)}</b></span>
                ${node.base_url ? `<span>· ${escapeHtml(node.base_url)}</span>` : ''}
              </div>
              ${detail ? `<div class="pu-node-error">${escapeHtml(detail)}</div>` : ''}
            </div>
            <button class="pu-update-btn pu-node-update"
                    type="button"
                    data-node-id="${escapeHtml(node.id)}"
                    data-target="${escapeHtml(version.target || version.latest || 'latest')}"
                    ${available ? '' : 'disabled'}>
              <i class="fas fa-download"></i><span>Update</span>
            </button>
          </div>
          <div class="pu-progress" hidden>
            <div class="pu-progress-top">
              <span>Waiting…</span><b>0%</b>
            </div>
            <div class="pu-track"><i style="width:0%"></i></div>
          </div>
        </section>
      `;
    }).join('');
  }

  async function refreshCenter() {
    if (state.reconnecting) return;

    setDisabled('pu-refresh', true);

    try {
      const [version, targets, status] = await Promise.all([
        api('/api/panel/version?fresh=1'),
        api('/api/panel/update/targets'),
        api('/api/panel/update/status'),
      ]);

      renderLocalVersion(version);
      renderNodes(targets);
      updateProgress(status);
    } catch (error) {
      toast(
        `Could not refresh Update Center: ${error.message}`,
        'error',
      );
    } finally {
      if (!state.reconnecting) {
        setDisabled('pu-refresh', false);
      }
    }
  }

  async function startLocalUpdate() {
    const button = $('pu-update-local');
    if (!button || button.disabled) return;

    const accepted = await askConfirmation({
      title: 'Update local panel?',
      message:
        'A rollback backup will be created, the new code will be validated, '
        + 'and the panel service will restart automatically.',
      acceptLabel: 'Start update',
    });

    if (!accepted) return;

    button.disabled = true;
    state.lastTerminalNotice = '';
    window.WG_PANEL_UPDATING = true;

    const target = String(
      button.dataset.target
      || state.localVersion?.target
      || state.localVersion?.latest
      || 'main',
    );

    try {
      const result = await api(
        '/api/panel/update',
        {
          method: 'POST',
          body: { target },
          timeout: 16000,
        },
      );

      const initial = result?.status || {
        status: 'queued',
        stage: 'queued',
        percent: 2,
        message: result?.message || 'Update queued.',
      };

      updateProgress(initial);
      toast('Panel update started.', 'info');
      startPoll();
    } catch (error) {
      window.WG_PANEL_UPDATING = false;
      button.disabled = false;
      toast(
        `Could not start update: ${error.message}`,
        'error',
        true,
      );
    }
  }

  async function startNodeUpdate(button) {
    if (!button || button.disabled) return;

    const nodeId = button.dataset.nodeId;
    const target = button.dataset.target || 'main';

    const accepted = await askConfirmation({
      title: 'Update remote node?',
      message:
        'The selected node will create a rollback backup and restart its own agent.',
      acceptLabel: 'Update node',
    });

    if (!accepted) return;

    button.disabled = true;

    try {
      await api(
        `/api/nodes/${encodeURIComponent(nodeId)}/update`,
        {
          method: 'POST',
          body: { target },
          timeout: 16000,
        },
      );

      toast('Node update queued.', 'info');
      setTimeout(refreshCenter, 1200);
    } catch (error) {
      button.disabled = false;
      toast(
        `Could not start node update: ${error.message}`,
        'error',
        true,
      );
    }
  }

  function openCenter() {
    const modal = $('panel-update-modal');
    if (!modal) return;

    modal.hidden = false;
    modal.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');
    state.opened = true;
    refreshCenter();
  }

  function closeCenter() {
    if (state.reconnecting || window.WG_PANEL_UPDATING) {
      toast(
        'The update is still running. Keep this page open while the panel restarts.',
        'warn',
      );
      return;
    }

    const modal = $('panel-update-modal');
    if (!modal) return;

    modal.hidden = true;
    modal.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('modal-open');
    state.opened = false;
    stopPoll();
  }

  function bind() {
    ensureConfirmDialog();

    $('sb2-update-open')?.addEventListener('click', openCenter);
    $('pu-refresh')?.addEventListener('click', refreshCenter);
    $('pu-update-local')?.addEventListener('click', startLocalUpdate);

    document.addEventListener('click', (event) => {
      const close = event.target.closest('[data-pu-close]');
      if (close) {
        event.preventDefault();
        closeCenter();
        return;
      }

      const nodeButton = event.target.closest('.pu-node-update');
      if (nodeButton) {
        startNodeUpdate(nodeButton);
      }
    });

    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && state.opened) {
        closeCenter();
      }
    });

    $('pu-log-toggle')?.addEventListener('click', () => {
      const drawer = $('pu-log-drawer');
      if (drawer) drawer.hidden = !drawer.hidden;
    });

    $('pu-log-clear')?.addEventListener('click', () => {
      setText('pu-log-output', 'No update activity yet.');
    });

    api('/api/panel/update/status', { timeout: 5000 })
      .then((status) => {
        if (isBusy(status)) {
          window.WG_PANEL_UPDATING = true;
          updateProgress(status);
          startPoll();
        }
      })
      .catch(() => {});
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bind);
  } else {
    bind();
  }
})();

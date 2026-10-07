(() => {
  'use strict';

  const byId = (id) => document.getElementById(id);

  function cleanVersion(value) {
    return String(value || '')
      .trim()
      .replace(/^v/i, '');
  }

  function shortRevision(payload, key) {
    return String(
      payload?.[`${key}_revision_short`]
      || payload?.[`${key}_revision`]
      || ''
    ).slice(0, 8);
  }

  function render(payload) {
    const card = byId('sb2-update-open');
    const currentElement = byId('sb2-version-current');
    const directionElement = byId('sb2-version-direction');
    const latestElement = byId('sb2-version-latest');
    const stateElement = byId('sb2-version-state');
    const hintElement = byId('sb2-update-hint');

    const current = cleanVersion(
      payload?.current
      || card?.dataset?.currentVersion
      || ''
    );

    const available = !!payload?.update_available;

    const currentRevision = shortRevision(
      payload,
      'current',
    );

    const latestRevision = shortRevision(
      payload,
      'latest',
    );

    if (currentElement) {
      const revisionLabel = (
        available
          ? latestRevision
          : currentRevision
      );

      currentElement.textContent = (
        current
          ? (
            revisionLabel
              ? `v${current} · main ${revisionLabel}`
              : `v${current}`
          )
          : '—'
      );

      currentElement.title = (
        revisionLabel
          ? `Installed version ${current || 'unknown'}, main revision ${revisionLabel}`
          : `Installed version ${current || 'unknown'}`
      );
    }

    if (directionElement) {
      directionElement.hidden = true;
    }

    if (latestElement) {
      latestElement.hidden = true;
      latestElement.textContent = '';
    }

    if (available) {
      if (stateElement) {
        stateElement.textContent = 'UPDATE';
        stateElement.classList.remove(
          'is-current',
          'is-error',
        );
        stateElement.classList.add(
          'is-update',
        );
      }

      if (hintElement) {
        hintElement.textContent = 'New update available';
      }

      if (card) {
        card.dataset.updateAvailable = '1';
        card.dataset.target = 'main';
        card.dataset.latestRevision = latestRevision;
        card.setAttribute(
          'aria-label',
          latestRevision
            ? `WG Panel update available, main revision ${latestRevision}`
            : 'WG Panel update available'
        );
      }

      return;
    }

    if (stateElement) {
      stateElement.textContent = 'CURRENT';
      stateElement.classList.remove(
        'is-update',
        'is-error',
      );
      stateElement.classList.add(
        'is-current',
      );
    }

    if (hintElement) {
      hintElement.textContent = 'Repository is current';
    }

    if (card) {
      card.dataset.updateAvailable = '0';
      card.dataset.target = 'main';
      card.dataset.latestRevision = latestRevision;
      card.setAttribute(
        'aria-label',
        'WG Panel is current'
      );
    }
  }

  function renderFailure(error) {
    const directionElement = byId(
      'sb2-version-direction'
    );

    const latestElement = byId(
      'sb2-version-latest'
    );

    const stateElement = byId(
      'sb2-version-state'
    );

    const hintElement = byId(
      'sb2-update-hint'
    );

    if (directionElement) {
      directionElement.hidden = true;
    }

    if (latestElement) {
      latestElement.hidden = true;
      latestElement.textContent = '';
    }

    if (stateElement) {
      stateElement.textContent = 'UNKNOWN';
      stateElement.classList.remove(
        'is-current',
        'is-update',
      );
      stateElement.classList.add(
        'is-error',
      );
    }

    if (hintElement) {
      hintElement.textContent = (
        'Could not check GitHub main'
      );

      hintElement.title = String(
        error?.message
        || error
        || 'Version check failed'
      );
    }
  }

  async function fetchJson(
    url,
    timeoutMs = 12000,
  ) {
    const controller = new AbortController();

    const timer = window.setTimeout(
      () => controller.abort(),
      timeoutMs,
    );

    try {
      const response = await fetch(
        url,
        {
          method: 'GET',
          credentials: 'same-origin',
          cache: 'no-store',
          headers: {
            Accept: 'application/json',
          },
          signal: controller.signal,
        },
      );

      let payload = {};

      try {
        payload = await response.json();
      } catch (_) {
        payload = {};
      }

      if (!response.ok) {
        throw new Error(
          payload?.detail
          || payload?.message
          || payload?.error
          || `HTTP ${response.status}`
        );
      }

      return payload;

    } finally {
      window.clearTimeout(timer);
    }
  }

  async function refreshSidebarVersion() {
    const stateElement = byId(
      'sb2-version-state'
    );

    const hintElement = byId(
      'sb2-update-hint'
    );

    if (stateElement) {
      stateElement.textContent = 'CHECKING';
      stateElement.classList.remove(
        'is-current',
        'is-update',
        'is-error',
      );
    }

    if (hintElement) {
      hintElement.textContent = (
        'Checking GitHub main…'
      );

      hintElement.removeAttribute(
        'title'
      );
    }

    try {
      const payload = await fetchJson(
        `/api/panel/version?fresh=1&_=${Date.now()}`,
      );

      render(payload);

    } catch (error) {
      renderFailure(error);
    }
  }

  window.refreshPanelVersionBadge = (
    refreshSidebarVersion
  );

  if (document.readyState === 'loading') {
    document.addEventListener(
      'DOMContentLoaded',
      refreshSidebarVersion,
      {
        once: true,
      },
    );
  } else {
    refreshSidebarVersion();
  }

  window.addEventListener(
    'wg-panel-update-finished',
    () => {
      window.setTimeout(
        refreshSidebarVersion,
        800,
      );
    },
  );

  function renderDashboardVersion(payload) {
    const card = byId('panel-version-card');
    if (!card) return;

    const currentElement = byId('panel-version-current');
    const latestElement = byId('panel-version-latest');
    const statusElement = byId('panel-version-status');
    const noteElement = byId('panel-version-note');
    const releaseElement = byId('panel-version-release');

    const current = cleanVersion(
      payload?.current
      || card.dataset.currentVersion
      || ''
    );

    const available = !!payload?.update_available;
    const currentRevision = shortRevision(payload, 'current');
    const latestRevision = shortRevision(payload, 'latest');

    if (currentElement) {
      currentElement.textContent = current ? `v${current}` : '—';
    }

    if (latestElement) {
      latestElement.textContent = latestRevision || '';
    }

    if (statusElement) {
      statusElement.classList.remove(
        'is-current',
        'is-update',
        'is-checking',
        'is-error',
      );

      statusElement.textContent = available ? 'UPDATE' : 'CURRENT';
      statusElement.classList.add(
        available ? 'is-update' : 'is-current',
      );
    }

    if (noteElement) {
      if (available) {
        noteElement.textContent = latestRevision
          ? `New main revision · ${latestRevision}`
          : 'New main revision available';
      } else {
        noteElement.textContent = currentRevision
          ? `Main revision · ${currentRevision}`
          : 'Repository is current';
      }
    }

    if (releaseElement && payload?.latest_url) {
      releaseElement.href = payload.latest_url;
    }

    card.dataset.updateAvailable = available ? '1' : '0';
    card.dataset.target = 'main';
  }

  function renderDashboardFailure(error) {
    const card = byId('panel-version-card');
    if (!card) return;

    const statusElement = byId('panel-version-status');
    const noteElement = byId('panel-version-note');

    if (statusElement) {
      statusElement.textContent = 'UNKNOWN';
      statusElement.classList.remove(
        'is-current',
        'is-update',
        'is-checking',
      );
      statusElement.classList.add('is-error');
    }

    if (noteElement) {
      noteElement.textContent = 'Could not check GitHub main';
      noteElement.title = String(
        error?.message
        || error
        || 'Version check failed'
      );
    }
  }

  async function refreshDashboardVersion() {
    const card = byId('panel-version-card');
    if (!card) return;

    const statusElement = byId('panel-version-status');
    const noteElement = byId('panel-version-note');
    const refreshButton = byId('panel-version-refresh');

    if (statusElement) {
      statusElement.textContent = 'CHECKING';
      statusElement.classList.remove(
        'is-current',
        'is-update',
        'is-error',
      );
      statusElement.classList.add('is-checking');
    }

    if (noteElement) {
      noteElement.textContent = 'Checking GitHub main…';
      noteElement.removeAttribute('title');
    }

    if (refreshButton) {
      refreshButton.disabled = true;
      refreshButton.classList.add('is-loading');
    }

    try {
      const payload = await fetchJson(
        `/api/panel/version?fresh=1&_=${Date.now()}`,
      );

      renderDashboardVersion(payload);
    } catch (error) {
      renderDashboardFailure(error);
    } finally {
      if (refreshButton) {
        refreshButton.disabled = false;
        refreshButton.classList.remove('is-loading');
      }
    }
  }

  window.refreshDashboardPanelVersion = refreshDashboardVersion;

  const dashboardRefreshButton = byId('panel-version-refresh');
  if (dashboardRefreshButton) {
    dashboardRefreshButton.addEventListener(
      'click',
      refreshDashboardVersion,
    );
  }

  if (document.readyState === 'loading') {
    document.addEventListener(
      'DOMContentLoaded',
      refreshDashboardVersion,
      { once: true },
    );
  } else {
    refreshDashboardVersion();
  }

  window.addEventListener(
    'wg-panel-update-finished',
    () => {
      window.setTimeout(
        refreshDashboardVersion,
        900,
      );
    },
  );

})();

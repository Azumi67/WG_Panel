(() => {
  'use strict';

  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? '')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#039;');

  let report = null;
  let selectedFindingId = null;
  let systemProfile = null;
  let historyEvents = [];
  const repairAttempts = new Map();
  const rollbackAvailable = new Map();
  let confirmResolver = null;
  let confirmReturnFocus = null;

  const severityRank = { critical: 0, high: 1, medium: 2, low: 3, healthy: 4 };

  const toast = (message, type = 'info') => {
    if (window.toastSafe) window.toastSafe(message, type);
  };


  async function copyText(text) {
    const value = String(text ?? '');
    if (!value) return false;

    try {
      if (navigator.clipboard?.writeText && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
        return true;
      }
    } catch (_) { /* use fallback below */ }

    let area = null;
    try {
      area = document.createElement('textarea');
      area.value = value;
      area.setAttribute('readonly', '');
      area.setAttribute('aria-hidden', 'true');
      Object.assign(area.style, {
        position: 'fixed', left: '-9999px', top: '0', width: '1px',
        height: '1px', opacity: '0', pointerEvents: 'none'
      });
      document.body.appendChild(area);
      area.focus({ preventScroll: true });
      area.select();
      area.setSelectionRange(0, area.value.length);
      return !!document.execCommand('copy');
    } catch (_) {
      return false;
    } finally {
      area?.remove();
    }
  }

  function showCopiedState(button, label = 'Copied') {
    if (!button) return;
    const original = button.innerHTML;
    button.classList.add('copied');
    button.innerHTML = `<i class="fas fa-check"></i>${label ? ` ${esc(label)}` : ''}`;
    window.setTimeout(() => {
      button.classList.remove('copied');
      button.innerHTML = original;
    }, 1300);
  }

  async function api(path, body) {
    const init = {
      method: body === undefined ? 'GET' : 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {
        ...(window.csrfHeaders?.(body !== undefined) || {}),
        Accept: 'application/json'
      }
    };
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    const response = await fetch(path, init);
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.error || payload.message || `Request failed (${response.status})`);
    }
    return response.json();
  }

  function closeConfirm(result = false) {
    const root = $('ops-confirm');
    if (!root || root.hidden) return;
    root.hidden = true;
    root.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('ops-confirm-open');
    const resolve = confirmResolver;
    confirmResolver = null;
    const focus = confirmReturnFocus;
    confirmReturnFocus = null;
    if (focus && typeof focus.focus === 'function') {
      try { focus.focus({ preventScroll: true }); } catch (_) { focus.focus(); }
    }
    if (resolve) resolve(Boolean(result));
  }

  function confirmationMarkup(options = {}) {
    const sections = Array.isArray(options.sections) ? options.sections : [];
    const items = Array.isArray(options.items) ? options.items : [];
    const sectionHtml = sections.map((section, index) => `
      <section class="ops-confirm__section">
        <div class="ops-confirm__section-head"><span>${index + 1}</span><strong>${esc(section.title || `Step ${index + 1}`)}</strong></div>
        <ul>${(section.lines || []).map(line => `<li><i class="fas fa-check"></i><span>${esc(line)}</span></li>`).join('')}</ul>
      </section>`).join('');
    const itemHtml = items.length ? `<div class="ops-confirm__items">${items.map((item, index) => `
      <div class="ops-confirm__item"><span>${index + 1}</span><div><strong>${esc(item.title || 'Repair')}</strong>${item.detail ? `<small>${esc(item.detail)}</small>` : ''}</div></div>`).join('')}</div>` : '';
    const plain = options.body ? `<p class="ops-confirm__plain">${esc(options.body).replaceAll('\n', '<br>')}</p>` : '';
    const safety = options.safety ? `<div class="ops-confirm__safety"><i class="fas fa-shield-halved"></i><div><strong>Safety boundary</strong><span>${esc(options.safety)}</span></div></div>` : '';
    return `${itemHtml}${sectionHtml}${plain}${safety}`;
  }

  function ask(optionsOrTitle, body, confirmText = 'Continue') {
    const options = typeof optionsOrTitle === 'object' && optionsOrTitle !== null
      ? optionsOrTitle
      : { title: optionsOrTitle, body, confirmText };
    const root = $('ops-confirm');
    if (!root) return Promise.resolve(false);

    if (confirmResolver) closeConfirm(false);
    confirmReturnFocus = document.activeElement;
    const tone = options.tone || 'safe';
    root.dataset.tone = tone;
    $('ops-confirm-eyebrow').textContent = options.eyebrow || (tone === 'danger' ? 'Review carefully' : tone === 'warning' ? 'Confirmation required' : 'Safe repair');
    $('ops-confirm-title').textContent = options.title || 'Confirm action';
    $('ops-confirm-intro').textContent = options.intro || '';
    $('ops-confirm-body').innerHTML = confirmationMarkup(options);
    const notice = $('ops-confirm-notice');
    if (notice) notice.querySelector('span').textContent = options.notice || 'Nothing changes until you confirm.';
    const ok = $('ops-confirm-ok');
    if (ok) {
      ok.classList.toggle('danger', tone === 'danger');
      ok.classList.toggle('warning', tone === 'warning');
      ok.querySelector('span').textContent = options.confirmText || 'Continue';
      const icon = ok.querySelector('i');
      if (icon) icon.className = `fas ${options.confirmIcon || (tone === 'danger' ? 'fa-rotate-left' : 'fa-check')}`;
    }
    const icon = $('ops-confirm-icon')?.querySelector('i');
    if (icon) icon.className = `fas ${options.icon || (tone === 'danger' ? 'fa-triangle-exclamation' : tone === 'warning' ? 'fa-circle-exclamation' : 'fa-shield-halved')}`;

    root.hidden = false;
    root.setAttribute('aria-hidden', 'false');
    document.body.classList.add('ops-confirm-open');
    window.setTimeout(() => ok?.focus(), 0);
    return new Promise(resolve => { confirmResolver = resolve; });
  }

  function formatDate(ts) {
    if (!ts) return '—';
    const n = Number(ts);
    const d = Number.isFinite(n) ? new Date(n * 1000) : new Date(ts);
    if (Number.isNaN(d.getTime())) return String(ts);
    try {
      if (window.wgPanelFormatDateTime) return window.wgPanelFormatDateTime(d.toISOString(), { seconds: true });
    } catch (_) { /* fallback below */ }
    return d.toLocaleString();
  }

  function relativeTime(ts) {
    const n = Number(ts);
    if (!Number.isFinite(n)) return '—';
    const sec = Math.max(0, Math.round(Date.now() / 1000 - n));
    if (sec < 10) return 'Just now';
    if (sec < 60) return `${sec}s ago`;
    const min = Math.floor(sec / 60);
    if (min < 60) return `${min}m ago`;
    const hr = Math.floor(min / 60);
    if (hr < 24) return `${hr}h ago`;
    const day = Math.floor(hr / 24);
    return `${day}d ago`;
  }

  function setStatus(message, tone = '') {
    const line = $('ops-status');
    if (!line) return;
    line.className = `ops2-status ${tone}`.trim();
    const text = line.querySelector('span:last-child');
    if (text) text.textContent = message;
  }

  function findingTone(finding) {
    const status = String(finding?.status || 'unknown');
    if (status === 'warning') return 'problem';
    if (status === 'unknown') return 'unknown';
    if (status === 'review') return 'advisory';
    return 'healthy';
  }

  function severityOf(finding) {
    if (findingTone(finding) === 'healthy') return 'healthy';
    return String(finding?.severity || (findingTone(finding) === 'problem' ? 'high' : 'low')).toLowerCase();
  }

  function severityLabel(finding) {
    const s = severityOf(finding);
    return s === 'healthy' ? 'Healthy' : s.charAt(0).toUpperCase() + s.slice(1);
  }

  function statusIcon(finding) {
    const tone = findingTone(finding);
    return ({
      problem: 'fa-circle-exclamation',
      unknown: 'fa-circle-question',
      advisory: 'fa-circle-info',
      healthy: 'fa-circle-check'
    })[tone] || 'fa-circle-info';
  }

  function categoryIcon(category) {
    return ({
      security: 'fa-shield-halved', network: 'fa-route', routing: 'fa-route', wireguard: 'fa-network-wired',
      packages: 'fa-box-open', service: 'fa-gears', database: 'fa-database', storage: 'fa-hard-drive',
      nodes: 'fa-server', system: 'fa-microchip', ports: 'fa-plug', dns: 'fa-globe', tls: 'fa-certificate',
      firewall: 'fa-shield-halved', panel: 'fa-gears', backups: 'fa-box-archive'
    })[category] || 'fa-circle-info';
  }

  function categoryLabel(category) {
    const value = String(category || 'system');
    return value.charAt(0).toUpperCase() + value.slice(1);
  }

  function counts() {
    const out = { problems: 0, fixable: 0, advisories: 0, healthy: 0 };
    for (const finding of report?.checks || []) {
      const tone = findingTone(finding);
      if (tone === 'problem' || tone === 'unknown') out.problems += 1;
      if (tone === 'advisory') out.advisories += 1;
      if (tone === 'healthy') out.healthy += 1;
      if (finding.repair && tone !== 'healthy') out.fixable += 1;
    }
    return out;
  }

  function safeRepairs() {
    const seen = new Set();
    const list = [];
    for (const finding of report?.checks || []) {
      const repair = finding.repair;
      if (!repair || repair.risk !== 'low' || finding.status === 'pass') continue;
      const key = `${repair.action}:${repair.target ?? ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      list.push({ finding, repair });
    }
    const priority = {
      install_iproute: 10,
      install_wireguard_tools: 20,
      install_nftables: 30,
      restrict_env: 80,
      enable_ipv4_forwarding: 90,
      start_interface: 100
    };
    list.sort((a, b) => (priority[a.repair.action] ?? 60) - (priority[b.repair.action] ?? 60));
    return list;
  }

  function updateSummary() {
    const c = counts();
    const filter = $('ops-filter')?.value || 'all';
    document.querySelectorAll('[data-summary-status]').forEach(button => {
      const key = button.dataset.summaryStatus;
      button.disabled = !report;
      button.classList.toggle('is-active', filter === key);
      const countNode = button.querySelector('.ops2-summary-copy > b');
      if (countNode) countNode.textContent = report ? String(c[key] ?? 0) : '—';
    });
    const allCount = report?.checks?.length || 0;
    const setTab = (id, value) => { const el = $(id); if (el) el.textContent = String(value ?? 0); };
    setTab('ops-tab-all', allCount);
    setTab('ops-tab-problems', c.problems);
    setTab('ops-tab-fixable', c.fixable);
    setTab('ops-tab-advisories', c.advisories);
    setTab('ops-tab-healthy', c.healthy);
    document.querySelectorAll('[data-ops-filter]').forEach(button => button.classList.toggle('is-active', button.dataset.opsFilter === filter));
    const findingCount = $('ops-finding-count');
    if (findingCount) findingCount.textContent = report ? `${allCount} finding${allCount === 1 ? '' : 's'}` : 'No diagnostic loaded';
    const safe = safeRepairs();
    const button = $('ops-repair-safe');
    if (button) {
      button.disabled = !safe.length;
      button.title = safe.length
        ? `${safe.length} low-risk allowlisted repair${safe.length === 1 ? '' : 's'} available`
        : 'No low-risk automatic repairs are currently available';
    }
  }

  function updateHost(profile, ts) {
    if (profile) systemProfile = profile;
    const p = profile || systemProfile;
    if (p) {
      if ($('ops-host-name')) $('ops-host-name').textContent = p.hostname || 'Local server';
      $('ops-host-os').textContent = p.os || 'Linux host';
      $('ops-host-meta').textContent = [p.kernel && `Kernel ${p.kernel}`, p.architecture].filter(Boolean).join(' · ') || '—';
      $('ops-host-pm').textContent = p.package_manager || 'Not detected';
      $('ops-host-wg').textContent = p.wireguard && p.wg_quick ? 'Ready' : 'Missing';
      $('ops-host-wg').className = p.wireguard && p.wg_quick ? 'good' : 'bad';
      $('ops-host-nft').textContent = p.nftables ? 'Ready' : 'Missing';
      $('ops-host-nft').className = p.nftables ? 'good' : 'bad';
    }
    if (ts) {
      $('ops-host-last').textContent = relativeTime(ts);
      $('ops-host-last-date').textContent = formatDate(ts);
    }
  }

  function findingMatches(finding) {
    const filter = $('ops-filter')?.value || 'all';
    const category = $('ops-category')?.value || 'all';
    const query = String($('ops-search')?.value || '').trim().toLowerCase();
    const tone = findingTone(finding);
    const filterOK = filter === 'all'
      || (filter === 'problems' && (tone === 'problem' || tone === 'unknown'))
      || (filter === 'fixable' && !!finding.repair && tone !== 'healthy')
      || (filter === 'advisories' && tone === 'advisory')
      || (filter === 'healthy' && tone === 'healthy');
    const categoryOK = category === 'all' || String(finding.category || 'system') === category;
    const haystack = [finding.title, finding.evidence, finding.guide, finding.category, finding.cause, finding.impact]
      .filter(Boolean).join(' ').toLowerCase();
    const queryOK = !query || haystack.includes(query);
    return filterOK && categoryOK && queryOK;
  }

  function sortedFindings() {
    const list = (report?.checks || []).filter(findingMatches).slice();
    const mode = $('ops-sort')?.value || 'severity';
    if (mode === 'category') {
      list.sort((a, b) => `${a.category || ''}\0${a.title || ''}`.localeCompare(`${b.category || ''}\0${b.title || ''}`));
    } else if (mode === 'name') {
      list.sort((a, b) => String(a.title || '').localeCompare(String(b.title || '')));
    } else {
      list.sort((a, b) => {
        const rankA = severityRank[severityOf(a)] ?? 3;
        const rankB = severityRank[severityOf(b)] ?? 3;
        if (rankA !== rankB) return rankA - rankB;
        const toneRank = { problem: 0, unknown: 1, advisory: 2, healthy: 3 };
        const ta = toneRank[findingTone(a)] ?? 4;
        const tb = toneRank[findingTone(b)] ?? 4;
        if (ta !== tb) return ta - tb;
        return String(a.title || '').localeCompare(String(b.title || ''));
      });
    }
    return list;
  }

  function renderFindings() {
    const root = $('ops-results');
    if (!root) return;
    if (!report) return;

    const list = sortedFindings();
    const total = report.checks?.length || 0;
    const filter = $('ops-filter')?.value || 'all';
    $('ops-findings-title').textContent = 'Findings';
    $('ops-findings-sub').textContent = `Issues and recommendations from the diagnostic scan · ${list.length} shown of ${total}`;

    if (!list.length) {
      const c = counts();
      const noProblems = filter === 'problems' && c.problems === 0;
      root.innerHTML = `<div class="ops2-empty">
        <span><i class="fas ${noProblems ? 'fa-circle-check' : 'fa-filter-circle-xmark'}"></i></span>
        <strong>${noProblems ? 'No current problems found' : 'Nothing matches this view'}</strong>
        <p>${noProblems ? 'The diagnostic found no failed checks. Review Needs confirmation only when you want to validate deployment-specific choices.' : 'Change the status, search, category, or sort controls to view other diagnostic checks.'}</p>
      </div>`;
      return;
    }

    root.replaceChildren();
    for (const finding of list) {
      const tone = findingTone(finding);
      const severity = severityOf(finding);
      const card = document.createElement('article');
      card.className = `ops2-finding ${tone}${selectedFindingId === finding.id ? ' is-selected' : ''}`;
      card.dataset.findingId = finding.id;
      card.innerHTML = `
        <button type="button" class="ops2-finding-hit" data-select-finding="${esc(finding.id)}" aria-label="Open resolution for ${esc(finding.title)}">
          <span class="ops2-finding-icon ${tone}"><i class="fas ${statusIcon(finding)}"></i></span>
          <span class="ops2-finding-copy">
            <strong>${esc(finding.title)}</strong>
            <small>${esc(finding.evidence || finding.guide || 'No additional detail.')}</small>
          </span>
          <span class="ops2-finding-tags">
            <span class="ops2-severity ${esc(severity)}">${esc(severityLabel(finding))}</span>
            <span class="ops2-category">${esc(categoryLabel(finding.category))}</span>
          </span>
          <i class="fas fa-chevron-right ops2-finding-chevron" aria-hidden="true"></i>
        </button>`;
      root.appendChild(card);
    }
  }

  function commandBlock(command) {
    return `<div class="ops2-command-row">
      <code>${esc(command)}</code>
      <button type="button" class="ops2-copy-command" data-command="${esc(command)}" title="Copy command" aria-label="Copy command"><i class="far fa-copy"></i></button>
    </div>`;
  }

  function uniqueAdvancedCommands(finding) {
    const out = [];
    const seen = new Set();
    const add = value => {
      const command = String(value || '').trim();
      if (!command || seen.has(command)) return;
      seen.add(command);
      out.push(command);
    };
    (finding?.commands || []).forEach(add);
    (finding?.manual_steps || []).forEach(step => (step.commands || []).forEach(add));
    (finding?.verification?.commands || []).forEach(add);
    return out;
  }

  function repairKey(repair, explicitNodeId = undefined) {
    if (!repair) return '';
    const selected = $('ops-scope')?.value || '';
    const nodeId = explicitNodeId !== undefined ? explicitNodeId : (selected ? Number(selected) : null);
    const scope = nodeId ? `node:${nodeId}` : 'local';
    return `${scope}:${repair.action}:${repair.target ?? ''}`;
  }

  function repairTargetPayload(repair) {
    if (repair?.target == null) return {};
    const raw = repair.target;
    const numeric = typeof raw === 'number' || /^\d+$/.test(String(raw));
    return { target: report?.remote && !numeric ? String(raw) : (numeric ? Number(raw) : String(raw)) };
  }

  function impactText(finding) {
    const text = String(finding?.impact || '').trim();
    if (text) return text;
    const severity = severityOf(finding);
    return ({
      critical: 'Service or data availability may be affected.',
      high: 'Peer or panel functionality may be affected.',
      medium: 'Configuration reliability or security may be reduced.',
      low: 'Usually advisory; confirm it matches your deployment.'
    })[severity] || 'No active impact detected.';
  }

  function actionMarkup(action) {
    if (!action?.path) return '';
    return `<a class="ops2-action-link" href="${esc(action.path)}">
      <span class="ops2-action-link-icon"><i class="fas ${esc(action.icon || 'fa-arrow-up-right-from-square')}"></i></span>
      <span><strong>${esc(action.label || 'Open related page')}</strong>${action.hint ? `<small>${esc(action.hint)}</small>` : ''}</span>
      <i class="fas fa-arrow-right"></i>
    </a>`;
  }

  function repairWorkflow(repair, finding) {
    const action = repair?.action || '';
    const maps = {
      restrict_env: {
        pre: ['Confirm the .env file exists', 'Check current permissions without reading its contents'],
        run: ['Remove group/other access', 'Keep the current owner permissions'],
        verify: ['Read the new permission mode', 'Confirm the file is no longer group/world-readable'],
        safety: 'WG Panel changes permission bits only. Secret values are never read or returned to the browser.'
      },
      install_wireguard_tools: {
        pre: ['Detect the package manager', 'Confirm WireGuard tools are missing'],
        run: ['Install the correct WireGuard tools package', 'Leave WireGuard configuration unchanged'],
        verify: ['Confirm wg and wg-quick are available', 'Read the installed tool version'],
        safety: 'This installs tools only. It does not replace keys or interface configuration.'
      },
      install_nftables: {
        pre: ['Detect the package manager', 'Confirm nft is missing'],
        run: ['Install the nftables package', 'Leave the current ruleset unchanged'],
        verify: ['Confirm nft is available', 'Read the installed version'],
        safety: 'The repair does not flush or rewrite firewall rules.'
      },
      install_iproute: {
        pre: ['Detect the package manager', 'Confirm the ip command is missing'],
        run: ['Install iproute/iproute2', 'Leave routes and addresses unchanged'],
        verify: ['Confirm the ip command is available', 'Read the installed version'],
        safety: 'This installs tooling only and does not alter routing tables.'
      },
      enable_ipv4_forwarding: {
        pre: ['Confirm this server is being used for routing', 'Read the current forwarding value'],
        run: ['Persist net.ipv4.ip_forward=1', 'Enable forwarding in the running kernel'],
        verify: ['Read the kernel value again', 'Confirm IPv4 forwarding is enabled'],
        safety: 'This is a host-wide setting. WG Panel does not change firewall rules as part of this repair.'
      },
      start_interface: {
        pre: ['Confirm the interface exists in WG Panel', 'Validate the interface name and config file'],
        run: ['Use WG Panel’s existing interface start routine', 'Apply the stored interface configuration'],
        verify: ['Run wg show for the interface', 'Confirm the interface is active'],
        safety: 'Review PostUp/PostDown hooks before approving. Keys and configuration files are not regenerated.'
      }
    };
    return maps[action] || {
      pre: ['Validate the repair target', 'Confirm this predefined repair is available'],
      run: [repair?.label || 'Run the predefined repair'],
      verify: [finding?.verification?.text || 'Run a fresh read-only verification'],
      safety: repair?.note || 'Only a predefined allowlisted repair is executed.'
    };
  }

  function normalizeGuideSteps(finding) {
    const raw = Array.isArray(finding?.manual_steps) ? finding.manual_steps : [];
    const actions = Array.isArray(finding?.actions) ? finding.actions : [];
    const primary = actions[0] || null;
    const logAction = actions.find(action => /log/i.test(String(action?.label || ''))) || null;
    if (findingTone(finding) === 'healthy') return [];

    if (primary?.path) {
      return [
        {
          title: primary.label || 'Open the related setting',
          text: primary.hint || 'WG Panel opens the exact related page or control.',
          action: { type: 'link', path: primary.path, label: primary.label || 'Open related settings', icon: primary.icon || 'fa-gear' }
        },
        {
          title: logAction ? 'Review logs if needed' : (raw[0]?.title || 'Apply the required change'),
          text: logAction ? 'Open the relevant logs only if you need more detail.' : (raw[0]?.text || finding?.guide || 'Change only the setting identified by this finding.'),
          action: logAction?.path ? { type: 'link', path: logAction.path, label: logAction.label || 'Open logs', icon: logAction.icon || 'fa-file-lines' } : null
        },
        {
          title: 'Return and verify',
          text: 'Come back to Operations and run a fresh verification.',
          action: { type: 'verify', label: 'Run verification', icon: 'fa-play' }
        }
      ];
    }

    return [
      {
        title: 'Review the host-level change',
        text: raw[0]?.text || finding?.guide || 'This setting is outside the web panel. Review the exact change before applying it.'
      },
      {
        title: raw[1]?.title || 'Apply the change',
        text: raw[1]?.text || 'Use the finding-specific command only if you prefer to fix it manually.',
        action: { type: 'advanced', label: 'Show advanced commands', icon: 'fa-terminal' }
      },
      {
        title: 'Return and verify',
        text: 'Come back to Operations and run a fresh verification.',
        action: { type: 'verify', label: 'Run verification', icon: 'fa-play' }
      }
    ];
  }

  function guideStepMarkup(step, index) {
    let action = '';
    if (step?.action?.type === 'link' && step.action.path) {
      action = `<a class="ops2-step-action" href="${esc(step.action.path)}"><i class="fas ${esc(step.action.icon || 'fa-arrow-up-right-from-square')}"></i>${esc(step.action.label || 'Open')}</a>`;
    } else if (step?.action?.type === 'verify') {
      action = `<button type="button" class="ops2-step-action" id="ops-run-verification"><i class="fas ${esc(step.action.icon || 'fa-play')}"></i>${esc(step.action.label || 'Run verification')}</button>`;
    } else if (step?.action?.type === 'advanced') {
      action = `<button type="button" class="ops2-step-action" data-open-advanced="1"><i class="fas ${esc(step.action.icon || 'fa-terminal')}"></i>${esc(step.action.label || 'Show commands')}</button>`;
    }
    return `<div class="ops2-guide-step">
      <span class="ops2-guide-step-number">${index + 1}</span>
      <div class="ops2-guide-step-copy">
        <strong>${esc(step?.title || `Step ${index + 1}`)}</strong>
        ${step?.text ? `<p>${esc(step.text)}</p>` : ''}
        ${action}
      </div>
    </div>`;
  }

  function updateJourney(stage) {
    const order = ['diagnose', 'review', 'repair', 'verify'];
    const idx = Math.max(0, order.indexOf(stage));
    document.querySelectorAll('[data-journey]').forEach(step => {
      const pos = order.indexOf(step.dataset.journey || '');
      step.classList.toggle('is-current', pos === idx);
      step.classList.toggle('is-done', pos >= 0 && pos < idx);
    });
  }

  function recommendationFor(finding, repair, action) {
    if (repair?.risk === 'low') return {
      icon: 'fa-wand-magic-sparkles',
      title: 'Recommended: let WG Panel repair this',
      text: 'This fix is on the predefined allowlist. WG Panel will run safety checks first, make only the listed change, and verify the result automatically.'
    };
    if (repair) return {
      icon: 'fa-user-shield',
      title: 'Recommended: review the repair before approving it',
      text: 'This change can affect the host or network. WG Panel will show you exactly what it intends to do and will not proceed without your confirmation.'
    };
    if (action?.path) return {
      icon: 'fa-arrow-up-right-from-square',
      title: `Recommended: ${action.label || 'open the related setting'}`,
      text: action.hint || 'Use the shortcut below. WG Panel will open the correct tab and highlight the control related to this finding.'
    };
    return {
      icon: 'fa-route',
      title: 'Recommended: follow the guided manual path',
      text: 'This is a host-level or deployment-specific change, so WG Panel will not guess. Follow the short steps below, then run verification.'
    };
  }

  function pathReadinessMarkup(finding) {
    const stages = Array.isArray(finding?.path_stages) ? finding.path_stages : [];
    if (!stages.length) return '';
    const iconFor = id => ({ wireguard: 'fa-network-wired', forwarding: 'fa-share-nodes', route: 'fa-route', firewall: 'fa-shield-halved', dns: 'fa-globe' })[id] || 'fa-circle';
    const labelFor = state => ({ ready: 'Ready', not_required: 'Not required', attention: 'Needs attention', review: 'Review' })[state] || 'Unknown';
    return `<section class="ops2-path-card">
      <div class="ops2-path-head"><span><i class="fas fa-route"></i></span><div><strong>Network path</strong><small>Read-only readiness from WireGuard to the host network.</small></div></div>
      <div class="ops2-path-stages">${stages.map((stage, index) => `<div class="ops2-path-stage ${esc(stage.state || 'review')}">
        <span class="ops2-path-stage-icon"><i class="fas ${iconFor(stage.id)}"></i></span>
        <span class="ops2-path-stage-copy"><strong>${esc(stage.label || `Stage ${index + 1}`)}</strong><small>${esc(stage.detail || labelFor(stage.state))}</small></span>
        <span class="ops2-path-state">${esc(labelFor(stage.state))}</span>
      </div>`).join('')}</div>
    </section>`;
  }

  function rollbackKeyForFinding(finding, repair) {
    if (repair) return repairKey(repair);
    const fallback = { env_mode: 'restrict_env:', forwarding: 'enable_ipv4_forwarding:' };
    return fallback[String(finding?.id || '')] || '';
  }

  function rollbackMarkup(finding, repair) {
    const key = rollbackKeyForFinding(finding, repair);
    if (!key) return '';
    const data = rollbackAvailable.get(key);
    if (!data?.token) return '';
    const expires = data.expires_at ? `Available until ${formatDate(data.expires_at)}` : 'Available for this recent repair';
    return `<div class="ops2-rollback-bar">
      <span class="ops2-rollback-icon"><i class="fas fa-clock-rotate-left"></i></span>
      <span class="ops2-rollback-copy"><strong>Recovery snapshot available</strong><small>${esc(expires)}. This restores only the state captured for this repair.</small></span>
      <button type="button" class="btn secondary" data-rollback-token="${esc(data.token)}"><i class="fas fa-rotate-left"></i> Restore previous state</button>
    </div>`;
  }

  function renderResolution(finding) {
    const body = $('ops-fix-body');
    const title = $('ops-fix-title');
    const counter = $('ops-resolution-counter');
    if (!body || !title) return;

    if (!finding) {
      title.textContent = 'Select a problem';
      if (counter) counter.hidden = true;
      body.innerHTML = `<div class="ops2-resolution-empty">
        <span class="ops2-resolution-empty-icon"><i class="fas fa-route"></i></span>
        <strong>Your recovery plan appears here</strong>
        <p>Select a finding after the diagnostic. WG Panel will show what it found, the safest fix, and how to verify it.</p>
        <div class="ops2-resolution-empty-points">
          <span><i class="fas fa-screwdriver-wrench"></i> Safe automatic repair when supported</span>
          <span><i class="fas fa-arrow-up-right-from-square"></i> Direct link to the related setting when available</span>
          <span><i class="fas fa-circle-check"></i> Fresh verification before the issue is closed</span>
        </div>
      </div>`;
      updateJourney(report ? 'review' : 'diagnose');
      return;
    }

    title.textContent = finding.title || 'Resolution';
    if (counter) {
      const checks = report?.checks || [];
      const index = Math.max(0, checks.findIndex(item => item.id === finding.id));
      counter.textContent = `Finding ${index + 1} of ${Math.max(1, checks.length)}`;
      counter.hidden = false;
    }

    const tone = findingTone(finding);
    const severity = severityOf(finding);
    const repair = finding.repair || null;
    const safe = repair?.risk === 'low';
    const attempts = repair ? repairAttempts.get(repairKey(repair)) : null;
    const lastAttempt = attempts ? `${attempts.ok ? 'Succeeded' : 'Failed'} · ${relativeTime(attempts.ts)}` : 'Never';
    const actions = Array.isArray(finding.actions) ? finding.actions : [];
    const advanced = uniqueAdvancedCommands(finding);
    const guideSteps = normalizeGuideSteps(finding);
    const workflow = repair ? repairWorkflow(repair, finding) : null;
    const isHealthy = tone === 'healthy';

    if (isHealthy) {
      body.innerHTML = `
        <section class="ops2-resolution-issue">
          <div class="ops2-resolution-issue-main">
            <span class="ops2-finding-icon healthy"><i class="fas ${statusIcon(finding)}"></i></span>
            <div><h3>${esc(finding.title)}</h3><p>${esc(finding.evidence || '')}</p></div>
          </div>
          <div class="ops2-resolution-tags"><span class="ops2-severity healthy">Healthy</span><span class="ops2-category">${esc(categoryLabel(finding.category))}</span></div>
        </section>
        <section class="ops2-healthy-card"><span><i class="fas fa-circle-check"></i></span><div><strong>No action required</strong><p>${esc(finding.verification?.text || 'This diagnostic check passed.')}</p></div><button type="button" class="btn secondary" id="ops-run-verification"><i class="fas fa-play"></i> Run verification</button></section>
        ${pathReadinessMarkup(finding)}
        ${rollbackMarkup(finding, repair)}
        ${actions.length ? `<section class="ops2-related-pages"><strong>Related page</strong><div>${actions.slice(0, 2).map(actionMarkup).join('')}</div></section>` : ''}`;
      updateJourney('verify');
      return;
    }

    const autoCard = repair ? `
      <section class="ops2-auto-card ${repair.risk === 'medium' ? 'is-medium' : ''}">
        <div class="ops2-auto-head">
          <div class="ops2-auto-title"><span class="ops2-auto-icon"><i class="fas fa-screwdriver-wrench"></i></span><span><strong>${safe ? 'Automatic repair (recommended)' : 'Automatic repair (review required)'}</strong><p>${esc(repair.note || 'WG Panel will run a predefined repair and verify the result.')}</p><small>Last attempt: ${esc(lastAttempt)}</small></span></div>
          <button type="button" class="btn ops2-auto-fix ${repair.risk === 'medium' ? 'medium' : ''}" data-repair-action="${esc(repair.action)}"><i class="fas fa-screwdriver-wrench"></i> ${safe ? 'Fix automatically' : 'Review & fix'}</button>
        </div>
        <div class="ops2-auto-plan">
          <div class="ops2-plan-column"><div class="ops2-plan-title"><span>1</span><strong>Pre-checks</strong></div><ul class="ops2-plan-list">${workflow.pre.map(x => `<li>${esc(x)}</li>`).join('')}</ul></div>
          <div class="ops2-plan-column"><div class="ops2-plan-title"><span>2</span><strong>Changes</strong></div><ul class="ops2-plan-list">${workflow.run.map(x => `<li>${esc(x)}</li>`).join('')}</ul></div>
          <div class="ops2-plan-column"><div class="ops2-plan-title"><span>3</span><strong>Verification</strong></div><ul class="ops2-plan-list">${workflow.verify.map(x => `<li>${esc(x)}</li>`).join('')}</ul></div>
        </div>
        <div class="ops2-auto-safety"><i class="fas fa-shield-halved"></i><span>${esc(workflow.safety)}</span></div>
      </section>` : `
      <section class="ops2-guidance-banner"><span><i class="fas fa-route"></i></span><div><strong>Manual recovery recommended</strong><p>This finding depends on your deployment, so WG Panel will not make an automatic change.</p></div></section>`;

    body.innerHTML = `
      <section class="ops2-resolution-issue">
        <div class="ops2-resolution-issue-main">
          <span class="ops2-finding-icon ${tone}"><i class="fas ${statusIcon(finding)}"></i></span>
          <div><h3>${esc(finding.title)}</h3><p>${esc(finding.evidence || '')}</p></div>
        </div>
        <div class="ops2-resolution-tags"><span class="ops2-severity ${esc(severity)}">${esc(severityLabel(finding))} severity</span><span class="ops2-category">${esc(categoryLabel(finding.category))}</span></div>
      </section>

      <section class="ops2-facts-grid ops2-facts-grid-3">
        <div class="ops2-fact-card"><span><i class="fas fa-file-lines"></i></span><div><strong>What WG Panel found</strong><p>${esc(finding.evidence || 'The diagnostic found a condition that needs review.')}</p></div></div>
        <div class="ops2-fact-card"><span><i class="fas fa-circle-question"></i></span><div><strong>Likely cause</strong><p>${esc(finding.cause || finding.guide || 'The diagnostic could not establish a more specific cause.')}</p></div></div>
        <div class="ops2-fact-card"><span><i class="fas fa-shield-halved"></i></span><div><strong>Why it matters</strong><p>${esc(impactText(finding))}</p></div></div>
      </section>

      ${pathReadinessMarkup(finding)}
      ${autoCard}
      ${rollbackMarkup(finding, repair)}

      <section class="ops2-guide-section ops2-manual-card">
        <div class="ops2-guide-title">
          <div class="ops2-guide-title-main"><i class="fas fa-book-open"></i><div><strong>Manual fix path ${repair ? '(alternative)' : ''}</strong><small>Prefer to make the change yourself? Follow these steps.</small></div></div>
        </div>
        <div class="ops2-guide-flow">${guideSteps.map((step, i) => guideStepMarkup(step, i)).join('')}</div>
      </section>

      ${finding.when_ok ? `<section class="ops2-intentional-note"><i class="fas fa-circle-info"></i><div><strong>Could this be intentional?</strong><p>${esc(finding.when_ok)}</p></div></section>` : ''}

      ${advanced.length ? `<details class="ops2-advanced"><summary><span><i class="fas fa-terminal"></i><span><strong>Advanced commands</strong><small>For experienced administrators</small></span></span><i class="fas fa-chevron-down"></i></summary><div class="ops2-advanced-body">${advanced.map(commandBlock).join('')}</div></details>` : ''}
    `;
    updateJourney(repair ? 'repair' : 'review');
  }

  function render() {
    updateSummary();
    if (!report) updateJourney('diagnose');
    else if (!selectedFindingId) updateJourney('review');
    renderFindings();
    const selected = (report?.checks || []).find(item => item.id === selectedFindingId) || null;
    renderResolution(selected);
    if (report?.system) updateHost(report.system, report.ts);
    else if (report?.ts) {
      $('ops-host-last').textContent = relativeTime(report.ts);
      $('ops-host-last-date').textContent = formatDate(report.ts);
    }
  }

  function selectFinding(id, { scroll = false } = {}) {
    selectedFindingId = id;
    renderFindings();
    const finding = (report?.checks || []).find(item => item.id === id) || null;
    renderResolution(finding);
    if (scroll && window.matchMedia('(max-width: 920px)').matches) {
      $('ops-fix-pane')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  function reportPayload() {
    const scope = $('ops-scope')?.value || '';
    return scope ? { node_id: Number(scope) } : {};
  }

  function chooseInitialFinding() {
    const checks = report?.checks || [];
    return checks.find(f => findingTone(f) === 'problem')?.id
      || checks.find(f => findingTone(f) === 'unknown')?.id
      || checks.find(f => findingTone(f) === 'advisory')?.id
      || checks[0]?.id
      || null;
  }

  async function runVerification({ afterRepair = false } = {}) {
    if (!report) return;
    const button = $('ops-run-verification');
    if (button) button.disabled = true;
    setStatus('Running read-only verification…', 'busy');
    const previousId = selectedFindingId;
    try {
      const fresh = await api('/api/operations/verify', reportPayload());
      report = fresh;
      const same = (report.checks || []).find(item => item.id === previousId);
      selectedFindingId = same?.id || chooseInitialFinding();
      const current = same || (report.checks || []).find(item => item.id === selectedFindingId);
      const tone = current ? findingTone(current) : 'healthy';
      if (current && tone === 'healthy') {
        setStatus(`${current.title} is healthy now. Verification passed.`, 'pass');
        toast('Verification passed', 'success');
      } else if (afterRepair && current) {
        setStatus(`Repair completed, but ${current.title} still needs attention. Follow the manual recovery steps before retrying.`, 'warning');
        toast('The repair completed but verification still reports an issue', 'warning');
      } else {
        const c = counts();
        setStatus(c.problems ? `${c.problems} item${c.problems === 1 ? '' : 's'} still need attention.` : 'Verification completed. No current problems found.', c.problems ? 'warning' : 'pass');
      }
      render();
      await loadHistory();
    } catch (error) {
      setStatus(error.message, 'warning');
      toast(error.message, 'error');
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function runRepair(repair) {
    const risk = repair.risk || 'low';
    const finding = (report?.checks || []).find(item => item.id === selectedFindingId) || null;
    const plan = repairWorkflow(repair, finding);
    const confirmed = await ask({
      title: repair.label || 'Automatic repair',
      intro: repair.note || 'WG Panel will run a predefined allowlisted repair and verify the result.',
      confirmText: risk === 'low' ? 'Fix and verify' : 'Approve repair',
      confirmIcon: 'fa-screwdriver-wrench',
      tone: risk === 'low' ? 'safe' : 'warning',
      sections: [
        { title: 'Pre-checks', lines: plan.pre },
        { title: 'Changes', lines: plan.run },
        { title: 'Verification', lines: plan.verify }
      ],
      safety: plan.safety,
      notice: risk === 'low' ? 'This action is allowlisted and verification runs automatically.' : 'This change affects host or network state. Review the plan before approving.'
    });
    if (!confirmed) return false;

    setStatus(`Running ${repair.label || 'repair'}…`, 'busy');
    const result = await api('/api/operations/repair', {
      ...reportPayload(),
      action: repair.action,
      ...repairTargetPayload(repair),
      confirm: true
    });
    repairAttempts.set(repairKey(repair), { ok: true, ts: Date.now() / 1000 });
    if (result.rollback?.token) rollbackAvailable.set(repairKey(repair), result.rollback);
    toast(result.message || 'Repair completed', 'success');
    setStatus('Repair completed. Verifying the result now…', 'busy');
    await runVerification({ afterRepair: true });
    return true;
  }

  async function runScan() {
    const button = $('ops-scan');
    if (!button) return;
    button.disabled = true;
    $('ops-repair-safe').disabled = true;
    setStatus('Running read-only diagnostic checks…', 'busy');
    try {
      report = await api('/api/operations/scan', reportPayload());
      selectedFindingId = chooseInitialFinding();
      $('ops-export').disabled = false;
      $('ops-filter').value = 'all';
      $('ops-category').value = 'all';
      $('ops-sort').value = 'severity';
      const c = counts();
      if (c.problems) {
        setStatus(`${c.problems} problem${c.problems === 1 ? '' : 's'} found. Select the first item to see the exact recovery path.`, 'warning');
      } else {
        setStatus(c.advisories ? `No current problems. ${c.advisories} deployment-specific item${c.advisories === 1 ? '' : 's'} can be reviewed if needed.` : 'No current problems found. All checks passed.', 'pass');
      }
      render();
      await loadHistory();
    } catch (error) {
      setStatus(error.message, 'warning');
      toast(error.message, 'error');
    } finally {
      button.disabled = false;
      updateSummary();
    }
  }

  function resetForScope() {
    report = null;
    selectedFindingId = null;
    $('ops-export').disabled = true;
    $('ops-repair-safe').disabled = true;
    document.querySelectorAll('[data-summary-status]').forEach(button => {
      button.disabled = true;
      const b = button.querySelector('.ops2-summary-copy > b');
      if (b) b.textContent = '—';
    });
    $('ops-results').innerHTML = '<div class="ops2-empty"><span><i class="fas fa-stethoscope"></i></span><strong>Ready to diagnose this server</strong><p>Run a new diagnostic after changing the target server.</p></div>';
    $('ops-findings-sub').textContent = 'No diagnostic loaded.';
    renderResolution(null);
    setStatus('Run a diagnostic for the selected server.');
  }

  async function fixSafeIssues() {
    const list = safeRepairs();
    if (!list.length) return;
    const confirmed = await ask({
      title: 'Fix safe issues',
      intro: `WG Panel found ${list.length} low-risk repair${list.length === 1 ? '' : 's'} that can be safely automated.`,
      confirmText: 'Fix safe issues',
      confirmIcon: 'fa-screwdriver-wrench',
      tone: 'safe',
      items: list.map(item => {
        const plan = repairWorkflow(item.repair, item.finding);
        return { title: item.finding.title, detail: `${item.repair.label} · Verify: ${plan.verify[0] || 'fresh diagnostic'}` };
      }),
      safety: 'Only low-risk allowlisted repairs are included. Medium-risk and deployment-dependent changes are excluded.',
      notice: 'Repairs run one at a time. WG Panel performs one fresh verification after the batch.'
    });
    if (!confirmed) return;

    const button = $('ops-repair-safe');
    button.disabled = true;
    let completed = 0;
    for (let index = 0; index < list.length; index += 1) {
      const item = list[index];
      setStatus(`Safe repair ${index + 1} of ${list.length}: ${item.repair.label}…`, 'busy');
      try {
        const result = await api('/api/operations/repair', {
          ...reportPayload(),
          action: item.repair.action,
          ...repairTargetPayload(item.repair),
          confirm: true
        });
        repairAttempts.set(repairKey(item.repair), { ok: true, ts: Date.now() / 1000 });
        if (result.rollback?.token) rollbackAvailable.set(repairKey(item.repair), result.rollback);
        completed += 1;
        if (result.message) toast(result.message, 'success');
      } catch (error) {
        repairAttempts.set(repairKey(item.repair), { ok: false, ts: Date.now() / 1000 });
        toast(`${item.repair.label}: ${error.message}`, 'error');
      }
    }
    setStatus(`${completed} of ${list.length} safe repair${list.length === 1 ? '' : 's'} completed. Running one final verification…`, completed ? 'busy' : 'warning');
    await runVerification({ afterRepair: true });
  }

  function parseRepairAttempts(events) {
    repairAttempts.clear();
    rollbackAvailable.clear();
    for (const event of [...events].reverse()) {
      const payload = event.payload || {};
      const action = payload.action;
      if (!action) continue;
      const key = repairKey(payload, payload.node_id ?? null);
      if (event.kind === 'rollback') {
        rollbackAvailable.delete(key);
        continue;
      }
      if (!['repair', 'repair_failed'].includes(event.kind)) continue;
      repairAttempts.set(key, { ok: event.kind === 'repair', ts: event.ts });
      if (event.kind === 'repair') {
        const expires = Number(payload.rollback?.expires_at || 0);
        if (payload.rollback?.token && (!expires || expires * 1000 > Date.now())) rollbackAvailable.set(key, payload.rollback);
        else rollbackAvailable.delete(key);
      }
    }
  }

  async function loadHistory() {
    const root = $('ops-history');
    if (!root) return;
    try {
      const payload = await api('/api/operations/history');
      historyEvents = payload.events || [];
      parseRepairAttempts(historyEvents);
      root.replaceChildren();
      if (!historyEvents.length) {
        root.innerHTML = '<div class="ops2-history-empty">No Operations history yet.</div>';
        return;
      }
      for (const event of historyEvents) {
        const row = document.createElement('div');
        row.className = `ops2-history-row kind-${esc(event.kind)}`;
        const isReport = ['scan', 'verification'].includes(event.kind) && event.payload?.checks;
        const label = ({
          scan: 'Diagnostic', verification: 'Verification', repair: 'Repair completed',
          repair_started: 'Repair started', repair_failed: 'Repair failed', rollback: 'Previous state restored', rollback_failed: 'Rollback failed'
        })[event.kind] || event.kind;
        let summary = '';
        if (isReport) {
          const c = event.payload.counts || {};
          summary = `${event.payload.scope || 'Server'} · ${Number(c.warning || 0) + Number(c.unknown || 0)} problem(s) · ${Number(c.review || 0)} confirmation item(s)`;
        } else {
          summary = event.payload?.message || event.payload?.action || 'Operations event';
        }
        row.innerHTML = `
          <span class="ops2-history-icon"><i class="fas ${['repair_failed','rollback_failed'].includes(event.kind) ? 'fa-triangle-exclamation' : event.kind === 'rollback' ? 'fa-clock-rotate-left' : isReport ? 'fa-stethoscope' : 'fa-screwdriver-wrench'}"></i></span>
          <span class="ops2-history-copy"><strong>${esc(label)}</strong><small>${esc(summary)} · ${esc(formatDate(event.ts))}</small></span>
          ${isReport ? `<button type="button" class="btn secondary" data-history-report="${event.id}">View report</button>` : ''}`;
        if (isReport) row._reportPayload = event.payload;
        root.appendChild(row);
      }
    } catch (error) {
      root.innerHTML = `<div class="ops2-history-empty">Could not load history: ${esc(error.message)}</div>`;
    }
  }

  function exportReport() {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = `wg-panel-diagnostic-${new Date().toISOString().replaceAll(':', '-').replace(/\.\d+Z$/, 'Z')}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function bindEvents() {
    $('ops-confirm-ok')?.addEventListener('click', () => closeConfirm(true));
    document.querySelectorAll('[data-ops-confirm-cancel]').forEach(node => node.addEventListener('click', () => closeConfirm(false)));
    document.addEventListener('keydown', event => {
      const dialog = $('ops-confirm');
      if (!dialog || dialog.hidden) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        closeConfirm(false);
        return;
      }
      if (event.key !== 'Tab') return;
      const focusable = [...dialog.querySelectorAll('button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])')]
        .filter(node => !node.hidden && node.offsetParent !== null);
      if (!focusable.length) { event.preventDefault(); return; }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    });
    $('ops-scan')?.addEventListener('click', runScan);
    document.addEventListener('click', event => {
      const start = event.target.closest('[data-run-diagnostic]');
      if (start) runScan();
    });
    $('ops-repair-safe')?.addEventListener('click', fixSafeIssues);
    $('ops-export')?.addEventListener('click', exportReport);
    $('ops-search')?.addEventListener('input', () => { selectedFindingId = null; render(); });
    document.querySelector('.ops2-status-tabs')?.addEventListener('click', event => {
      const button = event.target.closest('[data-ops-filter]');
      if (!button || !report) return;
      $('ops-filter').value = button.dataset.opsFilter || 'all';
      selectedFindingId = null;
      render();
    });

    $('ops-filter')?.addEventListener('change', () => {
      selectedFindingId = null;
      render();
    });
    $('ops-category')?.addEventListener('change', () => {
      selectedFindingId = null;
      render();
    });
    $('ops-sort')?.addEventListener('change', renderFindings);
    $('ops-scope')?.addEventListener('change', resetForScope);

    $('ops-results')?.addEventListener('click', event => {
      const target = event.target.closest('[data-select-finding]');
      if (!target) return;
      selectFinding(target.dataset.selectFinding, { scroll: true });
    });

    $('ops-summary')?.addEventListener('click', event => {
      const button = event.target.closest('[data-summary-status]');
      if (!button || button.disabled || !report) return;
      const key = button.dataset.summaryStatus;
      if (key === 'fixable') {
        $('ops-filter').value = 'fixable';
        selectedFindingId = null;
        render();
        return;
      }
      $('ops-filter').value = key;
      selectedFindingId = null;
      render();
    });

    $('ops-fix-body')?.addEventListener('click', async event => {
      const copy = event.target.closest('[data-command]');
      if (copy) {
        const ok = await copyText(copy.dataset.command || '');
        if (ok) {
          showCopiedState(copy, '');
          toast('Command copied', 'success');
        } else {
          toast('Could not copy command. Select the command text and copy it manually.', 'error');
        }
        return;
      }

      const openAdvanced = event.target.closest('[data-open-advanced]');
      if (openAdvanced) {
        const details = $('ops-fix-body')?.querySelector('.ops2-advanced');
        if (details) {
          details.open = true;
          details.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
        return;
      }

      const verify = event.target.closest('#ops-run-verification');
      if (verify) {
        await runVerification();
        return;
      }

      const rollbackButton = event.target.closest('[data-rollback-token]');
      if (rollbackButton) {
        const token = rollbackButton.dataset.rollbackToken || '';
        const confirmed = await ask({
          title: 'Restore previous state?',
          intro: 'WG Panel will restore the server state captured immediately before this repair.',
          confirmText: 'Restore previous state',
          confirmIcon: 'fa-rotate-left',
          tone: 'warning',
          sections: [
            { title: 'What happens', lines: ['Restore only the saved state for this repair', 'Leave unrelated settings unchanged'] },
            { title: 'Verification', lines: ['Run a fresh read-only diagnostic after the rollback'] }
          ],
          safety: 'Snapshots expire after 24 hours and can be used only by an authenticated administrator.',
          notice: 'Use rollback only when the automatic repair caused an unexpected result.'
        });
        if (!confirmed) return;
        rollbackButton.disabled = true;
        try {
          const result = await api('/api/operations/rollback', { ...reportPayload(), token, confirm: true });
          for (const [key, value] of rollbackAvailable.entries()) if (value?.token === token) rollbackAvailable.delete(key);
          toast(result.message || 'Previous state restored', 'success');
          setStatus('Previous state restored. Verifying the server now…', 'busy');
          await runVerification();
          await loadHistory();
        } catch (error) {
          setStatus(error.message, 'warning');
          toast(error.message, 'error');
        } finally { rollbackButton.disabled = false; }
        return;
      }

      const repairButton = event.target.closest('[data-repair-action]');
      if (!repairButton || !report) return;
      const finding = (report.checks || []).find(item => item.id === selectedFindingId);
      if (!finding?.repair) return;
      repairButton.disabled = true;
      try { await runRepair(finding.repair); }
      catch (error) {
        repairAttempts.set(repairKey(finding.repair), { ok: false, ts: Date.now() / 1000 });
        setStatus(error.message, 'warning');
        toast(error.message, 'error');
        renderResolution(finding);
        await loadHistory();
      } finally {
        repairButton.disabled = false;
      }
    });

    $('ops-resolution-close')?.addEventListener('click', () => {
      selectedFindingId = null;
      renderFindings();
      renderResolution(null);
    });

    $('ops-history')?.addEventListener('click', event => {
      const button = event.target.closest('[data-history-report]');
      if (!button) return;
      const row = button.closest('.ops2-history-row');
      if (!row?._reportPayload) return;
      report = row._reportPayload;
      selectedFindingId = chooseInitialFinding();
      $('ops-filter').value = 'all';
      $('ops-category').value = 'all';
      $('ops-sort').value = 'severity';
      $('ops-export').disabled = false;
      render();
      setStatus(`Loaded ${report.remote ? 'remote ' : ''}diagnostic from ${formatDate(report.ts)}.`);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  async function init() {
    bindEvents();
    try {
      const [guide, nodePayload] = await Promise.all([
        api('/api/operations/guide'),
        api('/api/operations/nodes')
      ]);
      systemProfile = guide.system || null;
      updateHost(systemProfile, null);
      const select = $('ops-scope');
      for (const node of nodePayload.nodes || []) {
        const option = document.createElement('option');
        option.value = String(node.id);
        option.textContent = node.name || `Node ${node.id}`;
        select?.appendChild(option);
      }
    } catch (error) {
      setStatus(`Host information could not be fully loaded: ${error.message}`, 'warning');
    }
    await loadHistory();
    const params = new URLSearchParams(location.search);
    if (params.get('from') === 'peer') {
      const node = params.get('node');
      const select = $('ops-scope');
      const note = document.createElement('div');
      note.className = 'ops-peer-context';
      note.setAttribute('role', 'status');
      const iface = params.get('interface') || 'selected interface';
      note.textContent = `Peer diagnosis · ${iface}. Running a read-only host scan. Peer access and client connectivity are managed in Peers; host repairs remain optional.`;
      $('operations-workspace')?.prepend(note);
      if (node && ![...select.options].some(option => option.value === node)) {
        note.textContent = `The selected node is unavailable. Choose the correct target before running a diagnostic for ${iface}.`;
        return;
      }
      select.value = node || '';
      await runScan();
      const finding = (report?.checks || []).find(item =>
        JSON.stringify([item.id, item.title, item.evidence]).toLowerCase().includes(iface.toLowerCase()));
      if (finding) selectFinding(finding.id);
    }
  }

  init();
})();

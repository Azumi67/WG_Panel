
(() => {
  function getCookie(name) {
    return document.cookie
      .split('; ')
      .map(v => v.split('='))
      .find(p => p[0] === name)?.[1] || '';
  }
  window.addEventListener('hashchange', () => {
  document.querySelectorAll('.modal.open').forEach(m => m.classList.remove('open'));
  document.body.classList.remove('modal-open');
});

  const origFetch = window.fetch;
  window.fetch = function (input, init) {
    init = init || {};
    const method = (init.method || 'GET').toUpperCase();

    if (!['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(method)) {
      const token = getCookie('csrf_token');
      init.headers = Object.assign({}, init.headers, { 'X-CSRFToken': token });
      if (init.credentials === undefined) init.credentials = 'same-origin';
    }

    return origFetch(input, init);
  };
const API_BASE = document.documentElement.getAttribute('data-api-base') || '';
const api = (p) => (API_BASE + p).replace(/\/{2,}/g, '/');

function peerKey(p) {
  const hasNodeScope = (typeof getScopeId === 'function' && !!getScopeId()) || !!window.NODE_ID;
  return hasNodeScope ? (p.public_key || p.id) : p.id;
}
function apiPeerPath(idOrPeer, suffix = '') {
  const key = (typeof idOrPeer === 'object') ? peerKey(idOrPeer) : idOrPeer;
  const scopeId = (typeof getScopeId === 'function' && getScopeId()) ? getScopeId() : '';
  const nodeId = window.NODE_ID || scopeId;
  if (nodeId) {
    return `/api/nodes/${encodeURIComponent(String(nodeId))}/peer/${encodeURIComponent(String(key))}${suffix}`;
  }
  return `/api/peer/${encodeURIComponent(String(key))}${suffix}`;
}
function fmtDaysHours(d) {
  const n = Number(d);
  if (!Number.isFinite(n) || n <= 0) return '–';
  const days = Math.floor(n);
  let hours = Math.round((n - days) * 24);
  let dd = days, hh = hours;
  if (hours === 24) { dd += 1; hh = 0; }
  const parts = [];
  if (dd) parts.push(`${dd}d`);
  if (hh) parts.push(`${hh}h`);
  return parts.length ? parts.join(' ') : '0d';
}

function fmtDaysOrHours(d) { return fmtDaysHours(d); }


  const $  = (sel, r = document) => r.querySelector(sel);
  const $$ = (sel, r = document) => Array.from(r.querySelectorAll(sel));
  const q  = (sel) => (typeof sel === 'string' && sel) ? document.querySelector(sel) : null;
  const qs = (sel) => Array.from(document.querySelectorAll(sel));
  const setVal = (sel, v) => { const el = q(sel); if (el) el.value = (v ?? ''); };
  const getVal = (sel) => (q(sel)?.value ?? '').trim();
  const setChecked = (sel, on) => { const el = q(sel); if (el) el.checked = !!on; };
  const intOrZero = (x) => { const n = parseInt(x, 10); return Number.isFinite(n) ? n : 0; };
  const numOrNull = (x) => { const n = Number(x); return (x === '' || Number.isNaN(n)) ? null : n; };
  const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
  const cap = s => s ? s[0].toUpperCase() + s.slice(1) : '';
  const statusIcon = s => (
  s === 'online' ? 'fa-signal' :
  s === 'enabled' ? 'fa-toggle-on' :
  s === 'disabled' ? 'fa-toggle-off' :
  s === 'blocked' ? 'fa-ban' :
  s === 'depleting' ? 'fa-hourglass-half' :
  'fa-times-circle'
);

function panelStatus(p) {
  return String(p.panel_status || p.status || 'offline').toLowerCase();
}

function connStatus(p) {
  return String(p.conn_status || p.connection_status || 'offline').toLowerCase() === 'online'
    ? 'online'
    : 'offline';
}

function isBlocked(p) {
  return panelStatus(p) === 'blocked';
}

function isEnabled(p) {
  return panelStatus(p) === 'online';
}

function isDisabled(p) {
  return !isEnabled(p);
}

function isDepleting(p) {
  if (isBlocked(p) || p.unlimited) return false;

  const remMiB = remainingMiB(p);
  const limMiB = toMiB(p.data_limit, p.limit_unit);

  const dataLow =
    Number.isFinite(remMiB) &&
    Number.isFinite(limMiB) &&
    limMiB > 0 &&
    remMiB <= Math.max(50, limMiB * 0.15);

  const ttl = Number(p.ttl_seconds);
  const timeLow =
    Number.isFinite(ttl) &&
    ttl > 0 &&
    ttl <= 24 * 3600;

  return dataLow || timeLow;
}

function peerTagsHTML(p) {
  const c = connStatus(p);
  const pStatus = panelStatus(p);
  const reason = String(p.conn_reason || '').replace(/_/g, ' ');

  const tags = [
    `<span class="peer-tag live-tag live-${c}" title="Live connection: ${cap(c)}${reason ? ' · ' + reason : ''}">
      <span class="live-dot" aria-hidden="true"></span>
      <span class="live-word">Live</span>
      <b>${c === 'online' ? 'Online' : 'Offline'}</b>
    </span>`
  ];

  if (pStatus === 'online') {
    tags.push(`
      <span class="peer-tag enabled" title="Panel state: enabled">
        <i class="fas ${statusIcon('enabled')}"></i> Enabled
      </span>
    `);
  } else if (pStatus === 'blocked') {
    tags.push(`
      <span class="peer-tag blocked" title="Panel state: blocked">
        <i class="fas ${statusIcon('blocked')}"></i> Blocked
      </span>
    `);
  } else {
    tags.push(`
      <span class="peer-tag disabled" title="Panel state: disabled">
        <i class="fas ${statusIcon('disabled')}"></i> Disabled
      </span>
    `);
  }

  if (isDepleting(p)) {
    tags.push(`
      <span class="peer-tag depleting" title="Depleting: low data or time remaining">
        <i class="fas ${statusIcon('depleting')}" aria-hidden="true"></i>
        <span>Low</span>
      </span>
    `);
  }

  return tags.join('');
}

const pick = (keys) => Array.isArray(keys) ? (keys.find(sel => !!q(sel)) || keys[0]) : keys;

const SEL = {
  use_profile_toggle: [
    '#use-profile-toggle',
    '[name="use_profile"]',
    '[name="use_profile_toggle"]'
  ],

  save_profile_btn: [
    '#save-profile-btn',
    '#profile-save-btn',
    '[data-profile-save]'
  ],

  profile_select: [
    '#profile-select',
    '[name="profile"]',
    '[name="profile_select"]'
  ],

  allowed_ips: [
    '#peer-allowed-ips',
    '#peer-allowed_ips',
    '#peer-modal [name="allowed_ips"]'
  ],

  endpoint: [
    '#peer-endpoint',
    '#peer-modal [name="endpoint"]'
  ],

  dns: [
    '#peer-dns',
    '#peer-modal [name="dns"]'
  ],

  mtu: [
    '#peer-mtu',
    '#peer-modal [name="mtu"]'
  ],

  keepalive: [
    '#peer-keepalive',
    '#peer-modal [name="persistent_keepalive"]'
  ],

  data_limit_value: [
    '#peer-data-limit-value',
    '#peer-modal [name="data_limit"]',
    '#peer-modal [name="data_limit_value"]'
  ],

  data_limit_unit: [
    '#peer-data-limit-unit',
    '#peer-modal [name="limit_unit"]',
    '#peer-modal [name="data_limit_unit"]'
  ],

  start_on_first_use: [
    '#peer-start-first-use',
    '#peer-modal [name="start_on_first_use"]'
  ],

  unlimited: [
    '#peer-unlimited',
    '#peer-modal [name="unlimited"]'
  ],

  time_days: [
    '#time_limit_days',
    '#peer-time-days',
    '#peer-modal [name="time_limit_days"]'
  ],

  time_hours: [
    '#time_limit_hours',
    '#peer-time-hours',
    '#peer-modal [name="time_limit_hours"]'
  ]
};

let __profileCache = null;
let __profileSnapshot = null;

function snapForm() {
  return {
    allowed_ips: getVal(pick(SEL.allowed_ips)),
    endpoint:    getVal(pick(SEL.endpoint)),
    dns:         getVal(pick(SEL.dns)),
    mtu:         getVal(pick(SEL.mtu)),
    keepalive:   getVal(pick(SEL.keepalive)),
    data_limit_value: getVal(pick(SEL.data_limit_value)),
    data_limit_unit:  getVal(pick(SEL.data_limit_unit)),
    start_on_first_use: !!q(pick(SEL.start_on_first_use))?.checked,
    unlimited:          !!q(pick(SEL.unlimited))?.checked,
    time_days:   getVal(pick(SEL.time_days)),
    time_hours:  getVal(pick(SEL.time_hours)),
  };
}

function restoreForm(s) {
   if (!s) return;
  setVal(pick(SEL.allowed_ips), s.allowed_ips);
  setVal(pick(SEL.endpoint),    s.endpoint);
  setVal(pick(SEL.dns),         s.dns);
  setVal(pick(SEL.mtu),         s.mtu);
  setVal(pick(SEL.keepalive),   s.keepalive);
  setVal(pick(SEL.data_limit_value), s.data_limit_value);
  setVal(pick(SEL.data_limit_unit),  s.data_limit_unit || 'Mi');
  setChecked(pick(SEL.start_on_first_use), !!s.start_on_first_use);
  setChecked(pick(SEL.unlimited),          !!s.unlimited);
  setVal(pick(SEL.time_days),  s.time_days);
  setVal(pick(SEL.time_hours), s.time_hours);
}

async function loadProfile(name = null, force = false) {
  if (!force && __profileCache && (__profileCache.__name || 'Default') === (name || 'Default')) {
    return __profileCache;
  }
  const url = name
    ? `/api/peer_profile?name=${encodeURIComponent(name)}`
    : `/api/peer_profile`;
  const r = await fetch(url, { credentials: 'same-origin' });
  if (!r.ok) return (__profileCache = {});
  const prof = await r.json();
  prof.__name = name || (prof.name || 'Default');
  return (__profileCache = prof);
}


function keepaliveMtu(profile) {
  const kaEl = q('#peer-keepalive');
  const mtuEl = q('#peer-mtu');

  if (kaEl) {
    const ka = profile?.persistent_keepalive;
    kaEl.placeholder = (ka == null || ka === '') ? '—' : String(ka);
  }
  if (mtuEl) {
    const mtu = profile?.mtu;
    mtuEl.placeholder = (mtu == null || mtu === '') ? '—' : String(mtu);
  }
}

function applyProfile(p) {
  setVal(pick(SEL.allowed_ips), p.allowed_ips);
  setVal(pick(SEL.endpoint),    p.endpoint);
  setVal(pick(SEL.dns),         p.dns);
  setVal(pick(SEL.mtu),         p.mtu ?? '');
  setVal(pick(SEL.keepalive),   p.persistent_keepalive ?? '');
  setVal(pick(SEL.data_limit_value), p.data_limit_value ?? 0);
  setVal(pick(SEL.data_limit_unit),  p.data_limit_unit || 'Mi');
  setChecked(pick(SEL.start_on_first_use), !!p.start_on_first_use);
  setChecked(pick(SEL.unlimited),          !!p.unlimited);
  setVal(pick(SEL.time_days),  p.time_limit_days ?? 0);
  setVal(pick(SEL.time_hours), p.time_limit_hours ?? 0);
}

function clearProfile() {
  setVal(pick(SEL.allowed_ips), '');
  setVal(pick(SEL.endpoint),    '');
  setVal(pick(SEL.dns),         '');
  setVal(pick(SEL.mtu),         '');
  setVal(pick(SEL.keepalive),   '');
  setVal(pick(SEL.data_limit_value), '');
  setVal(pick(SEL.data_limit_unit),  'Mi');
  setChecked(pick(SEL.start_on_first_use), false);
  setChecked(pick(SEL.unlimited),          false);
  setVal(pick(SEL.time_days),  '');
  setVal(pick(SEL.time_hours), '');
}

async function profileToggle() {
  const tog = q(pick(SEL.use_profile_toggle));
  const on  = !!tog?.checked;

  if (on) {
    if (!__profileSnapshot) __profileSnapshot = snapForm();
    const name = q(pick(SEL.profile_select))?.value || 'Default';
    const p = await loadProfile(name, /*force*/true);
    applyProfile(p);
  } else {
    if (__profileSnapshot) {
      restoreForm(__profileSnapshot);
      __profileSnapshot = null;
    }
  }
}

async function saveProfile(saveAsName = null) {
  const name = saveAsName || (q('#profile-select')?.value || 'Default');

  const payload = {
    name,  
    allowed_ips: getVal(pick(SEL.allowed_ips)),
    endpoint:    getVal(pick(SEL.endpoint)),
    dns:         getVal(pick(SEL.dns)),
    mtu:         numOrNull(getVal(pick(SEL.mtu))),
    persistent_keepalive: numOrNull(getVal(pick(SEL.keepalive))),
    data_limit_value: intOrZero(getVal(pick(SEL.data_limit_value))),
    data_limit_unit: getVal(pick(SEL.data_limit_unit)) || 'Mi',
    start_on_first_use: !!q(pick(SEL.start_on_first_use))?.checked,
    unlimited:          !!q(pick(SEL.unlimited))?.checked,
    time_limit_days:  intOrZero(getVal(pick(SEL.time_days))),
    time_limit_hours: intOrZero(getVal(pick(SEL.time_hours))),
  };

  const r = await fetch('/api/peer_profile', {
    method: 'POST',
    headers: Object.assign({'Content-Type':'application/json'}, window.csrfHeaders?.(true) || {}),
    credentials: 'same-origin',
    body: JSON.stringify(payload),
  });

  if (r.ok) {
    const j = await r.json().catch(() => ({}));
    __profileCache = (j.saved || payload);
    __profileCache.__name = name;
    await populateProfile(name);      
    toastSafe(`Profile “${name}” saved`, 'success');
  } else {
    toastSafe('Could not save profile', 'error');
  }
}

async function populateProfile(preselect = null) {
  const sel = q('#profile-select');
  if (!sel) return;
  try {
    const r = await fetch('/api/peer_profiles', { credentials: 'same-origin' });
    if (!r.ok) throw 0;
    const j = await r.json();
    const names  = (j.profiles && j.profiles.length) ? j.profiles : ['Default'];
    const active = j.active || 'Default';
    const chosen = preselect || sel.value || active;

    sel.innerHTML = names.map(n => {
      const star = (n === active) ? ' ★' : '';
      return `<option value="${n}" ${n === chosen ? 'selected' : ''}>${n}${star}</option>`;
    }).join('');

    await loadProfile(sel.value, /*force*/true);
  } catch (_) {
    sel.innerHTML = `<option value="Default" selected>Default</option>`;
  }
}

function closeProfileMenu(){ const m = q('#profile-menu'); if (m) m.style.display='none'; }
function openProfileMenu(){ const m = q('#profile-menu'); if (m) m.style.display='block'; }

async function prompt(title, def='') {
  if (typeof inputText === 'function') {
    return await inputText(title, def);
  }
  const v = window.prompt(title, def);
  return v == null ? null : v.trim();
}

async function profileAction(act){
  const sel = q('#profile-select');
  if (!sel) return;
  const current = sel.value || 'Default';

  if (act === 'new') {
    const name = await prompt('New profile name', '');
    if (!name) return;
    await saveProfile(name);            
    await populateProfile(name);
    toastSafe(`Profile “${name}” created`, 'success');
  }

  if (act === 'saveas') {
    const name = await prompt('Save current values as…', `${current}-copy`);
    if (!name) return;
    await saveProfile(name);
    await populateProfile(name);
    toastSafe(`Saved as “${name}”`, 'success');
  }

  if (act === 'activate') {
    const r = await fetch('/api/peer_profile/activate', {
      method: 'POST',
      headers: Object.assign({'Content-Type':'application/json'}, window.csrfHeaders?.(true) || {}),
      credentials: 'same-origin',
      body: JSON.stringify({ name: current })
    });
    if (r.ok) {
      await populateProfile(current);
      toastSafe(`“${current}” set active`, 'success');
    } else {
      toastSafe('Could not activate profile', 'error');
    }
  }

  if (act === 'rename') {
    const name = await prompt('Rename profile', current);
    if (!name || name === current) return;
    const r = await fetch('/api/peer_profile/rename', {
      method: 'POST',
      headers: Object.assign({'Content-Type':'application/json'}, window.csrfHeaders?.(true) || {}),
      credentials: 'same-origin',
      body: JSON.stringify({ old: current, new: name })
    });
    if (r.ok) {
      await populateProfile(name);
      toastSafe(`Renamed to “${name}”`, 'success');
    } else {
      const j = await r.json().catch(()=>({}));
      toastSafe(j.error || 'Rename failed', 'error');
    }
  }

  if (act === 'delete') {
    if (current === 'Default') {
      toastSafe('Cannot delete “Default”', 'error');
      return;
    }
    if (!(await confirmBox(`Delete profile “${current}”?`))) return;
    const r = await fetch(`/api/peer_profile?name=${encodeURIComponent(current)}`, {
      method: 'DELETE', credentials: 'same-origin'
    });
    if (r.ok) {
      await populateProfile('Default');
      toastSafe(`Deleted “${current}”`, 'success');
    } else {
      const j = await r.json().catch(()=>({}));
      toastSafe(j.error || 'Delete failed', 'error');
    }
  }
}


async function createPeerModal() {
  const togSel = pick(SEL.use_profile_toggle);
  const btnSel = pick(SEL.save_profile_btn);
  const selSel = pick(SEL.profile_select);
  const tog = q(togSel);
  const btn = q(btnSel);
  const sel = q(selSel);

  if (tog && !tog.__wired) { tog.addEventListener('change', profileToggle); tog.__wired = true; }
  if (btn && !btn.__wired) { btn.addEventListener('click', saveProfile);   btn.__wired = true; }

  if (sel && !sel.__wired) {
    sel.addEventListener('change', async () => {
      const name = sel.value || 'Default';
      const prof = await loadProfile(name, /*force*/true);
      if (q(togSel)?.checked) {
        applyProfile(prof);     
      }
      keepaliveMtu(prof);  
    });
    sel.__wired = true;
  }
  if (!window.__profile_menu_wired) {
  const btn = q('#profile-menu-btn');
  const menu = q('#profile-menu');
  if (btn && menu) {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const open = menu.style.display === 'block';
      if (open) closeProfileMenu(); else openProfileMenu();
    });
    menu.addEventListener('click', async (e) => {
      const b = e.target.closest('button[data-act]');
      if (!b) return;
      closeProfileMenu();
      await profileAction(b.dataset.act);
    });
    document.addEventListener('click', (e) => {
      if (!menu.contains(e.target) && e.target !== btn) closeProfileMenu();
    });
    window.__profile_menu_wired = true;
  }
}
  __profileSnapshot = null;

  await populateProfile();
  setChecked(togSel, false);

  const activeName = q(selSel)?.value || 'Default';
  const prof = await loadProfile(activeName);
  keepaliveMtu(prof);
}

window.createPeerModal = createPeerModal;


async function afterPeerCreated() {
  const tog = q(pick(SEL.use_profile_toggle));
  if (tog?.checked) {
    await saveProfile();
  }
}
window.afterPeerCreated = afterPeerCreated;
  function peerEsc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function toastSafe(msg, type = 'info', loading = false) {
    const kind = (type === 'warning' || type === 'warn') ? 'warn' : (type || 'info');
    let host = document.getElementById('peer-toast-box');
    if (!host) {
      host = document.createElement('div');
      host.id = 'peer-toast-box';
      document.body.appendChild(host);
    }

    const icon = kind === 'success' ? 'fa-circle-check'
      : kind === 'error' ? 'fa-circle-xmark'
      : kind === 'warn' ? 'fa-triangle-exclamation'
      : loading ? 'fa-circle-notch'
      : 'fa-circle-info';

    const ms = loading ? 0 : 2700;
    const t = document.createElement('div');
    t.className = `peer-toast ${kind}${loading ? ' is-loading' : ''}`;
    if (ms) t.style.setProperty('--toast-ms', `${ms}ms`);
    t.innerHTML = `
      <span class="peer-toast-icon"><i class="fas ${icon}"></i></span>
      <span class="peer-toast-msg">${peerEsc(msg)}</span>
      <button type="button" class="peer-toast-close" aria-label="Dismiss"><i class="fas fa-xmark"></i></button>
      <span class="peer-toast-progress"></span>
    `;

    let removed = false;
    const removeToast = () => {
      if (removed) return;
      removed = true;
      t.classList.remove('show');
      t.classList.add('hide');
      setTimeout(() => { try { t.remove(); } catch {} }, 220);
    };

    t.querySelector('.peer-toast-close')?.addEventListener('click', removeToast, { once:true });

    host.prepend(t);
    Array.from(host.querySelectorAll('.peer-toast')).slice(4).forEach(x => {
      try { x.remove(); } catch {}
    });
    requestAnimationFrame(() => t.classList.add('show'));
    if (ms) setTimeout(removeToast, ms + 80);

    t.remove = removeToast;
    return t;
  }

  async function copyTo(text) {
    try { if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); return true; } } catch {}
    try {
      const ta = document.createElement('textarea');
      ta.value = text; ta.setAttribute('readonly',''); ta.style.position = 'fixed'; ta.style.left = '-9999px';
      document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
      return true;
    } catch { return false; }
  }

function apiPath(p) {
  const nid = getScopeId();
  return nid ? `/api/nodes/${encodeURIComponent(nid)}${p}` : `/api${p}`;
}
function itStarted(p) {
  return !p.start_on_first_use || !!p.first_used_at_ts; 
}
function fmtDurShort(sec) {
  if (sec == null) return '–';
  sec = Math.max(0, Math.floor(sec));
  const d = Math.floor(sec / 86400); sec -= d * 86400;
  const h = Math.floor(sec / 3600);  sec -= h * 3600;
  const m = Math.floor(sec / 60);
  if (d > 0) return `${d}d${h ? ` ${h}h` : ''}`;
  if (h > 0) return `${h}h${m ? ` ${m}m` : ''}`;
  return `${m}m`;
}

function getScopeId() {
  const el = document.getElementById('peer-scope');
  const v = el && el.value;
  return (v && v !== 'local') ? v : '';
}

  const unitName = u => ({ Ki: 'KiB', Mi: 'MiB', Gi: 'GiB', Ti: 'TiB', Pi: 'PiB' }[u] || (u || ''));
  const toMiB = (v, u) => {
    const n = Number(v) || 0;
    if (u === 'Gi') return n * 1024;
    if (u === 'Mi') return n;
    return n;
  };
  const fmtAmountMiB = (mib, preferUnit) => {
    if (mib === Infinity) return 'Unlimited';
    if (!isFinite(mib))   return '–';
    const useGi = mib >= 1024 || preferUnit === 'Gi';
    if (useGi) {
      const x = mib / 1024;
      let s = x.toFixed(x >= 10 ? 1 : 2).replace(/\.0+$/, '').replace(/(\.\d*[1-9])0+$/, '$1');
      return `${s} GiB`;
    }
    return `${Math.max(0, Math.round(mib))} MiB`;
  };
  const fmtLimit = p => {
    if (p.unlimited) return 'Unlimited';
    if (p.data_limit !== null && p.data_limit !== undefined && p.data_limit !== '')
      return `${p.data_limit} ${unitName(p.limit_unit)}`.trim();
    return '–';
  };
  const usedBytes = p => {
  const live = Number(p.used_bytes) || 0;
  const snap = Number(p.used_bytes_db) || 0;
  return live || snap;
};
  const remainingMiB = p => {
  if (p.unlimited) return Infinity;

  const limMiB = toMiB(p.data_limit, p.limit_unit);

  if (!Number.isFinite(limMiB) || limMiB <= 0) {
    return 0;
  }

  const usedMiB = usedBytes(p) / 1048576;
  return Math.max(0, limMiB - usedMiB);
};

  const nowSec = () => Math.floor(Date.now() / 1000);
  const normEpoch = x => (x > 1e12 ? Math.floor(x / 1000) : Math.floor(x));
  function tsFrom(v) {
    if (v == null) return null;
    if (typeof v === 'number') return normEpoch(v);
    const s = String(v).trim();
    if (/^\d{10,13}$/.test(s)) return normEpoch(Number(s));
    const d = new Date(s);
    return isNaN(d) ? null : Math.floor(d.getTime() / 1000);
  }
  function fmtLocalTs(ts) {
    if (ts == null) return '–';
    const d = new Date(ts * 1000); const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }
  function leftTtl(ttl) {
    const s = Math.max(0, Math.floor(ttl || 0));
    return { total: s, days: Math.floor(s/86400), hours: Math.floor((s%86400)/3600), minutes: Math.floor((s%3600)/60), seconds: s%60 };
  }
  function prettyTtl(ttl) {
    const p = leftTtl(ttl);
    if (p.total === 0) return 'expired';
    if (p.days  > 0)   return `${p.days}d ${p.hours}h`;
    if (p.hours > 0)   return `${p.hours}h ${p.minutes}m`;
    return `${Math.max(1, p.minutes)}m ${p.seconds}s`;
  }
  function timeLimitCapSeconds(p) {
    const d = Number(p.time_limit_days ?? p.time_days ?? 0) || 0;
    const h = Number(p.time_limit_hours ?? p.time_hours ?? 0) || 0;
    const m = Number(p.time_limit_minutes ?? p.time_minutes ?? 0) || 0;
    return Math.max(0, Math.floor(d * 86400 + h * 3600 + m * 60));
  }

  function fmtCapDuration(sec) {
    sec = Math.max(0, Math.floor(Number(sec) || 0));
    if (!sec) return '';
    const d = Math.floor(sec / 86400);
    const h = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const parts = [];
    if (d) parts.push(`${d}d`);
    if (h) parts.push(`${h}h`);
    if (!d && !h && m) parts.push(`${m}m`);
    return parts.join(' ');
  }

  function timeBadge(p) {
    if (p.unlimited) return 'Unlimited';

    const started = itStarted(p);
    const capSec = timeLimitCapSeconds(p);
    const capTxt = fmtCapDuration(capSec);
    let ttl = null;

    if (started) {
      if (p.ttl_seconds != null && p.ttl_seconds !== '') {
        ttl = Number(p.ttl_seconds);
      } else if (p.expires_at_ts != null && p.expires_at_ts !== '') {
        ttl = Math.max(0, Number(p.expires_at_ts) - nowSec());
      } else if (p.expires_at) {
        const ts = tsFrom(p.expires_at);
        ttl = ts ? Math.max(0, ts - nowSec()) : null;
      }
    }

    if (!started) {
      return capTxt ? `Starts on use · ${capTxt}` : 'Starts on use';
    }

    if (ttl == null || !Number.isFinite(ttl)) {
      const remMiB = remainingMiB(p);
      const looksTimeBlocked = isBlocked(p) && (capSec > 0 || (Number.isFinite(remMiB) && remMiB > 1));
      if (looksTimeBlocked) return 'Expired';
      return capTxt ? `${capTxt} cap` : 'No timer';
    }

    if (ttl <= 0 || (isBlocked(p) && capSec > 0 && Number(ttl) === 0)) return 'Expired';
    const d = Math.floor(ttl / 86400);
    const h = Math.floor((ttl % 86400) / 3600);
    const m = Math.floor((ttl % 3600) / 60);
    if (d > 0) return `${d}d ${h}h left`;
    if (h > 0) return `${h}h ${m}m left`;
    return `${Math.max(1, m)}m left`;
  }

  function endpointDisplay(p) {
    if (p.endpoint && p.endpoint.trim()) return p.endpoint;
    if (p.server_public_ip && p.listen_port) return `${p.server_public_ip}:${p.listen_port}`;
    return '';
  }
  function getEndpoint(v) {
    v = (v || '').trim(); if (!v) return null;
    if (v.startsWith('[')) {
      const m = /^\[([^\]]+)\](?::(\d+))?$/.exec(v);
      if (!m) return null;
      return { host: m[1], port: m[2] ? parseInt(m[2], 10) : null };
    }
    let host = '', port = '';
    if (v.includes(':')) { const parts = v.split(':'); host = parts.slice(0, -1).join(':'); port = parts.slice(-1)[0]; }
    else host = v;
    if (port && !/^\d+$/.test(port)) return null;
    return { host, port: port ? parseInt(port, 10) : null };
  }

  let endpointPresets = [];

async function getPresets() {
  try {
    const r = await fetch(api('/api/endpoint_presets'), { credentials: 'same-origin' });
    if (!r.ok) return;
    const j = await r.json();
    endpointPresets = j.presets || [];
    document.dispatchEvent(new CustomEvent('endpoint-presets-updated', { detail: endpointPresets }));
  } catch {}
}

  function inputText(message, defText = '') {
    return new Promise(resolve => {
      const modal = document.createElement('div'); modal.className = 'modal open';
      modal.innerHTML = `
        <div class="modal-content" style="max-width:420px">
          <h3 style="margin:0 0 .5rem 0">${message}</h3>
          <input id="dlg-input" class="input" placeholder="${defText.replace(/"/g, '&quot;')}" style="width:100%;margin:.25rem 0 .75rem 0">
          <div style="display:flex;gap:8px;justify-content:flex-end">
            <button id="dlg-cancel" class="btn secondary">Cancel</button>
            <button id="dlg-ok" class="btn">OK</button>
          </div>
        </div>`;
      document.body.appendChild(modal);
      const inp = modal.querySelector('#dlg-input');
      const ok  = modal.querySelector('#dlg-ok');
      const no  = modal.querySelector('#dlg-cancel');
      const close = v => { modal.classList.remove('open'); setTimeout(() => modal.remove(), 120); resolve(v); };
      ok.onclick = () => close((inp.value || '').trim() || defText);
      no.onclick = () => close(null);
      modal.addEventListener('click', e => { if (e.target === modal) close(null); });
      setTimeout(() => inp && inp.focus(), 10);
    });
  }
  
  function attachEndpoint(modalEl) {
    if (!modalEl) return;
    const input = modalEl.querySelector('input[name="endpoint"], #bulk-endpoint');
    if (!input || input.dataset.enhanced === '1') return;
    input.dataset.enhanced = '1';

    const row = document.createElement('div');
    row.className = 'ep-row';
    row.innerHTML = `
      <select id="ep-saved" class="input" style="flex:1 1 320px; min-width:240px">
        <option value="">Saved endpoints…</option>
      </select>
      <button type="button" class="btn secondary" id="ep-save" title="Save current"><i class="fas fa-save"></i></button>
      <button type="button" class="btn secondary" id="ep-apply" title="Apply selected"><i class="fas fa-clipboard-check"></i></button>
      <button type="button" class="btn secondary" id="ep-del" title="Delete selected"><i class="fas fa-trash"></i></button>`;
    input.parentElement.appendChild(row);


    const fire = () => { input.dispatchEvent(new Event('input', { bubbles: true })); input.dispatchEvent(new Event('change', { bubbles: true })); };

    row.querySelector('#ep-save').addEventListener('click', async () => {
      const parsed = getEndpoint(input.value);
      if (!parsed || !parsed.host || !parsed.port) { toastSafe('Use host:port to save', 'error'); return; }
      const def = `${parsed.host}:${parsed.port}`;
      const label = await inputText('Label for this endpoint', def);
      if (label === null) return;
      try {
        const r = await fetch(api('/api/endpoint_presets'), {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
          body: JSON.stringify({ host: parsed.host, port: parsed.port, label })
        });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const j = await r.json(); endpointPresets = j.presets || [];
        refreshSavedOptions(); toastSafe('Saved', 'success');
      } catch { toastSafe('Save failed', 'error'); }
    });
  function refreshSavedOptions() {
  const sel = row.querySelector('#ep-saved');
  const opts = (endpointPresets || []).map((p, idx) =>
    `<option value="${idx}">${(p.label || `${p.host}:${p.port}`)} (${p.host}:${p.port})</option>`).join('');
  sel.innerHTML = `<option value="">Saved endpoints…</option>${opts}`;
}
refreshSavedOptions();

document.addEventListener('endpoint-presets-updated', refreshSavedOptions);

    row.querySelector('#ep-apply').addEventListener('click', () => {
      const sel = row.querySelector('#ep-saved'); if (!sel.value) return;
      const p = endpointPresets[parseInt(sel.value, 10)]; if (!p) return;
      input.value = `${p.host}:${p.port}`; fire();
    });

    row.querySelector('#ep-del').addEventListener('click', async () => {
      const sel = row.querySelector('#ep-saved'); if (!sel.value) { toastSafe('Pick a saved endpoint', 'error'); return; }
      const p = endpointPresets[parseInt(sel.value, 10)]; if (!p) return;
      const name = p.label || (p.host + ':' + p.port);
      if (!(await confirmBoxIn(modalEl, `Delete endpoint preset “${name}”?`))) return;
      try {
        const r = await fetch(api('/api/endpoint_presets'), {
          method: 'DELETE', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
          body: JSON.stringify({ host: p.host, port: p.port })
        });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const j = await r.json(); endpointPresets = j.presets || [];
        refreshSavedOptions(); sel.value = ''; toastSafe('Deleted', 'success');
      } catch { toastSafe('Delete failed', 'error'); }
    });
  }
const openMore = new Set();

function closeSections(exceptId = null) {
  document.querySelectorAll('.peer-card').forEach(card => {
    const id = String(card.dataset.id || '');
    if (!id) return;
    if (exceptId != null && String(exceptId) == id) return;

    const sec = card.querySelector('.peer-more-section');
    if (sec && !sec.hidden) sec.hidden = true;

    const btn = card.querySelector('.more-toggle');
    if (btn) btn.setAttribute('aria-expanded', 'false');

    openMore.delete(id);
  });
}
function wireContainedSelect(select) {
  if (!select || select.dataset.containedSelect === '1') return;
  select.dataset.containedSelect = '1';

  const collapse = () => {
    select.size = 1;
    select.classList.remove('is-expanded');
  };

  const expand = () => {
    const count = Math.max(1, Math.min(select.options.length || 1, 8));
    select.size = count;
    select.classList.add('is-expanded');
  };

  select.addEventListener('mousedown', e => {
    if (select.size > 1) return;
    e.preventDefault();
    expand();
    select.focus({ preventScroll: true });
  });

  select.addEventListener('focus', () => {
    if (select.matches(':hover')) expand();
  });

  select.addEventListener('change', () => {
    collapse();
    const hiddenAddr = document.getElementById('create-address');
    if (select.id === 'create-address-select' && hiddenAddr) {
      hiddenAddr.value = select.value || '';
    }
  });

  select.addEventListener('blur', collapse);
  select.addEventListener('keydown', e => {
    if (e.key === 'Escape' || e.key === 'Enter') collapse();
  });
}

function wireContainedPickers() {
  wireContainedSelect(document.querySelector('#peer-modal #create-address-select'));
  wireContainedSelect(document.querySelector('#bulk-modal #bulk-iface'));
}

function peerDetailInner(icon, label, value) {
  return `
    <span class="peer-detail-icon"><i class="fas fa-${icon}" aria-hidden="true"></i></span>
    <span class="peer-detail-copy">
      <span class="peer-detail-label">${label}</span>
      <span class="peer-detail-value">${value}</span>
    </span>`;
}

function peerDetailItem(cls, icon, label, value) {
  return `<div class="peer-detail-item ${cls}">${peerDetailInner(icon, label, value)}</div>`;
}

function peerProgressBar(p, ttl, started) {
  if (p.unlimited) return '';

  const limitMiB = toMiB(p.data_limit, p.limit_unit);
  const remainMiB = remainingMiB(p);
  const dataPct = Number.isFinite(limitMiB) && limitMiB > 0
    ? Math.max(0, Math.min(100, (remainMiB / limitMiB) * 100))
    : 0;

  let timePct = null;
  const totalSec = timeLimitCapSeconds(p);
  if (started && Number.isFinite(ttl) && totalSec > 0) {
    timePct = Math.max(0, Math.min(100, (ttl / totalSec) * 100));
  }

  return `
    <div class="peer-more-bars" aria-label="Peer limits">
      <div class="peer-limit-bar">
        <span>Data remaining</span>
        <div class="bar"><i class="data-bar" style="width:${dataPct.toFixed(1)}%"></i></div>
        <b>${dataPct.toFixed(0)}%</b>
      </div>
      <div class="peer-limit-bar time-progress">
        <span>Time remaining</span>
        <div class="bar"><i class="time-bar" style="width:${timePct == null ? 0 : timePct.toFixed(1)}%"></i></div>
        <b>${timePct == null ? '—' : `${timePct.toFixed(0)}%`}</b>
      </div>
    </div>`;
}

function cardHTML(p, i) {
  const limitStr   = fmtLimit(p);
  const remainStr  = p.unlimited ? 'Unlimited' : fmtAmountMiB(remainingMiB(p), p.limit_unit);
  const timerStr   = timeBadge(p);
  const epStr      = endpointDisplay(p);

  const first      = (p.first_used_at_ts != null) ? fmtLocalTs(p.first_used_at_ts)
                   : (p.first_used_at ? fmtLocalTs(tsFrom(p.first_used_at)) : '–');
  const created    = (p.created_at_ts != null) ? fmtLocalTs(p.created_at_ts)
                   : (p.created_at ? fmtLocalTs(tsFrom(p.created_at)) : '–');

  const expTs      = (p.expires_at_ts != null) ? p.expires_at_ts : tsFrom(p.expires_at);
  const exp        = expTs ? fmtLocalTs(expTs) : '–';
  const ttl        = (p.ttl_seconds != null) ? p.ttl_seconds : (expTs ? Math.max(0, expTs - nowSec()) : null);
  const remainTime = p.unlimited ? 'Unlimited' : (ttl != null ? prettyTtl(ttl) : '–');

  const totalBytes = (Number(p.used_bytes) || 0) + (Number(p.used_bytes_db) || 0);
  const totalMiB   = Math.round(totalBytes / 1048576);
  const totalStr   = fmtAmountMiB(totalMiB, 'Mi');

  const started    = (!p.start_on_first_use) || (p.first_used_at_ts != null) || (!!p.first_used_at);
  const capLabel   = started ? 'Active time cap' : 'Time cap';
  const capTail    = (!started && p.start_on_first_use) ? ' (starts on first use)' : '';

  const isOpen     = openMore.has(String(p.id));

  const cStatus    = connStatus(p);
  const pStatus    = panelStatus(p);
  const depleted   = isDepleting(p);
  const blocked    = isBlocked(p);
  const pKey       = peerEsc(peerKey(p) ?? p.id ?? p.public_key ?? '');

  return `
  <div class="peer-card"
       data-id="${pKey}"
       data-status="${cStatus}"
       data-panel-status="${pStatus}"
       data-blocked="${blocked ? '1' : '0'}"
       data-depleting="${depleted ? '1' : '0'}"
       data-name="${(p.name||'').toLowerCase()}"
       data-phone="${(p.phone_number||'').toLowerCase()}"
       data-tg="${(p.telegram_id||'').toLowerCase()}"
       data-iface="${p.iface || ''}">

    <div class="peer-main peer-main-nowrap">
      <span class="peer-index">${i + 1})</span>
      <span class="peer-name truncate">${p.name || ''}</span>

      <div class="peer-tags">
        ${peerTagsHTML(p)}
      </div>

      <div class="peer-traffic">
        <i class="fas fa-download"></i> <span class="rx">${String(p.rx || '0')}</span> MB |
        <i class="fas fa-upload"></i> <span class="tx">${String(p.tx || '0')}</span> MB
      </div>

      <div class="peer-ip">
        <i class="fas fa-network-wired"></i>
        <span class="address truncate">${p.address || ''}</span>
        <span class="endpoint-wrap"${epStr ? '' : ' style="display:none"'}> /
          <i class="fas fa-globe"></i> <span class="endpoint truncate">${epStr}</span>
        </span>
      </div>

      <div class="peer-data chip" title="Remaining / Limit">
        <i class="fas fa-database"></i>
        <span class="data-remaining truncate">${remainStr}</span>
        <span>&nbsp;/&nbsp;</span>
        <span class="data-limit truncate">${limitStr}</span>
      </div>

      <div class="peer-timer chip" title="Time status">
        <i class="fas fa-clock"></i>
        <span class="timer-text truncate">${timerStr}</span>
      </div>

      <div class="peer-info-wrap" data-id="${pKey}">
        <button
          type="button"
          class="more-toggle icon-only"
          data-id="${pKey}"
          title="More information"
          aria-label="More information"
          aria-expanded="${isOpen ? 'true' : 'false'}"
        >
          <i class="fas fa-info-circle" aria-hidden="true"></i>
          <span class="sr-only">More information</span>
        </button>
      </div>
    </div>

    <div class="peer-more-section" ${isOpen ? '' : 'hidden'}>
      <div class="peer-more-hdr">
        <div class="peer-more-title"><i class="fas fa-info-circle" aria-hidden="true"></i> More information</div>
        <button type="button" class="more-close icon-only" data-id="${pKey}" title="Close" aria-label="Close">
          <i class="fas fa-times" aria-hidden="true"></i>
        </button>
      </div>

      ${peerProgressBar(p, ttl, started)}

      <div class="peer-more-grid">
        ${peerDetailItem('mi-limit', 'database', 'Limit', limitStr)}
        ${peerDetailItem('mi-remain', 'hourglass-half', 'Time remaining', remainTime)}
        ${peerDetailItem('mi-days', 'calendar-alt', capLabel, `${fmtDaysOrHours(p.time_limit_days)}${capTail}`)}
        ${peerDetailItem('mi-first', 'play-circle', 'First used', first)}
        ${peerDetailItem('mi-created', 'calendar-plus', 'Created', created)}
        ${peerDetailItem('mi-exp', 'calendar-times', 'Expires', exp)}
        ${peerDetailItem('mi-total', 'exchange-alt', 'Total usage', totalStr)}
        ${peerDetailItem('mi-phone', 'phone', 'Phone', p.phone_number || '–')}
        ${peerDetailItem('mi-tg', 'paper-plane', 'Telegram', p.telegram_id || '–')}
        ${peerDetailItem('mi-iface', 'network-wired', 'Interface', `<span class="mi-iface-name">${p.iface || '–'}</span>`)}
      </div>
    </div>

    <div class="peer-actions-row">
      <div class="peer-actions peer-action-dock" style="display:flex; gap:.45em; padding:0; width:100%; justify-content:flex-end;">
        <button class="edit-btn"        title="Edit"                 data-id="${pKey}"><i class="fas fa-edit"></i></button>
        <button class="logs-btn"        title="Logs"                 data-id="${pKey}"><i class="fas fa-list"></i></button>
        <button class="download-btn"    title="Download config"      data-id="${pKey}"><i class="fas fa-download"></i></button>
        <button class="qr-btn"          title="Show QR & download"   data-id="${pKey}"><i class="fas fa-qrcode"></i></button>
        <button class="user-link-btn"   title="User link: click to copy, Ctrl/⌘ or middle-click to open" data-id="${pKey}"><i class="fas fa-link"></i></button>
        <button class="enable-btn"      title="Enable"               data-id="${pKey}" style="${pStatus==='online' ? 'display:none' : ''}"><i class="fas fa-play"></i></button>
        <button class="disable-btn"     title="Disable"              data-id="${pKey}" style="${pStatus==='online' ? '' : 'display:none'}"><i class="fas fa-ban"></i></button>
        <button class="reset-data-btn"  title="Reset data"           data-id="${pKey}"><i class="fas fa-tachometer-alt"></i></button>
        <button class="reset-timer-btn" title="Reset timer"          data-id="${pKey}"><i class="fas fa-history"></i></button>
        <button class="delete-btn"      title="Delete"               data-id="${pKey}"><i class="fas fa-trash"></i></button>
      </div>
    </div>

  </div>`;
}

  function hover(card) {
  // Hover is now controlled by CSS ..
  if (card.dataset.enhancedToolbar === '1') return;
  card.dataset.enhancedToolbar = '1';
}

function updateCard(card, p, i) {
  const cStatus  = connStatus(p);
  const pStatus  = panelStatus(p);
  const depleted = isDepleting(p);
  const blocked  = isBlocked(p);

  card.dataset.status = cStatus;
  card.dataset.panelStatus = pStatus;
  card.dataset.blocked = blocked ? '1' : '0';
  card.dataset.depleting = depleted ? '1' : '0';
  card.dataset.name   = (p.name || '').toLowerCase();
  card.dataset.phone  = (p.phone_number || '').toLowerCase();
  card.dataset.tg     = (p.telegram_id || '').toLowerCase();
  card.dataset.iface  = p.iface || '';

  const set = (sel, txt) => { const el = card.querySelector(sel); if (el) el.textContent = txt; };
  const setHTML = (sel, html) => { const el = card.querySelector(sel); if (el) el.innerHTML = html; };
  const started = (!p.start_on_first_use) || !!p.first_used_at_ts;

  set('.peer-index', `${i + 1})`);
  set('.peer-name', p.name || '');

  const tagsEl = card.querySelector('.peer-tags');
  if (tagsEl) tagsEl.innerHTML = peerTagsHTML(p);

  set('.peer-traffic .rx', String(p.rx || '0'));
  set('.peer-traffic .tx', String(p.tx || '0'));
  set('.peer-ip .address', p.address || '');

  const epStr = endpointDisplay(p);
  const wrap  = card.querySelector('.peer-ip .endpoint-wrap');
  if (wrap) {
    if (epStr) {
      wrap.style.removeProperty('display');
      set('.peer-ip .endpoint', epStr);
    } else {
      wrap.style.display = 'none';
    }
  }

  const remMiB = remainingMiB(p);
  set('.peer-data .data-remaining', p.unlimited ? 'Unlimited' : fmtAmountMiB(remMiB, p.limit_unit));
  set('.peer-data .data-limit', fmtLimit(p));
  set('.peer-timer .timer-text', timeBadge(p));

  const en = card.querySelector('.enable-btn');
  const di = card.querySelector('.disable-btn');
  if (en && di) {
    if (pStatus === 'online') {
      en.style.display = 'none';
      di.style.display = 'inline-flex';
    } else {
      en.style.display = 'inline-flex';
      di.style.display = 'none';
    }
  }

  const first = (p.first_used_at_ts != null)
      ? fmtLocalTs(p.first_used_at_ts)
      : (p.start_on_first_use ? '—' : 'n/a');

  const created = (p.created_at_ts != null)
      ? fmtLocalTs(p.created_at_ts)
      : (p.created_at ? fmtLocalTs(tsFrom(p.created_at)) : '—');

  const expTs = (p.expires_at_ts != null) ? p.expires_at_ts : tsFrom(p.expires_at);
  const ttl   = started
      ? ((p.ttl_seconds != null) ? Number(p.ttl_seconds)
         : (expTs ? Math.max(0, expTs - nowSec()) : null))
      : null;

  const exp   = (started && expTs) ? fmtLocalTs(expTs) : '—';
  const remainTime = p.unlimited ? 'Unlimited' : (started && ttl != null ? prettyTtl(ttl) : '—');

  const totalBytes = (Number(p.used_bytes) || 0) + (Number(p.used_bytes_db) || 0);
  const totalMiB   = Math.round(totalBytes / 1048576);
  const totalStr   = fmtAmountMiB(totalMiB, 'Mi');

  const capDays = (p.time_limit_days != null) ? p.time_limit_days : null;
  const capLabel = started ? 'Active time cap' : 'Time cap';
  const capTail  = (!started && p.start_on_first_use) ? ' (starts on first use)' : '';
  const capStr   = (capDays != null) ? fmtDaysOrHours(capDays) : '–';

  setHTML('.mi-limit',   peerDetailInner('database', 'Limit', fmtLimit(p)));
  setHTML('.mi-days',    peerDetailInner('calendar-alt', capLabel, `${capStr}${capTail}`));
  setHTML('.mi-first',   peerDetailInner('play-circle', 'First used', first));
  setHTML('.mi-created', peerDetailInner('calendar-plus', 'Created', created));
  setHTML('.mi-exp',     peerDetailInner('calendar-times', 'Expires', exp));
  setHTML('.mi-remain',  peerDetailInner('hourglass-half', 'Time remaining', remainTime));
  setHTML('.mi-total',   peerDetailInner('exchange-alt', 'Total usage', totalStr));
  setHTML('.mi-phone',   peerDetailInner('phone', 'Phone', p.phone_number || '–'));
  setHTML('.mi-tg',      peerDetailInner('paper-plane', 'Telegram', p.telegram_id || '–'));
  setHTML('.mi-iface',   peerDetailInner('network-wired', 'Interface', `<span class="mi-iface-name">${p.iface || '–'}</span>`));

  const totalSec = timeLimitCapSeconds(p);
  const timePct = started && Number.isFinite(ttl) && totalSec > 0
    ? Math.max(0, Math.min(100, (ttl / totalSec) * 100))
    : null;
  const timeBar = card.querySelector('.time-bar');
  const timeText = card.querySelector('.time-progress b');
  if (timeBar) timeBar.style.width = `${timePct == null ? 0 : timePct.toFixed(1)}%`;
  if (timeText) timeText.textContent = timePct == null ? '—' : `${timePct.toFixed(0)}%`;
  const dataBar = card.querySelector('.data-bar');
  const dataText = card.querySelector('.peer-limit-bar:first-child b');
  if (dataBar || dataText) {
    const limitMiB = toMiB(p.data_limit, p.limit_unit);
    const remainMiB = remainingMiB(p);
    const pct = Number.isFinite(limitMiB) && limitMiB > 0
      ? Math.max(0, Math.min(100, (remainMiB / limitMiB) * 100))
      : 0;
    if (dataBar) dataBar.style.width = `${pct.toFixed(1)}%`;
    if (dataText) dataText.textContent = `${pct.toFixed(0)}%`;
  }

  const more = card.querySelector('.peer-more-section');
  const moreBtn = card.querySelector('.more-toggle');
  const isOpen = openMore.has(String(p.id));
  if (more) more.hidden = !isOpen;
  if (moreBtn) moreBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');

  hover(card);
}
function peerTagCounts(peers) {
  const out = {
    total: 0,
    online: 0,
    offline: 0,
    enabled: 0,
    disabled: 0,
    blocked: 0,
    depleting: 0
  };

  for (const p of peers || []) {
    out.total += 1;

    const c = connStatus(p);
    const ps = panelStatus(p);

    if (c === 'online') out.online += 1;
    else out.offline += 1;

    if (ps === 'online') out.enabled += 1;
    else out.disabled += 1;

    if (ps === 'blocked') out.blocked += 1;
    if (isDepleting(p)) out.depleting += 1;
  }

  return out;
}

function ensurePeerSummary() {
  let box = document.getElementById('peer-tag-summary');
  if (box) return box;

  box = document.createElement('div');
  box.id = 'peer-tag-summary';
  box.className = 'peer-summary-card';
  box.innerHTML = `
  <div class="peer-summary-head">
    <div class="peer-summary-title">
      <span class="peer-summary-icon"><i class="fas fa-chart-pie" aria-hidden="true"></i></span>
      <div>
        <strong>Peer summary</strong>
        <small><b id="sum-total-head">0</b> peers · click a status to filter</small>
      </div>
    </div>
    <div class="peer-summary-live"><span></span> Live status</div>
  </div>

  <div class="peer-summary-grid">
    <button type="button" class="summary-stat online" data-summary-filter="online" title="Real connection status: recent WireGuard handshake">
      <span class="stat-ico"><i class="fas fa-signal" aria-hidden="true"></i></span>
      <span class="stat-copy"><b id="sum-online">0</b><small>Connected</small></span>
    </button>

    <button type="button" class="summary-stat offline" data-summary-filter="offline" title="Real connection status: no recent WireGuard handshake">
      <span class="stat-ico"><i class="fas fa-times-circle" aria-hidden="true"></i></span>
      <span class="stat-copy"><b id="sum-offline">0</b><small>Not connected</small></span>
    </button>

    <button type="button" class="summary-stat enabled" data-summary-filter="enabled" title="Panel state: enabled">
      <span class="stat-ico"><i class="fas fa-toggle-on" aria-hidden="true"></i></span>
      <span class="stat-copy"><b id="sum-enabled">0</b><small>Allowed</small></span>
    </button>

    <button type="button" class="summary-stat disabled" data-summary-filter="disabled" title="Panel state: disabled">
      <span class="stat-ico"><i class="fas fa-toggle-off" aria-hidden="true"></i></span>
      <span class="stat-copy"><b id="sum-disabled">0</b><small>Paused</small></span>
    </button>

    <button type="button" class="summary-stat depleting" data-summary-filter="depleting" title="Low data or time remaining">
      <span class="stat-ico"><i class="fas fa-hourglass-half" aria-hidden="true"></i></span>
      <span class="stat-copy"><b id="sum-depleting">0</b><small>Low quota</small></span>
    </button>

    <button type="button" class="summary-stat blocked" data-summary-filter="blocked" title="Blocked, expired, or data limit reached">
      <span class="stat-ico"><i class="fas fa-ban" aria-hidden="true"></i></span>
      <span class="stat-copy"><b id="sum-blocked">0</b><small>Blocked</small></span>
    </button>
  </div>
`;

  const filtersBox = document.querySelector('.peer-filters');
  const list = document.querySelector('.peers-container');

  if (filtersBox) {
    filtersBox.before(box);
  } else if (list) {
    list.before(box);
  }

  box.addEventListener('click', e => {
    const pill = e.target.closest('[data-summary-filter]');
    if (!pill) return;

    const val = pill.getAttribute('data-summary-filter') || '';
    filters.status = val;
    saveFilters();

    const sel = document.getElementById('peer-filter-status');
    if (sel) sel.value = val;

    pagination.page = 1;
    savePagination();
    applyPagi();
  });

  return box;
}

function renderPeerSummary(peers) {
  const box = ensurePeerSummary();
  if (!box) return;

  const c = peerTagCounts(peers || []);

  const set = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = String(val ?? 0);
  };

  set('sum-total', c.total);
  set('sum-total-head', c.total);
  set('sum-online', c.online);
  set('sum-offline', c.offline);
  set('sum-enabled', c.enabled);
  set('sum-disabled', c.disabled);
  set('sum-depleting', c.depleting);
  set('sum-blocked', c.blocked);

  const active = String(filters.status || '');
  box.querySelectorAll('[data-summary-filter]').forEach(el => {
    el.classList.toggle('is-active', (el.getAttribute('data-summary-filter') || '') === active);
  });
}
const filters = { q: '', status: '' };
const pagination = { page: 1, pageSize: 8 };

function loadFilters() {
  try {
    const s = JSON.parse(localStorage.getItem('peer_filters') || '{}');
    if (typeof s.q === 'string') filters.q = s.q;
    if (typeof s.status === 'string') filters.status = s.status;
  } catch {}
}

function saveFilters() {
  localStorage.setItem('peer_filters', JSON.stringify(filters));
}

function loadPagination() {
  try {
    const s = JSON.parse(localStorage.getItem('peer_pagination') || '{}');
    if (Number.isInteger(s.page)) pagination.page = s.page;
    if (Number.isInteger(s.pageSize)) pagination.pageSize = s.pageSize;
  } catch {}
  if (![5, 8, 12, 20, 50].includes(Number(pagination.pageSize))) pagination.pageSize = 8;
}

function savePagination() {
  localStorage.setItem('peer_pagination', JSON.stringify(pagination));
}

function buildFilters() {
  let host = $('.peer-filters');
  if (!host) {
    host = document.createElement('div');
    host.className = 'peer-filters';
    host.innerHTML = `
      <div style="display:flex; gap:8px; align-items:center; margin:10px 0; flex-wrap:wrap;">
        <input id="peer-filter-q" class="input" placeholder="Search name, phone, @telegram" style="flex:1 1 420px; min-width:260px;">

        <select id="peer-filter-status" class="input" style="width:190px;">
        <option value="">All tags</option>
        <option value="online">Online</option>
        <option value="offline">Offline</option>
        <option value="enabled">Enabled</option>
        <option value="disabled">Disabled</option>
        <option value="depleting">Depleting</option>
        <option value="blocked">Blocked</option>
        </select>

        <label style="display:flex; align-items:center; gap:6px;">
          <span>Page size</span>
          <select id="peer-page-size" class="input" style="width:90px;">
            <option value="10">10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
        </label>

        <button id="peer-filter-clear" class="btn secondary">Clear</button>
      </div>`;

    const list = $('.peers-container');
    if (list) list.before(host);
  }

  const q = $('#peer-filter-q', host);
  const s = $('#peer-filter-status', host);
  const c = $('#peer-filter-clear', host);
  const ps = $('#peer-page-size', host);

  q.value = filters.q || '';
  s.value = filters.status || '';
  ps.value = String(pagination.pageSize);

  q.addEventListener('input', debounce(() => {
    filters.q = q.value.trim().toLowerCase();
    saveFilters();
    pagination.page = 1;
    savePagination();
    applyPagi();
  }, 150));

  s.addEventListener('change', () => {
    filters.status = s.value;
    saveFilters();
    pagination.page = 1;
    savePagination();
    applyPagi();
  });

  c.addEventListener('click', () => {
    filters.q = '';
    filters.status = '';
    q.value = '';
    s.value = '';
    saveFilters();
    pagination.page = 1;
    savePagination();
    applyPagi();
  });

  ps.addEventListener('change', () => {
    pagination.pageSize = parseInt(ps.value, 10) || 10;
    pagination.page = 1;
    savePagination();
    applyPagi();
  });
}

function matchPeer(card) {
  if (SELECTED_IFACE_NAME) {
    const name = card.querySelector('.mi-iface-name')?.textContent || card.dataset.iface || '';
    if (name !== SELECTED_IFACE_NAME) return false;
  }

  const st = filters.status;
  const status = card.dataset.status;
  const panel = card.dataset.panelStatus;

  const statusOK =
    !st ||
    (st === 'online' && status === 'online') ||
    (st === 'offline' && status === 'offline') ||
    (st === 'depleting' && card.dataset.depleting === '1') ||
    (st === 'blocked' && card.dataset.blocked === '1') ||
    (st === 'enabled' && panel === 'online') ||
    (st === 'disabled' && panel !== 'online');

  if (!statusOK) return false;

  const q = filters.q;
  if (!q) return true;

  const name = card.dataset.name || '';
  const phone = card.dataset.phone || '';
  const tg = card.dataset.tg || '';

  return name.includes(q) || phone.includes(q) || tg.includes(q);
}

  function applyPagi() {
    const cont = $('.peers-container'); if (!cont) return;
    const cards = $$('.peer-card', cont);
    for (const c of cards) c.dataset._match = matchPeer(c) ? '1' : '0';
    const filtered = cards.filter(c => c.dataset._match === '1');
    const total = Math.max(1, Math.ceil(filtered.length / pagination.pageSize));
    if (pagination.page > total) { pagination.page = total; savePagination(); }
    const start = (pagination.page - 1) * pagination.pageSize, end = start + pagination.pageSize;
    filtered.forEach((c, idx) => { c.style.display = (idx >= start && idx < end) ? '' : 'none'; });
    cards.forEach(c => { if (c.dataset._match === '0') c.style.display = 'none'; });
    renderPager(total);
  }

  function renderPager(total) {
  let bar = $('#peer-pagination');

  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'peer-pagination';
    bar.className = 'peerx-pagination subx-pagination';

    const list = $('.peers-container');
    if (list) list.after(bar);

    bar.addEventListener('click', e => {
      const b = e.target.closest('button');
      if (!b) return;

      const maxPage = parseInt(bar.dataset.total || '1', 10) || 1;
      const nav = b.dataset.nav || '';

      if (nav === 'first') pagination.page = 1;
      else if (nav === 'prev') pagination.page = Math.max(1, pagination.page - 1);
      else if (nav === 'next') pagination.page = Math.min(maxPage, pagination.page + 1);
      else if (nav === 'last') pagination.page = maxPage;
      else return;

      savePagination();
      applyPagi();
    });

    bar.addEventListener('change', e => {
      const size = e.target.closest('#peer-page-size-pager');
      if (!size) return;

      pagination.pageSize = parseInt(size.value, 10) || 8;
      if (![5, 8, 12, 20, 50].includes(Number(pagination.pageSize))) pagination.pageSize = 8;
      pagination.page = 1;
      const oldTop = document.querySelector('.peer-filters #peer-page-size');
      if (oldTop) oldTop.value = String(pagination.pageSize);
      savePagination();
      applyPagi();
    });
  } else {
    bar.className = 'peerx-pagination subx-pagination';
  }

  const cur = Math.max(1, Math.min(total, pagination.page));
  pagination.page = cur;
  bar.dataset.total = String(total);

  const cards = $$('.peer-card', $('.peers-container') || document);
  const matched = cards.filter(c => c.dataset._match === '1').length;
  const from = matched ? ((cur - 1) * pagination.pageSize) + 1 : 0;
  const to = Math.min(matched, cur * pagination.pageSize);

  const sizeOptions = [5, 8, 12, 20, 50].map(n =>
    `<option value="${n}" ${Number(pagination.pageSize) === n ? 'selected' : ''}>${n} / page</option>`
  ).join('');

  bar.innerHTML = `
    <div class="subx-page-info">${from}-${to} of ${matched} peers</div>
    <div class="subx-page-controls" aria-label="Peer pagination">
      <button type="button" data-nav="first" ${cur <= 1 ? 'disabled' : ''} title="First page" aria-label="First page"><i class="fas fa-angles-left"></i></button>
      <button type="button" data-nav="prev" ${cur <= 1 ? 'disabled' : ''} title="Previous page" aria-label="Previous page"><i class="fas fa-chevron-left"></i></button>
      <span>Page <b>${cur}</b> of <b>${total}</b></span>
      <button type="button" data-nav="next" ${cur >= total ? 'disabled' : ''} title="Next page" aria-label="Next page"><i class="fas fa-chevron-right"></i></button>
      <button type="button" data-nav="last" ${cur >= total ? 'disabled' : ''} title="Last page" aria-label="Last page"><i class="fas fa-angles-right"></i></button>
      <select id="peer-page-size-pager" class="input" aria-label="Peers per page">${sizeOptions}</select>
    </div>
  `;
}


  // peers refresh
let refreshTimer = null,
    isRefreshing = false,
    firstLoad = false,
    refreshDelay = 5000,
    lastErrorAt = 0,
    peersFetchCtrl = null,
    peersLoadingSeq = 0,
    peersLoadingSince = 0;

const REFRESH_TIMEOUT_MS_LOCAL = 8000;
const REFRESH_TIMEOUT_MS_NODE  = 20000;
const MAX_BACKOFF_MS = 60000;

function nextSchedule(ms) {
  if (refreshTimer) clearTimeout(refreshTimer);

  refreshTimer = setTimeout(() => refreshPeers({ quiet: true }), ms);
}

function findPeer(id) {
  const key = String(id ?? '');
  return (window._peers || []).find(x =>
    String(peerKey(x)) === key ||
    String(x.id ?? '') === key ||
    String(x.public_key ?? '') === key
  );
}

function peersLoading(on, title, sub) {
  const el = document.getElementById('spinner-peers');
  if (!el) return;

  if (!el.dataset.enhanced) {
    el.dataset.enhanced = '1';
    el.innerHTML = `
      <div class="peers-loading-card" role="status" aria-live="polite">
        <span class="peers-loading-orb"><i class="fas fa-circle-notch" aria-hidden="true"></i></span>
        <span class="peers-loading-copy">
          <b id="peers-loading-title">Loading peers…</b>
          <small id="peers-loading-sub">Fetching latest state.</small>
        </span>
      </div>`;
  }

  const t = document.getElementById('peers-loading-title');
  const s = document.getElementById('peers-loading-sub');

  if (on) {
    peersLoadingSeq += 1;
    peersLoadingSince = Date.now();
    if (t) t.textContent = title || 'Loading peers…';
    if (s) s.textContent = sub || 'Fetching latest state.';
    el.hidden = false;
    el.style.setProperty('display', 'flex', 'important');
    el.setAttribute('aria-busy', 'true');
    document.body.classList.add('peers-is-loading');
    return;
  }

  const seq = peersLoadingSeq;
  const elapsed = Date.now() - peersLoadingSince;
  const delay = Math.max(0, 520 - elapsed);

  setTimeout(() => {
    if (seq !== peersLoadingSeq) return;
    el.hidden = true;
    el.style.setProperty('display', 'none', 'important');
    el.setAttribute('aria-busy', 'false');
    document.body.classList.remove('peers-is-loading');
  }, delay);
}
function renderPeers(container, count = 2) {
  if (!container) return;
  if (container.dataset.skeleton === '1') return;
  container.dataset.skeleton = '1';

  const parts = [];
  for (let i = 0; i < count; i++) {
    parts.push(`
      <div class="peer-skeleton-card">
        <div class="peer-skel-row">
          <div class="peer-skel-line" style="width:120px"></div>
          <div class="peer-skel-line" style="width:90px"></div>
          <div class="peer-skel-line" style="width:180px"></div>
          <div class="peer-skel-line" style="width:140px"></div>
        </div>
        <div style="height:10px"></div>
        <div class="peer-skel-line" style="width:60%"></div>
      </div>
    `);
  }
  container.innerHTML = parts.join('');
}

function clearPeers(container) {
  if (!container) return;

  container.querySelectorAll('.peer-skeleton-card').forEach(el => el.remove());

  if (container.dataset.skeleton === '1') {
    delete container.dataset.skeleton;
  }
}

async function refreshPeers(opts = {}) {
  const ifaceId   = (opts.ifaceId ?? SELECTED_IFACE_ID);
  const abortPrev = !!opts.abortPrev;
  const quiet    = !!opts.quiet;
  if (isRefreshing && !abortPrev) return;
  if (abortPrev && peersFetchCtrl) {
  try { peersFetchCtrl.abort('superseded-by-newer-request'); } catch {}
}

  const ctrl = new AbortController();
  peersFetchCtrl = ctrl;
  const { signal } = ctrl;

  const scopeId = getScopeId();
  const container = $('.peers-container');
  const title = scopeId ? 'Loading peers from node…' : 'Loading peers…';
  const sub   = scopeId ? 'Contacting node and syncing runtime.' : 'Fetching latest peers list.';

  let showTimer = null;

if (!quiet && opts.forceLoading) {
  peersLoading(true, title, sub);
  if (container) {
    container.innerHTML = '';
    renderPeers(container, 2);
  }
} else if (!quiet) {
  showTimer = setTimeout(() => {
    peersLoading(true, title, sub);

    if (container && (!container.children || container.children.length === 0)) {
      renderPeers(container, 2);
    }
  }, 250);
}

  isRefreshing = true;

  const timeoutMs = scopeId ? REFRESH_TIMEOUT_MS_NODE : REFRESH_TIMEOUT_MS_LOCAL;
    const killer = setTimeout(() => {
    try { ctrl.abort('refresh-timeout'); } catch {}
  }, timeoutMs);


  try {
    const base = scopeId
      ? `/api/nodes/${encodeURIComponent(scopeId)}/peers`
      : '/api/peers';

    const url = new URL(base, window.location.origin);

    if (scopeId) {
      if (typeof SELECTED_IFACE_NAME === 'string' && SELECTED_IFACE_NAME) {
        url.searchParams.set('iface', SELECTED_IFACE_NAME);
      }
    } else {
      if (ifaceId) url.searchParams.set('iface_id', String(ifaceId));
    }

    const res = await fetch(url.toString(), {
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Accept': 'application/json' },
      signal
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);

    const data = await res.json();
    const peers = data?.peers || [];
    window._peers = peers;
    renderPeerSummary(peers);

    if (!container) return;

    clearPeers(container);

    const existing = new Map(
      $$('.peer-card', container).map(c => [String(c.dataset.id || ''), c])
    );

    if (peers.length === 0) {
      container.innerHTML = `
        <div class="empty-peers empty-peers-pro">
          <span class="empty-peers-icon"><i class="fas fa-user-plus" aria-hidden="true"></i></span>
          <div class="empty-peers-copy">
            <strong>No peers in this interface</strong>
            <small>Create a peer or switch interface/scope to view existing peers.</small>
          </div>
        </div>`;
    } else {
      container.querySelector('.empty-peers')?.remove();

      peers.forEach((p, i) => {

        const idStr = String(scopeId ? (p.public_key || p.id) : p.id);

        let card = existing.get(idStr);

        if (!card) {
          const wrap = document.createElement('div');
          wrap.innerHTML = cardHTML(p, i);
          card = wrap.firstElementChild;
          container.appendChild(card);
        } else {
          const expected = container.children[i];
          if (expected !== card) container.insertBefore(card, expected || null);
        }

        updateCard(card, p, i);
        existing.delete(idStr);
      });

      for (const [, leftover] of existing) leftover.remove();
    }

    applyPagi?.();
    refreshDelay = 5000;

  } catch (err) {
  const msg = String(err?.message || err || '');
  const abortMsg = msg.toLowerCase();
  const benignAbort =
  err?.name === 'AbortError' ||
  abortMsg.includes('superseded-by-newer-request') ||
  abortMsg.includes('superseded-by-newer-poll');

if (benignAbort) return;

    const now = Date.now();
    if (now - lastErrorAt > 60000) {
      console.warn('Peers refresh failed:', msg);
      toastSafe?.('Temporary connection hiccup while refreshing peers. Retrying…', 'warning');
      lastErrorAt = now;
    }

    const next = Math.min(MAX_BACKOFF_MS, Math.max(7500, Math.round(refreshDelay * 1.7)));
    refreshDelay = next;

  } finally {
    clearTimeout(killer);

    if (showTimer) clearTimeout(showTimer);
    peersLoading(false);
    if (container) clearPeers(container);

    firstLoad = true;
    isRefreshing = false;

    const jitter = Math.floor(Math.random() * 800);
    nextSchedule(refreshDelay + jitter);

    if (peersFetchCtrl && peersFetchCtrl.signal === signal) {
      peersFetchCtrl = null;
    }
  }
}

async function postEdit(path, okMsg, failMsg) {
  const loader = toastSafe(okMsg.replace('Peer ', '') + '…', 'info', true);
  try {
    const r = await fetch(apiPath(path), { method: 'POST', credentials: 'same-origin' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    toastSafe(okMsg, 'success');

    if (/\/reset_data$/.test(path)) {
      const id = (path.match(/\/peer\/([^/]+)/) || [])[1];
      const peer = id ? findPeer(id) : null;
      if (peer) {
        peer.used_bytes = 0;
        peer.used_bytes_db = 0;
        const card = document.querySelector(`.peer-card[data-id="${peerEsc(peerKey(peer))}"]`);
        if (card) updateCard(card, peer, 0);
      }
    }

    refreshPeers(); 
  } catch (e) {
    console.error(e);
    toastSafe(failMsg, 'error');
  } finally {
    if (loader) { loader.classList.add('hide'); setTimeout(() => loader.remove(), 500); }
  }
}

async function getShortLink(idOrPeer) {
  const peer =
    typeof idOrPeer === 'object'
      ? idOrPeer
      : (typeof findPeer === 'function' ? findPeer(idOrPeer) : null);

  if (peer?.shortlink) {
    return peer.shortlink;
  }

  const apiKey = document.querySelector('meta[name="api-key"]')?.content?.trim() || '';

  const headers = {};
  if (apiKey) headers['X-API-KEY'] = apiKey;

  const path =
    typeof apiPeerPath === 'function'
      ? apiPeerPath(peer || idOrPeer, '/shortlink')
      : `/api/peer/${encodeURIComponent(String(idOrPeer))}/shortlink`;

  const r = await fetch(api(path), {
    method: 'GET',
    credentials: 'same-origin',
    headers
  });

  if (!r.ok) {
    const txt = await r.text().catch(() => '');
    throw new Error(`HTTP ${r.status}: ${txt}`);
  }

  const j = await r.json();
  return j.url;
}

  async function userLink(e, id) {
    try {
      const peer = typeof findPeer === 'function' ? findPeer(id) : null;
      const url = await getShortLink(peer || id);
      if (e.ctrlKey || e.metaKey) {
        window.open(url, '_blank', 'noopener');
        toastSafe('Opened user link', 'success');
      } else {
        const ok = await copyTo(url);
        toastSafe(ok ? 'User link copied' : 'Copy failed (blocked by browser)', ok ? 'success' : 'error');
      }
    } catch (err) {
      console.error(err);
      toastSafe('Failed to get user link', 'error');
    }
  }
  async function handleClick(e) {
    const btn = e.target.closest('button.user-link-btn'); if (!btn) return;
    if (e.button !== 1) return;
    const id = btn.dataset.id || btn.closest('.peer-card')?.dataset.id; if (!id) return;
    e.preventDefault();
    try {
      const peer = typeof findPeer === 'function' ? findPeer(id) : null;
      const url = await getShortLink(peer || id);
      window.open(url, '_blank', 'noopener');
      toastSafe('Opened user link', 'success');
    } catch (err) {
      console.error(err);
      toastSafe('Failed to get user link', 'error');
    }
  }

  let editModal, editForm;
  function openEdit(id) {
    const p = findPeer(id); if (!p) return;
    if (!editModal) editModal = $('#edit-peer-modal');
    if (!editForm)  editForm  = $('#edit-peer-form');
    if (!editForm) return;

    editForm.dataset.id = id;
    editForm.name && (editForm.name.value = p.name || '');
    const sel = editForm.querySelector('select[name="address"]'); if (sel) sel.innerHTML = `<option value="${p.address}">${p.address}</option>`;
    editForm.allowed_ips && (editForm.allowed_ips.value = p.allowed_ips || '');
    editForm.endpoint && (editForm.endpoint.value = p.endpoint || '');
    editForm.persistent_keepalive && (editForm.persistent_keepalive.value = p.persistent_keepalive || '');
    editForm.mtu && (editForm.mtu.value = p.mtu || '');
    editForm.dns && (editForm.dns.value = p.dns || '');
    editForm.data_limit_value && (editForm.data_limit_value.value = p.data_limit || '');
    editForm.data_limit_unit && (editForm.data_limit_unit.value = p.limit_unit || 'Mi');

    const raw = parseFloat(p.time_limit_days || 0);
    let d = 0, h = 0;
    if (isFinite(raw) && raw > 0) { d = Math.floor(raw); h = Math.floor((raw - d) * 24 + 1e-9); h = Math.max(0, Math.min(23, h)); }
    if (editForm.time_limit_days)  editForm.time_limit_days.value  = d || '';
    if (editForm.time_limit_hours) editForm.time_limit_hours.value = h || '';

    if (editForm.start_on_first_use) editForm.start_on_first_use.checked = !!p.start_on_first_use;
    if (editForm.unlimited)          editForm.unlimited.checked          = !!p.unlimited;
    if (editForm.phone_number)       editForm.phone_number.value         = p.phone_number || '';
    if (editForm.telegram_id)        editForm.telegram_id.value          = p.telegram_id || '';

    $('#edit-close')?.addEventListener('click', () => closeModal(editModal), { once: true });
    openModal(editModal);
    attachEndpoint(editModal);
  }

  async function subEdit(e) {
    e.preventDefault();
    const id = editForm.dataset.id;
    const form = new FormData(editForm);
    const data = Object.fromEntries(form.entries());
    if (editForm.start_on_first_use) data.start_on_first_use = !!editForm.start_on_first_use.checked;
    if (editForm.unlimited)          data.unlimited          = !!editForm.unlimited.checked;

    const loader = toastSafe('Updating peer…', 'info', true);
    try {
      const r = await fetch(api(`/api/peer/${id}`), {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
        body: JSON.stringify(data)
      });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      toastSafe('Peer updated', 'success'); closeModal(editModal); refreshPeers();
    } catch (e) { console.error(e); toastSafe('Update failed', 'error'); }
    finally { if (loader) { loader.classList.add('hide'); setTimeout(() => loader.remove(), 500); } }
  }

  // QR & logs 
  let qrModal;
  function itsQR() {
    if (qrModal) return qrModal;
    qrModal = document.createElement('div'); qrModal.className = 'modal peer-qr-modal'; qrModal.id = 'qr-modal';
    qrModal.setAttribute('aria-hidden', 'true');
    qrModal.innerHTML = `
      <div class="modal-content qr-modal-card" role="dialog" aria-modal="true" aria-labelledby="qr-modal-title">
        <button class="modal-close" id="qr-close" aria-label="Close" type="button">&times;</button>
        <div class="qr-modal-head">
          <span class="qr-modal-icon"><i class="fas fa-qrcode" aria-hidden="true"></i></span>
          <div>
            <h2 id="qr-modal-title">Peer QR</h2>
            <small>Scan in WireGuard or download the PNG.</small>
          </div>
        </div>
        <div id="qr-img-wrap" class="qr-img-wrap"><span class="qr-loading"><i class="fas fa-circle-notch fa-spin"></i> Generating…</span></div>
        <div class="qr-actions">
          <a id="qr-download" class="btn" download="peer.png"><i class="fas fa-download"></i> Download</a>
          <button id="qr-copy-text" class="btn secondary" type="button"><i class="fas fa-clipboard"></i> Copy config</button>
        </div>
      </div>`;
    document.body.appendChild(qrModal);
    $('#qr-close', qrModal)?.addEventListener('click', () => closeModal(qrModal));
  }
  async function openQR(id) {
    itsQR(); openModal(qrModal);
    const wrap = $('#qr-img-wrap', qrModal); wrap.innerHTML = '<span class="qr-loading"><i class="fas fa-circle-notch fa-spin"></i> Generating…</span>';
    const dl = $('#qr-download', qrModal); dl.removeAttribute('href'); dl.removeAttribute('download');
    try {
      let r = await fetch(apiPeerPath(id, '/config_qr'), { credentials: 'same-origin' });
      if (r.status === 501) r = await fetch(apiPeerPath(id, '/config_qr?install=1'), { credentials: 'same-origin' });
      if (r.ok) {
        const blob = await r.blob(); const url = URL.createObjectURL(blob);
        wrap.innerHTML = `<img src="${url}" alt="Peer WireGuard QR code">`;
        dl.href = url; dl.download = `peer-${id}.png`;
        $('#qr-copy-text', qrModal).onclick = async () => {
          const txt = await (await fetch(apiPeerPath(id, '/config'), { credentials: 'same-origin' })).text();
          await copyTo(txt); toastSafe('Config copied to clipboard', 'success');
        };
        return;
      }
      const txt = await (await fetch(apiPeerPath(id, '/config'), { credentials: 'same-origin' })).text();
      wrap.innerHTML = `<textarea readonly style="width:100%;height:260px;border:0;outline:none;background:#f9fafb;border-radius:8px;padding:8px">${txt}</textarea>`;
      dl.style.display = 'none';
      $('#qr-copy-text', qrModal).onclick = async () => { await copyTo(txt); toastSafe('Config copied to clipboard', 'success'); };
      toastSafe('Server QR not available. Installed? Try again.', 'error');
    } catch {
      wrap.innerHTML = '<span style="color:#e11d48">Failed to generate QR</span>';
    }
  }

  let logsModal;
  const eventIcon = { created:'fa-plus-circle', enabled:'fa-play', disabled:'fa-ban', expired:'fa-hourglass-end', limit_reached:'fa-gauge-high', edited:'fa-edit', reset_data:'fa-tachometer-alt', reset_timer:'fa-history', first_use:'fa-bolt' };
  function itsLogs() {
    if (logsModal) return logsModal;
    logsModal = document.createElement('div'); logsModal.className = 'modal'; logsModal.id = 'logs-modal';
    logsModal.innerHTML = `
      <div class="modal-content logs">
        <button class="modal-close" id="logs-close" aria-label="Close" style="position:absolute;top:10px;right:10px">&times;</button>
        <div class="logs-header" style="display:flex;align-items:center;gap:.6rem;margin-bottom:.75rem;">
          <i class="fas fa-list"></i><h2 style="margin:0">Peer Logs</h2>
        </div>
        <div class="logs-chips" id="logs-chips" style="display:flex;gap:.5rem;flex-wrap:wrap;margin:.25rem 0 .5rem;"></div>
        <div class="logs-tabs" style="display:flex;gap:6px;margin:.5rem 0 .25rem;border-bottom:1px solid #e5e7eb;">
          <button class="logs-tab active" data-tab="overview" style="background:transparent;border:0;cursor:pointer;padding:8px 12px;border-radius:8px 8px 0 0;font-weight:600;">Overview</button>
          <button class="logs-tab" data-tab="events" style="background:transparent;border:0;cursor:pointer;padding:8px 12px;border-radius:8px 8px 0 0;font-weight:600;">Events</button>
        </div>
        <div class="tab-panel active" data-panel="overview" style="padding-top:.75rem;">
          <div id="logs-overview" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;"></div>
        </div>
        <div class="tab-panel" data-panel="events" style="padding-top:.75rem;display:none;">
          <div class="logs-tools" style="display:flex;gap:8px;align-items:center;margin:4px 0 8px;">
            <input id="logs-search" class="input" placeholder="Search events/details…" style="height:34px;">
            <select id="logs-type" class="input" style="height:34px;width:160px">
              <option value="">All events</option>
              <option value="created">created</option>
              <option value="edited">edited</option>
              <option value="enabled">enabled</option>
              <option value="disabled">disabled</option>
              <option value="expired">expired</option>
              <option value="limit_reached">limit_reached</option>
              <option value="reset_data">reset_data</option>
              <option value="reset_timer">reset_timer</option>
              <option value="first_use">first_use</option>
            </select>
            <button id="logs-export" class="btn secondary xs" title="Export CSV">
          <i class="fas fa-file-arrow-down"></i> CSV
          </button>
          <button id="logs-clear" class="btn danger xs" title="Clear events">
          <i class="fas fa-eraser"></i> Clear
          </button>
          </div>
          <div class="logs-table-wrap" style="max-height:360px;overflow:auto;border:1px solid #e5e7eb;border-radius:8px;">
            <table class="logs-table" style="width:100%;border-collapse:separate;border-spacing:0;font-size:.95em;">
              <thead>
                <tr>
                  <th style="position:sticky;top:0;background:#f8fafc;text-align:left;padding:.55rem .5rem;border-bottom:1px solid #e5e7eb;">Time</th>
                  <th style="position:sticky;top:0;background:#f8fafc;text-align:left;padding:.55rem .5rem;border-bottom:1px solid #e5e7eb;">Event</th>
                  <th style="position:sticky;top:0;background:#f8fafc;text-align:left;padding:.55rem .5rem;border-bottom:1px solid #e5e7eb;">Details</th>
                  <th style="position:sticky;top:0;background:#f8fafc;text-align:left;padding:.55rem .5rem;border-bottom:1px solid #e5e7eb;">When</th>
                </tr>
              </thead>
              <tbody id="logs-tbody"></tbody>
            </table>
          </div>
        </div>
      </div>`;
    document.body.appendChild(logsModal);
    $('#logs-close', logsModal)?.addEventListener('click', () => closeModal(logsModal));
    logsModal.addEventListener('click', e => {
      if (e.target === logsModal) closeModal(logsModal);
      const t = e.target.closest('.logs-tab'); if (!t) return;
      $$('.logs-tab', logsModal).forEach(b => b.classList.toggle('active', b === t));
      $$('.tab-panel', logsModal).forEach(p => p.style.display = p.dataset.panel === t.dataset.tab ? 'block' : 'none');
    });
  }
function openLogs(id) {
  itsLogs();
  openModal(logsModal);

  logsModal.dataset.peerId = String(id);

  const $in = (sel, root = document) => root.querySelector(sel);

  const renderChips = () => {
    const pid  = logsModal.dataset.peerId;
    const peer = findPeer(pid) || {};

    const liveMiB  = Math.round(((Number(peer.used_bytes)    || 0)) / 1048576);
    const dbMiB    = Math.round(((Number(peer.used_bytes_db) || 0)) / 1048576);
    const totalMiB = dbMiB + Math.max(0, liveMiB);

    const limit  = peer ? fmtLimit(peer) : '–';
    const remain = peer
      ? (peer.unlimited ? 'Unlimited' : fmtAmountMiB(remainingMiB(peer), peer.limit_unit))
      : '–';

    const chips = $in('#logs-chips', logsModal);
    if (!chips) return;
    chips.innerHTML = `
      <span class="logs-chip"><i class="fas fa-gauge"></i> Usage: ${fmtAmountMiB(liveMiB, 'Mi')} used</span>
      <span class="logs-chip"><i class="fas fa-database"></i> Remaining: ${remain}</span>
      <span class="logs-chip"><i class="fas fa-layer-group"></i> Limit: ${limit}</span>
      <span class="logs-chip">
        <i class="fas fa-chart-column"></i>
        Total usage: ${fmtAmountMiB(totalMiB, 'Mi')}
        <button id="logs-clear-total" class="chip-btn" title="Clear lifetime total">
          <i class="fas fa-eraser"></i>
        </button>
      </span>
    `;
  };

  renderChips();
  if (logsModal._chipsTimer) clearInterval(logsModal._chipsTimer);
  logsModal._chipsTimer = setInterval(renderChips, 2000);

  if (!logsModal._hideObs) {
    logsModal._hideObs = new MutationObserver(() => {
      const hidden = logsModal.getAttribute('aria-hidden') === 'true';
      if (hidden && logsModal._chipsTimer) {
        clearInterval(logsModal._chipsTimer);
        logsModal._chipsTimer = null;
      }
    });
    logsModal._hideObs.observe(logsModal, { attributes: true, attributeFilter: ['aria-hidden'] });
  }

  const peer = findPeer(id) || {};
  const epStr = endpointDisplay(peer);
  $in('#logs-overview', logsModal).innerHTML = `
    <div class="logs-pill"><i class="fas fa-user"></i><strong>Name:</strong>&nbsp;${peer.name ?? '–'}</div>
    <div class="logs-pill"><i class="fas fa-network-wired"></i><strong>Address:</strong>&nbsp;${peer.address ?? '–'}</div>
    <div class="logs-pill"><i class="fas fa-globe"></i><strong>Endpoint:</strong>&nbsp;${epStr || '–'}</div>
    <div class="logs-pill"><i class="fas fa-shield-halved"></i><strong>Interface:</strong>&nbsp;${peer.iface ?? '–'}</div>
    <div class="logs-pill"><i class="fas fa-clock"></i><strong>Status:</strong>&nbsp;${cap(peer.status ?? '–')}</div>
  `;

  const logsFetchUrl = api(apiPeerPath(id, '/logs'));
  const logsTbodyLoading = $in('#logs-tbody', logsModal);
  if (logsTbodyLoading) {
    logsTbodyLoading.innerHTML = `<tr><td colspan="4" class="logs-empty"><i class="fas fa-circle-notch fa-spin"></i><span>Loading peer events…</span></td></tr>`;
  }

  fetch(logsFetchUrl, { credentials: 'same-origin' })
    .then(async r => {
      if (!r.ok) {
        const txt = await r.text().catch(() => '');
        throw new Error(`HTTP ${r.status}: ${txt.slice(0, 160)}`);
      }
      return r.json();
    })
    .then(({ logs }) => {
      const overview = $in('#logs-overview', logsModal);
      const toLocalStr = (val) => {
        if (val == null) return null;
        if (typeof val === 'number') return fmtLocalTs(normEpoch(val));
        const t = tsFrom(val); return t ? fmtLocalTs(t) : String(val);
      };

      const createdEvt  = (logs || []).find(l => l.event === 'created');
      const createdWhen = toLocalStr(createdEvt?.time) || (peer.created_at ? toLocalStr(peer.created_at) : null);
      if (createdWhen) overview.innerHTML += `<div class="logs-pill"><i class="fas fa-calendar-plus"></i><strong>Created:</strong>&nbsp;${createdWhen}</div>`;

      const firstUsedEvt  = (logs || []).find(l => l.event === 'first_use');
      const firstUsedWhen = peer.first_used_at ? toLocalStr(peer.first_used_at) : toLocalStr(firstUsedEvt?.time);
      if (firstUsedWhen) overview.innerHTML += `<div class="logs-pill"><i class="fas fa-bolt"></i><strong>First used:</strong>&nbsp;${firstUsedWhen}</div>`;

      const expiresWhen = peer.expires_at ? toLocalStr(peer.expires_at) : null;
      if (expiresWhen) overview.innerHTML += `<div class="logs-pill"><i class="fas fa-hourglass-end"></i><strong>Expires:</strong>&nbsp;${expiresWhen}</div>`;

      const tbody = $in('#logs-tbody', logsModal);
      const draw = () => {
        const q    = ($in('#logs-search', logsModal).value || '').toLowerCase();
        const type = $in('#logs-type',   logsModal).value || '';
        const rows = (logs || [])
          .filter(l => (!type || l.event === type))
          .filter(l =>
            !q ||
            (l.event || '').toLowerCase().includes(q) ||
            (l.details || '').toLowerCase().includes(q) ||
            String(l.time || '').toLowerCase().includes(q)
          )
          .map(l => {
            const ic = eventIcon[l.event] || 'fa-info-circle';
            const t  = (typeof l.time === 'number') ? normEpoch(l.time) : tsFrom(l.time);
            const when = t ? fmtLocalTs(t) : (l.time || '');
            const whenRel = (() => {
              const s = Math.max(0, nowSec() - (t ?? nowSec()));
              const r = (n,u) => `${n} ${u}${n>1?'s':''} ago`;
              if (s < 60) return r(s,'sec');
              const m = Math.floor(s/60); if (m < 60) return r(m,'min');
              const h = Math.floor(m/60); if (h < 24) return r(h,'hour');
              const d = Math.floor(h/24); if (d < 30) return r(d,'day');
              const mo = Math.floor(d/30); if (mo < 12) return r(mo,'month');
              return r(Math.floor(mo/12),'year');
            })();
            return `
              <tr>
                <td style="padding:.5rem .5rem;border-bottom:1px solid #f1f5f9;white-space:nowrap">${when}</td>
                <td style="padding:.5rem .5rem;border-bottom:1px solid #f1f5f9;">
                  <span style="display:inline-flex;align-items:center;gap:.45rem;font-weight:600;">
                    <i class="fas ${ic}"></i>${l.event.replace(/_/g,' ')}
                  </span>
                </td>
                <td style="padding:.5rem .5rem;border-bottom:1px solid #f1f5f9;">${(l.details || '').replace(/\n/g, '<br>')}</td>
                <td style="padding:.5rem .5rem;border-bottom:1px solid #f1f5f9;white-space:nowrap;color:#64748b">${whenRel}</td>
              </tr>`;
          }).join('');
        tbody.innerHTML = rows || `<tr><td colspan="4" class="logs-empty"><i class="fas fa-inbox"></i><span>No events yet</span><small>New actions for this peer will appear here.</small></td></tr>`;
      };
      draw();
      $in('#logs-search', logsModal).oninput = debounce(draw, 120);
      $in('#logs-type',   logsModal).onchange = draw;

      const btnExport = $in('#logs-export', logsModal);
      if (btnExport) {
        btnExport.onclick = () => {
          const csv = ['time,event,details'].concat((logs || []).map(l => {
            const det = (l.details || '').replaceAll('"', '""').replaceAll('\n', '; ');
            return `"${l.time}","${l.event}","${det}"`;
          })).join('\n');
          const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a'); a.href = url; a.download = `peer-${id}-logs.csv`;
          document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
        };
      }

      const btnClear = $in('#logs-clear', logsModal);
      if (btnClear) {
        btnClear.onclick = async () => {
          const ok = await confirmBoxIn(logsModal, 'Clear all events for this peer?', {
            title: 'Clear peer events',
            yesText: 'Clear',
            noText: 'Cancel'
          });
          if (!ok) return;
          try {
            const r = await fetch(api(apiPeerPath(id, '/logs')), { method: 'DELETE', credentials: 'same-origin' });
            if (!r.ok) throw new Error('HTTP ' + r.status);
            toastSafe('Events cleared', 'success');
            $in('#logs-tbody', logsModal).innerHTML = `<tr><td colspan="4" class="logs-empty"><i class="fas fa-inbox"></i><span>No events yet</span><small>New actions for this peer will appear here.</small></td></tr>`;
          } catch {
            toastSafe('Failed to clear events', 'error');
          }
        };
      }
    })
    .catch((err) => {
      console.error('Peer logs failed:', err);
      const tbody = $in('#logs-tbody', logsModal);
      if (tbody) {
        tbody.innerHTML = `<tr><td colspan="4" class="logs-empty error"><i class="fas fa-triangle-exclamation"></i><span>Could not load peer logs</span><small>${String(err.message || err).replace(/[<>]/g, '')}</small></td></tr>`;
      }
      toastSafe('Failed to load logs', 'error');
    });

  if (!logsModal._bindClearTotal) {
    logsModal.addEventListener('click', async (ev) => {
      const btn = ev.target.closest('#logs-clear-total');
      if (!btn) return;

      const pid = logsModal.dataset.peerId;
      const ok = await confirmBoxIn(logsModal, 'Clear lifetime total usage for this peer?', {
        title: 'Clear total usage',
        yesText: 'Clear',
        noText: 'Cancel'
      });
      if (!ok) return;

      try {
        const r = await fetch(api(apiPeerPath(pid, '/clear_total')), {
          method: 'POST',
          credentials: 'same-origin'
        });
        if (!r.ok) throw new Error('HTTP ' + r.status);

        const p = findPeer(pid);
        if (p) p.used_bytes_db = 0;  
        renderChips();               
        toastSafe('Lifetime total cleared', 'success');
      } catch {
        toastSafe('Failed to clear lifetime total', 'error');
      }
    });
    logsModal._bindClearTotal = true;
  }
}

let confirmModal, confirmText, confirmYes, confirmNo;

function uiConfirm() {
  if (confirmModal) return;

  confirmModal = document.createElement('div');
  confirmModal.className = 'peer-confirm-overlay';
  confirmModal.innerHTML = `
    <div class="peer-confirm-card" role="dialog" aria-modal="true" aria-labelledby="peer-confirm-title">
      <div class="peer-confirm-icon" id="peer-confirm-icon"><i class="fas fa-circle-question"></i></div>
      <div class="peer-confirm-copy">
        <h3 id="peer-confirm-title">Confirm action</h3>
        <p id="confirm-text"></p>
      </div>
      <div class="peer-confirm-actions">
        <button id="confirm-no" class="btn secondary" type="button">Cancel</button>
        <button id="confirm-yes" class="btn" type="button">Continue</button>
      </div>
    </div>
  `;

  document.body.appendChild(confirmModal);

  confirmText = confirmModal.querySelector('#confirm-text');
  confirmYes  = confirmModal.querySelector('#confirm-yes');
  confirmNo   = confirmModal.querySelector('#confirm-no');
}

  function ensureModalBackdrop(m) {
  if (!m) return null;
  let bd = m.querySelector(':scope > .modal-backdrop');
  if (!bd) {
    bd = document.createElement('div');
    bd.className = 'modal-backdrop';
    m.prepend(bd);
  }
  if (!bd.__peerBackdropBound) {
    bd.addEventListener('click', () => closeModal(m));
    bd.__peerBackdropBound = true;
  }
  return bd;
}

  function openModal(m) {
  document.querySelectorAll('.modal.open').forEach(el => el.classList.remove('open'));
  if (m) {
    ensureModalBackdrop(m);
    m.classList.add('open');
    document.body.classList.add('modal-open');
  }
}

function closeModal(m) {
  if (m) m.classList.remove('open');
  if (!document.querySelector('.modal.open')) {
    document.body.classList.remove('modal-open');
  }
}

function confirmBox(msg, opts = {}) {
  uiConfirm();
  return new Promise(resolve => {
    const danger = /delete|remove|clear|blocked|stop/i.test(String(msg || '') + ' ' + String(opts.title || ''));
    const titleEl = confirmModal.querySelector('#peer-confirm-title');
    const iconBox = confirmModal.querySelector('#peer-confirm-icon');
    const icon = iconBox?.querySelector('i');

    titleEl.textContent = opts.title || (danger ? 'Confirm dangerous action' : 'Confirm action');
    confirmText.textContent = msg || '';
    confirmYes.textContent = opts.yesText || (danger ? 'Continue' : 'Yes');
    confirmNo.textContent = opts.noText || 'Cancel';
    confirmYes.classList.toggle('danger', danger);
    iconBox?.classList.toggle('danger', danger);
    if (icon) icon.className = `fas ${danger ? 'fa-triangle-exclamation' : 'fa-circle-question'}`;

    confirmModal.classList.add('open');
    document.body.classList.add('modal-open');

    const y = () => done(true), n = () => done(false);
    function done(ans) {
      confirmModal.classList.remove('open');
      if (!document.querySelector('.modal.open')) document.body.classList.remove('modal-open');
      confirmYes.removeEventListener('click', y);
      confirmNo.removeEventListener('click', n);
      document.removeEventListener('keydown', keyHandler);
      resolve(ans);
    }
    function keyHandler(e) {
      if (e.key === 'Escape') { e.preventDefault(); done(false); }
      if (e.key === 'Enter')  { e.preventDefault(); done(true); }
    }
    confirmYes.addEventListener('click', y);
    confirmNo.addEventListener('click', n);
    document.addEventListener('keydown', keyHandler);
    confirmModal.addEventListener('click', e => { if (e.target === confirmModal) done(false); }, { once: true });
    setTimeout(() => confirmYes?.focus?.({preventScroll:true}), 30);
  });
}

function confirmBoxIn(container, msg, opts = {}) {
  const {
    title   = 'Confirm action',
    yesText = 'Continue',
    noText  = 'Cancel'
  } = opts;

  return new Promise(resolve => {
    const host = (container?.querySelector?.('.modal-content')) || container || document.body;
    if (host && getComputedStyle(host).position === 'static') host.style.position = 'relative';

    host.querySelectorAll('.cbi-wrap').forEach(w => w.remove());

    const danger = /delete|remove|clear|danger/i.test(String(title) + ' ' + String(msg));
    const wrap = document.createElement('div');
    wrap.className = 'cbi-wrap';
    Object.assign(wrap.style, {
      position: 'absolute',
      inset: '0',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 80,
      padding: '16px'
    });

    wrap.innerHTML = `
      <div class="cbi-card" role="dialog" aria-modal="true" aria-label="${peerEsc(title)}" tabindex="-1">
        <div class="cbi-icon ${danger ? 'danger' : ''}"><i class="fas ${danger ? 'fa-triangle-exclamation' : 'fa-circle-question'}"></i></div>
        <div class="cbi-copy">
          <h3>${peerEsc(title)}</h3>
          <p>${peerEsc(msg || '')}</p>
        </div>
        <div class="cbi-actions">
          <button class="btn secondary" id="cbi-no" type="button">${peerEsc(noText)}</button>
          <button class="btn ${danger ? 'danger' : ''}" id="cbi-yes" type="button">${peerEsc(yesText)}</button>
        </div>
      </div>
    `;

    host.appendChild(wrap);

    const inner = wrap.querySelector('.cbi-card');
    const yes = wrap.querySelector('#cbi-yes');
    const no  = wrap.querySelector('#cbi-no');

    setTimeout(() => { inner?.focus(); yes?.focus(); }, 10);

    const done = (ans) => {
      try { wrap.remove(); } catch {}
      resolve(ans);
    };

    yes.addEventListener('click', () => done(true),  { once:true });
    no .addEventListener('click', () => done(false), { once:true });

    wrap.addEventListener('click', (e) => {
      if (e.target === wrap) done(false);
    });

    inner.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { e.preventDefault(); done(false); }
      if (e.key === 'Enter' && document.activeElement !== no) {
        e.preventDefault(); done(true);
      }
    });
  });
}

function modalOpen(el) {
  return !!(el && getComputedStyle(el).display !== 'none' && el.classList.contains('open'));
}
function refreshDefaultIface(iface) {
  const ep = document.querySelector('#peer-modal input[name="endpoint"]');
  if (!ep || !iface) return;
  if (ep.dataset.lastIface !== String(SELECTED_IFACE_ID)) ep.dataset.userEdited = '0';
  if (ep.dataset.userEdited === '1') return;

  const port = iface.listen_port;
  const scopeId = getScopeId(); 

  if (scopeId) {
    if (window.NODE_PUBLIC_IP && port) {
      ep.value = `${window.NODE_PUBLIC_IP}:${port}`;
      ep.dataset.lastIface = String(SELECTED_IFACE_ID);
      ep.dataset.userEdited = '0';
    }
  } else {
    if (port) {
      fetch(api('/api/endpoint_presets'), { credentials: 'same-origin' })
        .then(r => r.ok ? r.json() : null)
        .then(j => {
          const pub = j?.public_ipv4 || '';
          if (pub && ep.dataset.userEdited !== '1') {
            ep.value = `${pub}:${port}`;
            ep.dataset.lastIface = String(SELECTED_IFACE_ID);
            ep.dataset.userEdited = '0';
          }
        })
        .catch(() => {});
    }
  }
  ep.addEventListener('input', () => { ep.dataset.userEdited = '1'; }, { once: true });
}

function refreshBulkIface(iface) {
  const input = document.querySelector('#bulk-endpoint');
  if (!input || !iface) return;
  if (input.dataset.lastIface !== String(SELECTED_IFACE_ID)) input.dataset.userEdited = '0';
  if (input.dataset.userEdited === '1') return;

  const port = iface.listen_port;
  const scopeId = getScopeId();

  if (scopeId) {
    if (window.NODE_PUBLIC_IP && port) {
      input.value = `${window.NODE_PUBLIC_IP}:${port}`;
      input.dataset.lastIface = String(SELECTED_IFACE_ID);
      input.dataset.userEdited = '0';
    }
  } else {
    fetch(api('/api/endpoint_presets'), { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(j => {
        const pub = j?.public_ipv4 || '';
        if (pub && input.dataset.userEdited !== '1') {
          input.value = `${pub}:${port}`;
          input.dataset.lastIface = String(SELECTED_IFACE_ID);
          input.dataset.userEdited = '0';
        }
      })
      .catch(() => {});
  }
  input.addEventListener('input', () => { input.dataset.userEdited = '1'; }, { once: true });
}

async function refreshInterfacesUI({ keepSelection = true, updateCreate = true, updateBulk = true } = {}) {
  const prevScope = window._lastScopeId ?? '';
  const scopeId   = getScopeId();

  let interfaces = [];
  try {
    const path = scopeId
      ? `/api/nodes/${encodeURIComponent(scopeId)}/interfaces`
      : `/api/get-interfaces`;

    const r = await fetch(path, { credentials: 'same-origin', cache: 'no-store' });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);

    const j   = await r.json();
    const raw = Array.isArray(j.interfaces) ? j.interfaces : [];

    window.NODE_PUBLIC_IP = getScopeId() ? (j.public_ipv4 || null) : null;

    interfaces = raw.map((it, idx) => {
      const syntheticId = scopeId ? `n${scopeId}:${it.name || idx}` : String(it.id ?? idx);
      return {
        ...it,
        id:   (it.id != null ? String(it.id) : syntheticId),
        name: (it.name || it.id || `wg${idx}`)
      };
    });
  } catch (e) {
    console.warn('refreshInterfacesUI: failed to fetch interfaces', e);
    return;
  }

  IFACES = interfaces;
  window.IFACES = interfaces;

  if (typeof makeIfaceBar === 'function') makeIfaceBar();

  const scopeChanged = (scopeId !== prevScope);
  const keepId = (!scopeChanged && keepSelection) ? SELECTED_IFACE_ID : null;
  const stillThere = keepId && IFACES.some(i => String(i.id) === String(keepId));
  const newSel = stillThere ? keepId : (IFACES[0]?.id ?? null);

  if (newSel != null) {
    SELECTED_IFACE_ID = String(newSel); 
    if (typeof setIfaceById === 'function') {
      setIfaceById(SELECTED_IFACE_ID);
    }
  }

  window._lastScopeId = scopeId;

  const getIfaceById = (id) => {
    if (typeof findIfaceById === 'function') return findIfaceById(id);
    return IFACES.find(i => String(i.id) === String(id));
  };

  if (updateCreate) {
    const createModal = document.querySelector('#peer-modal');
    if (createModal) {
      const ifaceIdForCreate = SELECTED_IFACE_ID ?? newSel;
      const iface = getIfaceById(ifaceIdForCreate);

      if (iface) {
        const addrSel = createModal.querySelector('#create-address-select')
                       || createModal.querySelector('select[name="address"]');
        if (addrSel) {
          const prevAddr = addrSel.value;
          const options = (iface.available_ips || []).map(ip => `<option value="${ip}">${ip}</option>`).join('');
          addrSel.innerHTML = options;

          if (prevAddr && [...addrSel.options].some(o => o.value === prevAddr)) {
            addrSel.value = prevAddr;
          }

          const hiddenAddr = document.getElementById('create-address');
          if (hiddenAddr) hiddenAddr.value = addrSel.value || '';
        }

        if (typeof refreshDefaultIface === 'function') {
          refreshDefaultIface(iface);
        }
      }

      const hiddenIface = document.getElementById('create-iface-id');
      if (hiddenIface) hiddenIface.value = scopeId ? '' : String(SELECTED_IFACE_ID ?? '');
    }
  }

  if (updateBulk) {
    const bulkModal = document.getElementById('bulk-modal');
    const bulkIfaceSel =
      document.getElementById('bulk-iface') ||
      bulkModal?.querySelector('select[name="iface"]') ||
      bulkModal?.querySelector('select[name="iface_id"]');

    if (bulkIfaceSel) {
      const prev = bulkIfaceSel.value || (SELECTED_IFACE_ID != null ? String(SELECTED_IFACE_ID) : null);

      bulkIfaceSel.innerHTML = IFACES
        .map(i => `<option value="${i.id}">${i.name ?? i.id}</option>`)
        .join('');

      const chosen =
        (prev && [...bulkIfaceSel.options].some(o => o.value === String(prev))) ? String(prev) :
        (newSel != null) ? String(newSel) :
        (bulkIfaceSel.options[0]?.value || '');

      if (chosen) bulkIfaceSel.value = chosen;

      bulkIfaceSel.addEventListener('change', () => {
        const iface = getIfaceById(bulkIfaceSel.value);
        if (iface && typeof refreshBulkIface === 'function') {
          refreshBulkIface(iface);
        }
      });

      const iface0 = getIfaceById(bulkIfaceSel.value);
      if (iface0 && typeof refreshBulkIface === 'function') {
        refreshBulkIface(iface0);
      }
    }

    if (typeof bulkAvailability === 'function') bulkAvailability();
  }
}
window.refreshInterfacesUI = refreshInterfacesUI;

  let IFACES = [];               
  let SELECTED_IFACE_ID = null;   
  let SELECTED_IFACE_NAME = null; 
  let peersFetchAbort = null;

  function findIfaceById(id) { return IFACES.find(i => String(i.id) === String(id)); }
  function setIfaceById(id, opts = {}) {
  const o = opts || {};
  const fromUser = !!o.fromUser;
  const force    = !!o.force;

  const key = String(id);
  const wasSame = (SELECTED_IFACE_ID != null && String(SELECTED_IFACE_ID) === key);

  if (wasSame && fromUser && !force) {
    if (typeof updateActiveInterface === 'function') updateActiveInterface();
    return;
  }

  SELECTED_IFACE_ID = key;

  const iface = (typeof findIfaceById === 'function')
    ? findIfaceById(key)
    : (Array.isArray(IFACES) ? IFACES.find(i => String(i.id) === key) : null);

  SELECTED_IFACE_NAME = iface ? (iface.name || null) : null;

  try { localStorage.setItem('selected_iface_id', String(SELECTED_IFACE_ID)); } catch (_) {}

  if (typeof updateActiveInterface === 'function') updateActiveInterface();

  try { pagination.page = 1; savePagination?.(); } catch (_) {}

  const hiddenIface = document.getElementById('create-iface-id');
  if (hiddenIface) hiddenIface.value = getScopeId() ? '' : String(SELECTED_IFACE_ID);

  if (iface && typeof refreshDefaultIface === 'function') {
    const ep = document.querySelector('#peer-modal input[name="endpoint"]');
    if (ep && ep.dataset.userEdited !== '1') refreshDefaultIface(iface);
  }

  if (iface && typeof refreshBulkIface === 'function') {
    const epBulk = document.querySelector('#bulk-endpoint');
    if (epBulk && epBulk.dataset.userEdited !== '1') refreshBulkIface(iface);
  }

  const addrSel = document.querySelector('#peer-modal #create-address-select, #peer-modal select[name="address"]');
  if (addrSel && iface?.available_ips) {
    setCreateAddressOptions(iface.available_ips || []);
  }

  if (fromUser && typeof refreshPeers === 'function') {
    const cont = document.querySelector('.peers-container');
    peersLoading(true, `Loading ${iface?.name || 'interface'}…`, 'Refreshing peers for the selected interface.');
    if (cont) {
      cont.innerHTML = '';
      renderPeers(cont, 1);
    }
    refreshPeers({ abortPrev: true, forceLoading: true });
  } else {
    applyPagi?.();
  }
}

function makeIfaceBar() {
  const host = $('#iface-bar');
  if (!host) return;

  if (!IFACES.length) {
    host.innerHTML = `
      <div class="iface-empty">
        <i class="fas fa-circle-info"></i>
        No interfaces found in this scope.
      </div>
    `;
    return;
  }

  host.innerHTML = `
    <div class="iface-toolbar-label" aria-hidden="true">
      <i class="fas fa-network-wired"></i><span>Interface</span>
    </div>
    ${IFACES.map(x => `
      <button type="button"
              class="iface-btn"
              data-id="${x.id}"
              aria-pressed="false"
              aria-label="Select interface ${x.name}">
        <span class="iface-dot ${x.is_up === true ? 'up' : (x.is_up === false ? 'down' : '')}" title="${x.is_up === true ? 'Interface up' : (x.is_up === false ? 'Interface down' : 'Interface status unknown')}"></span>
        <span class="iface-name">${x.name}</span>
      </button>`).join('')}
  `;

  if (!host.dataset.wired) {
    host.dataset.wired = '1';
    host.addEventListener('click', (e) => {
      const b = e.target.closest('.iface-btn');
      if (!b) return;
      setIfaceById(b.dataset.id, { fromUser: true });
    });
  }

  const saved = localStorage.getItem('selected_iface_id');
  const id = (saved && IFACES.some(i => String(i.id) === String(saved)))
         ? saved
         : (IFACES[0]?.id);

  if (id != null) setIfaceById(id, { force: true });
}


function updateActiveInterface() {
  const chip = $('#active-iface-chip');
  const iface = findIfaceById(SELECTED_IFACE_ID);

  document.querySelectorAll('.iface-btn').forEach(btn => {
    const on = iface && String(btn.dataset.id) === String(iface.id);
    btn.setAttribute('aria-pressed', on ? 'true' : 'false');
    btn.classList.toggle('is-active', !!on);
  });

  if (chip && iface) {
    const isUp = (typeof iface.is_up === 'boolean') ? iface.is_up : null;
    const dot = isUp != null
      ? `<span class="iface-dot ${isUp ? 'up' : 'down'}" title="${isUp ? 'Interface up' : 'Interface down'}"></span>`
      : `<span class="iface-dot" title="Interface status unknown"></span>`;
    const state = isUp == null ? 'Unknown' : (isUp ? 'Up' : 'Down');
    const port = iface.listen_port ?? '–';

    chip.innerHTML = `
      ${dot}
      <span class="iface-active-copy">
        <strong>${iface.name}</strong>
        <small>${state} · :${port}</small>
      </span>
    `;
    chip.style.display = 'inline-flex';

    const row = chip.parentElement;
    if (row) {
      row.classList.add('iface-active-row');
      let tgl = row.querySelector('#iface-toggle-btn');
      if (!tgl) {
        tgl = document.createElement('button');
        tgl.id = 'iface-toggle-btn';
        tgl.type = 'button';
        tgl.className = 'iface-action-btn';
        row.appendChild(tgl);
      }

      tgl.innerHTML = iface.is_up
        ? `<i class="fas fa-power-off" aria-hidden="true"></i><span>Disable</span>`
        : `<i class="fas fa-play" aria-hidden="true"></i><span>Enable</span>`;
      tgl.dataset.intent = iface.is_up ? 'down' : 'up';
      tgl.disabled = false;

      let del = row.querySelector('#iface-delete-btn');
      if (!del) {
        del = document.createElement('button');
        del.id = 'iface-delete-btn';
        del.className = 'iface-action-btn danger';
        del.type = 'button';
        row.appendChild(del);
      }

      del.innerHTML = `<i class="fas fa-trash" aria-hidden="true"></i><span>Delete</span>`;
      del.disabled = false;
      del.title = `Delete interface ${iface.name}`;
    }
  } else if (chip) {
    chip.style.display = 'none';
    const row = chip.parentElement;
    row?.classList.remove('iface-active-row');
    row?.querySelector('#iface-toggle-btn')?.remove();
    row?.querySelector('#iface-delete-btn')?.remove();
  }

  const createBtn = $('#create-peer-btn');
  if (createBtn && iface) {
    createBtn.innerHTML = `<i class="fas fa-plus"></i> Create peer <span class="btn-mini-on">${iface.name}</span>`;
  }
}
async function ifaceToggle(e) {
  const btn = e.target.closest('#iface-toggle-btn');
  if (!btn) return;

  const iface = findIfaceById(SELECTED_IFACE_ID);
  if (!iface) return;

  const goingDown = (btn.dataset.intent === 'down');
  btn.disabled = true;

  const scopeId = getScopeId();
  let path;
  if (scopeId) {

    path = `/api/nodes/${encodeURIComponent(scopeId)}/iface/${encodeURIComponent(iface.name)}/${goingDown ? 'down' : 'up'}`;
  } else {
    
    path = `/api/iface/${encodeURIComponent(iface.id)}/${goingDown ? 'disable' : 'enable'}`;
  }

  const loader = toastSafe((goingDown ? 'Disabling' : 'Enabling') + ' interface…', 'info', true);
  try {
    const r = await fetch(path, { method: 'POST', credentials: 'same-origin' });
    if (!r.ok) throw new Error('HTTP ' + r.status);

    await refreshInterfacesUI({ keepSelection: true, updateCreate: true, updateBulk: true });
    updateActiveInterface?.();
    bulkOptions?.();
    bulkAvailability?.();
    refreshPeers?.({ abortPrev: true });

    toastSafe(goingDown ? 'Interface disabled' : 'Interface enabled', 'success');
  } catch (err) {
    console.error(err);
    toastSafe('Interface toggle failed', 'error');
  } finally {
    loader?.classList?.add('hide');
    setTimeout(() => loader?.remove?.(), 500);
    btn.disabled = false;
  }
}
async function ifaceDelete(e) {
  const btn = e.target.closest('#iface-delete-btn');
  if (!btn) return;

  const iface = findIfaceById(SELECTED_IFACE_ID);
  if (!iface) return;

  const scopeId = getScopeId();
  const isNode = !!scopeId;

  btn.disabled = true;
  const loader = toastSafe('Checking interface before deletion…', 'info', true);

  async function sendDelete(deletePeers) {
    const url = isNode
      ? `/api/nodes/${encodeURIComponent(scopeId)}/iface/${encodeURIComponent(iface.name)}`
      : `/api/iface/${encodeURIComponent(iface.id)}`;

    const r = await fetch(url, {
      method: 'DELETE',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ delete_peers: !!deletePeers }),
    });

    const j = await r.json().catch(() => ({}));
    return { r, j };
  }

  try {
    let deletePeers = false;

    if (isNode) {
      const check = await sendDelete(false);

      if (check.r.status === 409 && check.j.error === 'interface_has_peers') {
        const peerCount = Number(check.j.peer_count || 0);
        const linkCount = Number(check.j.subscription_link_count || 0);

        const ok = await confirmBox(
          `Delete node interface "${iface.name}"?\n\n` +
          `This interface has ${peerCount} peer(s).` +
          (linkCount ? `\nIt is also used by ${linkCount} subscription inbound link(s).` : '') +
          `\n\nDeleting it will remove the interface and all its peers.`
        );

        if (!ok) {
          toastSafe('Interface deletion cancelled', 'info');
          return;
        }

        deletePeers = true;
      } else {
        if (!check.r.ok) {
          throw new Error(check.j.detail || check.j.error || `HTTP ${check.r.status}`);
        }

        const ok = await confirmBox(
          `Delete node interface "${iface.name}"?\n\n` +
          `This will stop the interface and remove its WireGuard config file.`
        );

        if (!ok) {
          toastSafe('Interface deletion cancelled', 'info');
          return;
        }

        toastSafe('Node interface deleted', 'success');

        SELECTED_IFACE_ID = null;
        SELECTED_IFACE_NAME = null;

        await refreshInterfacesUI({ keepSelection: false, updateCreate: true, updateBulk: true });
        updateActiveInterface?.();
        bulkOptions?.();
        bulkAvailability?.();
        refreshPeers?.({ abortPrev: true });
        return;
      }
    } else {
      const ok = await confirmBox(
        `Delete interface "${iface.name}"?\n\n` +
        `This will stop the interface and remove its WireGuard config file.\n\n` +
        `If this interface has peers, they may also need to be deleted.`
      );

      if (!ok) return;
    }

    let { r, j } = await sendDelete(deletePeers);

    if (!r.ok) {
      throw new Error(j.detail || j.error || `HTTP ${r.status}`);
    }

    toastSafe(isNode ? 'Node interface deleted' : 'Interface deleted', 'success');

    SELECTED_IFACE_ID = null;
    SELECTED_IFACE_NAME = null;

    await refreshInterfacesUI({ keepSelection: false, updateCreate: true, updateBulk: true });
    updateActiveInterface?.();
    bulkOptions?.();
    bulkAvailability?.();
    refreshPeers?.({ abortPrev: true });

  } catch (err) {
    console.error(err);
    toastSafe('Interface delete failed: ' + (err.message || err), 'error');
  } finally {
    loader?.classList?.add('hide');
    setTimeout(() => loader?.remove?.(), 500);
    btn.disabled = false;
  }
}
//  BULK 
let bulkModal = null, bulkForm = null;

function bulkOptions() {
  if (!bulkModal) return;
  const sel = bulkModal.querySelector('#bulk-iface');
  if (!sel) return;

  let html = '';
  if (Array.isArray(window.IFACES) && IFACES.length) {
    html = IFACES.map(i => `<option value="${i.id}">${i.name}</option>`).join('');
  } else {
    const src = document.querySelector('#create-iface-id') ||
                document.querySelector('#peer-modal select[name="iface"]') ||
                document.querySelector('#peer-modal select[name="iface_id"]');
    if (src) html = src.innerHTML;
  }

  const newHash = html;
  if (sel.dataset.lastHash !== newHash) {
    const prevValue = sel.value;
    sel.innerHTML = html;
    sel.dataset.lastHash = newHash;
    if (SELECTED_IFACE_ID != null) sel.value = String(SELECTED_IFACE_ID);
    else if (prevValue) sel.value = prevValue;
  } else {
    if (SELECTED_IFACE_ID != null) sel.value = String(SELECTED_IFACE_ID);
  }
}

function bulkAvailability() {
  if (!bulkModal) return;
  const iface = (typeof findIfaceById === 'function')
    ? findIfaceById(SELECTED_IFACE_ID)
    : (Array.isArray(IFACES) ? IFACES.find(i => String(i.id) === String(SELECTED_IFACE_ID)) : null);
  if (!iface) return;

  const cntEl = bulkModal.querySelector('#bulk-available-ips');
  const free  = Array.isArray(iface.available_ips) ? iface.available_ips.length : 0;
  if (cntEl) cntEl.textContent = String(free);

  const countInput = bulkModal.querySelector('#bulk-count');
  if (countInput) {
    if (free > 0) countInput.setAttribute('max', String(free));
    else countInput.removeAttribute('max');
  }

  if (typeof refreshBulkDefaults === 'function') {
    refreshBulkDefaults(iface);
  }

  const bulkIfaceSel = bulkModal.querySelector('#bulk-iface');
  if (bulkIfaceSel && SELECTED_IFACE_ID != null) {
    bulkIfaceSel.value = String(SELECTED_IFACE_ID);
  }
}

function resolveBulkModal() {
  if (!bulkModal) bulkModal = document.querySelector('#bulk-modal');
  if (!bulkForm)  bulkForm  = document.querySelector('#bulk-form');

  if (bulkModal && !bulkModal.dataset.wired) {
    bulkModal.querySelector('#bulk-close')?.addEventListener('click', () => closeModal(bulkModal));
    bulkModal.querySelector('#bulk-close-btn')?.addEventListener('click', () => closeModal(bulkModal));
    if (!bulkForm) bulkForm = bulkModal.querySelector('#bulk-form');
    if (bulkForm) bulkForm.onsubmit = submitBulk;
    if (typeof attachEndpoint === 'function') attachEndpoint(bulkModal);
    bulkModal.dataset.wired = '1';
  }

  bulkOptions();
  bulkAvailability();
}

function itsBulkModal() {
  if (bulkModal && bulkForm) return;
  resolveBulkModal();
}

async function refreshBulkDefaults(iface) {
  const countEl = $('#bulk-available-ips');
  const count = Array.isArray(iface.available_ips) ? iface.available_ips.length : 0;
  if (countEl) countEl.textContent = String(count);

  const countInp = $('#bulk-count');
  if (countInp) {
    if (count > 0) countInp.setAttribute('max', String(count));
    else countInp.removeAttribute('max');
  }

  try {
    const r = await fetch(api('/api/endpoint_presets'), { credentials: 'same-origin' });
    if (r.ok) {
      const j = await r.json();
      const pub = j.public_ipv4 || '';
      const ep = $('#bulk-endpoint');
      if (ep && !ep.value.trim() && pub && iface.listen_port) ep.value = `${pub}:${iface.listen_port}`;
    }
  } catch {}
  const mtu = $('#bulk-mtu'); if (mtu && iface.mtu != null) mtu.value = iface.mtu;
  const dns = $('#bulk-dns'); if (dns && iface.dns) dns.value = iface.dns;
}

async function openBulk() {
  itsBulkModal();

  if (typeof refreshInterfacesUI === 'function') {
    await refreshInterfacesUI({ keepSelection: true, updateCreate: false, updateBulk: true });
  }

  resolveBulkModal?.();
  if (typeof bulkOptions === 'function') bulkOptions();
  if (typeof bulkAvailability === 'function') bulkAvailability();

  if (!bulkModal) {
    console.error('Bulk modal not found');
    toastSafe('Bulk dialog not found on page.', 'error');
    return;
  }

  const bulkIfaceSel = bulkModal.querySelector('#bulk-iface, select[name="iface"], select[name="iface_id"]');
  if (bulkIfaceSel && typeof SELECTED_IFACE_ID !== 'undefined' && SELECTED_IFACE_ID != null) {
    bulkIfaceSel.value = String(SELECTED_IFACE_ID);
  }

  const iface = (typeof findIfaceById === 'function') ? findIfaceById(SELECTED_IFACE_ID) : null;
  if (iface && typeof refreshBulkDefaults === 'function') {
    refreshBulkDefaults(iface); 
  }

  openModal(bulkModal);
  wireContainedPickers();
  if (typeof attachEndpoint === 'function') attachEndpoint(bulkModal);
}

function updateBulkChange() {
  if (!bulkModal || getComputedStyle(bulkModal).display === 'none') return;
  const iface = findIfaceById(SELECTED_IFACE_ID);
  if (!iface) return;
  const cntEl = bulkModal.querySelector('#bulk-available-ips');
  const free = Array.isArray(iface.available_ips) ? iface.available_ips.length : 0;
  if (cntEl) cntEl.textContent = String(free);
  const bulkIfaceSel = bulkModal.querySelector('#bulk-iface');
  if (bulkIfaceSel) bulkIfaceSel.value = String(SELECTED_IFACE_ID);
}

async function submitBulk(ev) {
  ev.preventDefault();

  const fd = new FormData(bulkForm);
const scopeId = getScopeId();

const ifaceSel = document.querySelector('#bulk-iface, #bulk-modal select[name="iface"], #bulk-modal select[name="iface_id"]');
const rawIfaceId = (ifaceSel && ifaceSel.value) || (typeof SELECTED_IFACE_ID !== 'undefined' ? SELECTED_IFACE_ID : '');

const iface = typeof findIfaceById === 'function' ? findIfaceById(rawIfaceId) : null;

if (!iface) {
  toastSafe('No interface selected.', 'error');
  return;
}

const ifaceId = scopeId ? rawIfaceId : Number(rawIfaceId);

if (!scopeId && !ifaceId) {
  toastSafe('No interface selected.', 'error');
  return;
}

  const avail = Array.isArray(iface.available_ips) ? iface.available_ips.length : 0;
  const asked = Number(document.querySelector('#bulk-count')?.value || 0);
  if (!asked || asked < 1) { toastSafe('Please enter how many peers to create.', 'error'); return; }
  let finalCount = asked;
  if (avail && asked > avail) {
    if (!(await confirmBox(`Only ${avail} IPs available on ${iface.name}. Create ${avail} instead?`))) return;
    finalCount = avail;
  }

  const prefixEl = document.querySelector('#bulk-prefix, #bulk-modal input[name="prefix"], #bulk-modal input[name="base_name"]');
  const prefix   = (prefixEl?.value || 'b').trim() || 'b';
  const startIdxEl = document.querySelector('#bulk-start-index, #bulk-modal input[name="start_index"]');
  const startIdx   = startIdxEl && startIdxEl.value !== '' ? Number(startIdxEl.value) : 1;

  const parseListByName = (name, legacyId) => {
    const el = document.querySelector(`#bulk-modal [name="${name}"], ${legacyId || ''}`);
    if (!el) return [];
    const raw = String(el.value || '').trim();
    if (!raw) return [];
    return raw.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
  };

  const phoneNumbers = parseListByName('phone_numbers', '#bulk-phones');
  const telegramIds  = parseListByName('telegram_ids',  '#bulk-telegrams');
  const val  = q => document.querySelector(q)?.value || '';
  const num  = q => (document.querySelector(q)?.value ? Number(document.querySelector(q).value) : null);
  const bool = q => !!document.querySelector(q)?.checked;

  const payload = {
    scope: scopeId ? 'node' : 'local',
    node_id: scopeId || null,
    iface_id: scopeId ? null : ifaceId,
    iface_name: iface.name,
    count: finalCount,
    prefix,             
    name_prefix: prefix,  
    base_name: prefix,   
    start_index: startIdx,
    allowed_ips: val('#bulk-allowed_ips, #bulk-modal [name="allowed_ips"]'),
    endpoint:    val('#bulk-endpoint,     #bulk-modal [name="endpoint"]'),
    persistent_keepalive: num('#bulk-keepalive, #bulk-modal [name="persistent_keepalive"]'),
    mtu:         num('#bulk-mtu,          #bulk-modal [name="mtu"]'),
    dns:         val('#bulk-dns,          #bulk-modal [name="dns"]'),

    data_limit_value: num('#bulk-data_limit_value, #bulk-modal [name="data_limit_value"]'),
    data_limit_unit:  val('#bulk-data_limit_unit,  #bulk-modal [name="data_limit_unit"]') || null,
    time_limit_days:  num('#bulk-time-days,        #bulk-modal [name="time_limit_days"]') || 0,
    time_limit_hours: num('#bulk-time-hours,       #bulk-modal [name="time_limit_hours"]') || 0,
    start_on_first_use: bool('#bulk-start-first,   #bulk-modal [name="start_on_first_use"]'),
    unlimited:          bool('#bulk-unlimited,     #bulk-modal [name="unlimited"]'),
    name: (fd.get('name') || '').trim(),

    phone_numbers: phoneNumbers,
    phones:        phoneNumbers, 
    telegram_ids:  telegramIds,
    telegrams:     telegramIds   
  };

  let loader;
  try {
    loader = toastSafe('Creating peers…', 'info', true);
    const res = await fetch(api('/api/peers/bulk'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const j = await res.json().catch(() => ({}));
      throw new Error(j.error || `HTTP ${res.status}`);
    }

    const json = await res.json().catch(() => null);
    toastSafe(`Created ${json?.created ?? finalCount} peers`, 'success');

    const bulkModal = document.getElementById('bulk-modal');
    if (bulkModal) bulkModal.classList.remove('open');

    if (typeof refreshInterfacesUI === 'function') {
      await refreshInterfacesUI({ keepSelection: true, updateCreate: true, updateBulk: true });
    }

    refreshPeers();

    if (json?.peers?.length) {
      console.table(json.peers.map(p => ({
        name: p.name, address: p.address, phone: p.phone_number, telegram: p.telegram_id
      })));
    }
  } catch (e) {
    console.error(e);
    toastSafe(`Bulk create failed: ${e.message || e}`, 'error');
  } finally {
    if (loader) { loader.classList.add('hide'); setTimeout(() => loader.remove(), 500); }
  }
}

(function notifyStuff(){
  if (typeof window.notify === 'function') return;

  const css = `
  .toasts{position:fixed;top:16px;right:16px;z-index:10000;display:flex;flex-direction:column;gap:8px}
  .toast{background:#111827;color:#fff;padding:10px 12px;border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.16);
         font:500 14px/1.4 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;
         opacity:.97;transition:opacity .25s,transform .25s}
  .toast.success{background:#166534}.toast.error{background:#991b1b}.toast.info{background:#1f2937}
  .toast.hide{opacity:0;transform:translateY(-4px)}
  `;
  const st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);
  const cont = document.createElement('div'); cont.className = 'toasts'; document.body.appendChild(cont);

  window.notify = function(msg, type='info', ms=2200){
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = msg;
    cont.appendChild(el);
    setTimeout(()=>{ el.classList.add('hide'); setTimeout(()=> el.remove(), 260); }, ms);
  };
})();

function bulkVisible() {
  return !!(bulkModal && window.getComputedStyle(bulkModal).display !== 'none');
}
function setCreateAddressOptions(list) {
  const addrSel = document.querySelector('#peer-modal #create-address-select, #peer-modal select[name="address"]');
  if (!addrSel) return;

  const ips = Array.isArray(list) ? list : [];

  addrSel.innerHTML = ips
    .map(ip => {
      const safe = peerEsc(ip);
      return `<option value="${safe}">${safe}</option>`;
    })
    .join('');

  // Always select the first currently available IP.
  addrSel.selectedIndex = ips.length ? 0 : -1;

  const hiddenAddr = document.getElementById('create-address');
  if (hiddenAddr) hiddenAddr.value = addrSel.value || '';
}
async function refreshAddressOptions() {
  const addrSel = document.querySelector('#peer-modal #create-address-select, #peer-modal select[name="address"]');
  if (!addrSel) return;

  const scopeId = getScopeId();          
  const iface   = typeof findIfaceById === 'function' ? findIfaceById(SELECTED_IFACE_ID) : null;

  if (scopeId) {
    const list = Array.isArray(iface?.available_ips) ? iface.available_ips : [];
    setCreateAddressOptions(list);
    return;
  }

  const idNum = Number(SELECTED_IFACE_ID);
  if (idNum) {
    const r = await fetch(api(`/api/iface/${idNum}/available_ips`), { credentials: 'same-origin', cache: 'no-store' });
    if (r.ok) {
      const { available_ips } = await r.json();
      setCreateAddressOptions(available_ips || []);
    }
  }
}

async function clickList(e) {
  const btn = e.target.closest('button');
  if (!btn) return;

  if (btn.classList.contains('more-close')) {
    const card = btn.closest('.peer-card');
    if (!card) return;

    const id = String(card.dataset.id || '');
    const section = card.querySelector('.peer-more-section');
    if (section) section.hidden = true;

    const toggle = card.querySelector('.more-toggle');
    if (toggle) toggle.setAttribute('aria-expanded', 'false');

    openMore.delete(id);

    try { btn.blur?.(); } catch {}
    try { document.activeElement?.blur?.(); } catch {}

    card.classList.add('force-hide-actions');

    const onLeave = () => {
      card.classList.remove('force-hide-actions');
      card.removeEventListener('mouseleave', onLeave);
    };
    card.addEventListener('mouseleave', onLeave);

    setTimeout(() => card.classList.remove('force-hide-actions'), 250);

    e.stopPropagation();
    return;
  }

  if (btn.classList.contains('more-toggle')) {
    const card = btn.closest('.peer-card');
    if (!card) return;

    const id = String(card.dataset.id || '');
    const section = card.querySelector('.peer-more-section');
    if (!section) return;

    const willOpen = section.hidden;

    if (willOpen) closeSections(id);

    section.hidden = !willOpen;
    btn.setAttribute('aria-expanded', willOpen ? 'true' : 'false');

    if (willOpen) openMore.add(id);
    else openMore.delete(id);

    e.stopPropagation();
    return;
  }

  const id = btn.dataset.id || btn.closest('.peer-card')?.dataset.id;
  if (!id) return;

  const scopeId = getScopeId();
  const p = findPeer(id);

  const nodeFunc = act => {
    if (!p || !p.public_key) { toastSafe('Missing peer key', 'error'); return null; }
    return `/peer/${encodeURIComponent(p.public_key)}/${act}`; 
  };
  const localFunc = act => `/peer/${id}/${act}`;

  if (btn.classList.contains('user-link-btn')) return userLink(e, id);
  if (btn.classList.contains('edit-btn'))      return openEdit(id);
  if (btn.classList.contains('logs-btn'))      return openLogs(id);

  if (btn.classList.contains('download-btn')) {
    const a = document.createElement('a');
    a.href = apiPeerPath(id, '/config?download=1');
    a.target = '_blank';
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    a.remove();
    return;
  }

  if (btn.classList.contains('qr-btn')) return openQR(id);

  if (btn.classList.contains('enable-btn')) {
    const path = scopeId ? nodeFunc('enable') : localFunc('enable');
    if (!path) return;
    return postEdit(path, 'Peer enabled', 'Enable failed');
  }

  if (btn.classList.contains('disable-btn')) {
    const path = scopeId ? nodeFunc('disable') : localFunc('disable');
    if (!path) return;
    return postEdit(path, 'Peer disabled', 'Disable failed');
  }

  if (btn.classList.contains('reset-data-btn')) {
  const path = scopeId
    ? nodeFunc('reset_data')
    : localFunc('reset_data');

  if (!path) return;

  try {
    const r = await fetch(apiPath(path), {
      method: 'POST',
      credentials: 'same-origin'
    });

    if (!r.ok) throw new Error('HTTP ' + r.status);

    toastSafe('Data reset', 'success');
    refreshPeers?.({ abortPrev: true });
  } catch (err) {
    console.error(err);
    toastSafe('Reset failed', 'error');
  }

  return;
}

if (btn.classList.contains('reset-timer-btn')) {
  const path = scopeId
    ? nodeFunc('reset_timer')
    : localFunc('reset_timer');

  if (!path) return;

  try {
    const r = await fetch(apiPath(path), {
      method: 'POST',
      credentials: 'same-origin'
    });

    if (!r.ok) throw new Error('HTTP ' + r.status);

    toastSafe('Timer reset', 'success');
    refreshPeers?.({ abortPrev: true });
  } catch (err) {
    console.error(err);
    toastSafe('Reset failed', 'error');
  }

  return;
}

if (btn.classList.contains('reset-timer-btn')) {
  const path = scopeId
    ? nodeFunc('reset_timer')
    : localFunc('reset_timer');

  if (!path) return;

  try {
    const r = await fetch(apiPath(path), {
      method: 'POST',
      credentials: 'same-origin'
    });

    if (!r.ok) throw new Error('HTTP ' + r.status);

    toastSafe('Timer reset', 'success');
    refreshPeers?.({ abortPrev: true });
  } catch (err) {
    console.error(err);
    toastSafe('Reset failed', 'error');
  }

  return;
}

  if (btn.classList.contains('reset-timer-btn')) {
    try {
      const r = await fetch(api(`/api/peer/${encodeURIComponent(id)}/reset_timer`), {
        method: 'POST',
        credentials: 'same-origin'
      });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      toastSafe('Timer reset', 'success');
      refreshPeers?.({ abortPrev: true });
    } catch (err) {
      console.error(err);
      toastSafe('Reset failed', 'error');
    }
    return;
  }

  if (btn.classList.contains('delete-btn')) {
    if (await confirmBox('Really delete this peer?')) {
      const loader = toastSafe('Deleting peer…', 'info', true);
      try {
        const url = scopeId
          ? apiPath(`/peer/${encodeURIComponent(p?.public_key || '')}`)
          : `/api/peer/${encodeURIComponent(id)}`;

        const r = await fetch(url, { method: 'DELETE', credentials: 'same-origin' });
        if (!r.ok) throw new Error('HTTP ' + r.status);

        toastSafe('Peer deleted', 'success');

        await refreshInterfacesUI?.({ keepSelection: true, updateCreate: true, updateBulk: true });
        resolveBulkModal?.();
        bulkOptions?.();
        bulkAvailability?.();
        refreshPeers?.({ abortPrev: true });
      } catch (err) {
        console.error(err);
        toastSafe('Delete failed', 'error');
      } finally {
        if (loader) {
          loader.classList.add('hide');
          setTimeout(() => loader.remove(), 500);
        }
      }
    }
  }
}

function attachOpen(container) { container.addEventListener('auxclick', (e) => handleClick(e)); }
window.addEventListener('DOMContentLoaded', async () => {
  try { if (window.peerScopeReady) await window.peerScopeReady; } catch (_) {}
  await getPresets(); 
(function wireCreateFormSubmit(){
  const form = document.querySelector('#create-peer-form'); 
  if (!form) return;

  const selectEl  = document.querySelector('#create-address-select');
  const hiddenAddr = document.querySelector('#create-address');

  if (selectEl && hiddenAddr) {
    selectEl.addEventListener('change', () => hiddenAddr.value = selectEl.value);
    setTimeout(() => { hiddenAddr.value = selectEl.value || ''; }, 0);
  }

  form.addEventListener('submit', async (e) => {
    const scopeId = getScopeId();
    if (!scopeId) return;

    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    if (form.dataset.nodeSubmitting === '1') return;
    form.dataset.nodeSubmitting = '1';

    const submitBtn = form.querySelector('button[type="submit"], .btn[type="submit"]');
    if (submitBtn) submitBtn.disabled = true;                 

    const iface = findIfaceById(SELECTED_IFACE_ID);
    if (!iface) { toastSafe('No interface selected', 'error'); return; }

    const fd = new FormData(form);
    const payload = {
      name: (fd.get('name') || '').trim(),
      iface_name: iface.name,               
      address: document.getElementById('create-address')?.value || '',
      allowed_ips: (fd.get('allowed_ips') || '').trim(),
      endpoint: (fd.get('endpoint') || '').trim(),
      persistent_keepalive: fd.get('persistent_keepalive') || null,
      mtu: fd.get('mtu') || null,
      dns: (fd.get('dns') || '').trim(),
      data_limit: fd.get('data_limit') || null,
      limit_unit: fd.get('limit_unit') || null,
      time_limit_days: fd.get('time_limit_days') || null,
      time_limit_hours: fd.get('time_limit_hours') || null,
      start_on_first_use: !!fd.get('start_on_first_use'),
      unlimited: !!fd.get('unlimited'),
      phone_number: (fd.get('phone_number') || '').trim(),
      telegram_id: (fd.get('telegram_id') || '').trim()
    };

    const loader = toastSafe('Creating peer on node…', 'info', true);
    
    try {
      const addrSel = document.querySelector('#create-address-select, #peer-modal select[name="address"]');

      const r = await fetch(apiPath('/peers'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          name: (fd.get('name') || '').trim(),
          iface: SELECTED_IFACE_NAME,
          address: addrSel ? addrSel.value : '', 
          endpoint: (fd.get('endpoint') || '').trim(),
          persistent_keepalive: fd.get('persistent_keepalive') || 0,
          mtu: fd.get('mtu') || null,
          dns: (fd.get('dns') || '').trim(),
          allowed_ips: (fd.get('allowed_ips') || '0.0.0.0/0, ::/0').trim(),
          data_limit_value: Number(fd.get('data_limit') || 0),
          data_limit_unit:  fd.get('limit_unit') || 'Mi',
          time_limit_days:  Number(fd.get('time_limit_days') || 0),
          time_limit_hours: Number(fd.get('time_limit_hours') || 0),
          start_on_first_use: !!fd.get('start_on_first_use'),
          unlimited: !!fd.get('unlimited'),
          phone_number: (fd.get('phone_number') || '').trim(),
          telegram_id: (fd.get('telegram_id') || '').trim()
          }),
      });
      if (!r.ok) {
        const j = await r.json().catch(()=> ({}));
        throw new Error(j.error || ('HTTP ' + r.status));
      }

      toastSafe('Peer created', 'success');
      if (window.afterPeerCreated) { 
        await window.afterPeerCreated();
      }
      closeModal?.(document.getElementById('peer-modal'));

      await refreshInterfacesUI({ keepSelection: true, updateCreate: true, updateBulk: true });
      refreshPeers?.({ abortPrev: true });
    } catch (err) {
      console.error(err);
      toastSafe('Create failed: ' + (err.message || err), 'error');
    } finally {
  form.dataset.nodeSubmitting = '0';
  const submitBtn = form.querySelector('button[type="submit"], .btn[type="submit"]');
  if (submitBtn) submitBtn.disabled = false;

  loader?.classList.add('hide');
  setTimeout(() => loader?.remove(), 400);
}
  }, true);
})();

const scopeEl = document.getElementById('peer-scope');
if (scopeEl) {
  scopeEl.addEventListener('change', async () => {
    SELECTED_IFACE_ID = null;
    SELECTED_IFACE_NAME = null;
    try { localStorage.removeItem('selected_iface_id'); } catch {}
    const epBulk = document.querySelector('#bulk-endpoint');
    if (epBulk)   { epBulk.value   = ''; epBulk.dataset.userEdited   = '0'; }

    const cont = document.querySelector('.peers-container');
    peersLoading(true, getScopeId() ? 'Switching to node…' : 'Switching to local server…', 'Loading interfaces and peers for this scope.');
    if (cont) {
      cont.innerHTML = '';
      renderPeers(cont, 2);
    }

    try {
      await refreshInterfacesUI({ keepSelection: false, updateCreate: true, updateBulk: true });
      await refreshPeers({ abortPrev: true, forceLoading: true });
    } finally {
      peersLoading(false);
    }
  });
}
  const createModal = $('#peer-modal');
  $('#modal-close')?.addEventListener('click', () => closeModal(createModal));
  attachEndpoint(createModal);

  editModal = $('#edit-peer-modal');
  editForm  = $('#edit-peer-form');
  if (editForm) {
    $('#edit-close')?.addEventListener('click', () => closeModal(editModal));
    editForm.onsubmit = subEdit;
    attachEndpoint(editModal);
  }

  itsBulkModal(); 
  let bulkBtn  = $('#bulk-btn');
  const createBtn = $('#create-peer-btn');

  if (!bulkBtn && createBtn) {
    bulkBtn = document.createElement('button');
    bulkBtn.id = 'bulk-btn';
    bulkBtn.className = 'btn secondary';
    bulkBtn.style.marginLeft = '6px';
    bulkBtn.innerHTML = '<i class="fas fa-layer-group"></i> Bulk create';
    createBtn.after(bulkBtn);
  }

  if (bulkForm) {
    $('#bulk-close')?.addEventListener('click', () => closeModal(bulkModal));
    $('#bulk-close-btn')?.addEventListener('click', () => closeModal(bulkModal));
    bulkForm.onsubmit = submitBulk;
    if (typeof attachEndpoint === 'function') attachEndpoint(bulkModal);
  }

  await refreshInterfacesUI({ keepSelection: true, updateCreate: true, updateBulk: true });
  document.addEventListener('click', ifaceToggle);

  if (typeof SELECTED_IFACE_ID === 'undefined' || SELECTED_IFACE_ID == null) {
    if (IFACES.length) {
      const saved = localStorage.getItem('selected_iface_id');
      const defId = (saved && IFACES.some(i => String(i.id) === String(saved)))
        ? saved
        : IFACES[0].id;
      setIfaceById?.(defId);
    }
  }

  resolveBulkModal?.();

  const openBulkFresh = async (e) => {
    e?.preventDefault?.();
    await refreshInterfacesUI({ keepSelection: true, updateCreate: false, updateBulk: true });
    resolveBulkModal?.();
    if (typeof bulkOptions === 'function') bulkOptions();
    if (typeof bulkAvailability === 'function') bulkAvailability();
    openModal(bulkModal);
  };

  if (bulkBtn) bulkBtn.onclick = openBulkFresh;
  document.addEventListener('click', (e) => {
    const b = e.target.closest && e.target.closest('#bulk-btn');
    if (!b) return;
    openBulkFresh(e);
  });

  if (createBtn && createModal) {
    createBtn.onclick = async () => {
      await refreshInterfacesUI({ keepSelection: true, updateCreate: true, updateBulk: false });

      const sel = $('#create-iface-id');
      if (sel && SELECTED_IFACE_ID != null) sel.value = String(SELECTED_IFACE_ID);

      const iface = findIfaceById?.(SELECTED_IFACE_ID);
      if (iface && typeof refreshDefaultIface === 'function') {
        refreshDefaultIface(iface);
      }

      openModal(createModal);
      wireContainedPickers();
      window.createPeerModal?.();  
      attachEndpoint(createModal);
    };
  }


  function closeIfaceCreateModal() {
    const m = document.getElementById('iface-create-modal');
    if (!m) return;
    m.classList.remove('open');
    m.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('modal-open');
  }

  function openIfaceCreateModal() {
    const m = document.getElementById('iface-create-modal');
    if (!m) return;

    const usedNames = (window.IFACES || []).map(x => String(x.name || ''));
    let nextIdx = 0;
    while (usedNames.includes(`wg${nextIdx}`)) nextIdx++;

    const ports = (window.IFACES || []).map(x => Number(x.listen_port || 0)).filter(Boolean);
    let nextPort = ports.length ? Math.max(...ports) + 1 : 51820;
    if (nextPort > 65535) nextPort = 51820;

    const nameEl = document.getElementById('iface-new-name');
    const portEl = document.getElementById('iface-new-port');
    const addrEl = document.getElementById('iface-new-address');
    const dnsEl  = document.getElementById('iface-new-dns');
    const mtuEl  = document.getElementById('iface-new-mtu');

    if (nameEl && !nameEl.value) nameEl.value = `wg${nextIdx}`;
    if (portEl && !portEl.value) portEl.value = String(nextPort);
    if (addrEl && !addrEl.value) addrEl.value = `10.${77 + Math.min(nextIdx, 100)}.0.1/24`;
    if (dnsEl && !dnsEl.value) dnsEl.value = '1.1.1.1, 1.0.0.1';
    if (mtuEl && !mtuEl.value) mtuEl.value = '';

    m.classList.add('open');
    m.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');
    setTimeout(() => nameEl?.focus?.({ preventScroll: true }), 0);
  }

  async function submitIfaceCreate(e) {
    e.preventDefault();
    const form = e.currentTarget;
    const scopeId = getScopeId();
    const fd = new FormData(form);
    const payload = {
      name: (fd.get('name') || '').trim(),
      address: (fd.get('address') || '').trim(),
      listen_port: Number(fd.get('listen_port') || 0),
      dns: (fd.get('dns') || '').trim(),
      mtu: (fd.get('mtu') || '').trim() ? Number(fd.get('mtu')) : null,
      auto_up: !!fd.get('auto_up'),
    };

    if (!payload.name || !payload.address || !payload.listen_port) {
      toastSafe('Name, server address, and listen port are required', 'error');
      return;
    }

    const url = scopeId
      ? `/api/nodes/${encodeURIComponent(scopeId)}/interfaces`
      : '/api/interfaces';

    const loader = toastSafe(scopeId ? 'Creating interface on node…' : 'Creating local interface…', 'info', true);
    try {
      const r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(payload),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.detail || j.error || `HTTP ${r.status}`);

      if (j.up_error) {
        toastSafe(`Interface created, but could not start: ${j.up_error}`, 'warn', true);
      } else {
        toastSafe('Interface created', 'success');
      }

      closeIfaceCreateModal();
      await refreshInterfacesUI({ keepSelection: false, updateCreate: true, updateBulk: true });
      const createdName = j.interface?.name;
      if (createdName && Array.isArray(window.IFACES)) {
        const created = window.IFACES.find(x => String(x.name) === String(createdName));
        if (created) setIfaceById?.(created.id, { fromUser: true, force: true });
      }
      refreshPeers?.({ abortPrev: true });
    } catch (err) {
      console.error(err);
      toastSafe('Interface create failed: ' + (err.message || err), 'error', true);
    } finally {
      loader?.classList?.add?.('hide');
      setTimeout(() => loader?.remove?.(), 400);
    }
  }

  const ifaceCreateBtn = document.getElementById('create-iface-btn');
  const ifaceCreateModal = document.getElementById('iface-create-modal');
  const ifaceCreateForm = document.getElementById('iface-create-form');
  ifaceCreateBtn?.addEventListener('click', openIfaceCreateModal);
  document.addEventListener('click', ifaceDelete);
  ifaceCreateForm?.addEventListener('submit', submitIfaceCreate);
  document.getElementById('iface-create-close')?.addEventListener('click', closeIfaceCreateModal);
  document.getElementById('iface-create-cancel')?.addEventListener('click', closeIfaceCreateModal);
  ifaceCreateModal?.addEventListener('click', (e) => {
    if (e.target.classList?.contains('modal-backdrop')) closeIfaceCreateModal();
  });

  loadFilters(); loadPagination(); buildFilters();
  const peersCont = $('.peers-container');
  if (peersCont) {
    peersCont.addEventListener('click', clickList);
    attachOpen(peersCont);
  }

  refreshPeers();

});

})();

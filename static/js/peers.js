
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
  return (window.NODE_ID ? (p.public_key || p.id) : p.id);
}
function apiPeerPath(idOrPeer, suffix = '') {
  const key = (typeof idOrPeer === 'object') ? peerKey(idOrPeer) : idOrPeer;
  if (window.NODE_ID) {
    return `/api/nodes/${window.NODE_ID}/peer/${encodeURIComponent(String(key))}${suffix}`;
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
  const statusIcon = s => s === 'online' ? 'fa-check-circle' : (s === 'blocked' ? 'fa-ban' : 'fa-times-circle');
  const SEL = {
  allowed_ips:         ['#allowed_ips', '#peer-allowed-ips'],
  endpoint:            ['#endpoint', '#peer-endpoint'],
  dns:                 ['#dns', '#peer-dns'],
  mtu:                 ['#mtu', '#peer-mtu'],
  keepalive:           ['#persistent_keepalive', '#peer-keepalive'],
  data_limit_value:    ['#data_limit', '#peer-data-limit-value'],
  data_limit_unit:     ['#limit_unit', '#peer-data-limit-unit'],
  start_on_first_use:  ['#start_on_first_use', '#peer-start-first-use'],
  unlimited:           ['#unlimited', '#peer-unlimited'],
  time_days:           ['#time_limit_days', '#peer-time-days'],
  time_hours:          ['#time_limit_hours', '#peer-time-hours'],
  use_profile_toggle:  ['#use-profile-toggle'],
  save_profile_btn:    ['#save-profile-btn'],
  profile_select:      ['#profile-select'],
};

  const pick = (keys) => Array.isArray(keys) ? (keys.find(sel => !!q(sel)) || keys[0]) : keys;
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
    if (!confirm(`Delete profile “${current}”?`)) return;
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
  function toastSafe(msg, type = 'info', loading = false) {
  if (typeof window.toast === 'function') {
    try {
      const t = window.toast(msg, type, loading);

      if (t && t.classList && typeof t.classList.add === 'function') return t;

      if (t && typeof t.remove === 'function') return t;
    } catch (e) {
    }
  }

  if (!loading) console[type === 'error' ? 'error' : 'log'](msg);
  const dummy = document.createElement('div');
  dummy.className = 'hide';
  dummy.remove = () => {};
  return dummy;
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
  const limMiB  = toMiB(p.data_limit, p.limit_unit);
  const usedMiB = usedBytes(p) / 1048576;
  const rem     = Math.max(0, limMiB - usedMiB);
  return (p.status === 'blocked') ? 0 : rem;
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
  function timeBadge(p) {
  if (p.unlimited) return 'Unlimited';

  const started = itStarted(p);
  let ttl = null;

  if (started) {
    if (p.ttl_seconds != null) {
      ttl = Number(p.ttl_seconds);
    } else if (p.expires_at_ts != null) {
      ttl = Math.max(0, Number(p.expires_at_ts) - nowSec());
    }
  }

  if (!started) {
    if (p.time_limit_days) return `${fmtDaysHours(p.time_limit_days)} cap (starts on first use)`;
    return 'starts on first use';
  }

  if (ttl == null) {
    if (p.time_limit_days) return `${fmtDaysHours(p.time_limit_days)} cap`;
    return '–';
  }

  if (ttl <= 0) return 'expired';
  const d = Math.floor(ttl / 86400);
  const h = Math.floor((ttl % 86400) / 3600);
  const m = Math.floor((ttl % 3600) / 60);
  if (d > 0) return `${d}d left`;
  if (h > 0) return `${h}h left`;
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
      <button type="button" class="btn secondary" id="ep-save" title="Save current"><i class="fas fa-floppy-disk"></i></button>
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

  return `
  <div class="peer-card"
       data-id="${p.id}"
       data-status="${p.status}"
       data-name="${(p.name||'').toLowerCase()}"
       data-phone="${(p.phone_number||'').toLowerCase()}"
       data-tg="${(p.telegram_id||'').toLowerCase()}"
       data-iface="${p.iface || ''}">

    <div class="peer-main peer-main-nowrap">
      <span class="peer-index">${i + 1})</span>
      <span class="peer-name truncate">${p.name || ''}</span>

      <div class="peer-status ${p.status}">
        <i class="fas ${statusIcon(p.status)}" aria-hidden="true"></i>
        <span class="status-text">${cap(p.status)}</span>
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

      <!-- More information toggle pinned at the end of the row -->
      <div class="peer-info-wrap" data-id="${p.id}">
        <button
          type="button"
          class="more-toggle icon-only"
          data-id="${p.id}"
          title="More information"
          aria-label="More information"
          aria-expanded="${isOpen ? 'true' : 'false'}"
        >
          <i class="fas fa-circle-info" aria-hidden="true"></i>
          <span class="sr-only">More information</span>
        </button>
      </div>
    </div>

    <!-- More information box (inside the card; does not overlap other rows) -->
    <div class="peer-more-section" ${isOpen ? '' : 'hidden'}>
      <div class="peer-more-hdr">
        <div class="peer-more-title">More information</div>
        <button type="button" class="more-close icon-only" data-id="${p.id}" title="Close" aria-label="Close">
          <i class="fas fa-times" aria-hidden="true"></i>
        </button>
      </div>

      <div class="peer-more-line">
        <span class="mi-limit"><strong>Limit:</strong> ${limitStr}</span>
        <span class="sep">•</span>
        <span class="mi-days"><strong>${capLabel}:</strong> ${fmtDaysOrHours(p.time_limit_days)}${capTail}</span>
        <span class="sep">•</span>
        <span class="mi-first"><strong>First used:</strong> ${first}</span>
        <span class="sep">•</span>
        <span class="mi-created"><strong>Created:</strong> ${created}</span>
        <span class="sep">•</span>
        <span class="mi-exp"><strong>Expires:</strong> ${exp}</span>
        <span class="sep">•</span>
        <span class="mi-remain"><strong>Time remaining:</strong> ${remainTime}</span>
        <span class="sep">•</span>
        <span class="mi-total"><strong>Total usage:</strong> ${totalStr}</span>
        <span class="sep">•</span>
        <span class="mi-phone"><strong>Phone:</strong> ${p.phone_number || '–'}</span>
        <span class="sep">•</span>
        <span class="mi-tg"><strong>Telegram:</strong> ${p.telegram_id || '–'}</span>
        <span class="sep">•</span>
        <span class="mi-iface"><strong>Interface:</strong> <span class="mi-iface-name">${p.iface || '–'}</span></span>
      </div>
    </div>

    <!-- ACTIONS TOOLBAR (must remain INSIDE .peer-card) -->
    <div class="peer-actions-row">
      <div class="peer-actions" style="display:flex; gap:.6em; padding:.35rem 0 .25rem 0; width:100%; justify-content:flex-end;">
        <button class="edit-btn"        title="Edit"                 data-id="${p.id}"><i class="fas fa-pen-to-square"></i></button>
        <button class="logs-btn"        title="Logs"                 data-id="${p.id}"><i class="fas fa-list"></i></button>
        <button class="download-btn"    title="Download config"      data-id="${p.id}"><i class="fas fa-download"></i></button>
        <button class="qr-btn"          title="Show QR & download"   data-id="${p.id}"><i class="fas fa-qrcode"></i></button>
        <button class="user-link-btn"   title="User link: click to copy, Ctrl/⌘ or middle-click to open" data-id="${p.id}"><i class="fas fa-link"></i></button>
        <button class="enable-btn"      title="Enable"               data-id="${p.id}" style="${p.status==='online' ? 'display:none' : ''}"><i class="fas fa-play"></i></button>
        <button class="disable-btn"     title="Disable"              data-id="${p.id}" style="${p.status==='online' ? '' : 'display:none'}"><i class="fas fa-ban"></i></button>
        <button class="reset-data-btn"  title="Reset data"           data-id="${p.id}"><i class="fas fa-gauge-simple"></i></button>
        <button class="reset-timer-btn" title="Reset timer"          data-id="${p.id}"><i class="fas fa-clock-rotate-left"></i></button>
        <button class="delete-btn"      title="Delete"               data-id="${p.id}"><i class="fas fa-trash"></i></button>
      </div>
    </div>

  </div>`;
}

  function hover(card) {
  if (card.dataset.enhancedToolbar === '1') return;
  card.dataset.enhancedToolbar = '1';

  const toolbar = card.querySelector('.peer-actions');

  card.addEventListener('mouseenter', () => {
    if (toolbar) {
      toolbar.style.transition = 'transform .18s ease, opacity .18s ease';
      toolbar.style.transform = 'scale(1.01)';
      toolbar.style.opacity = '1';
    }
    card.style.transition = 'box-shadow .2s, transform .12s';
    card.style.transform = 'translateY(-1px)';
  });

  card.addEventListener('mouseleave', () => {
    if (toolbar) {
      toolbar.style.transform = 'scale(1)';
      toolbar.style.opacity = '.98';
    }
    card.style.transform = 'translateY(0)';
  });
}

function updateCard(card, p, i) {
  card.dataset.status = p.status;
  card.dataset.name   = (p.name || '').toLowerCase();
  card.dataset.phone  = (p.phone_number || '').toLowerCase();
  card.dataset.tg     = (p.telegram_id || '').toLowerCase();
  card.dataset.iface  = p.iface || '';

  const set = (sel, txt) => { const el = card.querySelector(sel); if (el) el.textContent = txt; };
  const setHTML = (sel, html) => { const el = card.querySelector(sel); if (el) el.innerHTML = html; };
  const started = (!p.start_on_first_use) || !!p.first_used_at_ts;

  set('.peer-index', `${i + 1})`);
  set('.peer-name', p.name || '');

  const sEl = card.querySelector('.peer-status');
  if (sEl) {
    sEl.classList.remove('online', 'offline', 'blocked');
    sEl.classList.add(p.status);
    const ic = sEl.querySelector('i'); if (ic) ic.className = `fas ${statusIcon(p.status)}`;
    const tx = sEl.querySelector('.status-text'); if (tx) tx.textContent = cap(p.status);
  }

  set('.peer-traffic .rx', String(p.rx || '0'));
  set('.peer-traffic .tx', String(p.tx || '0'));
  set('.peer-ip .address', p.address || '');

  const epStr = endpointDisplay(p);
  const wrap  = card.querySelector('.peer-ip .endpoint-wrap');
  if (wrap) {
    if (epStr) { wrap.style.removeProperty('display'); set('.peer-ip .endpoint', epStr); }
    else wrap.style.display = 'none';
  }

  const remMiB = remainingMiB(p);
  set('.peer-data .data-remaining', p.unlimited ? 'Unlimited' : fmtAmountMiB(remMiB, p.limit_unit));
  set('.peer-data .data-limit', fmtLimit(p));
  set('.peer-timer .timer-text', timeBadge(p));

  const en = card.querySelector('.enable-btn');
  const di = card.querySelector('.disable-btn');
  if (en && di) {
    if (p.status === 'online') { en.style.display = 'none'; di.style.display = 'inline-flex'; }
    else { en.style.display = 'inline-flex'; di.style.display = 'none'; }
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

  setHTML('.mi-limit',   `<strong>Limit:</strong> ${fmtLimit(p)}`);
  setHTML('.mi-days',    `<strong>${capLabel}:</strong> ${capStr}${capTail}`);
  setHTML('.mi-first',   `<strong>First used:</strong> ${first}`);
  setHTML('.mi-created', `<strong>Created:</strong> ${created}`);
  setHTML('.mi-exp',     `<strong>Expires:</strong> ${exp}`);
  setHTML('.mi-remain',  `<strong>Time remaining:</strong> ${remainTime}`);
  setHTML('.mi-total',   `<strong>Total usage:</strong> ${totalStr}`);
  setHTML('.mi-phone',   `<strong>Phone:</strong> ${p.phone_number || '–'}`);
  setHTML('.mi-tg',      `<strong>Telegram:</strong> ${p.telegram_id || '–'}`);
  setHTML('.mi-iface',   `<strong>Interface:</strong> <span class="mi-iface-name">${p.iface || '–'}</span>`);

  const bar = card.querySelector('.time-progress');
  if (bar) {
    if (!started) { bar.setAttribute('aria-hidden', 'true'); bar.style.opacity = '0.35'; }
    else { bar.removeAttribute('aria-hidden'); bar.style.opacity = ''; }
  }
  const more = card.querySelector('.peer-more-section');
  const moreBtn = card.querySelector('.more-toggle');
  const isOpen = openMore.has(String(p.id));
  if (more) more.hidden = !isOpen;
  if (moreBtn) moreBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');

  hover(card);
}

  const filters = { q: '', status: '' };
  const pagination = { page: 1, pageSize: 10 };
  function loadFilters() { try { const s = JSON.parse(localStorage.getItem('peer_filters') || '{}'); if (typeof s.q === 'string') filters.q = s.q; if (typeof s.status === 'string') filters.status = s.status; } catch {} }
  function saveFilters() { localStorage.setItem('peer_filters', JSON.stringify(filters)); }
  function loadPagination(){ try{ const s = JSON.parse(localStorage.getItem('peer_pagination')||'{}'); if (Number.isInteger(s.page)) pagination.page = s.page; if (Number.isInteger(s.pageSize)) pagination.pageSize = s.pageSize; }catch{} }
  function savePagination(){ localStorage.setItem('peer_pagination', JSON.stringify(pagination)); }

  function buildFilters() {
    let host = $('.peer-filters');
    if (!host) {
      host = document.createElement('div'); host.className = 'peer-filters';
      host.innerHTML = `
        <div style="display:flex; gap:8px; align-items:center; margin:10px 0; flex-wrap:wrap;">
          <input id="peer-filter-q" class="input" placeholder="Search name, phone, @telegram" style="flex:1 1 420px; min-width:260px;">
          <select id="peer-filter-status" class="input" style="width:180px;">
            <option value="">All statuses</option>
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
          </select>
          <label style="display:flex; align-items:center; gap:6px;">
            <span>Page size</span>
            <select id="peer-page-size" class="input" style="width:90px;">
              <option value="10">10</option><option value="25">25</option><option value="50">50</option><option value="100">100</option>
            </select>
          </label>
          <button id="peer-filter-clear" class="btn secondary">Clear</button>
        </div>`;
      const list = $('.peers-container'); if (list) list.before(host);
    }
    const q = $('#peer-filter-q', host), s = $('#peer-filter-status', host), c = $('#peer-filter-clear', host), ps = $('#peer-page-size', host);
    q.value = filters.q || ''; s.value = filters.status || ''; ps.value = String(pagination.pageSize);
    q.addEventListener('input', debounce(() => { filters.q = q.value.trim().toLowerCase(); saveFilters(); pagination.page = 1; savePagination(); applyPagi(); }, 150));
    s.addEventListener('change', () => { filters.status = s.value; saveFilters(); pagination.page = 1; savePagination(); applyPagi(); });
    c.addEventListener('click', () => { filters.q = ''; filters.status = ''; q.value = ''; s.value = ''; saveFilters(); pagination.page = 1; savePagination(); applyPagi(); });
    ps.addEventListener('change', () => { pagination.pageSize = parseInt(ps.value, 10) || 10; pagination.page = 1; savePagination(); applyPagi(); });
  }

    function matchPeer(card) {
    if (SELECTED_IFACE_NAME) {
      const name = card.querySelector('.mi-iface-name')?.textContent || card.dataset.iface || '';
      if (name !== SELECTED_IFACE_NAME) return false;
    }

    const st = filters.status, status = card.dataset.status;
    const statusOK = !st || (st === 'enabled' && status === 'online') || (st === 'disabled' && (status === 'offline' || status === 'blocked'));
    if (!statusOK) return false;
    const q = filters.q; if (!q) return true;
    const name = card.dataset.name || '', phone = card.dataset.phone || '', tg = card.dataset.tg || '';
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
      bar = document.createElement('div'); bar.id = 'peer-pagination';
      bar.style.marginTop = '10px'; bar.style.display = 'flex'; bar.style.justifyContent = 'center'; bar.style.gap = '6px';
      const list = $('.peers-container'); if (list) list.after(bar);
      bar.addEventListener('click', e => {
        const b = e.target.closest('button'); if (!b) return;
        if (b.dataset.page) { pagination.page = parseInt(b.dataset.page, 10); savePagination(); applyPagi(); }
        else if (b.dataset.nav === 'prev') { if (pagination.page > 1) { pagination.page--; savePagination(); applyPagi(); } }
        else if (b.dataset.nav === 'next') {
          const t = Math.max(1, Math.ceil(($$('.peer-card', $('.peers-container')).filter(c => c.dataset._match === '1').length) / pagination.pageSize));
          if (pagination.page < t) { pagination.page++; savePagination(); applyPagi(); }
        }
      });
    }
    const cur = pagination.page;
    const max = 7;
    let html = `<button class="btn secondary" data-nav="prev" ${cur <= 1 ? 'disabled' : ''}>Prev</button>`;
    const push = (i, a = false) => { html += `<button class="btn ${a ? '' : 'secondary'}" data-page="${i}">${i}</button>`; };
    const dot = () => { html += '<span style="padding:0 6px">…</span>'; };
    if (total <= max) { for (let i = 1; i <= total; i++) push(i, i === cur); }
    else {
      push(1, cur === 1);
      if (cur > 4) dot();
      const s = Math.max(2, cur - 2), e = Math.min(total - 1, cur + 2);
      for (let i = s; i <= e; i++) push(i, i === cur);
      if (cur < total - 3) dot();
      push(total, cur === total);
    }
    html += `<button class="btn secondary" data-nav="next" ${cur >= total ? 'disabled' : ''}>Next</button>`;
    bar.innerHTML = html;
  }

  // peers refresh
let refreshTimer = null,
    isRefreshing = false,
    firstLoad = false,
    refreshDelay = 5000,
    lastErrorAt = 0,
    peersFetchCtrl = null;

const REFRESH_TIMEOUT_MS_LOCAL = 8000;
const REFRESH_TIMEOUT_MS_NODE  = 20000;
const MAX_BACKOFF_MS = 60000;

function nextSchedule(ms) {
  if (refreshTimer) clearTimeout(refreshTimer);

  refreshTimer = setTimeout(() => refreshPeers({ quiet: true }), ms);
}

function findPeer(id) {
  return (window._peers || []).find(x => String(x.id) === String(id));
}

function peersLoading(on, title, sub) {
  const el = document.getElementById('spinner-peers');
  if (!el) return;

  const t = document.getElementById('peers-loading-title');
  const s = document.getElementById('peers-loading-sub');

  if (on) {
    if (t) t.textContent = title || 'Loading peers…';
    if (s) s.textContent = sub || 'Fetching latest state.';
    el.hidden = false;
  } else {
    el.hidden = true;
  }
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

if (!quiet) {
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

    if (!container) return;

    clearPeers(container);

    const existing = new Map(
      $$('.peer-card', container).map(c => [String(c.dataset.id || ''), c])
    );

    if (peers.length === 0) {
      container.innerHTML = `<div class="empty-peers" style="padding:16px;color:#64748b;">
        <i class="fas fa-circle-info"></i> No peers yet.
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
        const card = document.querySelector(`.peer-card[data-id="${peer.id}"]`);
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

  async function getShortLink(id) {
    const r = await fetch(api(`/api/peer/${id}/shortlink`), { credentials: 'same-origin' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    return j.url;
  }
  async function userLink(e, id) {
    try {
      const url = await getShortLink(id);
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
      const url = await getShortLink(id);
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
    qrModal = document.createElement('div'); qrModal.className = 'modal'; qrModal.id = 'qr-modal';
    qrModal.innerHTML = `
      <div class="modal-content" style="max-width:520px">
        <button class="modal-close" id="qr-close" aria-label="Close" style="position:absolute;top:10px;right:10px">&times;</button>
        <h2 style="margin-bottom:.5rem"><i class="fas fa-qrcode"></i> Peer QR</h2>
        <div id="qr-img-wrap" style="display:flex;justify-content:center;align-items:center;min-height:260px;border:1px dashed #e5e7eb;border-radius:8px;margin-bottom:8px;padding:8px"><span style="color:#666">Generating…</span></div>
        <div style="display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end; margin-top:6px;">
          <a id="qr-download" class="btn" download="peer.png"><i class="fas fa-download"></i> Download PNG</a>
          <button id="qr-copy-text" class="btn secondary"><i class="fas fa-clipboard"></i> Copy config</button>
        </div>
      </div>`;
    document.body.appendChild(qrModal);
    $('#qr-close', qrModal)?.addEventListener('click', () => closeModal(qrModal));
  }
  async function openQR(id) {
    itsQR(); openModal(qrModal);
    const wrap = $('#qr-img-wrap', qrModal); wrap.innerHTML = '<span style="color:#666">Generating…</span>';
    const dl = $('#qr-download', qrModal); dl.removeAttribute('href'); dl.removeAttribute('download');
    try {
      let r = await fetch(api(`/api/peer/${id}/config_qr`), { credentials: 'same-origin' });
      if (r.status === 501) r = await fetch(api(`/api/peer/${id}/config_qr?install=1`), { credentials: 'same-origin' });
      if (r.ok) {
        const blob = await r.blob(); const url = URL.createObjectURL(blob);
        wrap.innerHTML = `<img src="${url}" alt="QR" style="max-width:100%; height:auto">`;
        dl.href = url; dl.download = `peer-${id}.png`;
        $('#qr-copy-text', qrModal).onclick = async () => {
          const txt = await (await fetch(api(`/api/peer/${id}/config`), { credentials: 'same-origin' })).text();
          await copyTo(txt); toastSafe('Config copied to clipboard', 'success');
        };
        return;
      }
      const txt = await (await fetch(api(`/api/peer/${id}/config`), { credentials: 'same-origin' })).text();
      wrap.innerHTML = `<textarea readonly style="width:100%;height:260px;border:0;outline:none;background:#f9fafb;border-radius:8px;padding:8px">${txt}</textarea>`;
      dl.style.display = 'none';
      $('#qr-copy-text', qrModal).onclick = async () => { await copyTo(txt); toastSafe('Config copied to clipboard', 'success'); };
      toastSafe('Server QR not available. Installed? Try again.', 'error');
    } catch {
      wrap.innerHTML = '<span style="color:#e11d48">Failed to generate QR</span>';
    }
  }

  let logsModal;
  const eventIcon = { created:'fa-plus-circle', enabled:'fa-play', disabled:'fa-ban', expired:'fa-hourglass-end', limit_reached:'fa-gauge-high', edited:'fa-pen-to-square', reset_data:'fa-gauge-simple', reset_timer:'fa-clock-rotate-left', first_use:'fa-bolt' };
  function itsLogs() {
    if (logsModal) return logsModal;
    logsModal = document.createElement('div'); logsModal.className = 'modal'; logsModal.id = 'logs-modal';
    logsModal.innerHTML = `
      <div class="modal-content logs" style="max-width:760px">
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

  fetch(api(apiPeerPath(id, '/logs')), { credentials: 'same-origin' })
    .then(r => r.json())
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
            const ic = eventIcon[l.event] || 'fa-circle-info';
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
        tbody.innerHTML = rows || `<tr><td colspan="4" style="color:#64748b; padding:.75rem">No events yet</td></tr>`;
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
            $in('#logs-tbody', logsModal).innerHTML = `<tr><td colspan="4" style="color:#64748b; padding:.75rem">No events yet</td></tr>`;
          } catch {
            toastSafe('Failed to clear events', 'error');
          }
        };
      }
    })
    .catch(() => toastSafe('Failed to load logs', 'error'));

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
  confirmModal.className = 'modal';

  confirmModal.innerHTML = `
    <div class="modal-content" style="
      width: min(92vw, 420px);
      max-width: 420px;
      border-radius: 16px;
      padding: 16px 16px 14px;
    ">
      <div style="font-weight:800; margin:0 0 8px 0;">Confirm</div>

      <p id="confirm-text" style="margin:0 0 14px 0; color:#64748b; line-height:1.35"></p>

      <div style="display:flex; gap:10px; justify-content:flex-end;">
        <button id="confirm-no" class="btn secondary" type="button" style="min-width:96px;">No</button>
        <button id="confirm-yes" class="btn" type="button" style="min-width:96px;">Yes</button>
      </div>
    </div>
  `;

  document.body.appendChild(confirmModal);

  confirmText = confirmModal.querySelector('#confirm-text');
  confirmYes  = confirmModal.querySelector('#confirm-yes');
  confirmNo   = confirmModal.querySelector('#confirm-no');
}

  function openModal(m) {
  document.querySelectorAll('.modal.open').forEach(el => el.classList.remove('open'));
  if (m) {
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
  function confirmBox(msg) {
    uiConfirm();
    return new Promise(resolve => {
      confirmText.textContent = msg;
      openModal(confirmModal);
      const y = () => done(true), n = () => done(false);
      function done(ans) {
        closeModal(confirmModal);
        confirmYes.removeEventListener('click', y);
        confirmNo.removeEventListener('click', n);
        resolve(ans);
      }
      confirmYes.addEventListener('click', y);
      confirmNo.addEventListener('click', n);
      confirmModal.addEventListener('click', e => { if (e.target === confirmModal) done(false); }, { once: true });
    });
  }
function confirmBoxIn(container, msg, opts = {}) {
  const {
    title   = 'Really delete this peer?',
    yesText = 'Yes',
    noText  = 'No'
  } = opts;

  return new Promise(resolve => {
    const host = (container?.querySelector?.('.modal-content')) || container || document.body;
    if (host && getComputedStyle(host).position === 'static') host.style.position = 'relative';

    host.querySelectorAll('.cbi-wrap').forEach(w => w.remove());

    const wrap = document.createElement('div');
    wrap.className = 'cbi-wrap';
    Object.assign(wrap.style, {
      position: 'absolute',
      inset: '0',
      background: 'rgba(0,0,0,.35)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 50
    });

    const inner = document.createElement('div');
    inner.setAttribute('role', 'dialog');
    inner.setAttribute('aria-modal', 'true');
    inner.setAttribute('aria-label', title);
    inner.tabIndex = -1; 
    inner.className = 'modal-content';
    inner.style.maxWidth = '520px';
    inner.style.width = 'min(96%, 520px)';
    inner.innerHTML = `
      <h3 style="margin:0 0 .6rem 0">${title}</h3>
      <p style="margin:0 0 12px 0; color:#64748b">${msg || ''}</p>
      <div style="display:flex; gap:8px; justify-content:flex-end;">
        <button class="btn" id="cbi-yes" style="min-width:88px; display:inline-flex; justify-content:center">${yesText}</button>
        <button class="btn secondary" id="cbi-no" style="min-width:88px; display:inline-flex; justify-content:center">${noText}</button>
      </div>
    `;

    wrap.appendChild(inner);
    host.appendChild(wrap);

    const yes = inner.querySelector('#cbi-yes');
    const no  = inner.querySelector('#cbi-no');

    setTimeout(() => { inner.focus(); yes?.focus(); }, 10);

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
    const prevAddr = addrSel.value;
    addrSel.innerHTML = iface.available_ips.map(ip => `<option value="${ip}">${ip}</option>`).join('');
    if (prevAddr && [...addrSel.options].some(o => o.value === prevAddr)) addrSel.value = prevAddr;
    const hiddenAddr = document.getElementById('create-address');
    if (hiddenAddr) hiddenAddr.value = addrSel.value || '';
  }

  if (fromUser && typeof refreshPeers === 'function') {
    refreshPeers({ abortPrev: true });
  } else {
    applyPagi?.();
  }
}

function makeIfaceBar() {
  const host = $('#iface-bar');
  if (!host) return;

  host.innerHTML = IFACES.map(x => `
    <button type="button"
            class="btn secondary iface-btn"
            data-id="${x.id}"
            aria-pressed="false"
            aria-label="Select interface ${x.name}">
      <i class="fas fa-network-wired"></i> ${x.name}
      ${typeof x.is_up === 'boolean'
          ? `<span class="iface-dot ${x.is_up ? 'up' : 'down'}" title="${x.is_up ? 'Interface up' : 'Interface down'}"></span>`
          : ''}
    </button>`).join('');

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
  $$('#iface-bar .iface-btn').forEach(btn => {
    const isActive = String(btn.dataset.id) === String(SELECTED_IFACE_ID);
    btn.classList.toggle('active', isActive);
    btn.setAttribute('aria-pressed', isActive ? 'true' : 'false');
  });

  const chip = $('#active-iface-chip');
  const iface = findIfaceById(SELECTED_IFACE_ID);

  if (chip && iface) {
    const dot = (typeof iface.is_up === 'boolean')
      ? `<span class="iface-dot ${iface.is_up ? 'up' : 'down'}" title="${iface.is_up ? 'Interface up' : 'Interface down'}"></span>`
      : '';
    chip.innerHTML = `${dot}<span>Active interface:</span> <strong>${iface.name}</strong> <span class="mini">(port ${iface.listen_port ?? '–'})</span>`;
    chip.style.display = 'inline-flex';

    const row = chip.parentElement;
    if (row) {
      let tgl = row.querySelector('#iface-toggle-btn');
      if (!tgl) {
        tgl = document.createElement('button');
        tgl.id = 'iface-toggle-btn';
        tgl.className = 'btn secondary';
        tgl.style.marginLeft = '6px';
        row.appendChild(tgl);
      }
      tgl.textContent = iface.is_up ? 'Disable interface' : 'Enable interface';
      tgl.dataset.intent = iface.is_up ? 'down' : 'up';
      tgl.disabled = false;
    }
  } else if (chip) {
    chip.style.display = 'none';
  }

  const createBtn = $('#create-peer-btn');
  if (createBtn && iface) {
    createBtn.innerHTML = `<i class="fas fa-plus"></i> Create Peer on <strong>${iface.name}</strong>`;
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
    alert('Bulk dialog not found on page.');
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
  const ifaceSel = document.querySelector('#bulk-iface, #bulk-modal select[name="iface"], #bulk-modal select[name="iface_id"]');
  const ifaceId  = Number((ifaceSel && ifaceSel.value) || (typeof SELECTED_IFACE_ID !== 'undefined' ? SELECTED_IFACE_ID : 0));
  const iface    = typeof findIfaceById === 'function' ? findIfaceById(ifaceId) : null;
  if (!ifaceId || !iface) { alert('No interface selected.'); return; }

  const avail = Array.isArray(iface.available_ips) ? iface.available_ips.length : 0;
  const asked = Number(document.querySelector('#bulk-count')?.value || 0);
  if (!asked || asked < 1) { alert('Please enter how many peers to create.'); return; }
  let finalCount = asked;
  if (avail && asked > avail) {
    if (!confirm(`Only ${avail} IPs available on ${iface.name}. Create ${avail} instead?`)) return;
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
    iface_id: ifaceId,
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
async function refreshAddressOptions() {
  const addrSel = document.querySelector('#peer-modal #create-address-select, #peer-modal select[name="address"]');
  if (!addrSel) return;

  const scopeId = getScopeId();          
  const iface   = typeof findIfaceById === 'function' ? findIfaceById(SELECTED_IFACE_ID) : null;

  if (scopeId) {
    const list = Array.isArray(iface?.available_ips) ? iface.available_ips : [];
    addrSel.innerHTML = list.map(ip => `<option value="${ip}">${ip}</option>`).join('');
    const hiddenAddr = document.getElementById('create-address');
    if (hiddenAddr) hiddenAddr.value = addrSel.value || '';
    return;
  }

  const idNum = Number(SELECTED_IFACE_ID);
  if (idNum) {
    const r = await fetch(api(`/api/iface/${idNum}/available_ips`), { credentials: 'same-origin', cache: 'no-store' });
    if (r.ok) {
      const { available_ips } = await r.json();
      addrSel.innerHTML = available_ips.map(ip => `<option value="${ip}">${ip}</option>`).join('');
      const hiddenAddr = document.getElementById('create-address');
      if (hiddenAddr) hiddenAddr.value = addrSel.value || '';
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
    a.href = `/api/peer/${encodeURIComponent(id)}/config?download=1`;
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
    try {
      const r = await fetch(api(`/api/peer/${encodeURIComponent(id)}/reset_data`), {
        method: 'POST',
        credentials: 'same-origin'
      });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      toastSafe('Data reset', 'success');
      refreshPeers?.();
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
      loader?.classList.add('hide'); setTimeout(() => loader?.remove(), 400);
    }
  });
})();

const scopeEl = document.getElementById('peer-scope');
if (scopeEl) {
  scopeEl.addEventListener('change', async () => {
    SELECTED_IFACE_ID = null;
    try { localStorage.removeItem('selected_iface_id'); } catch {}
    const epBulk = document.querySelector('#bulk-endpoint');
    if (epBulk)   { epBulk.value   = ''; epBulk.dataset.userEdited   = '0'; }

    await refreshInterfacesUI({ keepSelection: false, updateCreate: true, updateBulk: true });
    refreshPeers({ abortPrev: true });
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
      window.createPeerModal?.();  
      attachEndpoint(createModal);
    };
  }

  loadFilters(); loadPagination(); buildFilters();
  const peersCont = $('.peers-container');
  if (peersCont) {
    peersCont.addEventListener('click', clickList);
    attachOpen(peersCont);
  }

  refreshPeers();

});

})();
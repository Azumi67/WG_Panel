(() => {
  const $  = (s, p=document)=>p.querySelector(s);
  const $$ = (s, p=document)=>Array.from(p.querySelectorAll(s));
  const pageToast = (msg, type='info', sticky=false) =>
    (window.toastSafe ? window.toastSafe(msg, type, sticky)
                      : (window.toast ? window.toast(msg, type) : null));

  const SOURCES = {
  app:      { label:'Application',         endpoint:'/api/app_logs',                   supportsDelete:true  },
  tg_app:   { label:'Telegram (bot app)',  endpoint:'/api/telegram/logs?format=json', supportsDelete:true  },
  tg_admin: { label:'Admins (Telegram)',   endpoint:'/api/telegram/admin_logs',       supportsDelete:true  },
  iface:    { label:'Interface',           endpoint:'/api/iface/{id}/logs',           supportsDelete:true }
};

  const state = {
    pane:'view', source:'app', ifaceId:'',
    auto:false, timer:null, settings:null,
    friendly:true, localTime:false,
    ifaceScope: 'local',
    nodeId: '' 
  };
  function humanIso(iso) {
  if (!iso) return 'Never';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;

  const diff = Date.now() - d.getTime();
  if (diff < 0) return 'Just now';

  const sec = Math.floor(diff / 1000);
  const min = Math.floor(sec / 60);
  const hr  = Math.floor(min / 60);
  const day = Math.floor(hr / 24);

  if (day > 0) return `${day} day${day > 1 ? 's' : ''} ago`;
  if (hr  > 0) return `${hr} hour${hr > 1 ? 's' : ''} ago`;
  if (min > 0) return `${min} minute${min > 1 ? 's' : ''} ago`;
  return 'Just now';
}

    try {
    const saved = JSON.parse(sessionStorage.getItem('logs-ui') || '{}');
    const validSources = Object.keys(SOURCES);

    if (saved.pane) state.pane = saved.pane;
    if (saved.source && validSources.includes(saved.source)) {
      state.source = saved.source;
    }
    if (saved.ifaceId) state.ifaceId = saved.ifaceId;
    if (typeof saved.friendly === 'boolean') state.friendly = saved.friendly;
    if (typeof saved.localTime === 'boolean') state.localTime = saved.localTime;
    if (saved.ifaceScope) state.ifaceScope = saved.ifaceScope;
    if (saved.nodeId)     state.nodeId     = saved.nodeId;
    if (typeof saved.auto === 'boolean')   state.auto = saved.auto;
  } catch {}


  function persistState(){
  sessionStorage.setItem('logs-ui', JSON.stringify({
    pane: state.pane,
    source: state.source,
    ifaceId: state.ifaceId,
    friendly: state.friendly,
    localTime: state.localTime,
    ifaceScope: state.ifaceScope,
    nodeId: state.nodeId,
    auto: state.auto
  }));
}

const escapeHtml = s => String(s).replace(/[&<>"']/g,c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
function redactSecrets(s){
  s = String(s || '');

  s = s.replace(
    /(https?:\/\/api\.telegram\.org\/bot)(\d+):([A-Za-z0-9_-]+)(\/[^\s"]*)/g,
    (_m, p1, botId, _tok, rest) => `${p1}${botId}:<redacted>${rest}`
  );

  s = s.replace(/Bearer\s+[A-Za-z0-9._-]+/gi, 'Bearer <redacted>');

  return s;
}

function stripLevels(s){
  s = String(s || '').trim();
  for (let i = 0; i < 3; i++){
    const m = s.match(/^(INFO|WARNING|ERROR|DEBUG|CRITICAL)\s*:\s*(.*)$/i);
    if (!m) break;
    s = (m[2] || '').trim();
  }
  return s;
}

function xHttpRequest(raw){
  const s = String(raw || '');
  const m = s.match(/HTTP Request:\s*([A-Z]+)\s+(\S+)\s+"HTTP\/[0-9.]+\s+(\d+)\s+([^"]+)"/i);
  if (!m) return null;

  const method = (m[1] || '').toUpperCase();
  const urlStr = (m[2] || '');
  const status = (m[3] || '');
  const reason = (m[4] || '').trim();

  let host = '';
  let path = '';
  try {
    const u = new URL(urlStr);
    host = u.host;
    path = u.pathname || '';
  } catch {

  }

  let tgMethod = '';
  if (host.includes('api.telegram.org')){
    const parts = path.split('/').filter(Boolean);
    if (parts.length >= 2 && parts[0].startsWith('bot')) tgMethod = parts[1];
  }

  const isTg = host.includes('api.telegram.org') && tgMethod;
  const main = isTg
    ? (tgMethod === 'getUpdates' ? 'Telegram polling' : 'Telegram API request')
    : 'HTTP request';

  const sub = isTg
    ? `${method} ${tgMethod} • ${status} ${reason}`.trim()
    : `${method} ${host || ''}${path ? ` ${path}` : ''} • ${status} ${reason}`.trim();

  return { main, sub };
}

function backupScheduler(raw){
  const s = String(raw || '');
  if (!/backup scheduler/i.test(s)) return null;
  if (/loop error/i.test(s)) return { main:'Backup scheduler error', sub:'Scheduler loop error (see raw details)' };
  return { main:'Backup scheduler', sub: stripLevels(s) };
}

function parseLevel(raw){
  const m = String(raw || '').match(/^\s*(INFO|WARNING|ERROR|DEBUG|CRITICAL)\s*:/i);
  return m ? m[1].toLowerCase() : '';
}

function formatMessage(x, src, rawMsg, niceMsg){
  const rawRed = redactSecrets(rawMsg).replace(/\s+/g, ' ').trim();
  const aid = String(x.admin_id || x.adminId || '').trim();
  const aun = String(x.admin_username || x.adminUsername || '').trim().replace(/^@/, '');
  const adminMeta = aid ? `Admin ${aid}${aun ? ` (@${aun})` : ''}` : '';

  const parsed =
    xHttpRequest(rawMsg) ||
    backupScheduler(rawMsg);

  const main = stripLevels(parsed?.main || niceMsg || rawMsg) || '—';
  const subParts = [];
  if (parsed?.sub) subParts.push(parsed.sub);
  if (adminMeta && src === 'tg_admin') subParts.push(adminMeta);
  const sub = subParts.join(' · ');

  const mainEsc = escapeHtml(main);
  const subEsc  = escapeHtml(sub);
  const ttlEsc  = escapeHtml(rawRed);

  return `<div class="log-msg" title="${ttlEsc}">
    <div class="log-msg__main">${mainEsc}</div>
    ${sub ? `<div class="log-msg__sub">${subEsc}</div>` : ''}
  </div>`;
}

  const isoLocalToZ = s => {
    if(!s) return '';
    const d=new Date(s);
    if(isNaN(d)) return '';
    return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,19)+'Z';
  };

  function fmtTsDisplay(ts, asLocal){
    if (!ts) return '';
    let d;
    if (/^\d{4}-\d{2}-\d{2}T/.test(ts)) d = new Date(ts);
    else if (/^\d{4}-\d{2}-\d{2} /.test(ts)) d = new Date(ts.replace(' ', 'T')+'Z');
    else if (/^\d{10,13}$/.test(String(ts))) d = new Date(Number(String(ts).padEnd(13,'0').slice(0,13)));
    else d = new Date(ts);
    if (isNaN(d)) return String(ts);

    const pad = n => String(n).padStart(2,'0');
    const y  = asLocal ? d.getFullYear()        : d.getUTCFullYear();
    const m  = pad((asLocal ? d.getMonth()      : d.getUTCMonth()) + 1);
    const dd = pad(asLocal ? d.getDate()        : d.getUTCDate());
    const hh = pad(asLocal ? d.getHours()       : d.getUTCHours());
    const mm = pad(asLocal ? d.getMinutes()     : d.getUTCMinutes());
    const ss = pad(asLocal ? d.getSeconds()     : d.getUTCSeconds());
    return `${y}-${m}-${dd} ${hh}:${mm}:${ss}` + (asLocal ? '' : 'Z');
  }

  const levelBadge = lvl => {
    const map = { error:'red', warning:'orange', warn:'orange', info:'blue', debug:'gray', heartbeat:'gray', action:'gray' };
    const key = (lvl||'info').toString().toLowerCase();
    const name = (lvl||'info').toString().toUpperCase();
    const cls = map[key] || 'gray';
    return `<span class="badge ${cls}">${name}</span>`;
  };

  const joinKV = (obj, keys) =>
    keys.filter(k => obj[k] != null && obj[k] !== '').map(k => `${k}: ${obj[k]}`).join(', ');

  function humanTgAdmin(x){
    const who = x.admin || x.user || x.by || '';
    const action = x.action || x.event || x.kind || '';
    const target = x.peer || x.name || x.peer_name || '';
    const details = x.details || x.msg || x.message || '';
    const extras = joinKV(x, ['peer_id','iface','ip','reason']);
    let base = '';
    if (action && target) base = `${action} “${target}”`;
    else if (action)      base = action;
    else                  base = details || '';
    if (who) base += ` by ${who}`;
    if (extras) base += ` (${extras})`;
    return base || details || '';
  }

  function humanTgApp(x){
    if (x.heartbeat || x.kind === 'heartbeat') {
      const n = x.n || x.seq || x.count || '';
      return `Bot heartbeat${n ? ` #${n}` : ''}`;
    }
    if (x.action && (x.admin || x.user)) return `${x.action} by ${x.admin || x.user}`;
    const route = x.route || x.path || '';
    const m = x.method || x.http_method || '';
    if (route || m) return `${m} ${route}`.trim();
    return x.msg || x.message || x.text || x.details || '';
  }

  function humanApp(x){
    const raw = (x.msg || x.message || x.text || x.details || x.raw || '').trim();
    if (!raw) return '';

    {
      const m = raw.match(/^HTTP\s+([A-Z]+)\s+(\S+)\s+(\d{3})(?:\s+([\d.:a-fA-F]+))?/);
      if (m) {
        const [, method, path, code, ip] = m;
        return `${method} ${path} → ${code}${ip ? ` (from ${ip})` : ''}`;
      }
    }

    if (/^BEGIN\b/i.test(raw))     return 'DB transaction — begin';
    if (/^COMMIT\b/i.test(raw))    return 'DB transaction — commit';
    if (/^ROLLBACK\b/i.test(raw))  return 'DB transaction — rollback';

    {
      const m = raw.match(/^\[cached since ([\d.]+)s ago\].*/i);
      if (m) return `Cache hit — fresh ${m[1]}s`;
    }

    {
      const mFrom  = raw.match(/\bFROM\s+([a-zA-Z0-9_."`]+)/i);
      const mInto  = raw.match(/\bINTO\s+([a-zA-Z0-9_."`]+)/i);
      const mTable = mFrom?.[1] || mInto?.[1];

      if (/^\s*SELECT\b/i.test(raw)) return `DB query — SELECT${mTable ? ` on ${mTable}` : ''}`;
      if (/^\s*UPDATE\b/i.test(raw)) return `DB update — ${mTable || 'table'}`;
      if (/^\s*INSERT\b/i.test(raw)) return `DB insert — ${mTable || 'table'}`;
      if (/^\s*DELETE\b/i.test(raw)) return `DB delete — ${mTable || 'table'}`;
      if (/^\s*FROM\b/i.test(raw))   return `DB query — source ${mTable || 'table'}`;

      if (/^\s*LIMIT\b/i.test(raw))  return 'DB pagination — LIMIT (placeholder)';
      if (/^\s*OFFSET\b/i.test(raw)) return 'DB pagination — OFFSET (placeholder)';
      if (/LIMIT\s*\?\s*OFFSET\s*\?/i.test(raw)) return 'DB pagination — limit/offset placeholders';
    }

    return raw;
  }

  function humanIface(x){
    const p = x.peer || x.name || '';
    if (x.event && p) return `${x.event} — ${p}`;
    if (x.action && p) return `${x.action} — ${p}`;
    return x.msg || x.message || x.text || x.raw || JSON.stringify(x);
  }

  function humanRow(x, src){
    switch (src){
      case 'tg_admin': return humanTgAdmin(x);
      case 'tg_app':   return humanTgApp(x);
      case 'iface':    return humanIface(x);
      case 'app':
      default:         return humanApp(x);
    }
  }

function setPane(p){
  state.pane = p;
  $$('#top-tabs .top-tab').forEach(b => b.classList.toggle('active', b.dataset.pane === p));
  ['view','settings','retention'].forEach(name => {
    const el = document.getElementById(`pane-${name}`);
    if (!el) return;
    const active = (name === p);
    el.classList.toggle('active', active);
    el.toggleAttribute('hidden', !active);
    el.style.display = active ? 'block' : 'none';   
  });
  persistState();
}


function buildURL() {
  const cfg = SOURCES[state.source] || SOURCES.app;
  let url = cfg.endpoint;

  if (state.source === 'iface') {
    if (state.ifaceScope === 'node') {
      const name = document.getElementById('iface-select')?.value || '';
      const nid  = state.nodeId || document.getElementById('node-select')?.value || '';
      if (!nid || !name) return '';
      url = `/api/nodes/${encodeURIComponent(nid)}/iface/${encodeURIComponent(name)}/logs`;
    } else {
      const id = state.ifaceId || document.getElementById('iface-select')?.value || '';
      if (!id) return '';
      url = `/api/iface/${encodeURIComponent(id)}/logs`;
    }
  }

  const qs = new URLSearchParams();

  const q = $('#q')?.value.trim();
  if (q) qs.set('q', q);

  const lvl = $('#level')?.value;
  if (lvl) qs.set('level', lvl);

  const from = isoLocalToZ($('#from')?.value || '');
  if (from) qs.set('from', from);

  const to   = isoLocalToZ($('#to')?.value || '');
  if (to) qs.set('to', to);

  const limit = $('#limit')?.value || '500';
  if (limit) qs.set('limit', limit);

  qs.set('_ts', Date.now().toString());

  const qsStr = qs.toString();
  return qsStr
    ? url + (url.includes('?') ? '&' : '?') + qsStr
    : url;
}

function renderizeRows(rows){
  const body = $('#logs-body'); if (!body) return;
  const arr = Array.isArray(rows) ? rows : [];
  const srcCfg = SOURCES[state.source] || SOURCES.app;

  const html = arr.map(x => {
  const tsRaw  = x.ts || x.time || x.timestamp || x.when || '';
  const tsShow = fmtTsDisplay(tsRaw, state.localTime);

  const rawMsg = String(
    x.msg || x.message || x.text ||
    (x.action ? (x.details ? `${x.action} • ${x.details}` : x.action) : '') ||
    x.details || x.raw || ''
  ).trim();

  const lvl = x.kind || x.level || parseLevel(rawMsg) || (x.action ? 'action' : 'info');

  const nice = state.friendly ? humanRow(x, state.source) : rawMsg;
  const msgShow = String(nice || rawMsg);

  return `<tr>
    <td class="mono">${escapeHtml(tsShow)}</td>
    <td>${levelBadge(lvl)}</td>
    <td>${escapeHtml(srcCfg.label)}</td>
    <td>${formatMessage(x, state.source, rawMsg, msgShow)}</td>
  </tr>`;
}).join('');


  body.innerHTML = html || `<tr><td colspan="4" class="muted">No entries</td></tr>`;
  const badge = $('#count-badge'); if (badge) badge.textContent = String(arr.length || 0);
  }

  async function getLogs(){
    const url = buildURL(); if (!url) return;
    const r = await fetch(url, { credentials:'same-origin' });
    if (!r.ok){ renderizeRows([]); return; }
    const j = await r.json().catch(()=>({}));
    renderizeRows(j.logs || j || []);
    const cfg = SOURCES[state.source] || SOURCES.app;
    $('#clear')?.toggleAttribute('disabled', !cfg.supportsDelete);
    window.dispatchEvent(new CustomEvent('logs:refreshed'));
  }

  window.uiConfirm = function({ title = "Are you sure?", body = "", okText = "OK", cancelText = "Cancel", tone = "danger" } = {}) {
    return new Promise((resolve) => {
      const root = document.getElementById('ui-confirm');
      if (!root) return resolve(confirm(title)); 
      const ttl = root.querySelector('.ui-confirm__title');
      const bdy = root.querySelector('.ui-confirm__body');
      const ok = root.querySelector('[data-act="ok"]');
      const cancel = root.querySelector('[data-act="cancel"]');

      ttl.textContent = title;
      bdy.textContent = body;
      ok.textContent = okText;
      cancel.textContent = cancelText;

      ok.classList.remove('danger','ghost');
      if (tone === 'danger') ok.classList.add('danger');

      root.hidden = false;

      const cleanup = (val) => {
        root.hidden = true;
        ok.onclick = cancel.onclick = null;
        resolve(val);
      };
      ok.onclick = () => cleanup(true);
      cancel.onclick = () => cleanup(false);
      root.onkeydown = (e) => { if (e.key === 'Escape') cleanup(false); };
      root.focus?.();
    });
  };

    async function clearLogs(){
    const cfg = SOURCES[state.source] || SOURCES.app;
    if (!cfg || !cfg.supportsDelete){
      pageToast('Clearing is not supported for this source.', 'warn');
      return;
    }

    const url = buildURL();
    if (!url){
      pageToast('No logs endpoint for this source.', 'error');
      return;
    }

    const ok = await (
      window.uiConfirm
        ? window.uiConfirm({
            title: 'Clear logs',
            body: 'This will permanently delete the logs for the current view. Continue?',
            okText: 'Clear',
            cancelText: 'Cancel',
            tone: 'danger'
          })
        : Promise.resolve(
            confirm('Clear logs?\n\nThis will permanently delete the logs for the current view.')
          )
    );

    if (!ok) return;

    const r = await fetch(url, {
      method:'DELETE',
      credentials:'same-origin'
    });

    if (!r.ok){
      pageToast('Clear failed', 'error');
      return;
    }

    getLogs();
    window.dispatchEvent(new CustomEvent('logs:cleared'));
  }



  function dlBlob(name, data, type){
    const b = new Blob([data], {type});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(b); a.download = name; a.click();
    setTimeout(()=>URL.revokeObjectURL(a.href), 400);
  }

  async function downloadCSV(){
    const url = buildURL(); if (!url) return;
    const r = await fetch(url, { credentials:'same-origin' });
    const j = await r.json().catch(()=>({}));
    const rows = j.logs || j || [];
    const csv = [
      'time,level,source,message',
      ...rows.map(x=>{
        const ts  = (x.ts || x.time || x.timestamp || '');
        const lvl = (x.kind || x.level || (x.action?'action':'info')).toUpperCase();
        const msg = redactSecrets(
          (x.msg || x.message || x.text ||
            (x.action ? (x.details?`${x.action} • ${x.details}`:x.action) : (x.details||x.raw||'')))
          ).replace(/\n/g,' ').replace(/"/g,'""');

        const srcCfg = SOURCES[state.source] || SOURCES.app;
        return `"${ts}","${lvl}","${srcCfg.label}","${msg}"`;
      })
    ].join('\n');
    dlBlob(`${state.source}_logs.csv`, csv, 'text/csv;charset=utf-8;');
    window.dispatchEvent(new CustomEvent('logs:exported', { detail:{ fmt:'CSV' } }));
  }

  async function downloadNDJSON(){
    const url = buildURL(); if (!url) return;
    const r = await fetch(url, { credentials:'same-origin' });
    const j = await r.json().catch(()=>({}));
    const rows = j.logs || j || [];
    dlBlob(`${state.source}_logs.ndjson`, (Array.isArray(rows)?rows:[]).map(o=>JSON.stringify(o)).join('\n'), 'application/x-ndjson');
    window.dispatchEvent(new CustomEvent('logs:exported', { detail:{ fmt:'NDJSON' } }));
  }

    async function loadIfaces(){
    const sel = document.getElementById('iface-select');
    if (!sel) return;

    sel.innerHTML = '';

    if (state.ifaceScope === 'node') {
      const nid = state.nodeId || document.getElementById('node-select')?.value || '';
      if (!nid) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = 'Select a node first';
        sel.appendChild(opt);
        state.ifaceId = '';
        return;
      }
    }

    let url = '/api/get-interfaces';
    if (state.ifaceScope === 'node') {
      const nid = state.nodeId || document.getElementById('node-select')?.value || '';
      if (!nid) return;
      url = `/api/nodes/${encodeURIComponent(nid)}/interfaces`;
    }

    const r = await fetch(url, { credentials:'same-origin', cache:'no-store' });
    const j = await r.json().catch(()=>({ interfaces: [] }));
    const arr = Array.isArray(j.interfaces) ? j.interfaces : [];

    sel.innerHTML = '';

    arr.forEach(it => {
      const o = document.createElement('option');
      o.value = (state.ifaceScope === 'node') ? (it.name || '') : (it.id ?? '');
      o.textContent = it.name || it.id || '';
      sel.appendChild(o);
    });

    if (state.ifaceId && arr.some(it =>
      (state.ifaceScope === 'node' ? it.name : String(it.id)) == state.ifaceId
    )) {
      sel.value = state.ifaceId;
    } else if (arr[0]) {
      sel.value = (state.ifaceScope === 'node')
        ? (arr[0].name || '')
        : (arr[0].id ?? '');
    }

    state.ifaceId = sel.value || '';
    persistState();
  }


  async function loadNodes(){
  const sel = document.getElementById('node-select');
  if (!sel) return;
  sel.innerHTML = '';
  try {

    let r = await fetch('/api/nodes', { credentials:'same-origin', cache:'no-store' });
    let j = await r.json();
    let rows = Array.isArray(j.nodes) ? j.nodes : [];

    await Promise.all(rows.map(async n => {
      try { await fetch(`/api/nodes/${encodeURIComponent(n.id)}/health`, { credentials:'same-origin', cache:'no-store' }); }
      catch {}
    }));

    r = await fetch('/api/nodes', { credentials:'same-origin', cache:'no-store' });
    j = await r.json();
    rows = Array.isArray(j.nodes) ? j.nodes : [];

    sel.innerHTML = '';
    rows.forEach(n => {
      const o = document.createElement('option');
      o.value = n.id;
      o.dataset.online = n.online ? '1' : '0';
      o.textContent = `${n.name}${n.online ? ' • online' : ' • offline'}`;
      sel.appendChild(o);
    });

    if (!state.nodeId && rows[0]) state.nodeId = String(rows[0].id);
    if (state.nodeId) sel.value = state.nodeId;
  } catch {}
}


    function sourceTab(src){
    state.source = src;
    const cfg = SOURCES[src] || SOURCES.app;

    $$('#log-tabs .tab').forEach(b =>
      b.classList.toggle('active', b.dataset.source === src)
    );

    const picker = $('#iface-picker');
    if (picker) picker.style.display = (src === 'iface') ? 'flex' : 'none';

    const chip = $('#source-chip');
    if (chip) chip.textContent = cfg.label;

    getLogs();
    persistState();
  }


  async function loadSettings(){
    const r = await fetch('/api/logs/settings', { credentials:'same-origin' });
    const j = await r.json().catch(()=>({}));

    state.settings = j || {};
    const setChecked = (sel, val) => { const el=$(sel); if (el) el.checked = !!val; };
    const setValue   = (sel, val) => { const el=$(sel); if (el) el.value = val; };

    setChecked('#s-enabled',   j.enabled);
    setChecked('#s-persist',   j.persist);
    setChecked('#s-mute-save', j.mute_save);
    setValue('#s-keep-lines',  j.keep_last_lines ?? '');

    const src = j.sources || {};
    const tgApp   = (src.tg_app ?? src.telegram ?? true);
    const tgAdmin = (src.tg_admin ?? src.telegram ?? true);

    setChecked('#s-app',      src.app    ?? true);
    setChecked('#s-tg-app',   tgApp);
    setChecked('#s-tg-admin', tgAdmin);
    setChecked('#s-iface',    src.iface  ?? true);
  }

  async function saveSettings(){
    const getChecked = sel => !!($(sel) && $(sel).checked);
    const payload = {
      enabled:         getChecked('#s-enabled'),
      persist:         getChecked('#s-persist'),
      mute_save:       getChecked('#s-mute-save'),
      keep_last_lines: Number(($('#s-keep-lines')?.value || 0)) || 0,
      sources: {
        app:      getChecked('#s-app'),
        tg_app:   getChecked('#s-tg-app'),
        tg_admin: getChecked('#s-tg-admin'),
        telegram: (getChecked('#s-tg-app') || getChecked('#s-tg-admin')),
        iface:    getChecked('#s-iface')
      }
    };

    const r = await fetch('/api/logs/settings', {
      method:'POST',
      headers:{ 'Content-Type':'application/json' },
      credentials:'same-origin',
      body: JSON.stringify(payload)
    });

    if (!r.ok) { pageToast('Failed to save settings', 'error', true); return; }

    state.settings = payload;
    pageToast('Settings saved', 'success');
    getLogs();
    window.dispatchEvent(new CustomEvent('logs:saved'));
  }

  function bindCard(onId, cardId, inputs){
    const on = document.getElementById(onId);
    const card = document.getElementById(cardId);
    const setState = () => {
      const enabled = !!on?.checked;
      card?.classList.toggle('is-off', !enabled);
      inputs.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.disabled = !enabled;
      });
    };
    on?.addEventListener('change', setState);
    setState();
  }

  function retentionToggle(){
    bindCard('ret-app-on','ret-card-app',         ['ret-app-mb','ret-app-days','ret-app-daily']);
    bindCard('ret-tgapp-on','ret-card-tgapp',     ['ret-tgapp-mb','ret-tgapp-days','ret-tgapp-daily']);
    bindCard('ret-tgadmin-on','ret-card-tgadmin', ['ret-tgadmin-mb','ret-tgadmin-days','ret-tgadmin-daily']);
    bindCard('ret-iface-on','ret-card-iface',     ['ret-iface-mb','ret-iface-days','ret-iface-daily']);
  }


async function loadRetention() {
  const r = await fetch('/api/logs/retention', { credentials: 'same-origin' });
  const j = await r.json().catch(() => ({ retention: {} }));
  const R = j.retention || {};

  const set = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.value = (val ?? '');
  };
  const on = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.checked = !!val;
  };
  const en = (o) =>
    !!(Number(o?.max_mb || 0) > 0 ||
       Number(o?.max_age_days || 0) > 0 ||
       !!o?.daily_clear);

  set('ret-app-mb',       R.app?.max_mb);
  set('ret-app-days',     R.app?.max_age_days);
  on('ret-app-daily',     R.app?.daily_clear);
  on('ret-app-on',        en(R.app));

  set('ret-tgapp-mb',     R.tg_app?.max_mb);
  set('ret-tgapp-days',   R.tg_app?.max_age_days);
  on('ret-tgapp-daily',   R.tg_app?.daily_clear);
  on('ret-tgapp-on',      en(R.tg_app));

  set('ret-tgadmin-mb',   R.tg_admin?.max_mb);
  set('ret-tgadmin-days', R.tg_admin?.max_age_days);
  on('ret-tgadmin-daily', R.tg_admin?.daily_clear);
  on('ret-tgadmin-on',    en(R.tg_admin));

  set('ret-iface-mb',     R.iface?.max_mb);
  set('ret-iface-days',   R.iface?.max_age_days);
  on('ret-iface-daily',   R.iface?.daily_clear);
  on('ret-iface-on',      en(R.iface));

  const setLast = (id, key) => {
    const el = document.getElementById(id);
    if (!el) return;
    const src = R[key] || {};
    const ts  = src.last_cleared_utc || '';
    el.textContent = humanIso(ts);   
    el.title = ts || 'Never cleared';   
  };

  setLast('ret-app-last',     'app');
  setLast('ret-tgapp-last',   'tg_app');
  setLast('ret-tgadmin-last', 'tg_admin');
  setLast('ret-iface-last',   'iface');
}


  async function saveRetention(){
    const v  = id => document.getElementById(id)?.value || '';
    const on = id => !!document.getElementById(id)?.checked;

    const pack = (base) => {
      const enabled = on(base+'-on');
      return enabled ? {
        max_mb: +v(base+'-mb')||0,
        max_age_days: +v(base+'-days')||0,
        daily_clear: on(base+'-daily')
      } : { max_mb:0, max_age_days:0, daily_clear:false };
    };

    const payload = {
      retention: {
        app:      pack('ret-app'),
        tg_app:   pack('ret-tgapp'),
        tg_admin: pack('ret-tgadmin'),
        iface:    pack('ret-iface')
      }
    };

    const r = await fetch('/api/logs/retention', {
      method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin',
      body: JSON.stringify(payload)
    });
    if (!r.ok) return pageToast('Failed to save retention', 'error', true);
    pageToast('Retention saved', 'success');
  }

  async function runBackup(source){
    const url = new URL('/api/logs/backup', location.origin);
    url.searchParams.set('source', source);
    const a = document.createElement('a');
    a.href = url.toString(); a.download = ''; a.click();
  }

  async function startAuto(){
  stopAuto();
  state.auto = true;
  await getLogs();                       
  state.timer = setInterval(getLogs, 4000);
}
function stopAuto(){
  state.auto = false;
  if (state.timer){
    clearInterval(state.timer);
    state.timer = null;
  }
  persistState();
}


  window.addEventListener('logs:applied',   () => pageToast('Filters applied',   'success'));
  window.addEventListener('logs:refreshed', () => { if (!state.auto) pageToast('Entries refreshed', 'success'); });
  window.addEventListener('logs:cleared',   () => pageToast('Logs cleared', 'success'));
  window.addEventListener('logs:exported',  (e) => pageToast(`Exported ${e.detail?.fmt || ''}`, 'success'));

  $('#top-tabs')?.addEventListener('click', e=>{
    const b = e.target instanceof HTMLButtonElement ? e.target : e.target.closest('button.top-tab');
    if (!b || !b.dataset.pane) return;
    setPane(b.dataset.pane);
  });

  $('#log-tabs')?.addEventListener('click', e=>{
    const btn = e.target instanceof HTMLButtonElement ? e.target : e.target.closest('button.tab');
    if (!btn || !btn.classList.contains('tab')) return;
    sourceTab(btn.dataset.source);
  });

    $('#iface-select')?.addEventListener('change', ()=>{
    state.ifaceId = $('#iface-select').value; getLogs(); persistState();
  });

  $('#refresh')?.addEventListener('click', getLogs);
  $('#clear')?.addEventListener('click', clearLogs);

  const exportBtn  = document.getElementById('logs-export-btn');
  const exportMenu = document.getElementById('logs-export-menu');

  if (exportBtn && exportMenu) {
    exportBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const hidden = exportMenu.hasAttribute('hidden');
      if (hidden) {
        exportMenu.removeAttribute('hidden');
        exportBtn.setAttribute('aria-expanded', 'true');
      } else {
        exportMenu.setAttribute('hidden', '');
        exportBtn.setAttribute('aria-expanded', 'false');
      }
    });

    exportMenu.addEventListener('click', (e) => {
      const item = e.target.closest('button[data-format]');
      if (!item) return;
      const fmt = item.dataset.format;
      exportMenu.setAttribute('hidden', '');
      exportBtn.setAttribute('aria-expanded', 'false');

      if (fmt === 'csv') {
        downloadCSV();
      } else if (fmt === 'ndjson') {
        downloadNDJSON();
      }
    });

    document.addEventListener('click', (e) => {
      if (!exportMenu.contains(e.target) && e.target !== exportBtn) {
        exportMenu.setAttribute('hidden', '');
        exportBtn.setAttribute('aria-expanded', 'false');
      }
    });
  }

  $('#auto-refresh')?.addEventListener('change', e=>{ if (e.target.checked) startAuto(); else stopAuto(); });
  $('#settings-save')?.addEventListener('click', saveSettings);

  document.getElementById('ret-save')?.addEventListener('click', saveRetention);
  document.getElementById('bk-app')?.addEventListener('click',   ()=>runBackup('app'));
  document.getElementById('bk-tg')?.addEventListener('click',    ()=>runBackup('telegram'));
  document.getElementById('bk-admin')?.addEventListener('click', ()=>runBackup('admin'));
  document.getElementById('bk-iface')?.addEventListener('click', ()=>runBackup('iface'));

  document.addEventListener('DOMContentLoaded', () => {
  const scopeSel = document.getElementById('iface-scope');
  const nodeSel  = document.getElementById('node-select');
  const nodeLbl  = document.getElementById('node-select-label');
  if (scopeSel) scopeSel.value = state.ifaceScope || 'local';
  if (nodeSel  && state.nodeId) nodeSel.value = state.nodeId || '';

function scopeUI(){
  const nodeMode = (state.ifaceScope === 'node');
  nodeSel?.toggleAttribute('hidden', !nodeMode);
  nodeLbl?.toggleAttribute('hidden', !nodeMode);
}
scopeUI();

scopeSel?.addEventListener('change', async () => {
  state.ifaceScope = scopeSel.value;
  persistState();
  scopeUI();
  if (state.ifaceScope === 'node') await loadNodes();
  await loadIfaces();
  getLogs();
});

nodeSel?.addEventListener('change', async () => {
  state.nodeId = nodeSel.value || '';
  persistState();
  await loadIfaces();
  getLogs();
});

    const fm = $('#friendly-mode'); if (fm) { fm.checked = !!state.friendly; }
    const lt = $('#local-time');    if (lt) { lt.checked = !!state.localTime; }
    const auto = $('#auto-refresh');
    if (auto) {
      auto.checked = !!state.auto;
      if (state.auto) startAuto();        
    }

    const thTime = $('#logs-table thead th:first-child');
    const applyTimeHdr = () => { if (thTime) thTime.textContent = (lt?.checked ? 'Time (local)' : 'Time (UTC)'); };
    applyTimeHdr();

    fm?.addEventListener('change', () => { state.friendly = !!fm.checked; persistState(); getLogs(); });
    lt?.addEventListener('change', () => { state.localTime = !!lt.checked; persistState(); applyTimeHdr(); getLogs(); });

    const toggle = $('#filters-toggle');
    const adv = document.querySelector('.filters-advanced');
    toggle?.addEventListener('click', () => {
      const open = !adv?.hasAttribute('hidden');
      if (open) {
        adv?.setAttribute('hidden', '');
        toggle.setAttribute('aria-expanded', 'false');
        toggle.querySelector('i')?.classList.remove('fa-chevron-up');
        toggle.querySelector('i')?.classList.add('fa-chevron-down');
      } else {
        adv?.removeAttribute('hidden');
        toggle.setAttribute('aria-expanded', 'true');
        toggle.querySelector('i')?.classList.remove('fa-chevron-down');
        toggle.querySelector('i')?.classList.add('fa-chevron-up');
      }
    });
  });

  function debounce(fn, ms=250){ let t; return (...a)=>{ clearTimeout(t); t=setTimeout(()=>fn(...a), ms); }; }
  const instantApply = debounce(() => getLogs(), 250);
  function bindFilters(){
    $('#q')?.addEventListener('input', instantApply);
    $('#level')?.addEventListener('change', getLogs);
    $('#limit')?.addEventListener('change', getLogs);
    $('#from')?.addEventListener('change', getLogs);
    $('#to')?.addEventListener('change', getLogs);
    $('#iface-select')?.addEventListener('change', (e)=>{ state.ifaceId = e.target.value || ''; getLogs(); });
  }

  (async function init(){
  try {

    await Promise.all([
      loadSettings(),
      loadIfaces(),
      loadRetention()
    ]);
    retentionToggle();

    if (state.ifaceScope === 'node') {
      await loadNodes();
      await loadIfaces();
    }

    bindFilters();

    const fm = JSON.parse(localStorage.getItem('logs_friendly') || 'false');
    const lt = JSON.parse(localStorage.getItem('logs_local_time') || 'false');
    $('#friendly-mode').checked = fm;
    $('#local-time').checked = lt;

    setPane('view');
    sourceTab(state.source || 'app');

  } catch (err) {
    console.error('Failed to init logs page', err);
  }
})();

})();

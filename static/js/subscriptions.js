const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function subToast(msg, type='success'){
  let box=document.getElementById('subx-toast-box');
  if(!box){ box=document.createElement('div'); box.id='subx-toast-box'; document.body.appendChild(box); }
  const t=document.createElement('div');
  t.className='subx-toast '+type;
  t.innerHTML=`<i class="fas ${type==='error'?'fa-circle-xmark':'fa-circle-check'}"></i><span>${esc(msg)}</span>`;
  box.appendChild(t);
  requestAnimationFrame(()=>t.classList.add('show'));
  setTimeout(()=>{t.classList.remove('show'); setTimeout(()=>t.remove(),260);},2600);
}
const toastOk = m => subToast(m,'success');
const toastBad = m => subToast(m,'error');

function matchBlob(x){
  return [
    x.name, x.label, x.address, x.endpoint, x.allowed_ips, x.dns,
    x.phone_number, x.telegram_id, x.status, x.iface, x.node_name, x.location_label
  ].map(v => String(v || '').toLowerCase()).join(' ');
}
function configMatchBlob(x){
  return [x.name, x.label, x.address, x.endpoint, x.allowed_ips, x.dns, x.phone_number, x.telegram_id, x.status]
    .map(v => String(v || '').toLowerCase()).join(' ');
}
function hiMatch(value, needle){
  const raw = String(value ?? '');
  const q = String(needle || '').trim();
  if(!q) return esc(raw);
  const i = raw.toLowerCase().indexOf(q.toLowerCase());
  if(i < 0) return esc(raw);
  return esc(raw.slice(0,i)) + '<mark>' + esc(raw.slice(i,i+q.length)) + '</mark>' + esc(raw.slice(i+q.length));
}

function subConfirm(opts = {}) {
  const {
    title = 'Confirm action',
    body = '',
    yesText = 'Continue',
    noText = 'Cancel',
    danger = false
  } = opts;

  return new Promise(resolve => {
    document.querySelectorAll('.subx-confirm-overlay').forEach(x => x.remove());

    const overlay = document.createElement('div');
    overlay.className = 'subx-confirm-overlay';
    overlay.innerHTML = `
      <div class="subx-confirm-card" role="dialog" aria-modal="true">
        <div class="subx-confirm-icon ${danger ? 'danger' : ''}">
          <i class="fas ${danger ? 'fa-triangle-exclamation' : 'fa-circle-question'}"></i>
        </div>
        <div class="subx-confirm-copy">
          <h3>${esc(title)}</h3>
          <p>${esc(body)}</p>
        </div>
        <div class="subx-confirm-actions">
          <button type="button" class="btn secondary" data-confirm-no>${esc(noText)}</button>
          <button type="button" class="btn ${danger ? 'danger' : ''}" data-confirm-yes>${esc(yesText)}</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    const done = ans => {
      overlay.classList.remove('show');
      setTimeout(() => overlay.remove(), 140);
      resolve(ans);
    };

    overlay.querySelector('[data-confirm-yes]')?.addEventListener('click', () => done(true), {once:true});
    overlay.querySelector('[data-confirm-no]')?.addEventListener('click', () => done(false), {once:true});
    overlay.addEventListener('click', e => {
      if (e.target === overlay) done(false);
    });

    overlay.addEventListener('keydown', e => {
      if (e.key === 'Escape') {
        e.preventDefault();
        done(false);
      }
      if (e.key === 'Enter') {
        e.preventDefault();
        done(true);
      }
    });

    requestAnimationFrame(() => {
      overlay.classList.add('show');
      overlay.querySelector('[data-confirm-yes]')?.focus();
    });
  });
}
const fmtBytes = b => { b=Number(b||0); const u=['B','KiB','MiB','GiB','TiB']; let i=0; while(b>=1024&&i<u.length-1){b/=1024;i++} return `${b.toFixed(i?2:0)} ${u[i]}`; };
function subDate(value) {
  if (!value) return 'Not used yet';
  const d = new Date(value);if (Number.isNaN(d.getTime())) {return String(value);
  }return d.toLocaleString([], {year: 'numeric',month: 'short',day: '2-digit',hour: '2-digit',minute: '2-digit',});}
function subscriptionTimeLabel(s) {if (s.unlimited) {return s.first_used_at? `Active since ${subDate(s.first_used_at)}`: 'Unlimited · not used yet';}return ttlText(s.ttl_seconds);}
if(!window.CSS) window.CSS = {}; if(!CSS.escape) CSS.escape = s => String(s).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
const ttlText = sec => {
  if (sec == null) return 'No timer';
  sec = Math.max(0, Number(sec) || 0);
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const parts = [];
  if (d) parts.push(`${d}d`);
  if (h || d) parts.push(`${h}h`);
  parts.push(`${m}m`);
  return `${parts.join(' ')} left`;
};

let MODE='new', SCOPE='all', STATUS_SCOPE='all', SEARCH='', NEW_ITEMS=[], CURRENT_ITEMS=[], SUBS=[], EDIT_ID=null, SUB_SETTINGS=null;
let SUBS_LIVE_TIMER=null, SUBS_LOADING=false, SUBS_LAST_JSON='';
let CURRENT_SELECTED = new Set();
const SUBS_REFRESH_MS = 8000;
const EXISTING_GROUP_PAGE = 36;
let EXISTING_GROUP_LIMITS = {};
function existingLimitFor(groupKey){ return EXISTING_GROUP_LIMITS[groupKey] || EXISTING_GROUP_PAGE; }
function setLiveState(text, cls=''){
  const bar = $('.subx-livebar');
  const st = $('#subx-live-state');
  if(st) st.textContent = text;
  if(bar) bar.className = 'subx-livebar' + (cls ? ' '+cls : '');
}
function nowClock(){
  try { return new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'}); }
  catch(_) { return 'now'; }
}
function detailsIsOpen(){ return $('#details-modal')?.classList.contains('open'); }
function modalIsOpen(){ return $('#sub-modal')?.classList.contains('open') || $('#sub-settings-modal')?.classList.contains('open'); }

function subxUpdateModalBodyState(){
  const anyOpen = !!document.querySelector(
    '#sub-modal.open, #details-modal.open, #sub-settings-modal.open, #label-edit-modal.open'
  );
  document.body.classList.toggle('subx-modal-open', anyOpen);
}

function openModal(){
  $('#sub-modal').classList.add('open');
  $('#sub-modal').setAttribute('aria-hidden','false');
  subxUpdateModalBodyState();
}

function closeModal(){
  $('#sub-modal').classList.remove('open');
  $('#sub-modal').setAttribute('aria-hidden','true');
  $('#sub-modal').classList.remove('manage-inbounds-mode');
  EDIT_ID=null;
  subxUpdateModalBodyState();
}

function openDetails(){
  $('#details-modal').classList.add('open');
  $('#details-modal').setAttribute('aria-hidden','false');
  subxUpdateModalBodyState();
}

function closeDetails(){
  $('#details-modal').classList.remove('open');
  $('#details-modal').setAttribute('aria-hidden','true');
  subxUpdateModalBodyState();
}

function openSettings(){
  $('#sub-settings-modal').classList.add('open');
  $('#sub-settings-modal').setAttribute('aria-hidden','false');
  subxUpdateModalBodyState();
}

function closeSettings(){
  $('#sub-settings-modal').classList.remove('open');
  $('#sub-settings-modal').setAttribute('aria-hidden','true');
  subxUpdateModalBodyState();
}

async function loadSubscriptionSettings(){
  const r = await fetch('/api/subscriptions/settings', {credentials:'same-origin'});
  SUB_SETTINGS = await r.json().catch(()=>({layout:'aurora', support:{}}));
  applySettingsToForm();
}
function applySettingsToForm(){
  const s = SUB_SETTINGS || {layout:'aurora', support:{}};
  const layout = s.layout || 'aurora';
  const radio = document.querySelector(`input[name="sub-layout"][value="${layout}"]`);
  if(radio) radio.checked = true;
  const sup = s.support || {};
  ['telegram','whatsapp','phone','email','website','instagram'].forEach(k=>{
    const el = document.getElementById('sup-'+k);
    if(el) el.value = sup[k] || '';
  });
  updateLayoutPreview(layout);
}
function collectSettingsForm(){
  const layout = document.querySelector('input[name="sub-layout"]:checked')?.value || 'aurora';
  return {
    layout,
    support: {
      telegram: $('#sup-telegram')?.value || '',
      whatsapp: $('#sup-whatsapp')?.value || '',
      phone: $('#sup-phone')?.value || '',
      email: $('#sup-email')?.value || '',
      website: $('#sup-website')?.value || '',
      instagram: $('#sup-instagram')?.value || ''
    }
  };
}
function updateLayoutPreview(layout){
  const p = $('#layout-preview');
  if(!p) return;
  p.className = 'preview-card layout-' + (layout || 'aurora');
}
async function saveSubscriptionSettings(){
  const body = collectSettingsForm();
  const r = await fetch('/api/subscriptions/settings', {
    method:'POST',
    headers:csrfHeaders(true),
    credentials:'same-origin',
    body:JSON.stringify(body)
  });
  const j = await r.json().catch(()=>({}));
  if(!r.ok){ toastBad(j.detail || j.error || 'Settings save failed.'); return; }
  SUB_SETTINGS = j.settings || body;
  toastOk('Short-link settings saved.');
  closeSettings();
}


async function loadPickers(){
  const [lr, cr] = await Promise.all([
    fetch('/api/subscriptions/locations',{credentials:'same-origin'}),
    fetch('/api/subscriptions/inbounds_catalog',{credentials:'same-origin'})
  ]);
  const lj = await lr.json().catch(()=>({}));
  const cj = await cr.json().catch(()=>({}));
  NEW_ITEMS = [];
  for(const l of (lj.local||[])) NEW_ITEMS.push({...l, pick_kind:'new'});
  for(const n of (lj.nodes||[])) for(const it of (n.interfaces||[])) NEW_ITEMS.push({...it, pick_kind:'new', node_online:n.online});
  CURRENT_ITEMS = (cj.inbounds||[]).map((x, idx)=>({...x, pick_kind:'current', __idx: idx}));
  renderPicker();
  refreshSubscriptionInternalNetworks();
}

function sourceItems(){
  const q = SEARCH.trim().toLowerCase();
  return (MODE==='new'?NEW_ITEMS:CURRENT_ITEMS).filter(x=>{
    if(!(SCOPE==='all'||x.scope===SCOPE)) return false;
    if(!q) return true;
    const blob = [
      x.name, x.label, x.location_label, x.node_name, x.iface, x.address,
      x.endpoint, x.allowed_ips, x.dns, x.status, x.listen_port, x.scope,
      x.phone_number, x.telegram_id
    ].map(v => String(v||'').toLowerCase()).join(' ');
    return blob.includes(q);
  });
}
function selectedItems(){
  if(MODE === 'current') return [...CURRENT_SELECTED].map(i => CURRENT_ITEMS[Number(i)]).filter(Boolean);
  const items=sourceItems();
  return $$('#inbound-list input:checked').map(x=>items[Number(x.value)]).filter(Boolean);
}

function groupKey(x){
  const node = x.scope === 'node' ? (x.node_name || x.location || x.label || `Node ${x.node_id || ''}`) : 'Local server';
  const iface = x.iface || 'Interface';
  return `${x.scope}|${node}|${iface}`;
}
function groupTitle(parts){
  const [scope, node, iface] = parts;
  const source = scope === 'node' ? (node || 'Node server') : 'Local server';
  return `${esc(source)} · ${esc(iface || 'Interface')}`;
}
function groupIcon(parts){
  return parts[0] === 'node' ? 'fa-server' : 'fa-house-signal';
}
function groupSourceLabel(parts){
  return parts[0] === 'node' ? 'Node' : 'Local';
}
function itemTitle(x){
  if(MODE === 'new') return `Create on ${esc(x.iface || x.label || 'interface')}`;
  return `${esc(x.name || 'Unnamed config')}`;
}
function itemSub(x){
  if (MODE === 'new') {
    const source =
      x.scope === 'node'
        ? 'Node interface'
        : 'Local interface';

    const address =
      x.address ||
      x.server_cidr ||
      'network unavailable';

    return `${source} · ${esc(address)}${
      x.listen_port
        ? ' · port ' + esc(x.listen_port)
        : ''
    }`;
  }

  return `${esc(x.address || 'no address')}${
    x.endpoint
      ? ' · ' + esc(x.endpoint)
      : ''
  }`;
}
function itemTags(x){
  const tags = [`<span class="pick-tag">${x.scope==='node'?'Node':'Local'}</span>`];
  if(MODE==='current'){
    tags.push(`<span class="pick-tag">${esc(x.status||'offline')}</span>`);
    if(x.used_bytes) tags.push(`<span class="pick-tag">${fmtBytes(x.used_bytes)}</span>`);
    if(x.phone_number) tags.push(`<span class="pick-tag">☎ ${esc(x.phone_number)}</span>`);
    if(x.telegram_id) tags.push(`<span class="pick-tag">TG ${esc(x.telegram_id)}</span>`);
    if(x.already_linked) tags.push(`<span class="pick-tag">sub #${x.subscription_id}</span>`);
    if(x.allowed_ips) tags.push(`<span class="pick-tag">${esc(x.allowed_ips)}</span>`);
  } else {
    tags.push(`<span class="pick-tag">new peer/config</span>`);
    if(x.scope==='node') tags.push(`<span class="pick-tag">${x.node_online?'online':'offline'}</span>`);
    if(x.listen_port) tags.push(`<span class="pick-tag">port ${esc(x.listen_port)}</span>`);
  }
  return tags.join('');
}
function renderCurrentRow(x, i, key, disabled){
  const contact = [x.phone_number ? `☎ ${x.phone_number}` : '', x.telegram_id ? `TG ${x.telegram_id}` : ''].filter(Boolean).join(' · ') || 'No contact';
  const linkedHere = EDIT_ID && x.subscription_id === EDIT_ID;
  const linkedOther = x.already_linked && !linkedHere;
  const info = linkedHere ? 'Already in this client' : (linkedOther ? `Already in client #${x.subscription_id}` : (x.endpoint || x.allowed_ips || x.dns || 'Ready to use'));
  const state = (x.status || 'offline').toLowerCase();
  const disabledText = linkedOther ? 'This config belongs to another client' : '';
  return `<label class="subx-existing-row ${disabled?'disabled':''}" title="${esc([x.name,x.address,contact,info].filter(Boolean).join(' · '))}">
    <input id="pick-${i}" type="checkbox" value="${i}" ${disabled?'disabled':''} data-group="${esc(key)}">
    <span class="existing-main">
      <span class="existing-name">
        <i class="fas ${x.scope==='node'?'fa-server':'fa-house-signal'}"></i>
        <b>${esc(x.name || 'Unnamed config')}</b>
        ${linkedHere ? '<em class="existing-chip current">Already here</em>' : ''}
        ${linkedOther ? '<em class="existing-chip locked">Used elsewhere</em>' : ''}
      </span>
      <span class="existing-meta">
        <span><i class="fas fa-network-wired"></i> ${esc(x.iface || 'interface')}</span>
        <span><i class="fas fa-location-crosshairs"></i> ${esc(x.address || 'no IP')}</span>
        <span><i class="fas fa-address-book"></i> ${esc(contact)}</span>
      </span>
    </span>
    <span class="existing-side">
      <span class="cfg-status ${state}">${esc(x.status || 'offline')}</span>
      <span class="existing-usage">${fmtBytes(x.used_bytes || 0)}</span>
      <small>${esc(disabledText || info)}</small>
    </span>
  </label>`;
}


function renderNewInterfaceCard(x, i, key, disabled){
  const isNode = x.scope === 'node';
  const serverName = isNode ? (x.node_name || x.location || x.label || `Node ${x.node_id || ''}`) : 'Local server';
  const online = isNode ? !!x.node_online : true;
  const statusText = isNode ? (online ? 'Node online' : 'Node offline') : 'This panel';
  return `<label class="subx-interface-card ${isNode ? 'node' : 'local'} ${disabled ? 'disabled' : ''}">
    <input id="pick-${i}" type="checkbox" value="${i}" ${disabled?'disabled':''} data-group="${esc(key)}">
    <span class="ifc-check"><i class="fas fa-check"></i></span>
    <span class="ifc-top">
      <span class="ifc-icon"><i class="fas ${isNode ? 'fa-server' : 'fa-house-signal'}"></i></span>
      <span class="ifc-title-wrap">
        <b>${esc(serverName)}</b>
        <small>${esc(isNode ? 'Remote node' : 'Local')}</small>
      </span>
      <em class="ifc-state ${online ? 'ok' : 'warn'}">${esc(statusText)}</em>
    </span>
    <span class="ifc-main">
      <span class="ifc-name"><i class="fas fa-network-wired"></i> ${esc(x.iface || x.label || 'interface')}</span>
      <span class="ifc-meta">
        ${x.listen_port ? `<span>Port ${esc(x.listen_port)}</span>` : ''}
        ${x.address ? `<span>${esc(x.address)}</span>` : ''}
        ${x.location_label ? `<span>${esc(x.location_label)}</span>` : ''}
      </span>
    </span>
  </label>`;
}


function currentGroupItems(group){
  return CURRENT_ITEMS
    .map((x, idx) => ({x, idx}))
    .filter(r => groupKey(r.x) === group);
}
function currentMainItems(){
  const q = SEARCH.trim().toLowerCase();
  return CURRENT_ITEMS.map((x, idx) => ({x, idx})).filter(({x}) => {
    if(!(SCOPE==='all'||x.scope===SCOPE)) return false;
    if(!q) return true;
    return matchBlob(x).includes(q);
  });
}
function renderSelectedCurrentTray(){
  const arr = [...CURRENT_SELECTED].map(i => CURRENT_ITEMS[Number(i)]).filter(Boolean);
  if(!arr.length) return '';
  return `<div class="subx-current-selected"><div class="subx-current-selected-head"><b>${arr.length} selected</b><button type="button" class="group-btn ghost" data-current-clear-all>Clear all</button></div><div class="subx-current-chips">${arr.map(x => {
    const idx = x.__idx;
    const src = x.scope === 'node' ? (x.node_name || 'Node') : 'Local';
    return `<span class="subx-current-chip"><input type="checkbox" id="pick-current-${idx}" data-current-hidden="1" value="${idx}" checked hidden><i class="fas fa-file-shield"></i><b>${esc(x.name || 'Unnamed')}</b><small>${esc(src)} · ${esc(x.iface || '')}</small><button type="button" data-current-remove="${idx}" aria-label="Remove selected config"><i class="fas fa-times"></i></button></span>`;
  }).join('')}</div></div>`;
}
function sourceKeyFromLocation(x){
  return groupKey({
    scope: x.scope,
    node_name: x.node_name || x.location || x.label,
    node_id: x.node_id,
    iface: x.iface || x.name || x.label
  });
}
function currentSourceEntries(){
  const q = SEARCH.trim().toLowerCase();
  const rowMap = new Map();
  CURRENT_ITEMS.forEach((x, idx) => {
    const key = groupKey(x);
    if(!rowMap.has(key)) rowMap.set(key, []);
    rowMap.get(key).push({x, idx});
  });

  const entries = [];
  const seen = new Set();
  const allSources = [...NEW_ITEMS];

  for(const src of allSources){
    if(!(SCOPE === 'all' || src.scope === SCOPE)) continue;
    const key = sourceKeyFromLocation(src);
    const rows = rowMap.get(key) || [];
    const srcBlob = [src.scope, src.node_name, src.label, src.iface, src.name, src.address, src.listen_port].map(v => String(v||'').toLowerCase()).join(' ');
    const rowBlob = rows.map(({x}) => configMatchBlob(x)).join(' ');
    if(q && !(srcBlob.includes(q) || rowBlob.includes(q))) continue;
    entries.push([key, rows, src]);
    seen.add(key);
  }

  for(const [key, rows] of rowMap.entries()){
    if(seen.has(key)) continue;
    const sample = rows[0]?.x || {};
    if(!(SCOPE === 'all' || sample.scope === SCOPE)) continue;
    const blob = [sample.scope, sample.node_name, sample.iface, sample.location_label, sample.label, ...rows.map(({x}) => configMatchBlob(x))].map(v => String(v||'').toLowerCase()).join(' ');
    if(q && !blob.includes(q)) continue;
    entries.push([key, rows, sample]);
  }

  return entries.sort((a,b) => {
    const ax = a[2] || {}, bx = b[2] || {};
    return String(ax.scope || '').localeCompare(String(bx.scope || '')) || String(ax.node_name || ax.label || '').localeCompare(String(bx.node_name || bx.label || '')) || String(ax.iface || '').localeCompare(String(bx.iface || ''));
  });
}
function renderCurrentSourceCard(key, rows, source){
  const parts = key.split('|');
  const sample = source || rows[0]?.x || {};
  const selectedCount = rows.filter(r => CURRENT_SELECTED.has(String(r.idx))).length;
  const isNode = sample.scope === 'node';
  const sourceName = isNode ? (sample.node_name || parts[1] || 'Node') : 'Local server';
  const iface = sample.iface || parts[2] || 'Interface';
  const locked = rows.filter(r => r.x.already_linked && (!EDIT_ID || r.x.subscription_id !== EDIT_ID)).length;
  const hasConfigs = rows.length > 0;
  const port = sample.listen_port ? ` · port ${esc(sample.listen_port)}` : '';
  const q = SEARCH.trim().toLowerCase();
  const matchedRows = q ? rows.filter(r => configMatchBlob(r.x).includes(q)) : rows;
  const initialQ = q && matchedRows.length ? SEARCH.trim() : '';
  const state = hasConfigs ? `${rows.length} config${rows.length===1?'':'s'}${locked ? ` · ${locked} locked` : ''}${port}` : `No existing configs${port}`;
  return `<button type="button" class="subx-current-source-card ${hasConfigs ? '' : 'empty'}" data-current-group="${esc(key)}" data-current-initial-q="${esc(initialQ)}" ${hasConfigs ? '' : 'disabled'}>
    <span class="src-top"><span class="src-icon"><i class="fas ${isNode ? 'fa-server' : 'fa-house-signal'}"></i></span><span><b>${hiMatch(sourceName, SEARCH)}</b><small>${esc(isNode ? 'Remote node' : 'Local server')}</small></span>${selectedCount ? `<em>${selectedCount} selected</em>` : ''}${q && matchedRows.length ? `<span class="src-match">${matchedRows.length} match${matchedRows.length===1?'':'es'}</span>` : ''}</span>
    <span class="src-main"><strong><i class="fas fa-network-wired"></i> ${hiMatch(iface, SEARCH)}</strong><small>${state}</small></span>
    <span class="src-foot"><span>${sample.location_label ? hiMatch(sample.location_label, SEARCH) : (hasConfigs ? 'Open to choose exact config' : 'Nothing to attach here yet')}</span><span>${hasConfigs ? 'Open picker <i class="fas fa-arrow-right"></i>' : 'Empty'}</span></span>
  </button>`;
}
function openCurrentPicker(group, initialSearch = ''){
  const allRows = currentGroupItems(group);
  if(!allRows.length) return;
  document.querySelectorAll('.subx-current-picker-overlay').forEach(x => x.remove());
  const parts = group.split('|');
  const sample = allRows[0].x || {};
  const sourceName = sample.scope === 'node' ? (sample.node_name || parts[1] || 'Node') : 'Local server';
  const iface = sample.iface || parts[2] || 'Interface';
  const overlay = document.createElement('div');
  overlay.className = 'subx-current-picker-overlay';
  overlay.innerHTML = `<div class="subx-current-picker" role="dialog" aria-modal="true">
    <div class="subx-current-picker-head">
      <div><h3><i class="fas fa-file-shield"></i> Choose existing config</h3><p>${esc(sourceName)} · ${esc(iface)} · ${allRows.length} config${allRows.length===1?'':'s'}</p></div>
      <button type="button" class="subx-current-picker-close" aria-label="Close"><i class="fas fa-times"></i></button>
    </div>
    <div class="subx-current-picker-search"><i class="fas fa-search"></i><input class="input" id="current-picker-search" placeholder="Search name, IP, phone, Telegram, endpoint…"></div>
    <div class="subx-current-picker-list" id="current-picker-list"></div>
    <div class="subx-current-picker-actions"><button type="button" class="btn secondary" data-current-select-visible><i class="fas fa-check-double"></i> Select visible</button><button type="button" class="btn secondary" data-current-clear-visible>Clear visible</button><button type="button" class="btn" data-current-done>Done</button></div>
  </div>`;
  document.body.appendChild(overlay);
  const list = overlay.querySelector('#current-picker-list');
  const search = overlay.querySelector('#current-picker-search');
  let q = String(initialSearch || '');
  if(search && q) search.value = q;
  function filteredRows(){
    const needle = q.trim().toLowerCase();
    if(!needle) return allRows;
    return allRows.filter(({x}) => configMatchBlob(x).includes(needle));
  }
  function rowHtml({x, idx}){
    const disabled = x.already_linked && (!EDIT_ID || x.subscription_id !== EDIT_ID);
    const checked = CURRENT_SELECTED.has(String(idx));
    return `<label class="subx-current-mini-row ${disabled ? 'disabled' : ''}">
      <input type="checkbox" data-current-pick="${idx}" ${checked?'checked':''} ${disabled?'disabled':''}>
      <span class="mini-main"><b>${hiMatch(x.name || 'Unnamed config', q)}</b><small>${hiMatch(x.address || 'no address', q)}${x.endpoint?' · '+hiMatch(x.endpoint, q):''}</small></span>
      <span class="mini-tags">${x.status ? `<em>${esc(x.status)}</em>` : ''}${x.phone_number ? `<em>☎ ${hiMatch(x.phone_number, q)}</em>` : ''}${x.telegram_id ? `<em>TG ${hiMatch(x.telegram_id, q)}</em>` : ''}${disabled ? '<em class="locked">Linked</em>' : ''}</span>
    </label>`;
  }
  function draw(){
    const rows = filteredRows();
    list.innerHTML = rows.length ? rows.map(rowHtml).join('') : '<div class="subx-empty" style="padding:18px"><b>No configs match this search</b><span>Try another keyword.</span></div>';
    list.querySelectorAll('[data-current-pick]').forEach(ch => ch.addEventListener('change', () => {
      const idx = String(ch.dataset.currentPick);
      if(ch.checked) CURRENT_SELECTED.add(idx); else CURRENT_SELECTED.delete(idx);
      updateSelected();
    }));
  }
  function close(){ overlay.classList.remove('show'); setTimeout(()=>{ overlay.remove(); renderPicker(); }, 120); }
  search.addEventListener('input', () => { q = search.value; draw(); });
  overlay.querySelector('[data-current-select-visible]').onclick = () => { filteredRows().forEach(({x,idx}) => { if(!(x.already_linked && (!EDIT_ID || x.subscription_id !== EDIT_ID))) CURRENT_SELECTED.add(String(idx)); }); draw(); updateSelected(); };
  overlay.querySelector('[data-current-clear-visible]').onclick = () => { filteredRows().forEach(({idx}) => CURRENT_SELECTED.delete(String(idx))); draw(); updateSelected(); };
  overlay.querySelector('[data-current-done]').onclick = close;
  overlay.querySelector('.subx-current-picker-close').onclick = close;
  overlay.addEventListener('click', e => { if(e.target === overlay) close(); });
  overlay.addEventListener('keydown', e => { if(e.key === 'Escape') close(); });
  draw();
  requestAnimationFrame(()=>{ overlay.classList.add('show'); search.focus(); });
}

function renderPicker(){
  const syncBox = $('#sync-box');
  const defaultsBox = $('#new-defaults');
  const editNote = $('#edit-inbound-note');
  const modeHelp = $('#inbound-mode-help');

  if(syncBox) syncBox.hidden = true;
  if(defaultsBox) defaultsBox.style.display = MODE === 'new' || EDIT_ID ? '' : 'none';
  if(editNote) editNote.hidden = !EDIT_ID;
  if(modeHelp){
    modeHelp.textContent = EDIT_ID
      ? 'Existing inbounds remain attached. Use this area only if you want to add another config to this client.'
      : (MODE === 'new'
        ? 'Create fresh WireGuard configs for this client on the selected local or node interfaces.'
        : 'Choose existing configs to include in this client.');
  }

  const items = sourceItems();
  const countEl = $('#picker-count');
  if(countEl) countEl.textContent = `${items.length} ${MODE==='new' ? 'interface' : 'config'}${items.length===1?'':'s'} available`;
  const hintEl = $('#picker-hint');
  if(hintEl) hintEl.textContent = MODE === 'new'
    ? 'Select one or more interfaces. A new peer/config will be created for each selected interface.'
    : 'Search by peer name, IP, phone, Telegram, endpoint, or status. Then open the matching Local/Node source to choose the exact config.';

  if(!items.length){
    $('#inbound-list').innerHTML = `<div class="subx-empty" style="padding:24px;display:grid"><b>No ${MODE==='new'?'interfaces':'existing configs'} found</b><span>Try another filter or clear search.</span></div>`;
    updateSelected();
    return;
  }

  const groups = new Map();
  items.forEach((x, i) => {
    const key = groupKey(x);
    if(!groups.has(key)) groups.set(key, []);
    groups.get(key).push({x, i});
  });

  if (MODE === 'new') {
    $('#inbound-list').innerHTML = `<div class="subx-interface-grid">${items.map((x, i) => {
      const key = groupKey(x);
      return renderNewInterfaceCard(x, i, key, false);
    }).join('')}</div>`;
  } else {
    const groupEntries = currentSourceEntries();
    const totalConfigs = CURRENT_ITEMS.filter(x => SCOPE === 'all' || x.scope === SCOPE).length;
    const attachableSources = groupEntries.filter(([,rows]) => rows.length).length;
    const q = SEARCH.trim();
    $('#inbound-list').innerHTML = `
      ${renderSelectedCurrentTray()}
      <div class="subx-existing-toolbar friendly compact">
        <div><b>${totalConfigs} existing config${totalConfigs===1?'':'s'}</b><span>${q ? ' Matching sources are shown below.' : ' Search or choose a Local/Node interface, then select the exact config in the mini picker.'}</span></div>
        <span>${attachableSources} source${attachableSources===1?'':'s'} with configs</span>
      </div>
      <div class="subx-current-source-grid">
        ${groupEntries.map(([key, rows, src]) => renderCurrentSourceCard(key, rows, src)).join('')}
      </div>`;
  }

  $$('#inbound-list input').forEach(ch=>ch.addEventListener('change', updateSelected));
  $$('[data-current-group]').forEach(btn=>btn.onclick=()=>{ if(!btn.disabled) openCurrentPicker(btn.dataset.currentGroup, btn.dataset.currentInitialQ || ''); });
  $$('[data-current-remove]').forEach(btn=>btn.onclick=()=>{ CURRENT_SELECTED.delete(String(btn.dataset.currentRemove)); renderPicker(); });
  const clearAll = $('[data-current-clear-all]');
  if(clearAll) clearAll.onclick=()=>{ CURRENT_SELECTED.clear(); renderPicker(); };
  $$('[data-group-select]').forEach(btn=>btn.onclick=()=>{
    const group = btn.dataset.groupSelect;
    $$(`#inbound-list input[data-group="${CSS.escape(group)}"]:not(:disabled)`).forEach(ch=>ch.checked=true);
    updateSelected();
  });
  $$('[data-group-clear]').forEach(btn=>btn.onclick=()=>{
    const group = btn.dataset.groupClear;
    $$(`#inbound-list input[data-group="${CSS.escape(group)}"]`).forEach(ch=>ch.checked=false);
    updateSelected();
  });
  updateSelected();
}

function updateSelected(){
  const arr=selectedItems();
  $('#selected-count').textContent = arr.length;
  $('#selected-preview').textContent = arr.length ? `${arr.length} inbound${arr.length>1?'s':''} ready for this client` : 'No inbound selected';

  const counts = {};
  if(MODE === 'current') {
    CURRENT_SELECTED.forEach(idx => {
      const x = CURRENT_ITEMS[Number(idx)];
      if(!x) return;
      const g = groupKey(x);
      counts[g] = (counts[g] || 0) + 1;
    });
  } else {
    $$('#inbound-list input:checked').forEach(ch => {
      const g = ch.dataset.group || '';
      counts[g] = (counts[g] || 0) + 1;
    });
  }
  $$('[data-group-count]').forEach(el => {
    const n = counts[el.dataset.groupCount] || 0;
    el.textContent = n ? `${n} selected` : '';
  });  refreshSubscriptionInternalNetworks();
}

function subscriptionPeerCounts(s){
  const out={online:0, offline:0, blocked:0, total:0};
  (s.locations||[]).forEach(l=>{
    const st=String(l.status||'offline').toLowerCase();
    out.total += 1;
    if(st === 'blocked') out.blocked += 1;
    else if(st === 'online') out.online += 1;
    else out.offline += 1;
  });
  return out;
}

function inboundLabel(l, i){
  return esc(l.location_label || l.name || `Inbound ${i+1}`);
}

function locationKeyForInbound(l){
  if(String(l.scope||'').toLowerCase() === 'node') return `node:${l.node_id || l.node_name || l.node || l.location || 'node'}`;
  return 'local:this-server';
}
function locationNameForInbound(l){
  if(String(l.scope||'').toLowerCase() === 'node') return l.node_name || l.node || l.location || 'Node server';
  return 'Local server';
}
function uniqueLocationCount(s){
  const set = new Set((s.locations||[]).map(locationKeyForInbound));
  return set.size;
}
function groupedInboundLocations(locs){
  const map = new Map();
  (locs||[]).forEach((l, i) => {
    const key = locationKeyForInbound(l);
    if(!map.has(key)){
      map.set(key, {
        key,
        name: locationNameForInbound(l),
        scope: String(l.scope||'local').toLowerCase(),
        flag: l.flag || '',
        rows: []
      });
    }
    map.get(key).rows.push({...l, _index:i});
  });
  return [...map.values()];
}

function activeInboundText(s){
  const locs = s.locations || [];
  const state = subscriptionState(s);
  if(state.cls === 'blocked') return 'Blocked';
  if(state.cls === 'disabled') return 'Disabled';
  return locs.length ? `${locs.length} config${locs.length>1?'s':''}` : 'No inbound selected yet';
}

function subscriptionState(s){
  const c = subscriptionPeerCounts(s);
  if(!s.enabled) return {label:'Disabled', cls:'disabled', sub:''};
  if(c.blocked > 0) return {label:'Blocked', cls:'blocked', sub:''};
  if(c.total > 0) return {label:'Active', cls:'online', sub:''};
  return {label:'No inbounds', cls:'offline', sub:''};
}

function rowHtml(s){
  const locs=s.locations||[], pct=s.limit_bytes?Math.min(100,Number(s.usage_pct||0)):100;
  const state = subscriptionState(s);
  const dataLabel = s.limit_bytes ? `${fmtBytes(s.used_bytes)} / ${fmtBytes(s.limit_bytes)}` : `${fmtBytes(s.used_bytes)} · unlimited`;
  const remaining = s.remaining_bytes == null ? 'Unlimited' : fmtBytes(s.remaining_bytes);
  const timerLabel = subscriptionTimeLabel(s);
  const locCount = uniqueLocationCount(s);
  const inboundSmall = locs.length ? `${locs.length} inbound${locs.length>1?'s':''}` : 'No inbound';
  return `<article class="subx-row state-${state.cls}" data-sub="${s.id}">
    <div class="subx-row-main">
      <div class="subx-client-block">
        <div class="subx-name"><i class="fas fa-user-shield"></i><span>${esc(s.name)}</span></div>
        <div class="subx-note">${esc(s.note||'Client subscription')}</div>
      </div>

      <div class="subx-summary-grid">
        <div class="subx-summary-card">
          <span><i class="fas fa-location-dot"></i> Locations</span>
          <b>${locCount}</b>
          <small>${inboundSmall}</small>
        </div>
        <div class="subx-summary-card wide">
          <span><i class="fas fa-database"></i> Data</span>
          <b>${dataLabel}</b>
          <small>${remaining} remaining</small>
          <div class="subx-progress slim"><span style="width:${Math.max(4,pct)}%"></span></div>
        </div>
        <div class="subx-summary-card">
          <span><i class="fas fa-clock"></i> Time</span>
          <b>${timerLabel}</b><small>${s.unlimited? (s.first_used_at? 'First connection recorded': 'Waiting for first connection'): (s.start_on_first_use? 'starts on first use': 'fixed expiry')}</small>
        </div>
        <div class="subx-summary-card status-card ${state.cls}">
          <span><i class="fas fa-signal"></i> Client status</span>
          <b>${esc(state.label)}</b>
          <small>${state.sub ? esc(state.sub) : '&nbsp;'}</small>
        </div>
      </div>

      <div class="subx-actions">
        <button class="subx-icon-btn" title="Copy public link" data-copy="${esc(s.public_url)}"><i class="fas fa-link"></i></button>
        <button class="subx-icon-btn" title="Copy config link" data-copy="${esc(s.config_url)}"><i class="fas fa-file-lines"></i></button>
        <button class="subx-icon-btn" title="Reset data" data-reset-data="${s.id}"><i class="fas fa-gauge-high"></i></button>
        <button class="subx-icon-btn" title="Reset timer" data-reset-timer="${s.id}"><i class="fas fa-clock-rotate-left"></i></button>
        <button class="subx-icon-btn" title="Manage inbounds" data-inbounds="${s.id}"><i class="fas fa-network-wired"></i></button>
        <button class="subx-icon-btn" title="Edit client" data-edit="${s.id}"><i class="fas fa-pen"></i></button>
        <button class="subx-icon-btn" title="More information" data-more="${s.id}"><i class="fas fa-circle-info"></i></button>
        <button class="subx-icon-btn danger" title="Delete" data-del="${s.id}"><i class="fas fa-trash"></i></button>
      </div>
    </div>
  </article>`;
}

async function loadSubs(opts={}){
  if(SUBS_LOADING) return;
  if(!opts.force && modalIsOpen()) return;
  SUBS_LOADING = true;
  setLiveState('Refreshing…', 'loading');
  try {
    const r=await fetch('/api/subscriptions',{credentials:'same-origin', cache:'no-store'});
    const j=await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(j.detail || j.error || 'Load failed');
    const next = j.subscriptions || [];
    const nextJson = JSON.stringify(next);
    SUBS = next;
    if(opts.force || nextJson !== SUBS_LAST_JSON){
      $('#subs-list').innerHTML=SUBS.map(rowHtml).join('');
      $('#subs-empty').hidden=SUBS.length>0;
      SUBS_LAST_JSON = nextJson;
    }
    $('#st-total').textContent=SUBS.length;
    $('#st-inbounds').textContent=SUBS.reduce((a,s)=>a+(s.locations||[]).length,0);
    const blocked = SUBS.reduce((a,s)=> a + (subscriptionState(s).cls === 'blocked' ? 1 : 0), 0);
    $('#st-blocked').textContent = blocked;
    if(detailsIsOpen()){
      const openId = $('#details-modal')?.dataset?.sid;
      const current = SUBS.find(x=>String(x.id)===String(openId));
      if(current) renderDetails(current, {keepOpen:true});
    }
    setLiveState(`Updated ${nowClock()}`);
  } catch(err) {
    setLiveState(`Live update failed: ${err.message || err}`, 'error');
  } finally {
    SUBS_LOADING = false;
  }
}

function setEditLayout(isEdit, allowInboundPicker=false){
  const modal = $('#sub-modal');
  const inbound = $('#sub-inbound-section');
  const clean = $('#sub-edit-clean-card');
  const defaultsBox = $('#new-defaults');
  const editNote = $('#edit-inbound-note');
  const syncBox = $('#sync-box');

  if(modal){
    modal.classList.toggle('edit-mode', !!isEdit);
    modal.classList.toggle('manage-inbounds-mode', !!allowInboundPicker);
  }

  if(inbound){
    inbound.hidden = false;
    inbound.classList.toggle('is-edit-only', !!isEdit && !allowInboundPicker);
  }
  if(clean) clean.hidden = true;
  if(editNote) editNote.hidden = true;

  if(syncBox) syncBox.hidden = true;
  const syncInput = $('#sync-existing');
  if(syncInput) syncInput.checked = true;

  if(defaultsBox){
    defaultsBox.style.display = '';
    defaultsBox.open = !!isEdit && !allowInboundPicker;
  }
}

function fillForm(s=null){
  const internalAllowed = document.querySelector('#sub-form [name="allowed_ips"]'); if(internalAllowed) internalAllowed.dataset.autoInternalNetworks = ''; 
  const f=$('#sub-form'); f.reset(); $('#sub-sid').value=s?.id||''; EDIT_ID=s?.id||null;
  $('#sub-modal-title').innerHTML = s ? '<i class="fas fa-pen"></i> Edit client subscription' : '<i class="fas fa-user-plus"></i> Create client subscription';
  const headHint = $('#sub-modal .subx-modal-head p');
  if(headHint) headHint.textContent = s
    ? 'Update client details, shared limits, and advanced WireGuard values.'
    : 'Create a client in one simple form. Only choose a name, limits, and where this client should work.';
  $('#sub-submit').innerHTML = s ? '<i class="fas fa-check"></i> Save changes' : '<i class="fas fa-check"></i> Create subscription';
  if(!s) return;
  f.name.value=s.name||''; f.note.value=s.note||''; f.data_limit_value.value=s.data_limit_value||0; f.data_limit_unit.value=s.data_limit_unit||'Gi';
  const days=Number(s.time_limit_days||0);
  const wholeDays=Math.floor(days);
  const totalMinutes=Math.round((days-wholeDays)*1440);
  f.time_limit_days.value=wholeDays;
  f.time_limit_hours.value=Math.floor(totalMinutes/60);
  if(f.time_limit_minutes) f.time_limit_minutes.value=totalMinutes%60;
  f.phone_number.value=s.phone_number||''; f.telegram_id.value=s.telegram_id||''; f.start_on_first_use.checked=!!s.start_on_first_use; f.unlimited.checked=!!s.unlimited;
}

async function openCreate(){
  MODE='new'; SCOPE='all'; STATUS_SCOPE='all'; SEARCH='';
  if($('#inbound-search')) $('#inbound-search').value='';
  EDIT_ID=null; fillForm(null);
  setEditLayout(false);

  $$('#inbound-list input[type="checkbox"]').forEach(ch => ch.checked = false);
  if(typeof updateSelected === 'function') updateSelected();

  const list = $('#inbound-list');
  if(list){
    list.innerHTML = `
      <div class="subx-empty subx-loading-state" style="padding:28px;display:grid">
        <span class="subx-loading-spinner" aria-hidden="true"></span>
        <b>Loading interfaces…</b>
        <span>Please wait while local and node interfaces are loaded.</span>
      </div>
    `;
  }
  const count = $('#picker-count');
  if(count) count.textContent = 'Loading…';
  const hint = $('#picker-hint');
  if(hint) hint.textContent = 'Fetching local and node interfaces.';

  openModal();

  try {
    await loadPickers();
    setModeButtons();
  } catch (err) {
    if(list){
      list.innerHTML = `
        <div class="subx-empty" style="padding:28px;display:grid">
          <b>Could not load interfaces</b>
          <span>Close this window and try again.</span>
        </div>
      `;
    }
    if(count) count.textContent = 'Unavailable';
    if(hint) hint.textContent = 'Interface loading failed.';
    toastBad('Could not load local and node interfaces.');
  }
}

async function openEdit(id, opts={}){
  const s=SUBS.find(x=>String(x.id)===String(id)); 
  if(!s) return;

  const manageInbounds = !!opts.manageInbounds;

  MODE='new'; 
  SCOPE='all'; 
  STATUS_SCOPE='all'; 
  SEARCH='';

  NEW_ITEMS=[]; 
  CURRENT_ITEMS=[];
  CURRENT_SELECTED.clear();

  if($('#inbound-search')) $('#inbound-search').value='';

  fillForm(s);
  setEditLayout(true, manageInbounds);

  const titleEl = $('#sub-modal-title');
  const hintEl = $('#sub-modal .subx-modal-head p');

  if(manageInbounds){
    if(titleEl) titleEl.innerHTML = '<i class="fas fa-network-wired"></i> Add inbound to client';
    if(hintEl) hintEl.textContent = 'Choose a local or node interface to create a new config, or attach an existing config to this subscription.';
    if($('#sub-submit')) $('#sub-submit').innerHTML = '<i class="fas fa-plus"></i> Save and add selected inbound';

    const list = $('#inbound-list');
    if(list){
      list.innerHTML = `
        <div class="subx-empty" style="padding:24px;display:grid">
          <b>Loading available inbounds…</b>
          <span>Please wait while local and node interfaces are loaded.</span>
        </div>
      `;
    }

    const count = $('#picker-count');
    if(count) count.textContent = 'Loading…';

    const hint = $('#picker-hint');
    if(hint) hint.textContent = 'Fetching local and node interfaces.';

    openModal();

    try{
      await loadPickers();
      setModeButtons();
    }catch(_){
      if(list){
        list.innerHTML = `
          <div class="subx-empty" style="padding:24px;display:grid">
            <b>Could not load inbounds</b>
            <span>Please close and try again.</span>
          </div>
        `;
      }
      toastBad('Could not load available inbounds.');
    }

    return;
  }

  openModal();
}


function showSubscriptionPickerLoading(mode) {
  const list = $('#inbound-list');
  const count = $('#picker-count');
  const hint = $('#picker-hint');
  const existing = mode === 'current';

  if (list) {
    list.innerHTML = `
      <div class="subx-empty subx-loading-state" style="padding:28px;display:grid">
        <span class="subx-loading-spinner" aria-hidden="true"></span>
        <b>${existing ? 'Loading existing configs…' : 'Loading interfaces…'}</b>
        <span>${existing
          ? 'Please wait while local and node configs are loaded.'
          : 'Please wait while local and node interfaces are loaded.'}</span>
      </div>
    `;
  }

  if (count) count.textContent = 'Loading…';
  if (hint) {
    hint.textContent = existing
      ? 'Fetching existing local and node configurations.'
      : 'Fetching local and node interfaces.';
  }
}

function setModeButtons(){
  $$('.subx-mode button').forEach(b=>b.classList.toggle('active', b.dataset.mode===MODE));
  $$('.subx-filters button[data-scope]').forEach(b=>b.classList.toggle('active', b.dataset.scope===SCOPE));
  const search = $('#inbound-search');
  if(search) search.placeholder = MODE === 'current' ? 'Search by config name, IP, phone, Telegram...' : 'Search interfaces...';
  renderPicker();
}


function subIpv4NetworkFromCidr(cidr) {
  const raw = String(cidr || '')
    .split(',')[0]
    .trim();

  const match =
    /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/
      .exec(raw);

  if (!match) return '';

  const octets = match[1]
    .split('.')
    .map(Number);

  const prefix = Number(match[2]);

  if (
    octets.length !== 4 ||
    octets.some(
      value =>
        !Number.isInteger(value) ||
        value < 0 ||
        value > 255
    ) ||
    prefix < 0 ||
    prefix > 32
  ) {
    return '';
  }

  const ip = (
    ((octets[0] << 24) >>> 0) |
    (octets[1] << 16) |
    (octets[2] << 8) |
    octets[3]
  ) >>> 0;

  const mask =
    prefix === 0
      ? 0
      : (0xffffffff << (32 - prefix)) >>> 0;

  const network = (ip & mask) >>> 0;

  return [
    (network >>> 24) & 255,
    (network >>> 16) & 255,
    (network >>> 8) & 255,
    network & 255,
  ].join('.') + `/${prefix}`;
}

function subAppendAllowedRoute(current, route) {
  const routes = String(current || '')
    .split(',')
    .map(value => value.trim())
    .filter(Boolean);

  if (route && !routes.includes(route)) {
    routes.push(route);
  }

  return routes.join(', ');
}

function subscriptionAllowedIpsWithNetworks(
  allowedIps,
  items
) {
  let result = String(allowedIps || '').trim();

  const routes = result
    .split(',')
    .map(value => value.trim())
    .filter(Boolean);

  if (
    routes.includes('0.0.0.0/0') ||
    routes.includes('::/0')
  ) {
    return result || '0.0.0.0/0, ::/0';
  }

  for (const item of items || []) {
    const network = subIpv4NetworkFromCidr(
      item?.address ||
      item?.server_cidr ||
      item?.interface_address ||
      item?.cidr ||
      ''
    );

    if (network) {
      result = subAppendAllowedRoute(
        result,
        network
      );
    }
  }

  return result;
}


function subNormalizeNetworkList(v){const o=[];for(const x of String(v||'').split(',')){const n=subIpv4NetworkFromCidr(x.trim());if(n&&!o.includes(n))o.push(n);}return o;}
function detectSelectedSubscriptionNetworks() {
  const chosen =
    MODE === 'new'
      ? selectedItems()
      : [];

  const source =
    chosen.length
      ? chosen
      : (
          Array.isArray(NEW_ITEMS)
            ? NEW_ITEMS
            : []
        );

  const networks = [];

  const addNetwork = value => {
    const network = subIpv4NetworkFromCidr(value);
    if (network && !networks.includes(network)) networks.push(network);
  };

  for (const item of source) {
    const scopeNetworks = item?.scope_networks;
    if (Array.isArray(scopeNetworks)) {
      scopeNetworks.forEach(addNetwork);
    } else if (scopeNetworks) {
      String(scopeNetworks).split(',').forEach(addNetwork);
    }

    addNetwork(
      item?.address ||
      item?.server_cidr ||
      item?.interface_address ||
      item?.cidr ||
      ''
    );
  }

  return networks;
}
function subRouteList(value){
  return String(value || '').split(',').map(v => v.trim()).filter(Boolean);
}
function subUniqueRoutes(value){
  return [...new Set(subRouteList(value))];
}
function subApplyInternalNetworksToAllowed(){
  const allowed = document.querySelector('#sub-form [name="allowed_ips"]');
  const detectedInput = document.getElementById('sub-internal-networks');
  const toggle = document.getElementById('sub-include-internal-network');
  if(!allowed || !detectedInput) return;

  const previouslyAdded = subUniqueRoutes(allowed.dataset.autoInternalNetworks || '');
  let current = subUniqueRoutes(allowed.value);

  if(previouslyAdded.length){
    const remove = new Set(previouslyAdded);
    current = current.filter(route => !remove.has(route));
  }

  const enabled = !!toggle?.checked;
  const detected = enabled ? subNormalizeNetworkList(detectedInput.value) : [];
  for(const route of detected){
    if(!current.includes(route)) current.push(route);
  }

  allowed.dataset.autoInternalNetworks = enabled ? detected.join(', ') : '';
  allowed.value = current.join(', ');
  allowed.dispatchEvent(new Event('input', {bubbles:true}));
  allowed.dispatchEvent(new Event('change', {bubbles:true}));
}
function refreshSubscriptionInternalNetworks(){
  const input=document.getElementById('sub-internal-networks');
  if(!input)return;
  const detected=detectSelectedSubscriptionNetworks();
  input.value=detected.join(', ');
  subApplyInternalNetworksToAllowed();
}
function payloadFromForm() {
  const form = $('#sub-form');
  const fd = new FormData(form);
  const body = Object.fromEntries(fd.entries());
  body.time_limit_days =Number(fd.get('time_limit_days') || 0) +(Number(fd.get('time_limit_hours') || 0) / 24) +(Number(fd.get('time_limit_minutes') || 0) / 1440);
  body.start_on_first_use = fd.has('start_on_first_use'); body.unlimited = fd.has('unlimited'); body.include_internal_network = fd.has('include_internal_network'); body.sync_existing = !!$('#sync-existing')?.checked;
  if (MODE === 'new' && body.include_internal_network) {for (const network of subNormalizeNetworkList(document.getElementById('sub-internal-networks')?.value)){body.allowed_ips=subAppendAllowedRoute(body.allowed_ips,network);}}

  const prefix=(fd.get('peer_name_prefix')||'').trim();
  body.targets=selectedItems().map((x,i)=>{
    if(MODE==='current') return {peer_id:x.peer_id, scope:x.scope, location_label:x.location_label||`${x.scope==='node'?x.node_name:'Local'} · ${x.iface}`, flag:x.flag, country_code:x.country_code||''};
    return {
      scope: x.scope,
      iface_id: x.iface_id,
      iface: x.iface,
      node_id: x.node_id,
      label: x.label,
      location: x.location,
      address: x.address || x.server_cidr || '',
      server_cidr: x.server_cidr || x.address || '',
      peer_name: prefix ? `${prefix}-${i+1}` : ''
    };
  });
  return body;
}

$('#open-sub-modal').onclick=openCreate; $('#sub-close').onclick=closeModal; $('#sub-cancel').onclick=closeModal;
$('#details-close').onclick=closeDetails;

$('#open-sub-settings').onclick=async()=>{ await loadSubscriptionSettings(); openSettings(); };
$('#settings-close').onclick=closeSettings;
$('#settings-cancel').onclick=closeSettings;
$('#settings-save').onclick=saveSubscriptionSettings;
$('#sub-settings-modal').addEventListener('click',e=>{if(e.target.dataset.closeSettings) closeSettings();});
document.querySelectorAll('input[name="sub-layout"]').forEach(r=>r.addEventListener('change',()=>updateLayoutPreview(r.value)));

$('#sub-modal').addEventListener('click',e=>{if(e.target.dataset.close) closeModal();});
$('#details-modal').addEventListener('click',e=>{if(e.target.dataset.closeDetails) closeDetails();});
$$('.subx-mode button').forEach(button => {
  button.onclick = async () => {
    const nextMode = button.dataset.mode || 'new';
    if (MODE === nextMode) return;

    MODE = nextMode;
    SEARCH = '';
    EXISTING_GROUP_LIMITS = {};

    const search = $('#inbound-search');
    if (search) search.value = '';

    showSubscriptionPickerLoading(MODE);

    const modeButtons = $$('.subx-mode button');
    modeButtons.forEach(item => {
      item.classList.toggle('active', item.dataset.mode === MODE);
      item.disabled = true;
    });

    try {
      await loadPickers();
      setModeButtons();
    } catch (error) {
      console.error('Subscription picker loading failed:', error);

      const list = $('#inbound-list');
      const count = $('#picker-count');
      const hint = $('#picker-hint');
      const existing = MODE === 'current';

      if (list) {
        list.innerHTML = `
          <div class="subx-empty" style="padding:28px;display:grid">
            <b>${existing ? 'Could not load existing configs' : 'Could not load interfaces'}</b>
            <span>Please try again.</span>
          </div>
        `;
      }

      if (count) count.textContent = 'Unavailable';
      if (hint) hint.textContent = 'Loading failed.';
      toastBad(existing
        ? 'Could not load existing configurations.'
        : 'Could not load interfaces.');
    } finally {
      modeButtons.forEach(item => { item.disabled = false; });
    }
  };
});
$$('.subx-filters button[data-scope]').forEach(b=>b.onclick=()=>{SCOPE=b.dataset.scope; setModeButtons();});

const searchEl = $('#inbound-search');
if(searchEl) searchEl.addEventListener('input', () => { SEARCH = searchEl.value || ''; EXISTING_GROUP_LIMITS = {}; renderPicker(); });


$('#sub-form').addEventListener('submit', async e=>{
  e.preventDefault();
  const body=payloadFromForm(), sid=$('#sub-sid').value;
  if(!sid && !body.targets.length){ toastBad('Select at least one interface or existing config.'); return; }
  if(MODE === 'current' && body.targets.length && body.sync_existing){
    const names = selectedItems().map(x => x.name || x.address || x.iface).slice(0, 6).join(', ');
    const extra = body.targets.length > 6 ? ` and ${body.targets.length - 6} more` : '';
        const ok = await subConfirm({
      title: 'Use existing configs?',
      body: `Use ${body.targets.length} existing config(s) for this client: ${names}${extra}. After this, the subscription will manage their shared data limit, timer, and first-use policy.`,
      yesText: 'Use configs',
      noText: 'Cancel'
    });
    if(!ok) return;
  }
  let url='/api/subscriptions', method='POST';
  if(sid && body.targets.length){
    let r=await fetch(`/api/subscriptions/${sid}`,{method:'PUT',headers:csrfHeaders(true),credentials:'same-origin',body:JSON.stringify(body)});
    if(!r.ok){ const j=await r.json().catch(()=>({})); toastBad(j.detail||j.error||'Update failed'); return; }
    r=await fetch(`/api/subscriptions/${sid}/inbounds`,{method:'POST',headers:csrfHeaders(true),credentials:'same-origin',body:JSON.stringify(body)});
    if(!r.ok){ const j=await r.json().catch(()=>({})); toastBad(j.detail||j.error||'Adding inbounds failed'); return; }
  } else if(sid) {
    const r=await fetch(`/api/subscriptions/${sid}`,{method:'PUT',headers:csrfHeaders(true),credentials:'same-origin',body:JSON.stringify(body)});
    if(!r.ok){ const j=await r.json().catch(()=>({})); toastBad(j.detail||j.error||'Update failed'); return; }
  } else {
    const r=await fetch(url,{method,headers:csrfHeaders(true),credentials:'same-origin',body:JSON.stringify(body)});
    if(!r.ok){ const j=await r.json().catch(()=>({})); toastBad(j.detail||j.error||'Create failed'); return; }
  }
  toastOk(sid?'Subscription updated.':'Subscription created.');
  closeModal(); await loadSubs();
});


async function copyText(txt){
  txt = String(txt || '');
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(txt);
      return true;
    }
  } catch (_) {}
  try {
    const ta = document.createElement('textarea');
    ta.value = txt;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    ta.style.top = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return !!ok;
  } catch (_) {
    return false;
  }
}

function statusBadgeClass(status){
  const st=String(status||'offline').toLowerCase();
  if(st==='blocked') return 'blocked';
  if(st==='online') return 'online';
  if(st==='disabled') return 'disabled';
  return 'offline';
}

function renderDetails(s, opts={}){
  const locs = s.locations || [];
  const groups = groupedInboundLocations(locs);
  const state = subscriptionState(s);
  const title = esc(s.name || 'Subscription details');
  const limit = s.limit_bytes ? fmtBytes(s.limit_bytes) : 'Unlimited';
  const used = fmtBytes(s.used_bytes);
  const remaining = s.remaining_bytes == null ? 'Unlimited' : fmtBytes(s.remaining_bytes);
  $('#details-title').innerHTML=`<i class="fas fa-circle-info"></i> ${title}`;
  $('#details-body').innerHTML=`
    <div class="detail-hero">
      <section class="detail-panel">
        <div class="detail-panel-title"><i class="fas fa-chart-pie"></i><span>Client overview</span></div>
        <div class="detail-grid">
          <div class="detail-card"><span>Locations</span><b>${groups.length}</b></div>
          <div class="detail-card"><span>Inbounds</span><b>${locs.length}</b></div>
          <div class="detail-card"><span>Used</span><b>${used}</b></div>
          <div class="detail-card"><span>Timer</span><b>${ttlText(s.ttl_seconds)}</b></div>
        </div>
      </section>
      <section class="detail-panel">
        <div class="detail-panel-title"><i class="fas fa-link"></i><span>Share links</span></div>
        <div class="detail-link-actions">
          <button class="btn secondary" data-copy="${esc(s.public_url)}"><i class="fas fa-copy"></i> Copy public page</button>
          <button class="btn secondary" data-copy="${esc(s.config_url)}"><i class="fas fa-file-lines"></i> Copy config URL</button>
        </div>
        <div class="detail-meta-row">
          <span class="detail-meta-pill"><i class="fas fa-signal"></i> ${esc(state.label)}</span>
          <span class="detail-meta-pill"><i class="fas fa-database"></i> ${used} / ${limit}</span>
          <span class="detail-meta-pill"><i class="fas fa-boxes-stacked"></i> ${remaining} remaining</span>
        </div>
      </section>
    </div>

    <section class="detail-panel">
      <div class="detail-locations-head">
        <h3><i class="fas fa-location-dot"></i> Locations & inbounds</h3>
        <div class="detail-head-actions">
          <span class="detail-count-pill">${groups.length} location${groups.length===1?'':'s'} · ${locs.length} inbound${locs.length===1?'':'s'}</span>
          <button class="btn secondary detail-add-btn" data-add-inbound="${s.id}"><i class="fas fa-plus"></i> Add inbound</button>
        </div>
      </div>
      <div class="detail-location-list">
        ${groups.map(g=>{
          const icon = g.flag ? esc(g.flag) : (g.scope === 'node' ? '<i class="fas fa-server"></i>' : '<i class="fas fa-house-signal"></i>');
          return `<div class="detail-location-group">
            <div class="detail-location-group-head">
              <div class="detail-location-name">
                <span class="detail-loc-icon">${icon}</span>
                <div><b>${esc(g.name)}</b><small>${g.scope === 'node' ? 'Node location' : 'This local server'}</small></div>
              </div>
              <span class="detail-location-count">${g.rows.length} inbound${g.rows.length===1?'':'s'}</span>
            </div>
            <div class="detail-location-inbounds">
              ${g.rows.map((l)=>{
                const customLabel = l.location_label || '';
                const displayName = customLabel || l.iface || l.name || `Inbound ${Number(l._index)+1}`;
                const status = statusBadgeClass(l.status);
                const iface = l.iface || 'Interface';
                const address = l.address || '';
                const endpoint = l.endpoint || '';
                const peerName = l.name && l.name !== displayName ? l.name : '';
                return `<div class="detail-inbound compact-inbound" data-link="${l.link_id}">
                  <div class="detail-inbound-main">
                    <div class="detail-inbound-top">
                      <span class="detail-loc-icon"><i class="fas fa-network-wired"></i></span>
                      <div>
                        <div class="detail-inbound-title"><b>${esc(displayName)}</b><span class="subx-status ${status}">${esc(l.status || 'offline')}</span></div>
                        <div class="detail-inbound-sub"><span class="detail-kind">${esc(iface)}</span>${address ? ' · '+esc(address) : ''}</div>
                      </div>
                    </div>
                    <div class="detail-meta-row clean-meta">
                      ${peerName ? `<span class="detail-meta-pill"><i class="fas fa-user-shield"></i> ${esc(peerName)}</span>` : ''}
                      ${endpoint ? `<span class="detail-meta-pill"><i class="fas fa-globe"></i> ${esc(endpoint)}</span>` : ''}
                    </div>
                  </div>
                  <div class="detail-actions">
                    <button class="detail-label-btn" data-edit-inbound-label="${l.link_id}" data-current-label="${esc(customLabel)}" title="Edit display label"><i class="fas fa-pen"></i></button>
                    <button class="subx-icon-btn" data-up="${l.link_id}" title="Move up"><i class="fas fa-arrow-up"></i></button>
                    <button class="subx-icon-btn" data-down="${l.link_id}" title="Move down"><i class="fas fa-arrow-down"></i></button>
                    <button class="subx-icon-btn danger" data-remove-inbound="${l.link_id}" title="Remove"><i class="fas fa-xmark"></i></button>
                  </div>
                </div>`;
              }).join('')}
            </div>
          </div>`;
        }).join('') || '<div class="detail-empty"><i class="fas fa-inbox"></i><br>No inbound is attached to this client.</div>'}
      </div>
    </section>`;
    const dm = $('#details-modal'); 
  if(dm) dm.dataset.sid = s.id;

  if(!opts.keepOpen) {
    openDetails();

    setTimeout(() => {
      if(!$('#sub-modal')?.classList.contains('open')){
        loadPickers().catch(()=>{});
      }
    }, 80);
  }
}

let LABEL_EDIT_LINK_ID = null;
function openLabelEditor(linkId, currentLabel=''){
  LABEL_EDIT_LINK_ID = linkId;
  const modal = $('#label-edit-modal');
  const input = $('#label-edit-input');

  if(input) input.value = currentLabel || '';

  if(modal){
    modal.classList.add('open');
    modal.setAttribute('aria-hidden','false');
  }

  subxUpdateModalBodyState();
  setTimeout(()=>input?.focus(), 30);
}

function closeLabelEditor(){
  LABEL_EDIT_LINK_ID = null;
  const modal = $('#label-edit-modal');

  if(modal){
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden','true');
  }

  subxUpdateModalBodyState();
}
async function saveLabelEditor(){
  const lid = LABEL_EDIT_LINK_ID;
  if(!lid) return;
  const sid = SUBS.find(s=>(s.locations||[]).some(l=>String(l.link_id)===String(lid)))?.id;
  if(!sid){ toastBad('Subscription not found.'); return; }
  const btn = $('#label-edit-save');
  if(btn) btn.disabled = true;
  const body = {location_label: $('#label-edit-input')?.value || ''};
  const r = await fetch(`/api/subscriptions/${sid}/inbounds/${lid}`,{method:'PATCH',headers:csrfHeaders(true),credentials:'same-origin',body:JSON.stringify(body)});
  if(btn) btn.disabled = false;
  if(r.ok){
    toastOk('Label saved.');
    closeLabelEditor();
    await loadSubs({force:true});
  } else {
    const j = await r.json().catch(()=>({}));
    toastBad(j.detail || j.error || 'Save failed.');
  }
}

$('#label-edit-close')?.addEventListener('click', closeLabelEditor);
$('#label-edit-cancel')?.addEventListener('click', closeLabelEditor);
$('#label-edit-save')?.addEventListener('click', saveLabelEditor);
$('#label-edit-modal')?.addEventListener('click', e=>{ if(e.target.dataset.closeLabel) closeLabelEditor(); });
$('#label-edit-input')?.addEventListener('keydown', e=>{ if(e.key === 'Enter'){ e.preventDefault(); saveLabelEditor(); } if(e.key === 'Escape'){ closeLabelEditor(); } });

document.addEventListener('click', async e=>{
  const copy=e.target.closest('[data-copy]'); if(copy){ const ok = await copyText(copy.dataset.copy); ok ? toastOk('Copied.') : toastBad('Copy failed. Open HTTPS or copy manually.'); return; }
  const more=e.target.closest('[data-more]'); if(more){ const s=SUBS.find(x=>String(x.id)===String(more.dataset.more)); if(s) renderDetails(s); return; }
  const editLabel=e.target.closest('[data-edit-inbound-label]'); if(editLabel){ openLabelEditor(editLabel.dataset.editInboundLabel, editLabel.dataset.currentLabel || ''); return; }
  const inbounds=e.target.closest('[data-inbounds]'); if(inbounds){ const s=SUBS.find(x=>String(x.id)===String(inbounds.dataset.inbounds)); if(s) renderDetails(s); return; }
  const addInbound=e.target.closest('[data-add-inbound]');if(addInbound){await openEdit(addInbound.dataset.addInbound, {manageInbounds:true});return;}
  const edit=e.target.closest('[data-edit]'); if(edit){ await openEdit(edit.dataset.edit); return; }
  const del=e.target.closest('[data-del]');if(del){const ok = await subConfirm({title: 'Delete subscription?',body: 'This removes the subscription record. Attached peer/config deletion still depends on your backend delete behavior.',yesText: 'Delete',noText: 'Cancel',danger: true});if(!ok) return;
  const r=await fetch(`/api/subscriptions/${del.dataset.del}`,{method:'DELETE',headers:csrfHeaders(true),credentials:'same-origin'});if(r.ok){toastOk('Deleted.');loadSubs();} else {toastBad('Delete failed.');}return;}
  const rt=e.target.closest('[data-reset-timer]'); if(rt){ const id=rt.dataset.resetTimer; rt.classList.add('is-busy'); rt.closest('.subx-row')?.classList.add('is-updating'); let r=await fetch(`/api/subscriptions/${id}/reset_timer`,{method:'POST',headers:csrfHeaders(true),credentials:'same-origin'}); if(r.status===404 || r.status===405){ r=await fetch(`/api/subscriptions/${id}`,{method:'PUT',headers:csrfHeaders(true),credentials:'same-origin',body:JSON.stringify({reset_timer:true})}); } if(r.ok){toastOk('Timer reset and peer runtime refreshed.'); await loadSubs({force:true});} else { const j=await r.json().catch(()=>({})); toastBad(j.detail||j.error||'Reset failed.'); } rt.classList.remove('is-busy'); rt.closest('.subx-row')?.classList.remove('is-updating'); return; }
  const rd=e.target.closest('[data-reset-data]'); if(rd){ const id=rd.dataset.resetData; rd.classList.add('is-busy'); rd.closest('.subx-row')?.classList.add('is-updating'); const r=await fetch(`/api/subscriptions/${id}/reset_data`,{method:'POST',headers:csrfHeaders(true),credentials:'same-origin'}); if(r.ok){toastOk('Data reset and peer runtime refreshed.'); await loadSubs({force:true});} else { const j=await r.json().catch(()=>({})); toastBad(j.detail||j.error||'Reset data failed.'); } rd.classList.remove('is-busy'); rd.closest('.subx-row')?.classList.remove('is-updating'); return; }
  const rem=e.target.closest('[data-remove-inbound]');if(rem){const sid=SUBS.find(s=>(s.locations||[]).some(l=>String(l.link_id)===String(rem.dataset.removeInbound)))?.id;if(!sid) return;
  const ok = await subConfirm({title: 'Remove inbound?',body: 'This removes the inbound from this client. The underlying peer/config will not be deleted.',yesText: 'Remove inbound',noText: 'Cancel',danger: true});if(!ok) return;
  const r=await fetch(`/api/subscriptions/${sid}/inbounds/${rem.dataset.removeInbound}`,{method:'DELETE',headers:csrfHeaders(true),credentials:'same-origin'});if(r.ok){toastOk('Inbound removed.');await loadSubs({force:true});} else {const j=await r.json().catch(()=>({}));toastBad(j.detail||j.error||'Remove failed.');}return;}  
  const save=e.target.closest('[data-save-inbound]'); if(save){ const lid=save.dataset.saveInbound; const sid=SUBS.find(s=>(s.locations||[]).some(l=>String(l.link_id)===String(lid)))?.id; const body={location_label:document.querySelector(`[data-label="${lid}"]`)?.value||''}; const r=await fetch(`/api/subscriptions/${sid}/inbounds/${lid}`,{method:'PATCH',headers:csrfHeaders(true),credentials:'same-origin',body:JSON.stringify(body)}); if(r.ok){toastOk('Inbound saved.'); closeDetails(); await loadSubs();} else toastBad('Save failed.'); return; }
});

loadSubs({force:true});
SUBS_LIVE_TIMER = setInterval(()=>loadSubs({force:false}), SUBS_REFRESH_MS);
document.addEventListener('visibilitychange', ()=>{ if(!document.hidden) loadSubs({force:true}); });

function subxDisplayMode(){ return (SUB_SETTINGS && SUB_SETTINGS.display_mode) || localStorage.getItem('subx-display-mode') || 'hybrid'; }
function subxClampPct(v){ v=Number(v||0); return Math.max(0, Math.min(100, Math.round(v))); }
function subxIconForState(cls){ return cls === 'blocked' ? 'fa-ban' : cls === 'disabled' ? 'fa-pause' : cls === 'offline' ? 'fa-circle-dot' : 'fa-signal'; }
function subxRing(p, color){ p=subxClampPct(p); return `<div class="subx-ring" style="--p:${p};--c:${color||'#3b82f6'}"><span>${p}%</span></div>`; }
function rowHtml(s){
  const locs=s.locations||[];
  const usedPct=s.limit_bytes?subxClampPct(s.usage_pct||0):0;
  const remainingPct=s.limit_bytes?Math.max(0,100-usedPct):100;
  const state=subscriptionState(s);
  const dataLabel=s.limit_bytes?`${fmtBytes(s.used_bytes)} / ${fmtBytes(s.limit_bytes)}`:`${fmtBytes(s.used_bytes)} · unlimited`;
  const remaining=s.remaining_bytes==null?'Unlimited':fmtBytes(s.remaining_bytes);
  const timerLabel=ttlText(s.ttl_seconds);
  const locCount=uniqueLocationCount(s);
  const inboundSmall=locs.length?`${locs.length} inbound${locs.length>1?'s':''}`:'No inbound';
  const mode=subxDisplayMode();
  const ringData=(mode==='rings'||mode==='hybrid')?`<div class="subx-ring-wrap">${subxRing(remainingPct,'#10b981')}<small>${remaining} remaining</small></div>`:'';
  const barData=(mode==='bars'||mode==='hybrid')?`<div class="subx-progress slim"><span style="width:${Math.max(4,remainingPct)}%"></span></div>`:'';
  const timePct=s.ttl_seconds==null?100:(Number(s.ttl_seconds)<=0?0:Math.min(100,Math.max(8,100)));
  const ringTime=(mode==='rings')?`<div class="subx-ring-wrap">${subxRing(timePct,'#3b82f6')}<small>${s.start_on_first_use?'starts on first use':'fixed expiry'}</small></div>`:'';
  return `<article class="subx-row state-${state.cls}" data-sub="${s.id}">
    <div class="subx-row-main">
      <div class="subx-client-block">
        <div class="subx-name"><i class="fas fa-user-shield"></i><span>${esc(s.name)}</span></div>
        <div class="subx-note">${esc(s.note||'Client subscription')}</div>
      </div>
      <div class="subx-summary-grid mode-${mode}">
        <div class="subx-summary-card">
          <span><i class="fas fa-location-dot"></i> Locations</span><b>${locCount}</b><small>${inboundSmall}</small>
        </div>
        <div class="subx-summary-card wide">
          <span><i class="fas fa-database"></i> Data</span><b>${dataLabel}</b><small>${remaining} remaining</small>${ringData}${barData}
        </div>
        <div class="subx-summary-card">
          <span><i class="fas fa-clock"></i> Time</span><b>${timerLabel}</b><small>${s.start_on_first_use?'starts on first use':'fixed expiry'}</small>${ringTime}
        </div>
        <div class="subx-summary-card status-card ${state.cls}">
          <span><i class="fas ${subxIconForState(state.cls)}"></i> Client status</span><b>${esc(state.label)}</b><small>${state.sub?esc(state.sub):'Ready for public link'}</small>
        </div>
      </div>
      <div class="subx-actions" aria-label="Subscription actions">
        <button class="subx-icon-btn" title="Copy public link" data-copy="${esc(s.public_url)}"><i class="fas fa-link"></i></button>
        <button class="subx-icon-btn" title="Copy config link" data-copy="${esc(s.config_url)}"><i class="fas fa-file-lines"></i></button>
        <button class="subx-icon-btn" title="Reset data" data-reset-data="${s.id}"><i class="fas fa-gauge-high"></i></button>
        <button class="subx-icon-btn" title="Reset timer" data-reset-timer="${s.id}"><i class="fas fa-clock-rotate-left"></i></button>
        <button class="subx-icon-btn" title="Manage inbounds" data-inbounds="${s.id}"><i class="fas fa-network-wired"></i></button>
        <button class="subx-icon-btn" title="Edit client" data-edit="${s.id}"><i class="fas fa-pen"></i></button>
        <button class="subx-icon-btn" title="More information" data-more="${s.id}"><i class="fas fa-circle-info"></i></button>
        <button class="subx-icon-btn danger" title="Delete" data-del="${s.id}"><i class="fas fa-trash"></i></button>
      </div>
    </div>
  </article>`;
}
function applySettingsToForm(){
  const s=SUB_SETTINGS||{layout:'aurora',support:{},display_mode:'hybrid'};
  const layout=s.layout||'aurora';
  const radio=document.querySelector(`input[name="sub-layout"][value="${layout}"]`); if(radio) radio.checked=true;
  const mode=s.display_mode||'hybrid'; const mr=document.querySelector(`input[name="sub-display-mode"][value="${mode}"]`); if(mr) mr.checked=true;
  const sup=s.support||{};
  ['telegram','whatsapp','phone','email','website','instagram'].forEach(k=>{const el=document.getElementById('sup-'+k); if(el) el.value=sup[k]||'';});
  const set=(id,val)=>{const el=document.getElementById(id); if(el) el.value=val||'';};
  set('portal-label',s.portal_label||sup.portal_label||'Secure WireGuard portal');
  set('portal-title',s.portal_title||'');
  set('portal-subtitle',s.portal_subtitle||'Your access is ready. Install WireGuard, then scan QR or import a config.');
  set('portal-icon',s.portal_icon||'fas fa-bolt');
  set('portal-animation',s.animation||'rich');
  updateLayoutPreview(layout);
}
function collectSettingsForm(){
  const layout=document.querySelector('input[name="sub-layout"]:checked')?.value||'aurora';
  const display_mode=document.querySelector('input[name="sub-display-mode"]:checked')?.value||'hybrid';
  try{localStorage.setItem('subx-display-mode', display_mode)}catch(_){}
  return {
    layout,
    display_mode,
    animation:$('#portal-animation')?.value||'rich',
    portal_label:$('#portal-label')?.value||'',
    portal_title:$('#portal-title')?.value||'',
    portal_subtitle:$('#portal-subtitle')?.value||'',
    portal_icon:$('#portal-icon')?.value||'fas fa-bolt',
    support:{telegram:$('#sup-telegram')?.value||'',whatsapp:$('#sup-whatsapp')?.value||'',phone:$('#sup-phone')?.value||'',email:$('#sup-email')?.value||'',website:$('#sup-website')?.value||'',instagram:$('#sup-instagram')?.value||''}
  };
}
function updateLayoutPreview(layout){
  const p=$('#layout-preview'); if(!p) return;
  const mode=document.querySelector('input[name="sub-display-mode"]:checked')?.value || $('#portal-animation')?.value && (SUB_SETTINGS?.display_mode||'hybrid') || 'hybrid';
  p.className='preview-card layout-'+(layout||'aurora')+' mode-'+mode;
  const icon=$('#portal-icon')?.value||'fas fa-bolt';
  const pi=p.querySelector('.preview-icon i'); if(pi) pi.className=icon;
  const label=$('#preview-label'); if(label) label.textContent=$('#portal-label')?.value||'Secure WireGuard portal';
  const title=$('#preview-title'); if(title) title.textContent=$('#portal-title')?.value||'premium-user';
  const sub=$('#preview-subtitle'); if(sub) sub.textContent=$('#portal-subtitle')?.value||'Your WireGuard access is ready.';
}
['portal-label','portal-title','portal-subtitle','portal-icon','portal-animation'].forEach(id=>document.getElementById(id)?.addEventListener('input',()=>updateLayoutPreview(document.querySelector('input[name="sub-layout"]:checked')?.value||'aurora')));
document.querySelectorAll('input[name="sub-display-mode"]').forEach(r=>r.addEventListener('change',()=>updateLayoutPreview(document.querySelector('input[name="sub-layout"]:checked')?.value||'aurora')));
try { setTimeout(() => loadSubs({force:true}), 0); } catch(_) {}

const SUBX_LIST = {
  q: '',
  status: 'all',
  scope: 'all',
  page: 1,
  perPage: Number(localStorage.getItem('subx-per-page') || 8)
};

function subxTtlText(sec){
  if(sec == null) return 'No time limit';
  sec = Math.max(0, Number(sec) || 0);
  if(sec <= 0) return 'Expired';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const parts = [];
  if(d) parts.push(`${d}d`);
  if(h || d) parts.push(`${h}h`);
  parts.push(`${m}m`);
  return `${parts.join(' ')} left`;
}

function subxSubscriptionState(s){
  const c = subscriptionPeerCounts(s);
  if(!s.enabled) return {label:'Disabled', cls:'disabled', sub:'Disabled in the panel'};
  if(c.blocked > 0) return {label:'Blocked', cls:'blocked', sub:'One or more configs are blocked'};
  if(c.total > 0) return {label:'Ready', cls:'online', sub:'Ready to use'};
  return {label:'No configs', cls:'offline', sub:'Add at least one config'};
}

function subxTimeHint(s){
  const ttl = s.ttl_seconds == null ? null : Number(s.ttl_seconds || 0);
  if(s.start_on_first_use && !s.first_used_at && ttl !== 0) return 'Starts on first use';
  if(ttl !== null && ttl <= 0) return 'Time limit reached';
  if(s.expires_at) return 'Expires on a set date';
  if(ttl === null) return 'No expiry limit';
  return 'Time remaining';
}

function subxUsagePct(s){
  if(!s.limit_bytes) return 0;
  return Math.max(0, Math.min(100, Math.round(Number(s.usage_pct || 0))));
}

function subxRemainingPct(s){
  return s.limit_bytes ? Math.max(0, 100 - subxUsagePct(s)) : 100;
}

function subxTimePct(s){
  if(s.ttl_seconds == null) return 100;
  return Number(s.ttl_seconds || 0) <= 0 ? 0 : 100;
}

function subxScopeOf(s){
  const locs = s.locations || [];
  const hasNode = locs.some(l => String(l.scope || '').toLowerCase() === 'node');
  const hasLocal = locs.some(l => String(l.scope || '').toLowerCase() !== 'node');
  if(hasNode && hasLocal) return 'mixed';
  if(hasNode) return 'node';
  if(hasLocal) return 'local';
  return 'none';
}

function subxStatusMatch(s, status){
  const st = subxSubscriptionState(s);
  const remPct = subxRemainingPct(s);
  const ttl = s.ttl_seconds == null ? null : Number(s.ttl_seconds || 0);
  if(status === 'all') return true;
  if(status === 'ready') return st.cls === 'online';
  if(status === 'blocked') return st.cls === 'blocked';
  if(status === 'disabled') return st.cls === 'disabled';
  if(status === 'empty') return !(s.locations || []).length;
  if(status === 'low-data') return !!s.limit_bytes && remPct <= 20;
  if(status === 'expiring') return ttl !== null && ttl > 0 && ttl <= 3 * 86400;
  return true;
}

function subxFilterSubs(){
  const q = (SUBX_LIST.q || '').trim().toLowerCase();
  return (SUBS || []).filter(s => {
    if(!subxStatusMatch(s, SUBX_LIST.status)) return false;
    if(SUBX_LIST.scope !== 'all'){
      const scope = subxScopeOf(s);
      if(SUBX_LIST.scope === 'mixed'){
        if(scope !== 'mixed') return false;
      } else if(scope !== SUBX_LIST.scope && scope !== 'mixed') {
        return false;
      }
    }
    if(!q) return true;
    const blob = [
      s.name, s.note, s.phone_number, s.telegram_id, s.status,
      ...(s.locations || []).flatMap(l => [
        l.name, l.iface, l.address, l.endpoint, l.location_label,
        l.node_name, l.scope, l.status, l.public_host
      ])
    ].map(v => String(v || '').toLowerCase()).join(' ');
    return blob.includes(q);
  });
}

function subxEnsureListTools(){
  if(document.getElementById('subx-list-tools')) return;
  const list = document.getElementById('subs-list');
  if(!list) return;

  const tools = document.createElement('section');
  tools.id = 'subx-list-tools';
  tools.className = 'subx-list-tools';
  tools.innerHTML = `
    <div class="subx-search-pill">
      <i class="fas fa-search"></i>
      <input id="subx-list-search" class="input" placeholder="Search clients, notes, phone, Telegram, IP, or location">
    </div>
    <div class="subx-filter-row" aria-label="Subscription filters">
      <button type="button" class="active" data-sub-filter="all">All</button>
      <button type="button" data-sub-filter="ready">Ready</button>
      <button type="button" data-sub-filter="blocked">Blocked</button>
      <button type="button" data-sub-filter="low-data">Low data</button>
      <button type="button" data-sub-filter="expiring">Expiring</button>
      <button type="button" data-sub-filter="empty">No configs</button>
      <button type="button" data-sub-filter="disabled">Disabled</button>
    </div>
    <div class="subx-filter-row subx-scope-row" aria-label="Location filters">
      <button type="button" class="active" data-sub-scope="all">All locations</button>
      <button type="button" data-sub-scope="local">Local</button>
      <button type="button" data-sub-scope="node">Nodes</button>
      <button type="button" data-sub-scope="mixed">Mixed</button>
    </div>
  `;
  list.parentNode.insertBefore(tools, list);

  const pager = document.createElement('section');
  pager.id = 'subx-pagination';
  pager.className = 'subx-pagination';
  list.parentNode.insertBefore(pager, list.nextSibling);

  document.getElementById('subx-list-search')?.addEventListener('input', e => {
    SUBX_LIST.q = e.target.value || '';
    SUBX_LIST.page = 1;
    renderSubscriptions();
  });

  tools.querySelectorAll('[data-sub-filter]').forEach(btn => {
    btn.addEventListener('click', () => {
      SUBX_LIST.status = btn.dataset.subFilter || 'all';
      SUBX_LIST.page = 1;
      tools.querySelectorAll('[data-sub-filter]').forEach(b => b.classList.toggle('active', b === btn));
      renderSubscriptions();
    });
  });

  tools.querySelectorAll('[data-sub-scope]').forEach(btn => {
    btn.addEventListener('click', () => {
      SUBX_LIST.scope = btn.dataset.subScope || 'all';
      SUBX_LIST.page = 1;
      tools.querySelectorAll('[data-sub-scope]').forEach(b => b.classList.toggle('active', b === btn));
      renderSubscriptions();
    });
  });
}

function subxActionButtons(s){
  return `<div class="subx-actions" aria-label="Subscription actions">
    <button class="subx-icon-btn" title="Copy public page link" data-copy="${esc(s.public_url)}"><i class="fas fa-link"></i></button>
    <button class="subx-icon-btn" title="Copy config bundle link" data-copy="${esc(s.config_url)}"><i class="fas fa-file-lines"></i></button>
    <button class="subx-icon-btn" title="Reset used data" data-reset-data="${s.id}"><i class="fas fa-gauge-high"></i></button>
    <button class="subx-icon-btn" title="Reset time limit" data-reset-timer="${s.id}"><i class="fas fa-clock-rotate-left"></i></button>
    <button class="subx-icon-btn" title="Manage inbounds" data-inbounds="${s.id}"><i class="fas fa-network-wired"></i></button>
    <button class="subx-icon-btn" title="Edit client" data-edit="${s.id}"><i class="fas fa-pen"></i></button>
    <button class="subx-icon-btn" title="View details" data-more="${s.id}"><i class="fas fa-circle-info"></i></button>
    <button class="subx-icon-btn danger" title="Delete subscription" data-del="${s.id}"><i class="fas fa-trash"></i></button>
  </div>`;
}

function rowHtml(s){
  const locs = s.locations || [];
  const state = subxSubscriptionState(s);
  const locCount = uniqueLocationCount(s);
  const inboundText = locs.length
    ? `${locs.length} config${locs.length > 1 ? 's' : ''}`
    : 'No config attached';

  const used = fmtBytes(s.used_bytes || 0);
  const unlimited = !!s.unlimited || !s.limit_bytes;
  const dataHeadline = unlimited
    ? `${used} used`
    : `${fmtBytes(s.remaining_bytes || 0)} left`;

  const dataDetail = unlimited
    ? 'No data cap'
    : `${used} used · ${fmtBytes(s.limit_bytes)} limit`;

  const startedValue =
    s.first_used_at ||
    (
      Array.isArray(locs)
        ? locs.map(x => x.first_used_at).filter(Boolean).sort()[0]
        : null
    );

  const startedText = startedValue
    ? `Active since ${subDate(startedValue)}`
    : (
        Number(s.used_bytes || 0) > 0
          ? 'Active · start time pending refresh'
          : 'Not started yet'
      );

  const timeHeadline = unlimited
    ? startedText
    : subxTtlText(s.ttl_seconds);

  const timeDetail = unlimited
    ? 'No expiry limit'
    : subxTimeHint(s);

  const dataPct = unlimited ? 100 : subxRemainingPct(s);
  const timePct = unlimited ? 100 : subxTimePct(s);
  const note = s.note || 'Multi-location client';
  const scope = subxScopeOf(s);
  const scopeText =
    scope === 'mixed' ? 'Local + nodes' :
    scope === 'node' ? 'Nodes only' :
    scope === 'local' ? 'Local only' :
    'No location yet';

  return `<article class="subx-row subx-row-line state-${state.cls}" data-sub="${s.id}">
    <div class="subx-line-id">
      <div class="subx-name"><i class="fas fa-user-shield"></i><span>${esc(s.name)}</span></div>
      <div class="subx-note">${esc(note)}</div>
    </div>

    <div class="subx-line-body">
      <div class="subx-line-top">
        <span><i class="fas fa-location-dot"></i> ${locCount} location${locCount === 1 ? '' : 's'} · ${esc(inboundText)}</span>
        <span><i class="fas fa-layer-group"></i> ${esc(scopeText)}</span>
        <span><i class="fas fa-database"></i> ${used} used · ${unlimited ? 'No data cap' : esc(fmtBytes(s.limit_bytes)) + ' limit'}</span>
        <span><i class="fas fa-play-circle"></i> ${esc(startedText)}</span>
      </div>

      <div class="subx-bars">
        <div class="subx-hbar data" title="${esc(dataHeadline + ' · ' + dataDetail)}">
          <span class="subx-hbar-label">
            <b>Data</b>
            <span class="subx-hbar-copy">
              <strong>${esc(dataHeadline)}</strong>
              <em>${esc(dataDetail)}</em>
            </span>
          </span>
          <i style="width:${Math.max(3, dataPct)}%"></i>
        </div>

        <div class="subx-hbar time" title="${esc(timeHeadline + ' · ' + timeDetail)}">
          <span class="subx-hbar-label">
            <b>Started</b>
            <span class="subx-hbar-copy">
              <strong>${esc(timeHeadline)}</strong>
              <em>${esc(timeDetail)}</em>
            </span>
          </span>
          <i style="width:${Math.max(3, timePct)}%"></i>
        </div>
      </div>
    </div>

    <div class="subx-line-state">
      <span class="subx-state-pill ${state.cls}">
        <i class="fas ${subxIconForState(state.cls)}"></i>${esc(state.label)}
      </span>
      <small>${esc(state.sub)}</small>
    </div>

    ${subxActionButtons(s)}
  </article>`;
}

function renderSubscriptions(){
  subxEnsureListTools();
  const list = document.getElementById('subs-list');
  const empty = document.getElementById('subs-empty');
  const pager = document.getElementById('subx-pagination');
  if(!list) return;

  const filtered = subxFilterSubs();
  const total = filtered.length;
  const perPage = Math.max(1, Number(SUBX_LIST.perPage || 8));
  const pages = Math.max(1, Math.ceil(total / perPage));
  SUBX_LIST.page = Math.max(1, Math.min(Number(SUBX_LIST.page || 1), pages));
  const start = (SUBX_LIST.page - 1) * perPage;
  const rows = filtered.slice(start, start + perPage);

  list.innerHTML = rows.map(rowHtml).join('');

  if(empty){
    empty.hidden = true;
    empty.style.display = 'none';
  }

  if(total <= 0){
    list.innerHTML = `<div class="subx-empty subx-filter-empty">
      <i class="fas fa-filter-circle-xmark"></i>
      <b>No matching subscriptions</b>
      <span>Try clearing search or choosing a different filter.</span>
    </div>`;
  }

  if(pager){
    const from = total ? start + 1 : 0;
    const to = Math.min(start + perPage, total);
    pager.innerHTML = `
      <div class="subx-page-info">${from}-${to} of ${total} clients</div>
      <div class="subx-page-controls">
        <button type="button" data-page-first ${SUBX_LIST.page<=1?'disabled':''}><i class="fas fa-angles-left"></i></button>
        <button type="button" data-page-prev ${SUBX_LIST.page<=1?'disabled':''}><i class="fas fa-chevron-left"></i></button>
        <span>Page <b>${SUBX_LIST.page}</b> of <b>${pages}</b></span>
        <button type="button" data-page-next ${SUBX_LIST.page>=pages?'disabled':''}><i class="fas fa-chevron-right"></i></button>
        <button type="button" data-page-last ${SUBX_LIST.page>=pages?'disabled':''}><i class="fas fa-angles-right"></i></button>
        <select id="subx-per-page" class="input" aria-label="Clients per page">
          ${[5,8,12,20,50].map(n=>`<option value="${n}" ${n===perPage?'selected':''}>${n} / page</option>`).join('')}
        </select>
      </div>
    `;
    pager.querySelector('[data-page-first]')?.addEventListener('click',()=>{SUBX_LIST.page=1;renderSubscriptions();});
    pager.querySelector('[data-page-prev]')?.addEventListener('click',()=>{SUBX_LIST.page--;renderSubscriptions();});
    pager.querySelector('[data-page-next]')?.addEventListener('click',()=>{SUBX_LIST.page++;renderSubscriptions();});
    pager.querySelector('[data-page-last]')?.addEventListener('click',()=>{SUBX_LIST.page=pages;renderSubscriptions();});
    pager.querySelector('#subx-per-page')?.addEventListener('change',e=>{
      SUBX_LIST.perPage = Number(e.target.value || 8);
      try{localStorage.setItem('subx-per-page', String(SUBX_LIST.perPage));}catch(_){}
      SUBX_LIST.page = 1;
      renderSubscriptions();
    });
  }
}

async function loadSubs(opts={}){
  if(SUBS_LOADING) return;
  if(!opts.force && modalIsOpen()) return;
  SUBS_LOADING = true;
  setLiveState('Refreshing…', 'loading');
  try {
    const r = await fetch('/api/subscriptions', {credentials:'same-origin', cache:'no-store'});
    const j = await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(j.detail || j.error || 'Load failed');

    const next = j.subscriptions || [];
    const nextJson = JSON.stringify(next);
    SUBS = next;

    if(opts.force || nextJson !== SUBS_LAST_JSON){
      renderSubscriptions();
      SUBS_LAST_JSON = nextJson;
    }

    const totalEl = $('#st-total');
    const inboundEl = $('#st-inbounds');
    const blockedEl = $('#st-blocked');
    if(totalEl) totalEl.textContent = SUBS.length;
    if(inboundEl) inboundEl.textContent = SUBS.reduce((a,s)=>a+(s.locations||[]).length,0);
    if(blockedEl) blockedEl.textContent = SUBS.reduce((a,s)=> a + (subxSubscriptionState(s).cls === 'blocked' ? 1 : 0), 0);

    if(detailsIsOpen()){
      const openId = $('#details-modal')?.dataset?.sid;
      const current = SUBS.find(x=>String(x.id)===String(openId));
      if(current) renderDetails(current, {keepOpen:true});
    }
    setLiveState(`Updated ${nowClock()}`);
  } catch(err) {
    setLiveState(`Live update failed: ${err.message || err}`, 'error');
  } finally {
    SUBS_LOADING = false;
  }
}

setTimeout(()=>renderSubscriptions(), 0);


(() => {
  const run = () => {
    const toggle = document.getElementById('sub-include-internal-network');
    if (!toggle || toggle.dataset.autoNetworkWired === '1') return;
    toggle.dataset.autoNetworkWired = '1';
    toggle.addEventListener('change', subApplyInternalNetworksToAllowed);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', run, {once:true});
  else run();
})();

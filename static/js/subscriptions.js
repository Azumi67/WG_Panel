const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function subToast(msg, type='success', duration=3000){
  let box=document.getElementById('subx-toast-box');
  if(!box){
    box=document.createElement('div');
    box.id='subx-toast-box';
    box.setAttribute('aria-live','polite');
    box.setAttribute('aria-atomic','false');
    document.body.appendChild(box);
  }

  const normalized = type==='warn' ? 'warning' : (type || 'info');
  const meta = {
    success:{icon:'fa-circle-check', title:'Saved'},
    error:{icon:'fa-circle-xmark', title:'Something went wrong'},
    warning:{icon:'fa-triangle-exclamation', title:'Attention'},
    info:{icon:'fa-circle-info', title:'Information'},
  }[normalized] || {icon:'fa-circle-info', title:'Information'};

  const t=document.createElement('div');
  t.className=`subx-toast ${normalized}`;
  t.setAttribute('role', normalized==='error' ? 'alert' : 'status');
  t.innerHTML=`
    <span class="subx-toast-icon" aria-hidden="true"><i class="fas ${meta.icon}"></i></span>
    <span class="subx-toast-copy">
      <b class="subx-toast-title">${meta.title}</b>
      <span class="subx-toast-message"></span>
    </span>
    <button class="subx-toast-close" type="button" aria-label="Dismiss notification"><i class="fas fa-xmark"></i></button>
    <span class="subx-toast-progress" aria-hidden="true"></span>`;
  t.querySelector('.subx-toast-message').textContent=String(msg ?? '');
  box.appendChild(t);

  let removed=false;
  let raf=0;
  const started=performance.now();
  const ms=Math.max(1400, Number(duration)||3000);
  const progress=t.querySelector('.subx-toast-progress');

  const remove=()=>{
    if(removed) return;
    removed=true;
    cancelAnimationFrame(raf);
    t.classList.add('hiding');
    t.classList.remove('show');
    setTimeout(()=>t.remove(),220);
  };
  t.querySelector('.subx-toast-close')?.addEventListener('click',remove);

  const tick=now=>{
    const pct=Math.max(0,1-(now-started)/ms);
    if(progress) progress.style.transform=`scaleX(${pct})`;
    if(pct>0&&!removed) raf=requestAnimationFrame(tick);
    else remove();
  };

  requestAnimationFrame(()=>{
    t.classList.add('show');
    raf=requestAnimationFrame(tick);
  });
}
const toastOk = m => subToast(m,'success');
const toastBad = m => subToast(m,'error');


function ensureSubActionLoaderStyle(){
  if(document.getElementById('subx-action-loader-style')) return;
  const style=document.createElement('style');
  style.id='subx-action-loader-style';
  style.textContent=`
    .subx-action-loader{
      position:fixed;inset:0;z-index:2147483000;
      display:grid;place-items:center;padding:24px;
      background:rgba(4,8,12,.72);backdrop-filter:blur(8px);
      opacity:0;visibility:hidden;transition:opacity .16s ease,visibility .16s ease;
    }
    .subx-action-loader.show{opacity:1;visibility:visible}
    .subx-action-loader-card{
      width:min(440px,calc(100vw - 32px));
      display:grid;grid-template-columns:48px minmax(0,1fr);gap:16px;align-items:center;
      padding:20px 22px;border-radius:18px;
      border:1px solid rgba(130,151,168,.26);
      background:#101820;color:#d9e1e8;
      box-shadow:0 28px 80px rgba(0,0,0,.52);
    }
    .subx-action-loader-spinner{
      width:42px;height:42px;border-radius:50%;
      border:3px solid rgba(148,163,184,.20);
      border-top-color:#3aa783;
      animation:subxActionSpin .78s linear infinite;
    }
    .subx-action-loader-copy{min-width:0}
    .subx-action-loader-title{font-size:15px;font-weight:800;letter-spacing:.01em;color:#e3e9ee}
    .subx-action-loader-text{margin-top:5px;font-size:12.5px;line-height:1.5;color:#8f9daa}
    body.subx-action-running{overflow:hidden!important}
    @keyframes subxActionSpin{to{transform:rotate(360deg)}}
    @media (prefers-reduced-motion:reduce){.subx-action-loader-spinner{animation-duration:1.5s}}
  `;
  document.head.appendChild(style);
}

function showSubActionLoader(title, text){
  ensureSubActionLoaderStyle();
  document.getElementById('subx-action-loader')?.remove();
  const overlay=document.createElement('div');
  overlay.id='subx-action-loader';
  overlay.className='subx-action-loader';
  overlay.setAttribute('role','status');
  overlay.setAttribute('aria-live','polite');
  overlay.setAttribute('aria-busy','true');
  overlay.innerHTML=`
    <div class="subx-action-loader-card">
      <span class="subx-action-loader-spinner" aria-hidden="true"></span>
      <div class="subx-action-loader-copy">
        <div class="subx-action-loader-title">${esc(title)}</div>
        <div class="subx-action-loader-text">${esc(text)}</div>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  document.body.classList.add('subx-action-running');
  requestAnimationFrame(()=>overlay.classList.add('show'));
  return overlay;
}

function hideSubActionLoader(){
  const overlay=document.getElementById('subx-action-loader');
  document.body.classList.remove('subx-action-running');
  if(!overlay) return;
  overlay.classList.remove('show');
  setTimeout(()=>overlay.remove(),170);
}

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

function subscriptionTimePresentation(s){
  const unlimited = !!s.unlimited || !Number(s.limit_bytes || 0);
  const locs = Array.isArray(s.locations) ? s.locations : [];
  const startedAt = s.first_used_at || locs.map(x=>x.first_used_at).filter(Boolean).sort()[0] || null;

  if(unlimited){
    return {
      title: 'Active since',
      value: startedAt
        ? subDate(startedAt)
        : (s.enabled === false ? 'Not started' : 'Waiting for first use'),
      hint: s.enabled === false ? 'Subscription disabled' : 'No expiry limit',
      top: startedAt ? `Active since ${subDate(startedAt)}` : (s.enabled === false ? 'Not started' : 'Waiting for first use'),
      percent: 100
    };
  }

  return {
    title: 'Time remaining',
    value: subxTtlText(s.ttl_seconds),
    hint: subxTimeHint(s),
    top: subxTtlText(s.ttl_seconds),
    percent: subxTimePct(s)
  };
}
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
let SUB_STUDIO_TARGET_ID=null, SUB_STUDIO_TARGET_NAME='', SUB_STUDIO_HAS_OVERRIDE=false;
let SUBS_LIVE_TIMER=null, SUBS_LOADING=false, SUBS_LAST_JSON='';
let SUBX_MOBILE_MANAGE_ID = null;
let CURRENT_SELECTED = new Set();
let OPEN_SUBSCRIPTION_LOGS_SID = null;
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
  const modal = $('#sub-settings-modal');
  if (!modal) return;

  if (window.matchMedia('(max-width: 820px)').matches && modal.parentElement !== document.body) {
    document.body.appendChild(modal);
  }

  document.body.classList.remove('mobile-nav-open');
  document.body.classList.add('mobile-sub-studio-open');
  document.getElementById('mobile-nav-toggle')?.setAttribute('aria-expanded','false');

  modal.classList.add('open');
  modal.setAttribute('aria-hidden','false');
  subxUpdateModalBodyState();
}

function closeSettings(){
  const modal = $('#sub-settings-modal');
  if (!modal) return;
  modal.classList.remove('open');
  modal.setAttribute('aria-hidden','true');
  document.body.classList.remove('mobile-sub-studio-open');
  subxUpdateModalBodyState();
}

async function loadSubscriptionSettings(sid=null){
  SUB_STUDIO_TARGET_ID = sid == null ? null : Number(sid);
  const endpoint = SUB_STUDIO_TARGET_ID
    ? `/api/subscriptions/${SUB_STUDIO_TARGET_ID}/portal-settings`
    : '/api/subscriptions/settings';
  const r = await fetch(endpoint, {credentials:'same-origin', cache:'no-store'});
  const j = await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(j.detail || j.message || j.error || 'Could not load template settings.');
  if(SUB_STUDIO_TARGET_ID){
    SUB_STUDIO_TARGET_NAME = j.subscription_name || (SUBS.find(x=>Number(x.id)===SUB_STUDIO_TARGET_ID)?.name || `Client #${SUB_STUDIO_TARGET_ID}`);
    SUB_STUDIO_HAS_OVERRIDE = !!j.has_override;
    SUB_SETTINGS = j.settings || j.global_settings || {};
  }else{
    SUB_STUDIO_TARGET_NAME = '';
    SUB_STUDIO_HAS_OVERRIDE = false;
    SUB_SETTINGS = j || {};
  }
  applySettingsToForm();
  updateStudioTargetUI();
  return SUB_SETTINGS;
}

function updateStudioTargetUI(){
  const actions=document.querySelector('#sub-settings-modal .studio8-head-actions');
  if(!actions) return;
  let box=document.getElementById('studio-template-target');
  if(!box){
    box=document.createElement('div');
    box.id='studio-template-target';
    box.className='studio-template-target';
    actions.prepend(box);
  }
  if(SUB_STUDIO_TARGET_ID){
    box.innerHTML=`<span class="studio-template-target-badge"><i class="fas fa-user"></i><span><small>Editing template for</small><b>${esc(SUB_STUDIO_TARGET_NAME)}</b></span></span><button type="button" id="studio-use-global" class="studio-template-inherit" ${SUB_STUDIO_HAS_OVERRIDE?'':'disabled'} title="Remove this client override and inherit the global template"><i class="fas fa-rotate-left"></i><span>${SUB_STUDIO_HAS_OVERRIDE?'Use global':'Using global'}</span></button>`;
    document.getElementById('studio-use-global')?.addEventListener('click',async()=>{
      if(!SUB_STUDIO_TARGET_ID || !SUB_STUDIO_HAS_OVERRIDE) return;
      try{
        const r=await fetch(`/api/subscriptions/${SUB_STUDIO_TARGET_ID}/portal-settings`,{method:'DELETE',headers:csrfHeaders(true),credentials:'same-origin',cache:'no-store'});
        const j=await r.json().catch(()=>({}));
        if(!r.ok) throw new Error(j.detail||j.message||j.error||'Could not remove client template override.');
        SUB_STUDIO_HAS_OVERRIDE=false;
        SUB_SETTINGS=j.settings||{};
        window.SubscriptionStudioV14?.apply?.(SUB_SETTINGS);
        window.SubscriptionStudioV13?.apply?.(SUB_SETTINGS);
        applySettingsToForm();
        updateStudioTargetUI();
        toastOk('This client now inherits the global subscription template.');
      }catch(err){toastBad(err.message||String(err));}
    });
  }else{
    box.innerHTML='<span class="studio-template-target-badge global"><i class="fas fa-earth-europe"></i><span><small>Editing</small><b>Global default template</b></span></span>';
  }
}

async function openClientTemplateStudio(sid){
  try{
    await loadSubscriptionSettings(sid);
    openSettings();
  }catch(err){toastBad(err.message||String(err));}
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
  const body = window.SubscriptionStudioV14?.collect?.()
    || window.SubscriptionStudioV13?.collect?.()
    || window.SubscriptionStudioV9?.collect?.()
    || collectSettingsForm();

  const endpoint = SUB_STUDIO_TARGET_ID
    ? `/api/subscriptions/${SUB_STUDIO_TARGET_ID}/portal-settings`
    : '/api/subscriptions/settings';

  const r = await fetch(endpoint, {
    method:'POST', headers:csrfHeaders(true), credentials:'same-origin', cache:'no-store', body:JSON.stringify(body)
  });
  const j = await r.json().catch(()=>({}));
  if(!r.ok){ toastBad(j.detail || j.message || j.error || 'Settings save failed.'); return; }

  let saved = SUB_STUDIO_TARGET_ID ? (j.settings || null) : (j.settings || null);
  try{
    const verify=await fetch(endpoint,{credentials:'same-origin',cache:'no-store'});
    if(verify.ok){
      const v=await verify.json();
      saved=SUB_STUDIO_TARGET_ID ? (v.settings||saved) : v;
      if(SUB_STUDIO_TARGET_ID){SUB_STUDIO_HAS_OVERRIDE=!!v.has_override;SUB_STUDIO_TARGET_NAME=v.subscription_name||SUB_STUDIO_TARGET_NAME;}
    }
  }catch(_){}

  SUB_SETTINGS=saved||body;
  window.SubscriptionStudioV14?.apply?.(SUB_SETTINGS);
  window.SubscriptionStudioV13?.apply?.(SUB_SETTINGS);
  window.SubscriptionStudioV9?.apply?.(SUB_SETTINGS);
  updateStudioTargetUI();

  const expected=String(body.layout||'aurora');
  const persisted=String((SUB_SETTINGS||{}).layout||expected);
  if(persisted!==expected){toastBad(`The server returned “${persisted}” after saving “${expected}”. app.py is still using old layout validation.`);return;}

  const layoutNames={ps5:'PS5',mac:'macOS',app:'Desktop app',compact:'Compact',minimal:'Minimal',showcase:'Showcase',aurora:'PS5',cards:'macOS',console:'Desktop app',split:'Showcase',profile:'Showcase',executive:'macOS',flow:'Minimal'};
  toastOk(SUB_STUDIO_TARGET_ID
    ? `${SUB_STUDIO_TARGET_NAME} template saved · ${layoutNames[persisted]||persisted}`
    : `Global template saved · ${layoutNames[persisted]||persisted}`);
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

    const network =
      x.server_cidr ||
      x.interface_address ||
      'network unavailable';

    return `${source} · ${esc(network)}${
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
    const srcBlob = [src.scope, src.node_name, src.label, src.iface, src.name, src.server_cidr, src.listen_port].map(v => String(v||'').toLowerCase()).join(' ');
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
        <button class="subx-icon-btn" title="Customize public template for this client" data-template="${s.id}"><i class="fas fa-wand-magic-sparkles"></i></button><button class="subx-icon-btn" title="Edit client" data-edit="${s.id}"><i class="fas fa-pen"></i></button>
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

  try {
    await loadPickers();
    refreshSubscriptionInternalNetworks();
  } catch (err) {
    console.debug('Could not refresh subscription networks while editing:', err);
  }
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
  const modal = $('#sub-modal');
  if(modal) modal.dataset.inboundMode = MODE;
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
      item?.server_cidr ||
      item?.interface_address ||
      item?.address ||
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
function subscriptionEditNetworkItems() {
  if (!EDIT_ID || !Array.isArray(NEW_ITEMS) || !NEW_ITEMS.length) return [];

  const subscription = SUBS.find(item => String(item?.id) === String(EDIT_ID));
  const locations = Array.isArray(subscription?.locations) ? subscription.locations : [];
  if (!locations.length) return [];

  const sameText = (a, b) => String(a ?? '').trim().toLowerCase() === String(b ?? '').trim().toLowerCase();

  return NEW_ITEMS.filter(item => locations.some(location => {
    const itemScope = String(item?.scope || 'local').toLowerCase();
    const locationScope = String(location?.scope || 'local').toLowerCase();
    if (itemScope !== locationScope) return false;

    const itemIface = item?.iface || item?.interface || item?.interface_name || item?.name || '';
    const locationIface = location?.iface || location?.interface || location?.interface_name || '';
    if (locationIface && !sameText(itemIface, locationIface)) return false;

    if (itemScope === 'node') {
      const itemNodeId = item?.node_id;
      const locationNodeId = location?.node_id;
      if (itemNodeId != null && locationNodeId != null && String(itemNodeId) !== String(locationNodeId)) return false;

      if (locationNodeId == null) {
        const itemNodeName = item?.node_name || item?.location || item?.label || '';
        const locationNodeName = location?.node_name || location?.node || location?.location || '';
        if (locationNodeName && itemNodeName && !sameText(itemNodeName, locationNodeName)) return false;
      }
    }

    return true;
  }));
}

function detectSelectedSubscriptionNetworks() {
  const chosen =
    MODE === 'new'
      ? selectedItems()
      : [];

  const editItems = subscriptionEditNetworkItems();

  const source =
    chosen.length
      ? chosen
      : editItems.length
        ? editItems
        : (EDIT_ID ? [] : (Array.isArray(NEW_ITEMS) ? NEW_ITEMS : []));

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
      item?.server_cidr ||
      item?.interface_address ||
      item?.address ||
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
function getSelectedInternalNetworks(){
  return subUniqueRoutes(document.getElementById('sub-selected-internal-networks')?.value || '');
}
function setSelectedInternalNetworks(routes){
  const input=document.getElementById('sub-selected-internal-networks');
  if(input) input.value=subUniqueRoutes((routes||[]).join(', ')).join(', ');
}
function renderAutoNetworkChooser(){
  const mount=document.getElementById('sub-auto-network-route-list');
  const input=document.getElementById('sub-internal-networks');
  if(!mount||!input) return;
  const detected=subNormalizeNetworkList(input.value);
  let selected=getSelectedInternalNetworks();
  if(!selected.length && detected.length) selected=[...detected];
  selected=selected.filter(route=>detected.includes(route));
  setSelectedInternalNetworks(selected);
  if(!detected.length){
    mount.innerHTML='<div class="subx-network-route-empty">No private networks detected yet. Select interfaces first.</div>';
    return;
  }
  mount.innerHTML=detected.map((route,index)=>{
    const checked=selected.includes(route)?'checked':'';
    const scope=route.startsWith('10.')?'Private LAN':route.startsWith('172.')?'Private subnet':route.startsWith('192.168.')?'Local segment':'Detected route';
    return `<label class="subx-network-route"><input type="checkbox" value="${route}" ${checked}><span class="subx-network-route-card-item"><span class="subx-network-route-badge"><i class="fas fa-plus"></i></span><span class="subx-network-route-copy"><b>${route}</b><small>${scope}</small></span><span class="subx-network-route-check"><i class="fas fa-check"></i></span></span></label>`;
  }).join('');
  mount.querySelectorAll('input[type="checkbox"]').forEach(box=>box.addEventListener('change',()=>{
    const selected=[...mount.querySelectorAll('input[type="checkbox"]:checked')].map(el=>el.value);
    setSelectedInternalNetworks(selected);
    updateAutoNetworkPreview();
    subApplyInternalNetworksToAllowed();
  }));
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
  const detected = enabled ? getSelectedInternalNetworks() : [];
  for(const route of detected){
    if(!current.includes(route)) current.push(route);
  }

  allowed.dataset.autoInternalNetworks = enabled ? detected.join(', ') : '';
  allowed.value = current.join(', ');
  allowed.dispatchEvent(new Event('input', {bubbles:true}));
  allowed.dispatchEvent(new Event('change', {bubbles:true}));
  updateAutoNetworkPreview();
}
function updateAutoNetworkPreview(){
  const title=document.getElementById('sub-auto-network-title');
  const note=document.getElementById('sub-auto-network-note');
  const tags=document.getElementById('sub-auto-network-tags');
  const toggle=document.getElementById('sub-include-internal-network');
  const input=document.getElementById('sub-internal-networks');
  if(!title||!note||!tags||!input) return;
  const detected=subNormalizeNetworkList(input.value);
  const selected=getSelectedInternalNetworks().filter(route=>detected.includes(route));
  const enabled=!!toggle?.checked;
  tags.innerHTML='';
  if(!detected.length){
    title.textContent='No extra private networks detected yet';
    note.textContent='Select one or more interfaces to preview which private networks can be appended here.';
    tags.innerHTML='<span class="net-chip muted"><i class="fas fa-info-circle"></i>No detected private routes</span>';
    return;
  }
  if(enabled){
    title.textContent=`${selected.length} selected private route${selected.length===1?'':'s'} will be appended`;
    note.textContent=selected.length ? 'Only the selected routes are appended to Allowed IPs. Uncheck any route below to leave it out.' : 'No route is selected yet. Pick one or more routes below to append them.';
  }else{
    title.textContent=`${detected.length} private route${detected.length===1?'':'s'} detected`;
    note.textContent='You can preselect routes below first, then enable the toggle when you want them appended automatically.';
  }
  tags.innerHTML=(enabled?selected:detected).map(net=>`<span class="net-chip"><i class="fas ${selected.includes(net)?'fa-check':'fa-plus'}"></i>${net}</span>`).join('') || '<span class="net-chip muted"><i class="fas fa-circle-exclamation"></i>No route selected yet</span>';
}

function refreshSubscriptionInternalNetworks(){
  if(window.SubscriptionAdvancedV9?.refresh){window.SubscriptionAdvancedV9.refresh();return;}
  const input=document.getElementById('sub-internal-networks');
  if(!input)return;
  const detected=detectSelectedSubscriptionNetworks();
  input.value=detected.join(', ');
  const current=getSelectedInternalNetworks().filter(route=>detected.includes(route));
  setSelectedInternalNetworks(current.length?current:detected);
  renderAutoNetworkChooser();
  subApplyInternalNetworksToAllowed();
  updateAutoNetworkPreview();
}
function subFixedClientEndpointError(value) {
  const raw = String(value || '').trim();
  if(!raw) return '';

  if(/\s/.test(raw) || raw.includes('://') || raw.includes('/') || raw.includes('?') || raw.includes('#')){
    return 'Fixed client endpoint must contain only a host and UDP port, for example client.example.com:51820.';
  }

  let portText = '';

  if(raw.startsWith('[')){
    const match = /^\[([0-9A-Fa-f:.]+)\]:(\d{1,5})$/.exec(raw);
    if(!match) return 'IPv6 fixed client endpoints must use [IPv6-address]:port format.';
    portText = match[2];
  } else {
    const split = raw.lastIndexOf(':');
    if(split <= 0 || raw.indexOf(':') !== split){
      return 'Fixed client endpoint must use host:port format. Put IPv6 addresses inside brackets.';
    }
    const host = raw.slice(0, split).trim();
    portText = raw.slice(split + 1).trim();
    if(!host || !/^[A-Za-z0-9._-]+$/.test(host)){
      return 'Fixed client endpoint host is invalid.';
    }
  }

  const port = Number(portText);
  if(!Number.isInteger(port) || port < 1 || port > 65535){
    return 'Fixed client endpoint port must be between 1 and 65535.';
  }

  return '';
}

function syncSubscriptionFixedClientInfo(){
  const input = document.getElementById('sub-peer-endpoint');
  const info = document.getElementById('sub-fixed-client-info');
  if(!input || !info) return;
  info.classList.toggle('has-value', !!String(input.value || '').trim());
}

function payloadFromForm() {
  const form = $('#sub-form');
  const fd = new FormData(form);
  const body = Object.fromEntries(fd.entries());
  body.time_limit_days =Number(fd.get('time_limit_days') || 0) +(Number(fd.get('time_limit_hours') || 0) / 24) +(Number(fd.get('time_limit_minutes') || 0) / 1440);
  body.start_on_first_use = fd.has('start_on_first_use'); body.unlimited = fd.has('unlimited'); body.include_internal_network = fd.has('include_internal_network'); body.sync_existing = !!$('#sync-existing')?.checked;
  if (MODE === 'new' && document.getElementById('sub-include-internal-network')?.checked) {
    const selectedNetworks = window.SubscriptionAdvancedV9?.getSelectedInternalNetworks?.() || getSelectedInternalNetworks();
    for (const network of selectedNetworks) body.allowed_ips=subAppendAllowedRoute(body.allowed_ips,network);
  }

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
      server_cidr: x.server_cidr || x.interface_address || '',
      peer_name: prefix ? `${prefix}-${i+1}` : ''
    };
  });
  return body;
}

$('#open-sub-modal').onclick=openCreate; $('#sub-close').onclick=closeModal; $('#sub-cancel').onclick=closeModal;
$('#details-close').onclick=closeDetails;

$('#open-sub-settings').onclick=async()=>{ try{await loadSubscriptionSettings(null);openSettings();}catch(err){toastBad(err.message||String(err));} };
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
  const fixedEndpointError = subFixedClientEndpointError(body.peer_endpoint);
  if(fixedEndpointError){
    const advanced = document.getElementById('new-defaults');
    const info = document.getElementById('sub-fixed-client-info');
    const input = document.getElementById('sub-peer-endpoint');
    if(advanced) advanced.open = true;
    if(info) info.open = true;
    toastBad(fixedEndpointError);
    input?.focus();
    return;
  }
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


function subxRelativeTime(value){
  if(value === null || value === undefined || value === '') return '';
  let ms;
  if(typeof value === 'number' && Number.isFinite(value)) ms = value < 1e12 ? value * 1000 : value;
  else {
    const parsed = Date.parse(String(value));
    if(!Number.isFinite(parsed)) return String(value);
    ms = parsed;
  }
  const diff = Math.round((Date.now() - ms) / 1000);
  const future = diff < 0;
  const sec = Math.abs(diff);
  let n, unit;
  if(sec < 10) return future ? 'in a few seconds' : 'just now';
  if(sec < 60){ n=sec; unit='s'; }
  else if(sec < 3600){ n=Math.floor(sec/60); unit='m'; }
  else if(sec < 86400){ n=Math.floor(sec/3600); unit='h'; }
  else if(sec < 604800){ n=Math.floor(sec/86400); unit='d'; }
  else if(sec < 2592000){ n=Math.floor(sec/604800); unit='w'; }
  else if(sec < 31536000){ n=Math.floor(sec/2592000); unit='mo'; }
  else { n=Math.floor(sec/31536000); unit='y'; }
  return future ? `in ${n}${unit}` : `${n}${unit} ago`;
}

function subxExactTime(value){
  if(!value) return '';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString([], {dateStyle:'medium', timeStyle:'medium'});
}

function subscriptionConnectionPresentation(s){
  const locs = Array.isArray(s?.locations) ? s.locations : [];
  const api = s?.connection || {};
  const connectedLocs = locs.filter(loc => loc?.connected === true || String(loc?.connection_status || loc?.conn_status || '').toLowerCase() === 'connected' || String(loc?.conn_status || '').toLowerCase() === 'online');
  let active = null;
  if(api.active_peer_id != null) active = locs.find(loc => String(loc.peer_id) === String(api.active_peer_id)) || null;
  if(!active && connectedLocs.length) active = connectedLocs.slice().sort((a,b)=>(Number(b.latest_handshake)||0)-(Number(a.latest_handshake)||0))[0];
  if(!active) active = locs.slice().sort((a,b)=>(Number(b.latest_handshake)||0)-(Number(a.latest_handshake)||0))[0] || null;

  const connected = api.connected === true || connectedLocs.length > 0;
  const runtimeUnavailable = locs.length > 0 && locs.every(loc => loc.runtime_available === false);
  const peerName = api.active_peer_name || active?.name || '';
  const scope = api.active_scope || active?.scope || '';
  const nodeName = api.active_node_name || active?.node_name || '';
  const iface = api.active_iface || active?.iface || '';
  const last = api.last_activity_at || active?.last_activity_at || '';
  const where = [scope === 'node' ? (nodeName || 'Node') : (scope === 'local' ? 'Local' : ''), iface].filter(Boolean).join(' / ');

  if(!locs.length) return {cls:'none', label:'No connection', detail:'No configs attached', title:'No WireGuard configs are attached to this client.'};
  if(runtimeUnavailable) return {cls:'unknown', label:'Status unavailable', detail:'Runtime could not be reached', title:'The panel could not read the attached WireGuard runtime.'};
  if(connected){
    const count = Number(api.connected_count || connectedLocs.length || 1);
    const detail = count > 1
      ? `${count} peers active${peerName ? ` · latest ${peerName}` : ''}${where ? ` · ${where}` : ''}`
      : `${peerName || 'Peer'}${where ? ` · ${where}` : ''}`;
    return {cls:'connected', label:'Connected', detail, title:`Live WireGuard activity${last ? ` · ${subxExactTime(last)}` : ''}`};
  }
  return {
    cls:'disconnected',
    label:'Disconnected',
    detail:last ? `Last activity ${subxRelativeTime(last)}${peerName ? ` · ${peerName}` : ''}` : 'No recent WireGuard activity',
    title:last ? `Last WireGuard handshake: ${subxExactTime(last)}` : 'No recent WireGuard handshake was detected.'
  };
}

function subscriptionLogEventLabel(value){
  return String(value || 'event').replace(/[_-]+/g, ' ').replace(/\b\w/g, ch=>ch.toUpperCase());
}

function renderSubscriptionLogRows(logs){
  const rows = Array.isArray(logs) ? logs : [];
  if(!rows.length){
    return `<div class="subx-peer-log-empty"><i class="fas fa-clock-rotate-left"></i><b>No subscription events yet</b><span>Enable, disable, reset, edit, and inbound events from attached configs will appear here.</span></div>`;
  }
  return `<div class="subx-peer-log-list">${rows.map(row=>{
    const event = row.event || row.level || 'event';
    const details = row.details || row.text || '';
    const time = row.time || row.ts || '';
    const source = row.source_name || 'Attached config';
    const level = String(row.level || 'info').toLowerCase();
    const relative = time ? subxRelativeTime(time) : '';
    const exact = time ? subxExactTime(time) : '';
    return `<article class="subx-peer-log-row level-${esc(level)}">
      <span class="subx-peer-log-dot"></span>
      <div class="subx-peer-log-copy">
        <div class="subx-log-mainline"><span class="subx-log-event"><b>${esc(subscriptionLogEventLabel(event))}</b><span class="subx-log-source">${esc(source)}</span></span>${time ? `<time title="${esc(exact)}">${esc(relative || exact)}</time>` : ''}</div>
        <p>${esc(details || 'No additional details.')}</p>
      </div>
    </article>`;
  }).join('')}</div>`;
}

function ensureSubscriptionLogsDrawer(){
  let shell = document.getElementById('subscription-logs-drawer');
  if(shell) return shell;

  shell = document.createElement('div');
  shell.id = 'subscription-logs-drawer';
  shell.className = 'subx-logs-drawer-shell';
  shell.setAttribute('aria-hidden', 'true');
  shell.innerHTML = `
    <button class="subx-logs-drawer-backdrop" type="button" data-close-subscription-logs aria-label="Close subscription logs"></button>
    <aside class="subx-logs-drawer" role="dialog" aria-modal="true" aria-labelledby="subscription-logs-title">
      <div id="subscription-logs-content" class="subx-logs-drawer-content"></div>
    </aside>`;
  document.body.appendChild(shell);
  return shell;
}

function closeSubscriptionLogs(){
  OPEN_SUBSCRIPTION_LOGS_SID = null;
  const shell = document.getElementById('subscription-logs-drawer');
  if(!shell) return;
  shell.classList.remove('open');
  shell.setAttribute('aria-hidden','true');
  document.body.classList.remove('subx-logs-drawer-open');
}

async function openSubscriptionLogs(subscription, opts={}){
  if(!subscription) return;
  const shell = ensureSubscriptionLogsDrawer();
  const panel = document.getElementById('subscription-logs-content');
  if(!panel) return;

  OPEN_SUBSCRIPTION_LOGS_SID = String(subscription.id);
  shell.classList.add('open');
  shell.setAttribute('aria-hidden','false');
  document.body.classList.add('subx-logs-drawer-open');

  panel.innerHTML = `<div class="subx-peer-log-head"><div><i class="fas fa-rectangle-list"></i><span><b id="subscription-logs-title">${esc(subscription.name || 'Subscription')} logs</b><small>Loading events from all attached configs…</small></span></div><div class="subx-peer-log-actions"><button class="subx-icon-btn" data-close-subscription-logs title="Close logs"><i class="fas fa-xmark"></i></button></div></div><div class="subx-peer-log-loading"><span class="subx-mini-spinner"></span> Loading subscription logs…</div>`;

  try{
    const locations = Array.isArray(subscription.locations) ? subscription.locations.filter(x=>x.peer_id) : [];
    const responses = await Promise.all(locations.map(async loc=>{
      const r = await fetch(`/api/peer/${encodeURIComponent(loc.peer_id)}/logs`, {credentials:'same-origin', cache:'no-store'});
      const j = await r.json().catch(()=>({}));
      if(!r.ok) throw new Error(j.detail || j.error || `HTTP ${r.status}`);
      const sourceName = loc.name || loc.iface || `Config ${loc.peer_id}`;
      const rows = (j.logs || []).map(row=>({...row, source_name: sourceName}));
      if(j.runtime){
        const rt=j.runtime;
        const connected=rt.connected===true || String(rt.conn_status||'').toLowerCase()==='online';
        rows.unshift({
          time: rt.last_activity_at || new Date().toISOString(),
          event: connected ? 'connection_live' : 'connection_idle',
          level: connected ? 'success' : 'muted',
          details: connected
            ? `Connected now${rt.conn_reason ? ` · detected by ${String(rt.conn_reason).replaceAll('_',' ')}` : ''}`
            : (rt.last_activity_at ? `Disconnected now · last WireGuard activity ${subxRelativeTime(rt.last_activity_at)}` : 'Disconnected now · no recent WireGuard activity'),
          source_name: sourceName
        });
      }
      return rows;
    }));
    const logs = responses.flat().sort((a,b)=>{
      const at = Date.parse(a.time || a.ts || 0) || 0;
      const bt = Date.parse(b.time || b.ts || 0) || 0;
      return bt-at;
    }).slice(0,500);
    panel.innerHTML = `<div class="subx-peer-log-head">
      <div><i class="fas fa-rectangle-list"></i><span><b id="subscription-logs-title">${esc(subscription.name || 'Subscription')} logs</b><small>${locations.length} attached config${locations.length===1?'':'s'} · most recent events</small></span></div>
      <div class="subx-peer-log-actions">
        <button class="subx-icon-btn" data-refresh-subscription-logs="${esc(subscription.id)}" title="Refresh subscription logs"><i class="fas fa-rotate"></i></button>
        <button class="subx-icon-btn" data-close-subscription-logs title="Close logs"><i class="fas fa-xmark"></i></button>
      </div>
    </div>${renderSubscriptionLogRows(logs)}`;
  }catch(err){
    panel.innerHTML = `<div class="subx-peer-log-head"><div><i class="fas fa-triangle-exclamation"></i><span><b id="subscription-logs-title">Could not load subscription logs</b><small>${esc(err.message || 'Request failed')}</small></span></div><button class="subx-icon-btn" data-close-subscription-logs title="Close"><i class="fas fa-xmark"></i></button></div>`;
  }
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
          <div class="detail-card"><span>${subscriptionTimePresentation(s).title}</span><b>${esc(subscriptionTimePresentation(s).value)}</b><small>${esc(subscriptionTimePresentation(s).hint)}</small></div>
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
          <button class="btn secondary detail-log-btn" data-subscription-logs="${s.id}"><i class="fas fa-rectangle-list"></i> Subscription logs</button>
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
  const mobileManage=e.target.closest('[data-sub-mobile-manage]'); if(mobileManage){
    const row=mobileManage.closest('.subx-row');
    const id=String(mobileManage.dataset.subMobileManage || row?.dataset.sub || '');
    const open=!row?.classList.contains('subx-mobile-actions-open');
    SUBX_MOBILE_MANAGE_ID = open ? id : null;
    document.querySelectorAll('.subx-row.subx-mobile-actions-open').forEach(x=>{ if(x!==row){ x.classList.remove('subx-mobile-actions-open'); x.querySelector('[data-sub-mobile-manage]')?.setAttribute('aria-expanded','false'); }});
    row?.classList.toggle('subx-mobile-actions-open',open);
    mobileManage.setAttribute('aria-expanded',open?'true':'false');
    return;
  }
  const copy=e.target.closest('[data-copy]'); if(copy){ const ok = await copyText(copy.dataset.copy); ok ? toastOk('Copied.') : toastBad('Copy failed. Open HTTPS or copy manually.'); return; }
  const more=e.target.closest('[data-more]'); if(more){ const s=SUBS.find(x=>String(x.id)===String(more.dataset.more)); if(s) renderDetails(s); return; }
  const subLogs=e.target.closest('[data-subscription-logs]'); if(subLogs){ const s=SUBS.find(x=>String(x.id)===String(subLogs.dataset.subscriptionLogs)); if(s) await openSubscriptionLogs(s); return; }
  const refreshSubLogs=e.target.closest('[data-refresh-subscription-logs]'); if(refreshSubLogs){ const s=SUBS.find(x=>String(x.id)===String(refreshSubLogs.dataset.refreshSubscriptionLogs)); if(s) await openSubscriptionLogs(s,{preserveScroll:true}); return; }
  const closeSubLogs=e.target.closest('[data-close-subscription-logs]'); if(closeSubLogs){ closeSubscriptionLogs(); return; }
  const editLabel=e.target.closest('[data-edit-inbound-label]'); if(editLabel){ openLabelEditor(editLabel.dataset.editInboundLabel, editLabel.dataset.currentLabel || ''); return; }
  const inbounds=e.target.closest('[data-inbounds]'); if(inbounds){ const s=SUBS.find(x=>String(x.id)===String(inbounds.dataset.inbounds)); if(s) renderDetails(s); return; }
  const addInbound=e.target.closest('[data-add-inbound]');if(addInbound){await openEdit(addInbound.dataset.addInbound, {manageInbounds:true});return;}
  const template=e.target.closest('[data-template]'); if(template){ await openClientTemplateStudio(template.dataset.template); return; }
  const edit=e.target.closest('[data-edit]'); if(edit){ await openEdit(edit.dataset.edit); return; }
  const subEnable=e.target.closest('[data-sub-enable]'); if(subEnable){
    const id=subEnable.dataset.subEnable;
    const ok=await subConfirm({
      title:'Enable and reset subscription?',
      body:'This enables every attached config and starts a fresh subscription lifecycle. Used data, Active since, first-use state, and the timer will be reset.',
      yesText:'Enable & reset',
      noText:'Cancel'
    });
    if(!ok) return;
    subEnable.classList.add('is-busy');
    subEnable.disabled=true;
    showSubActionLoader(
      'Enabling subscription…',
      'Restoring attached configs, resetting data usage, and resetting the timer. This may take a moment on remote nodes.'
    );
    try{
      const r=await fetch(`/api/subscriptions/${id}/enable`,{method:'POST',headers:csrfHeaders(true),credentials:'same-origin'});
      const j=await r.json().catch(()=>({}));
      if(r.ok){
        toastOk(j.message||'Subscription enabled. Data usage and timer were reset.');
        await loadSubs({force:true});
      }else{
        toastBad(j.detail||j.error||'Could not enable and reset subscription.');
      }
    }catch(error){
      console.error('Subscription enable failed:',error);
      toastBad('Could not enable the subscription. Check the panel and node connection.');
    }finally{
      hideSubActionLoader();
      subEnable.classList.remove('is-busy');
      subEnable.disabled=false;
    }
    return;
  }
  const subDisable=e.target.closest('[data-sub-disable]'); if(subDisable){
    const id=subDisable.dataset.subDisable;
    const ok=await subConfirm({
      title:'Disable subscription?',
      body:'This stops all attached configs without deleting them. Current data usage, Active since, and timer values will be preserved until the subscription is enabled again.',
      yesText:'Disable',
      noText:'Cancel',
      danger:true
    });
    if(!ok) return;
    subDisable.classList.add('is-busy');
    subDisable.disabled=true;
    showSubActionLoader(
      'Disabling subscription…',
      'Stopping all attached configs. Remote node operations can take a few seconds.'
    );
    try{
      const r=await fetch(`/api/subscriptions/${id}/disable`,{method:'POST',headers:csrfHeaders(true),credentials:'same-origin'});
      const j=await r.json().catch(()=>({}));
      if(r.ok){
        toastOk(j.message||'Subscription and attached configs were disabled.');
        await loadSubs({force:true});
      }else{
        toastBad(j.detail||j.error||'Could not disable subscription.');
      }
    }catch(error){
      console.error('Subscription disable failed:',error);
      toastBad('Could not disable the subscription. Check the panel and node connection.');
    }finally{
      hideSubActionLoader();
      subDisable.classList.remove('is-busy');
      subDisable.disabled=false;
    }
    return;
  }
  const del=e.target.closest('[data-del]');if(del){const ok = await subConfirm({title: 'Delete subscription?',body: 'This removes the subscription record. Attached peer/config deletion still depends on your backend delete behavior.',yesText: 'Delete',noText: 'Cancel',danger: true});if(!ok) return;
  const r=await fetch(`/api/subscriptions/${del.dataset.del}`,{method:'DELETE',headers:csrfHeaders(true),credentials:'same-origin'});if(r.ok){toastOk('Deleted.');loadSubs();} else {toastBad('Delete failed.');}return;}
  const rt=e.target.closest('[data-reset-timer]'); if(rt){ const id=rt.dataset.resetTimer; rt.classList.add('is-busy'); rt.closest('.subx-row')?.classList.add('is-updating'); let r=await fetch(`/api/subscriptions/${id}/reset_timer`,{method:'POST',headers:csrfHeaders(true),credentials:'same-origin'}); if(r.status===404 || r.status===405){ r=await fetch(`/api/subscriptions/${id}`,{method:'PUT',headers:csrfHeaders(true),credentials:'same-origin',body:JSON.stringify({reset_timer:true})}); } const j=await r.json().catch(()=>({})); if(r.ok){ if(j.still_blocked_reason==='data_limit') toastBad('Timer reset, but the client is still blocked because its data limit is exhausted. Reset data as well.'); else if((j.failed_peer_ids||[]).length) toastBad('Timer reset, but one or more configs could not be re-enabled.'); else toastOk(j.reactivated ? `Timer reset and ${j.reactivated} blocked config${j.reactivated===1?' was':'s were'} re-enabled.` : 'Timer reset successfully.'); await loadSubs({force:true});} else { toastBad(j.detail||j.error||'Reset failed.'); } rt.classList.remove('is-busy'); rt.closest('.subx-row')?.classList.remove('is-updating'); return; }
  const rd=e.target.closest('[data-reset-data]'); if(rd){ const id=rd.dataset.resetData; rd.classList.add('is-busy'); rd.closest('.subx-row')?.classList.add('is-updating'); const r=await fetch(`/api/subscriptions/${id}/reset_data`,{method:'POST',headers:csrfHeaders(true),credentials:'same-origin'}); const j=await r.json().catch(()=>({})); if(r.ok){ if(j.still_blocked_reason==='time_limit') toastBad('Data reset, but the client is still blocked because its timer has expired. Reset the timer as well.'); else if((j.failed_peer_ids||[]).length) toastBad('Data reset, but one or more configs could not be re-enabled.'); else toastOk(j.reactivated ? `Data reset and ${j.reactivated} blocked config${j.reactivated===1?' was':'s were'} re-enabled.` : 'Data reset successfully.'); await loadSubs({force:true});} else { toastBad(j.detail||j.error||'Reset data failed.'); } rd.classList.remove('is-busy'); rd.closest('.subx-row')?.classList.remove('is-updating'); return; }
  const rem=e.target.closest('[data-remove-inbound]');if(rem){const sid=SUBS.find(s=>(s.locations||[]).some(l=>String(l.link_id)===String(rem.dataset.removeInbound)))?.id;if(!sid) return;
  const ok = await subConfirm({title: 'Remove inbound?',body: 'This removes the inbound from this client. The underlying peer/config will not be deleted.',yesText: 'Remove inbound',noText: 'Cancel',danger: true});if(!ok) return;
  const r=await fetch(`/api/subscriptions/${sid}/inbounds/${rem.dataset.removeInbound}`,{method:'DELETE',headers:csrfHeaders(true),credentials:'same-origin'});if(r.ok){toastOk('Inbound removed.');await loadSubs({force:true});} else {const j=await r.json().catch(()=>({}));toastBad(j.detail||j.error||'Remove failed.');}return;}  
  const save=e.target.closest('[data-save-inbound]'); if(save){ const lid=save.dataset.saveInbound; const sid=SUBS.find(s=>(s.locations||[]).some(l=>String(l.link_id)===String(lid)))?.id; const body={location_label:document.querySelector(`[data-label="${lid}"]`)?.value||''}; const r=await fetch(`/api/subscriptions/${sid}/inbounds/${lid}`,{method:'PATCH',headers:csrfHeaders(true),credentials:'same-origin',body:JSON.stringify(body)}); if(r.ok){toastOk('Inbound saved.'); closeDetails(); await loadSubs();} else toastBad('Save failed.'); return; }
});

const subPeerEndpointInput = document.getElementById('sub-peer-endpoint');
const subFixedClientInfo = document.getElementById('sub-fixed-client-info');
if(subPeerEndpointInput){
  subPeerEndpointInput.addEventListener('input', syncSubscriptionFixedClientInfo);
  subPeerEndpointInput.addEventListener('focus', () => {
    if(subFixedClientInfo && !subFixedClientInfo.open){
      subFixedClientInfo.classList.add('is-attention');
    }
  });
  subPeerEndpointInput.addEventListener('blur', () => {
    subFixedClientInfo?.classList.remove('is-attention');
  });
}
if(subFixedClientInfo){
  subFixedClientInfo.addEventListener('toggle', () => {
    if(subFixedClientInfo.open) subFixedClientInfo.classList.add('was-opened');
  });
}
syncSubscriptionFixedClientInfo();

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
        <button class="subx-icon-btn" title="Customize public template for this client" data-template="${s.id}"><i class="fas fa-wand-magic-sparkles"></i></button><button class="subx-icon-btn" title="Edit client" data-edit="${s.id}"><i class="fas fa-pen"></i></button>
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
  const sub=$('#preview-subtitle'); if(sub) sub.textContent=$('#portal-subtitle')?.value||'Install WireGuard, then scan QR or import a config.';
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
  if(!s.enabled) return {label:'Disabled', cls:'disabled', sub:'Subscription disabled'};
  if(c.blocked > 0) return {label:'Blocked', cls:'blocked', sub:'One or more configs are blocked'};
  if(c.offline > 0) {
    const allDisabled = c.offline === c.total;
    return {
      label: allDisabled ? 'Disabled' : 'Partly disabled',
      cls: 'disabled',
      sub: allDisabled ? 'All configs are disabled' : `${c.offline} config${c.offline===1?' is':'s are'} disabled`
    };
  }
  if(c.total > 0) return {label:'Ready', cls:'online', sub:'All configs are enabled'};
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
  const state = subxSubscriptionState(s);
  const isBlocked = state.cls === 'blocked';
  const isDisabled = !s.enabled || state.cls === 'disabled';
  let toggleButton;
  if(isBlocked){toggleButton = `<button class="subx-icon-btn subscription-power state-blocked" title="Blocked — enable and reset data and timer" aria-label="Blocked subscription. Enable and reset" data-sub-enable="${s.id}"><i class="fas fa-power-off"></i></button>`;}
  else if(isDisabled){toggleButton = `<button class="subx-icon-btn subscription-power state-disabled" title="Disabled — enable and reset data and timer" aria-label="Disabled subscription. Enable and reset" data-sub-enable="${s.id}"><i class="fas fa-power-off"></i></button>`;}
  else{toggleButton = `<button class="subx-icon-btn subscription-power state-ready" title="Ready — disable subscription and stop all configs" aria-label="Ready subscription. Disable" data-sub-disable="${s.id}"><i class="fas fa-power-off"></i></button>`;}
  const mobileOpen = String(SUBX_MOBILE_MANAGE_ID ?? '') === String(s.id);
  return `<button class="subx-mobile-manage-btn" type="button" data-sub-mobile-manage="${s.id}" aria-expanded="${mobileOpen ? 'true' : 'false'}"><span><i class="fas fa-sliders"></i><b>Manage client</b></span><i class="fas fa-chevron-down"></i></button><div class="subx-actions subx-actions-icons" aria-label="Subscription actions">
    <div class="subx-tool-row" aria-label="Subscription tools">
      <button class="subx-tool-btn subx-logs-box-btn" type="button" title="Open subscription activity history" data-subscription-logs="${s.id}"><i class="fas fa-clock-rotate-left"></i><span>Logs</span></button>
      <button class="subx-tool-btn subx-theme-box-btn" type="button" title="Open Theme Studio for this client's public portal" data-template="${s.id}"><span class="subx-theme-pulse"><i class="fas fa-wand-magic-sparkles"></i></span><span>Theme</span></button>
    </div>
    <div class="subx-action-icon-grid">
      <button class="subx-icon-btn" title="Copy public page link" data-copy="${esc(s.public_url)}"><i class="fas fa-link"></i></button>${toggleButton}
      <button class="subx-icon-btn" title="Reset used data" data-reset-data="${s.id}"><i class="fas fa-gauge-high"></i></button>
      <button class="subx-icon-btn" title="Reset time limit" data-reset-timer="${s.id}"><i class="fas fa-clock-rotate-left"></i></button>
      <button class="subx-icon-btn" title="Manage inbounds" data-inbounds="${s.id}"><i class="fas fa-network-wired"></i></button>
      <button class="subx-icon-btn" title="Edit client" data-edit="${s.id}"><i class="fas fa-pen"></i></button>
      <button class="subx-icon-btn" title="View details" data-more="${s.id}"><i class="fas fa-circle-info"></i></button>
      <button class="subx-icon-btn danger" title="Delete subscription" data-del="${s.id}"><i class="fas fa-trash"></i></button>
    </div>
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

  const timeInfo = subscriptionTimePresentation(s);
  const timeHeadline = timeInfo.value;
  const timeDetail = timeInfo.hint;

  const dataPct = unlimited ? 100 : subxRemainingPct(s);
  const timePct = timeInfo.percent;
  const note = s.note || 'Multi-location client';
  const connection = subscriptionConnectionPresentation(s);
  const scope = subxScopeOf(s);
  const scopeText =
    scope === 'mixed' ? 'Local + nodes' :
    scope === 'node' ? 'Nodes only' :
    scope === 'local' ? 'Local only' :
    'No location yet';

  const mobileActionsOpen = String(SUBX_MOBILE_MANAGE_ID ?? '') === String(s.id);
  return `<article class="subx-row subx-row-line state-${state.cls}${mobileActionsOpen ? ' subx-mobile-actions-open' : ''}" data-sub="${s.id}">
    <div class="subx-line-id">
      <div class="subx-name"><i class="fas fa-user-shield"></i><span>${esc(s.name)}</span></div>
      <div class="subx-note">${esc(note)}</div>
      <div class="subx-client-connection ${esc(connection.cls)}" title="${esc(connection.title || '')}">
        <span class="subx-conn-dot" aria-hidden="true"></span>
        <span class="subx-conn-copy"><b>${esc(connection.label)}</b><small>${esc(connection.detail)}</small></span>
      </div>
    </div>

    <div class="subx-line-body">
      <div class="subx-line-top">
        <span><i class="fas fa-location-dot"></i> ${locCount} location${locCount === 1 ? '' : 's'} · ${esc(inboundText)}</span>
        <span><i class="fas fa-layer-group"></i> ${esc(scopeText)}</span>
        <span><i class="fas fa-database"></i> ${used} used · ${unlimited ? 'No data cap' : esc(fmtBytes(s.limit_bytes)) + ' limit'}</span>
        <span><i class="fas ${unlimited ? 'fa-play-circle' : 'fa-hourglass-half'}"></i> ${esc(timeInfo.top)}</span>
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
            <b>${esc(timeInfo.title)}</b>
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
      <small class="subx-policy-note">${esc(state.sub)}</small>
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
    if(SUBX_MOBILE_MANAGE_ID != null && !SUBS.some(x => String(x.id) === String(SUBX_MOBILE_MANAGE_ID))){
      SUBX_MOBILE_MANAGE_ID = null;
    }

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





document.addEventListener('keydown', e=>{ if(e.key==='Escape' && OPEN_SUBSCRIPTION_LOGS_SID){ closeSubscriptionLogs(); } });


(() => {
  'use strict';
  const q=(s,r=document)=>r.querySelector(s), qa=(s,r=document)=>[...r.querySelectorAll(s)];
  const DEFAULT_ROUTES=['0.0.0.0/0','::/0'];
  const excludedDetected=new Set();

  function uniqueRoutes(value){
    const raw=Array.isArray(value)?value:String(value||'').split(',');
    const out=[];
    for(const part of raw){const route=String(part||'').trim();if(route&&!out.includes(route))out.push(route)}
    return out;
  }
  function normalizeRoute(route){
    route=String(route||'').trim().replace(/^\[|\]$/g,'');
    if(!route)return'';
    if(!route.includes('/')) route += route.includes(':') ? '/128' : '/32';
    const slash=route.lastIndexOf('/');
    const address=route.slice(0,slash), prefix=Number(route.slice(slash+1));
    if(!Number.isInteger(prefix))return'';
    if(address.includes(':')) return prefix>=0&&prefix<=128&&/^[0-9a-fA-F:.]+$/.test(address)?`${address}/${prefix}`:'';
    const octets=address.split('.');
    return prefix>=0&&prefix<=32&&octets.length===4&&octets.every(v=>/^\d{1,3}$/.test(v)&&Number(v)>=0&&Number(v)<=255)?`${octets.map(Number).join('.')}/${prefix}`:'';
  }
  function validRoute(route){return !!normalizeRoute(route)}
  function allowedInput(){return q('#sub-allowed-ips-value')||q('#sub-form [name="allowed_ips"]')}
  function routes(){return uniqueRoutes(allowedInput()?.value)}
  function detected(){return uniqueRoutes(q('#sub-internal-networks')?.value)}
  function setRoutes(next,{silent=false}={}){
    const input=allowedInput(); if(!input)return;
    input.value=uniqueRoutes(next).join(', ');
    if(!silent){input.dispatchEvent(new Event('input',{bubbles:true}));input.dispatchEvent(new Event('change',{bubbles:true}))}
    render(); updateSummary();
  }
  function addRoute(route,{detectedRoute=false}={}){
    route=normalizeRoute(route);
    if(!route){showError('Enter a valid IPv4 or IPv6 CIDR route, for example 192.168.1.0/24 or fd00::/8.');return false}
    if(detectedRoute)excludedDetected.delete(route);
    setRoutes([...routes(),route]);showError('');return true;
  }
  function addRoutes(value){
    const parts=String(value||'').split(/[\n,]+/).map(v=>v.trim()).filter(Boolean);
    if(!parts.length)return false;
    let ok=true;
    for(const part of parts)if(!addRoute(part))ok=false;
    return ok;
  }
  function removeRoute(route){
    if(detected().includes(route)&&q('#sub-include-internal-network')?.checked)excludedDetected.add(route);
    setRoutes(routes().filter(v=>v!==route));
  }
  function showError(text){const el=q('#sub-route-error');if(!el)return;el.textContent=text||'';el.hidden=!text}
  function routeChip(route){
    const isDetected=detected().includes(route);
    return `<span class="adv8-route-chip ${isDetected?'detected':''}" data-route="${escapeHtml(route)}"><span>${escapeHtml(route)}</span>${isDetected?'<small class="route-origin">detected</small>':''}<button type="button" aria-label="Remove '+escapeHtml(route)+'" title="Remove route"><i class="fas fa-times"></i></button></span>`;
  }
  function escapeHtml(v){return String(v??'').replace(/[&<>"]/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[ch]))}
  function renderChips(){
    const mount=q('#sub-route-chips');if(!mount)return;
    const all=routes();
    mount.innerHTML=all.length?all.map(routeChip).join(''):'<span class="adv8-route-chip empty"><span>No routes added</span></span>';
    qa('.adv8-route-chip[data-route] button',mount).forEach(btn=>btn.addEventListener('click',()=>removeRoute(btn.closest('[data-route]').dataset.route)));
  }
  function renderDetected(){
    const count=q('#sub-auto-network-count'),note=q('#sub-auto-network-note'),tray=q('#sub-detected-network-tray');
    const found=detected(), current=routes(), enabled=!!q('#sub-include-internal-network')?.checked;
    if(count)count.textContent=`${found.length} found`;
    if(note)note.textContent=found.length
      ? (enabled ? `${found.filter(route=>current.includes(route)).length} detected route${found.length===1?'':'s'} currently included. Remove any chip above or use the quick chips below to exclude them.` : 'Turn this on to append detected local and selected-node networks as removable chips.')
      : 'Select interfaces below to detect their local and node networks.';
    if(tray){
      if(!found.length){tray.innerHTML='<span class="adv11-empty-detected"><i class="fas fa-circle-info"></i><span>Select interfaces to reveal local or node private networks here.</span></span>';}
      else {
        const available=found.filter(route=>!current.includes(route));
        if(!available.length){ tray.innerHTML=''; tray.hidden=true; }
        else {
          tray.hidden=false;
          tray.innerHTML = available.map(route=>`<button type="button" class="adv11-detected-chip" data-route="${escapeHtml(route)}"><i class="fas fa-plus"></i><span>${escapeHtml(route)}</span><small>Add</small></button>`).join('');
          qa('.adv11-detected-chip',tray).forEach(btn=>btn.addEventListener('click',()=>{addRoute(btn.dataset.route,{detectedRoute:true});render();updateSummary()}));
        }
      }
    }
  }
  function render(){renderChips();renderDetected()}
  function applyDetected(){
    const toggle=q('#sub-include-internal-network');if(!toggle)return;
    const found=detected();
    if(toggle.checked){setRoutes([...routes(),...found.filter(route=>!excludedDetected.has(route))],{silent:true})}
    else{setRoutes(routes().filter(route=>!found.includes(route)),{silent:true});excludedDetected.clear()}
    const input=allowedInput();input?.dispatchEvent(new Event('change',{bubbles:true}));render();updateSummary();
  }
  function refreshNetworks(){
    const input=q('#sub-internal-networks');if(!input)return;
    let found=[];
    try{found=typeof detectSelectedSubscriptionNetworks==='function'?detectSelectedSubscriptionNetworks():[]}catch(_){found=[]}
    input.value=uniqueRoutes(found).join(', ');
    for(const route of [...excludedDetected])if(!found.includes(route))excludedDetected.delete(route);
    if(q('#sub-include-internal-network')?.checked)applyDetected();else render();
  }
  function updateSummary(){
    const summary=q('#adv8-summary');if(!summary)return;
    const parts=[];
    const current=routes();
    if(current.join(', ')!==DEFAULT_ROUTES.join(', '))parts.push(`${current.length} route${current.length===1?'':'s'}`);
    const endpoint=q('#sub-form [name="endpoint"]')?.value?.trim();const fixed=q('#sub-peer-endpoint')?.value?.trim();
    if(endpoint||fixed)parts.push('endpoint override');
    const dns=q('#sub-form [name="dns"]')?.value?.trim(),mtu=q('#sub-form [name="mtu"]')?.value?.trim(),keep=q('#sub-form [name="persistent_keepalive"]')?.value?.trim();
    if(dns||mtu||keep)parts.push('client override');
    summary.textContent=parts.length?parts.join(' · '):'Using interface defaults';
  }
  function state(){return {routes:routes(),include_internal_network:!!q('#sub-include-internal-network')?.checked,excluded_detected:[...excludedDetected],peer_name_prefix:q('#sub-form [name="peer_name_prefix"]')?.value||'',endpoint:q('#sub-form [name="endpoint"]')?.value||'',peer_endpoint:q('#sub-peer-endpoint')?.value||'',persistent_keepalive:q('#sub-form [name="persistent_keepalive"]')?.value||'',mtu:q('#sub-form [name="mtu"]')?.value||'',dns:q('#sub-form [name="dns"]')?.value||''}}
  function applyState(data={}){
    const set=(sel,val)=>{const el=q(sel);if(el)el.value=val??''};
    setRoutes(Array.isArray(data.routes)?data.routes:uniqueRoutes(data.allowed_ips||DEFAULT_ROUTES),{silent:true});
    set('#sub-form [name="peer_name_prefix"]',data.peer_name_prefix);set('#sub-form [name="endpoint"]',data.endpoint);set('#sub-peer-endpoint',data.peer_endpoint);set('#sub-form [name="persistent_keepalive"]',data.persistent_keepalive);set('#sub-form [name="mtu"]',data.mtu);set('#sub-form [name="dns"]',data.dns);
    excludedDetected.clear();for(const r of data.excluded_detected||[])excludedDetected.add(r);
    const toggle=q('#sub-include-internal-network');if(toggle)toggle.checked=!!data.include_internal_network;
    refreshNetworks();render();updateSummary();
  }

  try{window.getSelectedInternalNetworks=()=>q('#sub-include-internal-network')?.checked?detected().filter(route=>routes().includes(route)):[];window.setSelectedInternalNetworks=value=>{const wanted=uniqueRoutes(value);setRoutes([...routes().filter(route=>!detected().includes(route)),...wanted],{silent:true});render()};window.renderAutoNetworkChooser=renderDetected;window.updateAutoNetworkPreview=renderDetected;window.subApplyInternalNetworksToAllowed=applyDetected;window.refreshSubscriptionInternalNetworks=refreshNetworks}catch(_){ }

  function wire(){
    const editor=q('#sub-route-editor');if(!editor||editor.dataset.wired==='1')return;editor.dataset.wired='1';const autoToggle=q('#sub-include-internal-network');if(autoToggle)autoToggle.dataset.autoNetworkWired='1';
    q('#sub-route-add')?.addEventListener('click',()=>{const entry=q('#sub-route-entry');if(addRoutes(entry?.value)){entry.value='';entry.focus()}});
    q('#sub-route-entry')?.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===','){e.preventDefault();if(addRoutes(e.currentTarget.value)){e.currentTarget.value=''}}});
    q('#sub-route-reset')?.addEventListener('click',()=>{excludedDetected.clear();const toggle=q('#sub-include-internal-network');if(toggle)toggle.checked=false;setRoutes(DEFAULT_ROUTES)});
    q('#sub-include-internal-network')?.addEventListener('change',()=>{if(q('#sub-include-internal-network').checked)excludedDetected.clear();applyDetected()});
    q('#new-defaults')?.addEventListener('toggle',updateSummary);
    qa('#new-defaults input').forEach(el=>el.addEventListener('input',updateSummary));
    const modal=q('#sub-modal');if(modal)new MutationObserver(()=>{if(modal.getAttribute('aria-hidden')==='false'){setTimeout(()=>{const input=allowedInput();if(input&&!input.value)input.value=DEFAULT_ROUTES.join(', ');refreshNetworks();render();updateSummary()},0)}}).observe(modal,{attributes:true,attributeFilter:['aria-hidden']});
    render();refreshNetworks();updateSummary();
  }
  wire();
  window.SubscriptionAdvancedV9={getState:state,applyState,refresh:refreshNetworks,getRoutes:routes,setRoutes,getSelectedInternalNetworks:()=>q('#sub-include-internal-network')?.checked?detected().filter(route=>routes().includes(route)):[]};
})();


(() => {
  'use strict';
  const q=(s,r=document)=>r.querySelector(s), qa=(s,r=document)=>[...r.querySelectorAll(s)];
  const defaults={layout:'ps5',background:'orbits',display_mode:'hybrid',animation:'cinematic',entrance_animation:'stagger',hover_animation:'lift',toast_style:'pill',toast_position:'bottom_center',toast_motion:'slide',toast_duration:2200,accent:'mint',primary_color:'#3addaa',secondary_color:'#63a5ff',online_color:'#22c55e',offline_color:'#94a3b8',warning_color:'#f59e0b',danger_color:'#ef4444',pill_color:'#64748b',action_color:'#3addaa',custom_primary:'#3addaa',custom_secondary:'#63a5ff',surface:'glass',radius:'rounded',shadow:'deep',density:'comfortable',page_width:'wide',config_style:'cards',config_columns:'two',section_order:'usage_first',module_order:['configs','usage','install','support'],module_enabled:{configs:true,usage:true,install:true,support:true},module_sizes:{configs:'auto',usage:'auto',install:'auto',support:'auto'},module_mobile:{configs:'auto',usage:'auto',install:'auto',support:'auto'},module_surface:{configs:'auto',usage:'auto',install:'auto',support:'auto'},module_spacing:{configs:'auto',usage:'auto',install:'auto',support:'auto'},module_radius:{configs:'auto',usage:'auto',install:'auto',support:'auto'},module_heading:{configs:'auto',usage:'auto',install:'auto',support:'auto'},module_mobile_position:{configs:'auto',usage:'auto',install:'auto',support:'auto'},module_gap:'standard',support_style:'buttons',theme_default:'auto',hero_style:'banner',button_style:'solid',font_scale:'standard',background_intensity:86,card_opacity:82,motion_speed:125,motion_intensity:150,particle_density:90,stat_size:'standard',show_quick_stats:true,show_percentage:true,show_used_detail:true,show_install:true,show_support:true,show_live_badge:true,show_status_badge:true,show_location_country:true,show_download_action:true,show_copy_action:true,show_theme_action:true,show_section_descriptions:true,show_admin_notice:false,notice_title:'Service notice',notice_text:'',notice_tone:'info',notice_style:'banner',notice_position:'after_summary',title_align:'left',logo_size:'medium',portal_label:'Secure WireGuard portal',portal_title:'',portal_subtitle:'Your account is ready. Install WireGuard, then scan QR or import a config.',portal_icon:'fas fa-bolt',usage_title:'Usage overview',configs_title:'Configs',install_title:'Install WireGuard',support_title:'Support',support:{telegram:'',whatsapp:'',phone:'',email:'',website:'',instagram:''}};
  const labels={layout:{ps5:'PS5',mac:'macOS',app:'Desktop app',compact:'Compact',minimal:'Minimal',showcase:'Showcase',aurora:'PS5',cards:'macOS',console:'Desktop app',split:'Showcase',profile:'Showcase',executive:'macOS',flow:'Minimal'},background:{aurora:'Aurora',waves:'Waves',network:'Network',orbits:'Orbits',mesh:'Mesh',nebula:'Nebula',lines:'Lines',constellation:'Constellation',prism:'Prism',circuit:'Circuit',pulse:'Pulse',none:'None'},display_mode:{bars:'Progress bars',rings:'Circles',hybrid:'Hybrid',focus:'Large values',minimal:'Compact rows',segments:'Segments'},animation:{cinematic:'Cinematic',immersive:'Immersive',rich:'Rich',balanced:'Balanced',soft:'Soft',drift:'Drift',minimal:'Minimal',off:'Off'},accent:{mint:'Mint',blue:'Blue',violet:'Violet',coral:'Coral',amber:'Amber',mono:'Monochrome',custom:'Custom'}};
  let previewTheme='auto',previewDevice='desktop',previewFit='width',previewPaused=false,previewTimer=0,frameToken=0;
  function radio(name,fallback){return q(`input[name="${name}"]:checked`)?.value||fallback}
  function setRadio(name,value){const el=q(`input[name="${name}"][value="${CSS.escape(String(value))}"]`);if(el)el.checked=true}
  function setValue(id,value){const el=q('#'+id);if(el)el.value=value??''}
  function setCheck(id,value){const el=q('#'+id);if(el)el.checked=!!value}
  function checked(id,fallback=true){const el=q('#'+id);return el?!!el.checked:fallback}
  function number(id,fallback){const n=Number(q('#'+id)?.value);return Number.isFinite(n)?n:fallback}
  function supportValues(){const out={};for(const key of ['telegram','whatsapp','phone','email','website','instagram'])out[key]=q('#sup-'+key)?.value||'';return out}
  function currentSettings(){
    return {layout:radio('sub-layout',defaults.layout),background:radio('sub-background',defaults.background),display_mode:radio('sub-display-mode',defaults.display_mode),animation:radio('portal-animation-choice',q('#portal-animation')?.value||defaults.animation),entrance_animation:radio('sub-entrance-animation',defaults.entrance_animation),hover_animation:radio('sub-hover-animation',defaults.hover_animation),toast_style:radio('sub-toast-style',defaults.toast_style),toast_position:q('#portal-toast-position')?.value||defaults.toast_position,toast_motion:radio('sub-toast-motion',defaults.toast_motion),toast_duration:number('portal-toast-duration',defaults.toast_duration),accent:radio('sub-accent',defaults.accent),primary_color:q('#portal-primary-color')?.value||defaults.primary_color,secondary_color:q('#portal-secondary-color')?.value||defaults.secondary_color,online_color:q('#portal-online-color')?.value||defaults.online_color,offline_color:q('#portal-offline-color')?.value||defaults.offline_color,warning_color:q('#portal-warning-color')?.value||defaults.warning_color,danger_color:q('#portal-danger-color')?.value||defaults.danger_color,pill_color:q('#portal-pill-color')?.value||defaults.pill_color,action_color:q('#portal-action-color')?.value||defaults.action_color,custom_primary:q('#portal-primary-color')?.value||defaults.primary_color,custom_secondary:q('#portal-secondary-color')?.value||defaults.secondary_color,surface:radio('sub-surface',defaults.surface),radius:radio('sub-radius',defaults.radius),shadow:radio('sub-shadow',defaults.shadow),density:radio('sub-density',defaults.density),page_width:radio('sub-page-width',defaults.page_width),config_style:radio('sub-config-style',defaults.config_style),config_columns:radio('sub-config-columns',defaults.config_columns),section_order:radio('sub-section-order',defaults.section_order),module_order:moduleOrderFromComposer(),module_enabled:moduleEnabledFromComposer(),module_sizes:moduleSizesFromComposer(),module_mobile:moduleMobileFromComposer(),module_surface:moduleSurfaceFromComposer(),module_spacing:moduleSpacingFromComposer(),module_radius:moduleRadiusFromComposer(),module_heading:moduleHeadingFromComposer(),module_mobile_position:moduleMobilePositionFromComposer(),module_gap:q('#studio-module-gap')?.value||defaults.module_gap,support_style:radio('sub-support-style',defaults.support_style),theme_default:radio('sub-theme-default',defaults.theme_default),hero_style:radio('sub-hero-style',defaults.hero_style),button_style:radio('sub-button-style',defaults.button_style),font_scale:radio('sub-font-scale',defaults.font_scale),background_intensity:number('portal-background-intensity',defaults.background_intensity),card_opacity:number('portal-card-opacity',defaults.card_opacity),motion_speed:number('portal-motion-speed',defaults.motion_speed),motion_intensity:number('portal-motion-intensity',defaults.motion_intensity),particle_density:number('portal-particle-density',defaults.particle_density),stat_size:radio('sub-stat-size',defaults.stat_size),show_quick_stats:checked('show-quick-stats'),show_percentage:checked('show-percentage'),show_used_detail:checked('show-used-detail'),show_install:checked('show-install'),show_support:checked('show-support'),show_live_badge:checked('show-live-badge'),show_status_badge:checked('show-status-badge'),show_location_country:checked('show-location-country'),show_download_action:checked('show-download-action'),show_copy_action:checked('show-copy-action'),show_theme_action:checked('show-theme-action'),show_section_descriptions:checked('show-section-descriptions'),show_admin_notice:checked('show-admin-notice'),notice_title:q('#portal-notice-title')?.value||defaults.notice_title,notice_text:q('#portal-notice-text')?.value||'',notice_tone:q('#portal-notice-tone')?.value||defaults.notice_tone,notice_style:q('#portal-notice-style')?.value||defaults.notice_style,notice_position:q('#portal-notice-position')?.value||defaults.notice_position,title_align:radio('sub-title-align',defaults.title_align),logo_size:radio('sub-logo-size',defaults.logo_size),portal_label:q('#portal-label')?.value||'',portal_title:q('#portal-title')?.value||'',portal_subtitle:q('#portal-subtitle')?.value||'',portal_icon:q('#portal-icon')?.value||defaults.portal_icon,usage_title:q('#portal-usage-title')?.value||defaults.usage_title,configs_title:q('#portal-configs-title')?.value||defaults.configs_title,install_title:q('#portal-install-title')?.value||defaults.install_title,support_title:q('#portal-support-title')?.value||defaults.support_title,support:supportValues()};
  }
  function applySettings(settings={}){
    const legacyLayout={aurora:'ps5',cards:'mac',console:'app',split:'showcase',profile:'showcase',executive:'mac',flow:'minimal'};
    const normalized={...settings,layout:legacyLayout[settings.layout]||settings.layout};
    const s={...defaults,...normalized,support:{...defaults.support,...(settings.support||{})}};
    for(const [name,key] of [['sub-layout','layout'],['sub-background','background'],['sub-display-mode','display_mode'],['portal-animation-choice','animation'],['sub-entrance-animation','entrance_animation'],['sub-hover-animation','hover_animation'],['sub-toast-style','toast_style'],['sub-toast-motion','toast_motion'],['sub-accent','accent'],['sub-surface','surface'],['sub-radius','radius'],['sub-shadow','shadow'],['sub-density','density'],['sub-page-width','page_width'],['sub-config-style','config_style'],['sub-config-columns','config_columns'],['sub-section-order','section_order'],['sub-support-style','support_style'],['sub-theme-default','theme_default'],['sub-hero-style','hero_style'],['sub-button-style','button_style'],['sub-font-scale','font_scale'],['sub-stat-size','stat_size'],['sub-title-align','title_align'],['sub-logo-size','logo_size']])setRadio(name,s[key]);
    setModuleComposer(s);syncModuleEditor(s.layout);setCheck('show-admin-notice',!!s.show_admin_notice);setValue('portal-notice-title',s.notice_title||defaults.notice_title);setValue('portal-notice-text',s.notice_text||'');setValue('portal-notice-tone',s.notice_tone||defaults.notice_tone);setValue('portal-notice-style',s.notice_style||defaults.notice_style);setValue('portal-notice-position',s.notice_position||defaults.notice_position);
    setValue('portal-animation',s.animation);setValue('portal-toast-position',s.toast_position);setValue('portal-toast-duration',s.toast_duration);const primary=s.primary_color||s.custom_primary||defaults.primary_color;const secondary=s.secondary_color||s.custom_secondary||defaults.secondary_color;setValue('portal-primary-color',primary);setValue('portal-primary-text',primary);setValue('portal-secondary-color',secondary);setValue('portal-secondary-text',secondary);for(const [id,key] of [['online','online_color'],['offline','offline_color'],['warning','warning_color'],['danger','danger_color'],['pill','pill_color'],['action','action_color']]){const value=s[key]||defaults[key];setValue(`portal-${id}-color`,value);setValue(`portal-${id}-text`,value)}setValue('portal-background-intensity',s.background_intensity);setValue('portal-card-opacity',s.card_opacity);setValue('portal-motion-speed',s.motion_speed);setValue('portal-motion-intensity',s.motion_intensity);setValue('portal-particle-density',s.particle_density);updateStudioTokenPreview(s);
    for(const [id,key] of [['show-quick-stats','show_quick_stats'],['show-percentage','show_percentage'],['show-used-detail','show_used_detail'],['show-install','show_install'],['show-support','show_support'],['show-live-badge','show_live_badge'],['show-status-badge','show_status_badge'],['show-location-country','show_location_country'],['show-download-action','show_download_action'],['show-copy-action','show_copy_action'],['show-theme-action','show_theme_action'],['show-section-descriptions','show_section_descriptions']])setCheck(id,s[key]);
    for(const [id,key] of [['portal-label','portal_label'],['portal-title','portal_title'],['portal-subtitle','portal_subtitle'],['portal-icon','portal_icon'],['portal-usage-title','usage_title'],['portal-configs-title','configs_title'],['portal-install-title','install_title'],['portal-support-title','support_title']])setValue(id,s[key]);
    for(const key of Object.keys(defaults.support))setValue('sup-'+key,s.support[key]);
    updateRangeLabels();schedulePreview(true);
  }
  try{applySettingsToForm=()=>applySettings(SUB_SETTINGS||{});collectSettingsForm=()=>currentSettings();updateLayoutPreview=()=>schedulePreview()}catch(_){window.applySettingsToForm=()=>applySettings(window.SUB_SETTINGS||{});window.collectSettingsForm=currentSettings}
  window.SubscriptionStudioV9={collect:currentSettings,apply:applySettings,refresh:()=>schedulePreview(true)};
  window.SubscriptionStudioV13=window.SubscriptionStudioV9;
  window.SubscriptionStudioV14=window.SubscriptionStudioV9;

  const MODULE_KEYS=['configs','usage','install','support'];
  function normalizeModuleOrder(order){
    const out=[];
    for(const v of (Array.isArray(order)?order:[])){if(MODULE_KEYS.includes(v)&&!out.includes(v))out.push(v)}
    for(const v of MODULE_KEYS)if(!out.includes(v))out.push(v);
    return out.slice(0,4);
  }
  function moduleList(){return q('#studio-module-list')}
  function moduleItems(){return qa('#studio-module-list [data-module-editor]')}
  function moduleItem(key){return q(`[data-module-editor="${key}"]`)}
  function moduleOrderFromComposer(){return moduleItems().map(el=>el.dataset.moduleEditor)}
  function moduleEnabledFromComposer(){const out={};MODULE_KEYS.forEach(k=>{out[k]=!moduleItem(k)?.classList.contains('is-hidden')});return out}
  function moduleSizesFromComposer(){const out={};MODULE_KEYS.forEach(k=>{out[k]=q(`[data-module-size="${k}"]`)?.value||'auto'});return out}
  function moduleMobileFromComposer(){const out={};MODULE_KEYS.forEach(k=>{out[k]=q(`[data-module-mobile="${k}"]`)?.value||'auto'});return out}
  function moduleSurfaceFromComposer(){const out={};MODULE_KEYS.forEach(k=>{out[k]=q(`[data-module-surface="${k}"]`)?.value||'auto'});return out}
  function moduleSpacingFromComposer(){const out={};MODULE_KEYS.forEach(k=>{out[k]=q(`[data-module-spacing="${k}"]`)?.value||'auto'});return out}
  function moduleRadiusFromComposer(){const out={};MODULE_KEYS.forEach(k=>{out[k]=q(`[data-module-radius="${k}"]`)?.value||'auto'});return out}
  function moduleHeadingFromComposer(){const out={};MODULE_KEYS.forEach(k=>{out[k]=q(`[data-module-heading="${k}"]`)?.value||'auto'});return out}
  function moduleMobilePositionFromComposer(){const out={};MODULE_KEYS.forEach(k=>{out[k]=q(`[data-module-mobile-position="${k}"]`)?.value||'auto'});return out}

  function normalizedModuleEnabled(value){
    const src=value&&typeof value==='object'?value:{},out={};
    MODULE_KEYS.forEach(k=>{out[k]=src[k]===undefined?true:!!src[k]});
    if(!MODULE_KEYS.some(k=>out[k]))out.configs=true;
    return out;
  }
  function normalizeModuleMap(value,allowed,defaultValue){
    const src=value&&typeof value==='object'?value:{},out={};
    MODULE_KEYS.forEach(k=>{out[k]=allowed.includes(src[k])?src[k]:defaultValue});
    return out;
  }
  function normalizedModuleSizes(value){return normalizeModuleMap(value,['auto','small','medium','large','full'],'auto')}
  function normalizedModuleMobile(value){return normalizeModuleMap(value,['auto','half','full'],'auto')}
  function normalizedModuleSurface(value){return normalizeModuleMap(value,['auto','panel','soft','outline','flat','accent'],'auto')}
  function normalizedModuleSpacing(value){return normalizeModuleMap(value,['auto','compact','comfortable','roomy'],'auto')}
  function normalizedModuleRadius(value){return normalizeModuleMap(value,['auto','square','soft','round'],'auto')}
  function normalizedModuleHeading(value){return normalizeModuleMap(value,['auto','standard','compact','accent','hidden'],'auto')}
  function normalizedModuleMobilePosition(value){return normalizeModuleMap(value,['auto','1','2','3','4'],'auto')}

  function updateModuleComposer(){
    const items=moduleItems(),visible=items.filter(el=>!el.classList.contains('is-hidden'));
    items.forEach((el,idx)=>{
      const key=el.dataset.moduleEditor,hidden=el.classList.contains('is-hidden');
      el.hidden=hidden;
      const restore=q(`[data-module-restore="${key}"]`);if(restore)restore.hidden=!hidden;
      q(`[data-module-up="${key}"]`)?.toggleAttribute('disabled',idx===0);
      q(`[data-module-down="${key}"]`)?.toggleAttribute('disabled',idx===items.length-1);
      q(`[data-module-remove="${key}"]`)?.toggleAttribute('disabled',!hidden&&visible.length<=1);
    });
    const summary=q('#studio-modules-summary');if(summary)summary.textContent=`${visible.length} visible`;
    q('#studio-hidden-modules')?.classList.toggle('is-empty',visible.length===items.length);
    updateMobilePositionLocks();
  }

  function updateMobilePositionLocks(){
    const selects=MODULE_KEYS.map(k=>q(`[data-module-mobile-position="${k}"]`)).filter(Boolean);
    const selected=selects.map(el=>el.value).filter(v=>v!=='auto');
    selects.forEach(select=>{
      [...select.options].forEach(option=>{
        if(option.value==='auto'){option.disabled=false;return}
        option.disabled=selected.includes(option.value)&&select.value!==option.value;
      });
    });
  }
  function setModuleComposer(s){
    const order=normalizeModuleOrder(s?.module_order||defaults.module_order);
    const enabled=normalizedModuleEnabled(s?.module_enabled||defaults.module_enabled);
    const sizes=normalizedModuleSizes(s?.module_sizes||defaults.module_sizes);
    const mobile=normalizedModuleMobile(s?.module_mobile||defaults.module_mobile);
    const surfaces=normalizedModuleSurface(s?.module_surface||defaults.module_surface);
    const spacing=normalizedModuleSpacing(s?.module_spacing||defaults.module_spacing);
    const radius=normalizedModuleRadius(s?.module_radius||defaults.module_radius);
    const heading=normalizedModuleHeading(s?.module_heading||defaults.module_heading);
    const mobilePosition=normalizedModuleMobilePosition(s?.module_mobile_position||defaults.module_mobile_position);
    const list=moduleList();
    if(list)order.forEach(k=>{const el=moduleItem(k);if(el)list.appendChild(el)});
    MODULE_KEYS.forEach(k=>{
      moduleItem(k)?.classList.toggle('is-hidden',!enabled[k]);
      const size=q(`[data-module-size="${k}"]`);if(size)size.value=sizes[k];
      const mob=q(`[data-module-mobile="${k}"]`);if(mob)mob.value=mobile[k];
      const surface=q(`[data-module-surface="${k}"]`);if(surface)surface.value=surfaces[k];
      const space=q(`[data-module-spacing="${k}"]`);if(space)space.value=spacing[k];
      const rad=q(`[data-module-radius="${k}"]`);if(rad)rad.value=radius[k];
      const head=q(`[data-module-heading="${k}"]`);if(head)head.value=heading[k];
      const pos=q(`[data-module-mobile-position="${k}"]`);if(pos)pos.value=mobilePosition[k];
    });
    const gap=q('#studio-module-gap');if(gap)gap.value=['auto','tight','standard','roomy'].includes(s?.module_gap)?s.module_gap:defaults.module_gap;
    updateModuleComposer();
    applyModuleStateToPreview();
  }

  function moduleState(){
    return {
      module_order:moduleOrderFromComposer(),
      module_enabled:moduleEnabledFromComposer(),
      module_sizes:moduleSizesFromComposer(),
      module_mobile:moduleMobileFromComposer(),
      module_surface:moduleSurfaceFromComposer(),
      module_spacing:moduleSpacingFromComposer(),
      module_radius:moduleRadiusFromComposer(),
      module_heading:moduleHeadingFromComposer(),
      module_mobile_position:moduleMobilePositionFromComposer(),
      module_gap:q('#studio-module-gap')?.value||defaults.module_gap
    };
  }

  function applyModuleStateToPreview(){
    const frame=q('#studio-preview-frame'),root=frame?.contentDocument?.documentElement;if(!root)return;
    const s=moduleState(),order=normalizeModuleOrder(s.module_order);
    order.forEach((v,i)=>root.dataset['module'+(i+1)]=v);
    root.dataset.moduleGap=s.module_gap;
    MODULE_KEYS.forEach(k=>{
      const cap=k[0].toUpperCase()+k.slice(1);
      root.dataset['module'+cap+'Enabled']=s.module_enabled[k]?'true':'false';
      root.dataset['module'+cap+'Size']=s.module_sizes[k];
      root.dataset['module'+cap+'Mobile']=s.module_mobile[k];
      root.dataset['module'+cap+'Surface']=s.module_surface[k];
      root.dataset['module'+cap+'Spacing']=s.module_spacing[k];
      root.dataset['module'+cap+'Radius']=s.module_radius[k];
      root.dataset['module'+cap+'Heading']=s.module_heading[k];
      root.dataset['module'+cap+'MobilePosition']=s.module_mobile_position[k];
    });
    requestAnimationFrame(()=>requestAnimationFrame(fitFrame));
  }

  function moduleChanged(){updateModuleComposer();applyModuleStateToPreview();schedulePreview(true)}
  function moveModule(key,delta){
    const list=moduleList(),el=moduleItem(key);if(!list||!el)return;
    const items=moduleItems(),idx=items.indexOf(el),target=items[idx+delta];if(!target)return;
    if(delta<0)list.insertBefore(el,target);else list.insertBefore(target,el);
    moduleChanged();
  }
  function removeModule(key){
    const visible=moduleItems().filter(el=>!el.classList.contains('is-hidden'));
    if(visible.length<=1)return;
    moduleItem(key)?.classList.add('is-hidden');moduleChanged();
  }
  function restoreModule(key){moduleItem(key)?.classList.remove('is-hidden');moduleChanged()}
  function applyModulePreset(name){
    const presets={
      balanced:{order:['configs','usage','install','support'],enabled:{configs:true,usage:true,install:true,support:true},sizes:{configs:'large',usage:'medium',install:'small',support:'small'},mobile:{configs:'full',usage:'full',install:'half',support:'half'},surface:{configs:'auto',usage:'auto',install:'auto',support:'auto'},spacing:{configs:'auto',usage:'auto',install:'auto',support:'auto'},radius:{configs:'auto',usage:'auto',install:'auto',support:'auto'},heading:{configs:'auto',usage:'auto',install:'auto',support:'auto'},mobilePosition:{configs:'auto',usage:'auto',install:'auto',support:'auto'},gap:'standard'},
      configs:{order:['configs','usage','install','support'],enabled:{configs:true,usage:true,install:true,support:true},sizes:{configs:'full',usage:'medium',install:'small',support:'small'},mobile:{configs:'full',usage:'full',install:'half',support:'half'},surface:{configs:'accent',usage:'auto',install:'soft',support:'soft'},spacing:{configs:'roomy',usage:'comfortable',install:'compact',support:'compact'},radius:{configs:'round',usage:'auto',install:'soft',support:'soft'},heading:{configs:'accent',usage:'standard',install:'compact',support:'compact'},mobilePosition:{configs:'1',usage:'2',install:'3',support:'4'},gap:'standard'},
      minimal:{order:['configs','usage','install','support'],enabled:{configs:true,usage:true,install:false,support:false},sizes:{configs:'full',usage:'full',install:'auto',support:'auto'},mobile:{configs:'full',usage:'full',install:'auto',support:'auto'},surface:{configs:'flat',usage:'flat',install:'auto',support:'auto'},spacing:{configs:'comfortable',usage:'comfortable',install:'auto',support:'auto'},radius:{configs:'square',usage:'square',install:'auto',support:'auto'},heading:{configs:'standard',usage:'standard',install:'auto',support:'auto'},mobilePosition:{configs:'1',usage:'2',install:'auto',support:'auto'},gap:'tight'},
      support:{order:['support','configs','usage','install'],enabled:{configs:true,usage:true,install:true,support:true},sizes:{support:'full',configs:'large',usage:'medium',install:'small'},mobile:{support:'full',configs:'full',usage:'full',install:'half'},surface:{support:'accent',configs:'auto',usage:'auto',install:'soft'},spacing:{support:'roomy',configs:'auto',usage:'auto',install:'compact'},radius:{support:'round',configs:'auto',usage:'auto',install:'soft'},heading:{support:'accent',configs:'auto',usage:'auto',install:'compact'},mobilePosition:{support:'1',configs:'2',usage:'3',install:'4'},gap:'standard'}
    };
    const p=presets[name]||presets.balanced;
    setModuleComposer({module_order:p.order,module_enabled:p.enabled,module_sizes:p.sizes,module_mobile:p.mobile,module_surface:p.surface,module_spacing:p.spacing,module_radius:p.radius,module_heading:p.heading,module_mobile_position:p.mobilePosition,module_gap:p.gap});
    schedulePreview(true);
  }
  function syncModuleEditor(){updateModuleComposer()}
  function activateTab(name){qa('[data-studio8-tab]').forEach(btn=>btn.classList.toggle('active',btn.dataset.studio8Tab===name));qa('[data-studio8-panel]').forEach(panel=>{const active=panel.dataset.studio8Panel===name;panel.classList.toggle('active',active);panel.hidden=!active})}
  qa('[data-studio8-tab]').forEach(btn=>btn.addEventListener('click',()=>activateTab(btn.dataset.studio8Tab)));

  q('#studio-module-list')?.addEventListener('change',e=>{
    if(e.target.matches('[data-module-size],[data-module-mobile],[data-module-mobile-position],[data-module-surface],[data-module-spacing],[data-module-radius],[data-module-heading]'))moduleChanged();
  });
  q('#studio-module-list')?.addEventListener('click',e=>{
    const up=e.target.closest('[data-module-up]'),down=e.target.closest('[data-module-down]'),remove=e.target.closest('[data-module-remove]');
    if(up)moveModule(up.dataset.moduleUp,-1);
    if(down)moveModule(down.dataset.moduleDown,1);
    if(remove)removeModule(remove.dataset.moduleRemove);
  });
  q('#studio-hidden-modules')?.addEventListener('click',e=>{const btn=e.target.closest('[data-module-restore]');if(btn)restoreModule(btn.dataset.moduleRestore)});
  q('#studio-module-gap')?.addEventListener('change',moduleChanged);
  q('#studio-module-reset')?.addEventListener('click',()=>{setModuleComposer(defaults);schedulePreview(true)});
  qa('[data-module-preset]').forEach(btn=>btn.addEventListener('click',()=>applyModulePreset(btn.dataset.modulePreset)));
  const layoutPresets={
    ps5:{background:'orbits',animation:'cinematic',motion_speed:125,motion_intensity:150,particle_density:90,background_intensity:86,surface:'glass',radius:'rounded',shadow:'deep',density:'comfortable',page_width:'wide',hero_style:'banner',config_style:'cards',config_columns:'two',section_order:'usage_first',module_gap:'standard'},
    mac:{background:'mesh',animation:'balanced',motion_speed:92,motion_intensity:82,particle_density:42,background_intensity:62,surface:'glass',radius:'rounded',shadow:'soft',density:'comfortable',page_width:'wide',hero_style:'panel',config_style:'cards',config_columns:'two',section_order:'standard',module_gap:'comfortable'},
    app:{background:'network',animation:'rich',motion_speed:112,motion_intensity:112,particle_density:72,background_intensity:70,surface:'solid',radius:'medium',shadow:'soft',density:'compact',page_width:'wide',hero_style:'minimal',config_style:'list',config_columns:'one',section_order:'configs_first',module_gap:'tight'},
    compact:{background:'lines',animation:'soft',motion_speed:80,motion_intensity:65,particle_density:30,background_intensity:52,surface:'solid',radius:'medium',shadow:'none',density:'compact',page_width:'standard',hero_style:'minimal',config_style:'compact',config_columns:'two',section_order:'configs_first',module_gap:'tight'},
    minimal:{background:'none',animation:'drift',motion_speed:65,motion_intensity:50,particle_density:0,background_intensity:30,surface:'soft',radius:'square',shadow:'none',density:'comfortable',page_width:'narrow',hero_style:'minimal',config_style:'list',config_columns:'one',section_order:'standard',module_gap:'comfortable'},
    showcase:{background:'nebula',animation:'immersive',motion_speed:120,motion_intensity:138,particle_density:82,background_intensity:84,surface:'glass',radius:'rounded',shadow:'deep',density:'comfortable',page_width:'wide',hero_style:'banner',config_style:'cards',config_columns:'two',section_order:'configs_first',module_gap:'standard'}
  };
  function cleanModuleDefaults(){return {module_order:[...defaults.module_order],module_enabled:{...defaults.module_enabled},module_sizes:{...defaults.module_sizes},module_mobile:{...defaults.module_mobile},module_surface:{...defaults.module_surface},module_spacing:{...defaults.module_spacing},module_radius:{...defaults.module_radius},module_heading:{...defaults.module_heading},module_mobile_position:{...defaults.module_mobile_position}}}
  function applyLayoutPreset(layout,{preserveIdentity=true}={}){
    const base=preserveIdentity?currentSettings():defaults;
    const preset=layoutPresets[layout]||layoutPresets.ps5;
    applySettings({...base,...cleanModuleDefaults(),...preset,layout});
    activateTab('layout');
    applyPreviewSettingsToFrame(currentSettings(),{replay:true});
  }
  function resetOnLayoutChange(){const el=q('#studio-reset-on-layout-change');return el?!!el.checked:true}
  try{const saved=localStorage.getItem('sub-studio-reset-on-layout-change');if(saved!==null)setCheck('studio-reset-on-layout-change',saved!=='false')}catch(_){}
  q('#studio-reset-on-layout-change')?.addEventListener('change',e=>{try{localStorage.setItem('sub-studio-reset-on-layout-change',String(!!e.target.checked))}catch(_){}});
  qa('input[name="sub-layout"]').forEach(el=>el.addEventListener('change',()=>{if(resetOnLayoutChange())applyLayoutPreset(el.value);else{syncModuleEditor();applyPreviewSettingsToFrame(currentSettings(),{replay:true});schedulePreview(true)}}));
  q('#studio-reset-layout')?.addEventListener('click',()=>applyLayoutPreset(radio('sub-layout',defaults.layout)));
  q('#studio-reset-all')?.addEventListener('click',async()=>{let yes=true;try{if(window.subConfirm)yes=await window.subConfirm({title:'Factory reset template?',body:'This resets the unsaved Studio design, module sizing, colors, motion, content visibility and toast settings.',yesText:'Reset everything',noText:'Cancel',danger:true});else yes=window.confirm('Factory reset all unsaved template settings?')}catch(_){}if(yes)applySettings({...defaults,...cleanModuleDefaults(),support:{...defaults.support}})});
  q('#studio-reset-semantic')?.addEventListener('click',()=>{for(const key of ['online_color','offline_color','warning_color','danger_color','pill_color','action_color']){const short=key.replace('_color','');setValue(`portal-${short}-color`,defaults[key]);setValue(`portal-${short}-text`,defaults[key])}const s=currentSettings();updateStudioTokenPreview(s);applyPreviewSettingsToFrame(s);schedulePreview()});

  function updateRangeLabels(){
    const set=(id,text)=>{const el=q('#'+id);if(el)el.textContent=text};
    set('background-intensity-value',`${number('portal-background-intensity',70)}%`);
    set('card-opacity-value',`${number('portal-card-opacity',82)}%`);
    set('motion-speed-value',`${number('portal-motion-speed',100)}%`);
    set('motion-intensity-value',`${number('portal-motion-intensity',100)}%`);
    set('particle-density-value',`${number('portal-particle-density',60)}%`);
    set('toast-duration-value',`${number('portal-toast-duration',2200)} ms`);
  }

  for(const [color,text] of [
    ['portal-primary-color','portal-primary-text'],
    ['portal-secondary-color','portal-secondary-text']
  ]){
    q('#'+color)?.addEventListener('input',e=>{
      setValue(text,e.target.value);
      setRadio('sub-accent','custom');
    });
    q('#'+text)?.addEventListener('change',e=>{
      if(/^#[0-9a-fA-F]{6}$/.test(e.target.value)){
        setValue(color,e.target.value);
        setRadio('sub-accent','custom');
      }else{
        e.target.value=q('#'+color)?.value||'';
      }
    });
  }

  function updateStudioTokenPreview(s=currentSettings()){
    const modal=q('#sub-settings-modal');if(!modal)return;
    modal.style.setProperty('--studio-online',s.online_color||defaults.online_color);
    modal.style.setProperty('--studio-offline',s.offline_color||defaults.offline_color);
    modal.style.setProperty('--studio-warning',s.warning_color||defaults.warning_color);
    modal.style.setProperty('--studio-danger',s.danger_color||defaults.danger_color);
    modal.style.setProperty('--studio-pill',s.pill_color||defaults.pill_color);
  }
  for(const name of ['online','offline','warning','danger','pill','action']){
    const color=q(`#portal-${name}-color`),text=q(`#portal-${name}-text`);
    color?.addEventListener('input',e=>{if(text)text.value=e.target.value;updateStudioTokenPreview();applyPreviewSettingsToFrame(currentSettings())});
    text?.addEventListener('change',e=>{if(/^#[0-9a-fA-F]{6}$/.test(e.target.value)){if(color)color.value=e.target.value;updateStudioTokenPreview();applyPreviewSettingsToFrame(currentSettings())}else e.target.value=color?.value||''});
  }

  function esc(v){
    return String(v??'').replace(/[&<>"']/g,c=>({
      '&':'&amp;',
      '<':'&lt;',
      '>':'&gt;',
      '"':'&quot;',
      "'":'&#39;'
    }[c]));
  }

  function bool(v){
    return v?'true':'false';
  }

  function resolvedTheme(s={}){
    if(previewTheme==='light'||previewTheme==='dark')return previewTheme;
    if(s.theme_default==='light'||s.theme_default==='dark')return s.theme_default;
    return document.documentElement.dataset.theme==='light'?'light':'dark';
  }

  function supportMarkup(s){if(!s.show_support)return'';const icons={telegram:'fab fa-telegram',whatsapp:'fab fa-whatsapp',phone:'fas fa-phone',email:'fas fa-envelope',website:'fas fa-globe',instagram:'fab fa-instagram'};const active=Object.entries(s.support||{}).filter(([,v])=>String(v||'').trim());return `<section class="support surface" id="support-box" data-module-key="support"><div class="section-head simple"><div><h2><i class="fas fa-headset"></i>${esc(s.support_title)}</h2><p>Contact the service team.</p></div></div><div class="support-links">${active.length?active.map(([k])=>`<a href="#"><i class="${icons[k]}"></i><span>${esc(k[0].toUpperCase()+k.slice(1))}</span></a>`).join(''):'<span class="support-empty">No support channels configured.</span>'}</div></section>`}
  function previewDoc(s){
    const theme=resolvedTheme(s),title=esc(s.portal_title||'premium-user'),label=esc(s.portal_label||defaults.portal_label),subtitle=esc(s.portal_subtitle||defaults.portal_subtitle),css=`${location.origin}/static/css/subscription_public.css?v=20260820-studio-v16`,fa=`${location.origin}/static/vendor/fa/css/all.min.css`;
    const customStyle=`:root{--custom-accent:${esc(s.primary_color||s.custom_primary)};--custom-accent2:${esc(s.secondary_color||s.custom_secondary)};--background-intensity:${s.background_intensity/100};--card-opacity:${s.card_opacity/100};--motion-speed:${100/s.motion_speed};--motion-power:${s.motion_intensity/100};--particle-density:${s.particle_density/100};--engine-speed:${s.motion_speed/100};--engine-density:${s.particle_density/100};--status-online:${esc(s.online_color)};--status-offline:${esc(s.offline_color)};--status-warning:${esc(s.warning_color)};--status-danger:${esc(s.danger_color)};--pill-color:${esc(s.pill_color)};--action-color:${esc(s.action_color)}}`;
    return `<!doctype html><html lang="en" data-preview="true" data-preview-device="${previewDevice}" data-theme="${theme}" data-layout="${s.layout}" data-hero-style="${s.hero_style}" data-background="${s.background}" data-stat-style="${s.display_mode}" data-motion="${s.animation}" data-motion-intensity="${s.motion_intensity}" data-accent="${s.accent}" data-surface="${s.surface}" data-radius="${s.radius}" data-shadow="${s.shadow}" data-density="${s.density}" data-page-width="${s.page_width}" data-config-style="${s.config_style}" data-config-columns="${s.config_columns}" data-section-order="${s.section_order}" data-module-1="${normalizeModuleOrder(s.module_order)[0]}" data-module-2="${normalizeModuleOrder(s.module_order)[1]}" data-module-3="${normalizeModuleOrder(s.module_order)[2]}" data-module-4="${normalizeModuleOrder(s.module_order)[3]}" data-module-configs-enabled="${bool(normalizedModuleEnabled(s.module_enabled).configs)}" data-module-usage-enabled="${bool(normalizedModuleEnabled(s.module_enabled).usage)}" data-module-install-enabled="${bool(normalizedModuleEnabled(s.module_enabled).install)}" data-module-support-enabled="${bool(normalizedModuleEnabled(s.module_enabled).support)}" data-module-configs-size="${normalizedModuleSizes(s.module_sizes).configs}" data-module-usage-size="${normalizedModuleSizes(s.module_sizes).usage}" data-module-install-size="${normalizedModuleSizes(s.module_sizes).install}" data-module-support-size="${normalizedModuleSizes(s.module_sizes).support}" data-module-configs-mobile="${normalizedModuleMobile(s.module_mobile).configs}" data-module-usage-mobile="${normalizedModuleMobile(s.module_mobile).usage}" data-module-install-mobile="${normalizedModuleMobile(s.module_mobile).install}" data-module-support-mobile="${normalizedModuleMobile(s.module_mobile).support}" data-module-configs-surface="${normalizedModuleSurface(s.module_surface).configs}" data-module-usage-surface="${normalizedModuleSurface(s.module_surface).usage}" data-module-install-surface="${normalizedModuleSurface(s.module_surface).install}" data-module-support-surface="${normalizedModuleSurface(s.module_surface).support}" data-module-configs-spacing="${normalizedModuleSpacing(s.module_spacing).configs}" data-module-usage-spacing="${normalizedModuleSpacing(s.module_spacing).usage}" data-module-install-spacing="${normalizedModuleSpacing(s.module_spacing).install}" data-module-support-spacing="${normalizedModuleSpacing(s.module_spacing).support}" data-module-configs-radius="${normalizedModuleRadius(s.module_radius).configs}" data-module-usage-radius="${normalizedModuleRadius(s.module_radius).usage}" data-module-install-radius="${normalizedModuleRadius(s.module_radius).install}" data-module-support-radius="${normalizedModuleRadius(s.module_radius).support}" data-module-configs-heading="${normalizedModuleHeading(s.module_heading).configs}" data-module-usage-heading="${normalizedModuleHeading(s.module_heading).usage}" data-module-install-heading="${normalizedModuleHeading(s.module_heading).install}" data-module-support-heading="${normalizedModuleHeading(s.module_heading).support}" data-module-configs-mobile-position="${normalizedModuleMobilePosition(s.module_mobile_position).configs}" data-module-usage-mobile-position="${normalizedModuleMobilePosition(s.module_mobile_position).usage}" data-module-install-mobile-position="${normalizedModuleMobilePosition(s.module_mobile_position).install}" data-module-support-mobile-position="${normalizedModuleMobilePosition(s.module_mobile_position).support}" data-module-gap="${s.module_gap||'auto'}" data-notice-tone="${esc(s.notice_tone||'info')}" data-notice-style="${esc(s.notice_style||'banner')}" data-notice-position="${esc(s.notice_position||'after_summary')}" data-support-style="${s.support_style}" data-button-style="${s.button_style}" data-font-scale="${s.font_scale}" data-stat-size="${s.stat_size}" data-title-align="${s.title_align}" data-logo-size="${s.logo_size}" data-show-quick="${bool(s.show_quick_stats)}" data-show-install="${bool(s.show_install)}" data-show-support="${bool(s.show_support)}" data-show-live="${bool(s.show_live_badge)}" data-show-percentage="${bool(s.show_percentage)}" data-show-used-detail="${bool(s.show_used_detail)}" data-show-status="${bool(s.show_status_badge)}" data-show-country="${bool(s.show_location_country)}" data-show-download="${bool(s.show_download_action)}" data-show-copy="${bool(s.show_copy_action)}" data-show-theme-action="${bool(s.show_theme_action)}" data-show-descriptions="${bool(s.show_section_descriptions)}" data-entrance="${s.entrance_animation}" data-hover="${s.hover_animation}" data-toast-style="${s.toast_style}" data-toast-position="${s.toast_position}" data-toast-motion="${s.toast_motion}" data-toast-duration="${s.toast_duration}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="${fa}"><link rel="stylesheet" href="${css}"><style>${customStyle}</style></head><body class="preview-body"><div class="live-bg"><span class="bg-orb one"></span><span class="bg-orb two"></span><span class="bg-orb three"></span><span class="bg-wave one"></span><span class="bg-wave two"></span><span class="bg-grid"></span><span class="bg-orbits"></span><span class="bg-lines"></span></div><canvas id="particles" aria-hidden="true"></canvas><div class="page"><main class="portal-shell"><div class="layout-chrome" aria-hidden="true"><span class="chrome-dot one"></span><span class="chrome-dot two"></span><span class="chrome-dot three"></span><span class="chrome-brand"><i class="fas fa-shield-halved"></i></span><span class="chrome-rail"><i></i><i></i><i></i><i></i></span></div><section class="portal-hero surface"><div class="portal-id"><div class="portal-icon"><i class="${esc(s.portal_icon)}"></i></div><div class="portal-copy"><div class="portal-meta"><span class="portal-label">${label}</span><span class="hero-live"><i class="fas fa-circle"></i> Live</span></div><h1>${title}</h1><p>${subtitle}</p></div></div><div class="portal-actions"><a class="icon-action primary"><i class="fas fa-download"></i></a><button class="icon-action copy-action"><i class="fas fa-link"></i></button><button class="icon-action theme-action"><i class="fas fa-moon"></i></button><span class="auto-chip"><i class="fas fa-circle"></i><b>Auto</b></span></div></section><section class="quick-stats surface"><article><span>Status</span><b>Ready</b><small>2 configs</small></article><article><span>Data</span><b>8.4 GiB left</b><small>78% left</small></article><article><span>Time</span><b>12d 4h</b><small>Fixed expiry</small></article></section>${s.show_admin_notice&&String(s.notice_text||'').trim()?`<section class="portal-announcement surface" id="portal-announcement" data-tone="${esc(s.notice_tone||'info')}" data-style="${esc(s.notice_style||'banner')}"><span class="announcement-icon"><i class="fas fa-bullhorn"></i></span><div class="announcement-copy"><b>${esc(s.notice_title||'Service notice')}</b><p>${esc(s.notice_text||'')}</p></div></section>`:''}<div class="portal-content"><section class="usage-section" data-module-key="usage"><div class="section-head simple"><div><h2><i class="fas fa-chart-pie"></i>${esc(s.usage_title)}</h2><p>Live data and time remaining.</p></div></div><div class="stats-grid"><article class="stat-card surface data-stat"><div class="stat-head"><span><i class="fas fa-database"></i> Data remaining</span></div><div class="stat-body"><div class="ring" style="--p:78;--c:var(--accent)"><span>78%</span></div><div class="stat-copy"><div class="big">8.4 GiB</div><div class="subline">2.4 GiB used from 10.8 GiB</div><div class="meter"><span style="width:78%"></span></div><div class="segments"><i></i><i></i><i></i><i></i><i></i></div></div></div></article><article class="stat-card surface time-stat"><div class="stat-head"><span><i class="fas fa-clock"></i> Time remaining</span></div><div class="stat-body"><div class="ring" style="--p:42;--c:var(--accent2)"><span>42%</span></div><div class="stat-copy"><div class="big">12d 4h</div><div class="subline">Expires 18 Aug 2026</div><div class="meter"><span style="width:42%"></span></div><div class="segments"><i></i><i></i><i></i><i></i><i></i></div></div></div></article></div></section><section class="install-card surface" data-module-key="install"><div><h2><i class="fas fa-mobile-screen-button"></i>${esc(s.install_title)}</h2><p>Open the official app, then scan QR or import a config.</p></div><div class="client-links"><a title="Desktop"><i class="fas fa-desktop"></i></a><a title="iPhone / iPad"><i class="fab fa-apple"></i></a><a title="Android"><i class="fab fa-android"></i></a><a title="All platforms"><i class="fas fa-arrow-up-right-from-square"></i></a></div></section><section class="configs surface" data-module-key="configs"><div class="section-head"><div><h2><i class="fas fa-location-dot"></i>${esc(s.configs_title)}</h2><p>Choose a location, download the config, or scan QR.</p></div><span>2 configs</span></div><div class="loc-grid">${['🇳🇱|Amsterdam|Netherlands','🇩🇪|Frankfurt|Germany'].map(row=>{const [flag,name,country]=row.split('|');return `<article class="loc"><div class="loc-top"><div class="loc-main"><div class="loc-name"><span class="loc-flag">${flag}</span><span class="loc-title">${name}</span></div><span class="loc-country">${country}</span></div><span class="status online">Online</span></div><div class="loc-actions"><a class="loc-btn loc-download" title="Download config" aria-label="Download config"><i class="fas fa-download"></i></a><button class="loc-btn"><i class="fas fa-qrcode"></i></button><button class="loc-btn copy-action"><i class="fas fa-copy"></i></button></div></article>`}).join('')}</div></section>${supportMarkup(s)}</div></main></div></body></html>`;
  }
  function updateSummaries(s){const set=(id,text)=>{const el=q('#'+id);if(el)el.textContent=text};set('studio-layout-summary',labels.layout[s.layout]||s.layout);set('studio-background-summary',labels.background[s.background]||s.background);set('studio-stats-summary',labels.display_mode[s.display_mode]||s.display_mode);set('studio-motion-summary',labels.animation[s.animation]||s.animation);set('preview-layout-name',labels.layout[s.layout]||s.layout);set('preview-accent-name',labels.accent[s.accent]||s.accent);set('preview-stats-name',labels.display_mode[s.display_mode]||s.display_mode);set('preview-motion-name',labels.animation[s.animation]||s.animation);set('studio-support-summary',`${Object.values(s.support||{}).filter(v=>String(v||'').trim()).length} active`)}
  let lastVisualSignature='';
  function applyPreviewSettingsToFrame(s=currentSettings(),{replay=false}={}){
    const frame=q('#studio-preview-frame'),doc=frame?.contentDocument,root=doc?.documentElement;if(!root)return;
    const data={preview:'true',previewDevice,layout:s.layout,heroStyle:s.hero_style,background:s.background,statStyle:s.display_mode,motion:s.animation,motionIntensity:s.motion_intensity,accent:s.accent,surface:s.surface,radius:s.radius,shadow:s.shadow,density:s.density,pageWidth:s.page_width,configStyle:s.config_style,configColumns:s.config_columns,sectionOrder:s.section_order,moduleGap:s.module_gap||'auto',supportStyle:s.support_style,buttonStyle:s.button_style,fontScale:s.font_scale,statSize:s.stat_size,titleAlign:s.title_align,logoSize:s.logo_size,entrance:s.entrance_animation,hover:s.hover_animation,toastStyle:s.toast_style,toastPosition:s.toast_position,toastMotion:s.toast_motion,toastDuration:s.toast_duration};
    Object.entries(data).forEach(([k,v])=>{if(v!==undefined&&v!==null)root.dataset[k]=String(v)});
    const order=normalizeModuleOrder(s.module_order),enabled=normalizedModuleEnabled(s.module_enabled),sizes=normalizedModuleSizes(s.module_sizes),mobile=normalizedModuleMobile(s.module_mobile),surfaces=normalizedModuleSurface(s.module_surface),spacing=normalizedModuleSpacing(s.module_spacing),radii=normalizedModuleRadius(s.module_radius),headings=normalizedModuleHeading(s.module_heading),mobilePos=normalizedModuleMobilePosition(s.module_mobile_position);
    order.forEach((v,i)=>root.dataset[`module${i+1}`]=v);
    for(const key of MODULE_KEYS){const cap=key[0].toUpperCase()+key.slice(1);root.dataset[`module${cap}Enabled`]=String(!!enabled[key]);root.dataset[`module${cap}Size`]=sizes[key];root.dataset[`module${cap}Mobile`]=mobile[key];root.dataset[`module${cap}Surface`]=surfaces[key];root.dataset[`module${cap}Spacing`]=spacing[key];root.dataset[`module${cap}Radius`]=radii[key];root.dataset[`module${cap}Heading`]=headings[key];root.dataset[`module${cap}MobilePosition`]=mobilePos[key]}
    const visibility={showQuick:s.show_quick_stats,showInstall:s.show_install,showSupport:s.show_support,showLive:s.show_live_badge,showPercentage:s.show_percentage,showUsedDetail:s.show_used_detail,showStatus:s.show_status_badge,showCountry:s.show_location_country,showDownload:s.show_download_action,showCopy:s.show_copy_action,showThemeAction:s.show_theme_action,showDescriptions:s.show_section_descriptions};Object.entries(visibility).forEach(([k,v])=>root.dataset[k]=String(!!v));
    const primary=s.primary_color||s.custom_primary||defaults.primary_color,secondary=s.secondary_color||s.custom_secondary||defaults.secondary_color;
    const vars={'--custom-accent':primary,'--custom-accent2':secondary,'--background-intensity':Math.max(0,Math.min(1,Number(s.background_intensity||0)/100)),'--card-opacity':Math.max(.5,Math.min(1,Number(s.card_opacity||82)/100)),'--motion-speed':100/Math.max(1,Number(s.motion_speed||100)),'--motion-power':Math.max(.4,Math.min(2,Number(s.motion_intensity||100)/100)),'--particle-density':Math.max(0,Math.min(1.2,Number(s.particle_density||0)/100)),'--engine-speed':Math.max(.5,Math.min(1.8,Number(s.motion_speed||100)/100)),'--engine-density':Math.max(0,Math.min(1.2,Number(s.particle_density||0)/100)),'--status-online':s.online_color||defaults.online_color,'--status-offline':s.offline_color||defaults.offline_color,'--status-warning':s.warning_color||defaults.warning_color,'--status-danger':s.danger_color||defaults.danger_color,'--pill-color':s.pill_color||defaults.pill_color,'--action-color':s.action_color||primary};Object.entries(vars).forEach(([k,v])=>root.style.setProperty(k,String(v)));
    const setText=(sel,value)=>{const el=doc.querySelector(sel);if(el&&value!==undefined)el.textContent=value};setText('.portal-label',s.portal_label||defaults.portal_label);if(String(s.portal_title||'').trim())setText('.portal-copy h1',s.portal_title);setText('.portal-copy p',s.portal_subtitle||defaults.portal_subtitle);
    updateStudioTokenPreview(s);
    const sig=[s.background,s.animation,s.motion_speed,s.motion_intensity,s.particle_density,s.background_intensity,previewDevice,resolvedTheme(s)].join('|');
    const engine=frame.contentWindow?.SubscriptionBackgroundEngine;if(engine&&sig!==lastVisualSignature){lastVisualSignature=sig;try{engine.refresh()}catch(_){}}if(engine&&!previewPaused){try{engine.resume()}catch(_){}}
    if(replay){const entrance=s.entrance_animation||'stagger';root.dataset.entrance='none';void doc.body?.offsetWidth;requestAnimationFrame(()=>{root.dataset.entrance=entrance})}
    applyPreviewPlayback();
  }
  function replayPreviewEntrance(){applyPreviewSettingsToFrame(currentSettings(),{replay:true})}
  function pulsePreviewBackground(){const frame=q('#studio-preview-frame'),root=frame?.contentDocument?.documentElement;if(!root)return;const s=currentSettings(),normal=Math.max(.4,Math.min(2,Number(s.motion_intensity||100)/100));root.style.setProperty('--motion-power','2');try{frame.contentWindow?.SubscriptionBackgroundEngine?.refresh()}catch(_){}setTimeout(()=>{root.style.setProperty('--motion-power',String(normal));try{frame.contentWindow?.SubscriptionBackgroundEngine?.refresh()}catch(_){ }},1200)}
  function showPreviewToast(){const frame=q('#studio-preview-frame');if(!frame?.contentDocument)return;applyPreviewSettingsToFrame(currentSettings());try{if(typeof frame.contentWindow?.showToast==='function'){frame.contentWindow.showToast('Template preview · toast is live');return}}catch(_){}const el=frame.contentDocument.getElementById('toast');if(el){el.textContent='Template preview · toast is live';el.classList.remove('show');void el.offsetWidth;el.classList.add('show')}}
  q('#studio-replay-entrance')?.addEventListener('click',replayPreviewEntrance);
  q('#studio-pulse-background')?.addEventListener('click',pulsePreviewBackground);
  q('#studio-preview-toast')?.addEventListener('click',showPreviewToast);

  function applyPreviewPlayback(){
    const frame=q('#studio-preview-frame');
    if(!frame?.contentDocument)return;
    frame.contentDocument.documentElement.dataset.previewPaused=String(previewPaused);
    const engine=frame.contentWindow?.SubscriptionBackgroundEngine;
    if(engine){previewPaused?engine.pause():engine.resume();}
    const btn=q('#studio-preview-motion-toggle');
    if(btn){btn.classList.toggle('active',!previewPaused);btn.setAttribute('aria-pressed',String(!previewPaused));btn.innerHTML=`<i class="fas fa-${previewPaused?'play':'pause'}"></i><span>${previewPaused?'Resume motion':'Pause motion'}</span>`;}
  }
  function fitFrame(){
    const frame=q('#studio-preview-frame'),stage=q('.studio8-frame-stage'),canvas=q('.studio8-frame-canvas');
    if(!frame||!stage||!canvas||!frame.contentDocument)return;
    const baseWidth=previewDevice==='mobile'?390:1280;
    const doc=frame.contentDocument,root=doc.documentElement,body=doc.body;
    frame.style.transform='none';
    frame.style.width=baseWidth+'px';
    frame.style.height='auto';
    const fullHeight=Math.max(root.scrollHeight,body?.scrollHeight||0,root.offsetHeight,body?.offsetHeight||0,620);
    const cs=getComputedStyle(stage);
    const padX=(parseFloat(cs.paddingLeft)||0)+(parseFloat(cs.paddingRight)||0);
    const padY=(parseFloat(cs.paddingTop)||0)+(parseFloat(cs.paddingBottom)||0);
    const availableWidth=Math.max(160,stage.clientWidth-padX-4);
    const availableHeight=Math.max(180,stage.clientHeight-padY-4);
    let scale=1;
    if(previewFit==='page') scale=Math.min(1,availableWidth/baseWidth,availableHeight/fullHeight);
    else if(previewFit==='width') scale=Math.min(1,availableWidth/baseWidth);
    frame.style.width=baseWidth+'px';
    frame.style.height=fullHeight+'px';
    frame.style.transformOrigin='top left';
    frame.style.transform=`scale(${scale})`;
    canvas.style.width=Math.max(1,Math.floor(baseWidth*scale))+'px';
    canvas.style.height=Math.max(1,Math.floor(fullHeight*scale))+'px';
    stage.style.overflow=previewFit==='page'?'hidden':'auto';
    stage.scrollTop=0;stage.scrollLeft=0;
  }
  async function refreshPreview(){
    clearTimeout(previewTimer);
    const s=currentSettings();updateRangeLabels();updateSummaries(s);
    const frame=q('#studio-preview-frame');if(!frame)return;
    const token=++frameToken;
    const applyFrame=()=>{if(token!==frameToken)return;frame.style.display='block';frame.style.visibility='visible';frame.style.opacity='1';applyPreviewSettingsToFrame(s,{replay:true});requestAnimationFrame(()=>requestAnimationFrame(fitFrame));setTimeout(()=>{applyPreviewSettingsToFrame(currentSettings());fitFrame()},160);setTimeout(fitFrame,480);setTimeout(fitFrame,900)};
    frame.onload=applyFrame;
    try{
      const r=await fetch('/api/subscriptions/template-preview',{method:'POST',headers:csrfHeaders(true),credentials:'same-origin',cache:'no-store',body:JSON.stringify({settings:{...s,theme_default:resolvedTheme(s)},subscription_id:SUB_STUDIO_TARGET_ID||null})});
      if(!r.ok)throw new Error(`Preview HTTP ${r.status}`);
      const html=await r.text();
      if(token!==frameToken)return;
      frame.srcdoc=html;
    }catch(err){
      console.warn('Server-rendered template preview unavailable; using local preview fallback.',err);
      if(token!==frameToken)return;
      frame.srcdoc=previewDoc(s);
    }
  }

  function schedulePreview(now=false){clearTimeout(previewTimer);previewTimer=setTimeout(refreshPreview,now?0:90)}
  q('#sub-settings-modal')?.addEventListener('input',()=>{const s=currentSettings();updateRangeLabels();updateSummaries(s);applyPreviewSettingsToFrame(s);schedulePreview()});q('#sub-settings-modal')?.addEventListener('change',e=>{if(e.target.name==='portal-animation-choice')setValue('portal-animation',e.target.value);const s=currentSettings();updateStudioTokenPreview(s);applyPreviewSettingsToFrame(s,{replay:e.target.name==='sub-entrance-animation'});schedulePreview()});
  qa('[data-preview-theme]').forEach(btn=>btn.addEventListener('click',()=>{previewTheme=btn.dataset.previewTheme;qa('[data-preview-theme]').forEach(b=>b.classList.toggle('active',b===btn));schedulePreview(true)}));
  qa('[data-preview-device]').forEach(btn=>btn.addEventListener('click',()=>{previewDevice=btn.dataset.previewDevice==='mobile'?'mobile':'desktop';q('.studio8-frame-stage')?.setAttribute('data-preview-device',previewDevice);qa('[data-preview-device]').forEach(b=>b.classList.toggle('active',b===btn));applyPreviewSettingsToFrame(currentSettings(),{replay:true});schedulePreview(true)}));
  qa('[data-preview-fit]').forEach(btn=>btn.addEventListener('click',()=>{previewFit=['page','width','actual'].includes(btn.dataset.previewFit)?btn.dataset.previewFit:'page';q('.studio8-frame-stage')?.setAttribute('data-preview-fit',previewFit);qa('[data-preview-fit]').forEach(b=>b.classList.toggle('active',b===btn));fitFrame()}));
  q('#studio-preview-motion-toggle')?.addEventListener('click',()=>{previewPaused=!previewPaused;applyPreviewPlayback()});
  new ResizeObserver(()=>fitFrame()).observe(q('.studio8-frame-stage'));
  new MutationObserver(()=>{if(previewTheme==='auto')schedulePreview()}).observe(document.documentElement,{attributes:true,attributeFilter:['data-theme']});
  const settingsModal=q('#sub-settings-modal');if(settingsModal)new MutationObserver(()=>{if(settingsModal.getAttribute('aria-hidden')==='false'){activateTab('layout');setTimeout(()=>{applySettings(SUB_SETTINGS||{});schedulePreview(true);setTimeout(fitFrame,220)},0)}}).observe(settingsModal,{attributes:true,attributeFilter:['aria-hidden']});
  activateTab('layout');updateRangeLabels();updateStudioTokenPreview();schedulePreview(true);
})();


(() => {
  'use strict';
  const q=(s,r=document)=>r.querySelector(s),qa=(s,r=document)=>[...r.querySelectorAll(s)];
  let profiles=[],activeProfile='',pendingScope='create',updatingName='';
  const notify=(ok,msg)=>{try{(ok?toastOk:toastBad)(msg)}catch(_){console[ok?'log':'error'](msg)}};
  async function request(url, opts = {}) {
    const method = String(opts.method || 'GET').toUpperCase();
    const headers = Object.assign({}, opts.headers || {});

    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      Object.assign(headers, window.csrfHeaders?.(true) || {'Content-Type': 'application/json'});
      if (!headers['Content-Type']) headers['Content-Type'] = 'application/json';
    }

    const r = await fetch(url, {
      credentials: 'same-origin',
      cache: 'no-store',
      ...opts,
      method,
      headers,
    });

    const j = await r.json().catch(() => ({}));
    if (!r.ok) {
      throw new Error(j.detail || j.message || j.error || `HTTP ${r.status}`);
    }
    return j;
  }
  function profileSelects(){return [q('#sub-profile-select'),q('#studio-profile-select')].filter(Boolean)}
  function selectedName(scope){return (scope==='studio'?q('#studio-profile-select'):q('#sub-profile-select'))?.value||''}
  function syncSelects(selected=''){for(const select of profileSelects()){const current=selected||select.value;select.innerHTML='<option value="">Choose profile…</option>'+profiles.map(p=>`<option value="${escapeHtml(p.name)}">${escapeHtml(p.name)}${p.name===activeProfile?' · default':''}</option>`).join('');if(profiles.some(p=>p.name===current))select.value=current}}
  function escapeHtml(v){return String(v??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
  async function loadProfiles(selected=''){try{const j=await request('/api/subscription_profiles');profiles=j.profiles||[];activeProfile=j.active||'';syncSelects(selected||activeProfile||'')}catch(err){notify(false,'Could not load subscription profiles: '+err.message)}}
  function clientState(){
    const form=q('#sub-form');if(!form)return{};const get=name=>form.elements[name]?.value??'';const yes=name=>!!form.elements[name]?.checked;
    return {name:get('name'),note:get('note'),data_limit_value:get('data_limit_value'),data_limit_unit:get('data_limit_unit'),time_limit_days:get('time_limit_days'),time_limit_hours:get('time_limit_hours'),time_limit_minutes:get('time_limit_minutes'),phone_number:get('phone_number'),telegram_id:get('telegram_id'),start_on_first_use:yes('start_on_first_use'),unlimited:yes('unlimited'),mode:typeof MODE==='string'?MODE:'new'};
  }
  function interfaceDescriptor(item){return {scope:item?.scope||'',node_id:item?.node_id??null,node_name:item?.node_name||item?.location||'',iface:item?.iface||'',name:item?.name||'',address:item?.address||item?.interface_address||'',peer_id:item?.peer_id??null,id:item?.id??null}}
  function interfaceState(){let items=[];try{items=selectedItems()}catch(_){}return items.map(interfaceDescriptor)}
  async function ensureTemplateLoaded(){
    if(q('input[name="sub-layout"]:checked'))return;
    try{const settings=await request('/api/subscriptions/settings');try{SUB_SETTINGS=settings}catch(_){window.SUB_SETTINGS=settings}window.SubscriptionStudioV9?.apply?.(settings||{})}catch(_){}
  }
  function profilePayload(){
    const include={client:checked('profile-include-client'),advanced:checked('profile-include-advanced'),interfaces:checked('profile-include-interfaces'),template:checked('profile-include-template')};
    const profile={include};
    if(include.client)profile.client=clientState();
    if(include.advanced)profile.advanced=window.SubscriptionAdvancedV9?.getState?.()||{};
    if(include.interfaces)profile.interfaces=interfaceState();
    if(include.template)profile.template=window.SubscriptionStudioV9?.collect?.()||{};
    return profile;
  }
  function checked(id){return !!q('#'+id)?.checked}
  function openSave(scope, {update = false} = {}) {
    pendingScope = scope;
    updatingName = update ? selectedName(scope) : '';

    const modal = q('#subscription-profile-modal');
    if (!modal) return;

    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
    document.body.classList.add('subx-modal-open');

    const nameInput = q('#subscription-profile-name');
    if (nameInput) nameInput.value = updatingName || '';

    const title = q('#subscription-profile-title');
    if (title) title.textContent = update ? 'Update subscription profile' : 'Save subscription profile';

    const confirmButton = q('#subscription-profile-confirm');
    if (confirmButton) {
      confirmButton.innerHTML = update
        ? '<i class="fas fa-rotate"></i> Update profile'
        : '<i class="fas fa-save"></i> Save profile';
    }

    const studio = scope === 'studio';
    for (const [id, value] of [
      ['profile-include-client', !studio],
      ['profile-include-advanced', !studio],
      ['profile-include-interfaces', !studio],
      ['profile-include-template', true],
    ]) {
      const control = q('#' + id);
      if (control) control.checked = value;
    }

    setTimeout(() => nameInput?.focus(), 30);
  }

  function closeSave() {
    const modal = q('#subscription-profile-modal');
    modal?.classList.remove('open');
    modal?.setAttribute('aria-hidden', 'true');
    updatingName = '';

    if (!q('#sub-modal.open, #sub-settings-modal.open, #details-modal.open, #label-edit-modal.open')) {
      document.body.classList.remove('subx-modal-open');
    }
  }

  async function saveProfile() {
    const name = String(q('#subscription-profile-name')?.value || '').trim();
    if (!name) {
      notify(false, 'Enter a profile name.');
      q('#subscription-profile-name')?.focus();
      return;
    }

    if (checked('profile-include-template')) await ensureTemplateLoaded();

    const profile = profilePayload();
    if (!Object.values(profile.include).some(Boolean)) {
      notify(false, 'Select at least one profile section.');
      return;
    }

    const saveButton = q('#subscription-profile-confirm');
    if (saveButton) saveButton.disabled = true;

    try {
      const wasUpdate = !!updatingName;
      const j = await request('/api/subscription_profiles', {
        method: 'POST',
        body: JSON.stringify({name, profile, activate: true}),
      });

      await loadProfiles(j.saved_name || j.name || name);
      closeSave();
      notify(true, wasUpdate ? 'Profile updated.' : 'Profile saved.');
    } catch (err) {
      notify(false, 'Profile save failed: ' + err.message);
    } finally {
      if (saveButton) saveButton.disabled = false;
    }
  }
  function applyClient(data={}){const form=q('#sub-form');if(!form)return;for(const [name,value] of Object.entries(data)){const el=form.elements[name];if(!el||name==='mode')continue;if(el.type==='checkbox')el.checked=!!value;else el.value=value??'';el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}))}}
  function matches(item,d){if(!item||!d)return false;if(d.peer_id!=null&&item.peer_id!=null)return String(d.peer_id)===String(item.peer_id);if(d.id!=null&&item.id!=null&&String(d.scope)===String(item.scope))return String(d.id)===String(item.id);return String(item.scope||'')===String(d.scope||'')&&String(item.iface||'')===String(d.iface||'')&&(d.node_id==null||item.node_id==null||String(item.node_id)===String(d.node_id))}
  async function applyInterfaces(descriptors=[],mode='new'){
    if(!Array.isArray(descriptors)||!descriptors.length)return;
    const modeButton=q(`.subx-mode button[data-mode="${mode==='current'?'current':'new'}"]`);if(modeButton&&typeof MODE==='string'&&MODE!==mode){modeButton.click();await new Promise(resolve=>setTimeout(resolve,350))}
    try{if((mode==='new'&&!NEW_ITEMS.length)||(mode==='current'&&!CURRENT_ITEMS.length))await loadPickers()}catch(_){}
    if(mode==='current'){
      CURRENT_SELECTED.clear();CURRENT_ITEMS.forEach((item,index)=>{if(descriptors.some(d=>matches(item,d)))CURRENT_SELECTED.add(String(index))});renderPicker();updateSelected();return;
    }
    SCOPE='all';SEARCH='';q('#inbound-search')&&(q('#inbound-search').value='');renderPicker();const items=sourceItems();qa('#inbound-list input[type="checkbox"]').forEach(box=>{const item=items[Number(box.value)];box.checked=descriptors.some(d=>matches(item,d))});updateSelected();
  }
  async function applyProfile(scope){const name=selectedName(scope);if(!name){notify(false,'Choose a subscription profile first.');return}try{const j=await request(`/api/subscription_profiles/${encodeURIComponent(name)}`),p=j.profile||{};if(p.client)applyClient(p.client);if(p.advanced)window.SubscriptionAdvancedV9?.applyState?.(p.advanced);if(p.template)window.SubscriptionStudioV9?.apply?.(p.template);if(p.interfaces)await applyInterfaces(p.interfaces,p.client?.mode||'new');notify(true,`Applied profile “${name}”.`)}catch(err){notify(false,'Profile apply failed: '+err.message)}}

  async function setDefaultProfile(scope){const name=selectedName(scope);if(!name){notify(false,'Choose a profile first.');return}try{await request(`/api/subscription_profiles/${encodeURIComponent(name)}/activate`,{method:'POST',body:'{}'});await loadProfiles(name);notify(true,`“${name}” is now the default profile.`)}catch(err){notify(false,'Could not set default profile: '+err.message)}}
  function profileTextPrompt(title, initialValue = '') {
    return new Promise(resolve => {
      document.querySelectorAll('.profile8-text-dialog-shell').forEach(node => node.remove());

      const shell = document.createElement('div');
      shell.className = 'profile8-text-dialog-shell open';
      shell.innerHTML = `
        <button type="button" class="profile8-text-dialog-backdrop" aria-label="Cancel"></button>
        <section class="profile8-text-dialog" role="dialog" aria-modal="true" aria-label="${escapeHtml(title)}">
          <header>
            <span><i class="fas fa-pen"></i></span>
            <div><b>${escapeHtml(title)}</b><small>Use a short, recognizable profile name.</small></div>
          </header>
          <label><span>Profile name</span><input class="input" maxlength="80"></label>
          <footer>
            <button type="button" class="btn secondary" data-profile-prompt-cancel>Cancel</button>
            <button type="button" class="btn" data-profile-prompt-ok><i class="fas fa-check"></i> Continue</button>
          </footer>
        </section>`;

      document.body.appendChild(shell);
      const input = shell.querySelector('input');
      input.value = String(initialValue || '');
      input.select();

      const finish = value => {
        shell.classList.remove('open');
        setTimeout(() => shell.remove(), 140);
        resolve(value);
      };

      shell.querySelector('[data-profile-prompt-ok]').onclick = () => finish(input.value.trim());
      shell.querySelector('[data-profile-prompt-cancel]').onclick = () => finish(null);
      shell.querySelector('.profile8-text-dialog-backdrop').onclick = () => finish(null);
      shell.addEventListener('keydown', event => {
        if (event.key === 'Escape') finish(null);
        if (event.key === 'Enter') {
          event.preventDefault();
          finish(input.value.trim());
        }
      });

      setTimeout(() => input.focus(), 20);
    });
  }

  async function renameProfile(scope) {
    const old = selectedName(scope);
    if (!old) {
      notify(false, 'Choose a profile first.');
      return;
    }

    const next = String(await profileTextPrompt('Rename subscription profile', old) || '').trim();
    if (!next || next === old) return;

    try {
      await request(`/api/subscription_profiles/${encodeURIComponent(old)}/rename`, {
        method: 'POST',
        body: JSON.stringify({name: next}),
      });
      await loadProfiles(next);
      notify(true, 'Profile renamed.');
    } catch (err) {
      notify(false, 'Profile rename failed: ' + err.message);
    }
  }

  async function deleteProfile(scope) {
    const name = selectedName(scope);
    if (!name) {
      notify(false, 'Choose a profile to delete.');
      return;
    }

    const accepted = typeof subConfirm === 'function'
      ? await subConfirm({
          title: 'Delete subscription profile?',
          body: `Delete “${name}”? This does not delete clients or WireGuard configs.`,
          yesText: 'Delete profile',
          noText: 'Cancel',
          danger: true,
        })
      : window.confirm(`Delete subscription profile “${name}”?`);

    if (!accepted) return;

    try {
      await request(`/api/subscription_profiles/${encodeURIComponent(name)}`, {method: 'DELETE'});
      await loadProfiles();
      notify(true, 'Profile deleted.');
    } catch (err) {
      notify(false, 'Profile delete failed: ' + err.message);
    }
  }
  function wire(){
    q('#sub-profile-apply')?.addEventListener('click',()=>applyProfile('create'));q('#studio-profile-apply')?.addEventListener('click',()=>applyProfile('studio'));
    q('#sub-profile-save')?.addEventListener('click',()=>openSave('create'));q('#studio-profile-save')?.addEventListener('click',()=>openSave('studio'));
    q('#sub-profile-update')?.addEventListener('click',()=>{if(selectedName('create'))openSave('create',{update:true});else notify(false,'Choose a profile to update.')});q('#studio-profile-update')?.addEventListener('click',()=>{if(selectedName('studio'))openSave('studio',{update:true});else notify(false,'Choose a profile to update.')});
    q('#sub-profile-default')?.addEventListener('click',()=>setDefaultProfile('create'));q('#studio-profile-default')?.addEventListener('click',()=>setDefaultProfile('studio'));q('#sub-profile-rename')?.addEventListener('click',()=>renameProfile('create'));q('#studio-profile-rename')?.addEventListener('click',()=>renameProfile('studio'));q('#sub-profile-delete')?.addEventListener('click',()=>deleteProfile('create'));q('#studio-profile-delete')?.addEventListener('click',()=>deleteProfile('studio'));
    q('#subscription-profile-confirm')?.addEventListener('click', saveProfile);
    q('#subscription-profile-close')?.addEventListener('click', closeSave);
    q('#subscription-profile-cancel')?.addEventListener('click', closeSave);
    q('#subscription-profile-modal')?.addEventListener('click', e => {
      if (e.target.dataset.closeSubProfile) closeSave();
    });
    q('#subscription-profile-modal')?.addEventListener('keydown', e => {
      if (e.key === 'Escape') closeSave();
    });
    profileSelects().forEach(select=>select.addEventListener('change',()=>{for(const other of profileSelects())if(other!==select)other.value=select.value}));
    loadProfiles();
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',wire,{once:true});else wire();
  window.SubscriptionProfilesV9={reload:loadProfiles,apply:applyProfile,openSave};
})();


(() => {
  'use strict';
  const q=(s,p=document)=>p.querySelector(s);
  const qa=(s,p=document)=>[...p.querySelectorAll(s)];
  const emit=(el,type='input')=>el&&el.dispatchEvent(new Event(type,{bubbles:true}));

  function fixedClientUI(){
    const input=q('#sub-peer-endpoint');
    const guide=q('#sub-fixed-client-info');
    const state=q('#sub-fixed-client-state');
    const summary=q('#sub-fixed-client-summary');
    const clear=q('#sub-fixed-client-clear');
    if(!input||!guide) return;
    const sync=()=>{
      const active=!!input.value.trim();
      guide.classList.toggle('has-value',active);
      if(state) state.textContent=active?'Override active':'Important guide';
      if(summary) summary.textContent=active?'A fixed server-side destination is currently configured.':'Most clients should leave this field empty.';
      if(clear) clear.disabled=!active;
    };
    input.addEventListener('input',sync);
    input.addEventListener('focus',()=>{ if(!guide.open) guide.classList.add('is-attention'); });
    input.addEventListener('blur',()=>guide.classList.remove('is-attention'));
    guide.addEventListener('toggle',()=>{ if(guide.open) guide.classList.add('was-opened'); });
    clear?.addEventListener('click',()=>{ input.value='';emit(input);emit(input,'change');input.focus();sync(); });
    sync();
  }

  const identityFields={
    label:q('#portal-label'),title:q('#portal-title'),subtitle:q('#portal-subtitle'),icon:q('#portal-icon')
  };
  function count(el,id,max){const out=q(id);if(out)out.textContent=`${(el?.value||'').length}/${max}`}
  function checked(name,fallback){return q(`input[name="${name}"]:checked`)?.value||fallback}
  function syncIdentity(){
    const {label,title,subtitle,icon}=identityFields;
    count(label,'#studio92-label-count',40);count(title,'#studio92-title-count',48);count(subtitle,'#studio92-subtitle-count',150);
    const mini=q('#studio92-mini-hero');
    if(mini){mini.dataset.align=checked('sub-title-align','left');mini.dataset.logo=checked('sub-logo-size','medium')}
    const set=(id,val)=>{const el=q(id);if(el)el.textContent=val};
    set('#studio92-mini-label',(label?.value||'Secure WireGuard portal').trim()||'Secure WireGuard portal');
    set('#studio92-mini-title',(title?.value||'premium-user').trim()||'premium-user');
    set('#studio92-mini-subtitle',(subtitle?.value||'Your account is ready.').trim()||'Your account is ready.');
    const miniIcon=q('#studio92-mini-icon');if(miniIcon)miniIcon.className=icon?.value||'fas fa-bolt';
    qa('[data-studio-icon]').forEach(btn=>btn.classList.toggle('active',btn.dataset.studioIcon===(icon?.value||'fas fa-bolt')));
  }
  for(const el of Object.values(identityFields))el?.addEventListener('input',syncIdentity);
  qa('input[name="sub-title-align"],input[name="sub-logo-size"]').forEach(el=>el.addEventListener('change',syncIdentity));
  qa('[data-studio-icon]').forEach(btn=>btn.addEventListener('click',()=>{
    if(!identityFields.icon)return;
    identityFields.icon.value=btn.dataset.studioIcon;
    emit(identityFields.icon);emit(identityFields.icon,'change');syncIdentity();
  }));
  q('#studio92-copy-default')?.addEventListener('click',()=>{
    if(identityFields.label)identityFields.label.value='Secure WireGuard portal';
    if(identityFields.subtitle)identityFields.subtitle.value='Your account is ready. Install WireGuard, then scan QR or import a config.';
    emit(identityFields.label);emit(identityFields.subtitle);syncIdentity();
  });
  q('#studio92-title-client')?.addEventListener('click',()=>{
    if(identityFields.title){identityFields.title.value='';emit(identityFields.title);identityFields.title.focus()}syncIdentity();
  });

  const supportMeta={
    telegram:['fab fa-telegram','Telegram'],whatsapp:['fab fa-whatsapp','WhatsApp'],phone:['fas fa-phone','Phone'],email:['fas fa-envelope','Email'],website:['fas fa-globe','Website'],instagram:['fab fa-instagram','Instagram']
  };
  function syncSupport(){
    const preview=q('#studio92-support-preview-list');
    const active=[];
    for(const [key,[icon,label]] of Object.entries(supportMeta)){
      const input=q('#sup-'+key);const card=q(`[data-support-channel="${key}"]`);const value=(input?.value||'').trim();
      card?.classList.toggle('has-value',!!value);
      const state=card?.querySelector('.studio92-channel-state');if(state)state.textContent=value?'Active':'Empty';
      if(value)active.push({key,icon,label,value});
    }
    const sum=q('#studio-support-summary');if(sum)sum.textContent=`${active.length} active`;
    if(preview){
      preview.innerHTML=active.length?active.map(x=>`<span class="studio92-support-preview-item"><i class="${x.icon}"></i><span><b>${x.label}</b><small>${String(x.value).replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}</small></span></span>`).join(''):'<span class="studio92-support-empty"><i class="fas fa-eye-slash"></i>No support channels configured</span>';
    }
  }
  for(const key of Object.keys(supportMeta))q('#sup-'+key)?.addEventListener('input',syncSupport);
  qa('[data-clear-support]').forEach(btn=>btn.addEventListener('click',()=>{const el=q('#sup-'+btn.dataset.clearSupport);if(el){el.value='';emit(el);emit(el,'change');el.focus()}syncSupport()}));

  const modal=q('#sub-settings-modal');
  if(modal){
    new MutationObserver(()=>{syncIdentity();syncSupport()}).observe(modal,{attributes:true,attributeFilter:['class','aria-hidden']});
  }
  document.addEventListener('change',e=>{
    if(e.target.matches('input[name="sub-title-align"],input[name="sub-logo-size"],#portal-icon'))syncIdentity();
  });
  setTimeout(()=>{fixedClientUI();syncIdentity();syncSupport()},0);
})();


(() => {
  'use strict';
  const q=(s,p=document)=>p.querySelector(s), qa=(s,p=document)=>[...p.querySelectorAll(s)];
  function setPreviewMode(mode){
    const stage=q('.studio8-frame-stage');
    if(stage) stage.setAttribute('data-preview-fit', mode);
    qa('[data-preview-fit]').forEach(btn=>btn.classList.toggle('active', btn.dataset.previewFit===mode));
  }
  const modal=q('#sub-settings-modal');
  if(modal){
    new MutationObserver(()=>{
      if(modal.getAttribute('aria-hidden')==='false') setTimeout(()=>setPreviewMode('page'),20);
    }).observe(modal,{attributes:true,attributeFilter:['aria-hidden']});
  }
})();

(() => {
  'use strict';
  const q=(s,r=document)=>r.querySelector(s), qa=(s,r=document)=>[...r.querySelectorAll(s)];
  function updateFixedClientState(){
    const input=q('#sub-peer-endpoint'); const summary=q('#sub-fixed-client-summary'); const state=q('#sub-fixed-client-state'); const info=q('#sub-fixed-client-info'); const reset=q('#sub-fixed-client-clear');
    if(!input) return; const has=!!input.value.trim();
    if(summary) summary.textContent = has ? 'A fixed destination is configured. Make sure this client always comes from that exact public endpoint.' : 'Most clients should leave this field empty and use automatic endpoint behavior.';
    if(state) state.textContent = has ? 'Override set' : 'Info';
    if(info) info.classList.toggle('has-value', has);
    if(reset) reset.disabled = !has;
  }
  function wireFixed(){
    const input=q('#sub-peer-endpoint'), reset=q('#sub-fixed-client-clear');
    if(!input || input.dataset.v11Wired==='1') return; input.dataset.v11Wired='1';
    input.addEventListener('input', updateFixedClientState);
    if(reset) reset.addEventListener('click', ()=>{ input.value=''; input.dispatchEvent(new Event('input',{bubbles:true})); input.focus(); });
    const modal=q('#sub-modal'); if(modal) new MutationObserver(()=>{ if(modal.getAttribute('aria-hidden')==='false') setTimeout(updateFixedClientState,0); }).observe(modal,{attributes:true,attributeFilter:['aria-hidden']});
    updateFixedClientState();
  }
  function preferOverview(){
    const stage=q('#sub-settings-modal .studio8-frame-stage'); if(stage) stage.setAttribute('data-preview-fit','page');
    qa('#sub-settings-modal [data-preview-fit]').forEach(btn=>btn.classList.toggle('active', btn.dataset.previewFit==='page'));
  }
  const sm=q('#sub-settings-modal'); if(sm){ new MutationObserver(()=>{ if(sm.getAttribute('aria-hidden')==='false') setTimeout(preferOverview,25); }).observe(sm,{attributes:true,attributeFilter:['aria-hidden']}); }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', wireFixed); else wireFixed();
})();

(() => {
  'use strict';
  const q=(s,r=document)=>r.querySelector(s), qa=(s,r=document)=>[...r.querySelectorAll(s)];
  function syncFixedGuide(){
    const input=q('#sub-peer-endpoint'), summary=q('#sub-fixed-client-summary'), card=q('.adv11-fixed-guide'), clear=q('#sub-fixed-client-clear');
    if(!input) return;
    const has=!!input.value.trim();
    if(summary) summary.textContent = has ? 'A fixed destination is set. Confirm that this client always keeps the same reachable public host and UDP port.' : 'Most clients should leave this field empty and use automatic endpoint behavior.';
    if(card) card.classList.toggle('has-value', has);
    if(clear) clear.disabled=!has;
  }
  function bindFixed(){
    const input=q('#sub-peer-endpoint');
    if(!input || input.dataset.v12Bound==='1') return;
    input.dataset.v12Bound='1';
    input.addEventListener('input', syncFixedGuide);
    q('#sub-fixed-client-clear')?.addEventListener('click', ()=>{input.value=''; input.dispatchEvent(new Event('input',{bubbles:true})); input.focus();});
    syncFixedGuide();
  }
  function resetPreviewStage(){
    const stage=q('#sub-settings-modal .studio8-frame-stage'); if(stage){ stage.scrollTop=0; stage.scrollLeft=0; }
  }
  function bindPreviewResets(){
    qa('#sub-settings-modal [data-preview-fit], #sub-settings-modal [data-preview-device], #sub-settings-modal [data-preview-theme], #studio-preview-motion-toggle').forEach(btn=>{
      if(btn.dataset.v12Bound==='1') return; btn.dataset.v12Bound='1';
      btn.addEventListener('click', ()=>setTimeout(resetPreviewStage,25));
    });
  }
  function onOpenWatch(modalSel, cb){
    const el=q(modalSel); if(!el) return;
    new MutationObserver(()=>{ if(el.getAttribute('aria-hidden')==='false') setTimeout(cb,20); }).observe(el,{attributes:true,attributeFilter:['aria-hidden']});
  }
  function init(){ bindFixed(); bindPreviewResets(); }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', init); else init();
  onOpenWatch('#sub-modal', ()=>{bindFixed(); syncFixedGuide();});
  onOpenWatch('#sub-settings-modal', ()=>{bindPreviewResets(); resetPreviewStage();});
})();

(() => {'use strict';const q=(s,r=document)=>r.querySelector(s),qa=(s,r=document)=>[...r.querySelectorAll(s)];function refit(){const stage=q('#sub-settings-modal .studio8-frame-stage');if(stage){stage.scrollTop=0;stage.scrollLeft=0;}window.dispatchEvent(new Event('resize'));}function bind(){qa('#sub-settings-modal [data-preview-theme],#sub-settings-modal [data-preview-device],#sub-settings-modal [data-preview-fit],#studio-preview-motion-toggle').forEach(btn=>{if(btn.dataset.v121Bound==='1')return;btn.dataset.v121Bound='1';btn.addEventListener('click',()=>{setTimeout(refit,40);setTimeout(refit,220);});});}const modal=q('#sub-settings-modal');if(modal)new MutationObserver(()=>{if(modal.getAttribute('aria-hidden')==='false'){setTimeout(bind,20);setTimeout(refit,100);setTimeout(refit,500);}}).observe(modal,{attributes:true,attributeFilter:['aria-hidden']});if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bind);else bind();})();

(() => {
  'use strict';
  const q=(s,r=document)=>r.querySelector(s);
  const qa=(s,r=document)=>[...r.querySelectorAll(s)];
  const root=document.documentElement;

  function validTheme(v){ return v==='light'||v==='dark'; }
  function currentTheme(){
    if(validTheme(root.dataset.theme)) return root.dataset.theme;
    return matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';
  }
  function persistTheme(theme){
    try{
      localStorage.setItem('wg-panel-theme',theme);
      localStorage.setItem('panel-theme',theme);
      ['theme','app-theme','color-theme'].forEach(key=>{
        if(localStorage.getItem(key)!==null) localStorage.setItem(key,theme);
      });
    }catch(_){}
  }
  function renderPanelThemeButton(){
    const btn=q('#subx-panel-theme-toggle'); if(!btn) return;
    const theme=currentTheme(), toLight=theme==='dark';
    btn.classList.toggle('is-dark',theme==='dark');
    btn.classList.toggle('is-light',theme==='light');
    btn.innerHTML=`<i class="fas fa-${toLight?'sun':'moon'}"></i><span>${toLight?'Light':'Dark'}</span>`;
    btn.title=toLight?'Switch panel to light mode':'Switch panel to dark mode';
    btn.setAttribute('aria-label',btn.title);
  }
  function applyPanelTheme(theme){
    if(!validTheme(theme)) return;
    root.dataset.theme=theme;
    root.style.colorScheme=theme;
    persistTheme(theme);
    renderPanelThemeButton();
    window.dispatchEvent(new CustomEvent('wgpanel:themechange',{detail:{theme}}));
  }
  function bindPanelTheme(){
    const btn=q('#subx-panel-theme-toggle');
    if(!btn || btn.dataset.v122Bound==='1') return;
    btn.dataset.v122Bound='1';
    btn.addEventListener('click',()=>applyPanelTheme(currentTheme()==='dark'?'light':'dark'));
    renderPanelThemeButton();
    new MutationObserver(renderPanelThemeButton).observe(root,{attributes:true,attributeFilter:['data-theme']});
  }

  function resetPreviewScroll(){
    const stage=q('#sub-settings-modal .studio8-frame-stage');
    if(stage){stage.scrollTop=0;stage.scrollLeft=0;}
  }
  function directPreviewTheme(theme){
    const frame=q('#studio-preview-frame');
    const doc=frame?.contentDocument;
    if(doc && (theme==='light'||theme==='dark')){
      doc.documentElement.dataset.theme=theme;
      doc.documentElement.style.colorScheme=theme;
    }
  }
  function bindPreviewControls(){
    qa('#sub-settings-modal [data-preview-theme]').forEach(btn=>{
      if(btn.dataset.v122Bound==='1') return;
      btn.dataset.v122Bound='1';
      btn.addEventListener('click',()=>{
        const requested=btn.dataset.previewTheme;
        const theme=requested==='auto'?currentTheme():requested;
        setTimeout(()=>directPreviewTheme(theme),0);
        setTimeout(resetPreviewScroll,30);
      });
    });
    qa('#sub-settings-modal [data-preview-fit],#sub-settings-modal [data-preview-device]').forEach(btn=>{
      if(btn.dataset.v122Bound==='1') return;
      btn.dataset.v122Bound='1';
      btn.addEventListener('click',()=>setTimeout(resetPreviewScroll,30));
    });
  }
  function observeOpen(){
    const modal=q('#sub-settings-modal'); if(!modal) return;
    new MutationObserver(()=>{
      if(modal.getAttribute('aria-hidden')==='false'){
        setTimeout(()=>{bindPreviewControls();resetPreviewScroll();},40);
      }
    }).observe(modal,{attributes:true,attributeFilter:['aria-hidden']});
  }
  function init(){bindPanelTheme();bindPreviewControls();observeOpen();}
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',init); else init();
})();

(() => {
  'use strict';
  const q=(s,r=document)=>r.querySelector(s),qa=(s,r=document)=>[...r.querySelectorAll(s)];
  function fixedState(){
    const input=q('#sub-peer-endpoint'),clear=q('#sub-fixed-client-clear');
    if(clear) clear.disabled=!(input&&input.value.trim());
  }
  function bindFixed(){
    const input=q('#sub-peer-endpoint'),trigger=q('#sub-fixed-client-info-trigger'),guide=q('#sub-fixed-client-info'),clear=q('#sub-fixed-client-clear');
    if(input&&input.dataset.v123Bound!=='1'){
      input.dataset.v123Bound='1'; input.addEventListener('input',fixedState);
    }
    if(trigger&&trigger.dataset.v123Bound!=='1'){
      trigger.dataset.v123Bound='1'; trigger.addEventListener('click',()=>{if(!guide)return;guide.open=!guide.open;trigger.setAttribute('aria-expanded',String(guide.open));if(guide.open)guide.scrollIntoView({block:'nearest',behavior:'smooth'});});
    }
    if(clear&&clear.dataset.v123Bound!=='1'){
      clear.dataset.v123Bound='1'; clear.addEventListener('click',()=>{if(!input)return;input.value='';input.dispatchEvent(new Event('input',{bubbles:true}));input.focus();});
    }
    fixedState();
  }
  function refreshPreview(){
    const stage=q('#sub-settings-modal .studio8-frame-stage');
    if(stage){stage.scrollTop=0;stage.scrollLeft=0;}
    window.dispatchEvent(new Event('resize'));
  }
  function bindPreview(){
    qa('#sub-settings-modal [data-preview-theme],#sub-settings-modal [data-preview-device],#sub-settings-modal [data-preview-fit],#studio-preview-motion-toggle').forEach(btn=>{
      if(btn.dataset.v123Bound==='1')return;btn.dataset.v123Bound='1';btn.addEventListener('click',()=>{setTimeout(refreshPreview,50);setTimeout(refreshPreview,250);});
    });
  }
  function watch(sel,cb){const el=q(sel);if(!el)return;new MutationObserver(()=>{if(el.getAttribute('aria-hidden')==='false')setTimeout(cb,30)}).observe(el,{attributes:true,attributeFilter:['aria-hidden']});}
  function init(){bindFixed();bindPreview();}
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
  watch('#sub-modal',bindFixed);watch('#sub-settings-modal',()=>{bindPreview();refreshPreview()});
})();

(() => {
  'use strict';
  const q=(s,r=document)=>r.querySelector(s);
  function markCompactSupport(){
    const panel=q('#sub-settings-modal [data-studio8-panel="support"]');
    if(panel) panel.classList.add('studio124-compact-support');
  }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',markCompactSupport); else markCompactSupport();
})();

(() => {
  'use strict';
  const q=(s,r=document)=>r.querySelector(s);
  function tidyDetectedTray(){
    const tray=q('#sub-detected-network-tray');
    if(tray) tray.hidden=!tray.children.length;
  }
  const observerTarget=q('#sub-detected-network-tray');
  if(observerTarget){new MutationObserver(tidyDetectedTray).observe(observerTarget,{childList:true,subtree:true});tidyDetectedTray();}
})();

const fmtBytes=b=>{b=Number(b||0);const u=['B','KiB','MiB','GiB','TiB'];let i=0;while(b>=1024&&i<u.length-1){b/=1024;i++}return `${b.toFixed(i?2:0)} ${u[i]}`};
const humanTTL=s=>{if(s==null)return 'No timer';s=Number(s||0);const d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60);return d?`${d}d ${h}h left`:h?`${h}h ${m}m left`:`${m}m left`};
function formatDateTime(value){
  if(!value) return '';
  const d = new Date(value);
  if(Number.isNaN(d.getTime())) return String(value);

  try {
    return d.toLocaleString([], {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  } catch(_) {
    return d.toLocaleString();
  }
}
function unlimitedActiveText() {
  if (!DATA.unlimited) return '';

  if (DATA.first_used_at) {
    return `Active since ${formatDateTime(
      DATA.first_used_at
    )}`;
  }

  return 'Not used yet';
}

function timeModeText() {
  if (DATA.unlimited) {
    return DATA.first_used_at
      ? 'Active'
      : 'Not started';
  }

  const ttl =
    DATA.ttl_seconds == null
      ? null
      : Number(DATA.ttl_seconds || 0);

  if (
    DATA.start_on_first_use &&
    !DATA.first_used_at &&
    ttl !== 0
  ) {
    return 'Starts on first use';
  }

  if (ttl === 0) return 'Expired';
  if (DATA.expires_at) return 'Fixed expiry';

  return 'No timer';
}

function timeSubText() {
  if (DATA.unlimited) {
    return DATA.first_used_at
      ? `First connected ${formatDateTime(
          DATA.first_used_at
        )}`
      : 'Waiting for the first WireGuard connection.';
  }

  const ttl =
    DATA.ttl_seconds == null
      ? null
      : Number(DATA.ttl_seconds || 0);

  if (
    DATA.start_on_first_use &&
    !DATA.first_used_at &&
    ttl !== 0
  ) {
    return 'Timer begins when this config is first used.';
  }

  if (DATA.expires_at) {
    return `Expires ${formatDateTime(
      DATA.expires_at
    )}`;
  }

  return 'No expiry date';
}

function clientStateText(){
  const locs = DATA.locations || [];
  const blocked = locs.some(l => String(l.status || '').toLowerCase() === 'blocked');

  if(blocked) return 'Blocked';
  if(DATA.ttl_seconds !== null && Number(DATA.ttl_seconds || 0) <= 0) return 'Expired';
  return 'Ready';
}
function pct(n,d){return d?Math.max(0,Math.min(100,Math.round((n/d)*100))):0}
function showToast(t='Copied'){const el=document.getElementById('toast');el.textContent=t;el.classList.add('show');clearTimeout(window.__tt);window.__tt=setTimeout(()=>el.classList.remove('show'),2200)}
async function copyText(txt){try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(txt);showToast();return}}catch(e){}const ta=document.createElement('textarea');ta.value=txt;ta.style.position='fixed';ta.style.left='-9999px';document.body.appendChild(ta);ta.select();document.execCommand('copy');ta.remove();showToast()}
function configUrl(id){return `/s/${encodeURIComponent(TOKEN)}/inbound/${id}/config`}
function qrUrl(id){return `/s/${encodeURIComponent(TOKEN)}/inbound/${id}/qr`}
function safeConfName(value){
  const clean=String(value||'wireguard').trim().replace(/[^A-Za-z0-9_.-]+/g,'_').replace(/^[._]+|[._]+$/g,'');
  return `${clean||'wireguard'}.conf`;
}
async function downloadConfigFile(url, filename){
  try{
    const r=await fetch(url,{cache:'no-store',credentials:'same-origin',headers:{Accept:'application/octet-stream,text/plain;q=0.9,*/*;q=0.8'}});
    if(!r.ok) throw new Error(`HTTP ${r.status}`);
    const raw=await r.blob();
    const blob=new Blob([raw],{type:'application/octet-stream'});
    const objectUrl=URL.createObjectURL(blob);
    const a=document.createElement('a');
    a.href=objectUrl;
    a.download=safeConfName(filename);
    a.style.display='none';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(()=>URL.revokeObjectURL(objectUrl),1500);
    showToast('Config downloaded');
  }catch(err){
    console.error(err);
    const a=document.createElement('a');
    a.href=url;
    a.download=safeConfName(filename);
    document.body.appendChild(a);
    a.click();
    a.remove();
  }
}
function escapeHtml(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function isCountryCode(cc){return /^[A-Z]{2}$/.test(String(cc||'').trim().toUpperCase())}
function flagImgUrl(cc){cc=String(cc||'').trim().toLowerCase();return /^[a-z]{2}$/.test(cc)?`https://flagcdn.com/w40/${cc}.png`:''}
function flagMarkup(cc, fallback){
  cc = String(cc || '').trim().toUpperCase();
  if(isCountryCode(cc)){
    const low = cc.toLowerCase();
    return `<img class="flag-img" src="https://flagcdn.com/w20/${low}.png" srcset="https://flagcdn.com/w40/${low}.png 2x" alt="${escapeHtml(cc)} flag" loading="lazy" decoding="async">`;
  }
  return escapeHtml(fallback || '🌐');
}
function countryName(cc){
  cc = String(cc || '').trim().toUpperCase();
  if(!cc) return '';
  try { return new Intl.DisplayNames([navigator.language || 'en'], {type:'region'}).of(cc) || cc; }
  catch(_) { return cc; }
}
function cleanLocation(l){
  const cn = countryName(l.country_code);
  if(cn) return cn;
  let s = String(l.location_label || '').trim();
  s = s.replace(/\bLocal\b/ig,'').replace(/\bserver\b/ig,'').replace(/\bwg\d+\b/ig,'').replace(/\bn\d+:\S+/ig,'');
  s = s.replace(/[·•|/,-]+/g,' ').replace(/\s+/g,' ').trim();
  return s || 'Location';
}
function publicAddress(l){
  return String(l.public_host || l.endpoint || '').replace(/^.*@/,'').split(':')[0] || '';
}
function renderStats(){
  const used = Number(DATA.used_bytes || 0);
  const lim = DATA.limit_bytes == null ? null : Number(DATA.limit_bytes || 0);
  const remaining = lim == null ? null : Math.max(0, lim - used);

  const usedPct = lim ? pct(used, lim) : 0;
  const remPct = lim ? Math.max(0, 100 - usedPct) : 100;

  const dataHuman = document.getElementById('data-human');
  const dataSub = document.getElementById('data-sub');
  const dataMeter = document.getElementById('data-meter');
  const dataPct = document.getElementById('data-pct-label');
  const dataWrap = document.getElementById('data-meter-wrap');

  if (dataHuman) {dataHuman.textContent = lim? fmtBytes(remaining): `${fmtBytes(used)} used`;}
  if(dataSub) dataSub.textContent = lim
    ? `${fmtBytes(used)} used from ${fmtBytes(lim)}`
    : `${fmtBytes(used)} used · no data cap`;
  if(dataMeter) dataMeter.style.width = Math.max(3, remPct) + '%';
  if (dataPct) {dataPct.textContent = lim? `${remPct}% left`: 'No data cap';}
  if(dataWrap) dataWrap.classList.toggle('warn', !!(lim && remPct <= 20));

  const timeHuman = document.getElementById('time-human');
  const timeSub = document.getElementById('time-sub');
  const timerMode = document.getElementById('timer-mode');

  if (timeHuman) {timeHuman.textContent = DATA.unlimited? unlimitedActiveText(): humanTTL(DATA.ttl_seconds);}
  if(timeSub) timeSub.textContent = timeSubText();
  if(timerMode) {
    timerMode.textContent = timeModeText();
    timerMode.className = 'timer-chip ' + timeModeText().toLowerCase().replace(/\s+/g, '-');
  }

  const cfgCount = document.getElementById('cfg-count');
  if(cfgCount) {
    const n = (DATA.locations || []).length;
    cfgCount.textContent = `${n} config${n === 1 ? '' : 's'}`;
  }

  const heroState = document.getElementById('hero-state');
  if(heroState) heroState.textContent = clientStateText();

  const heroTime = document.getElementById('hero-time');
  if (heroTime) {heroTime.textContent = DATA.unlimited? (DATA.first_used_at? formatDateTime(DATA.first_used_at): 'Not started'): humanTTL(DATA.ttl_seconds);}

  const heroData = document.getElementById('hero-data');
  if (heroData) {heroData.textContent = lim? `${fmtBytes(remaining)} left`: `${fmtBytes(used)} used`;}

  const heroConfigs = document.getElementById('hero-configs');
  if(heroConfigs) {
    const n = (DATA.locations || []).length;
    heroConfigs.textContent = `${n} config${n === 1 ? '' : 's'}`;
  }
}
function renderLocations(){
  const grid=document.getElementById('loc-grid');
  const locs=DATA.locations||[];
  if(!locs.length){grid.innerHTML='<div class="empty">No configs are available.</div>';return}
  grid.innerHTML=locs.map(l=>{
    const initialLoc = cleanLocation(l);
    const initialFlag = l.flag || '🌐';
    const initialFlagHtml = flagMarkup(l.country_code, initialFlag);
    const host = publicAddress(l);
    const needsGeo = !!host;
    return `<article class="loc" data-link="${l.link_id}" data-host="${escapeHtml(host)}" data-geo="${needsGeo?'1':'0'}">
      <div class="loc-top">
        <div class="loc-main">
      <div class="loc-name">
       <span class="loc-flag">${initialFlagHtml}</span>
       <span class="loc-title">${escapeHtml(l.name||'Config')}</span>
       </div>
       <span class="loc-country" hidden>${needsGeo?'Detecting location...':escapeHtml(initialLoc)}</span>
      </div>
        <span class="status ${(l.status||'').toLowerCase()}">${escapeHtml(l.status||'offline')}</span>
      </div>
      <div class="loc-actions">
        <a class="btn small" href="${configUrl(l.link_id)}" data-download-config="${l.link_id}" data-filename="${escapeHtml(l.name||'wireguard')}" download="${escapeHtml(l.name||'wireguard')}.conf"><i class="fas fa-download"></i> Download</a>
        <button class="btn small secondary" data-qr="${l.link_id}"><i class="fas fa-qrcode"></i> QR</button>
        <button class="btn small secondary" data-copy="${location.origin}${configUrl(l.link_id)}"><i class="fas fa-copy"></i> Link</button>
      </div>
      <div class="qrbox"><img alt="QR code" data-src="${qrUrl(l.link_id)}"><div class="qr-caption">Scan this QR code in WireGuard.</div></div>
    </article>`;
  }).join('');
  detectVisibleGeo();
}


const GEO_CACHE_KEY = 'sub-geo-cache-v2';
function loadGeoCache(){try{return JSON.parse(localStorage.getItem(GEO_CACHE_KEY)||'{}')}catch(_){return {}}}
function saveGeoCache(c){try{localStorage.setItem(GEO_CACHE_KEY, JSON.stringify(c))}catch(_){}}
function flagFromCC(cc){
  cc = String(cc||'').trim().toUpperCase();
  if(!/^[A-Z]{2}$/.test(cc)) return '🌐';
  return String.fromCodePoint(...[...cc].map(ch=>127397+ch.charCodeAt(0)));
}
function applyGeoToCard(card, geo){
  if(!card || !geo) return;

  const cc = String(geo.country_code || '').trim().toUpperCase();
  const flag = geo.flag || flagFromCC(cc);
  const country = geo.country || geo.country_name || cc || 'Location';

  card.querySelectorAll('.loc-flag').forEach(el => {
    el.innerHTML = flagMarkup(cc, flag || '🌐');
  });

  const c = card.querySelector('.loc-country');
  if(c) c.textContent = country;

  card.dataset.geo = 'done';
}
async function detectVisibleGeo(){
  const cache = loadGeoCache();
  const now = Date.now();
  const cards = [...document.querySelectorAll('.loc[data-geo="1"]')];
  for(const card of cards){
    const id = card.dataset.link || '';
    const host = (card.dataset.host || id || '').trim();
    if(!id) continue;
    const cached = cache[host];
    if(cached && now - Number(cached.ts||0) < 7*24*3600*1000){
      applyGeoToCard(card, cached);
      continue;
    }
    try{
      const r = await fetch(`/s/${encodeURIComponent(TOKEN)}/inbound/${encodeURIComponent(id)}/geo`, {
        cache:'no-store',
        headers:{'Accept':'application/json'}
      });
      if(!r.ok) throw new Error('geo failed');
      const j = await r.json();
      if(j && (j.country || j.country_code || j.flag)){
        const geo = {
          country:j.country||'',
          country_code:j.country_code||'',
          flag:j.flag || flagFromCC(j.country_code),
          ts:now
        };
        cache[host] = geo;
        saveGeoCache(cache);
        applyGeoToCard(card, geo);
      } else {
        const c = card.querySelector('.loc-country');
        if(c) c.textContent = 'Location';
      }
    }catch(_){
      const c = card.querySelector('.loc-country');
      if(c) c.textContent = 'Location';
    }
  }
}

function render(){renderStats();renderLocations()}
async function refreshData(silent=false){
  const live=document.getElementById('live-dot');
  live.classList.add('loading');
  try{
    const r=await fetch(API_URL,{cache:'no-store',headers:{'Accept':'application/json'}});
    if(!r.ok) throw new Error('bad status');
    const j=await r.json();
    DATA=j.subscription||DATA;
    render();
    if(!silent) showToast('Updated');
  }catch(e){
    if(!silent) showToast('Update failed');
  }finally{setTimeout(()=>live.classList.remove('loading'),700)}
}
render();
setInterval(()=>refreshData(true), 30000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden) refreshData(true)});
document.getElementById('copy-sub').onclick = () => copyText(CONFIG_URL);

document.addEventListener('click', e => {
  const dl = e.target.closest('[data-download-config]');
  if (dl) {
    e.preventDefault();
    e.stopPropagation();
    downloadConfigFile(
      dl.getAttribute('href'),
      dl.dataset.filename || 'wireguard'
    );
    return;
  }

  const q = e.target.closest('[data-qr]');
  if (q) {
    e.preventDefault();
    e.stopPropagation();

    const loc = q.closest('.loc');
    if (!loc) return;

    const wasOpen = loc.classList.contains('open');

    document.querySelectorAll('.loc.open').forEach(other => {
      if (other !== loc) other.classList.remove('open');
    });

    const img = loc.querySelector('.qrbox img');
    if (img && !img.src) img.src = img.dataset.src;

    loc.classList.toggle('open', !wasOpen);
    return;
  }

  const c = e.target.closest('[data-copy]');
  if (c) {
    e.preventDefault();
    e.stopPropagation();
    copyText(c.dataset.copy);
  }
});

(function theme(){
  const root=document.documentElement;
  const btn=document.getElementById('theme-toggle');
  if(!btn) return;

  const valid=v=>v==='dark'||v==='light';
  const preferred=()=>matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';
  const current=()=>valid(root.dataset.theme)?root.dataset.theme:preferred();

  function apply(theme, persist=false){
    root.dataset.theme=theme;
    root.style.colorScheme=theme;
    const meta=document.getElementById('browser-theme-color');
    if(meta) meta.setAttribute('content', theme==='light' ? '#e5f2ff' : '#06101e');
    if(persist){
      try{localStorage.setItem('sub-theme',theme)}catch(_){}
    }
    const toLight=theme==='dark';
    btn.innerHTML=`<i class="fas fa-${toLight?'sun':'moon'}"></i>`;
    btn.title=toLight?'Switch to light mode':'Switch to dark mode';
    btn.setAttribute('aria-label',btn.title);
    btn.setAttribute('aria-pressed',String(theme==='light'));
  }

  apply(current());
  btn.addEventListener('click',()=>apply(current()==='dark'?'light':'dark',true));
})();
(function particles(){
  const c=document.getElementById('particles');
  if(!c) return;
  const ctx=c.getContext('2d',{alpha:true});
  if(!ctx) return;
  const reduced=matchMedia('(prefers-reduced-motion: reduce)').matches;
  let cssW=0,cssH=0,dpr=1,pts=[],raf=0,last=0;
  function resize(){
    cssW=Math.max(1,innerWidth); cssH=Math.max(1,innerHeight);
    dpr=Math.min(2,devicePixelRatio||1);
    c.width=Math.round(cssW*dpr); c.height=Math.round(cssH*dpr);
    c.style.width=cssW+'px'; c.style.height=cssH+'px';
    ctx.setTransform(dpr,0,0,dpr,0,0);
    const area=cssW*cssH;
    const count=reduced?22:Math.max(34,Math.min(90,Math.round(area/14500)));
    pts=Array.from({length:count},()=>({
      x:Math.random()*cssW,y:Math.random()*cssH,
      vx:(Math.random()-.5)*(reduced?.035:.12),
      vy:(Math.random()-.5)*(reduced?.035:.12),
      r:.75+Math.random()*1.45
    }));
  }
  function frame(now){
    if(document.hidden){raf=requestAnimationFrame(frame);return;}
    if(now-last<33){raf=requestAnimationFrame(frame);return;}
    last=now; ctx.clearRect(0,0,cssW,cssH);
    const light=document.documentElement.dataset.theme==='light';
    const lightDots=['20,102,230','0,166,166','109,65,210'];
    const darkDots=['190,220,255','116,232,203','168,145,255'];
    const palette=light?lightDots:darkDots;
    for(let i=0;i<pts.length;i++){
      const p=pts[i];
      p.x+=p.vx; p.y+=p.vy;
      if(p.x<-8)p.x=cssW+8; else if(p.x>cssW+8)p.x=-8;
      if(p.y<-8)p.y=cssH+8; else if(p.y>cssH+8)p.y=-8;
      const rgb=palette[i%palette.length];
      ctx.fillStyle=`rgba(${rgb},${light?.58:.82})`;
      ctx.beginPath();ctx.arc(p.x,p.y,p.r*(light?1.05:1),0,Math.PI*2);ctx.fill();
    }
    const max=cssW<560?118:138;
    ctx.lineWidth=light?.78:.68;
    for(let i=0;i<pts.length;i++) for(let j=i+1;j<pts.length;j++){
      const a=pts[i],b=pts[j],d=Math.hypot(a.x-b.x,a.y-b.y);
      if(d<max){
        const rgb=palette[(i+j)%palette.length];
        ctx.strokeStyle=`rgba(${rgb},${(1-d/max)*(light?.23:.30)})`;
        ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();
      }
    }
    raf=requestAnimationFrame(frame);
  }
  addEventListener('resize',resize,{passive:true});
  resize(); raf=requestAnimationFrame(frame);
})();

function setRing(id,p,label,color){const el=document.getElementById(id);if(!el)return;p=Math.max(0,Math.min(100,Math.round(Number(p||0))));el.style.setProperty('--p',p);if(color)el.style.setProperty('--c',color);const s=el.querySelector('span');if(s)s.textContent=label||`${p}%`;}
function renderStats(){
  const used=Number(DATA.used_bytes||0), lim=DATA.limit_bytes==null?null:Number(DATA.limit_bytes||0), remaining=lim==null?null:Math.max(0,lim-used);
  const usedPct=lim?pct(used,lim):0, remPct=lim?Math.max(0,100-usedPct):100;
  const set=(id,t)=>{const el=document.getElementById(id); if(el) el.textContent=t;};
  const dataCard=document.querySelector('.data-stat');
  const timeCard=document.querySelector('.time-stat');
  if(dataCard) dataCard.classList.toggle('is-unlimited',lim==null);
  if(timeCard) timeCard.classList.toggle('is-unlimited',DATA.ttl_seconds==null);

  set('data-human', lim?fmtBytes(remaining):'Unlimited');
  set('data-sub', lim?`${fmtBytes(used)} used from ${fmtBytes(lim)}`:`${fmtBytes(used)} used · no data cap`);
  const dataMeter=document.getElementById('data-meter'); if(dataMeter)dataMeter.style.width=Math.max(3,remPct)+'%';
  const dataWrap=document.getElementById('data-meter-wrap'); if(dataWrap){dataWrap.classList.toggle('warn',!!(lim&&remPct<=20));dataWrap.hidden=lim==null;}
  set('data-pct-label', lim?`${remPct}% left`:'No cap'); setRing('data-ring',remPct,lim?`${remPct}%`:'∞','#62e6b0');

  const unlimitedTime=DATA.ttl_seconds==null;
  set('time-human', unlimitedTime ? (DATA.first_used_at?'Active':'No timer') : humanTTL(DATA.ttl_seconds));
  set('time-sub', timeSubText()); set('timer-mode', timeModeText());
  const timePct=unlimitedTime?100:(Number(DATA.ttl_seconds)<=0?0:100);
  const tm=document.getElementById('time-meter'); if(tm){tm.style.width=Math.max(3,timePct)+'%';tm.parentElement.hidden=unlimitedTime;}
  setRing('time-ring',timePct,unlimitedTime?'∞':`${timePct}%`,'#60a5fa');

  const n=(DATA.locations||[]).length;
  set('cfg-count',`${n} config${n===1?'':'s'}`);
  set('hero-state',clientStateText());
  set('hero-time',unlimitedTime?(DATA.first_used_at?'Active':'No timer'):humanTTL(DATA.ttl_seconds));
  set('hero-data',lim?`${fmtBytes(remaining)} left`:'Unlimited');
  set('hero-configs',`${n} config${n===1?'':'s'}`);
}
function renderLocations(){
  const grid=document.getElementById('loc-grid'); const locs=DATA.locations||[]; if(!grid)return;
  if(!locs.length){grid.innerHTML='<div class="empty">No configs are available.</div>';return}
  grid.innerHTML=locs.map(l=>{const initialLoc=cleanLocation(l), initialFlag=l.flag||'🌐', initialFlagHtml=flagMarkup(l.country_code,initialFlag), host=publicAddress(l), needsGeo=!!host;return `<article class="loc" data-link="${l.link_id}" data-host="${escapeHtml(host)}" data-geo="${needsGeo?'1':'0'}">
    <div class="loc-top"><div class="loc-main"><div class="loc-name"><span class="loc-flag">${initialFlagHtml}</span><span class="loc-title">${escapeHtml(l.name||'Config')}</span></div><span class="loc-country">${needsGeo?'Detecting location...':escapeHtml(initialLoc)}</span></div><span class="status ${(l.status||'').toLowerCase()}">${escapeHtml(l.status||'offline')}</span></div>
    <div class="loc-actions"><a class="loc-btn loc-download" href="${configUrl(l.link_id)}" data-download-config="${l.link_id}" data-filename="${escapeHtml(l.name||'wireguard')}" download="${escapeHtml(l.name||'wireguard')}.conf" title="Download config" aria-label="Download config"><i class="fas fa-download"></i><span>Download</span></a><button class="loc-btn" data-qr="${l.link_id}" title="Show QR" aria-label="Show QR"><i class="fas fa-qrcode"></i></button><button class="loc-btn" data-copy="${location.origin}${configUrl(l.link_id)}" title="Copy config link" aria-label="Copy config link"><i class="fas fa-copy"></i></button></div>
    <div class="qrbox"><img alt="QR code" data-src="${qrUrl(l.link_id)}"><div class="qr-caption">Scan in WireGuard.</div></div>
  </article>`}).join(''); detectVisibleGeo();
}


try{document.documentElement.dataset.statStyle=(PUBLIC_SETTINGS&&PUBLIC_SETTINGS.display_mode)||document.documentElement.dataset.statStyle||'hybrid';document.documentElement.dataset.motion=(PUBLIC_SETTINGS&&PUBLIC_SETTINGS.animation)||document.documentElement.dataset.motion||'rich';}catch(_){}
render();

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

function timeModeText(){
  const ttl = DATA.ttl_seconds == null ? null : Number(DATA.ttl_seconds || 0);

  if(DATA.start_on_first_use && !DATA.first_used_at && ttl !== 0) {
    return 'Starts on first use';
  }

  if(ttl === 0) return 'Expired';
  if(DATA.expires_at) return 'Fixed expiry';
  return 'No timer';
}

function timeSubText(){
  const ttl = DATA.ttl_seconds == null ? null : Number(DATA.ttl_seconds || 0);

  if(DATA.start_on_first_use && !DATA.first_used_at && ttl !== 0) {
    return 'Timer begins when this config is first used.';
  }

  if(DATA.expires_at) {
    return `Expires ${formatDateTime(DATA.expires_at)}`;
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

  if(dataHuman) dataHuman.textContent = lim ? fmtBytes(remaining) : 'Unlimited';
  if(dataSub) dataSub.textContent = lim
    ? `${fmtBytes(used)} used from ${fmtBytes(lim)}`
    : `${fmtBytes(used)} used · no data cap`;
  if(dataMeter) dataMeter.style.width = Math.max(3, remPct) + '%';
  if(dataPct) dataPct.textContent = lim ? `${remPct}% left` : 'Unlimited';
  if(dataWrap) dataWrap.classList.toggle('warn', !!(lim && remPct <= 20));

  const timeHuman = document.getElementById('time-human');
  const timeSub = document.getElementById('time-sub');
  const timerMode = document.getElementById('timer-mode');

  if(timeHuman) timeHuman.textContent = humanTTL(DATA.ttl_seconds);
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
  if(heroTime) heroTime.textContent = humanTTL(DATA.ttl_seconds);

  const heroData = document.getElementById('hero-data');
  if(heroData) heroData.textContent = lim ? `${fmtBytes(remaining)} left` : 'Unlimited data';

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
        <a class="btn small" href="${configUrl(l.link_id)}" download><i class="fas fa-download"></i> Download</a>
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

(function theme(){const root=document.documentElement,btn=document.getElementById('theme-toggle');const saved=localStorage.getItem('sub-theme')||'dark';root.dataset.theme=saved;btn.innerHTML=saved==='dark'?'<i class="fas fa-moon"></i>':'<i class="fas fa-sun"></i>';btn.onclick=()=>{const next=root.dataset.theme==='dark'?'light':'dark';root.dataset.theme=next;localStorage.setItem('sub-theme',next);btn.innerHTML=next==='dark'?'<i class="fas fa-moon"></i>':'<i class="fas fa-sun"></i>'}})();
(function particles(){const c=document.getElementById('particles'),ctx=c.getContext('2d');let w,h,pts=[];function resize(){w=c.width=innerWidth*devicePixelRatio;h=c.height=innerHeight*devicePixelRatio;pts=Array.from({length:Math.min(90,Math.floor(innerWidth/18))},()=>({x:Math.random()*w,y:Math.random()*h,vx:(Math.random()-.5)*.24*devicePixelRatio,vy:(Math.random()-.5)*.24*devicePixelRatio,r:(Math.random()*1.7+0.7)*devicePixelRatio}))}addEventListener('resize',resize);resize();function tick(){ctx.clearRect(0,0,w,h);const light=document.documentElement.dataset.theme==='light';ctx.fillStyle=light?'rgba(37,99,235,.32)':'rgba(210,230,255,.55)';ctx.strokeStyle=light?'rgba(37,99,235,.10)':'rgba(150,190,255,.11)';for(const p of pts){p.x+=p.vx;p.y+=p.vy;if(p.x<0||p.x>w)p.vx*=-1;if(p.y<0||p.y>h)p.vy*=-1;ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,Math.PI*2);ctx.fill()}for(let i=0;i<pts.length;i++)for(let j=i+1;j<pts.length;j++){const a=pts[i],b=pts[j],dx=a.x-b.x,dy=a.y-b.y,d=Math.hypot(dx,dy),max=125*devicePixelRatio;if(d<max){ctx.globalAlpha=1-d/max;ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();ctx.globalAlpha=1}}requestAnimationFrame(tick)}tick()})();

function setRing(id,p,label,color){const el=document.getElementById(id);if(!el)return;p=Math.max(0,Math.min(100,Math.round(Number(p||0))));el.style.setProperty('--p',p);if(color)el.style.setProperty('--c',color);const s=el.querySelector('span');if(s)s.textContent=label||`${p}%`;}
function renderStats(){
  const used=Number(DATA.used_bytes||0), lim=DATA.limit_bytes==null?null:Number(DATA.limit_bytes||0), remaining=lim==null?null:Math.max(0,lim-used);
  const usedPct=lim?pct(used,lim):0, remPct=lim?Math.max(0,100-usedPct):100;
  const set=(id,t)=>{const el=document.getElementById(id); if(el) el.textContent=t;};
  set('data-human', lim?fmtBytes(remaining):'Unlimited');
  set('data-sub', lim?`${fmtBytes(used)} used from ${fmtBytes(lim)}`:`${fmtBytes(used)} used · no data cap`);
  const dataMeter=document.getElementById('data-meter'); if(dataMeter)dataMeter.style.width=Math.max(3,remPct)+'%';
  const dataWrap=document.getElementById('data-meter-wrap'); if(dataWrap)dataWrap.classList.toggle('warn',!!(lim&&remPct<=20));
  set('data-pct-label', lim?`${remPct}% left`:'Unlimited'); setRing('data-ring',remPct,lim?`${remPct}%`:'∞','#62e6b0');
  set('time-human', humanTTL(DATA.ttl_seconds)); set('time-sub', timeSubText()); set('timer-mode', timeModeText());
  const timePct=DATA.ttl_seconds==null?100:(Number(DATA.ttl_seconds)<=0?0:100); const tm=document.getElementById('time-meter'); if(tm)tm.style.width=Math.max(3,timePct)+'%'; setRing('time-ring',timePct,DATA.ttl_seconds==null?'∞':`${timePct}%`,'#60a5fa');
  const n=(DATA.locations||[]).length; set('cfg-count',`${n} config${n===1?'':'s'}`); set('hero-state',clientStateText()); set('hero-time',humanTTL(DATA.ttl_seconds)); set('hero-data',lim?`${fmtBytes(remaining)} left`:'Unlimited data'); set('hero-configs',`${n} config${n===1?'':'s'}`);
}
function renderLocations(){
  const grid=document.getElementById('loc-grid'); const locs=DATA.locations||[]; if(!grid)return;
  if(!locs.length){grid.innerHTML='<div class="empty">No configs are available.</div>';return}
  grid.innerHTML=locs.map(l=>{const initialLoc=cleanLocation(l), initialFlag=l.flag||'🌐', initialFlagHtml=flagMarkup(l.country_code,initialFlag), host=publicAddress(l), needsGeo=!!host;return `<article class="loc" data-link="${l.link_id}" data-host="${escapeHtml(host)}" data-geo="${needsGeo?'1':'0'}">
    <div class="loc-top"><div class="loc-main"><div class="loc-name"><span class="loc-flag">${initialFlagHtml}</span><span class="loc-title">${escapeHtml(l.name||'Config')}</span></div><span class="loc-country">${needsGeo?'Detecting location...':escapeHtml(initialLoc)}</span></div><span class="status ${(l.status||'').toLowerCase()}">${escapeHtml(l.status||'offline')}</span></div>
    <div class="loc-actions"><a class="loc-btn" href="${configUrl(l.link_id)}" download title="Download config" aria-label="Download config"><i class="fas fa-download"></i></a><button class="loc-btn" data-qr="${l.link_id}" title="Show QR" aria-label="Show QR"><i class="fas fa-qrcode"></i></button><button class="loc-btn" data-copy="${location.origin}${configUrl(l.link_id)}" title="Copy config link" aria-label="Copy config link"><i class="fas fa-copy"></i></button></div>
    <div class="qrbox"><img alt="QR code" data-src="${qrUrl(l.link_id)}"><div class="qr-caption">Scan in WireGuard.</div></div>
  </article>`}).join(''); detectVisibleGeo();
}
try{document.documentElement.dataset.statStyle=(PUBLIC_SETTINGS&&PUBLIC_SETTINGS.display_mode)||document.documentElement.dataset.statStyle||'hybrid';document.documentElement.dataset.motion=(PUBLIC_SETTINGS&&PUBLIC_SETTINGS.animation)||document.documentElement.dataset.motion||'rich';}catch(_){}
render();

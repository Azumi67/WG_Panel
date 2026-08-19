(() => {
  'use strict';
  const root = document.documentElement;
  const canvas = document.getElementById('particles');
  if (!canvas) return;
  const ctx = canvas.getContext('2d', {alpha:true});
  if (!ctx) return;

  let width=1,height=1,dpr=1,raf=0,last=0,time=0,paused=false,destroyed=false;
  let points=[];
  const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)');

  const cssNumber=(name,fallback)=>{const n=parseFloat(getComputedStyle(root).getPropertyValue(name));return Number.isFinite(n)?n:fallback};
  const clamp=(n,a,b)=>Math.max(a,Math.min(b,n));
  function themeColors(){
    const light=root.dataset.theme==='light';
    return light ? {a:[34,152,230],b:[14,166,139],c:[124,92,210],alpha:.32} : {a:[96,165,250],b:[45,212,191],c:[167,139,250],alpha:.62};
  }
  function motionFactor(){const m=root.dataset.motion||'balanced';return m==='immersive'?1.9:m==='cinematic'?1.55:m==='rich'?1.25:m==='balanced'?1:m==='soft'?.58:m==='drift'?.38:m==='minimal'?.2:0}
  function engineSpeed(){return clamp(cssNumber('--engine-speed',1),.35,1.8)*motionFactor()}
  function density(){return clamp(cssNumber('--engine-density',cssNumber('--particle-density',.6)),0,1)}
  function intensity(){return clamp(cssNumber('--background-intensity',.7),0,1)}
  function mode(){return root.dataset.background||'aurora'}
  function active(){return !destroyed&&!paused&&root.dataset.previewPaused!=='true'&&mode()!=='none'&&motionFactor()>0}

  function resize(){
    width=Math.max(1,innerWidth);height=Math.max(1,innerHeight);dpr=Math.min(2,devicePixelRatio||1);
    canvas.width=Math.round(width*dpr);canvas.height=Math.round(height*dpr);canvas.style.width=width+'px';canvas.style.height=height+'px';ctx.setTransform(dpr,0,0,dpr,0,0);
    const mobile=width<620;const count=Math.max(12,Math.min(mobile?44:78,Math.round((width*height/22000)*(0.45+density()))));
    points=Array.from({length:count},(_,i)=>({x:Math.random()*width,y:Math.random()*height,vx:(Math.random()-.5)*.22,vy:(Math.random()-.5)*.22,r:.7+Math.random()*1.6,phase:Math.random()*Math.PI*2,color:i%3}));
    drawFrame(performance.now(),true);
  }
  function rgba(rgb,a){return `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${a})`}
  function glow(x,y,r,rgb,a){const g=ctx.createRadialGradient(x,y,0,x,y,r);g.addColorStop(0,rgba(rgb,a));g.addColorStop(.45,rgba(rgb,a*.45));g.addColorStop(1,rgba(rgb,0));ctx.fillStyle=g;ctx.fillRect(x-r,y-r,r*2,r*2)}
  function drawAurora(t,c,k){glow(width*(.18+.08*Math.sin(t*.00018*k)),height*(.22+.1*Math.cos(t*.00015*k)),Math.max(width,height)*.36,c.b,.18*k);glow(width*(.82+.07*Math.cos(t*.00013*k)),height*(.28+.12*Math.sin(t*.00017*k)),Math.max(width,height)*.32,c.a,.16*k);glow(width*(.52+.1*Math.sin(t*.00011*k)),height*(.82+.06*Math.cos(t*.00016*k)),Math.max(width,height)*.30,c.c,.12*k)}
  function drawWaves(t,c,k){ctx.save();ctx.globalCompositeOperation='screen';const colors=[c.a,c.b,c.c];for(let j=0;j<3;j++){ctx.beginPath();const y0=height*(.25+j*.22);for(let x=-20;x<=width+20;x+=12){const y=y0+Math.sin(x*.012+t*.0008*k+j*1.7)*22+Math.sin(x*.004-t*.00035*k)*13;if(x===-20)ctx.moveTo(x,y);else ctx.lineTo(x,y)}ctx.lineWidth=2+j*.7;ctx.strokeStyle=rgba(colors[j],(.18-j*.02)*k);ctx.shadowBlur=18;ctx.shadowColor=rgba(colors[j],.25*k);ctx.stroke()}ctx.restore()}
  function drawNetwork(t,c,k){const step=52,off=(t*.012*engineSpeed())%step;ctx.lineWidth=.6;ctx.strokeStyle=rgba(c.a,.075*k);for(let x=-step+off;x<width+step;x+=step){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,height);ctx.stroke()}for(let y=-step+off;y<height+step;y+=step){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(width,y);ctx.stroke()}const max=width<620?92:132;for(const p of points){p.x+=p.vx*engineSpeed();p.y+=p.vy*engineSpeed();if(p.x<-10)p.x=width+10;if(p.x>width+10)p.x=-10;if(p.y<-10)p.y=height+10;if(p.y>height+10)p.y=-10}for(let i=0;i<points.length;i++){for(let j=i+1;j<points.length;j++){const a=points[i],b=points[j],d=Math.hypot(a.x-b.x,a.y-b.y);if(d<max){ctx.strokeStyle=rgba((i+j)%2?c.a:c.b,(1-d/max)*.18*k);ctx.lineWidth=.7;ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();if((i+j)%11===0){const progress=(t*.00018*engineSpeed()+a.phase)%1;const px=a.x+(b.x-a.x)*progress,py=a.y+(b.y-a.y)*progress;glow(px,py,12,(i+j)%2?c.a:c.b,.35*k)}}}}for(const p of points){ctx.fillStyle=rgba(p.color===0?c.a:p.color===1?c.b:c.c,.65*k);ctx.beginPath();ctx.arc(p.x,p.y,p.r+1,0,Math.PI*2);ctx.fill()}}
  function drawOrbits(t,c,k){const cx=width*.64,cy=height*.43,base=Math.min(width,height);ctx.save();ctx.translate(cx,cy);for(let i=0;i<4;i++){ctx.save();ctx.rotate((i*.55)+t*.00006*engineSpeed()*(i%2?-1:1));ctx.scale(1,.48+i*.05);ctx.strokeStyle=rgba(i%2?c.a:c.b,(.16-i*.018)*k);ctx.lineWidth=1.1;ctx.beginPath();ctx.ellipse(0,0,base*(.18+i*.075),base*(.18+i*.075),0,0,Math.PI*2);ctx.stroke();const ang=t*.00045*engineSpeed()*(i%2?-1:1)+i;const r=base*(.18+i*.075);const x=Math.cos(ang)*r,y=Math.sin(ang)*r;glow(x,y,14,i%2?c.a:c.b,.36*k);ctx.restore()}ctx.restore()}
  function drawMesh(t,c,k){const positions=[[.18,.22,c.b,.32],[.78,.24,c.a,.28],[.64,.76,c.c,.25],[.28,.78,c.a,.18]];positions.forEach((p,i)=>{const x=width*(p[0]+.09*Math.sin(t*(.00012+i*.000025)*engineSpeed()+i)),y=height*(p[1]+.08*Math.cos(t*(.0001+i*.00002)*engineSpeed()+i*1.3));glow(x,y,Math.max(width,height)*(.30+i*.025),p[2],p[3]*k)})}
  function drawLines(t,c,k){ctx.save();ctx.translate((t*.025*engineSpeed())%180-180,0);ctx.rotate(-.24);for(let x=-height;x<width+height+360;x+=72){const grad=ctx.createLinearGradient(x,0,x+180,0);grad.addColorStop(0,rgba(c.a,0));grad.addColorStop(.5,rgba((x/72)%2?c.a:c.b,.18*k));grad.addColorStop(1,rgba(c.b,0));ctx.strokeStyle=grad;ctx.lineWidth=1.4;ctx.beginPath();ctx.moveTo(x,-height);ctx.lineTo(x,height*2);ctx.stroke()}ctx.restore()}
  function drawParticles(t,c,k){if(mode()==='network')return;const m=root.dataset.motion||'balanced';if(m==='minimal'||m==='off')return;for(const p of points){p.x+=p.vx*.35*engineSpeed();p.y+=p.vy*.35*engineSpeed();if(p.x<-5)p.x=width+5;if(p.x>width+5)p.x=-5;if(p.y<-5)p.y=height+5;if(p.y>height+5)p.y=-5;const rgb=p.color===0?c.a:p.color===1?c.b:c.c;ctx.fillStyle=rgba(rgb,(m==='rich'?.46:.26)*k);ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,Math.PI*2);ctx.fill()}}
  function drawFrame(now,force=false){
    if(destroyed)return; if(!force&&(!active()||document.hidden)){raf=requestAnimationFrame(drawFrame);return}
    if(!force&&now-last<33){raf=requestAnimationFrame(drawFrame);return}last=now;time=now;ctx.clearRect(0,0,width,height);
    const c=themeColors(),k=intensity();const m=mode();
    if(m==='aurora')drawAurora(now,c,k);else if(m==='waves')drawWaves(now,c,k);else if(m==='network')drawNetwork(now,c,k);else if(m==='orbits')drawOrbits(now,c,k);else if(m==='mesh')drawMesh(now,c,k);else if(m==='nebula'){drawAurora(now,c,k*.9);drawMesh(now,c,k*.85);}else if(m==='lines')drawLines(now,c,k);else if(m==='constellation'){drawNetwork(now,c,k*.7);drawOrbits(now,c,k*.5);}else if(m==='prism'){drawWaves(now,c,k*.9);drawLines(now,c,k*.5);}else if(m==='circuit'){drawNetwork(now,c,k*.8);drawLines(now,c,k*.7);}else if(m==='pulse'){drawAurora(now,c,k*.7);drawOrbits(now,c,k*.7);} 
    drawParticles(now,c,k);
    if(!force)raf=requestAnimationFrame(drawFrame);
  }
  function refresh(){resize()}
  function pause(){paused=true;root.dataset.previewPaused='true';cancelAnimationFrame(raf);drawFrame(time||performance.now(),true)}
  function resume(){paused=false;root.dataset.previewPaused='false';cancelAnimationFrame(raf);raf=requestAnimationFrame(drawFrame)}
  function destroy(){destroyed=true;cancelAnimationFrame(raf);ctx.clearRect(0,0,width,height)}
  window.SubscriptionBackgroundEngine={refresh,pause,resume,destroy,get paused(){return paused}};
  addEventListener('resize',resize,{passive:true});
  new MutationObserver(()=>refresh()).observe(root,{attributes:true,attributeFilter:['data-theme','data-background','data-motion','style','data-preview-paused']});
  reduceMotion.addEventListener?.('change',refresh);
  resize();
  if(reduceMotion.matches||!active())drawFrame(performance.now(),true);else raf=requestAnimationFrame(drawFrame);
})();


/* Public subscription portal.
 *
 * Data contract (see _subscription_public_payload in app.py). The initial
 * payload rendered into the template and the payload returned by the refresh
 * API are produced by the same function, so this file can rely on one shape:
 *
 *   id, name, token, enabled, unlimited, limit_bytes, used_bytes,
 *   data_limit_value, data_limit_unit, start_on_first_use, first_used_at,
 *   expires_at, expires_at_ts, ttl_seconds,
 *   access: { allowed, reason, message },
 *   locations: [{ link_id, peer_id, name, status, endpoint, public_host,
 *                 location_label, country_code, flag }]
 */

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

function accessState(){
  const access = DATA.access || {};
  return {
    allowed: access.allowed !== false,
    reason: String(access.reason || ''),
    message: String(access.message || '')
  };
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
  const access = accessState();
  if(!access.allowed){
    if(access.reason === 'expired') return 'Expired';
    if(access.reason === 'data_exhausted') return 'No data left';
    return 'Disabled';
  }

  const locs = DATA.locations || [];
  if (DATA.access && DATA.access.has_inbounds === false) return 'No configs';
  if(locs.some(l => String(l.status || '').toLowerCase() === 'blocked')) return 'Blocked';
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
    if(r.status===403){
      await refreshData(true);
      showToast(accessState().message || 'This subscription is no longer active');
      return;
    }
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
    showToast('Download failed');
  }
}
function escapeHtml(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function isCountryCode(cc){return /^[A-Z]{2}$/.test(String(cc||'').trim().toUpperCase())}
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

function setRing(id,p,label,color){const el=document.getElementById(id);if(!el)return;p=Math.max(0,Math.min(100,Math.round(Number(p||0))));el.style.setProperty('--p',p);if(color)el.style.setProperty('--c',color);const s=el.querySelector('span');if(s)s.textContent=label||`${p}%`;}

function renderAccess(){
  const banner=document.getElementById('access-banner');
  const access=accessState();
  document.documentElement.dataset.access = access.allowed ? 'allowed' : (access.reason || 'revoked');
  if(!banner) return;
  if(access.allowed){
    banner.hidden = true;
    banner.textContent = '';
    return;
  }
  banner.hidden = false;
  banner.textContent = access.message || 'This subscription is no longer active.';
}

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
  set('time-sub', timeSubText());
  const timerMode=document.getElementById('timer-mode');
  if(timerMode){
    timerMode.textContent=timeModeText();
    timerMode.className='timer-chip '+timeModeText().toLowerCase().replace(/\s+/g,'-');
  }
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
  const grid=document.getElementById('loc-grid');
  if(!grid) return;
  const locs=DATA.locations||[];
  if(!locs.length){grid.innerHTML='<div class="empty">No configs are available.</div>';return}
  const access=accessState();
  if(!access.allowed){grid.innerHTML=`<div class="empty">${escapeHtml(access.message||'Configs are unavailable for this subscription.')}</div>`;return}
  grid.innerHTML=locs.map(l=>{
    const initialLoc=cleanLocation(l), initialFlagHtml=flagMarkup(l.country_code,l.flag||'🌐'), host=publicAddress(l), needsGeo=!!host, label=escapeHtml(l.name||'wireguard');
    return `<article class="loc" data-link="${l.link_id}" data-host="${escapeHtml(host)}" data-geo="${needsGeo?'1':'0'}"><div class="loc-top"><div class="loc-main"><div class="loc-name"><span class="loc-flag">${initialFlagHtml}</span><span class="loc-title">${escapeHtml(l.name||'Config')}</span></div><span class="loc-country">${needsGeo?'Detecting location...':escapeHtml(initialLoc)}</span></div><span class="status ${escapeHtml(String(l.status||'').toLowerCase())}">${escapeHtml(l.status||'offline')}</span></div><div class="loc-actions"><a class="loc-btn loc-download" href="${configUrl(l.link_id)}" data-download-config="${l.link_id}" data-filename="${label}" download="${label}.conf"><i class="fas fa-download"></i><span>Download</span></a><button class="loc-btn" data-qr="${l.link_id}" data-name="${label}" data-location="${escapeHtml(initialLoc)}"><i class="fas fa-qrcode"></i></button><button class="loc-btn" data-copy="${location.origin}${configUrl(l.link_id)}"><i class="fas fa-copy"></i></button></div></article>`;
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
      // Geo lookup is decoration: a failure must never block the config actions.
      const c = card.querySelector('.loc-country');
      if(c) c.textContent = 'Location';
    }
  }
}

function render(){renderAccess();renderStats();renderLocations()}

async function refreshData(silent=false){
  const live=document.getElementById('live-dot');
  if(live) live.classList.add('loading');
  try{
    const r=await fetch(API_URL,{cache:'no-store',headers:{'Accept':'application/json'}});
    if(!r.ok) throw new Error('bad status');
    const j=await r.json();
    DATA=j.subscription||DATA;
    render();
    if(!silent) showToast('Updated');
  }catch(e){
    if(!silent) showToast('Update failed');
  }finally{if(live) setTimeout(()=>live.classList.remove('loading'),700)}
}

const copySubButton = document.getElementById('copy-sub');
if(copySubButton) copySubButton.onclick = () => copyText(CONFIG_URL);

const downloadAllButton = document.getElementById('download-all');
if(downloadAllButton){
  downloadAllButton.addEventListener('click', async e => {
    e.preventDefault();
    const url = downloadAllButton.getAttribute('href');
    try{
      const r = await fetch(url, {cache:'no-store', credentials:'same-origin'});
      if(r.status === 403){
        await refreshData(true);
        showToast(accessState().message || 'This subscription is no longer active');
        return;
      }
      if(!r.ok) throw new Error(`HTTP ${r.status}`);
      const objectUrl = URL.createObjectURL(await r.blob());
      const a = document.createElement('a');
      a.href = objectUrl;
      a.download = `${String(DATA.name || 'subscription').replace(/[^A-Za-z0-9_.-]+/g,'_') || 'subscription'}.zip`;
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(objectUrl), 1500);
      showToast('Configs downloaded');
    }catch(err){
      console.error(err);
      showToast('Download failed');
    }
  });
}

function openQrDialog(id,name,locationLabel){
  const dialog=document.getElementById('qr-dialog'),img=document.getElementById('qr-image'),title=document.getElementById('qr-title'),locationEl=document.getElementById('qr-location'),download=document.getElementById('qr-download');
  if(!dialog||!img) return;
  img.src=qrUrl(id); if(title)title.textContent=name||'WireGuard QR'; if(locationEl)locationEl.textContent=locationLabel||'Scan with the WireGuard app';
  if(download){download.href=configUrl(id);download.dataset.downloadConfig=id;download.dataset.filename=name||'wireguard';}
  dialog.hidden=false;document.body.classList.add('qr-open');
}
function closeQrDialog(){const dialog=document.getElementById('qr-dialog');if(dialog)dialog.hidden=true;document.body.classList.remove('qr-open');}
document.querySelectorAll('[data-close-qr]').forEach(el=>el.addEventListener('click',closeQrDialog));
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeQrDialog();});

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
  if(q){e.preventDefault();e.stopPropagation();openQrDialog(q.dataset.qr,q.dataset.name||'WireGuard',q.dataset.location||'Scan with the WireGuard app');return;}

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
  if(window.SubscriptionBackgroundEngine) return;
  const c=document.getElementById('particles'); if(!c)return; const ctx=c.getContext('2d',{alpha:true}); if(!ctx)return;
  const motion=document.documentElement.dataset.motion||PUBLIC_SETTINGS?.animation||'balanced';
  if(motion==='off'||motion==='minimal'||matchMedia('(prefers-reduced-motion: reduce)').matches){c.style.display='none';return;}
  let w=0,h=0,dpr=1,pts=[],raf=0,last=0;
  const configuredDensity=Math.max(0,Math.min(1,Number(PUBLIC_SETTINGS?.particle_density ?? 60)/100));
  const configuredSpeed=Math.max(.5,Math.min(1.5,Number(PUBLIC_SETTINGS?.motion_speed ?? 100)/100));
  const factor=(motion==='rich'?1:motion==='soft'?.45:.72)*configuredDensity;
  function resize(){w=Math.max(1,innerWidth);h=Math.max(1,innerHeight);dpr=Math.min(2,devicePixelRatio||1);c.width=Math.round(w*dpr);c.height=Math.round(h*dpr);c.style.width=w+'px';c.style.height=h+'px';ctx.setTransform(dpr,0,0,dpr,0,0);const count=Math.max(18,Math.min(85,Math.round((w*h/17000)*factor)));pts=Array.from({length:count},()=>({x:Math.random()*w,y:Math.random()*h,vx:(Math.random()-.5)*(.1*factor*configuredSpeed),vy:(Math.random()-.5)*(.1*factor*configuredSpeed),r:.7+Math.random()*1.4}));}
  function frame(now){if(document.hidden||now-last<33){raf=requestAnimationFrame(frame);return}last=now;ctx.clearRect(0,0,w,h);const light=document.documentElement.dataset.theme==='light';const colors=light?['49,126,236','20,168,143','126,93,220']:['183,218,255','92,226,190','174,146,255'];for(let i=0;i<pts.length;i++){const p=pts[i];p.x+=p.vx;p.y+=p.vy;if(p.x<-8)p.x=w+8;else if(p.x>w+8)p.x=-8;if(p.y<-8)p.y=h+8;else if(p.y>h+8)p.y=-8;ctx.fillStyle=`rgba(${colors[i%3]},${light?.42:.68})`;ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,Math.PI*2);ctx.fill();}if(motion==='rich'||document.documentElement.dataset.background==='network'){const max=w<560?105:135;ctx.lineWidth=.65;for(let i=0;i<pts.length;i++)for(let j=i+1;j<pts.length;j++){const a=pts[i],b=pts[j],d=Math.hypot(a.x-b.x,a.y-b.y);if(d<max){ctx.strokeStyle=`rgba(${colors[(i+j)%3]},${(1-d/max)*(light?.16:.24)})`;ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();}}}raf=requestAnimationFrame(frame);}
  addEventListener('resize',resize,{passive:true});resize();raf=requestAnimationFrame(frame);
})();
try{
  const root=document.documentElement,s=PUBLIC_SETTINGS||{};
  const attrs={statStyle:s.display_mode,motion:s.animation,accent:s.accent,surface:s.surface,radius:s.radius,shadow:s.shadow,density:s.density,pageWidth:s.page_width,configStyle:s.config_style,configColumns:s.config_columns,sectionOrder:s.section_order,supportStyle:s.support_style,buttonStyle:s.button_style,fontScale:s.font_scale,heroStyle:s.hero_style,background:s.background,layout:s.layout,statSize:s.stat_size,titleAlign:s.title_align,logoSize:s.logo_size};
  Object.entries(attrs).forEach(([k,v])=>{if(v)root.dataset[k]=v});
  [['showQuick','show_quick_stats'],['showInstall','show_install'],['showSupport','show_support'],['showLive','show_live_badge'],['showPercentage','show_percentage'],['showUsedDetail','show_used_detail'],['showStatus','show_status_badge'],['showCountry','show_location_country'],['showDownload','show_download_action'],['showCopy','show_copy_action'],['showThemeAction','show_theme_action'],['showDescriptions','show_section_descriptions']].forEach(([dataKey,key])=>{if(key in s)root.dataset[dataKey]=String(!!s[key]);});
  if(s.custom_primary)root.style.setProperty('--custom-accent',s.custom_primary);
  if(s.custom_secondary)root.style.setProperty('--custom-accent2',s.custom_secondary);
  if(s.background_intensity!=null)root.style.setProperty('--background-intensity',Math.max(0,Math.min(1,Number(s.background_intensity)/100)));
  if(s.card_opacity!=null)root.style.setProperty('--card-opacity',Math.max(.5,Math.min(1,Number(s.card_opacity)/100)));
  if(s.motion_speed!=null)root.style.setProperty('--motion-speed',Math.max(.5,Math.min(1.5,100/Number(s.motion_speed||100))));
  if(s.particle_density!=null)root.style.setProperty('--particle-density',Math.max(0,Math.min(1,Number(s.particle_density)/100)));
}catch(_){}
render();
setInterval(()=>refreshData(true), 30000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden) refreshData(true)});

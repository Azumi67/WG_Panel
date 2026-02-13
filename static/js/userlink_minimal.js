
(() => {
  const IS_PREVIEW = new URLSearchParams(location.search).has('embed');
  const safeStore = {
    get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
    set: (k, v) => { try { localStorage.setItem(k, v); } catch {} }
    };

  const $ = (s, r = document) => r.querySelector(s);
  const clamp01 = (x) => Math.max(0, Math.min(1, x));
  const bytesToMiB = (b) => (Number(b) || 0) / 1048576;
  const pad2 = (n) => String(n).padStart(2, '0');

  function toast(msg, type = 'ok', ms = 2200) {
    const host =
      $('#toast-container') ||
      (() => {
        const d = document.createElement('div');
        d.id = 'toast-container';
        document.body.appendChild(d);
        return d;
      })();
    const t = document.createElement('div');
    t.className = `toast ${type === 'err' ? 'err' : 'ok'}`;
    t.textContent = msg;
    host.appendChild(t);
    setTimeout(() => {
      t.style.opacity = '0';
      t.style.transform = 'translateY(-4px)';
      t.style.transition = 'all .2s';
    }, ms - 180);
    setTimeout(() => t.remove(), ms);
  }

  function setText(idOrEl, text) {
    const el = typeof idOrEl === 'string' ? $(idOrEl) : idOrEl;
    if (el && el.textContent !== String(text)) el.textContent = String(text);
  }
  function setStyle(el, prop, value) {
    if (!el) return;
    if (el.style[prop] !== value) el.style[prop] = value;
  }

  function fmtMiB(mib) {
    if (!isFinite(mib)) return 'Unlimited';
    if (mib >= 1024) {
      const g = mib / 1024;
      return `${(g >= 10 ? g.toFixed(1) : g.toFixed(2)).replace(/\.0+$/, '')} GiB`;
    }
    return `${Math.max(0, Math.round(mib))} MiB`;
  }
  function fmtTime(s) {
    s = Math.max(0, Math.floor(s || 0));
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }
  function iso(ts) {
    if (!ts) return '—';
    const d = new Date(ts * 1000);
    return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(
      d.getMinutes()
    )}`;
  }

  const THEME_KEY = 'ulm-theme';
  const root = document.documentElement;

  function currentTheme() {
  return root.getAttribute('data-theme') || safeStore.get(THEME_KEY) || systemPref();
}
  function systemPref() {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}
  function applyTheme(theme) {
  root.setAttribute('data-theme', theme);
  safeStore.set(THEME_KEY, theme);
  const btn = $('#ulm-theme');
  if (btn) {
    btn.innerHTML =
      theme === 'dark'
        ? '<i class="fas fa-sun" aria-hidden="true"></i>'
        : '<i class="fas fa-moon" aria-hidden="true"></i>';
    btn.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
  }
}
  function initTheme() {
  applyTheme(currentTheme());
  $('#ulm-theme')?.addEventListener('click', () => {
    const next = currentTheme() === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    refreshLiveBgTheme();
  });
}

  function setStatus(el, status) {
  if (!el) return;
  el.classList.remove('ok', 'off', 'blk');
  const dot = el.querySelector('.dot');
  const label = el.querySelector('b');
  if (label) setText(label, status ? status[0].toUpperCase() + status.slice(1) : '—');

  if (status === 'online') {
    el.classList.add('ok');
    if (dot) setStyle(dot, 'background', 'var(--ok)');
  } else if (status === 'blocked') {
    el.classList.add('blk');
    if (dot) setStyle(dot, 'background', 'var(--bad)');   // <-- red
  } else {
    el.classList.add('off');
    if (dot) setStyle(dot, 'background', 'var(--bad)');
  }
}


  const activeAnims = new WeakMap();
  function animateWidth(el, targetPct, ms = 400) {
    if (!el) return;
    const target = clamp01(targetPct) * 100;
    const start = parseFloat(el.style.width) || 0;
    if (Math.abs(target - start) < 0.5) {
      setStyle(el, 'width', target + '%');
      return;
    }
    const prev = activeAnims.get(el);
    if (prev && prev.raf) cancelAnimationFrame(prev.raf);

    const t0 = performance.now();
    function step(t) {
      const k = Math.min(1, (t - t0) / ms);
      const v = start + (target - start) * (1 - Math.pow(1 - k, 3)); 
      setStyle(el, 'width', v + '%');
      if (k < 1) {
        const raf = requestAnimationFrame(step);
        activeAnims.set(el, { raf });
      }
    }
    const raf = requestAnimationFrame(step);
    activeAnims.set(el, { raf });
  }

  function setBar(el, pct, flavor) {
    if (!el) return;
    el.classList.remove('green', 'warn', 'bad');
    if (flavor) el.classList.add(flavor);
    animateWidth(el, pct);
  }

  let qrRendered = false;
  async function renderQROnce(url) {
    if (qrRendered) return;
    const host = $('#ulm-qr');
    if (!host) return;
    host.innerHTML = '';
    try {
      new QRCode(host, { text: url, width: 200, height: 200, correctLevel: QRCode.CorrectLevel.M });
      qrRendered = true;
    } catch (e) {
      setText(host, 'QR unavailable');
    }
  }

  const token = (window.USER_LINK_TOKEN || '').trim();
  const API = token ? `/api/u/${token}` : '';
  const state = { ttl: null, unlimited: false, limit_mib: 0, used_mib: 0, capSec: null }; 
  let ttlOrigin = null;

  async function getPeer(signal) {
    const r = await fetch(API, { cache: 'no-store', signal });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }
  function pick(/* selectors */) {
  for (const s of arguments) {
    const el = document.querySelector(s);
    if (el) return el;
  }
  return null;
  }

  function applyStatic(j) {
  const nameEl = pick('#ulm-name', '#ulc-name', '#peer-title', '.peer-name', '[data-role="peer-name"]');
  if (nameEl) nameEl.textContent = j.name || '—';

  const stEl = pick('#ulm-status', '#ulc-status');
  if (stEl) setStatus(stEl, j.status);

  const addrEl = pick('#ulm-address', '#ulc-address'); if (addrEl) addrEl.textContent = j.address || '—';
  const epEl   = pick('#ulm-endpoint', '#ulc-endpoint'); if (epEl) epEl.textContent = (j.endpoint || '').trim() || '—';

  const dl = document.querySelector('#ulm-dl');
  if (!IS_PREVIEW && dl && !dl.dataset.bound) { dl.href = `${API}/config`; dl.dataset.bound = '1'; }
  const copyBtn = document.querySelector('#ulm-copy');
  if (!IS_PREVIEW && copyBtn && !copyBtn.dataset.bound) {
    copyBtn.addEventListener('click', async () => {
      try {
        const r = await fetch(`${API}/config`); const t = await r.text();
        await navigator.clipboard.writeText(t); toast('Config copied');
      } catch { toast('Copy failed','err'); }
    }, { once:true });
    copyBtn.dataset.bound = '1';
  }
}

function nowSec(){ return Math.floor(Date.now()/1000); }
function parseTs(v){
  if (v == null) return null;
  if (typeof v === 'number') return v > 1e12 ? Math.floor(v/1000) : Math.floor(v);
  const d = new Date(String(v)); return isNaN(d) ? null : Math.floor(d.getTime()/1000);
}

function applyData(j, isFirst){
  state.unlimited = !!j.unlimited;

  let lim = Infinity;
  if (!state.unlimited) {
    const unit = String(j.limit_unit || j.unit || '').toLowerCase(); 
    const raw  = Number(j.data_limit) || 0;
    if (raw > 0) lim = unit.startsWith('gi') ? raw * 1024 : raw;
    else {
      const b = Number(j.data_limit_bytes || j.limit_bytes) || 0;
      lim = b > 0 ? b/1048576 : (Number(j.limit_mib) || 0);
    }
  }

  const usedEff = (j.used_effective_bytes
                  ?? ((Number(j.used_bytes)||0) + (Number(j.used_bytes_db)||0))
                  ?? (Number(j.used_bytes)||0));
  const used = bytesToMiB(usedEff);

  const isBlocked = String(j.status||'').toLowerCase() === 'blocked';
  let remaining = state.unlimited ? Infinity : Math.max(0, lim - used);
  if (!state.unlimited && isFinite(lim) && lim > 0 && isBlocked) remaining = 0;

  state.used_mib  = used;
  state.limit_mib = lim;
  {
    const el = pick('#ulm-name', '#ulc-name', '#name', '#peer-name',
      '.peer-name', '[data-role="peer-name"]', '[data-name]');
      if (el) el.textContent = j.name || '—';
      }
  setText('#ulm-data-left', fmtMiB(remaining));
  setText('#ulm-limit', state.unlimited ? 'Unlimited' : `Limit ${fmtMiB(lim)}`);
  setText('#ulm-used', state.unlimited ? '' : `${fmtMiB(isBlocked ? lim : used)} used`);

  if (state.unlimited) setBar($('#ulm-data-bar'), 1, 'green');
  else {
    const pctRemain = lim ? remaining/lim : 0;
    const flavor = pctRemain < 0.15 ? 'bad' : pctRemain < 0.45 ? 'warn' : 'green';
    setBar($('#ulm-data-bar'), pctRemain, flavor);
  }

  const expTs = parseTs(j.expires_at_ts ?? j.expires_at ?? null);
  state.ttl = Number.isFinite(j.ttl_seconds) ? Number(j.ttl_seconds)
           : (expTs != null ? Math.max(0, expTs - nowSec()) : null);
  const startTs = parseTs(j.start_at ?? j.started_at ?? j.first_used ?? j.created_at ?? j.added_at);
  let capSec =
  Number(j.time_limit_seconds ?? j.timer_seconds ?? j.duration_seconds ?? j.max_age_seconds) || 0;
  if (!capSec) {
    const days = Number(j.time_limit_days ?? j.valid_days) || 0;
    if (days > 0) capSec = days * 86400;
  }
  if (!capSec && expTs && startTs && expTs > startTs) capSec = expTs - startTs;
  if (!capSec) capSec = Math.max(state.ttl || 0, 1);
  state.capSec = capSec;


  if (state.unlimited || state.ttl == null) {
    setText('#ulm-time-left', '—');
    setText('#ulm-exp', 'No expiry');
    setBar($('#ulm-time-bar'), 1, '');
    ttlOrigin = null;
  } else {
    const cap = Math.max(state.capSec || 0, 1);
    const pct = clamp01(state.ttl / cap);
    const flavor = state.ttl === 0 ? 'bad' : state.ttl < 3600 ? 'bad' : state.ttl < 21600 ? 'warn' : '';
    setBar($('#ulm-time-bar'), pct, flavor);
  }
}

function isDark(){ return document.documentElement.getAttribute('data-theme') === 'dark'; }
function cssVar(name, fallback){ return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback; }

function toRgba(c, a){
  c = (c||'').trim();
  if (c.startsWith('#')){
    const n = parseInt(c.slice(1),16);
    const r=(n>>16)&255, g=(n>>8)&255, b=n&255;
    return `rgba(${r},${g},${b},${a})`;
  }
  if (c.startsWith('rgba(')) return c.replace(/rgba\(([^)]+),\s*[\d.]+\)/, `rgba($1, ${a})`);
  if (c.startsWith('rgb('))  return c.replace('rgb(', 'rgba(').replace(')', `, ${a})`);
  return `rgba(99,102,241,${a})`;
}

let BG = { cvs:null, ctx:null, w:0, h:0, dpr:1, raf:0, pts:[], reduced:false, conf:null };

function initLiveBg(){
  const cvs = document.getElementById('ulm-bg');
  if (!cvs) return;
  const ctx = cvs.getContext('2d', { alpha:true });
  BG.cvs=cvs; BG.ctx=ctx;
  BG.reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function config(){
    const area = BG.w * BG.h;
    const count = Math.round(area / 12000); 
    return {
      COUNT: Math.min(200, Math.max(70, count)),
      R_MIN: 1.0,  R_MAX: 2.4,                 
      SPEED_MIN: 0.08, SPEED_MAX: 0.28,       
      LINK_DIST: 120,                         
      LINK_ALPHA: isDark()? 0.25 : 0.16,
      WASH_ALPHA: isDark()? 0.10 : 0.06,
      COLORS: [
        cssVar('--accent',   '#6366f1'),
        cssVar('--accent-2', '#8b5cf6'),
        cssVar('--ok',       '#22c55e')
      ]
    };
  }

  function resize(){
    const dpr = Math.min(window.devicePixelRatio||1, 2);
    BG.dpr=dpr;
    const w = cvs.clientWidth|0, h = cvs.clientHeight|0;
    if (w===BG.w && h===BG.h) return;
    BG.w=w; BG.h=h;
    cvs.width=w*dpr; cvs.height=h*dpr; ctx.setTransform(dpr,0,0,dpr,0,0);
    BG.conf = config();
    spawn();
    draw(true); 
  }

  function spawn(){
    const C=BG.conf; BG.pts.length=0;
    for (let i=0;i<C.COUNT;i++){
      const r   = C.R_MIN + Math.random()*(C.R_MAX - C.R_MIN);
      const sp  = C.SPEED_MIN + Math.random()*(C.SPEED_MAX - C.SPEED_MIN);
      const th  = Math.random()*Math.PI*2;
      BG.pts.push({
        x: Math.random()*BG.w,
        y: Math.random()*BG.h,
        vx: Math.cos(th)*sp*(BG.reduced?0:1),
        vy: Math.sin(th)*sp*(BG.reduced?0:1),
        r,
        c: C.COLORS[i % C.COLORS.length]
      });
    }
  }

  function wash(){
    const wash = cssVar('--track', isDark()? '#0f172a' : '#eef2f7');
    BG.ctx.fillStyle = wash;
    BG.ctx.globalAlpha = BG.conf.WASH_ALPHA;
    BG.ctx.fillRect(0,0,BG.w,BG.h);
    BG.ctx.globalAlpha = 1;
  }

  function draw(staticOnly=false){
    const {ctx}=BG, C=BG.conf, pts=BG.pts;
    ctx.clearRect(0,0,BG.w,BG.h);
    wash();

    for (const p of pts){
      p.x += p.vx; p.y += p.vy;
      if (p.x < -10) p.x = BG.w+10; else if (p.x > BG.w+10) p.x = -10;
      if (p.y < -10) p.y = BG.h+10; else if (p.y > BG.h+10) p.y = -10;
    }

    ctx.lineWidth = 1;
    for (let i=0;i<pts.length;i++){
      const a = pts[i];
      for (let j=i+1;j<pts.length;j++){
        const b = pts[j];
        const dx=a.x-b.x, dy=a.y-b.y, d2=dx*dx+dy*dy, ld=C.LINK_DIST;
        if (d2 < ld*ld){
          const t = 1 - Math.sqrt(d2)/ld;
          ctx.strokeStyle = `rgba(148,163,184,${C.LINK_ALPHA * t})`;
          ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke();
        }
      }
    }

    for (const p of pts){
      ctx.beginPath();
      ctx.fillStyle = toRgba(p.c, isDark()? 0.45 : 0.28);
      ctx.arc(p.x, p.y, p.r*2.2, 0, Math.PI*2); ctx.fill();
      ctx.beginPath();
      ctx.fillStyle = toRgba(p.c, isDark()? 0.90 : 0.70);
      ctx.arc(p.x, p.y, p.r, 0, Math.PI*2); ctx.fill();
    }

    if (staticOnly || BG.reduced) return;
    BG.raf = requestAnimationFrame(()=>draw(false));
  }

  function start(){ stop(); resize(); if (!BG.reduced) BG.raf=requestAnimationFrame(()=>draw(false)); }
  function stop(){ if (BG.raf) cancelAnimationFrame(BG.raf); BG.raf=0; }

  BG.resize=resize; BG.start=start; BG.stop=stop;
  BG.rebuild = () => { BG.conf = config(); spawn(); draw(true); };

  window.addEventListener('resize', resize);
  document.addEventListener('visibilitychange', ()=>{ if (document.hidden) stop(); else start(); });

  start();
}

function refreshLiveBgTheme(){
  if (!BG.cvs) return;
  BG.rebuild?.(); BG.start?.();
}

  function applySupport(tgHandle) {
    const slot = $('#ulm-support-slot');
    if (!slot || slot.dataset.bound) return;
    slot.dataset.bound = '1';
    const tg = (tgHandle || window.SUPPORT_TG || '').trim();
    if (!tg) return;
    const a = document.createElement('a');
    a.href = `https://t.me/${tg.replace('@', '')}`;
    a.target = '_blank';
    a.className = 'chip';
    a.innerHTML = `<i class="fab fa-telegram"></i><b>${tg}</b>`;
    const dot = document.createElement('i');
    dot.className = 'dot';
    dot.style.background = 'var(--accent)';
    a.prepend(dot);
    slot.appendChild(a);
  }

  function startCountdown() {
    let last = performance.now();
    function tick(now) {
      const dt = Math.floor((now - last) / 1000);
      if (dt >= 1) {
        last = now;
        if (state.ttl != null && !state.unlimited) {
          state.ttl = Math.max(0, state.ttl - dt);
          setText('#ulm-time-left', state.ttl ? fmtTime(state.ttl) : 'expired');
          const cap = Math.max(state.capSec || state.ttl || 1, 1);
          const pct = clamp01((state.ttl || 0) / cap);
          const flavor = state.ttl === 0 ? 'bad' : state.ttl < 3600 ? 'bad' : state.ttl < 21600 ? 'warn' : '';
          setBar($('#ulm-time-bar'), pct, flavor);
        }
      }
      requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  let baseInterval = 15000;
  let backoff = 0;
  let pollTimer = null;
  function schedule(nextMs) {
    clearTimeout(pollTimer);
    if (document.hidden) return;
    pollTimer = setTimeout(pollOnce, nextMs);
  }
  function successReset() {
    backoff = 0;
    schedule(baseInterval + Math.floor(Math.random() * 1200));
  }
  function failureBackoff() {
    backoff = Math.min(backoff + 1, 5);
    const delay = Math.min(baseInterval * Math.pow(1.7, backoff), 60000);
    schedule(delay);
  }
  async function pollOnce() {
    const controller = new AbortController();
    const killer = setTimeout(() => controller.abort(), 6000);
    try {
      const j = await getPeer(controller.signal);
      applyStatic(j);
      applyData(j, false);
      successReset();
    } catch (e) {
      if (backoff === 0) console.warn('User link refresh failed:', e?.message || e);
      failureBackoff();
    } finally {
      clearTimeout(killer);
    }
  }
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) schedule(500);
    else clearTimeout(pollTimer);
  });

  document.addEventListener('DOMContentLoaded', async () => {
    initTheme();
    initLiveBg();

    if (IS_PREVIEW) {
      const now = Math.floor(Date.now()/1000);
      const demo = {
        name: 'azumi',
        status: 'online',
        address: '10.66.66.7/24',
        endpoint: 'wireguard.azumi.com:51820',
        unlimited: false,
        limit_unit: 'Gi',         
        data_limit: 1,
        used_bytes: 0,
        ttl_seconds: 6*3600,      
        expires_at_ts: now + 6*3600
   };
   applyStatic(demo);
   applyData(demo, true);
   await renderQROnce('[WG-CONFIG-PREVIEW]');
   const slot = document.getElementById('ulm-support-slot');
   if (slot && window.SOCIALS) renderSocials(slot, window.SOCIALS);
   return;  
 }
    

    const controller = new AbortController();
    const killer = setTimeout(() => controller.abort(), 8000);

    try {
      const j = await getPeer(controller.signal);
      applyStatic(j);
      applyData(j, true);
      await renderQROnce(`${window.location.origin}${API}/config`);
      const slot = document.getElementById('ulm-support-slot');
      if (slot && window.SOCIALS) renderSocials(slot, window.SOCIALS);
      startCountdown();
      successReset();
    } catch (e) {
      console.error(e);
      toast('Failed to load', 'err');
    } finally {
      clearTimeout(killer);
    }
  });
  function renderSocials(slot, socials){
  const S = socials || {};
  const items = [];
  if (S.telegram)  items.push({href:`https://t.me/${S.telegram.replace('@','')}`, icon:'fab fa-telegram',  label:S.telegram});
  if (S.whatsapp)  items.push({href: S.whatsapp.startsWith('http')?S.whatsapp:`https://wa.me/${S.whatsapp.replace(/\D+/g,'')}`, icon:'fab fa-whatsapp', label:'WhatsApp'});
  if (S.instagram) items.push({href:S.instagram, icon:'fab fa-instagram', label:'Instagram'});
  if (S.website)   items.push({href:S.website, icon:'fas fa-globe', label:'Website'});
  if (S.email)     items.push({href:`mailto:${S.email}`, icon:'fas fa-envelope', label:S.email});
  if (S.phone)     items.push({href:`tel:${S.phone}`, icon:'fas fa-phone', label:S.phone});

  slot.innerHTML = items.map(x =>
    `<a class="chip" target="_blank" rel="noopener" href="${x.href}">
       <i class="${x.icon}" aria-hidden="true"></i><b>${x.label}</b>
     </a>`).join('');
}

document.addEventListener('DOMContentLoaded', () => {
  const slot = document.getElementById('ulc-support-slot') || document.getElementById('ulm-support-slot');
  if (slot && window.SOCIALS) renderSocials(slot, window.SOCIALS);
});

})();

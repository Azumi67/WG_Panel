
(() => {
  const IS_PREVIEW = new URLSearchParams(location.search).has('embed');
  const safeStore = {
    get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
    set: (k, v) => { try { localStorage.setItem(k, v); } catch {} }
  };

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const clamp01 = x => Math.max(0, Math.min(1, x));
  const pad2 = n => String(n).padStart(2, '0');
  const bytesToMiB = b => (Number(b) || 0) / 1048576;

  function toast(msg, type='ok', ms=2200){
    const host = $('#toast-container') || (() => {
      const d = document.createElement('div');
      d.id = 'toast-container';
      document.body.appendChild(d);
      return d;
    })();
    const t = document.createElement('div');
    t.className = `toast ${type==='err'?'err':''}`;
    t.textContent = msg;
    host.appendChild(t);
    setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .2s'; }, ms - 150);
    setTimeout(() => t.remove(), ms);
  }

  function setText(selOrEl, txt){
    const el = typeof selOrEl === 'string' ? $(selOrEl) : selOrEl;
    if (el && el.textContent !== String(txt)) el.textContent = String(txt);
  }

  const fmtMiB = (mib) => {
    if (!isFinite(mib)) return 'Unlimited';
    if (mib >= 1024) { const g = mib/1024; return `${(g>=10?g.toFixed(1):g.toFixed(2)).replace(/\.0+$/,'')} GiB`; }
    return `${Math.max(0, Math.round(mib))} MiB`;
  };
  const fmtTime = (s) => {
    s = Math.max(0, Math.floor(s||0));
    const d = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60);
    if (d>0) return `${d}d ${h}h`;
    if (h>0) return `${h}h ${m}m`;
    return `${m}m`;
  };
  const iso = (ts) => {
    if (!ts) return '—';
    const d = new Date(ts*1000);
    return `${d.getFullYear()}-${pad2(d.getMonth()+1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  };


  function applyThemeClass(isLight){
    const root = document.documentElement;
    root.classList.toggle('light', isLight);
    root.setAttribute('data-theme', isLight ? 'light' : 'dark');
    }
  function loadTheme(){
    const t = safeStore.get('pro-theme');
    applyThemeClass(t ? t === 'light' : false);
    }
  function toggleTheme(){
    const root = document.documentElement;
    const isLight = !root.classList.contains('light');
    applyThemeClass(isLight);
    safeStore.set('pro-theme', isLight ? 'light' : 'dark');
    }

  function setStatus(elOrSel, status){
  const el = typeof elOrSel === 'string' ? document.querySelector(elOrSel) : elOrSel;
  if (!el) return;

  const s = String(status || '').toLowerCase();
  el.classList.remove('ok','off','blk');

  const label = el.querySelector('.label') ||
                el.querySelector('b') ||
                el.querySelector('span:not(.dot)') || el;
  label.textContent = status ? (status[0].toUpperCase() + status.slice(1)) : '—';

  const dot = el.querySelector('.dot');
  if (s === 'online') { el.classList.add('ok');  if (dot) dot.style.background = 'var(--ok)'; }
  else if (s === 'blocked') { el.classList.add('blk'); if (dot) dot.style.background = 'var(--bad)'; }
  else { el.classList.add('off'); if (dot) dot.style.background = 'var(--muted)'; }
}

  const anims = new WeakMap();
  function animateWidth(el, pct, ms=420){
    if (!el) return;
    const target = clamp01(pct) * 100;
    const start = parseFloat(el.style.width) || 0;
    if (Math.abs(target - start) < 0.4){ el.style.width = target + '%'; return; }
    const prev = anims.get(el); if (prev?.raf) cancelAnimationFrame(prev.raf);
    const t0 = performance.now();
    function step(t){
      const k = Math.min(1, (t - t0) / ms);
      const v = start + (target - start) * (1 - Math.pow(1 - k, 3));
      el.style.width = v + '%';
      if (k < 1){ const raf = requestAnimationFrame(step); anims.set(el, { raf }); }
    }
    const raf = requestAnimationFrame(step); anims.set(el, { raf });
  }
  function setBar(el, pct, flavor, pctLabelEl){
    if (!el) return;
    el.classList.remove('green','warn','bad');
    if (flavor) el.classList.add(flavor);
    animateWidth(el, pct);
    if (pctLabelEl) setText(pctLabelEl, `${Math.round(clamp01(pct)*100)}%`);
  }

  const TOKEN = document.querySelector('meta[name="user-token"]')?.content || window.USER_LINK_TOKEN || '';
  const API   = TOKEN ? `/api/u/${TOKEN}` : '';

  async function getPeer(signal){
    const r = await fetch(API, { cache:'no-store', signal });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }

  const state = { ttl:null, ttlOrigin:null, unlimited:false, limitMiB:0, usedMiB:0 };

  function applyStatic(j){
    setText('#name', j.name || '—');
    setStatus($('#status'), j.status);
    setText('#address', j.address || '—');
    setText('#endpoint', (j.endpoint||'').trim() || '—');

    const dl = $('#dl');
    if (dl && !dl.dataset.bound){ dl.href = `${API}/config`; dl.dataset.bound='1'; }

    const copy = $('#copy-config');
    if (copy && !copy.dataset.bound){
      copy.addEventListener('click', async () => {
        try{
          const r = await fetch(`${API}/config`, { cache:'no-store' });
          const t = await r.text();
          await navigator.clipboard.writeText(t);
          toast('Config copied');
        }catch{ toast('Copy failed','err'); }
      }, { once:true });
      copy.dataset.bound='1';
    }
  }

function pick(...sels){
  for (const s of sels){
    const el = document.querySelector(s);
    if (el) return el;
  }
  return null;
}


const nowSec   = () => Math.floor(Date.now() / 1000);
function unitToMiB(amount, unit) {
  const u = String(unit || '').toLowerCase();
  const n = Number(amount) || 0;
  if (n <= 0) return 0;
  return u.startsWith('gi') ? n * 1024 : n;  
}

function computeTTL(j) {
  if (Number.isFinite(j?.ttl_seconds)) return Math.max(0, Number(j.ttl_seconds));
  const ts = Number(j?.expires_at_ts) ||
             (j?.expires_at ? Math.floor(new Date(j.expires_at).getTime()/1000) : 0);
  return ts ? Math.max(0, ts - nowSec()) : null;   
}

function num(v){ return Number(v) || 0; }
function tsAny(j, keys){
  for (const k of keys){
    if (j[k] != null){
      const v = j[k];
      if (typeof v === 'number') return Math.floor(v);
      const t = Date.parse(v);
      if (!Number.isNaN(t)) return Math.floor(t/1000);
    }
  }
  return null;
}

function computeSeconds(j){
  const sec =
    num(j.time_limit_seconds) || num(j.timer_seconds) ||
    num(j.duration_seconds)   || num(j.max_age_seconds);
  if (sec > 0) return sec;

  const days = num(j.time_limit_days) || num(j.valid_days);
  if (days > 0) return days * 86400;

  const exp = tsAny(j, ['expires_at_ts','expires_at']);
  if (!exp) return null;

  const start = tsAny(j, [
    'first_used_at_ts','first_used_at','first_used',
    'start_at','started_at',
    'created_at_ts','created_at','added_at'
  ]);
  if (start && exp > start) return exp - start;

  return null;
}

function setBar(el, pct01, flavor, pctLabelEl) {
  if (!el) return;
  el.classList.remove('green', 'warn', 'bad');
  if (flavor) el.classList.add(flavor);
  const pct = clamp01(pct01) * 100;
  el.style.width = pct + '%';
  if (pctLabelEl) pctLabelEl.textContent = Math.round(pct) + '%';
}

function applyData(j, first) {
  const unlimited = !!j.unlimited;
  const limitMiB  = unlimited ? Infinity : unitToMiB(j.data_limit, j.limit_unit || j.unit);

  const usedEff = (j.used_effective_bytes ??
                  ((j.used_bytes || 0) + (j.used_bytes_db || 0)) ??
                   (j.used_bytes || 0));
  const usedMiB = (Number(usedEff) || 0) / 1048576;
  const remainingMiB = unlimited ? Infinity : Math.max(0, limitMiB - usedMiB);

  const statusStr = String(j.status || '').toLowerCase();
  const isBlocked = !unlimited && statusStr === 'blocked' && isFinite(limitMiB) && limitMiB > 0;

  const $left  = document.querySelector('#data-left');
  const $limit = document.querySelector('#limit-human');
  const $used  = document.querySelector('#used-human');

  if ($limit) {
    if (unlimited) $limit.textContent = 'Unlimited';
    else $limit.textContent =
      `Limit ${limitMiB >= 1024
        ? ((limitMiB/1024).toFixed(2).replace(/\.0+$/,'') + ' GiB')
        : (Math.round(limitMiB) + ' MiB')}`;
  }

  if (isBlocked) {
    if ($left) $left.textContent = '0 MiB';
    if ($used) $used.textContent =
      limitMiB >= 1024 ? ((limitMiB/1024).toFixed(2).replace(/\.0+$/,'') + ' GiB')
                       : (Math.round(limitMiB) + ' MiB');
  } else {
    if ($left) $left.textContent = unlimited ? 'Unlimited'
      : (remainingMiB >= 1024 ? ((remainingMiB/1024).toFixed(2).replace(/\.0+$/,'') + ' GiB')
                              : (Math.max(0, Math.round(remainingMiB)) + ' MiB'));
    if ($used) $used.textContent = unlimited ? ''
      : (usedMiB >= 1024 ? ((usedMiB/1024).toFixed(2).replace(/\.0+$/,'') + ' GiB')
                         : (Math.round(usedMiB) + ' MiB'));
  }

  const $usageBar = document.querySelector('#usage-bar');
  const $dataPct  = document.querySelector('#data-pct');
  if (unlimited) {
    setBar($usageBar, 1, 'green', $dataPct);
  } else if (isBlocked) {
    setBar($usageBar, 0, 'bad', $dataPct);
  } else {
    const pctRemain = limitMiB ? (remainingMiB / limitMiB) : 0;
    const flavor = pctRemain < 0.15 ? 'bad' : (pctRemain < 0.45 ? 'warn' : 'green');
    setBar($usageBar, pctRemain, flavor, $dataPct);
  }

  state.unlimited = unlimited;
  state.ttl    = computeTTL(j);          
  state.capSec = computeSeconds(j);   

  const $timeBar  = document.querySelector('#time-bar');
  const $timePct  = document.querySelector('#time-pct');
  const $leftTime = document.querySelector('#time-left');
  const $expires  = document.querySelector('#expires-at');

  let expTs = Number(j.expires_at_ts) || null;
  if (!expTs && Number.isFinite(state.ttl)) expTs = nowSec() + state.ttl;

  const writeLeft = (sec) => {
    sec = Math.max(0, Math.floor(sec || 0));
    const d = Math.floor(sec/86400), h = Math.floor((sec%86400)/3600), m = Math.floor((sec%3600)/60);
    return d>0 ? `${d}d ${h}h` : (h>0 ? `${h}h ${m}m` : `${m}m`);
  };

  if (state.ttl == null) {
    if ($leftTime) $leftTime.textContent = '—';
    if ($expires)  $expires.textContent  = 'No expiry';
    setBar($timeBar, 1, 'green', $timePct);
    state.ttlOrigin = null;
    return;
  }

  if (state.capSec && state.capSec > 0) {
    const pctRemainTime = Math.max(0, Math.min(1, state.ttl / state.capSec));
    const tFlavor = state.ttl === 0 ? 'bad' : (state.ttl < 3600 ? 'bad' : (state.ttl < 21600 ? 'warn' : 'green'));
    if ($leftTime) $leftTime.textContent = writeLeft(state.ttl);
    if ($expires)  $expires.textContent  = expTs
      ? `Expires ${new Date(expTs*1000).toISOString().slice(0,16).replace('T',' ')}`
      : 'Expires —';
    setBar($timeBar, pctRemainTime, tFlavor, $timePct);
  } else {

    if (first || state.ttlOrigin == null || state.ttl > state.ttlOrigin) {
      state.ttlOrigin = Math.max(state.ttl, 1);
    }
    const pct = Math.max(0, Math.min(1, state.ttl / Math.max(state.ttlOrigin, 1)));
    const tFlavor = state.ttl === 0 ? 'bad' : (state.ttl < 3600 ? 'bad' : (state.ttl < 21600 ? 'warn' : 'green'));
    if ($leftTime) $leftTime.textContent = writeLeft(state.ttl);
    if ($expires)  $expires.textContent  = expTs
      ? `Expires ${new Date(expTs*1000).toISOString().slice(0,16).replace('T',' ')}`
      : 'Expires —';
    setBar($timeBar, pct, tFlavor, $timePct);
  }
}

  function startCount(){
  let last = performance.now();
  function tick(now){
    const dt = Math.floor((now - last)/1000);
    if (dt >= 1){
      last = now;
      if (state.ttl != null && !state.unlimited){
        state.ttl = Math.max(0, state.ttl - dt);

        const timeBar   = pick('#time-bar',  '.time .bar .fill', '[data-role="time-bar"]');
        const timePctEl = pick('#time-pct',  '.time .pct',       '[data-role="time-pct"]');
        const timeLeft  = pick('#time-left', '.time .value',     '[data-field="time-left"]');

        if (state.ttl === 0){
          if (timeLeft) timeLeft.textContent = 'expired';
          setBar(timeBar, 0, 'bad', timePctEl);
        } else {
  let pct;
  if (state.capSec && state.capSec > 0) {

    pct = clamp01(state.ttl / state.capSec);
  } else {

    if (state.ttlOrigin == null || state.ttl > state.ttlOrigin) {
      state.ttlOrigin = Math.max(state.ttl, 1);
    }
    pct = clamp01(state.ttl / Math.max(state.ttlOrigin, 1));
  }
  const flavor = state.ttl < 3600 ? 'bad' : state.ttl < 21600 ? 'warn' : 'green';
  if (timeLeft) timeLeft.textContent = fmtTime(state.ttl);
  setBar(timeBar, pct, flavor, timePctEl);
  }

      }
    }
    requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

  let qrDone = false;
  async function renderQR(){
    if (qrDone) return;
    const host = $('#qr'); if (!host) return;
    try{
      const cfg = await fetch(`${API}/config`, { cache:'no-store' }).then(r => r.text());
      if (window.QRCode){
        host.innerHTML = '';
        new QRCode(host, { text: cfg, width: 220, height: 220, correctLevel: QRCode.CorrectLevel.M });
        qrDone = true;
      } else {
        host.textContent = 'QR unavailable';
      }
    }catch{ host.textContent = 'QR unavailable'; }
  }

  let baseMs = 15000, backoff = 0, timer = null;
  function schedule(ms){ clearTimeout(timer); if (document.hidden) return; timer = setTimeout(poll, ms); }
  function ok(){ backoff = 0; schedule(baseMs + Math.floor(Math.random()*1000)); }
  function fail(){ backoff = Math.min(backoff+1, 5); schedule(Math.min(baseMs*Math.pow(1.7, backoff), 60000)); }

  async function poll(){
    const ctrl = new AbortController(); const killer = setTimeout(() => ctrl.abort(), 6000);
    try{
      const j = await getPeer(ctrl.signal);
      applyStatic(j);
      applyData(j, false);
      ok();
    } catch(e){
      if (backoff === 0) console.warn('refresh failed:', e?.message || e);
      fail();
    } finally { clearTimeout(killer); }
  }
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) schedule(500); else clearTimeout(timer);
  });

  document.addEventListener('DOMContentLoaded', async () => {
    loadTheme();
    $('#theme-toggle')?.addEventListener('click', toggleTheme);

    if (!API){ toast('Missing token','err'); return; }

    const ctrl = new AbortController(); const killer = setTimeout(() => ctrl.abort(), 8000);
    try{
      const j = await getPeer(ctrl.signal);
      $$('.skeleton, .skeleton-qr').forEach(el => el.classList.remove('skeleton','skeleton-qr'));
      applyStatic(j);
      applyData(j, true);
      await renderQR();
      startCount();
      ok();
    } catch(e){
      console.error(e);
      toast('Failed to load','err');
    } finally { clearTimeout(killer); }
  });
  function rendSocials(slot, socials){
  const S = socials || {};
  const items = [];
  if (S.telegram)  items.push({href:`https://t.me/${S.telegram.replace('@','')}`, icon:'fab fa-telegram',  label:S.telegram});
  if (S.whatsapp)  items.push({href: S.whatsapp.startsWith('http')?S.whatsapp:`https://wa.me/${S.whatsapp.replace(/\D+/g,'')}`, icon:'fab fa-whatsapp', label:'WhatsApp'});
  if (S.instagram) items.push({href:S.instagram, icon:'fab fa-instagram', label:'Instagram'});
  if (S.website)   items.push({href:S.website, icon:'fas fa-globe', label:'Website'});
  if (S.email)     items.push({href:`mailto:${S.email}`, icon:'fas fa-envelope', label:S.email});
  if (S.phone)     items.push({href:`tel:${S.phone}`, icon:'fas fa-phone', label:S.phone});

  slot.innerHTML = items.map(x => 
    `<a class="ulc-chip" target="_blank" rel="noopener" href="${x.href}">
       <i class="${x.icon}"></i><span>${x.label}</span>
     </a>`).join('');
}
document.addEventListener('DOMContentLoaded', () => {
  const slot = document.getElementById('ulc-support-slot') || document.getElementById('ulm-support-slot');
  if (slot && window.SOCIALS) rendSocials(slot, window.SOCIALS);
});

})();

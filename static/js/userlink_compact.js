(() => {
  const safeStore = {
    get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
    set: (k, v) => { try { localStorage.setItem(k, v); } catch {} }
  };
  const $  = (sel, r=document) => r.querySelector(sel);
  const $$ = (sel, r=document) => [...r.querySelectorAll(sel)];
  const sleep   = (ms) => new Promise(r => setTimeout(r, ms));
  const clamp01 = (x) => Math.max(0, Math.min(1, x));

  function toast(msg, type="ok", ms=2500){
    const host = $("#toast-container") || (() => {
      const d = document.createElement("div"); d.id = "toast-container";
      document.body.appendChild(d); return d;
    })();
    const t = document.createElement("div");
    t.className = `toast ${type==="error"||type==="err"?"err":"ok"}`;
    t.textContent = msg; host.appendChild(t);
    setTimeout(() => { t.style.opacity="0"; t.style.transform="translateY(-4px)"; t.style.transition="all .2s"; }, ms-220);
    setTimeout(() => t.remove(), ms);
  }

  const bytesToMiB = (b) => (Number(b) || 0) / 1048576;
  function fmtAmountFromMiB(mib){
    if (!isFinite(mib)) return "Unlimited";
    if (mib >= 1024) {
      const g = mib/1024, s = g >= 10 ? g.toFixed(1) : g.toFixed(2);
      return `${Number(s)} GiB`;
    }
    return `${Math.round(Math.max(0,mib))} MiB`;
  }
  const pad2 = n => String(n).padStart(2,'0');
  function isoFromTs(ts){
    if (!ts && ts !== 0) return "—";
    const d = new Date(ts*1000);
    return `${d.getFullYear()}-${pad2(d.getMonth()+1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  }
  function fmtTimeLeft(s){
    s = Math.max(0, Math.floor(s||0));
    const d = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60);
    if (d>0) return `${d}d ${h}h`;
    if (h>0) return `${h}h ${m}m`;
    return `${m}m`;
  }

  function applyStatus(el, status){
    el.textContent = status ? status.charAt(0).toUpperCase()+status.slice(1) : "—";
    el.classList.remove("ok","off","block");
    if (status==="online") el.classList.add("ok");
    else if (status==="blocked") el.classList.add("block");
    else el.classList.add("off");
  }

  function setRadial(el, pct, color){
    if (!el) return;
    el.style.setProperty("--pct", Math.max(0, Math.min(1, pct)));
    if (color) el.style.setProperty("--clr", color);
    const v = el.querySelector(".value"); if (v) v.style.color = "var(--text)";
    const lb= el.querySelector(".label"); if (lb) lb.style.color = "var(--muted)";
  }

  function loadTheme(){
    const saved = safeStore.get("theme");
    document.documentElement.dataset.theme = saved==="light" ? "" : "dark";
    syncThemeIcon();
    refreshLiveBgTheme();
  }
  function toggleTheme(){
    const isDark = document.documentElement.dataset.theme === "dark";
    document.documentElement.dataset.theme = isDark ? "" : "dark";
    safeStore.set("theme", isDark ? "light" : "dark");
    syncThemeIcon();
    ["#ulc-time-gauge","#ulc-data-gauge"].forEach(sel=>{
      const g = $(sel); if (!g) return;
      const pct = parseFloat(g.style.getPropertyValue("--pct")||"0")||0;
      setRadial(g, pct, null);
      refreshLiveBgTheme();
    });
  }
  function syncThemeIcon(){
    const btn = $("#ulc-theme"); if (!btn) return;
    const i = btn.querySelector("i");
    const dark = document.documentElement.dataset.theme === "dark";
    if (i) i.className = dark ? "fas fa-sun" : "fas fa-moon";
    btn.title = dark ? "Switch to light" : "Switch to dark";
  }

  function renderSocials(slot, socials){
    const S = socials || {};
    const items = [];
    if (S.telegram)  items.push({href:`https://t.me/${S.telegram.replace('@','')}`, icon:'fab fa-telegram', label:S.telegram});
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

  function injectSupport(){
    const tg = (window.SUPPORT_TG||"").trim();
    const slot = $("#ulc-support-slot");
    if (!slot || !tg) return;
    const a = document.createElement("a");
    a.className = "ulc-chip";
    a.href = `https://t.me/${tg.replace('@','')}`;
    a.target = "_blank";
    a.innerHTML = `<i class="fab fa-telegram"></i><span>${tg}</span>`;
    slot.appendChild(a);
  }

  let qr;
  function renderQR(text){
    const box = $("#ulc-qr"); if (!box) return;
    box.innerHTML = "";
    try {
      qr = new QRCode(box, { text, width:200, height:200, correctLevel: QRCode.CorrectLevel.M });
    } catch {
      box.textContent = "QR unavailable";
    }
  }

  const token =
    (window.USER_LINK_TOKEN || (location.pathname.match(/\/u\/([^\/?#]+)/)||[])[1] || "").trim();
  const API = token ? `/api/u/${token}` : "";

  const state = {
    ttl: null,
    ttl_origin: null,
    expires_at_ts: null,
    limit_mib: null,
    used_mib: null,
    unlimited: false,
    capSec: null, 
  };

  async function userPeer(){
    if (!API) return null;
    const r = await fetch(API, { credentials:"same-origin", cache:"no-store" });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }

  const nowSec = () => Math.floor(Date.now()/1000);
  function parseTs(v){
    if (v == null) return null;
    if (typeof v === 'number') return v > 1e12 ? Math.floor(v/1000) : Math.floor(v);
    const d = new Date(String(v));
    return isNaN(d) ? null : Math.floor(d.getTime()/1000);
  }

  function applyData(j){
    $("#ulc-name").textContent = j.name || "—";
    applyStatus($("#ulc-status"), j.status);
    $("#ulc-address").textContent = j.address || "—";
    $("#ulc-endpoint").textContent = (j.endpoint||"").trim() || "—";

    const dl = $("#ulc-download"); if (dl) dl.href = `${API}/config`;
    $("#ulc-copy")?.addEventListener("click", async () => {
      try {
        const r = await fetch(`${API}/config`); const t = await r.text();
        await navigator.clipboard.writeText(t); toast("Config copied");
      } catch { toast("Copy failed","error"); }
    }, { once:true });

    renderQR(`${window.location.origin}${API}/config`);

    state.unlimited = !!j.unlimited;
    let limMiB = Infinity;
    if (!state.unlimited) {
      const unit = String(j.limit_unit || j.unit || '').toLowerCase(); 
      const raw  = Number(j.data_limit) || 0;
      if (raw > 0) {
        limMiB = unit.startsWith('gi') ? raw * 1024 : raw;
      } else {
        const bytesLim = Number(j.data_limit_bytes || j.limit_bytes) || 0;
        if (bytesLim > 0) limMiB = bytesLim / 1048576;
        else {
          const limMibField = Number(j.limit_mib || 0);
          limMiB = limMibField > 0 ? limMibField : 0;
        }
      }
    }

    const usedEffBytes =
        (j.used_effective_bytes ??
         ((Number(j.used_bytes) || 0) + (Number(j.used_bytes_db) || 0)) ??
         (Number(j.used_bytes) || 0));
    let usedMiB = bytesToMiB(usedEffBytes);

    let leftMiB = state.unlimited ? Infinity : Math.max(0, limMiB - usedMiB);

    const isBlocked = String(j.status||'').toLowerCase() === 'blocked';
    if (!state.unlimited && isFinite(limMiB) && limMiB > 0 && isBlocked) {
      usedMiB = limMiB;
      leftMiB = 0;
    }

    state.limit_mib = state.unlimited ? Infinity : limMiB;
    state.used_mib  = usedMiB;

    $("#ulc-data-left").textContent = fmtAmountFromMiB(leftMiB);
    $("#ulc-limit-sub").textContent = state.unlimited
      ? "Limit — Unlimited"
      : `Limit ${fmtAmountFromMiB(state.limit_mib)}`;

    const dataGauge = $("#ulc-data-gauge");
    if (state.unlimited) {
      setRadial(dataGauge, 1, "var(--accent-2)");
      const dv  = dataGauge.querySelector(".value"); if (dv)  dv.textContent  = "∞";
      const dlb = dataGauge.querySelector(".label"); if (dlb) dlb.textContent = "Unlimited";
    } else {
      const pctRemain = clamp01(state.limit_mib ? leftMiB/state.limit_mib : 0);
      const color = pctRemain < 0.15 ? "var(--danger)"
                  : pctRemain < 0.45 ? "var(--accent-3)"
                  :                      "var(--accent-2)";
      setRadial(dataGauge, pctRemain, color);
      const dv  = dataGauge.querySelector(".value"); if (dv)  dv.textContent  = fmtAmountFromMiB(leftMiB);
      const dlb = dataGauge.querySelector(".label"); if (dlb) dlb.textContent = "Remaining";
    }

    const expTs = parseTs(j.expires_at_ts ?? j.expires_at ?? null);
    let ttl = Number(j.ttl_seconds);
    if (!Number.isFinite(ttl)) ttl = expTs != null ? Math.max(0, expTs - nowSec()) : null;

    state.expires_at_ts = expTs;
    state.ttl = ttl;
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


    const timeGauge = $("#ulc-time-gauge");
    if (state.unlimited || state.ttl == null) {
      timeGauge.querySelector(".value").textContent = "—";
      timeGauge.querySelector(".label").textContent = "No expiry";
      $("#ulc-exp-sub").textContent = "No expiry";
      setRadial(timeGauge, 1, "var(--accent)");
      state.ttl_origin = null;
    } else {
      $("#ulc-exp-sub").textContent = expTs ? `Expires ${isoFromTs(expTs)}` : "Expires —";
      timeGauge.querySelector(".value").textContent = fmtTimeLeft(state.ttl);
      timeGauge.querySelector(".label").textContent = "Time left";

      const cap = Math.max(state.capSec || 0, 1);
      const pctRemain = clamp01(state.ttl / cap);

      const color = state.ttl === 0 ? "var(--danger)"
                  : state.ttl < 3600 ? "var(--danger)"
                  : state.ttl < 6*3600 ? "var(--accent-3)"
                  :                       "var(--accent)";
      setRadial(timeGauge, pctRemain, color);
    }
  }

  function startCountdown(){
    let last = Date.now();
    const tick = () => {
      const now = Date.now();
      const dt = Math.floor((now - last)/1000);
      if (dt >= 1) {
        last = now;
        if (state.ttl != null && !state.unlimited) {
          state.ttl = Math.max(0, state.ttl - dt);
          const g = $("#ulc-time-gauge");
          const v = g.querySelector(".value");
          if (v) v.textContent = state.ttl ? fmtTimeLeft(state.ttl) : "expired";
          const cap = Math.max(state.capSec || state.ttl || 1, 1);
          const pct = clamp01(state.ttl / cap);

          const color = state.ttl === 0 ? "var(--danger)"
                      : state.ttl < 3600 ? "var(--danger)"
                      : state.ttl < 6*3600 ? "var(--accent-3)"
                      :                       "var(--accent)";
          setRadial(g, pct, color);
        }
      }
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  async function autoRefresh(){
    while (true) {
      try { const j = await userPeer(); applyData(j); } catch {}
      await sleep(15000);
    }
  }

  document.addEventListener("DOMContentLoaded", async () => {
    loadTheme();
    initLiveBg();
    $("#ulc-theme")?.addEventListener("click", toggleTheme);

    injectSupport();
    const slot = $("#ulc-support-slot");
    if (slot && window.SOCIALS) renderSocials(slot, window.SOCIALS);

    if (!API) { toast("Missing token","error"); return; }

    ["#ulc-time-gauge","#ulc-data-gauge"].forEach(sel => {
      const g = $(sel);
      if (g && !g.querySelector(".center")) {
        const c = document.createElement("div");
        c.className = "center";
        c.innerHTML = '<div class="value">—</div><div class="label">—</div>';
        const ring = document.createElement("div"); ring.className = "ring";
        g.appendChild(ring); g.appendChild(c);
      }
    });

    try {
      const j = await userPeer();
      applyData(j);
      startCountdown();
      autoRefresh();
    } catch {
      toast("Failed to load peer","error");
    }
  });

function isDark(){ return document.documentElement.dataset.theme === 'dark'; }

function bgColorVars(){
  const get = (name, fallback) => getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
  return {
    a: get('--accent',  '#6366f1'),
    b: get('--accent-2','#22c55e'),
    track: get('--track','#e8ebf3')
  };
}

let __bg = { ctx:null, cvs:null, pts:[], raf:0, lastW:0, lastH:0, start:null, stop:null, resize:null };

function initLiveBg(){
  const cvs = document.getElementById('ulc-bg');
  if (!cvs) return;
  const ctx = cvs.getContext('2d', { alpha:true });
  __bg.cvs = cvs; __bg.ctx = ctx;

  function resize(){
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = cvs.clientWidth | 0, h = cvs.clientHeight | 0;
    if (w === __bg.lastW && h === __bg.lastH) return;
    __bg.lastW = w; __bg.lastH = h;
    cvs.width = Math.max(1, w * dpr);
    cvs.height = Math.max(1, h * dpr);
    ctx.setTransform(dpr,0,0,dpr,0,0);
    spawn();
  }

  function spawn(){
    const N = Math.max(36, Math.min(64, Math.floor((__bg.lastW*__bg.lastH)/50000)));
    const { a, b } = bgColorVars();
    __bg.pts = Array.from({length:N}, (_,i) => {
      const speed = 0.2 + Math.random()*0.8;
      return {
        x: Math.random()*__bg.lastW,
        y: Math.random()*__bg.lastH,
        vx:(Math.random()*2-1)*speed,
        vy:(Math.random()*2-1)*speed,
        r: 1.1 + Math.random()*1.8,
        c: i%3===0 ? a : b
      };
    });
  }

  function step(){
  const W = __bg.lastW, H = __bg.lastH;
  const { track } = bgColorVars();
  ctx.clearRect(0,0,W,H);
  ctx.fillStyle = track;
  ctx.globalAlpha = isDark() ? 0.14 : 0.06;
  ctx.fillRect(0,0,W,H);
  ctx.globalAlpha = 1;

  ctx.globalCompositeOperation = isDark() ? 'lighter' : 'source-over';

  for (const p of __bg.pts){
    p.x += p.vx; p.y += p.vy;
    if (p.x < -10 || p.x > W+10) p.vx *= -1;
    if (p.y < -10 || p.y > H+10) p.vy *= -1;

    ctx.beginPath();
    ctx.fillStyle = p.c;
    ctx.globalAlpha = isDark() ? 0.26 : 0.14;
    ctx.arc(p.x, p.y, p.r * 4, 0, Math.PI * 2);
    ctx.fill();

    ctx.beginPath();
    ctx.globalAlpha = isDark() ? 0.65 : 0.35;
    ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
    ctx.fill();

    ctx.globalAlpha = 1;
  }

  ctx.lineWidth = 1;
  for (let i = 0; i < __bg.pts.length; i++){
    const p = __bg.pts[i];
    for (let j = i + 1; j < __bg.pts.length; j++){
      const q = __bg.pts[j];
      const dx = p.x - q.x, dy = p.y - q.y;
      const d2 = dx*dx + dy*dy;
      if (d2 < 110*110){
        const a = 1 - Math.sqrt(d2) / 110;
        const base = isDark() ? 0.30 : 0.14;
        ctx.strokeStyle = 'rgba(148,163,184,' + (base * a) + ')';
        ctx.beginPath();
        ctx.moveTo(p.x, p.y); ctx.lineTo(q.x, q.y); ctx.stroke();
      }
    }
  }

  ctx.globalCompositeOperation = 'source-over';

  __bg.raf = requestAnimationFrame(step);
}

  function start(){ stop(); resize(); step(); }
  function stop(){ if (__bg.raf) cancelAnimationFrame(__bg.raf); __bg.raf = 0; }

  __bg.start = start; __bg.stop = stop; __bg.resize = resize;

  window.addEventListener('resize', resize);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) stop(); else start();
  });

  start();
}

function refreshLiveBgTheme(){
  if (!__bg.ctx) return;
  __bg.resize();
  __bg.start && __bg.start();
}


})();

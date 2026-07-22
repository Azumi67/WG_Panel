(() => {
  'use strict';

  const IS_PREVIEW = new URLSearchParams(location.search).has('embed');
  const TOKEN = (window.USER_LINK_TOKEN || document.querySelector('meta[name="user-token"]')?.content || '').trim();
  const API = TOKEN ? `/api/u/${TOKEN}` : '';
  const REFRESH_MS = 15000;
  const $ = (id) => document.getElementById(id);
  const clamp = (n, min = 0, max = 1) => Math.max(min, Math.min(max, n));
  const nowSec = () => Math.floor(Date.now() / 1000);
  const state = { ttl: null, cap: null, unlimited: false, timer: null, poll: null, config: '' };

  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch {} }
  };

  function parseTs(value) {
    if (value == null || value === '') return null;
    if (typeof value === 'number') return value > 1e12 ? Math.floor(value / 1000) : Math.floor(value);
    if (/^\d{10,13}$/.test(String(value))) {
      const n = Number(value);
      return n > 1e12 ? Math.floor(n / 1000) : Math.floor(n);
    }
    const d = new Date(String(value));
    return Number.isNaN(d.getTime()) ? null : Math.floor(d.getTime() / 1000);
  }

  function firstTs(obj, keys) {
    for (const key of keys) {
      const ts = parseTs(obj?.[key]);
      if (ts) return ts;
    }
    return null;
  }

  function formatDate(ts) {
    if (!ts) return '—';
    return new Intl.DateTimeFormat(undefined, {
      year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit'
    }).format(new Date(ts * 1000));
  }

  function formatDuration(seconds) {
    seconds = Math.max(0, Math.floor(Number(seconds) || 0));
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d) return `${d}d ${h}h`;
    if (h) return `${h}h ${m}m`;
    return `${m}m`;
  }

  function bytesToHuman(bytes) {
    const b = Math.max(0, Number(bytes) || 0);
    const mib = b / 1048576;
    if (mib >= 1024) return `${trim(mib / 1024, 2)} GiB`;
    return `${trim(mib, mib < 10 ? 2 : 0)} MiB`;
  }

  function limitToBytes(value, unit) {
    const n = Math.max(0, Number(value) || 0);
    const u = String(unit || '').toLowerCase();
    return n * (u.startsWith('gi') || u.startsWith('g') ? 1073741824 : 1048576);
  }

  function trim(n, digits = 1) {
    return Number(n.toFixed(digits)).toString();
  }

  function setText(id, value) {
    const el = $(id);
    if (el) el.textContent = value == null || value === '' ? '—' : String(value);
  }

  function setStatus(status) {
    const el = $('peer-status');
    if (!el) return;
    const raw = String(status || 'offline').toLowerCase();
    const label = raw === 'online' ? 'Online' : raw === 'blocked' ? 'Blocked' : raw === 'offline' ? 'Offline' : raw;
    el.className = `status-pill ${raw === 'online' ? 'online' : raw === 'blocked' ? 'blocked' : 'offline'}`;
    const labelEl = $('peer-status-label');
    if (labelEl) labelEl.textContent = label.charAt(0).toUpperCase() + label.slice(1);
  }

  function setMeter(id, pct, tone = '') {
    const bar = $(id);
    if (!bar) return;
    bar.className = `meter-fill ${tone}`.trim();
    bar.style.width = `${Math.round(clamp(pct) * 100)}%`;
  }

  function toneFor(pct) {
    return pct <= .12 ? 'danger' : pct <= .35 ? 'warning' : 'healthy';
  }

  function renderTags(id, raw, emptyLabel = 'Not set') {
    const host = $(id);
    if (!host) return;
    const values = Array.isArray(raw)
      ? raw
      : String(raw || '').split(',').map(v => v.trim()).filter(Boolean);
    host.innerHTML = '';
    if (!values.length) {
      const span = document.createElement('span');
      span.className = 'route-tag muted-tag';
      span.textContent = emptyLabel;
      host.appendChild(span);
      return;
    }
    for (const value of [...new Set(values)]) {
      const span = document.createElement('span');
      span.className = 'route-tag';
      span.textContent = value;
      host.appendChild(span);
    }
  }

  function toast(message, type = 'ok') {
    const host = $('toast-container') || document.body;
    const item = document.createElement('div');
    item.className = `toast ${type}`;
    item.innerHTML = `<i class="fas ${type === 'error' ? 'fa-triangle-exclamation' : 'fa-circle-check'}"></i><span></span>`;
    item.querySelector('span').textContent = message;
    host.appendChild(item);
    requestAnimationFrame(() => item.classList.add('show'));
    setTimeout(() => {
      item.classList.remove('show');
      setTimeout(() => item.remove(), 250);
    }, 2200);
  }

  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    store.set('wg-user-theme', theme);
    const icon = $('theme-toggle')?.querySelector('i');
    if (icon) icon.className = `fas ${theme === 'dark' ? 'fa-sun' : 'fa-moon'}`;
  }

  function initTheme() {
    const saved = store.get('wg-user-theme');
    const preferred = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    setTheme(saved || preferred);
    $('theme-toggle')?.addEventListener('click', () => {
      setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
    });
  }

  function supportLink(kind, value) {
    const clean = String(value || '').trim();
    if (!clean) return null;
    const map = {
      telegram: [`https://t.me/${clean.replace('@', '')}`, 'fab fa-telegram', clean],
      whatsapp: [clean.startsWith('http') ? clean : `https://wa.me/${clean.replace(/\D/g, '')}`, 'fab fa-whatsapp', 'WhatsApp'],
      instagram: [clean.startsWith('http') ? clean : `https://instagram.com/${clean.replace('@', '')}`, 'fab fa-instagram', 'Instagram'],
      website: [clean.startsWith('http') ? clean : `https://${clean}`, 'fas fa-globe', 'Website'],
      email: [`mailto:${clean}`, 'fas fa-envelope', clean],
      phone: [`tel:${clean.replace(/\s/g, '')}`, 'fas fa-phone', clean]
    };
    return map[kind];
  }

  function renderSupport() {
    const host = $('support-links');
    if (!host) return;
    host.innerHTML = '';
    const socials = window.SOCIALS || {};
    for (const key of ['telegram', 'whatsapp', 'instagram', 'website', 'email', 'phone']) {
      const data = supportLink(key, socials[key]);
      if (!data) continue;
      const a = document.createElement('a');
      a.className = 'support-chip';
      a.href = data[0];
      a.target = data[0].startsWith('http') ? '_blank' : '_self';
      a.rel = 'noopener';
      a.innerHTML = `<i class="${data[1]}"></i><span></span>`;
      a.querySelector('span').textContent = data[2];
      host.appendChild(a);
    }
    if (!host.children.length) {
      const empty = document.createElement('span');
      empty.className = 'support-empty';
      empty.textContent = 'No support contacts configured.';
      host.appendChild(empty);
    }
  }

  async function fetchJson(url, signal) {
    const r = await fetch(url, { cache: 'no-store', credentials: 'same-origin', signal });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }

  async function fetchText(url) {
    const r = await fetch(url, { cache: 'no-store', credentials: 'same-origin' });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.text();
  }

  async function ensureConfig() {
    if (state.config) return state.config;
    if (IS_PREVIEW) return '[Interface]\nPrivateKey = preview\nAddress = 10.66.66.2/24';
    state.config = await fetchText(`${API}/config`);
    return state.config;
  }

  async function drawQR() {
    const host = $('config-qr');
    if (!host || host.dataset.ready === '1') return;
    try {
      const text = await ensureConfig();
      host.innerHTML = '';
      new QRCode(host, { text, width: 210, height: 210, correctLevel: QRCode.CorrectLevel.M });
      host.dataset.ready = '1';
      host.setAttribute('aria-busy', 'false');
    } catch {
      host.innerHTML = '<div class="qr-error"><i class="fas fa-triangle-exclamation"></i><span>QR unavailable</span></div>';
    }
  }

  function bindActions() {
    const dl = $('download-config');
    if (dl && !IS_PREVIEW) dl.href = `${API}/config`;
    if (dl && IS_PREVIEW) dl.addEventListener('click', e => e.preventDefault());

    $('copy-config')?.addEventListener('click', async () => {
      try {
        const text = await ensureConfig();
        if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
        else {
          const ta = document.createElement('textarea');
          ta.value = text;
          ta.style.position = 'fixed';
          ta.style.left = '-9999px';
          document.body.appendChild(ta);
          ta.select();
          document.execCommand('copy');
          ta.remove();
        }
        toast('Configuration copied');
      } catch { toast('Copy failed', 'error'); }
    });

    document.querySelectorAll('[data-copy-target]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const target = $(btn.dataset.copyTarget);
        const value = target?.textContent?.trim();
        if (!value || value === '—') return;
        try { await navigator.clipboard.writeText(value); toast('Copied'); }
        catch { toast('Copy failed', 'error'); }
      });
    });
  }

  function demoPayload() {
    const now = nowSec();
    return {
      name: 'azumi-premium', status: 'online', address: '10.66.66.7/24',
      endpoint: 'wireguard.example.com:51820', unlimited: true,
      limit_unit: 'GiB', data_limit: 50, used_effective_bytes: 18.4 * 1073741824,
      first_used_at_ts: now - 7 * 86400, expires_at_ts: now + 23 * 86400,
      ttl_seconds: 23 * 86400, time_limit_days: 30,
      allowed_ips: '0.0.0.0/0, ::/0, 10.66.66.0/24, 10.30.0.0/30',
      dns: '1.1.1.1, 1.0.0.1', mtu: 1420, start_on_first_use: true
    };
  }

  function render(payload) {
    const j = payload || {};
    setText('peer-name', j.name || '—');
    setStatus(j.status);
    setText('peer-address', j.address || '—');
    setText('peer-endpoint', String(j.endpoint || '').trim() || '—');
    renderTags('allowed-ips-list', j.allowed_ips, 'Default route');
    renderTags('dns-list', j.dns, 'System DNS');
    setText('peer-mtu', j.mtu || 'Auto');

    const started = firstTs(j, ['first_used_at_ts', 'first_used_at', 'first_used', 'started_at', 'start_at']);
    const created = firstTs(j, ['created_at_ts', 'created_at', 'added_at']);
    const unlimited = Boolean(j.unlimited);
    if (started) {
      setText('active-since', formatDate(started));
      setText('activation-label', 'Active since');
    } else if (unlimited && created) {
      setText('active-since', formatDate(created));
      setText('activation-label', 'Active since');
    } else if (j.start_on_first_use) {
      setText('active-since', 'Waiting for first connection');
      setText('activation-label', 'Activation');
    } else if (created) {
      setText('active-since', formatDate(created));
      setText('activation-label', 'Created');
    } else {
      setText('active-since', 'Not active yet');
      setText('activation-label', 'Activation');
    }


    state.unlimited = unlimited;
    const usedBytes = Number(j.used_effective_bytes ?? j.used_bytes ?? j.used_bytes_db ?? 0) || 0;
    const limitBytes = unlimited ? Infinity : limitToBytes(j.data_limit ?? j.limit, j.limit_unit ?? j.unit);
    const remaining = unlimited ? Infinity : Math.max(0, limitBytes - usedBytes);
    const dataPct = unlimited ? 1 : limitBytes > 0 ? remaining / limitBytes : 0;

    setText('data-left', unlimited ? 'Unlimited' : bytesToHuman(remaining));
    setText('data-used', `${bytesToHuman(usedBytes)} used`);
    setText('data-limit', unlimited ? 'No data cap' : limitBytes > 0 ? `${bytesToHuman(limitBytes)} total` : 'No data allowance');
    setText('data-pct', unlimited ? '∞' : `${Math.round(clamp(dataPct) * 100)}%`);
    setMeter('data-bar', dataPct, unlimited ? 'infinite' : toneFor(dataPct));

    const expires = firstTs(j, ['expires_at_ts', 'expires_at']);
    let ttl = Number(j.ttl_seconds);
    if (!Number.isFinite(ttl)) ttl = expires ? Math.max(0, expires - nowSec()) : null;
    let cap = Number(j.time_limit_seconds || j.duration_seconds || 0);
    if (!cap) cap = Number(j.time_limit_days || 0) * 86400;
    if (!cap && expires && started && expires > started) cap = expires - started;
    state.ttl = ttl;
    state.cap = cap || (ttl || 1);

    if (unlimited || ttl == null) {
      setText('time-left', unlimited ? 'Unlimited' : 'No expiry');
      setText('time-expiry', unlimited ? 'No time limit' : 'No expiration date');
      setText('time-pct', '∞');
      setMeter('time-bar', 1, 'infinite');
    } else {
      const pct = state.cap > 0 ? ttl / state.cap : 0;
      setText('time-left', ttl <= 0 ? 'Expired' : formatDuration(ttl));
      setText('time-expiry', expires ? `Expires ${formatDate(expires)}` : 'Expiration pending');
      setText('time-pct', `${Math.round(clamp(pct) * 100)}%`);
      setMeter('time-bar', pct, toneFor(pct));
    }
  }

  function startCountdown() {
    clearInterval(state.timer);
    state.timer = setInterval(() => {
      if (state.unlimited || state.ttl == null || state.ttl <= 0) return;
      state.ttl = Math.max(0, state.ttl - 1);
      const pct = state.cap > 0 ? state.ttl / state.cap : 0;
      setText('time-left', state.ttl ? formatDuration(state.ttl) : 'Expired');
      setText('time-pct', `${Math.round(clamp(pct) * 100)}%`);
      setMeter('time-bar', pct, toneFor(pct));
    }, 1000);
  }

  async function load() {
    if (IS_PREVIEW) {
      render(demoPayload());
      await drawQR();
      return;
    }
    if (!API) throw new Error('Missing token');
    const ctrl = new AbortController();
    const timeout = setTimeout(() => ctrl.abort(), 8000);
    try {
      const data = await fetchJson(API, ctrl.signal);
      render(data);
      await drawQR();
    } finally { clearTimeout(timeout); }
  }

  function startPolling() {
    clearInterval(state.poll);
    state.poll = setInterval(() => {
      if (!document.hidden) load().catch(() => {});
    }, REFRESH_MS);
  }

  document.addEventListener('DOMContentLoaded', async () => {
    initTheme();
    renderSupport();
    bindActions();
    try {
      await load();
      document.body.classList.add('data-ready');
      startCountdown();
      startPolling();
    } catch (error) {
      console.error(error);
      document.body.classList.add('data-error');
      toast('Unable to load this access profile', 'error');
    }
  });

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) load().catch(() => {});
  });
})();

(function initPublicLiveBackground(){
  const canvas = document.getElementById('live-background');
  if (!canvas || canvas.dataset.bound === '1') return;
  canvas.dataset.bound = '1';
  const ctx = canvas.getContext('2d', { alpha: true });
  if (!ctx) return;

  const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  let dpr = 1, width = 0, height = 0, particles = [], raf = 0;

  function themeColors(){
    const cs = getComputedStyle(document.documentElement);
    const dark = document.documentElement.getAttribute('data-theme') === 'dark' ||
      (!document.documentElement.getAttribute('data-theme') && window.matchMedia('(prefers-color-scheme: dark)').matches);
    const accent = (cs.getPropertyValue('--accent') || cs.getPropertyValue('--fill-strong') || '#3b82f6').trim();
    const secondary = (cs.getPropertyValue('--good') || cs.getPropertyValue('--accent-2') || '#14b8a6').trim();
    return { dark, accent, secondary };
  }

  function hexRgb(value, fallback){
    const v = String(value || '').trim();
    const short = /^#([0-9a-f]{3})$/i.exec(v);
    if (short) return short[1].split('').map(x => parseInt(x+x,16));
    const full = /^#([0-9a-f]{6})$/i.exec(v);
    if (full) return [parseInt(full[1].slice(0,2),16),parseInt(full[1].slice(2,4),16),parseInt(full[1].slice(4,6),16)];
    const rgb = /rgba?\(\s*(\d+)\D+(\d+)\D+(\d+)/i.exec(v);
    return rgb ? [Number(rgb[1]),Number(rgb[2]),Number(rgb[3])] : fallback;
  }

  function resize(){
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.max(1, Math.floor(width*dpr));
    canvas.height = Math.max(1, Math.floor(height*dpr));
    canvas.style.width = width+'px';
    canvas.style.height = height+'px';
    ctx.setTransform(dpr,0,0,dpr,0,0);
    const count = Math.max(38, Math.min(110, Math.round(width*height/13500)));
    particles = Array.from({length:count}, (_,i)=>({
      x:Math.random()*width, y:Math.random()*height,
      vx:(Math.random()-.5)*(reduced?0:.42), vy:(Math.random()-.5)*(reduced?0:.42),
      r:.8+Math.random()*1.7, group:i%2
    }));
  }

  function frame(){
    const {dark,accent,secondary}=themeColors();
    const a=hexRgb(accent,[59,130,246]);
    const b=hexRgb(secondary,[20,184,166]);
    ctx.clearRect(0,0,width,height);

    const glow=ctx.createRadialGradient(width*.78,height*.08,10,width*.78,height*.08,Math.max(width,height)*.72);
    glow.addColorStop(0,`rgba(${a.join(',')},${dark?.18:.14})`);
    glow.addColorStop(1,'rgba(0,0,0,0)');
    ctx.fillStyle=glow; ctx.fillRect(0,0,width,height);

    for(const p of particles){
      p.x+=p.vx; p.y+=p.vy;
      if(p.x<-12)p.x=width+12; else if(p.x>width+12)p.x=-12;
      if(p.y<-12)p.y=height+12; else if(p.y>height+12)p.y=-12;
      const c=p.group?a:b;
      ctx.beginPath();
      ctx.fillStyle=`rgba(${c.join(',')},${dark?.72:.48})`;
      ctx.arc(p.x,p.y,p.r,0,Math.PI*2); ctx.fill();
    }
    ctx.lineWidth=.8;
    for(let i=0;i<particles.length;i++){
      for(let j=i+1;j<particles.length;j++){
        const p=particles[i],q=particles[j],dx=p.x-q.x,dy=p.y-q.y,d2=dx*dx+dy*dy;
        if(d2<145*145){
          const alpha=(1-Math.sqrt(d2)/145)*(dark?.30:.20);
          ctx.strokeStyle=`rgba(${a.join(',')},${alpha})`;
          ctx.beginPath();ctx.moveTo(p.x,p.y);ctx.lineTo(q.x,q.y);ctx.stroke();
        }
      }
    }
    if(!reduced) raf=requestAnimationFrame(frame);
  }

  function restart(){ if(raf) cancelAnimationFrame(raf); resize(); frame(); }
  window.addEventListener('resize', restart, {passive:true});
  new MutationObserver(restart).observe(document.documentElement,{attributes:true,attributeFilter:['class','data-theme']});
  restart();
})();

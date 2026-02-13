
let cpuChart, memChart, diskChart, netChart;
let pollTimer = null;
let intervalMs = 2000;
let backoff = 0;
let prevNet = { ts: 0, rxMB: 0, txMB: 0 };
function rateTotals(s) {
  const rxMB = s?.net?.rx_total_mb; const txMB = s?.net?.tx_total_mb;
  if (rxMB == null || txMB == null) return null;
  const now = Date.now() / 1000;
  if (!prevNet.ts) { prevNet = { ts: now, rxMB, txMB }; return { rx: 0, tx: 0 }; }
  const dt = Math.max(0.001, now - prevNet.ts);
  const rx = Math.max(0, (rxMB - prevNet.rxMB) / dt);
  const tx = Math.max(0, (txMB - prevNet.txMB) / dt);
  prevNet = { ts: now, rxMB, txMB };
  return { rx: +rx.toFixed(2), tx: +tx.toFixed(2) };
}

function fmtIsoShort(s) {
  if (!s) return '—';
  const d = new Date(s);
  return isNaN(d) ? s : d.toLocaleString();
}
function fmtAgo(d) {
  const s = Math.floor((Date.now() - d.getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60); if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60); if (h < 24) return `${h}h ago`;
  const dys = Math.floor(h / 24); return `${dys}d ago`;
}
function fmtIso(s) {
  if (!s) return '—';
  const d = new Date(s);
  if (isNaN(d)) return s;
  return `${d.toLocaleString()}  (${fmtAgo(d)})`;
}


const $    = (id) => document.getElementById(id);
const bySel = (s, r = document) => r.querySelector(s);

function setBadgeUI(target, tone, text) {
  const el = typeof target === 'string' ? $(target) : target;
  if (!el) return;
  el.className = 'badge ' + tone;
  el.textContent = text;
}
function hideSpinner(id){ const el = $(id); if (el) el.style.display = 'none'; }
function setText(id, t){ const el = $(id); if (el) el.textContent = t; }

function lineChart(ctx) {
  return new Chart(ctx, {
    type: 'line',
    data: {
      labels: Array.from({ length: 30 }, (_, i) => `${-29 + i}s`),
      datasets: [{ data: Array(30).fill(0), fill: false, tension: 0.3 }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { display: false } },
      scales: { x: { display: false }, y: { beginAtZero: true } }
    }
  });
}
function makeChart(ctx) {
  return new Chart(ctx, {
    type: 'line',
    data: {
      labels: Array.from({ length: 30 }, (_, i) => `${-29 + i}s`),
      datasets: [
        {
          label: 'RX (MB/s)',
          data: Array(30).fill(0),
          borderColor: '#3b82f6',
          backgroundColor: 'rgba(59,130,246,.15)',
          tension: 0.3, pointRadius: 2, pointHoverRadius: 3, borderWidth: 2, fill: false
        },
        {
          label: 'TX (MB/s)',
          data: Array(30).fill(0),
          borderColor: '#f472b6',
          backgroundColor: 'rgba(244,114,182,.15)',
          tension: 0.3, pointRadius: 2, pointHoverRadius: 3, borderWidth: 2, fill: false
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { display: false } },  
      scales: { x: { display: false }, y: { beginAtZero: true } }
    }
  });
}
function initCharts() {
  if (!$('cpuChart')) return;
  cpuChart  = lineChart($('cpuChart').getContext('2d'));
  memChart  = lineChart($('memChart').getContext('2d'));
  diskChart = lineChart($('diskChart').getContext('2d'));
  netChart  = makeChart($('netChart').getContext('2d'));
}

function fmtUptime(s) {
  if (s == null) return '—';
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  return `${d}d ${h}h ${m}m`;
}
function fmtBytes(x){
  if (x == null || isNaN(x)) return '—';
  const u = ['B','KB','MB','GB','TB','PB'];
  let i = 0, v = Math.max(0, Number(x));
  while (v >= 1024 && i < u.length - 1){ v /= 1024; i++; }
  return (v < 10 ? v.toFixed(1) : Math.round(v)) + ' ' + u[i];
}
function pushData(chart, v){
  const ds = chart.data.datasets[0].data;
  ds.shift(); ds.push(v ?? 0); chart.update('none');
}
function pushNet(rx, tx){
  const rxData = netChart.data.datasets[0].data;
  const txData = netChart.data.datasets[1].data;
  rxData.shift(); rxData.push(rx ?? 0);
  txData.shift(); txData.push(tx ?? 0);
  netChart.update('none');
}

function statusBadge(id, online, textOn='Online', textOff='Offline') {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = 'badge ' + (online ? 'ok' : 'bad'); 
  el.textContent = online ? textOn : textOff;
}

async function loadAppStat() {
  const r = await fetch('/api/app_status', { credentials: 'same-origin', cache: 'no-store' });
  const j = await r.json();
  const online = (j?.app?.online ?? true);
  statusBadge('app-status', online);
  setText('app-since', fmtIso(j?.app?.since));
}

async function loadTgStatus() {
  const r = await fetch('/api/telegram/status', { credentials: 'same-origin', cache: 'no-store' });
  const j = await r.json();
  const online = !!j?.bot_online;  
  statusBadge('tg-status', online);
  setText('tg-last', fmtIso(j?.last_seen));
}

function updateUtil(){
  document.querySelectorAll('.util[data-util-from]').forEach(el=>{
    const sel = el.getAttribute('data-util-from');
    const vEl = document.querySelector(sel);
    if (!vEl) return;
    const m = String(vEl.textContent || '').match(/([\d.]+)/);
    const pct = m ? Math.max(0, Math.min(100, parseFloat(m[1]))) : 0;
    el.firstElementChild.style.width = pct + '%';
  });
}

const utilRO = new MutationObserver(updateUtil);
const rowRO = new MutationObserver(hideEmpty);

function hideEmpty(){
  document.querySelectorAll('.kv-row').forEach(row=>{
    const v = row.querySelector('.kv-v');
    if (!v) return;
    const txt = (v.textContent || '').trim();
    row.classList.toggle('hidden', txt === '—' || txt === '');
  });
}
async function peerCounts(scope) {
  try {
    const r = await fetch(`/api/peer_counts?scope=${encodeURIComponent(scope)}`, {
      credentials: 'same-origin',
      cache: 'no-store'
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    const c = j.counts || {};
    setText('count-online',  String(c.online  ?? 0));
    setText('count-offline', String(c.offline ?? 0));
    setText('count-blocked', String(c.blocked ?? 0));
  } catch (e) {
    console.error(e);
  }
}

async function updateStats () {
  try {
    const res = await fetch('/api/stats', { credentials: 'same-origin', cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const s = await res.json();

    let rx = s.rx, tx = s.tx;

    if (typeof rateTotals === 'function') {
      const d = rateTotals(s);
      if (d) {
        if (rx == null || rx === 0) rx = d.rx;
        if (tx == null || tx === 0) tx = d.tx;
      }
    } else {
      window.__prevNet ??= { ts: 0, rxMB: 0, txMB: 0 };
      const now = Date.now() / 1000;
      const rxMB = s?.net?.rx_total_mb, txMB = s?.net?.tx_total_mb;
      if (rxMB != null && txMB != null) {
        if (!window.__prevNet.ts) {
          window.__prevNet = { ts: now, rxMB, txMB };
          rx = rx ?? 0; tx = tx ?? 0;
        } else {
          const dt = Math.max(0.001, now - window.__prevNet.ts);
          const rxCalc = Math.max(0, (rxMB - window.__prevNet.rxMB) / dt);
          const txCalc = Math.max(0, (txMB - window.__prevNet.txMB) / dt);
          window.__prevNet = { ts: now, rxMB, txMB };
          if (rx == null || rx === 0) rx = +rxCalc.toFixed(2);
          if (tx == null || tx === 0) tx = +txCalc.toFixed(2);
        }
      }
    }

    if (cpuChart) {
      pushData(cpuChart,  s.cpu);
      pushData(memChart,  s.mem?.percent ?? 0);
      pushData(diskChart, s.disk?.percent ?? 0);
      pushNet(rx ?? 0, tx ?? 0);
    }

    setText('cpu-val',  `${s.cpu}%`);
    setText('mem-val',  `${s.mem?.percent ?? 0}%`);
    setText('disk-val', `${s.disk?.percent ?? 0}%`);
    setText('net-val',  `${(rx ?? 0)}/${(tx ?? 0)} MB/s`);
    setText('rx-last',  rx ?? '—');
    setText('tx-last',  tx ?? '—');

    ['spinner-cpu','spinner-mem','spinner-disk','spinner-net'].forEach(hideSpinner);

    setText('cores',   s.cores ?? '—');
    setText('threads', s.threads ?? '—');
    if (s.load_pct != null) setText('cpu-load', `${s.load_pct}%`);
    if (Array.isArray(s.load)) {
      const [l1, l5, l15] = s.load;
      setText('load1-top',  l1 ?? '—');
      setText('load5-top',  l5 ?? '—');
      setText('load15-top', l15 ?? '—');
      setText('load1',  l1 ?? '—');
      setText('load5',  l5 ?? '—');
      setText('load15', l15 ?? '—');
    }

    setText('uptime',    fmtUptime(s.uptime ?? 0));
    setText('hostname',  s.hostname ?? '—');
    setText('cpu-model', s.cpu_model ?? '—');
    setText('kernel',    s.kernel ?? '—');
    setText('platform',  s.platform ?? '—');
    setText('arch',      s.arch ?? '—');
    const v4 = String(s.ipv4 || '').trim();
    let v6 = String(s.ipv6 || '').trim();

    setText('ipv4', v4 || 'IPv4 not available');

    if (!v6 || v6 === '—' || v6 === v4 || !v6.includes(':')) {
      setText('ipv6', 'IPv6 not available');
    } else {
      setText('ipv6', v6);
    }

    if (s.mem) {
      const MB = 1024 * 1024;
      setText('mem-used',   fmtBytes((s.mem.used_mb        ?? 0) * MB));
      setText('mem-free',   fmtBytes((s.mem.free_mb        ?? 0) * MB));
      setText('mem-total',  fmtBytes((s.mem.total_mb       ?? 0) * MB));
      setText('swap-used',  fmtBytes((s.mem.swap_used_mb   ?? 0) * MB));
      setText('swap-total', fmtBytes((s.mem.swap_total_mb  ?? 0) * MB));
    }

    if (s.disk) {
      const GB = 1024 ** 3;
      setText('disk-used',  fmtBytes((s.disk.used_gb  ?? 0) * GB));
      setText('disk-free',  fmtBytes((s.disk.free_gb  ?? 0) * GB));
      setText('disk-total', fmtBytes((s.disk.total_gb ?? 0) * GB));
    }

    if (s.net) {
      const MB = 1024 * 1024;
      setText('rx-total', fmtBytes((s.net.rx_total_mb ?? 0) * MB));
      setText('tx-total', fmtBytes((s.net.tx_total_mb ?? 0) * MB));
    }

    if (s.connections) {
      setText('conn-total', String(s.connections.total  ?? 0));
      setText('conn-uniq',  String(s.connections.unique ?? 0));
    }

    if (s.unique_public_ips) {
      setText('uniq-pub-count', String(s.unique_public_ips.count ?? 0));
      const box = document.getElementById('uniq-pub-list');
      if (box) {
        const arr = s.unique_public_ips.list || [];
        box.style.display = arr.length ? 'block' : 'none';
        box.textContent = arr.join(' · ');
      }
    }

    updateUtil();
    hideEmpty();
    backoff = 0;

    peerCounts(window.CURRENT_PEER_SCOPE || 'local');

  } catch (e) {
    console.error(e);
    backoff = Math.min(backoff + 1, 4);
    if (typeof window.toastSafe === 'function' && backoff === 1)
      window.toastSafe('Dashboard stats temporarily unavailable', 'error');
    else if (typeof window.toast === 'function' && backoff === 1)
      window.toast('Dashboard stats temporarily unavailable', 'error');
  } finally {
    scheduleNext();
  }
}

function scheduleNext () {
  clearTimeout(pollTimer);
  if (document.hidden) return;
  const delay = intervalMs * (1 << backoff);
  pollTimer = setTimeout(updateStats, delay);
}

document.addEventListener('visibilitychange', () => {
  if (!document.hidden) scheduleNext(); else clearTimeout(pollTimer);
});

function showModal() {
  const m = bySel('#logs-modal');
  if (!m) return;
  m.removeAttribute('hidden');
  m.classList.add('open');
  document.body.classList.add('modal-open');
}
function hideModal() {
  const m = bySel('#logs-modal');
  if (!m) return;
  m.classList.remove('open');
  m.setAttribute('hidden', '');
  document.body.classList.remove('modal-open');
}
function toEpoch(v){
  if (v == null) return null;
  if (typeof v === 'number') return v > 1e12 ? Math.floor(v/1000) : v; // ms->s
  const d = new Date(v); return isNaN(d) ? null : Math.floor(d.getTime()/1000);
}
function fmtLocal(ts){
  try{
    const d = new Date(ts*1000);
    const pad = n => String(n).padStart(2,'0');
    return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }catch{ return String(ts); }
}
function humanTime(raw){ const e = toEpoch(raw); return e ? fmtLocal(e) : (raw ?? ''); }

async function refreshLogs() {
  const level = bySel('#log-level')?.value || '';
  const q = (bySel('#log-q')?.value || '').trim();
  const url = new URL('/api/app_logs', location.origin);
  if (level) url.searchParams.set('level', level);
  if (q)     url.searchParams.set('q', q);
  url.searchParams.set('limit', '500');

  const r = await fetch(url, { cache: 'no-store' });
  if (!r.ok) return;

  const j = await r.json();
  const tbody = bySel('#log-rows');
  tbody.innerHTML = '';
  (j.logs || []).forEach(rec => {
    const tr = document.createElement('tr');

    const tdT = document.createElement('td');
    tdT.textContent = humanTime(rec.ts || rec.time || '');
    tdT.title = (rec.ts || rec.time || '');

    const lvl = (rec.level || rec.kind || 'info').toLowerCase();
    const tdL = document.createElement('td');
    tdL.innerHTML = `<span class="pill ${lvl}">${lvl.toUpperCase()}</span>`;

    const tdM = document.createElement('td');
    tdM.textContent = rec.msg || rec.text || '';

    tr.append(tdT, tdL, tdM);
    tbody.appendChild(tr);
  });
}
let CURRENT_PEER_SCOPE = 'local';
document.addEventListener('DOMContentLoaded', () => {
  const radios = Array.from(document.querySelectorAll('input[name="peer-scope"]'));
  if (!radios.length) return;

  const saved = localStorage.getItem('peer-scope') || 'local';
  const found = radios.find(r => r.value === saved) || radios[0];
  if (found) {
    found.checked = true;
    radios.forEach(r => r.nextElementSibling?.setAttribute('aria-selected', r.checked ? 'true' : 'false'));
    window.CURRENT_PEER_SCOPE = found.value;
    peerCounts(window.CURRENT_PEER_SCOPE);
  }

  radios.forEach(r => {
    r.addEventListener('change', () => {
      if (!r.checked) return;
      localStorage.setItem('peer-scope', r.value);
      radios.forEach(x => x.nextElementSibling?.setAttribute('aria-selected', x.checked ? 'true' : 'false'));
      window.CURRENT_PEER_SCOPE = r.value;
      peerCounts(window.CURRENT_PEER_SCOPE);
      // updateStats();
    });
  });
  initCharts();

  ['#mem-val','#disk-val'].forEach(id=>{
    const n = document.querySelector(id);
    if (n) utilRO.observe(n, { characterData:true, subtree:true, childList:true });
  });

  rowRO.observe(document.body, { subtree:true, childList:true, characterData:true });

  updateStats();           
  loadAppStat();        
  loadTgStatus();    

  $('open-logs')?.addEventListener('click', (e) => {
    e.preventDefault();
    showModal();
    refreshLogs();
  });

  const modal = bySel('#logs-modal');
  modal?.addEventListener('click', (e) => {
    if (e.target.closest('[data-close], .modal-backdrop')) hideModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal?.classList.contains('open')) hideModal();
  });

  bySel('#log-refresh')?.addEventListener('click', refreshLogs);
  bySel('#log-clear')?.addEventListener('click', async () => {
    if (!confirm('Clear application logs?')) return;
    const r = await fetch('/api/app_logs', { method: 'DELETE' });
    if (r.ok) {
      await refreshLogs();
      if (typeof toast === 'function') toast('Logs cleared', 'success');
    } else {
      if (typeof toast === 'function') toast('Failed to clear logs', 'error');
    }
  });
  bySel('#log-level')?.addEventListener('change', refreshLogs);
  bySel('#log-q')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') refreshLogs(); });
  document.querySelectorAll('.more-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const sel = btn.getAttribute('data-target');
      const box = sel && document.querySelector(sel);
      if (!box) return;
      const open = box.hasAttribute('hidden');
      if (open) box.removeAttribute('hidden'); else box.setAttribute('hidden','');
      btn.innerHTML = `<i class="fas fa-circle-info"></i> ${open ? 'Hide details' : 'More information'}`;
    });
  });

  async function copy(t) {
  const notify = window.toastSafe || window.toast;
  try {
    await navigator.clipboard.writeText(t);
    if (typeof notify === 'function') notify('Copied', 'success', 1200);
  } catch {
    if (typeof notify === 'function') notify('Copy failed', 'error', 1600);
  }
}

if (!window.__dashCopyBound) {
  window.__dashCopyBound = true;
  document.addEventListener('click', (e) => {
    const c = e.target.closest('.copyable');
    if (!c) return;
    const sel = c.getAttribute('data-copy-target');
    const el = sel && document.querySelector(sel);
    if (el) copy((el.textContent || '').trim());
  });
}

  document.addEventListener('click', (e) => {
    const c = e.target.closest('.copyable'); if (!c) return;
    const sel = c.getAttribute('data-copy-target');
    const el = sel && document.querySelector(sel);
    if (el) copy(el.textContent.trim());
  });

  document.querySelectorAll('.more-wrap .more-pop').forEach(btn => {
    const wrap = btn.closest('.more-wrap');
    const pop  = wrap.querySelector('.popover');

    if (!document.getElementById('popover-arrow-style')) {
      const st = document.createElement('style');
      st.id = 'popover-arrow-style';
      st.textContent = '.popover::after{content:"";position:absolute;width:10px;height:10px;background:#fff;border-left:1px solid #e5e7eb;border-top:1px solid #e5e7eb;transform:rotate(45deg);top:var(--arrowTop,-6px);left:var(--arrowLeft,20px);}';
      document.head.appendChild(st);
    }

    const placeholder = document.createComment('popover-home');
    wrap.replaceChild(placeholder, pop);         
    document.body.appendChild(pop);             
    pop.style.position = 'fixed';
    pop.style.zIndex   = 10050;

    function place() {
      const SAFE = 10;
      const r = btn.getBoundingClientRect();
      const pw = Math.min(280, window.innerWidth - SAFE*2);
      pop.style.width = pw + 'px';

      let left = Math.min(Math.max(r.right - pw, SAFE), window.innerWidth - SAFE - pw);

      const below = window.innerHeight - r.bottom, above = r.top;
      let top;
      if (above > below && above > 140) {
        top = Math.max(r.top - pop.offsetHeight - 10, SAFE);
        pop.style.setProperty('--arrowTop', (pop.offsetHeight - 4) + 'px');  
      } else {
        top = Math.max(r.bottom + 8, SAFE);
        pop.style.setProperty('--arrowTop', '-6px');                          
      }
      pop.style.left = left + 'px';
      pop.style.top  = top  + 'px';

      const arrowLeft = Math.min(Math.max(r.left + r.width/2 - left, 12), pw - 12);
      pop.style.setProperty('--arrowLeft', arrowLeft + 'px');
    }

    function open()  { pop.classList.add('open');  place(); btn.setAttribute('aria-expanded','true'); }
    function close() { pop.classList.remove('open'); btn.setAttribute('aria-expanded','false'); }

    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      (pop.classList.contains('open') ? close : open)();
    });

    wrap.addEventListener('mouseenter', () => { if (!pop.classList.contains('open')) place(); });
    window.addEventListener('resize', () => { if (pop.classList.contains('open')) place(); });
    window.addEventListener('scroll', () => { if (pop.classList.contains('open')) place(); }, { passive: true });

    document.addEventListener('click', (e) => { if (!pop.contains(e.target) && !wrap.contains(e.target)) close(); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });
  });

});

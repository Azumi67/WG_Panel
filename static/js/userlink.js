
(() => {
  const IS_PREVIEW = new URLSearchParams(location.search).has('embed');
  let TOKEN = (window.USER_LINK_TOKEN || '').trim();
  if (IS_PREVIEW) TOKEN = 'DEMO';
  const REFRESH_MS = 3000;
  const safeStore = {
  get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch {} }
};

  const root = document.documentElement;
  const toggle = document.getElementById('theme-toggle');

  const currentParticleColor = () =>
    (getComputedStyle(root).getPropertyValue('--particles').trim() || '#b6c1d8');

  function setTheme(mode) {
    document.documentElement.setAttribute('data-theme', mode);
    safeStore.set('userlink:theme', mode);
    root.setAttribute('data-theme', mode);
    if (toggle) {
      toggle.innerHTML = `<i class="fas ${mode === 'dark' ? 'fa-sun' : 'fa-moon'}"></i>`;
      toggle.title = mode === 'dark' ? 'Switch to light' : 'Switch to dark';
    }
  }

  (function initTheme() {
    const saved = safeStore.get('userlink:theme');
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    setTheme(saved || (prefersDark ? 'dark' : 'light'));
    toggle?.addEventListener('click', () =>
      setTheme(root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark')
    );
  })();

  const $ = id => document.getElementById(id);
  const nameEl = $('name');
  const statusEl = $('status');
  const addressEl = $('address');
  const endpointEl = $('endpoint');

  const timeLeftEl = $('time-left');
  const expiresAtEl = $('expires-at');
  const timeBar = $('time-bar');
  const timeSub = $('time-sub');
  const timePctEl = $('time-pct');

  const dataLeftEl = $('data-left');
  const usedHumanEl = $('used-human');
  const limitHumanEl = $('limit-human');
  const usageBar = $('usage-bar');
  const dataPctEl = $('data-pct');

  const qrWrap = $('qr');
  const copyBtn = $('copy-config');
  const dl = $('dl');

  let lastCfgText = '';
  let lastQrContent = '';
  let qrDrawn = false;
  let refreshTimer = null;

  const nowSec = () => Math.floor(Date.now() / 1000);
  const normalizeEpoch = x => (x > 1e12 ? Math.floor(x / 1000) : Math.floor(x));
  function tsFrom(o, k) {
    if (!o) return null;
    if (o[k + '_ts'] != null && !isNaN(o[k + '_ts'])) return Number(o[k + '_ts']);
    const v = o[k]; if (v == null) return null;
    if (typeof v === 'number') return normalizeEpoch(v);
    if (/^\d{10,13}$/.test(String(v))) return normalizeEpoch(Number(v));
    const d = new Date(String(v));
    return isNaN(d) ? null : Math.floor(d.getTime() / 1000);
  }
  const fmtLocal = ts => {
    if (!ts) return '—';
    const d = new Date(ts * 1000), p = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
  };
  const leftParts = exp => {
    if (!exp) return null;
    const s = Math.max(0, exp - nowSec());
    return { sec: s, d: Math.floor(s / 86400), h: Math.floor((s % 86400) / 3600), m: Math.floor((s % 3600) / 60) };
  };
  const fmtCountdown = p => !p ? '00d 00h 00m'
    : `${String(p.d).padStart(2, '0')}d ${String(p.h).padStart(2, '0')}h ${String(p.m).padStart(2, '0')}m`;

  const toMiB = (v, u) => {
    const n = Number(v); if (!Number.isFinite(n)) return 0;
    return (u && u.toLowerCase().startsWith('g')) ? n * 1024 : n;
  };
  const bytesToMiB = b => (Number(b) || 0) / 1048576;
  const fmtMiB = mib => !isFinite(mib) ? 'Unlimited'
    : mib >= 1024 ? (mib / 1024).toFixed(2).replace(/\.0+$/, '') + ' GiB'
      : Math.max(0, Math.round(mib)) + ' MiB';

  function pickNum(obj, keys) {
    for (const k of keys) {
      const v = Number(obj?.[k]);
      if (Number.isFinite(v) && v > 0) return v;
    }
    return 0;
  }
  const pctRemaining = (remain, total) =>
    (!isFinite(total) || total <= 0) ? 0 : Math.max(0, Math.min(100, (remain / total) * 100));

  function setBar(span, pct) {
    const v = Math.max(0, Math.min(100, Math.round(pct || 0)));
    if (!span) return;
    span.style.width = v + '%';
  }

  function toast(msg) {
    const host = document.getElementById('toast-container') || document.body;
    const box = document.createElement('div');
    box.className = 'toast';
    box.textContent = msg;
    host.appendChild(box);
    setTimeout(() => {
      box.classList.add('hide');
      setTimeout(() => box.remove(), 350);
    }, 1600);
  }

  async function fetchJson(url) {
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }
  async function fetchText(url) {
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.text();
  }

  function drawQR(text) {
    try {
      if (text === lastQrContent) return;
      lastQrContent = text;
      if (!qrWrap) return;
      if (!qrDrawn) qrWrap.innerHTML = '';
      if (window.QRCode) {
        new QRCode(qrWrap, {
          text,
          width: 180,
          height: 180,
          colorDark: "#111827",
          colorLight: "#ffffff"
        });
        qrDrawn = true;
      } else {
        setTimeout(() => drawQR(text), 120);
      }
    } catch {
    }
  }

  async function render() {
  let j;
  if (IS_PREVIEW) {
    const now = Math.floor(Date.now() / 1000);
    j = {
      name: 'azumi',
      address: '10.66.66.7/24',
      endpoint: '167.71.78.88:57015',
      status: 'online',
      unlimited: false,
      limit_unit: 'Gi',        
      data_limit: 1,           
      used_bytes: 0,
      first_used: now - 86400 * 3,
      expires_at_ts: now - 60,
      ttl_seconds: 86400 * 10
    };
  } else {
    j = await fetchJson(`/api/u/${TOKEN}`);
  }

  if (statusEl) {
    if (!statusEl.querySelector('.status-indicator')) {
      statusEl.innerHTML = '<span class="status-indicator"></span><span class="status-label">—</span>';
    }
    const raw = String(j.status || '').trim().toLowerCase();
    const isOnline  = raw === 'online';
    const isOffline = raw === 'offline' || raw === '' || raw === 'unknown' || raw === 'inactive';
    const cls   = isOnline ? 'ok' : (isOffline ? 'bad' : 'muted');
    const label = isOnline ? 'Online' : (isOffline ? 'Offline' : (j.status || '—'));
    statusEl.querySelector('.status-label').textContent = label;
    statusEl.className = 'v status-chip ' + cls;
  }

  if (nameEl)     nameEl.textContent    = j.name || '—';
  if (addressEl)  addressEl.textContent = j.address || '—';
  if (endpointEl) endpointEl.textContent = (j.endpoint || '').trim() || '—';


  let limMiB = j.unlimited
    ? Infinity
    : toMiB(
        (pickNum(j, ['data_limit', 'limit', 'limit_mib']) || 0),
        (j.limit_unit || j.unit || '')
      );

  if (!isFinite(limMiB) || limMiB <= 0) {
    const bytesLim = pickNum(j, ['data_limit_bytes', 'limit_bytes']);
    if (Number.isFinite(bytesLim) && bytesLim > 0) limMiB = bytesToMiB(bytesLim);
  }

  const usedEffBytes =
      (pickNum(j, ['used_effective_bytes']) ??
       ((Number(j.used_bytes) || 0) + (Number(j.used_bytes_db) || 0)) ??
       (Number(j.used_bytes) || 0));

  let usedMiB = bytesToMiB(usedEffBytes);
  let leftMiB = j.unlimited ? Infinity : Math.max(0, (limMiB || 0) - usedMiB);

  const isBlocked = String(j.status).toLowerCase() === 'blocked';
  if (!j.unlimited && isBlocked && isFinite(limMiB) && limMiB > 0) {
    usedMiB = limMiB;
    leftMiB = 0;
  }

  if (dataLeftEl)   dataLeftEl.textContent   = isFinite(leftMiB) ? fmtMiB(leftMiB) : 'Unlimited';
  if (usedHumanEl)  usedHumanEl.textContent  = fmtMiB(usedMiB);
  if (limitHumanEl) limitHumanEl.textContent =
    isFinite(limMiB) && limMiB > 0 ? fmtMiB(limMiB) : (j.unlimited ? 'Unlimited' : '0 MiB');

  const pctData = isFinite(limMiB) && limMiB > 0
    ? pctRemaining(leftMiB, limMiB)
    : (j.unlimited ? 100 : 0);

  setBar(usageBar, pctData);
  if (dataPctEl) {
    dataPctEl.textContent =
      isFinite(limMiB) && limMiB > 0 ? `${Math.round(pctData)}%` : (j.unlimited ? '∞' : '0%');
  }

  if (j.unlimited) {
    if (timeLeftEl)  timeLeftEl.textContent  = '∞ Unlimited';
    if (expiresAtEl) expiresAtEl.textContent = 'Expires —';
    if (timeSub)     timeSub.textContent     = 'No time limit';
    setBar(timeBar, 100);
    if (timePctEl) timePctEl.textContent = '∞';
  } else {
    const exp   = tsFrom(j, 'expires_at');
    const parts = leftParts(exp);
    if (timeLeftEl)  timeLeftEl.textContent  = fmtCountdown(parts);
    if (expiresAtEl) expiresAtEl.textContent = exp ? `Expires ${fmtLocal(exp)}` : 'Expires —';
    if (timeSub)     timeSub.textContent     = 'Countdown to expiry';

    let capSec =
    pickNum(j, ['time_limit_seconds', 'timer_seconds', 'duration_seconds', 'max_age_seconds']) ||
    (pickNum(j, ['time_limit_days', 'valid_days']) * 86400);


    const startTs = tsFrom(j, 'start_at') || tsFrom(j, 'started_at') ||
                    tsFrom(j, 'first_used') || tsFrom(j, 'created_at') || tsFrom(j, 'added_at');

    if (!capSec) {
      const expTs = exp;
      if (expTs && startTs && expTs > startTs) capSec = expTs - startTs;
    }

    const remainOverride = pickNum(j, ['remaining_seconds', 'seconds_left', 'time_left_seconds']);
    const remainingSec = (Number.isFinite(remainOverride) && remainOverride > 0)
      ? remainOverride
      : (parts ? parts.sec : 0);

    if (!capSec) capSec = Math.max(remainingSec, 1);

    const pctTime = pctRemaining(remainingSec, capSec);
    setBar(timeBar, pctTime);
    if (timePctEl) timePctEl.textContent = `${Math.round(pctTime)}%`;
  }

  if (dl) {
    if (IS_PREVIEW) {
      dl.removeAttribute('href');
      dl.setAttribute('aria-disabled', 'true');
      dl.classList.add('btn-disabled');
    } else {
      dl.href = `/api/u/${TOKEN}/config`;
    }
  }

  if (!qrDrawn) {
    if (IS_PREVIEW) {
      drawQR('[WG-CONFIG-PREVIEW]');
    } else {
      try {
        lastCfgText = await fetchText(`/api/u/${TOKEN}/config`);
      } catch {
        lastCfgText = '';
      }
      if (lastCfgText && lastCfgText.trim().length > 0) {
        drawQR(lastCfgText);
      } else {
        drawQR(`${location.origin}/api/u/${TOKEN}/config`);
        toast('Config text not available. Using download URL instead.');
      }
    }
  }
}

  copyBtn?.addEventListener('click', async () => {
    try {
      if (!lastCfgText) {
        try { lastCfgText = await fetchText(`/api/u/${TOKEN}/config`); } catch {}
      }
      if (!lastCfgText) { toast('No config text to copy'); return; }

      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(lastCfgText);
      } else {
        const ta = document.createElement('textarea');
        ta.value = lastCfgText;
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
      }
      const old = copyBtn.innerHTML;
      copyBtn.innerHTML = '<i class="fas fa-check"></i>';
      setTimeout(() => { copyBtn.innerHTML = old; }, 900);
      toast('Config copied');
    } catch {
      toast('Copy failed');
    }
  });

  function startRefresh() {
    if (!refreshTimer) {
      refreshTimer = setInterval(() => { render().catch(() => {}); }, REFRESH_MS);
    }
  }
  function stopRefresh() {
    if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
  }

  if (TOKEN) {
    render().catch(() => {});
    startRefresh();
  } else {
    console.warn('USER_LINK_TOKEN missing – nothing to load.');
  }

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { stopRefresh(); }
    else { render().catch(() => {}); startRefresh(); }
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
    `<a class="ulc-chip" target="_blank" rel="noopener" href="${x.href}">
       <i class="${x.icon}"></i><span>${x.label}</span>
     </a>`).join('');
}
document.addEventListener('DOMContentLoaded', () => {
  const slot = document.getElementById('ulc-support-slot') || document.getElementById('ulm-support-slot');
  if (slot && window.SOCIALS) renderSocials(slot, window.SOCIALS);
});

})();

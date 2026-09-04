
(() => {
  const $  = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

  const PANEL_CLOCK = {
    timezone: String(window.PANEL_TIMEZONE || 'UTC'),
    serverEpochMs: null,
    syncedAt: null,
  };

  function _normalizeUtcText(value) {
    const text = String(value ?? '').trim();
    if (!text) return '';
    // Backend/database timestamps without an explicit offset are UTC.
    if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/.test(text)) {
      return text.replace(' ', 'T') + 'Z';
    }
    return text;
  }

  function _parseTs(any){
    if (!any && any!==0) return null;
    if (any instanceof Date) return isNaN(any)?null:any;
    const n = Number(any);
    if (Number.isFinite(n) && String(any).trim()!=='') {
      const ms = n >= 1e12 ? n : n*1000;
      const d = new Date(ms); return isNaN(d)?null:d;
    }
    const s = _normalizeUtcText(any);
    if (!s) return null;
    const d = new Date(s); return isNaN(d)?null:d;
  }

  function _panelNowMs() {
    if (Number.isFinite(PANEL_CLOCK.serverEpochMs) && Number.isFinite(PANEL_CLOCK.syncedAt)) {
      return PANEL_CLOCK.serverEpochMs + (performance.now() - PANEL_CLOCK.syncedAt);
    }
    return Date.now();
  }

  function _applyClockPayload(payload) {
    if (payload?.timezone) {
      PANEL_CLOCK.timezone = String(payload.timezone);
      window.PANEL_TIMEZONE = PANEL_CLOCK.timezone;
    }
    const epoch = Number(payload?.server_epoch);
    if (Number.isFinite(epoch)) {
      PANEL_CLOCK.serverEpochMs = epoch * 1000;
      PANEL_CLOCK.syncedAt = performance.now();
    }
  }

  async function syncPanelClock() {
    const response = await fetch(`/api/timezone?_=${Date.now()}`, {
      credentials:'same-origin',
      headers:{Accept:'application/json'},
      cache:'no-store',
    });
    if (!response.ok) throw new Error(`Timezone sync failed (${response.status})`);
    const payload = await response.json();
    _applyClockPayload(payload);
    return payload;
  }

  function _fmtLocal(any, options = {}) {
    const d = _parseTs(any);
    if (!d) return '—';
    try {
      return new Intl.DateTimeFormat(undefined, {
        timeZone:PANEL_CLOCK.timezone,
        year:'numeric', month:'short', day:'2-digit',
        hour:'2-digit', minute:'2-digit', second:'2-digit',
        hour12:false,
        ...options,
      }).format(d);
    } catch {
      return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    }
  }

  function _fmtAgo(any) {
    const d = _parseTs(any);
    if (!d) return '';
    const signed = Math.floor((_panelNowMs() - d.getTime()) / 1000);
    const future = signed < -4;
    const sec = Math.abs(signed);
    if (sec < 5) return 'just now';
    const min = Math.floor(sec/60), hr=Math.floor(min/60), day=Math.floor(hr/24);
    const value = day > 0 ? `${day}d ${hr%24}h` : hr > 0 ? `${hr}h ${min%60}m` : min > 0 ? `${min}m` : `${sec}s`;
    return future ? `in ${value}` : `${value} ago`;
  }

  function _formatStamp(rowOrValue) {
    const row = rowOrValue && typeof rowOrValue === 'object' && !(rowOrValue instanceof Date)
      ? rowOrValue : null;
    const value = row ? (row.ts ?? row.time ?? row.timestamp) : rowOrValue;
    const d = _parseTs(value);
    return {
      text: row?.time_display || _fmtLocal(d),
      ago: _fmtAgo(d),
    };
  }

  function _panelFileStamp() {
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone:PANEL_CLOCK.timezone,
      year:'numeric', month:'2-digit', day:'2-digit',
      hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false,
    }).formatToParts(new Date(_panelNowMs()));
    const get = type => parts.find(part => part.type === type)?.value || '00';
    return `${get('year')}-${get('month')}-${get('day')}_${get('hour')}-${get('minute')}-${get('second')}`;
  }

  const panelClockReady = syncPanelClock().catch(() => null);
  window.panelTime = {
    sync:syncPanelClock,
    format:_fmtLocal,
    relative:_fmtAgo,
    stamp:_formatStamp,
    fileStamp:_panelFileStamp,
    timezone:() => PANEL_CLOCK.timezone,
    now:() => new Date(_panelNowMs()),
  };

  (function restoreTabAttr() {
    const KEY_NEW    = 'settings:activeTab';
    const KEY_LEGACY = 'wg:set:tab';  

    const stored = localStorage.getItem(KEY_NEW) || localStorage.getItem(KEY_LEGACY);
    if (stored) {
      document.documentElement.setAttribute('data-tab', stored);
    }
  })();

  (function initTabs() {
    const tabs   = document.getElementById('set-tabs');
    const panels = document.getElementById('set-panels');
    const KEY    = 'settings:activeTab';

    if (!tabs || !panels) return;

    function showTab(name) {
      if (!name) return;

      tabs.querySelectorAll('.tab').forEach(btn => {
        const on = btn.dataset.tab === name;
        btn.classList.toggle('active', on);
      });

      panels.querySelectorAll('.panel').forEach(p => {
        const on = p.dataset.panel === name;
        p.classList.toggle('active', on);
      });

      localStorage.setItem(KEY, name);
      document.documentElement.setAttribute('data-tab', name);

      if (name === 'iface') {
        const localRadio = document.getElementById('iface-scope-local');
        if (localRadio) {
          localRadio.dispatchEvent(new Event('change', { bubbles: true }));
        }
      }
    }

    tabs.addEventListener('click', (e) => {
      const btn = e.target.closest('.tab');
      if (!btn) return;
      const name = btn.dataset.tab;
      showTab(name);
    });

    const initial = localStorage.getItem(KEY) || 'panel';
    showTab(initial);
  })();


  window.toastSafe = window.toastSafe || function (msg, type = 'info') {
    if (typeof window.toast === 'function') return window.toast(msg, type);
    if (type === 'error') console.error(msg); else console.log(msg);
  };
  const toast = (m, t = 'info') => (window.toastSafe ? window.toastSafe(m, t) : alert(m));

  function csrf(json = false) {
    return (window.csrfHeaders?.(json)) || (function(){
      const m = (document.cookie.match(/csrf_token=([^;]+)/) || [])[1] || '';
      const h = {}; if (json) h['Content-Type'] = 'application/json';
      if (m) { h['X-CSRFToken'] = m; h['X-CSRF-Token'] = m; }
      return h;
    })();
  }

  async function jfetch(url, opt = {}) {
    const wantsJson = !!(opt && opt.body && typeof opt.body === 'object');
    const res = await fetch(url, {
      method: opt.method || 'GET',
      headers: { ...csrf(wantsJson), ...(opt.headers || {}), 'Accept': 'application/json' },
      body: wantsJson ? JSON.stringify(opt.body) : (opt.body || null),
      credentials: 'same-origin',
      cache: 'no-store'
    });

    let payload = null;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) { try { payload = await res.json(); } catch {} }
    else { try { payload = await res.text(); } catch {} }

    if (!res.ok) {
      let msg = (payload && payload.error) ? payload.error
        : (typeof payload === 'string' && payload) || ('HTTP ' + res.status);
      const s = String(msg).toLowerCase();
      if (s.includes('<html') || s.includes('<!doctype') || msg.length > 180) {
        msg = (res.status === 500) ? 'Server error (500)' : ('HTTP ' + res.status);
      }
      throw new Error(msg);
    }
    return payload;
  }

  function lockBodyScroll() {
    const sbw = window.innerWidth - document.documentElement.clientWidth;
    document.body.classList.add('modal-open');
    if (sbw > 0) document.body.style.paddingRight = sbw + 'px';
  }
  function unlockBodyScroll() {
    document.body.classList.remove('modal-open');
    document.body.style.paddingRight = '';
  }
  function pinModals() {
    ['tg-logs-modal', 'iface-logs-modal', 'tg-add-modal', 'admin-logs-modal', 'sec-advanced-modal', 'sec-history-modal'].forEach(id => {
      const el = document.getElementById(id);
      if (el && el.parentElement !== document.body) document.body.appendChild(el);
    });
  }
  function openModal(nodeOrId) {
    const m = typeof nodeOrId === 'string' ? document.getElementById(nodeOrId) : nodeOrId;
    if (!m) return;
    m.classList.add('open'); lockBodyScroll();
  }
  function closeModal(nodeOrId) {
    const m = typeof nodeOrId === 'string' ? document.getElementById(nodeOrId) : nodeOrId;
    if (!m) return;
    m.classList.remove('open'); unlockBodyScroll();
  }
  window.openModal = openModal;
  window.closeModal = closeModal;

  document.addEventListener('click', (e) => {
    if (e.target.matches('[data-close], [data-modal-close], .modal-backdrop')) {
      const m = e.target.closest('.modal') || document.querySelector('.modal.open');
      if (m) closeModal(m);
    }
  });

  window.showToast = function showToast(msg, type = 'info', { duration = 3000, actionText, onAction } = {}) {
    const host = document.getElementById('toast-container');
    if (!host) { toast(msg, type); return; }
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.setAttribute('role', 'status');
    el.innerHTML = `
      <span class="toast-icon"><i class="fa-solid ${type === 'success' ? 'fa-check'
        : type === 'error' ? 'fa-triangle-exclamation'
        : type === 'warn'  ? 'fa-exclamation' : 'fa-info'}"></i></span>
      <span class="msg">${msg}</span>
      ${actionText ? `<button class="action">${actionText}</button>` : ''}
      <span class="progress"></span>`;
    host.appendChild(el);

    const hide = () => { el.classList.add('hiding'); setTimeout(() => el.remove(), 180); };
    if (actionText) el.querySelector('.action')?.addEventListener('click', () => { try { onAction?.(); } finally { hide(); } });

    let t0 = performance.now();
    let rafId = requestAnimationFrame(function tick(now) {
      const pct = Math.max(0, 1 - (now - t0) / duration);
      el.style.setProperty('--pct', pct);
      if (pct > 0) rafId = requestAnimationFrame(tick); else hide();
    });
    el.addEventListener('keydown', (e) => { if (e.key === 'Escape') hide(); });
    window.toast = window.showToast;        // expose
    window.toastSafe = (m, t='info') => window.showToast(m, t);
    return { hide };
  };

  window.confirmDialog = function confirmDialog({ title='Confirm', body='Are you sure?', okText='OK', cancelText='Cancel' } = {}) {
    const sheet = document.getElementById('ui-confirm');
    const t = document.getElementById('ui-confirm-title');
    const b = document.getElementById('ui-confirm-body');
    const ok = document.getElementById('ui-confirm-ok');
    const cancel = document.getElementById('ui-confirm-cancel');
    if (!sheet) return Promise.resolve(false);

    t.textContent = title; b.textContent = body; ok.textContent = okText; cancel.textContent = cancelText;
    document.body.appendChild(sheet);
    sheet.hidden = false;

    let resolveFn;
    function close(result) {
      sheet.hidden = true;
      ok.onclick = cancel.onclick = null;
      document.removeEventListener('keydown', onKey);
      resolveFn?.(result);
    }
    function onKey(e) { if (e.key === 'Escape') close(false); if (e.key === 'Enter') close(true); }
    document.addEventListener('keydown', onKey);

    return new Promise((resolve) => {
      resolveFn = resolve;
      ok.onclick = () => close(true);
      cancel.onclick = () => close(false);
    });
  };


(function panelSecurityAndRuntime () {
  const $  = (s, r = document) => r.querySelector(s);

  function setTLSAdvanced(open) {
  const box = $('#tls-advanced');
  if (!box) return;

  const on = !!open;
  box.classList.toggle('open', on);
  box.style.display = on ? '' : 'none';
}

  function rowsForTLS(on) {
    const httpRow  = document.getElementById('row-http-port');
    const httpsBlk = document.getElementById('row-https-block');
    if (httpRow)  httpRow.style.display  = on ? 'none' : '';
    if (httpsBlk) httpsBlk.style.display = on ? '' : 'none';
  }

  function runtimePortUI(tlsOn) {
    const bind = document.getElementById('rt2-bind');
    const port = document.getElementById('rt2-port');
    const pill = document.getElementById('rt-managed-pill');
    const note = document.getElementById('rt-managed-note');
    const managed = !!tlsOn;

    if (bind) { bind.disabled = managed; bind.readOnly = managed; bind.parentElement.style.opacity = managed ? 0.6 : 1; }
    if (port) { port.disabled = managed; port.readOnly = managed; port.parentElement.style.opacity = managed ? 0.6 : 1; }
    if (pill) pill.style.display = managed ? '' : 'none';
    if (note) note.style.display = managed ? '' : 'none';
  }

  function browserTimezoneName() {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    } catch {
      return 'UTC';
    }
  }

  function supportedTimezoneNames(current = 'UTC') {
    let zones = [];
    try {
      if (typeof Intl.supportedValuesOf === 'function') {
        zones = Intl.supportedValuesOf('timeZone');
      }
    } catch {}
    if (!zones.length) {
      zones = ['UTC','Africa/Cairo','America/New_York','Asia/Dubai','Asia/Tehran','Asia/Tokyo','Australia/Sydney','Europe/Amsterdam','Europe/Berlin','Europe/London'];
    }
    const wanted = String(current || 'UTC');
    if (!zones.includes('UTC')) zones.unshift('UTC');
    if (wanted && !zones.includes(wanted)) zones.unshift(wanted);
    return Array.from(new Set(zones));
  }

  function populatePanelTimezone(current) {
    const select = document.getElementById('panel-timezone');
    if (!select) return;
    const wanted = String(current || 'UTC');
    const zones = supportedTimezoneNames(wanted);
    select.innerHTML = '';
    zones.forEach((zone) => {
      const option = document.createElement('option');
      option.value = zone;
      option.textContent = zone;
      option.selected = zone === wanted;
      select.appendChild(option);
    });
    select.value = wanted;
    select.dispatchEvent(new Event('change', { bubbles:true }));
  }

  function updateRegionalPreview(timezoneName) {
    const tz = String(timezoneName || 'UTC');
    const current = document.getElementById('panel-timezone-current');
    const nowEl = document.getElementById('panel-timezone-now');
    const status = document.getElementById('panel-timezone-status');
    if (current) current.textContent = tz;
    if (status) {
      status.textContent = tz;
      status.className = 'badge green';
    }
    if (nowEl) {
      try {
        nowEl.textContent = 'Current local time ' + new Intl.DateTimeFormat(undefined, {
          timeZone: tz,
          year:'numeric', month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit',
          hour12:false,
        }).format(new Date(_panelNowMs()));
      } catch {
        nowEl.textContent = 'Current local time unavailable';
      }
    }
  }

  async function loadPanelSettings() {
    await panelClockReady;
    const j = await jfetch('/api/settings');
    const tlsOn = !!j.tls_enabled;

    const tlsChk = document.getElementById('tls-enabled');
    if (tlsChk) {
      tlsChk.checked = tlsOn;
      tlsChk.dataset.initial_tls = tlsOn ? '1' : '0';
    }

    const domEl  = document.getElementById('domain');       if (domEl) domEl.value    = j.domain || '';
    const force  = document.getElementById('force-https');  if (force) force.checked  = !!j.force_https_redirect;
    const hsts   = document.getElementById('hsts');         if (hsts)  hsts.checked   = !!j.hsts;

    const httpP  = document.getElementById('http-port');    if (httpP)  httpP.value  = (j.http_port  ?? '');
    const httpsP = document.getElementById('https-port');   if (httpsP) httpsP.value = (j.https_port ?? '');

    const curEl = document.getElementById('cur-scheme');
    if (curEl) {
      const onHttps = (window.location.protocol === 'https:');
      curEl.textContent = onHttps ? 'HTTPS' : 'HTTP';
      curEl.className = 'badge ' + (onHttps ? 'green' : 'gray');
    }

    const timezoneName = String(j.timezone || 'UTC');
    if (timezoneName !== PANEL_CLOCK.timezone) {
      await syncPanelClock().catch(() => {
        PANEL_CLOCK.timezone = timezoneName;
        window.PANEL_TIMEZONE = timezoneName;
      });
    }
    populatePanelTimezone(timezoneName);
    updateRegionalPreview(timezoneName);

    const browserTz = document.getElementById('panel-browser-timezone');
    if (browserTz) browserTz.textContent = browserTimezoneName();

    setTLSAdvanced(tlsOn);
    rowsForTLS(tlsOn);
    runtimePortUI(tlsOn);
  }

  async function rtLoad() {
    try {
      const j = await jfetch('/api/runtime');
      const saved = j?.saved || {};

      const bindEl = document.getElementById('rt2-bind');
      const portEl = document.getElementById('rt2-port');

      const host = (saved.bind || '0.0.0.0').replace(/:\d+$/, '').trim() || '0.0.0.0';
      const port = Number(saved.port || 0) || 8000;        
      if (bindEl) bindEl.value = `${host}:${port}`;
      if (portEl) portEl.value = String(port);

      const w  = document.getElementById('rt-workers');  if (w)  w.value  = saved.workers ?? 1;
      const t  = document.getElementById('rt-threads');  if (t)  t.value  = saved.threads ?? 1;
      const to = document.getElementById('rt-timeout');  if (to) to.value = saved.timeout ?? 30;
      const gt = document.getElementById('rt-gtimeout'); if (gt) gt.value = saved.graceful_timeout ?? 30;
      const ll = document.getElementById('rt-loglevel'); if (ll) ll.value = (saved.loglevel || 'INFO');

      try {
        const s = await jfetch('/api/app_status');
        const ts = s?.app?.since || s?.since || s?.started_at || s?.app_started || null;
        const d  = _parseTs(ts);
        const upEl = document.getElementById('rt-uptime');
        if (upEl && d) upEl.textContent = `${_fmtLocal(d)} · ${_fmtAgo(d)}`;

        const tlsOn = !!document.getElementById('tls-enabled')?.checked;
        const scheme = (s?.scheme || (tlsOn || location.protocol === 'https:' ? 'https' : 'http')).toUpperCase();
        const modeEl = document.getElementById('rt-mode');
        if (modeEl) modeEl.textContent = scheme;
      } catch {}

      const tlsOn = !!document.getElementById('tls-enabled')?.checked;
      runtimePortUI(tlsOn);
    } catch {
    }
  }

  /* ____ TLS runtime ____ */
  async function tLSSyncRuntime() {
    const tlsChk  = document.getElementById('tls-enabled');
    const tlsOn   = !!tlsChk?.checked;
    const domain  = (document.getElementById('domain')?.value || '').trim();
    const force   = !!document.getElementById('force-https')?.checked;
    const hsts    = !!document.getElementById('hsts')?.checked;
    const httpP   = Number(document.getElementById('http-port')?.value || 0) || null;
    const httpsP  = Number(document.getElementById('https-port')?.value || 0) || null;
    const tlsCert = (document.getElementById('cert-path')?.value || '').trim();
    const tlsKey  = (document.getElementById('key-path')?.value  || '').trim();
    const panelTimezone = (document.getElementById('panel-timezone')?.value || 'UTC').trim() || 'UTC';

    const btn = document.getElementById('save-panel'); 
    if (btn) btn.disabled = true;

    const initialFlag = tlsChk?.dataset.initial_tls;
    const wasOn = initialFlag === '1';
    const tlsChanged = (typeof wasOn === 'boolean') ? (wasOn !== tlsOn) : false;

    try {
      const resp = await jfetch('/api/settings', {
        method: 'POST',
        body: {
          tls_enabled: tlsOn,
          domain: domain || null,
          force_https_redirect: force,
          hsts,
          http_port:  httpP,
          https_port: httpsP,
          tls_cert_path: tlsCert || null,
          tls_key_path:  tlsKey  || null,
          timezone: panelTimezone,
        }
      });

      if (!tlsOn && Number.isInteger(httpP) && httpP >= 1 && httpP <= 65535) {
        await jfetch('/api/runtime', { method: 'POST', body: { port: httpP } }).catch(() => {});
      }

      if (tlsChanged && typeof rtRestart === 'function') {
        toast('TLS changed. Restarting panel to apply…', 'info');
        await rtRestart();  
        return;             
      }

      if (resp?.next_url) {
        window.location.assign(resp.next_url);
        return;
      }

      toast('Settings saved.', 'success');
      await loadPanelSettings();
      await rtLoad();
      runtimePortUI(tlsOn);
    } catch (e) {
      console.error(e);
      toast('Save failed: ' + (e?.message || 'unknown'), 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function saveRegionalSettings() {
    const select = document.getElementById('panel-timezone');
    const timezoneName = String(select?.value || 'UTC').trim() || 'UTC';
    const btn = document.getElementById('save-regional');
    if (btn) btn.disabled = true;
    try {
      const current = await jfetch('/api/settings');
      await jfetch('/api/settings', {
        method: 'POST',
        body: {
          tls_enabled: !!current.tls_enabled,
          domain: current.domain || null,
          force_https_redirect: !!current.force_https_redirect,
          hsts: !!current.hsts,
          http_port: current.http_port ?? null,
          https_port: current.https_port ?? null,
          tls_cert_path: current.tls_cert_path || null,
          tls_key_path: current.tls_key_path || null,
          timezone: timezoneName,
        }
      });
      toast(`Panel timezone saved: ${timezoneName}`, 'success');
      await syncPanelClock().catch(() => null);
      await loadPanelSettings();
    } catch (e) {
      console.error(e);
      toast('Timezone save failed: ' + (e?.message || 'unknown'), 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  /* ___ runtime.json ___ */
  async function rtSave() {
    const tlsOn = !!document.getElementById('tls-enabled')?.checked;
    const body = {
      workers: Number(document.getElementById('rt-workers')?.value ?? 1),
      threads: Number(document.getElementById('rt-threads')?.value ?? 1),
      timeout: Number(document.getElementById('rt-timeout')?.value ?? 30),
      graceful_timeout: Number(document.getElementById('rt-gtimeout')?.value ?? 30),
      loglevel: (document.getElementById('rt-loglevel')?.value || 'info')
    };

    if (!tlsOn) {
      const combo = (document.getElementById('rt2-bind')?.value || '').trim();
      let host = '0.0.0.0', port = Number(document.getElementById('rt2-port')?.value || 8080);
      if (combo.includes(':')) {
        const idx = combo.lastIndexOf(':');
        host = combo.slice(0, idx).trim() || host;
        const p = Number(combo.slice(idx + 1).trim());
        if (!Number.isNaN(p)) port = p;
      }
      body.port = port;
      body.bind = `${host}:${port}`;
    }

    await jfetch('/api/runtime', { method: 'POST', body });
    toast('Runtime saved. Restart required to apply.', 'success');
    await rtLoad();
  }
  let rtRestartInProgress = false;

async function rtRestart() {
  const btn = document.getElementById('rt-restart');
  if (rtRestartInProgress) return;
  rtRestartInProgress = true;

  if (btn) {
    btn.disabled = true;
    btn.classList.add('btn-busy');  
  }

  try {
    toast('Restarting panel with new settings…', 'info');

    const resp = await jfetch('/api/panel/restart', { method: 'POST', body: {} });
    const base   = (resp && resp.next_url) ? resp.next_url : (window.location.origin + '/');
    const path   = window.location.pathname || '/';  
    const target = base.replace(/\/+$/, '') + path;   

    setTimeout(() => {
      window.location.assign(target);
    }, 5000);
  } catch (e) {
    console.error(e);
    toast('Restart failed: ' + (e?.message || 'unknown'), 'error');
    rtRestartInProgress = false;
    if (btn) {
      btn.disabled = false;
      btn.classList.remove('btn-busy');
    }
  }
}

document.getElementById('rt-restart')
  ?.addEventListener('click', rtRestart);

  function subtab(name) {
    document.querySelectorAll('#panel-subtabs .subtab').forEach(b => {
      const on = b.dataset.sub === name;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', String(on));
    });
    document.querySelectorAll('.subpanel[data-subpanel]').forEach(p => {
      const on = p.dataset.subpanel === name;
      p.hidden = !on;
      p.classList.toggle('active', on);
    });
    localStorage.setItem('settings:panelSubtab', name);

    if (name === 'tls') loadPanelSettings();
    if (name === 'runtime') rtLoad();
    if (name === 'regional') loadPanelSettings();
  }

  document.addEventListener('DOMContentLoaded', async () => {
    await panelClockReady;
    const savedSub = localStorage.getItem('settings:panelSubtab') || 'tls';
    subtab(savedSub);

    await loadPanelSettings();
    await rtLoad();
    document.getElementById('panel-subtabs')?.addEventListener('click', (e) => {
      const b = e.target.closest('.subtab');
      if (!b) return;
      const name = b.dataset.sub;
      if (name) subtab(name);
      });

    document.getElementById('tls-enabled')?.addEventListener('change', (e) => {
      const on = !!e.target.checked;
      setTLSAdvanced(on);
      rowsForTLS(on);
      runtimePortUI(on);
    });

    document.getElementById('save-panel')?.addEventListener('click', () =>
      tLSSyncRuntime().catch(e => toast('Save failed: ' + (e?.message || 'unknown'), 'error'))
    );
    document.getElementById('save-regional')?.addEventListener('click', () =>
      saveRegionalSettings().catch(e => toast('Timezone save failed: ' + (e?.message || 'unknown'), 'error'))
    );
    document.getElementById('panel-timezone')?.addEventListener('change', (e) => {
      updateRegionalPreview(e.target.value || 'UTC');
    });
    document.getElementById('panel-use-browser-timezone')?.addEventListener('click', () => {
      const detected = browserTimezoneName();
      populatePanelTimezone(detected);
      updateRegionalPreview(detected);
      toast(`Selected browser timezone: ${detected}. Save to apply.`, 'info');
    });
    setInterval(() => {
      const selected = document.getElementById('panel-timezone')?.value || PANEL_CLOCK.timezone;
      updateRegionalPreview(selected);
    }, 1000);
    setInterval(() => syncPanelClock().catch(() => null), 300000);
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) syncPanelClock().catch(() => null);
    });
    document.getElementById('save-runtime')?.addEventListener('click', () =>
      rtSave().catch(e => toast('Runtime save failed: ' + (e?.message || 'unknown'), 'error'))
    );

    (function hint() {
      const hintBtn = document.getElementById('rt-hint');
      const pop     = document.getElementById('rt-pop');
      const copyBtn = document.getElementById('rt-copy');
      const cmdEl   = document.getElementById('rt-cmd');
      function show(){ if (pop) { pop.style.display='block'; hintBtn?.setAttribute('aria-expanded','true'); } }
      function hide(){ if (pop) { pop.style.display='none';  hintBtn?.setAttribute('aria-expanded','false'); } }
      hintBtn?.addEventListener('click', (e)=>{ e.stopPropagation(); (pop?.style.display==='block'?hide:show)(); });
      document.addEventListener('click', (e)=>{ if (pop && !pop.contains(e.target) && e.target!==hintBtn) hide(); });
      window.addEventListener('keydown', (e)=>{ if (e.key==='Escape') hide(); });
      copyBtn?.addEventListener('click', async ()=>{
        const txt = (cmdEl?.textContent||'').trim();
        try { await navigator.clipboard.writeText(txt); toast('Restart command copied', 'success'); }
        catch { toast('Copy failed', 'error'); }
      });
      if (window.RUNTIME_RESTART_CMD && cmdEl) cmdEl.textContent = window.RUNTIME_RESTART_CMD;
    })();
  });
})();



  (function iface() {
  let statusTimer = null;
  let IFACE_SCOPE = 'local';   
  let IFACE_NODE  = null;      
  let NODE_IFACES = [];       
  let loadIfaceAbort;

  const $  = (s, r = document) => r.querySelector(s);
  const toast = (m, t='info') => (window.toastSafe ? window.toastSafe(m, t) : alert(m));

  function setChip(isUp) {
    const chip = $('#iface-scope-chip');
    if (!chip) return;
    chip.className = 'badge ' + (isUp ? 'green' : 'red');
    chip.textContent = (IFACE_SCOPE === 'local' ? 'Local' : 'Node') + ' · ' + (isUp ? 'Up' : 'Down');
  }

  function setActions({ save, scope, target }) {
    const btnSave = $('#iface-save');
    const btnUp   = $('#iface-up');
    const btnDn   = $('#iface-down');
    if (btnSave) {
      btnSave.disabled = !save;
      btnSave.title    = save ? '' : 'Editing interface settings on nodes is disabled';
    }
    if (btnUp) { btnUp.dataset.scope = scope; btnUp.dataset.target = String(target ?? ''); }
    if (btnDn) { btnDn.dataset.scope = scope; btnDn.dataset.target = String(target ?? ''); }
  }

  function ifaceView(meta) {
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = (v ?? ''); };
    set('i-name',    meta?.name ?? '');
    set('i-path',    meta?.path ?? '');
    set('i-address', meta?.address ?? '');
    set('i-listen',  meta?.listen_port ?? '');
    set('i-dns',     meta?.dns ?? '');
    set('i-mtu',     meta?.mtu ?? '');

    const badge = $('#iface-status');
    if (badge) {
      badge.className = `badge ${meta?.is_up ? 'green' : 'red'}`;
      badge.textContent = meta?.is_up ? 'Up' : 'Down';
    }
    setChip(!!meta?.is_up);

    const view = $('#iface-view');
    if (view) view.hidden = false;
  }

  async function loadInterfaceLocal() {
    const sel = $('#iface-select'); if (!sel) return;
    sel.innerHTML = '';
    try {
      const r = await fetch('/api/get-interfaces', { credentials:'same-origin' });
      if (!r.ok) throw new Error('HTTP '+r.status);
      const j = await r.json();
      sel.innerHTML = (j.interfaces || []).map(i => `<option value="${i.id}">${i.name}</option>`).join('');
      if (sel.options.length) {
        sel.value = sel.options[0].value;
        await loadIfaceLocal(sel.value);
      }
      $('#iface-view').hidden = false;
    } catch (e) { console.error(e); toast('Failed to load interfaces', 'error'); }
  }

  async function loadIfaceLocal(id) {
    if (!id) return;
    if (loadIfaceAbort) loadIfaceAbort.abort();
    const ctrl = new AbortController(); loadIfaceAbort = ctrl;
    try {
      const r = await fetch(`/api/iface/${id}`, { credentials:'same-origin', signal: ctrl.signal });
      if (!r.ok) throw new Error('HTTP '+r.status);
      const j = await r.json();
      ifaceView(j);
      setActions({ save:true, scope:'local', target:id });
    } catch (e) {
      if (e.name !== 'AbortError') { console.error(e); toast('Failed to load interface details', 'error'); }
    }
  }

    async function refreshIfaceStatusLocal(id) {
    if (!id) return;
    try {
      const r = await fetch(`/api/iface/${id}/status`, {
        credentials: 'same-origin',
        cache: 'no-store',
      });
      if (!r.ok) throw 0;
      const j = await r.json();   

      const badge = document.getElementById('iface-status');
      if (badge) {
        badge.className = `badge ${j.is_up ? 'green' : 'red'}`;
        badge.textContent = j.is_up ? 'Up' : 'Down';
      }
      setChip(!!j.is_up);
    } catch {
    }
  }


  function statusPollLocal() {
    if (statusTimer) clearInterval(statusTimer);
    const id = $('#iface-select')?.value;
    if (!id) return;
    statusTimer = setInterval(() => refreshIfaceStatusLocal(id), 10000);
  }

  async function loadNodesIface() {
    const sel = $('#iface-node'); if (!sel) return;
    sel.innerHTML = '';
    try {
      let r = await fetch('/api/nodes', { credentials:'same-origin', cache:'no-store' });
      let j = await r.json();
      let rows = Array.isArray(j.nodes) ? j.nodes : [];

      await Promise.all(rows.map(async n => {
        try { await fetch(`/api/nodes/${n.id}/health`, { credentials:'same-origin', cache:'no-store' }); } catch {}
      }));
      r = await fetch('/api/nodes', { credentials:'same-origin', cache:'no-store' });
      j = await r.json();
      rows = Array.isArray(j.nodes) ? j.nodes : [];

      rows.forEach(n => {
        const opt = document.createElement('option');
        opt.value = n.id;
        opt.textContent = `${n.name} ${n.online ? '• online' : '• offline'}`;
        opt.dataset.online = n.online ? '1' : '0';
        sel.appendChild(opt);
      });
      IFACE_NODE = rows[0]?.id || null;
    } catch {
    }
  }

  async function loadNodeIfaces(nid) {
    const sel = $('#iface-select'); if (!sel || !nid) return;
    sel.innerHTML = '';
    try {
      const r = await fetch(`/api/nodes/${nid}/interfaces`, { credentials:'same-origin', cache:'no-store' });
      const j = await r.json();
      NODE_IFACES = Array.isArray(j.interfaces) ? j.interfaces : [];
      sel.innerHTML = NODE_IFACES.map(it => `<option value="${it.name}">${it.name}</option>`).join('');
      if (sel.options.length) {
        sel.value = sel.options[0].value;
        await loadIfaceNode(sel.value);
      }
      $('#iface-view').hidden = false;
    } catch (e) { console.error(e); toast('Failed to load node interfaces', 'error'); }
  }
  async function loadNodesForLogs() {
    const sel = document.getElementById('iflog-node');
    if (!sel) return;
    sel.innerHTML = '';

    try {
      let r = await fetch('/api/nodes', {
        credentials: 'same-origin',
        cache: 'no-store'
      });
      let j = await r.json();
      let rows = Array.isArray(j.nodes) ? j.nodes : [];

      try {
        await Promise.all(rows.map(async (n) => {
          try {
            await fetch(`/api/nodes/${n.id}/health`, {
              credentials: 'same-origin',
              cache: 'no-store'
            });
          } catch (_) {}
        }));
        r = await fetch('/api/nodes', {
          credentials: 'same-origin',
          cache: 'no-store'
        });
        j = await r.json();
        rows = Array.isArray(j.nodes) ? j.nodes : [];
      } catch (_) {}

      rows.forEach((n) => {
        const opt = document.createElement('option');
        opt.value = n.id;
        opt.textContent = `${n.name} ${n.online ? '• online' : '• offline'}`;
        sel.appendChild(opt);
      });

      if (rows.length) {
        sel.value = rows[0].id;
      }
    } catch (e) {
      console.error(e);
      toast('Failed to load nodes for logs', 'error');
    }
  }

  async function loadNodeIfacesForLogs(nid) {
    const sel = document.getElementById('iflog-select');
    if (!sel || !nid) return;
    sel.innerHTML = '';

    try {
      const r = await fetch(`/api/nodes/${nid}/interfaces`, {
        credentials: 'same-origin',
        cache: 'no-store'
      });
      const j = await r.json();
      const list = Array.isArray(j.interfaces) ? j.interfaces : [];

      sel.innerHTML = list
        .map((it) => `<option value="${it.name}">${it.name}</option>`)
        .join('');

      if (sel.options.length) {
        sel.value = sel.options[0].value;
      }
    } catch (e) {
      console.error(e);
      toast('Failed to load node interfaces for logs', 'error');
    }
  }

  window.loadNodesForLogs = loadNodesForLogs;
  window.loadNodeIfacesForLogs = loadNodeIfacesForLogs;


  async function loadIfaceNode(name) {
    const meta = NODE_IFACES.find(x => x.name === name) || {};
    ifaceView(meta);
    setActions({ save:false, scope:'node', target:name });
  }

  async function refreshIfaceStatusNode() {
    try {
      const r = await fetch(`/api/nodes/${IFACE_NODE}/interfaces`, { credentials:'same-origin', cache:'no-store' });
      const j = await r.json();
      NODE_IFACES = Array.isArray(j.interfaces) ? j.interfaces : [];
      const cur = $('#iface-select')?.value || '';
      const meta = NODE_IFACES.find(x => x.name === cur);
      if (meta) ifaceView(meta);
    } catch {}
  }

  function statusPollNode() {
    if (statusTimer) clearInterval(statusTimer);
    statusTimer = setInterval(refreshIfaceStatusNode, 10000);
  }

  async function loadInterfaceList() {
    if (IFACE_SCOPE === 'local') {
      await loadInterfaceLocal();
      statusPollLocal();
    } else {
      await loadNodesIface();
      IFACE_NODE = Number($('#iface-node')?.value || 0) || null;
      await loadNodeIfaces(IFACE_NODE);
      statusPollNode();
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    const localRadio = document.getElementById('iface-scope-local');
    if (localRadio) {
      localRadio.dispatchEvent(new Event('change', { bubbles: true }));
    } else {
      loadInterfaceList();
    }
  });

  $('#iface-select')?.addEventListener('change', async (e) => {
    if (IFACE_SCOPE === 'local') {
      await loadIfaceLocal(e.target.value);
      statusPollLocal();
    } else {
      await loadIfaceNode(e.target.value);
      statusPollNode();
    }
    if (typeof syncIfLogSelector === 'function') syncIfLogSelector();
  });

  $('#iface-scope-local')?.addEventListener('change', async (e) => {
    if (!e.target.checked) return;
    IFACE_SCOPE = 'local';
    $('#iface-node')?.setAttribute('hidden', '');
    await loadInterfaceList();
  });

  $('#iface-scope-node')?.addEventListener('change', async (e) => {
    if (!e.target.checked) return;
    IFACE_SCOPE = 'node';
    $('#iface-node')?.removeAttribute('hidden');
    await loadInterfaceList();
  });

  $('#iface-node')?.addEventListener('change', async (e) => {
    IFACE_NODE = Number(e.target.value || 0) || null;
    await loadNodeIfaces(IFACE_NODE);
    statusPollNode();
  });

  $('#iface-save')?.addEventListener('click', async () => {
    if (IFACE_SCOPE !== 'local') return; 
    const iid = $('#iface-select')?.value; if (!iid) return;
    const payload = {
      listen_port: Number($('#i-listen')?.value || 0) || null,
      dns:   ($('#i-dns')?.value || '').trim() || null,
      mtu:   Number($('#i-mtu')?.value || 0) || null
    };
    try {
      await jfetch(`/api/iface/${iid}`, { method:'POST', body: payload });
      toast('Interface saved', 'success');
      refreshIfaceStatusLocal(iid);
    } catch (e) { toast('Save failed: ' + e.message, 'error'); }
  });

  async function toggleIface(action, elId) {
    const btn = document.getElementById(elId);
    const scope  = btn?.dataset.scope || IFACE_SCOPE;
    const target = btn?.dataset.target || ($('#iface-select')?.value || '');

    try {
      if (scope === 'local') {
        await jfetch(`/api/iface/${target}/${action}`, { method:'POST' });
      } else {
        await jfetch(`/api/nodes/${IFACE_NODE}/iface/${encodeURIComponent(target)}/${action}`, { method:'POST' });
      }
      toast(scope === 'local' ? `Interface ${action} on local` : `Interface ${action} on node`, 'success');
    } catch (e) { toast(`Failed to bring ${action}: ` + e.message, 'error'); }

    if (scope === 'local') {
      await loadIfaceLocal(target);
      refreshIfaceStatusLocal(target);
    } else {
      await loadNodeIfaces(IFACE_NODE);
      await loadIfaceNode(target);
    }
  }

  $('#iface-up')  ?.addEventListener('click', () => toggleIface('up',   'iface-up'));
  $('#iface-down')?.addEventListener('click', () => toggleIface('down', 'iface-down'));

  function syncIfLogSelector() {
    const source = $('#iface-select'), target = $('#iflog-select');
    if (!source || !target) return;
    target.innerHTML = source.innerHTML;
    target.value     = source.value;
  }
  window.syncIfLogSelector = syncIfLogSelector;
})();

(function ifaceLogs() {
  let RAW_TEXT = '';
  const $  = (s, r = document) => r.querySelector(s);
  const toast = (m, t='info') => (window.toastSafe ? window.toastSafe(m, t) : alert(m));
  const colorize  = window.colorize  || ((t)=>t);
  const highlight = window.highlight || ((t)=>t);
  const saveScope = window.saveScope || (()=>{});
  const readScope = window.readScope || (()=>'local');

  let pre = document.getElementById('iface-logs-pre');

  function currentLog() {
    let scope = window.IFLOG_SCOPE || readScope() || 'local';
    if (scope !== 'local' && scope !== 'node') scope = 'local';

    if (scope === 'node') {
      const nodeOpt  = $('#iflog-node')?.selectedOptions?.[0] || null;
      const ifaceOpt = $('#iflog-select')?.selectedOptions?.[0] || null;
      return {
        scope,
        nodeLabel: (nodeOpt?.textContent || '').trim(),
        ifaceLabel: (ifaceOpt?.textContent || '').trim()
      };
    }

    const ifaceOpt =
      $('#iflog-select')?.selectedOptions?.[0] ||
      $('#iface-select')?.selectedOptions?.[0] ||
      null;

    return {
      scope: 'local',
      nodeLabel: '',
      ifaceLabel: (ifaceOpt?.textContent || '').trim()
    };
  }

  function updateLog() {
    const { scope, nodeLabel, ifaceLabel } = currentLog();
    const subtitle = $('#iface-log-subtitle');
    const chipNode = $('#iflog-nodechip');
    const chipIface = $('#iflog-ifacechip');

    if (subtitle) {
      if (scope === 'node' && nodeLabel && ifaceLabel) {
        subtitle.textContent = `${nodeLabel} • ${ifaceLabel}`;
      } else if (ifaceLabel) {
        subtitle.textContent = `Device: ${ifaceLabel}`;
      } else {
        subtitle.textContent = '';
      }
    }

    if (chipIface) {
      chipIface.textContent = ifaceLabel || '—';
    }

    if (chipNode) {
      if (scope === 'node' && nodeLabel) {
        chipNode.hidden = false;
        chipNode.textContent = nodeLabel;
      } else {
        chipNode.hidden = true;
      }
    }
  }

  function safeName(s, fallback) {
    const base = (s || fallback || '').trim() || 'log';
    return base
      .normalize('NFKD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/\s+/g, '_')
      .replace(/[^a-zA-Z0-9_.-]/g, '');
  }

  updateLog();
    function humanDate() {
      return _panelFileStamp();
    }


  async function loadLogsScope() {
    pre = document.getElementById('iface-logs-pre'); 
    if (!pre) return;

    pre.textContent = 'Loading…';

    try {
      let data;
      let scope = window.IFLOG_SCOPE || readScope() || 'local';
      if (scope !== 'local' && scope !== 'node') scope = 'local';
      window.IFLOG_SCOPE = scope;

      if (scope === 'node') {

        const nodeId = window.IFLOG_NODE || Number($('#iflog-node')?.value || 0) || null;
        const ifaceName = window.IFLOG_IFACE || $('#iflog-select')?.value || null;

        if (!nodeId || !ifaceName) {
          pre.textContent = 'Select a node and interface to view logs.';
          updateLog();
          return;
        }

        const url = `/api/nodes/${encodeURIComponent(nodeId)}/iface/${encodeURIComponent(ifaceName)}/logs`;
        data = await jfetch(url).catch(() => ({}));
      } else {

        const id = window.IFLOG_IFACE || $('#iflog-select')?.value || $('#iface-select')?.value;
        if (!id) {
          pre.textContent = 'No interface selected.';
          updateLog();
          return;
        }
        data = await jfetch(`/api/iface/${id}/logs`).catch(() => ({}));
      }

      const toText = (j) => {
        if (typeof j?.text === 'string') return j.text;
        if (Array.isArray(j?.logs)) {
          return j.logs.map(x => {
            if (typeof x === 'string') return x;
            const rawTs = x.ts || x.time || x.timestamp || '';
            const convertedTs = rawTs ? _fmtLocal(rawTs) : '';
            const ts = x.time_display || (convertedTs && convertedTs !== '—' ? convertedTs : rawTs);
            const lvl = (x.level || x.lvl || '').toString().toUpperCase();
            const msg = x.msg || x.message || x.text || JSON.stringify(x);
            return `${ts ? '[' + ts + '] ' : ''}${lvl ? lvl + ' ' : ''}${msg}`;
          }).join('\n');
        }
        if (typeof j?.logs === 'string') return j.logs;
        return '(no logs yet)';
      };

      RAW_TEXT = toText(data);
      pre.innerHTML = colorize(RAW_TEXT);
      pre.scrollTop = pre.scrollHeight;
      updateLog();
    } catch (e) {
      pre.textContent = 'Failed to load logs.';
      toast('Failed to load logs', 'error');
    }
  }

  window.loadLogsScope = loadLogsScope;

  $('#iflog-wrap')?.addEventListener('click', (e) => {
    if (!pre) return;
    pre.classList.toggle('is-wrapped');
    const on = pre.classList.contains('is-wrapped');
    e.currentTarget.setAttribute('aria-pressed', on ? 'true' : 'false');
    e.currentTarget.title = on ? 'Wrap: ON' : 'Wrap: OFF';
  });

  $('#iflog-copy')?.addEventListener('click', async () => {
    const text = pre ? pre.innerText : '';
    try { await navigator.clipboard.writeText(text); }
    catch {
      const ta = document.createElement('textarea'); ta.value = text;
      document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
    }
    toast('Copied to clipboard', 'success');
  });

    $('#iflog-dl')?.addEventListener('click', () => {
    const ctx = currentLog();
    const nodePart  = ctx.scope === 'node' ? safeName(ctx.nodeLabel, 'node') : null;
    const ifacePart = safeName(ctx.ifaceLabel, 'interface');
    const baseName  = nodePart ? `${nodePart}_${ifacePart}` : ifacePart;

    const stamp = humanDate();

    const blob = new Blob([pre?.innerText || ''], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${baseName}__${stamp}.log`;
    document.body.appendChild(a);
    a.click();
    URL.revokeObjectURL(a.href);
    a.remove();
  });


  const deb = (fn, ms = 120) => {
    let t; return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
  };

  $('#iflog-q')?.addEventListener('input', deb((e) => {
    const q = e.target.value.trim();
    if (!pre) return;
    pre.innerHTML = highlight(colorize(RAW_TEXT), q);
  }));

  $('#iflog-scope-local')?.addEventListener('change', async (e) => {
    if (!e.target.checked) return;
    window.IFLOG_SCOPE = 'local';
    saveScope(window.IFLOG_SCOPE);
    $('#iflog-node')?.setAttribute('hidden', '');
    if (typeof window.syncIfLogSelector === 'function') window.syncIfLogSelector();
    window.IFLOG_IFACE = $('#iflog-select')?.value || $('#iface-select')?.value || null;
    updateLog();
    await loadLogsScope();
  });

  $('#iflog-scope-node')?.addEventListener('change', async (e) => {
    if (!e.target.checked) return;
    window.IFLOG_SCOPE = 'node';
    saveScope(window.IFLOG_SCOPE);
    $('#iflog-node')?.removeAttribute('hidden');
    if (typeof window.loadNodesForLogs === 'function') {
      await window.loadNodesForLogs();
      window.IFLOG_NODE = Number($('#iflog-node')?.value || 0) || null;
      if (typeof window.loadNodeIfacesForLogs === 'function') {
        await window.loadNodeIfacesForLogs(window.IFLOG_NODE);
      }
    }
    window.IFLOG_IFACE = $('#iflog-select')?.value || null;
    updateLog();
    await loadLogsScope();
  });

  $('#iflog-node')?.addEventListener('change', async (e) => {
    window.IFLOG_NODE = Number(e.target.value || 0) || null;
    if (typeof window.loadNodeIfacesForLogs === 'function') {
      await window.loadNodeIfacesForLogs(window.IFLOG_NODE);
    }
    window.IFLOG_IFACE = $('#iflog-select')?.value || null;
    updateLog();
    await loadLogsScope();
  });

  $('#iflog-select')?.addEventListener('change', async (e) => {
    window.IFLOG_IFACE = e.target.value;  
    updateLog();
    await loadLogsScope();
  });

  $('#open-logs')?.addEventListener('click', async () => {
    const last = readScope();
    document.getElementById(last === 'node' ? 'iflog-scope-node' : 'iflog-scope-local')?.click();

    if (typeof window.syncIfLogSelector === 'function') window.syncIfLogSelector();
    window.IFLOG_IFACE = $('#iflog-select')?.value || $('#iface-select')?.value || null;

    const preEl = document.getElementById('iface-logs-pre');
    const wrapBtn = document.getElementById('iflog-wrap');
    const on = preEl?.classList.contains('is-wrapped');
    if (wrapBtn) {
      wrapBtn.setAttribute('aria-pressed', on ? 'true' : 'false');
      wrapBtn.setAttribute('title', on ? 'Wrap: ON' : 'Wrap: OFF');
    }

    if (typeof window.openModal === 'function') {
      window.openModal('iface-logs-modal');
    } else {

      const m = $('#iface-logs-modal');
      if (m) m.classList.add('is-open');
    }

    updateLog();
    await loadLogsScope();
  });

  $('#iflog-refresh')?.addEventListener('click', async () => {
    updateLog();
    await loadLogsScope();
  });
})();


  (function securitySettings() {
    const $s = (id) => document.getElementById(id);
    let lastTelegram = null;
    let trustedNetworks = [];
    let denyNetworks = [];
    let temporaryAllows = [];
    let lastSecurityPayload = null;
    let firewallCapability = {};
    let advancedDirty = false;
    let advancedSnapshot = null;
    const dirtySecuritySelects = new Set();
    const dirtySecurityBooleans = new Set();
    const dirtyTelegramToggles = new Set();
    let applyingSecurityFromServer = false;

    const booleanIds = {
      enabled: 'sec-enabled',
      escalate: 'sec-escalate',
      enrich_ip: 'sec-enrich-ip',
      firewall_enabled: 'sec-firewall-enabled'
    };
    const selectIds = {
      response_mode: 'sec-response-mode',
      ip_source: 'sec-ip-source',
      block_scope: 'sec-block-scope'
    };
    const numberIds = {
      threshold: 'sec-threshold',
      sensitive_threshold: 'sec-sensitive-threshold',
      rate_limit_threshold: 'sec-rate-limit-threshold',
      login_threshold: 'sec-login-threshold',
      firewall_after_offenses: 'sec-firewall-after'
    };
    const timeFields = {
      window_seconds: { hidden:'sec-window', value:'sec-window-value', unit:'sec-window-unit', fallback:60 },
      cooldown_seconds: { hidden:'sec-cooldown', value:'sec-cooldown-value', unit:'sec-cooldown-unit', fallback:600 },
      block_seconds: { hidden:'sec-block-seconds', value:'sec-block-value', unit:'sec-block-unit', fallback:900 },
      max_block_seconds: { hidden:'sec-max-block-seconds', value:'sec-max-block-value', unit:'sec-max-block-unit', fallback:86400 },
      login_window_seconds: { hidden:'sec-login-window', value:'sec-login-window-value', unit:'sec-login-window-unit', fallback:600 }
    };

    function escapeHtml(value) {
      return String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
    }

    function humanSeconds(raw) {
      let n = Math.max(0, Math.floor(Number(raw || 0)));
      if (!n) return '0m';
      const d = Math.floor(n / 86400); n %= 86400;
      const h = Math.floor(n / 3600); n %= 3600;
      const m = Math.floor(n / 60); const sec = n % 60;
      const out = [];
      if (d) out.push(`${d}d`);
      if (h) out.push(`${h}h`);
      if (m) out.push(`${m}m`);
      if (sec && !d && !h) out.push(`${sec}s`);
      return out.slice(0, 2).join(' ') || '<1m';
    }

    function bestTimeParts(seconds) {
      let n = Math.max(60, Math.round(Number(seconds || 60)));
      if (n % 86400 === 0) return { value:n/86400, unit:86400 };
      if (n % 3600 === 0) return { value:n/3600, unit:3600 };
      return { value:Math.max(1, Math.round(n/60)), unit:60 };
    }

    function setTimeField(name, seconds) {
      const f = timeFields[name]; if (!f) return;
      const parts = bestTimeParts(seconds ?? f.fallback);
      if ($s(f.value)) $s(f.value).value = String(parts.value);
      if ($s(f.unit)) {
        $s(f.unit).value = String(parts.unit);
        $s(f.unit).dispatchEvent(new Event('change', { bubbles: true }));
      }
      syncTimeField(name);
    }

    function syncTimeField(name) {
      const f = timeFields[name]; if (!f) return f?.fallback || 60;
      const amount = Math.max(1, Number($s(f.value)?.value || 1));
      const unit = Math.max(60, Number($s(f.unit)?.value || 60));
      const seconds = Math.round(amount * unit);
      if ($s(f.hidden)) $s(f.hidden).value = String(seconds);
      return seconds;
    }

    function syncAllTimeFields() {
      Object.keys(timeFields).forEach(syncTimeField);
    }

    function selectedCustomValue(id, fallback = '') {
      const select = $s(id);
      if (!select) return fallback;
      const wrap = select.closest('.set-select');
      const selectedItem = wrap?.querySelector('.set-select__option[aria-selected="true"]');
      return String(selectedItem?.dataset?.value ?? select.value ?? fallback);
    }

    function setSelectValueAndSync(id, value) {
      const select = $s(id);
      if (!select) return;
      const wanted = String(value ?? '');
      const options = Array.from(select.options || []);
      const index = options.findIndex(opt => String(opt.value) === wanted);
      if (index >= 0) {
        select.selectedIndex = index;
        options.forEach((opt, i) => { opt.selected = i === index; });
      }
      select.value = wanted;
      select.dispatchEvent(new Event('change', { bubbles: true }));
    }

    function renderStats(stats) {
      stats = stats || {};
      const pill = $s('sec-status-24h');
      if (pill) {
        const events = Number(stats.monitor_triggers || 0) + Number(stats.blocks || 0);
        pill.innerHTML = `<i class="fa-solid fa-chart-simple"></i> 24h ${events} trigger${events === 1 ? '' : 's'} · ${Number(stats.blocks || 0)} block${Number(stats.blocks || 0) === 1 ? '' : 's'}`;
        pill.className = 'sec-state ' + (Number(stats.blocks || 0) ? 'warn' : 'neutral');
      }
      const map = {
        'sec-stat-rejected': stats.rejected,
        'sec-stat-sensitive': stats.sensitive,
        'sec-stat-blocks': stats.blocks,
        'sec-stat-logins': stats.login_failures,
        'sec-stat-ips': stats.unique_ips
      };
      Object.entries(map).forEach(([id, value]) => { if ($s(id)) $s(id).textContent = String(Number(value || 0)); });
    }

    function setStatus(settings, blocks, stats) {
      const enabled = !!settings.enabled;
      const blocking = settings.response_mode === 'block';
      const monitor = $s('sec-status-monitor');
      const response = $s('sec-status-response');
      const engine = $s('sec-engine-pill');
      const blockPill = $s('sec-status-blocks');
      if (monitor) { monitor.innerHTML = `<i class="fa-solid fa-circle"></i> ${enabled ? 'Monitoring' : 'Disabled'}`; monitor.className = 'sec-state ' + (enabled ? 'good' : 'neutral'); }
      if (response) { response.innerHTML = `<i class="fa-solid fa-shield"></i> ${blocking ? 'Blocking' : 'Monitor only'}`; response.className = 'sec-state ' + (blocking ? 'good' : 'neutral'); }
      if (engine) { engine.textContent = enabled ? 'Enabled' : 'Disabled'; engine.className = 'sec-pill ' + (enabled ? 'good' : 'neutral'); }
      if (blockPill) { const n = Array.isArray(blocks) ? blocks.length : 0; blockPill.innerHTML = `<i class="fa-solid fa-ban"></i> ${n} active block${n === 1 ? '' : 's'}`; blockPill.className = 'sec-state ' + (n ? 'danger' : 'good'); }
      renderStats(stats);
    }

    function updateHumanHints() {
      syncAllTimeFields();
      const items = [
        ['window_seconds','sec-window-human','Rolling window'],
        ['cooldown_seconds','sec-cooldown-human','Alert cooldown'],
        ['block_seconds','sec-block-human','First offense'],
        ['max_block_seconds','sec-max-block-human','Maximum'],
        ['login_window_seconds','sec-login-window-human','Login window']
      ];
      for (const [name, hintId, label] of items) {
        const f = timeFields[name]; const hint = $s(hintId);
        if (f && hint) hint.textContent = `${label}: ${humanSeconds($s(f.hidden)?.value || f.fallback)}`;
      }
      updateEscalationPreview();
    }

    function updateEscalationPreview() {
      const host = $s('sec-escalation-preview'); if (!host) return;
      const base = Math.max(60, Number($s('sec-block-seconds')?.value || 900));
      const max = Math.max(base, Number($s('sec-max-block-seconds')?.value || 86400));
      const escalating = !!$s('sec-escalate')?.checked;
      const values = [];
      for (let i=0;i<5;i++) values.push(humanSeconds(Math.min(max, escalating ? base * (2 ** i) : base)));
      const span = host.querySelector('span');
      if (span) span.textContent = escalating ? `${values.join(' → ')} … capped at ${humanSeconds(max)}` : `Every offense: ${humanSeconds(base)}`;
    }

    function updateIpSourceHelp() {
      const effective = selectedCustomValue('sec-ip-source', 'direct') === 'effective';
      const help = $s('sec-ip-source-help');
      if (!help) return;
      help.textContent = effective
        ? 'Use only when direct access to Flask is restricted to a trusted reverse proxy or CDN.'
        : 'Recommended when the panel is reached directly; headers cannot override the socket address.';
      help.classList.toggle('is-warning', effective);
    }

    function renderNetworkChips(hostId, list, kind) {
      const host = $s(hostId); if (!host) return;
      host.innerHTML = '';
      if (!list.length) {
        host.innerHTML = `<span class="sec-trust-empty"><i class="fa-solid fa-shield"></i> ${kind === 'deny' ? 'No permanent deny entries.' : 'No trusted addresses — every valid client IP is eligible for temporary blocking.'}</span>`;
        return;
      }
      list.forEach((network, index) => {
        const chip = document.createElement('span');
        chip.className = 'sec-cidr-chip ' + (kind === 'deny' ? 'is-deny' : '');
        chip.innerHTML = `<i class="fa-solid ${kind === 'deny' ? 'fa-ban' : 'fa-shield-check'}"></i><code>${escapeHtml(network)}</code><button type="button" class="sec-cidr-remove" data-kind="${kind}" data-index="${index}" aria-label="Remove ${escapeHtml(network)}" title="Remove"><i class="fa-solid fa-xmark"></i></button>`;
        host.appendChild(chip);
      });
    }

    function renderTrustedChips() { renderNetworkChips('sec-trusted-chips', trustedNetworks, 'trusted'); }
    function renderDenyChips() { renderNetworkChips('sec-deny-chips', denyNetworks, 'deny'); }

    function addNetworkFromInput(inputId, list, render, duplicateMessage) {
      const input = $s(inputId); if (!input) return;
      const value = input.value.trim(); if (!value) return;
      if (list.some(v => v.toLowerCase() === value.toLowerCase())) { toast(duplicateMessage, 'warn'); return; }
      list.push(value); input.value = ''; render();
    }

    function renderTempAllows(rows) {
      temporaryAllows = Array.isArray(rows) ? rows : [];
      const host = $s('sec-temp-allow-list'); if (!host) return;
      host.innerHTML = '';
      if (!temporaryAllows.length) {
        host.innerHTML = '<span class="sec-trust-empty"><i class="fa-solid fa-clock"></i> No temporary allow entries.</span>';
        return;
      }
      const now = Date.now() / 1000;
      temporaryAllows.forEach(row => {
        const remain = Math.max(0, Number(row.expires_at || 0) - now);
        const chip = document.createElement('span'); chip.className = 'sec-temp-allow-chip';
        chip.innerHTML = `<span><i class="fa-solid fa-clock"></i><code>${escapeHtml(row.network || '')}</code><small>${humanSeconds(remain)} left</small></span><button type="button" data-temp-allow-remove="${escapeHtml(row.network || '')}" aria-label="Remove temporary allow"><i class="fa-solid fa-xmark"></i></button>`;
        host.appendChild(chip);
      });
    }

    function markAdvancedDirty(on = true) {
      advancedDirty = !!on;
      const state = $s('sec-advanced-save-state');
      const badge = $s('sec-advanced-badge');
      if (state) {
        state.classList.toggle('is-dirty', advancedDirty);
        state.innerHTML = advancedDirty
          ? '<i class="fa-solid fa-circle-exclamation"></i> Unsaved advanced changes · Temporary Allow entries still apply immediately.'
          : '<i class="fa-solid fa-circle-check"></i> Saved policy · Temporary Allow entries apply immediately.';
      }
      if (badge && advancedDirty) {
        badge.textContent = 'Unsaved';
        badge.classList.add('is-dirty');
      }
    }

    function captureAdvancedSnapshot() {
      return {
        block_scope: selectedCustomValue('sec-block-scope', 'all'),
        rate_limit_threshold: $s('sec-rate-limit-threshold')?.value ?? '',
        enrich_ip: !!$s('sec-enrich-ip')?.checked,
        login_threshold: $s('sec-login-threshold')?.value ?? '',
        login_window_value: $s('sec-login-window-value')?.value ?? '',
        login_window_unit: $s('sec-login-window-unit')?.value ?? '60',
        firewall_enabled: !!$s('sec-firewall-enabled')?.checked,
        firewall_after: $s('sec-firewall-after')?.value ?? '',
        deny_networks: [...denyNetworks],
        tg_security_block: !!$s('tg-n-security-block')?.checked,
        tg_security_release: !!$s('tg-n-security-release')?.checked,
        tg_security_auto_release: !!$s('tg-n-security-auto-release')?.checked
      };
    }

    function clearAdvancedDirtyFlags() {
      dirtySecuritySelects.delete('sec-block-scope');
      dirtySecurityBooleans.delete('sec-enrich-ip');
      dirtySecurityBooleans.delete('sec-firewall-enabled');
      dirtyTelegramToggles.delete('tg-n-security-block');
      dirtyTelegramToggles.delete('tg-n-security-release');
      dirtyTelegramToggles.delete('tg-n-security-auto-release');
    }

    function restoreAdvancedSnapshot(snapshot) {
      if (!snapshot) return;
      applyingSecurityFromServer = true;
      try {
        setSelectValueAndSync('sec-block-scope', snapshot.block_scope ?? 'all');
        if ($s('sec-rate-limit-threshold')) $s('sec-rate-limit-threshold').value = snapshot.rate_limit_threshold ?? '';
        if ($s('sec-enrich-ip')) $s('sec-enrich-ip').checked = !!snapshot.enrich_ip;
        if ($s('sec-login-threshold')) $s('sec-login-threshold').value = snapshot.login_threshold ?? '';
        if ($s('sec-login-window-value')) $s('sec-login-window-value').value = snapshot.login_window_value ?? '';
        if ($s('sec-login-window-unit')) {
          $s('sec-login-window-unit').value = String(snapshot.login_window_unit ?? '60');
          $s('sec-login-window-unit').dispatchEvent(new Event('change', { bubbles: true }));
        }
        syncTimeField('login_window_seconds');
        if ($s('sec-firewall-enabled')) $s('sec-firewall-enabled').checked = !!snapshot.firewall_enabled;
        if ($s('sec-firewall-after')) $s('sec-firewall-after').value = snapshot.firewall_after ?? '';
        denyNetworks = Array.isArray(snapshot.deny_networks) ? [...snapshot.deny_networks] : [];
        renderDenyChips();
        if ($s('tg-n-security-block')) $s('tg-n-security-block').checked = !!snapshot.tg_security_block;
        if ($s('tg-n-security-release')) $s('tg-n-security-release').checked = !!snapshot.tg_security_release;
        if ($s('tg-n-security-auto-release')) $s('tg-n-security-auto-release').checked = !!snapshot.tg_security_auto_release;
      } finally {
        applyingSecurityFromServer = false;
      }
      clearAdvancedDirtyFlags();
      updateHumanHints();
      renderFirewallStatus(firewallCapability);
      renderAdvancedSummary();
      markAdvancedDirty(false);
    }

    function cancelAdvancedChanges() {
      restoreAdvancedSnapshot(advancedSnapshot);
      closeModal('sec-advanced-modal');
    }

    function advancedStatusText() {
      const bits = [];
      if ($s('sec-enrich-ip')?.checked) bits.push('Geo');
      if ($s('sec-firewall-enabled')?.checked && firewallCapability?.usable) bits.push('nft');
      if (denyNetworks.length) bits.push(`${denyNetworks.length} deny`);
      if (temporaryAllows.length) bits.push(`${temporaryAllows.length} allow`);
      return bits.length ? bits.join(' · ') : 'Configured';
    }

    function renderAdvancedSummary() {
      const scope = selectedCustomValue('sec-block-scope', 'all');
      const loginThreshold = Number($s('sec-login-threshold')?.value || 5);
      const loginWindow = Number($s('sec-login-window')?.value || 600);
      const geoOn = !!$s('sec-enrich-ip')?.checked;
      const fwConfigured = !!$s('sec-firewall-enabled')?.checked;
      const fwUsable = !!firewallCapability?.usable;

      const setChip = (id, html, tone='') => {
        const el = $s(id); if (!el) return;
        el.innerHTML = html;
        el.className = 'sec-adv-chip' + (tone ? ` ${tone}` : '');
      };
      setChip('sec-adv-status-scope', `<i class="fa-solid fa-shield"></i> ${scope === 'auth_admin' ? 'Auth/admin only' : 'Entire panel'}`);
      setChip('sec-adv-status-login', `<i class="fa-solid fa-key"></i> Login ${loginThreshold}/${humanSeconds(loginWindow)}`, 'is-good');
      setChip('sec-adv-status-geo', `<i class="fa-solid fa-earth-europe"></i> Geo/ASN ${geoOn ? 'on' : 'off'}`, geoOn ? 'is-good' : 'is-neutral');
      setChip('sec-adv-status-firewall', `<i class="fa-solid fa-shield-halved"></i> nftables ${fwConfigured ? (fwUsable ? 'on' : 'unavailable') : (fwUsable ? 'off' : 'unavailable')}`, fwConfigured && fwUsable ? 'is-good' : (!fwUsable ? 'is-warn' : 'is-neutral'));
      setChip('sec-adv-status-deny', `<i class="fa-solid fa-ban"></i> Deny ${denyNetworks.length}`, denyNetworks.length ? 'is-danger' : 'is-neutral');
      setChip('sec-adv-status-allow', `<i class="fa-solid fa-clock"></i> Allow ${temporaryAllows.length}`, temporaryAllows.length ? 'is-good' : 'is-neutral');

      const badge = $s('sec-advanced-badge');
      if (badge && !advancedDirty) {
        badge.textContent = advancedStatusText();
        badge.classList.remove('is-dirty');
      }
    }

    function renderFirewallStatus(status) {
      const host = $s('sec-firewall-status'); if (!host) return;
      status = status || {};
      firewallCapability = status;
      const available = !!status.available;
      const usable = !!status.usable;
      const toggle = $s('sec-firewall-enabled');
      const remedy = $s('sec-firewall-remedy');
      const remedyTitle = $s('sec-firewall-remedy-title');
      const remedyText = $s('sec-firewall-remedy-text');
      const remedyCommand = $s('sec-firewall-remedy-command');

      host.className = 'sec-firewall-status ' + (usable ? 'is-good' : 'is-warn');
      if (usable) {
        host.innerHTML = '<i class="fa-solid fa-circle-check"></i><span>nftables ready · WG Panel can manage its dedicated temporary-block table</span>';
        if (remedy) remedy.hidden = true;
        if (toggle) { toggle.disabled = false; toggle.removeAttribute('aria-disabled'); }
      } else {
        const reason = String(status.reason || (available ? 'permission_denied' : 'not_installed'));
        const detail = String(status.detail || '').trim();
        host.innerHTML = available
          ? '<i class="fa-solid fa-triangle-exclamation"></i><span>nftables is installed but WG Panel cannot manage firewall rules · application blocking still works</span>'
          : '<i class="fa-solid fa-triangle-exclamation"></i><span>nftables is not installed · application blocking still works</span>';

        if (toggle) {
          if (!toggle.checked) toggle.disabled = true;
          else toggle.disabled = false;
          toggle.setAttribute('aria-disabled', toggle.checked ? 'false' : 'true');
        }
        if (remedy) remedy.hidden = false;
        if (remedyTitle) remedyTitle.textContent = available ? 'Firewall permission is unavailable' : 'Install nftables to enable host-firewall escalation';
        if (remedyText) remedyText.textContent = available
          ? (detail || 'Keep host-firewall escalation off unless the WG Panel service has permission to manage nftables. Application quarantine remains active.')
          : 'WG Panel will not install packages automatically. Install nftables manually, then click Recheck.';
        const command = String(status.install_command || status.check_command || (available ? 'sudo nft list ruleset' : 'sudo apt-get update && sudo apt-get install -y nftables'));
        if (remedyCommand) remedyCommand.textContent = command;
      }
      renderAdvancedSummary();
    }

    async function refreshFirewallCapability(showToast = false) {
      try {
        const result = await jfetch('/api/security/http-protection/capabilities');
        renderFirewallStatus(result?.firewall || {});
        if (showToast) toast(result?.firewall?.usable ? 'nftables is ready.' : 'Host firewall is still unavailable. Application blocking remains active.', result?.firewall?.usable ? 'success' : 'warn');
      } catch (e) {
        if (showToast) toast('Could not recheck nftables: ' + (e?.message || 'unknown'), 'error');
      }
    }

    function renderBlocks(blocks) {
      const body = document.querySelector('#sec-blocks-table tbody');
      const tableWrap = $s('sec-blocks-table-wrap');
      const empty = $s('sec-blocks-empty');
      if (!body || !tableWrap || !empty) return;
      body.innerHTML = '';
      if (!Array.isArray(blocks) || !blocks.length) { tableWrap.hidden = true; empty.hidden = false; return; }
      empty.hidden = true; tableWrap.hidden = false;
      for (const block of blocks) {
        const tr = document.createElement('tr');
        const until = block.blocked_until ? new Date(Number(block.blocked_until) * 1000) : null;
        const category = String(block.category || '').replaceAll('_',' ');
        const network = block.geo || {};
        const networkText = [network.country_code, network.asn].filter(Boolean).join(' · ');
        tr.innerHTML = `
          <td><code class="sec-ip-code"><i class="fa-solid fa-user-lock"></i> ${escapeHtml(block.ip || '')}</code>${networkText ? `<small class="sec-ip-meta">${escapeHtml(networkText)}</small>` : ''}</td>
          <td><span class="sec-category">${escapeHtml(category || 'security trigger')}</span><span class="sec-reason">${escapeHtml(block.reason || 'Threshold reached')}</span>${block.firewall ? '<small class="sec-firewall-badge"><i class="fa-solid fa-shield"></i> host firewall</small>' : ''}</td>
          <td><span class="sec-offense">${Number(block.offenses || 1)}</span></td>
          <td>${until && !isNaN(until) ? escapeHtml(_fmtLocal(until)) : '—'}</td>
          <td><span class="sec-remaining"><i class="fa-regular fa-clock"></i> ${humanSeconds(block.remaining_seconds)}</span></td>
          <td><button class="btn secondary sm sec-unblock" type="button" data-ip="${escapeHtml(block.ip || '')}"><i class="fa-solid fa-unlock"></i> Release</button></td>`;
        body.appendChild(tr);
      }
    }

    function applyServerSettings(settings) {
      applyingSecurityFromServer = true;
      try {
        Object.entries(booleanIds).forEach(([key, id]) => {
          const el = $s(id);
          if (el && !dirtySecurityBooleans.has(id)) el.checked = !!settings[key];
        });
        Object.entries(selectIds).forEach(([key, id]) => { if (!dirtySecuritySelects.has(id)) setSelectValueAndSync(id, settings[key] ?? ''); });
        Object.entries(numberIds).forEach(([key, id]) => { const el = $s(id); if (el) el.value = settings[key] ?? ''; });
        Object.keys(timeFields).forEach(name => setTimeField(name, settings[name] ?? timeFields[name].fallback));
        trustedNetworks = Array.isArray(settings.trusted_networks) ? [...settings.trusted_networks] : [];
        denyNetworks = Array.isArray(settings.deny_networks) ? [...settings.deny_networks] : [];
        renderTrustedChips(); renderDenyChips(); updateHumanHints(); updateIpSourceHelp();
      } finally { applyingSecurityFromServer = false; }
      renderAdvancedSummary();
    }

    async function loadSecurity() {
      try {
        const [security, tg] = await Promise.all([jfetch('/api/security/http-protection'), jfetch('/api/telegram/settings')]);
        const settings = security?.settings || security || {}; const blocks = security?.active_blocks || [];
        lastSecurityPayload = security || {};
        lastTelegram = tg || {};
        applyServerSettings(settings);
        renderTempAllows(security?.temporary_allow || []);
        firewallCapability = security?.firewall || {};
        renderFirewallStatus(firewallCapability);
        const notify = tg?.notify || {};
        const notifyMap = {
          'tg-n-login-success': 'login_success',
          'tg-n-login-fail': 'login_fail',
          'tg-n-4xx': 'suspicious_4xx',
          'tg-n-security-block': 'security_block',
          'tg-n-security-release': 'security_release',
          'tg-n-security-auto-release': 'security_auto_release'
        };
        Object.entries(notifyMap).forEach(([id,key]) => {
          const el = $s(id);
          if (el && !dirtyTelegramToggles.has(id)) el.checked = !!notify[key];
        });
        renderBlocks(blocks); setStatus(settings, blocks, security?.stats_24h || {}); renderAdvancedSummary();
      } catch (e) { console.error(e); toast('Failed to load security settings: ' + (e?.message || 'unknown'), 'error'); }
    }

    function applyRecommended() {
      if ($s('sec-enabled')) $s('sec-enabled').checked = true;
      setSelectValueAndSync('sec-response-mode', 'monitor');
      setSelectValueAndSync('sec-ip-source', 'direct');
      setSelectValueAndSync('sec-block-scope', 'all');
      if ($s('sec-threshold')) $s('sec-threshold').value = '20';
      if ($s('sec-sensitive-threshold')) $s('sec-sensitive-threshold').value = '3';
      if ($s('sec-rate-limit-threshold')) $s('sec-rate-limit-threshold').value = '10';
      if ($s('sec-login-threshold')) $s('sec-login-threshold').value = '5';
      setTimeField('window_seconds', 60);
      setTimeField('login_window_seconds', 600);
      setTimeField('cooldown_seconds', 600);
      setTimeField('block_seconds', 900);
      setTimeField('max_block_seconds', 86400);
      if ($s('sec-escalate')) $s('sec-escalate').checked = true;
      if ($s('sec-enrich-ip')) $s('sec-enrich-ip').checked = false;
      if ($s('sec-firewall-enabled')) $s('sec-firewall-enabled').checked = false;
      if ($s('sec-firewall-after')) $s('sec-firewall-after').value = '3';
      if (!trustedNetworks.length) trustedNetworks = ['127.0.0.1/32','::1/128'];
      renderTrustedChips(); updateHumanHints(); updateIpSourceHelp();
      toast('Safe recommended values applied. Save to activate them.', 'info');
    }

    async function saveSecurity() {
      const buttons = [$s('sec-save'), $s('sec-advanced-save')].filter(Boolean);
      buttons.forEach(button => button.disabled = true);
      try {
        syncAllTimeFields();
        const securityBody = {
          enabled: !!$s('sec-enabled')?.checked,
          response_mode: selectedCustomValue('sec-response-mode', 'monitor'),
          ip_source: selectedCustomValue('sec-ip-source', 'direct'),
          block_scope: selectedCustomValue('sec-block-scope', 'all'),
          threshold: Number($s('sec-threshold')?.value || 20),
          window_seconds: Number($s('sec-window')?.value || 60),
          sensitive_threshold: Number($s('sec-sensitive-threshold')?.value || 3),
          rate_limit_threshold: Number($s('sec-rate-limit-threshold')?.value || 10),
          login_threshold: Number($s('sec-login-threshold')?.value || 5),
          login_window_seconds: Number($s('sec-login-window')?.value || 600),
          cooldown_seconds: Number($s('sec-cooldown')?.value || 600),
          block_seconds: Number($s('sec-block-seconds')?.value || 900),
          max_block_seconds: Number($s('sec-max-block-seconds')?.value || 86400),
          escalate: !!$s('sec-escalate')?.checked,
          enrich_ip: !!$s('sec-enrich-ip')?.checked,
          firewall_enabled: !!$s('sec-firewall-enabled')?.checked,
          firewall_after_offenses: Number($s('sec-firewall-after')?.value || 3),
          trusted_networks: [...trustedNetworks],
          deny_networks: [...denyNetworks]
        };
        const savedSecurity = await jfetch('/api/security/http-protection', { method: 'POST', body: securityBody });
        const savedSettings = savedSecurity?.settings || {};
        for (const key of ['response_mode','ip_source','block_scope']) {
          if (String(savedSettings[key] || '') !== String(securityBody[key])) throw new Error(`${key.replaceAll('_',' ')} was not persisted.`);
        }
        dirtySecuritySelects.clear();
        dirtySecurityBooleans.clear();
        markAdvancedDirty(false);
        applyServerSettings(savedSettings);
        renderTempAllows(savedSecurity?.temporary_allow || temporaryAllows);
        firewallCapability = savedSecurity?.firewall || {};
        renderFirewallStatus(firewallCapability);
        setStatus(savedSettings, savedSecurity?.active_blocks || [], savedSecurity?.stats_24h || {});

        const current = lastTelegram || await jfetch('/api/telegram/settings');
        const notify = { ...(current.notify || {}) };
        notify.login_success = !!$s('tg-n-login-success')?.checked;
        notify.login_fail = !!$s('tg-n-login-fail')?.checked;
        notify.suspicious_4xx = !!$s('tg-n-4xx')?.checked;
        notify.security_block = !!$s('tg-n-security-block')?.checked;
        notify.security_release = !!$s('tg-n-security-release')?.checked;
        notify.security_auto_release = !!$s('tg-n-security-auto-release')?.checked;
        await jfetch('/api/telegram/settings', { method: 'POST', body: { enabled: !!current.enabled, notify } });
        dirtyTelegramToggles.clear();
        toast('Security policy saved.', 'success');
        await loadSecurity();
      } catch (e) { console.error(e); toast('Security save failed: ' + (e?.message || 'unknown'), 'error'); }
      finally { buttons.forEach(button => button.disabled = false); }
    }

    async function addTemporaryAllow() {
      const input = $s('sec-temp-allow-input');
      const value = input?.value.trim() || '';
      if (!value) return;
      const amount = Math.max(1, Number($s('sec-temp-allow-duration-value')?.value || 1));
      const unit = Math.max(60, Number(selectedCustomValue('sec-temp-allow-duration-unit', '3600')) || 3600);
      try {
        const result = await jfetch('/api/security/http-protection/temporary-allow', { method:'POST', body:{ network:value, duration_seconds:Math.round(amount * unit) } });
        if (input) input.value = '';
        renderTempAllows(result?.temporary_allow || []);
        renderAdvancedSummary();
        toast(`${result.network || value} temporarily allowed.`, 'success');
        await loadHistory(false);
      } catch (e) { toast('Temporary allow failed: ' + (e?.message || 'unknown'), 'error'); }
    }

    async function loadHistory(showErrors = true) {
      try {
        const ip = ($s('sec-history-ip')?.value || '').trim();
        const type = selectedCustomValue('sec-history-type', '');
        const params = new URLSearchParams({ limit:'300' });
        if (ip) params.set('ip', ip);
        if (type) params.set('type', type);
        const result = await jfetch('/api/security/http-protection/events?' + params.toString());
        renderStats(result?.stats_24h || {});
        const rows = Array.isArray(result?.events) ? result.events : [];
        const body = document.querySelector('#sec-history-table tbody');
        const wrap = $s('sec-history-table-wrap'); const empty = $s('sec-history-empty');
        if (!body || !wrap || !empty) return;
        body.innerHTML = '';
        if (!rows.length) { wrap.hidden = true; empty.hidden = false; return; }
        wrap.hidden = false; empty.hidden = true;
        for (const row of rows) {
          const date = row.ts ? new Date(Number(row.ts) * 1000) : null;
          const geo = row.geo || {};
          const network = [geo.country_code, geo.asn, geo.provider].filter(Boolean).join(' · ');
          const tr = document.createElement('tr');
          tr.innerHTML = `<td>${date && !isNaN(date) ? escapeHtml(_fmtLocal(date)) : '—'}</td><td><code>${escapeHtml(row.ip || '—')}</code></td><td><span class="sec-event-type">${escapeHtml(String(row.type || 'event').replaceAll('_',' '))}</span></td><td>${escapeHtml(String(row.category || '—').replaceAll('_',' '))}</td><td>${escapeHtml(row.reason || '—')}</td><td>${escapeHtml(network || '—')}</td>`;
          body.appendChild(tr);
        }
      } catch (e) { if (showErrors) toast('History load failed: ' + (e?.message || 'unknown'), 'error'); }
    }

    document.addEventListener('click', async (event) => {
      const remove = event.target.closest('.sec-cidr-remove');
      if (remove) {
        const index = Number(remove.dataset.index); const kind = remove.dataset.kind;
        const list = kind === 'deny' ? denyNetworks : trustedNetworks;
        if (Number.isInteger(index) && index >= 0 && index < list.length) {
          list.splice(index,1);
          kind === 'deny' ? renderDenyChips() : renderTrustedChips();
          if (kind === 'deny') markAdvancedDirty(true);
          renderAdvancedSummary();
        }
        return;
      }
      const tempRemove = event.target.closest('[data-temp-allow-remove]');
      if (tempRemove) {
        const network = tempRemove.dataset.tempAllowRemove || '';
        try { const result = await jfetch('/api/security/http-protection/temporary-allow/remove', { method:'POST', body:{network} }); renderTempAllows(result?.temporary_allow || []); renderAdvancedSummary(); toast(`${network} removed from temporary allow.`, 'success'); }
        catch (e) { toast('Remove failed: ' + (e?.message || 'unknown'), 'error'); }
        return;
      }
      const unblock = event.target.closest('.sec-unblock'); if (!unblock) return;
      const ip = unblock.dataset.ip || ''; if (!ip) return;
      const ok = await confirmDialog({ title:'Release temporary block?', body:`Allow ${ip} to access the panel again immediately? Its offense counter remains for repeat-offender escalation.`, okText:'Release' });
      if (!ok) return;
      try { await jfetch('/api/security/http-protection/unban', { method:'POST', body:{ip} }); toast(`${ip} released`, 'success'); await loadSecurity(); await loadHistory(false); }
      catch (e) { toast('Release failed: ' + (e?.message || 'unknown'), 'error'); }
    });

    document.addEventListener('DOMContentLoaded', () => {
      $s('sec-save')?.addEventListener('click', saveSecurity);
      $s('sec-advanced-save')?.addEventListener('click', saveSecurity);
      $s('sec-refresh-blocks')?.addEventListener('click', loadSecurity);
      $s('sec-apply-recommended')?.addEventListener('click', applyRecommended);
      $s('sec-trusted-add')?.addEventListener('click', () => addNetworkFromInput('sec-trusted-input', trustedNetworks, renderTrustedChips, 'That trusted address is already listed.'));
      $s('sec-trusted-input')?.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); addNetworkFromInput('sec-trusted-input', trustedNetworks, renderTrustedChips, 'That trusted address is already listed.'); } });
      $s('sec-deny-add')?.addEventListener('click', () => { const before = denyNetworks.length; addNetworkFromInput('sec-deny-input', denyNetworks, renderDenyChips, 'That deny entry is already listed.'); if (denyNetworks.length !== before) { markAdvancedDirty(true); renderAdvancedSummary(); } });
      $s('sec-deny-input')?.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); const before = denyNetworks.length; addNetworkFromInput('sec-deny-input', denyNetworks, renderDenyChips, 'That deny entry is already listed.'); if (denyNetworks.length !== before) { markAdvancedDirty(true); renderAdvancedSummary(); } } });
      $s('sec-temp-allow-add')?.addEventListener('click', addTemporaryAllow);
      $s('sec-temp-allow-input')?.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); addTemporaryAllow(); } });
      Object.values(timeFields).forEach(f => { $s(f.value)?.addEventListener('input', updateHumanHints); $s(f.unit)?.addEventListener('change', updateHumanHints); });
      $s('sec-escalate')?.addEventListener('input', updateHumanHints);
      Object.values(selectIds).forEach(id => $s(id)?.addEventListener('change', () => {
        if (!applyingSecurityFromServer) dirtySecuritySelects.add(id);
        if (id === 'sec-ip-source') updateIpSourceHelp();
      }));
      Object.values(booleanIds).forEach(id => $s(id)?.addEventListener('change', () => {
        if (!applyingSecurityFromServer) dirtySecurityBooleans.add(id);
      }));

      const advancedPolicyIds = new Set([
        'sec-block-scope','sec-rate-limit-threshold','sec-enrich-ip','sec-login-threshold',
        'sec-login-window-value','sec-login-window-unit','sec-firewall-enabled','sec-firewall-after'
      ]);
      const advancedModal = $s('sec-advanced-modal');
      const advancedPolicyChanged = (event) => {
        const id = event?.target?.id || '';
        if (!id || !advancedPolicyIds.has(id) || applyingSecurityFromServer) return;
        if (id === 'sec-firewall-enabled' && event.target.checked && !firewallCapability?.usable) {
          event.target.checked = false;
          toast('Host-firewall escalation is unavailable. Application blocking remains active; use the nftables status box for the fix.', 'warn');
          renderFirewallStatus(firewallCapability);
          return;
        }
        markAdvancedDirty(true);
        renderAdvancedSummary();
      };
      advancedModal?.addEventListener('change', advancedPolicyChanged);
      advancedModal?.addEventListener('input', advancedPolicyChanged);
      ['tg-n-login-success','tg-n-login-fail','tg-n-4xx','tg-n-security-block','tg-n-security-release','tg-n-security-auto-release']
        .forEach(id => $s(id)?.addEventListener('change', () => {
          if (!applyingSecurityFromServer) {
            dirtyTelegramToggles.add(id);
            if (id.startsWith('tg-n-security-')) markAdvancedDirty(true);
          }
        }));
      document.querySelector('[data-tab="security"]')?.addEventListener('click', () => {
        if (!dirtySecuritySelects.size && !dirtySecurityBooleans.size && !dirtyTelegramToggles.size) loadSecurity();
      });

      $s('sec-advanced-trigger')?.addEventListener('click', async () => {
        if (!lastSecurityPayload) await loadSecurity();
        advancedSnapshot = captureAdvancedSnapshot();
        markAdvancedDirty(false);
        renderAdvancedSummary();
        openModal('sec-advanced-modal');
      });
      $s('sec-firewall-refresh')?.addEventListener('click', () => refreshFirewallCapability(true));
      $s('sec-firewall-copy')?.addEventListener('click', async () => {
        const text = ($s('sec-firewall-remedy-command')?.textContent || '').trim();
        if (!text) return;
        try { await navigator.clipboard.writeText(text); toast('Command copied.', 'success'); }
        catch { toast('Copy failed.', 'error'); }
      });

      const advancedInfoTrigger = $s('sec-advanced-info-trigger');
      const advancedInfo = $s('sec-advanced-info-popover');
      const advancedInfoClose = $s('sec-advanced-info-close');
      const closeAdvancedInfo = () => { if (!advancedInfo) return; advancedInfo.hidden = true; advancedInfoTrigger?.setAttribute('aria-expanded','false'); };
      advancedInfoTrigger?.addEventListener('click', event => { event.stopPropagation(); if (!advancedInfo) return; const open = !!advancedInfo.hidden; advancedInfo.hidden = !open; advancedInfoTrigger.setAttribute('aria-expanded', String(open)); });
      advancedInfoClose?.addEventListener('click', event => { event.stopPropagation(); closeAdvancedInfo(); });
      advancedInfo?.addEventListener('click', event => event.stopPropagation());
      $s('sec-alert-options-trigger')?.addEventListener('click', async () => {
        if (!lastSecurityPayload) await loadSecurity();
        openModal('sec-advanced-modal');
        setTimeout(() => $s('sec-alert-options-section')?.scrollIntoView({behavior:'smooth',block:'center'}), 80);
      });
      $s('sec-history-trigger')?.addEventListener('click', async () => { openModal('sec-history-modal'); await loadHistory(); });
      $s('sec-history-refresh')?.addEventListener('click', () => loadHistory());
      $s('sec-history-type')?.addEventListener('change', () => loadHistory(false));
      $s('sec-history-ip')?.addEventListener('keydown', e => { if (e.key === 'Enter') loadHistory(false); });
      $s('sec-history-clear')?.addEventListener('click', async () => {
        const ok = await confirmDialog({title:'Clear security event history?',body:'This removes retained security events. Active blocks, offense counters and 24-hour statistics are not cleared.',okText:'Clear history'});
        if (!ok) return;
        try { await jfetch('/api/security/http-protection/events', {method:'DELETE'}); toast('Security history cleared.', 'success'); await loadHistory(); }
        catch (e) { toast('Clear failed: ' + (e?.message || 'unknown'), 'error'); }
      });

      document.querySelectorAll('#sec-advanced-modal [data-close]').forEach(el => el.addEventListener('click', cancelAdvancedChanges));
      document.querySelectorAll('#sec-history-modal [data-close]').forEach(el => el.addEventListener('click', () => closeModal('sec-history-modal')));

      document.addEventListener('click', () => {
        const advancedInfo = $s('sec-advanced-info-popover');
        if (advancedInfo && !advancedInfo.hidden) { advancedInfo.hidden = true; $s('sec-advanced-info-trigger')?.setAttribute('aria-expanded','false'); }
      });

      const infoTrigger = $s('sec-info-trigger');
      const infoPopover = $s('sec-info-popover');
      const infoClose = $s('sec-info-close');
      const closeInfo = () => { if (!infoPopover) return; infoPopover.hidden = true; infoTrigger?.setAttribute('aria-expanded','false'); };
      const toggleInfo = (event) => { event?.stopPropagation(); if (!infoPopover) return; const willOpen = !!infoPopover.hidden; infoPopover.hidden = !willOpen; infoTrigger?.setAttribute('aria-expanded',String(willOpen)); };
      infoTrigger?.addEventListener('click', toggleInfo);
      infoClose?.addEventListener('click', event => { event.stopPropagation(); closeInfo(); });
      infoPopover?.addEventListener('click', event => event.stopPropagation());
      document.addEventListener('click', closeInfo);
      document.addEventListener('keydown', event => { if (event.key === 'Escape') closeInfo(); });

      loadSecurity();
    });
  })();


  (function telegram() {
    function fmtLocal(iso) {
      return _fmtLocal(iso);
    }

    function updateChips(state) {
      const enabled = !!state.enabled;
      const hasTok  = !!state.has_token;
      const admins  = Array.isArray(state.admins) ? state.admins.length : (state.admin_count || 0);
      const ce = $('#tg-chip-enabled'), ct = $('#tg-chip-token'), ca = $('#tg-chip-admins');
      if (ce) { ce.textContent = 'Notifications: ' + (enabled ? 'On' : 'Off'); ce.className = 'chip ' + (enabled ? 'green' : 'gray'); }
      if (ct) { ct.textContent = 'Token: ' + (hasTok ? 'Set' : 'Not set'); ct.className = 'chip ' + (hasTok ? 'green' : 'red'); }
      if (ca) { ca.textContent = 'Admins: ' + admins; ca.className = 'chip ' + (admins > 0 ? 'blue' : 'gray'); }
    }
    function updateStatusChips(st) {
      const b = $('#tg-chip-bot'), ls = $('#tg-chip-seen');
      if (b) { const on = !!st.bot_online; b.textContent = 'Bot: ' + (on ? 'Online' : 'Offline'); b.className = 'chip ' + (on ? 'green' : 'red'); }
      if (ls){ const has = !!st.last_seen; ls.textContent = 'Last seen: ' + (has ? fmtLocal(st.last_seen) : '—'); ls.className = 'chip ' + (has ? 'blue' : 'gray'); }
    }

    async function loadSettings() {
      try {
        const s = await jfetch('/api/telegram/settings');
        $('#tg-enabled').checked = !!s.enabled;
        $('#tg-token').value = '';
        $('#tg-token').placeholder = s.has_token ? '•••••• (token already set)' : '123456:ABC-DEF...';
        const n = s.notify || {};
        const setChecked = (id, value) => {
          const el = document.getElementById(id);
          if (el) el.checked = !!value;
        };

        setChecked('tg-n-app-down',       n.app_down);
        setChecked('tg-n-app-up',         n.app_up);
        setChecked('tg-n-node-down',      n.node_down);
        setChecked('tg-n-node-up',        n.node_up);
        setChecked('tg-n-iface-down',     n.iface_down);
        setChecked('tg-n-iface-up',       n.iface_up);
        setChecked('tg-n-peer-expired',   n.peer_expired);
        setChecked('tg-n-peer-limit',     n.peer_limit);
        setChecked('tg-n-backup-success', n.backup_success);
        setChecked('tg-n-backup-failed',  n.backup_failed);
        setChecked('tg-n-update-success', n.update_success);
        setChecked('tg-n-update-failed',  n.update_failed);
        updateChips({ enabled: s.enabled, has_token: s.has_token, admins: [] });
      } catch { toast('Failed to load Telegram settings', 'error'); }
    }
    async function saveSettings() {
      const payload = {
        enabled: $('#tg-enabled').checked,
        notify: {
          app_down:       !!$('#tg-n-app-down')?.checked,
          app_up:         !!$('#tg-n-app-up')?.checked,
          node_down:      !!$('#tg-n-node-down')?.checked,
          node_up:        !!$('#tg-n-node-up')?.checked,
          iface_down:     !!$('#tg-n-iface-down')?.checked,
          iface_up:       !!$('#tg-n-iface-up')?.checked,
          peer_expired:   !!$('#tg-n-peer-expired')?.checked,
          peer_limit:     !!$('#tg-n-peer-limit')?.checked,
          backup_success: !!$('#tg-n-backup-success')?.checked,
          backup_failed:  !!$('#tg-n-backup-failed')?.checked,
          update_success: !!$('#tg-n-update-success')?.checked,
          update_failed:  !!$('#tg-n-update-failed')?.checked
        }
      };
      try {
        await jfetch('/api/telegram/settings', { method:'POST', body: payload });
        toast('Telegram settings saved', 'success');
        updateChips({ enabled: payload.enabled, has_token: ($('#tg-token').placeholder.startsWith('•')), admins: [] });
      } catch (e) { toast('Save failed: ' + e.message, 'error'); }
    }
    async function updateToken() {
      const tok = ($('#tg-token').value || '').trim();
      if (!tok) { toast('Enter a bot token', 'error'); return; }
      try {
        await jfetch('/api/telegram/token', { method:'POST', body: { bot_token: tok } });
        $('#tg-token').value = '';
        $('#tg-token').placeholder = '•••••• (token already set)';
        toast('Bot token updated', 'success');
        updateChips({ enabled: $('#tg-enabled').checked, has_token: true, admins: [] });
      } catch (e) { toast('Token update failed: ' + e.message, 'error'); }
    }
    async function clearToken() {
      if (!await confirmDialog({ title:'Clear bot token?', body:'Notifications will stop until you set a new token.', okText:'Clear' })) return;
      try {
        await jfetch('/api/telegram/token', { method:'DELETE' });
        $('#tg-token').placeholder = '123456:ABC-DEF...';
        toast('Bot token cleared', 'success');
        updateChips({ enabled: $('#tg-enabled').checked, has_token: false, admins: [] });
      } catch (e) { toast('Clear failed: ' + e.message, 'error'); }
    }

    function notificationInputs() {
      return Array.from(
        document.querySelectorAll('#tg-acc-notify-body input[type="checkbox"]')
      );
    }

    function applyNotificationPreset(mode) {
      const criticalIds = new Set([
        'tg-n-app-down',
        'tg-n-node-down',
        'tg-n-iface-down',
        'tg-n-backup-failed',
        'tg-n-update-failed'
      ]);

      notificationInputs().forEach((input) => {
        input.checked =
          mode === 'all'
            ? true
            : mode === 'critical'
              ? criticalIds.has(input.id)
              : false;
      });
    }

    $('#tg-notify-critical')?.addEventListener('click', () =>
      applyNotificationPreset('critical')
    );
    $('#tg-notify-all')?.addEventListener('click', () =>
      applyNotificationPreset('all')
    );
    $('#tg-notify-none')?.addEventListener('click', () =>
      applyNotificationPreset('none')
    );

    async function loadStatus() {
      try { const j = await jfetch('/api/telegram/status'); updateStatusChips(j); } catch {}
    }

    function renderAdmins(list) {
      const tb = document.querySelector('#tg-admins-table tbody'); if (!tb) return;
      tb.innerHTML = '';
      (list || []).forEach(a => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${a.id}</td>
          <td>${a.username ? '@' + a.username : ''}</td>
          <td>${a.note || ''}</td>
          <td>
            <button class="pill ${a.muted ? 'gray' : 'green'} tg-mute-toggle" data-id="${a.id}" data-muted="${a.muted ? '1' : '0'}">${a.muted ? 'Muted' : 'Active'}</button>
          </td>
          <td>
            <button class="btn danger sm tg-del" data-id="${a.id}"><i class="fa-solid fa-trash"></i> Delete</button>
          </td>`;
        tb.appendChild(tr);
      });

      tb.querySelectorAll('.tg-mute-toggle').forEach(btn => {
        btn.addEventListener('click', async () => {
          const id = btn.dataset.id;
          const willMute = btn.dataset.muted !== '1';
          const row = btn.closest('tr');
          const username = (row.children[1].textContent || '').replace(/^@/, '');
          const note = row.children[2].textContent || '';
          try {
            await jfetch('/api/telegram/admins', { method:'POST', body:{ id, username, note, muted: willMute, status: willMute ? 'Muted' : 'Active' } });
            await loadAdmins();
          } catch { toast('Failed to update admin', 'error'); }
        });
      });
      tb.querySelectorAll('.tg-del').forEach(btn => {
        btn.addEventListener('click', async () => {
          const id = btn.dataset.id;
          if (!await confirmDialog({ title: 'Delete admin?', body: `Delete admin ${id}?`, okText: 'Delete' })) return;
          try { await deleteAdmin(id); toast('Admin deleted', 'success'); }
          catch { toast('Delete failed', 'error'); }
        });
      });

      const hasToken = ($('#tg-token')?.placeholder || '').startsWith('•');
      const enabled = !!$('#tg-enabled')?.checked;
      updateChips({ enabled, has_token: hasToken, admins: list });
    }
    async function loadAdmins() {
      try { const j = await jfetch('/api/telegram/admins'); renderAdmins(j.admins || []); }
      catch { toast('Failed to load admins', 'error'); }
    }
    async function addAdmin(id, username, note, muted = false) {
      const j = await jfetch('/api/telegram/admins', { method:'POST', body:{ id, username, note, muted, status: muted ? 'Muted' : 'Active' } });
      renderAdmins(j.admins || []);
    }
    async function deleteAdmin(id) {
      const j = await jfetch(`/api/telegram/admins/${encodeURIComponent(id)}`, { method:'DELETE' });
      renderAdmins(j.admins || []);
    }
    function addAdminSave() {
      const id = ($('#tg-new-id').value || '').trim();
      const usr = ($('#tg-new-username').value || '').trim().replace(/^@/, '');
      const note = ($('#tg-new-note').value || '').trim();
      if (!/^\d+$/.test(id)) { toast('Telegram ID must be numeric', 'error'); return; }
      addAdmin(id, usr, note, false).then(() => {
        $('#tg-new-id').value = ''; $('#tg-new-username').value = ''; $('#tg-new-note').value = '';
        toast('Admin saved', 'success'); closeModal('tg-add-modal');
      }).catch(e => toast('Save failed: ' + (e.message || e), 'error'));
    }

    function badge(kind) {
      const k = (kind || 'info').toLowerCase();
      const map = { error:{cls:'lvl-badge lvl-error',text:'ERROR'}, warning:{cls:'lvl-badge lvl-warning',text:'WARN'}, info:{cls:'lvl-badge lvl-info',text:'INFO'}, heartbeat:{cls:'lvl-badge lvl-heartbeat',text:'HEART'} };
      const m = map[k] || map.info; return `<span class="${m.cls}">${m.text}</span>`;
    }
    function escapeHtml(s) { return String(s).replace(/[&<>\"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
    function formatStamp(row) { return _formatStamp(row); }
    

    async function loadTgLogs() {
      const list = $('#tg-logs-list');
      const q = ($('#tg-q')?.value || '').trim();
      const level = ($('#tg-level')?.value || '').trim();
      const fromV = $('#tg-from')?.value || '';
      const toV   = $('#tg-to')?.value || '';
      const params = new URLSearchParams({ format:'json', limit:'800' });
      if (q) params.set('q', q); if (level) params.set('level', level);
      if (fromV) params.set('from', fromV); if (toV) params.set('to', toV);
      const j = await jfetch('/api/telegram/logs?' + params.toString()).catch(()=>({logs:[]}));
      const logs = Array.isArray(j.logs) ? j.logs : [];
      if (!logs.length) { list.innerHTML = `<div class="log-row" style="opacity:.7">(no logs yet)</div>`; return; }
      list.innerHTML = logs.map(x => {
        const dt = formatStamp(x);
        const ts = `<span class="log-ts">[${dt.text}] · ${dt.ago}</span>`;
        return `<div class="log-row">${ts}${badge(x.kind)} ${escapeHtml(x.text || '')}</div>`;
      }).join('');
      list.scrollTop = list.scrollHeight;
    }

    async function sendTest() {
      const payload = { text: 'Test notification from the panel' };
      const endpoints = [
        ['/api/telegram/test', 'POST'],
        ['/api/telegram/send-test', 'POST'],
        ['/api/telegram/message', 'POST']
      ];
      let lastErr = null;
      for (const [url, method] of endpoints) {
        try {
          const res = await fetch(url, { method, headers: csrf(true), credentials:'same-origin', body: JSON.stringify(payload) });
          if (!res.ok) throw new Error('HTTP ' + res.status);
          const j = await res.json().catch(() => ({}));
          if (j.ok === false) throw new Error(j.error || 'failed');
          toast('Test message sent to Telegram', 'success');
          return;
        } catch (e) { lastErr = e; }
      }
      toast('Failed to send test message: ' + (lastErr?.message || lastErr || 'error'), 'error');
    }

    $('#tg-save')?.addEventListener('click',   saveSettings);
    $('#tg-update-token')?.addEventListener('click', updateToken);
    $('#tg-clear-token')?.addEventListener('click',  clearToken);
    $('#tg-test')?.addEventListener('click', sendTest);

    $('#tg-add-admin')?.addEventListener('click', () => openModal('tg-add-modal'));
    $('#tg-add-save')?.addEventListener('click', addAdminSave);
    $('#tg-add-cancel')?.addEventListener('click', () => closeModal('tg-add-modal'));
    $('#tg-add-modal')?.addEventListener('click', e => { if (e.target.id === 'tg-add-modal') closeModal('tg-add-modal'); });

    $('#open-logs-telegram')?.addEventListener('click', async () => { await loadTgLogs(); openModal('tg-logs-modal'); });
    $('#tg-logs-refresh')?.addEventListener('click', () => loadTgLogs());
    $('#tg-logs-apply')?.addEventListener('click',   () => loadTgLogs());
    $('#tg-logs-clear')?.addEventListener('click', async () => {
      if (!await confirmDialog({ title:'Clear Telegram logs?', body:'This will permanently remove all Telegram bot log entries.', okText:'Clear' })) return;
      try {
        let r = await fetch('/api/telegram/logs', { method:'DELETE', headers: csrf(), credentials:'same-origin' });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        toast('Telegram logs cleared.', 'success');
        await loadTgLogs();
      } catch { toast('Failed to clear Telegram logs.', 'error'); }
    });
    $('#tg-logs-close')?.addEventListener('click', () => closeModal('tg-logs-modal'));
    (function lockTouchScroll() {
      const m = document.getElementById('tg-logs-modal'); if (!m) return;
      m.addEventListener('touchmove', (e) => { if (!e.target.closest('#tg-logs-list,.modal-content')) e.preventDefault(); }, { passive: false });
    })();

    document.addEventListener('DOMContentLoaded', async () => {
      await loadSettings();
      await loadAdmins();
      await loadStatus();
      setInterval(loadStatus, 60000);
    });
  })();


  (function templatePicker() {
    const $ = (s, r = document) => r.querySelector(s);
    const $$ = (s, r = document) => [...r.querySelectorAll(s)];

    (function preview() {
      const dock  = $('#tpl-preview-dock');
      const body  = dock?.querySelector('.dock-body');
      const wrap  = $('#tpl-scale-wrap');
      const frame = $('#tpl-preview-frame');
      const title = $('#tpl-preview-title');

      const PRESET = { default:[1100,740], compact:[900,560], minimal:[900,520], pro:[1120,780] };
      window.__tplDims = PRESET.default;

      function applyScale() {
        if (!wrap || !frame || !body) return;
        const [baseW, baseH] = window.__tplDims || PRESET.default;
        const innerW = body.clientWidth - 24;
        const rect   = body.getBoundingClientRect();
        const viewportH = document.documentElement.clientHeight;
        const reservedBelow = 96;
        const maxH = Math.max(180, Math.min(440, viewportH - rect.top - reservedBelow));
        const sW = innerW / baseW;
        const sH = maxH / baseH;
        const s  = Math.max(0.34, Math.min(1, Math.min(sW, sH)));

        frame.style.width  = baseW + 'px';
        frame.style.height = baseH + 'px';
        frame.style.transform = `scale(${s})`;
        wrap.style.width  = Math.round(baseW * s) + 'px';
        wrap.style.height = Math.round(baseH * s) + 'px';
      }
      window.applyPreviewScale = applyScale;

      window.showPreview = function(name) {
        const nice = name.charAt(0).toUpperCase() + name.slice(1);
        if (title) title.textContent = `${nice} — Preview`;
        const PRESET = { default:[1100,740], compact:[900,560], minimal:[900,520], pro:[1120,780] };
        window.__tplDims = PRESET[name] || PRESET.default;
        const src = `/preview/template/${name}?embed=1`;
        if (frame && frame.getAttribute('src') !== src) frame.setAttribute('src', src);
        dock?.setAttribute('aria-hidden', 'false');
        requestAnimationFrame(applyScale);
      };

      frame?.addEventListener('load', () => requestAnimationFrame(applyScale));
      window.addEventListener('resize', applyScale);
      if (window.ResizeObserver && body) new ResizeObserver(applyScale).observe(body);
    })();

    let savedSel = 'default';
    const radioOf = (name) => $$(`input[name="${name}"]`);
    function currentPending() { return (radioOf('tpl').find(x => x.checked)?.value) || 'default'; }
    function updateDirty() { const dirty = (currentPending() !== savedSel); const el = $('#tpl-dirty'); if (el) el.style.display = dirty ? 'inline' : 'none'; }

    $$('#tpl-grid .tpl-icon').forEach(tile => {
      const name = tile.dataset.name;
      const input = tile.querySelector('input[type="radio"]');
      tile.addEventListener('click', () => {
        input.checked = true;
        $$('#tpl-grid .tpl-icon').forEach(t => t.setAttribute('aria-checked', 'false'));
        tile.setAttribute('aria-checked', 'true');
        window.showPreview?.(name);
        updateDirty();
      });
      tile.addEventListener('mouseenter', () => window.showPreview?.(name));
      tile.addEventListener('focusin',   () => window.showPreview?.(name));
    });

    $('#tpl-save')?.addEventListener('click', async () => {
      const sel = currentPending();
      try {
        await jfetch('/api/template_settings', { method:'POST', body:{ selected: sel } });
        savedSel = sel; updateDirty(); toast('Template saved', 'success');
      } catch { toast('Save failed', 'error'); }
    });

    function readSocials() {
      return {
        telegram:  ($('#soc-telegram')?.value || '').trim(),
        whatsapp:  ($('#soc-whatsapp')?.value || '').trim(),
        instagram: ($('#soc-instagram')?.value || '').trim(),
        phone:     ($('#soc-phone')?.value || '').trim(),
        website:   ($('#soc-website')?.value || '').trim(),
        email:     ($('#soc-email')?.value || '').trim(),
      };
    }
    async function loadSocials() {
      try {
        const j = await jfetch('/api/template_settings');
        const s = j.socials || {};
        if ($('#soc-telegram'))  $('#soc-telegram').value  = s.telegram  || '';
        if ($('#soc-whatsapp'))  $('#soc-whatsapp').value  = s.whatsapp  || '';
        if ($('#soc-instagram')) $('#soc-instagram').value = s.instagram || '';
        if ($('#soc-phone'))     $('#soc-phone').value     = s.phone     || '';
        if ($('#soc-website'))   $('#soc-website').value   = s.website   || '';
        if ($('#soc-email'))     $('#soc-email').value     = s.email     || '';
      } catch { toast('Failed to load socials', 'error'); }
    }
    $('#soc-save')?.addEventListener('click', async () => {
      try {
        await jfetch('/api/template_settings', { method:'POST', body:{ socials: readSocials() } });
        toast('Socials saved', 'success');
      } catch (e) { toast('Save failed: ' + (e.message || e), 'error'); }
    });

  document.getElementById('set-tabs')?.addEventListener('click', (e) => {
      const b = e.target.closest('.tab');
      if (b?.dataset.tab === 'template') loadSocials();
    });

    (async function boot() {
      try {
        const j = await jfetch('/api/template_settings');
        savedSel = j.selected || 'default';
        radioOf('tpl').forEach(x => {
          const on = (x.value === savedSel);
          x.checked = on;
          x.closest('.tpl-icon')?.setAttribute('aria-checked', on ? 'true' : 'false');
        });
        window.showPreview?.(savedSel);
        updateDirty();
      } catch { window.showPreview?.('default'); }
      if (document.querySelector('.panel[data-panel="template"].active')) loadSocials();
    })();
  })();


  (function adminPanel() {
    const badge   = $('#admin-2fa-badge');
    const uForm   = $('#admin-username-form');
    const uinput  = $('#admin-username');
    const pForm   = $('#admin-password-form');
    const curPw   = $('#pw-current');
    const newPw   = $('#pw-new');
    const newPw2  = $('#pw-new2');
    const secOff  = $('#twofa-off');
    const secOn   = $('#twofa-on');
    const secSetup= $('#twofa-setup');
    const begin   = $('#twofa-begin');
    const disableBtn = $('#twofa-disable');
    const qrBox   = $('#admin-qr');
    const secret  = $('#admin-secret');
    const otpIn   = $('#admin-otp');
    const confirmBtn = $('#twofa-confirm');
    const rcount  = $('#twofa-rcount');

    function set2FABadge(on) {
      if (!badge) return;
      badge.textContent = on ? '2FA: ON' : '2FA: OFF';
      badge.className = 'badge ' + (on ? 'green' : 'red');
    }

    async function refreshAdmin() {
      const s = await jfetch('/api/admin');
      uinput.value = s.username || '';
      const on = !!(s.totp_confirmed || s.twofa_enabled);
      set2FABadge(on);
      secOn.style.display  = on ? '' : 'none';
      secOff.style.display = on ? 'none' : '';
      secSetup.classList.remove('open'); secSetup.style.display = 'none';
      if (rcount) {
        if (on) { rcount.style.display = 'inline-block'; rcount.textContent = 'codes: ' + (s.recovery_count || 0); }
        else rcount.style.display = 'none';
      }
    }

    uForm?.addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        const username = (uinput.value || '').trim();
        if (!username) throw new Error('Empty username');
        await jfetch('/api/admin/rename',   { method:'POST', body:{ username } });
        toast('Username updated', 'success');
        await refreshAdmin();
      } catch (e2) { toast(e2.message || 'Rename failed', 'error'); }
    });

    pForm?.addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        const cur = curPw.value || '';
        const a = newPw.value || '';
        const b = newPw2.value || '';
        if (!a) throw new Error('Enter a new password');
        if (a !== b) throw new Error('New passwords do not match');
        await jfetch('/api/admin/password', { method:'POST', body:{ current: cur, new: a } });
        curPw.value = ''; newPw.value = ''; newPw2.value = '';
        toast('Password updated', 'success');
      } catch (e2) { toast(e2.message || 'Password update failed', 'error'); }
    });

    begin?.addEventListener('click', async () => {
      try {
        secSetup.style.display = ''; secSetup.classList.add('open');
        secret.value = '';
        qrBox.innerHTML = '<div class="muted">Generating…</div>';
        const out = await jfetch('/api/admin/twofa_begin', { method:'POST' });
        secret.value = out.secret || '';
        qrBox.innerHTML = '';
        if (window.QRCode && out.otp_uri) {
          new QRCode(qrBox, { text: out.otp_uri, width: 156, height: 156, correctLevel: QRCode.CorrectLevel.M });
        } else {
          qrBox.innerHTML = '<div class="muted">Use the manual key.</div>';
        }
        otpIn?.focus();
      } catch (e2) {
        secSetup.classList.remove('open'); secSetup.style.display = 'none';
        toast('2FA start failed: ' + (e2.message || e2), 'error');
      }
    });

    confirmBtn?.addEventListener('click', async () => {
      try {
        const otp = (otpIn.value || '').trim();
        if (!otp) throw new Error('Enter the 6-digit code');
        const out = await jfetch('/api/admin/twofa_confirm', { method:'POST', body:{ otp } });
        if (out.recovery_codes?.length) {

        }
        await refreshAdmin();
        toast('Two-factor authentication enabled.', 'success');
      } catch (e2) {
        toast(e2.message || 'Invalid code', 'error');
        otpIn?.select();
      }
    });

    disableBtn?.addEventListener('click', async () => {
      if (!await confirmDialog({ title:'Disable 2FA', body:'Are you sure you want to disable two-factor authentication?', okText:'Disable' })) return;
      try {
        await jfetch('/api/admin/twofa_disable', { method:'POST' });
        await refreshAdmin();
        toast('Two-factor authentication disabled.', 'success');
      } catch (e2) { toast(e2.message || 'Disable failed', 'error'); }
    });

    document.addEventListener('DOMContentLoaded', () => { refreshAdmin().catch(()=>{}); });
  })();



    (function adminLogs() {
    const $  = (s, r = document) => r.querySelector(s);
    const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
    const ENDPOINT = '/api/admin_logs';

    function escapeHTML(s) {
      return String(s ?? '').replace(/[&<>"']/g, ch => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
      }[ch]));
    }

    function formatStamp(row) { return _formatStamp(row); }
  function prettylog(a) {
  const s = String(a || '').trim();
  if (!s) return '';
  return s.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function prettyDetails(x, detRaw) {
  const raw = String(detRaw || '').trim();
  const parts = [];

  const pid =
    (x && x.resource && x.resource.peer_id != null ? String(x.resource.peer_id) : '') ||
    ((raw.match(/(?:^|[;,\s])pid=(\d+)/i) || [])[1] || '');

  const iface =
    (x && x.resource && x.resource.iface ? String(x.resource.iface) : '') ||
    ((raw.match(/(?:^|[;,\s])iface=([A-Za-z0-9_.:-]+)/i) || [])[1] || '');

  const scope =
    (x && x.resource && x.resource.scope ? String(x.resource.scope) : '') ||
    ((raw.match(/(?:^|[;,\s])scope=([A-Za-z0-9_.:-]+)/i) || [])[1] || '');

  if (pid) parts.push(`peer_id=${pid}`);
  if (iface) parts.push(`iface=${iface}`);
  if (scope) parts.push(`scope=${scope}`);

  let fields = ((raw.match(/fields=([^;]+)/i) || [])[1] || '').trim();
  if (fields) {
    fields = fields
      .split(',')
      .map(s => s.trim())
      .filter(Boolean)
      .map(s => s.replace(/_/g, ' '))
      .join(', ');
  }

  const rest = raw
    .replace(/(^|[;,\s])(?:pid|peer_id|iface|scope|fields)=([^;]+)/gi, '')
    .replace(/^[;\s]+|[;\s]+$/g, '')
    .trim();

  let out = '';
  if (parts.length) out += parts.join(' · ');
  if (fields) out += (out ? '\n' : '') + `fields: ${fields}`;
  if (rest) out += (out ? '\n' : '') + rest;

  return out || raw || '';
}


async function loadAdminLogs() {
  try {
      const q = $('#al-q')?.value?.trim() || '';
      const a = $('#al-action')?.value || '';
      const f = $('#al-from')?.value || '';
      const t = $('#al-to')?.value || '';
      const qs = new URLSearchParams({ q, action: a, from: f, to: t, limit: '500' });
      const j = await jfetch(`${ENDPOINT}?${qs.toString()}`);

      const rows = (j.logs || []).map(x => {
      const stamp = formatStamp(x);

      const adminId   = escapeHTML(x.admin_id || '—');
      const adminName = escapeHTML((x.admin_username || x.admin || x.username || x.user || '').trim());
      const whoCell   = adminId !== '—'
        ? `<div class="al-adminid mono">${adminId}</div>${adminName ? `<div class="al-adminname muted">${adminName}</div>` : ''}`
        : (adminName || '—');

      const act = escapeHTML(prettylog(x.action || '') || '—');


      const detRaw = (typeof x.details === 'string')
        ? x.details
        : (x.details ? JSON.stringify(x.details) : '');

      const detPretty = prettyDetails(x, detRaw);
      const detCell = escapeHTML(detPretty);
      const detAttr = escapeHTML(detRaw);



  return `<tr>
  <td class="mono al-time">
    <div class="al-ts">${stamp.text}</div>
    <div class="al-ago muted">${stamp.ago}</div>
  </td>
  <td class="al-admin">${whoCell}</td>
  <td class="mono al-action">${act}</td>
  <td class="mono al-details">${detCell}</td>
  <td class="al-copy">
    <button class="btn sm" type="button" data-copy="${detAttr}" title="Copy details" aria-label="Copy details">
      <i class="fa-solid fa-copy"></i>
    </button>
  </td>
</tr>`;

        }).join('');

        $('#al-table tbody').innerHTML =
          rows || '<tr><td colspan="5" class="muted" style="text-align:center">No logs</td></tr>';

        $$('#al-table [data-copy]').forEach(btn => {
          btn.addEventListener('click', async () => {
            try {
              await navigator.clipboard.writeText(btn.getAttribute('data-copy') || '');
              (window.toastSafe || window.toast || (()=>{}))('Copied', 'success');
            } catch {}
          });
        });
      } catch (e) {
        console.error(e);
        toast('Failed to load admin logs', 'error');
      }
    }

    window.loadAdminLogs = loadAdminLogs;

    function exportCSV() {
      const rows = $$('#al-table tr');
      const esc = s => `"${String(s).replace(/"/g, '""')}"`;
      const csv = rows
        .map(tr => Array.from(tr.children).slice(0, 4).map(td => esc(td.textContent.trim())).join(','))
        .join('\n');

      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `admin_logs_${_panelFileStamp()}.csv`;
      document.body.appendChild(a);
      a.click();
      URL.revokeObjectURL(a.href);
      a.remove();
    }

    async function clearLogs() {
      if (!await confirmDialog({ title: 'Clear admin logs?', body: 'This will permanently remove all admin log entries.', okText: 'Clear' })) return;
      try {
        let r = await fetch(ENDPOINT, { method: 'DELETE', credentials: 'same-origin' });
        if (!r.ok) r = await fetch(ENDPOINT + '/clear', { method: 'POST', credentials: 'same-origin' });
        if (!r.ok) throw new Error('HTTP ' + r.status);

        toast('Admin logs cleared', 'success');
        await loadAdminLogs();
      } catch (e) {
        console.error(e);
        toast('Failed to clear admin logs', 'error');
      }
    }

    $('#open-logs-admin-top')?.addEventListener('click', () => { openModal('admin-logs-modal'); loadAdminLogs(); });

    document.addEventListener('DOMContentLoaded', () => {
      $('#open-logs-admin')?.addEventListener('click', () => { openModal('admin-logs-modal'); loadAdminLogs(); });

      $('#admin-logs-modal .modal-backdrop')?.addEventListener('click', () => closeModal('admin-logs-modal'));
      $$('#admin-logs-modal .modal-content .btn[data-close], #admin-logs-modal .modal-content .btn[data-modal-close], #admin-logs-modal .modal-content .modal-close')
        .forEach(el => el.addEventListener('click', () => closeModal('admin-logs-modal')));

      let alTimer = null;
      $('#al-autoref')?.addEventListener('change', (e) => {
        if (e.target.checked) {
          loadAdminLogs();
          alTimer = setInterval(loadAdminLogs, 5000);
        } else if (alTimer) {
          clearInterval(alTimer);
          alTimer = null;
        }
      });

      $('#al-refresh')?.addEventListener('click', (e) => { e.preventDefault(); loadAdminLogs(); });
      $('#al-export') ?.addEventListener('click', (e) => { e.preventDefault(); exportCSV(); });
      $('#btn-clear-admin-logs')?.addEventListener('click', (e) => { e.preventDefault(); clearLogs(); });
    });
  })();



  document.addEventListener('DOMContentLoaded', () => {
    pinModals();
  });
})();

(() => {
  const SELECTOR = '#set-panels select.input, .modal select.input';

  function closeAll(except = null) {
    document.querySelectorAll('.set-select.is-open').forEach((wrap) => {
      if (wrap !== except) wrap.classList.remove('is-open');
    });
  }

  function enhanceSelect(select) {
    if (!select || select.dataset.setSelectEnhanced === '1') return;

    const wrap = document.createElement('div');
    wrap.className = 'set-select';
    select.parentNode.insertBefore(wrap, select);
    wrap.appendChild(select);

    select.dataset.setSelectEnhanced = '1';
    select.classList.add('set-select__native');

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'set-select__button';
    button.setAttribute('aria-haspopup', 'listbox');
    button.setAttribute('aria-expanded', 'false');

    const menu = document.createElement('div');
    menu.className = 'set-select__menu';
    menu.setAttribute('role', 'listbox');

    wrap.append(button, menu);

    function syncVisibility() {
      const hidden = select.hidden || select.hasAttribute('hidden');
      wrap.hidden = hidden;
      wrap.classList.toggle('is-hidden', hidden);
    }

    function selectedOption() {
      return select.options[select.selectedIndex] || select.options[0] || null;
    }

    function syncButton() {
      const option = selectedOption();
      button.textContent = option ? option.textContent.trim() : 'Select';
      button.disabled = !!select.disabled;
      button.setAttribute('aria-label', select.getAttribute('aria-label') || button.textContent);
      menu.querySelectorAll('.set-select__option').forEach((item) => {
        item.setAttribute('aria-selected', item.dataset.value === String(select.value));
      });
      syncVisibility();
    }

    function rebuild() {
      menu.innerHTML = '';
      Array.from(select.options).forEach((option) => {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'set-select__option';
        item.dataset.value = String(option.value);
        item.textContent = option.textContent.trim();
        item.disabled = !!option.disabled;
        item.setAttribute('role', 'option');
        item.setAttribute('aria-selected', option.selected ? 'true' : 'false');
        item.addEventListener('click', (event) => {
          event.preventDefault();
          event.stopPropagation();
          if (item.disabled) return;

          const nextValue = String(item.dataset.value ?? option.value);
          const options = Array.from(select.options);
          const nextIndex = options.findIndex((opt) => String(opt.value) === nextValue);

          if (nextIndex >= 0) {
            select.selectedIndex = nextIndex;
            options.forEach((opt, index) => { opt.selected = index === nextIndex; });
          }
          select.value = nextValue;

          syncButton();
          wrap.classList.remove('is-open');
          button.setAttribute('aria-expanded', 'false');
          select.dispatchEvent(new Event('input', { bubbles: true }));
          select.dispatchEvent(new Event('change', { bubbles: true }));
          syncButton();
          button.focus({ preventScroll: true });
        });
        menu.appendChild(item);
      });
      syncButton();
    }

    button.addEventListener('click', (event) => {
      event.preventDefault();
      if (button.disabled) return;
      const opening = !wrap.classList.contains('is-open');
      closeAll(opening ? wrap : null);
      wrap.classList.toggle('is-open', opening);
      button.setAttribute('aria-expanded', opening ? 'true' : 'false');
      if (opening) {
        menu.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' });
      }
    });

    button.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        wrap.classList.remove('is-open');
        button.setAttribute('aria-expanded', 'false');
      }
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        if (!wrap.classList.contains('is-open')) button.click();
        const items = Array.from(menu.querySelectorAll('.set-select__option:not(:disabled)'));
        const current = menu.querySelector('.set-select__option:focus');
        let index = Math.max(0, items.indexOf(current));
        index = event.key === 'ArrowDown' ? Math.min(items.length - 1, index + 1) : Math.max(0, index - 1);
        items[index]?.focus();
      }
    });

    select.addEventListener('change', syncButton);

    new MutationObserver(() => rebuild()).observe(select, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['disabled', 'hidden', 'selected']
    });

    rebuild();
  }

  function enhanceAll(root = document) {
    root.querySelectorAll?.(SELECTOR).forEach(enhanceSelect);
  }

  function activeTheme() {
    return document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light';
  }

  function applyPreviewTheme() {
    const frame = document.getElementById('tpl-preview-frame');
    const title = document.getElementById('tpl-preview-title');
    if (!frame) return;

    const theme = activeTheme();
    if (title) {
      let note = title.parentElement?.querySelector('.tpl-preview-theme-note');
      if (!note) {
        note = document.createElement('span');
        note.className = 'tpl-preview-theme-note';
        title.parentElement?.appendChild(note);
      }
      note.innerHTML = `<i class="fa-solid ${theme === 'dark' ? 'fa-moon' : 'fa-sun'}"></i> ${theme === 'dark' ? 'Dark preview' : 'Light preview'}`;
    }

    try {
      const doc = frame.contentDocument;
      if (!doc) return;
      doc.documentElement.dataset.theme = theme;
      doc.documentElement.classList.toggle('dark', theme === 'dark');
      doc.documentElement.classList.toggle('light', theme !== 'dark');
      doc.documentElement.style.colorScheme = theme;
      doc.body?.setAttribute('data-theme', theme);

      let style = doc.getElementById('wg-settings-preview-theme');
      if (!style) {
        style = doc.createElement('style');
        style.id = 'wg-settings-preview-theme';
        doc.head?.appendChild(style);
      }
      style.textContent = theme === 'dark' ? `
        :root { color-scheme: dark !important; }
        html, body { background: #071015 !important; color: #edf3f6 !important; }
        body::before { opacity: .45 !important; }
        .page, .shell, .container, .subscription-page, main { color: #edf3f6 !important; }
        .card, .panel, .section, .config-card, .stat-card, .download-card {
          background: #0e1d24 !important;
          color: #edf3f6 !important;
          border-color: #29434f !important;
        }
        input, button, .btn { color-scheme: dark !important; }
      ` : '';
    } catch (_) {
    }
  }

  document.addEventListener('click', (event) => {
    if (!event.target.closest('.set-select')) closeAll();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeAll();
  });

  document.addEventListener('DOMContentLoaded', () => {
    enhanceAll();
    const frame = document.getElementById('tpl-preview-frame');
    frame?.addEventListener('load', applyPreviewTheme);
    applyPreviewTheme();

    new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType !== 1) return;
          if (node.matches?.(SELECTOR)) enhanceSelect(node);
          enhanceAll(node);
        });
      }
    }).observe(document.body, { childList: true, subtree: true });

    new MutationObserver(applyPreviewTheme).observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme', 'class']
    });
  });
})();

/* ============================================================
   Traffic Control · WireGuard forwarding policy · V1.8
   ============================================================ */
(() => {
  const byId = (id) => document.getElementById(id);
  if (!byId('traffic-tab')) return;

  const COUNTRY_CHOICES = [{"code":"AF","name":"Afghanistan"},{"code":"AL","name":"Albania"},{"code":"DZ","name":"Algeria"},{"code":"AS","name":"American Samoa"},{"code":"AD","name":"Andorra"},{"code":"AO","name":"Angola"},{"code":"AI","name":"Anguilla"},{"code":"AQ","name":"Antarctica"},{"code":"AG","name":"Antigua and Barbuda"},{"code":"AR","name":"Argentina"},{"code":"AM","name":"Armenia"},{"code":"AW","name":"Aruba"},{"code":"AU","name":"Australia"},{"code":"AT","name":"Austria"},{"code":"AZ","name":"Azerbaijan"},{"code":"BS","name":"Bahamas"},{"code":"BH","name":"Bahrain"},{"code":"BD","name":"Bangladesh"},{"code":"BB","name":"Barbados"},{"code":"BY","name":"Belarus"},{"code":"BE","name":"Belgium"},{"code":"BZ","name":"Belize"},{"code":"BJ","name":"Benin"},{"code":"BM","name":"Bermuda"},{"code":"BT","name":"Bhutan"},{"code":"BO","name":"Bolivia, Plurinational State of"},{"code":"BQ","name":"Bonaire, Sint Eustatius and Saba"},{"code":"BA","name":"Bosnia and Herzegovina"},{"code":"BW","name":"Botswana"},{"code":"BV","name":"Bouvet Island"},{"code":"BR","name":"Brazil"},{"code":"IO","name":"British Indian Ocean Territory"},{"code":"BN","name":"Brunei Darussalam"},{"code":"BG","name":"Bulgaria"},{"code":"BF","name":"Burkina Faso"},{"code":"BI","name":"Burundi"},{"code":"CV","name":"Cabo Verde"},{"code":"KH","name":"Cambodia"},{"code":"CM","name":"Cameroon"},{"code":"CA","name":"Canada"},{"code":"KY","name":"Cayman Islands"},{"code":"CF","name":"Central African Republic"},{"code":"TD","name":"Chad"},{"code":"CL","name":"Chile"},{"code":"CN","name":"China"},{"code":"CX","name":"Christmas Island"},{"code":"CC","name":"Cocos (Keeling) Islands"},{"code":"CO","name":"Colombia"},{"code":"KM","name":"Comoros"},{"code":"CG","name":"Congo"},{"code":"CD","name":"Congo, The Democratic Republic of the"},{"code":"CK","name":"Cook Islands"},{"code":"CR","name":"Costa Rica"},{"code":"HR","name":"Croatia"},{"code":"CU","name":"Cuba"},{"code":"CW","name":"Curaçao"},{"code":"CY","name":"Cyprus"},{"code":"CZ","name":"Czechia"},{"code":"CI","name":"Côte d'Ivoire"},{"code":"DK","name":"Denmark"},{"code":"DJ","name":"Djibouti"},{"code":"DM","name":"Dominica"},{"code":"DO","name":"Dominican Republic"},{"code":"EC","name":"Ecuador"},{"code":"EG","name":"Egypt"},{"code":"SV","name":"El Salvador"},{"code":"GQ","name":"Equatorial Guinea"},{"code":"ER","name":"Eritrea"},{"code":"EE","name":"Estonia"},{"code":"SZ","name":"Eswatini"},{"code":"ET","name":"Ethiopia"},{"code":"FK","name":"Falkland Islands (Malvinas)"},{"code":"FO","name":"Faroe Islands"},{"code":"FJ","name":"Fiji"},{"code":"FI","name":"Finland"},{"code":"FR","name":"France"},{"code":"GF","name":"French Guiana"},{"code":"PF","name":"French Polynesia"},{"code":"TF","name":"French Southern Territories"},{"code":"GA","name":"Gabon"},{"code":"GM","name":"Gambia"},{"code":"GE","name":"Georgia"},{"code":"DE","name":"Germany"},{"code":"GH","name":"Ghana"},{"code":"GI","name":"Gibraltar"},{"code":"GR","name":"Greece"},{"code":"GL","name":"Greenland"},{"code":"GD","name":"Grenada"},{"code":"GP","name":"Guadeloupe"},{"code":"GU","name":"Guam"},{"code":"GT","name":"Guatemala"},{"code":"GG","name":"Guernsey"},{"code":"GN","name":"Guinea"},{"code":"GW","name":"Guinea-Bissau"},{"code":"GY","name":"Guyana"},{"code":"HT","name":"Haiti"},{"code":"HM","name":"Heard Island and McDonald Islands"},{"code":"VA","name":"Holy See (Vatican City State)"},{"code":"HN","name":"Honduras"},{"code":"HK","name":"Hong Kong"},{"code":"HU","name":"Hungary"},{"code":"IS","name":"Iceland"},{"code":"IN","name":"India"},{"code":"ID","name":"Indonesia"},{"code":"IR","name":"Iran, Islamic Republic of"},{"code":"IQ","name":"Iraq"},{"code":"IE","name":"Ireland"},{"code":"IM","name":"Isle of Man"},{"code":"IL","name":"Israel"},{"code":"IT","name":"Italy"},{"code":"JM","name":"Jamaica"},{"code":"JP","name":"Japan"},{"code":"JE","name":"Jersey"},{"code":"JO","name":"Jordan"},{"code":"KZ","name":"Kazakhstan"},{"code":"KE","name":"Kenya"},{"code":"KI","name":"Kiribati"},{"code":"KP","name":"Korea, Democratic People's Republic of"},{"code":"KR","name":"Korea, Republic of"},{"code":"KW","name":"Kuwait"},{"code":"KG","name":"Kyrgyzstan"},{"code":"LA","name":"Lao People's Democratic Republic"},{"code":"LV","name":"Latvia"},{"code":"LB","name":"Lebanon"},{"code":"LS","name":"Lesotho"},{"code":"LR","name":"Liberia"},{"code":"LY","name":"Libya"},{"code":"LI","name":"Liechtenstein"},{"code":"LT","name":"Lithuania"},{"code":"LU","name":"Luxembourg"},{"code":"MO","name":"Macao"},{"code":"MG","name":"Madagascar"},{"code":"MW","name":"Malawi"},{"code":"MY","name":"Malaysia"},{"code":"MV","name":"Maldives"},{"code":"ML","name":"Mali"},{"code":"MT","name":"Malta"},{"code":"MH","name":"Marshall Islands"},{"code":"MQ","name":"Martinique"},{"code":"MR","name":"Mauritania"},{"code":"MU","name":"Mauritius"},{"code":"YT","name":"Mayotte"},{"code":"MX","name":"Mexico"},{"code":"FM","name":"Micronesia, Federated States of"},{"code":"MD","name":"Moldova, Republic of"},{"code":"MC","name":"Monaco"},{"code":"MN","name":"Mongolia"},{"code":"ME","name":"Montenegro"},{"code":"MS","name":"Montserrat"},{"code":"MA","name":"Morocco"},{"code":"MZ","name":"Mozambique"},{"code":"MM","name":"Myanmar"},{"code":"NA","name":"Namibia"},{"code":"NR","name":"Nauru"},{"code":"NP","name":"Nepal"},{"code":"NL","name":"Netherlands"},{"code":"NC","name":"New Caledonia"},{"code":"NZ","name":"New Zealand"},{"code":"NI","name":"Nicaragua"},{"code":"NE","name":"Niger"},{"code":"NG","name":"Nigeria"},{"code":"NU","name":"Niue"},{"code":"NF","name":"Norfolk Island"},{"code":"MK","name":"North Macedonia"},{"code":"MP","name":"Northern Mariana Islands"},{"code":"NO","name":"Norway"},{"code":"OM","name":"Oman"},{"code":"PK","name":"Pakistan"},{"code":"PW","name":"Palau"},{"code":"PS","name":"Palestine, State of"},{"code":"PA","name":"Panama"},{"code":"PG","name":"Papua New Guinea"},{"code":"PY","name":"Paraguay"},{"code":"PE","name":"Peru"},{"code":"PH","name":"Philippines"},{"code":"PN","name":"Pitcairn"},{"code":"PL","name":"Poland"},{"code":"PT","name":"Portugal"},{"code":"PR","name":"Puerto Rico"},{"code":"QA","name":"Qatar"},{"code":"RO","name":"Romania"},{"code":"RU","name":"Russian Federation"},{"code":"RW","name":"Rwanda"},{"code":"RE","name":"Réunion"},{"code":"BL","name":"Saint Barthélemy"},{"code":"SH","name":"Saint Helena, Ascension and Tristan da Cunha"},{"code":"KN","name":"Saint Kitts and Nevis"},{"code":"LC","name":"Saint Lucia"},{"code":"MF","name":"Saint Martin (French part)"},{"code":"PM","name":"Saint Pierre and Miquelon"},{"code":"VC","name":"Saint Vincent and the Grenadines"},{"code":"WS","name":"Samoa"},{"code":"SM","name":"San Marino"},{"code":"ST","name":"Sao Tome and Principe"},{"code":"SA","name":"Saudi Arabia"},{"code":"SN","name":"Senegal"},{"code":"RS","name":"Serbia"},{"code":"SC","name":"Seychelles"},{"code":"SL","name":"Sierra Leone"},{"code":"SG","name":"Singapore"},{"code":"SX","name":"Sint Maarten (Dutch part)"},{"code":"SK","name":"Slovakia"},{"code":"SI","name":"Slovenia"},{"code":"SB","name":"Solomon Islands"},{"code":"SO","name":"Somalia"},{"code":"ZA","name":"South Africa"},{"code":"GS","name":"South Georgia and the South Sandwich Islands"},{"code":"SS","name":"South Sudan"},{"code":"ES","name":"Spain"},{"code":"LK","name":"Sri Lanka"},{"code":"SD","name":"Sudan"},{"code":"SR","name":"Suriname"},{"code":"SJ","name":"Svalbard and Jan Mayen"},{"code":"SE","name":"Sweden"},{"code":"CH","name":"Switzerland"},{"code":"SY","name":"Syrian Arab Republic"},{"code":"TW","name":"Taiwan, Province of China"},{"code":"TJ","name":"Tajikistan"},{"code":"TZ","name":"Tanzania, United Republic of"},{"code":"TH","name":"Thailand"},{"code":"TL","name":"Timor-Leste"},{"code":"TG","name":"Togo"},{"code":"TK","name":"Tokelau"},{"code":"TO","name":"Tonga"},{"code":"TT","name":"Trinidad and Tobago"},{"code":"TN","name":"Tunisia"},{"code":"TM","name":"Turkmenistan"},{"code":"TC","name":"Turks and Caicos Islands"},{"code":"TV","name":"Tuvalu"},{"code":"TR","name":"Türkiye"},{"code":"UG","name":"Uganda"},{"code":"UA","name":"Ukraine"},{"code":"AE","name":"United Arab Emirates"},{"code":"GB","name":"United Kingdom"},{"code":"US","name":"United States"},{"code":"UM","name":"United States Minor Outlying Islands"},{"code":"UY","name":"Uruguay"},{"code":"UZ","name":"Uzbekistan"},{"code":"VU","name":"Vanuatu"},{"code":"VE","name":"Venezuela, Bolivarian Republic of"},{"code":"VN","name":"Viet Nam"},{"code":"VG","name":"Virgin Islands, British"},{"code":"VI","name":"Virgin Islands, U.S."},{"code":"WF","name":"Wallis and Futuna"},{"code":"EH","name":"Western Sahara"},{"code":"YE","name":"Yemen"},{"code":"ZM","name":"Zambia"},{"code":"ZW","name":"Zimbabwe"},{"code":"AX","name":"Åland Islands"}];
  const COUNTRY_BY_CODE = new Map(COUNTRY_CHOICES.map(row => [row.code.toUpperCase(), row]));
  const COUNTRY_BY_NAME = new Map(COUNTRY_CHOICES.map(row => [row.name.toLowerCase(), row]));

  function trafficCsrfHeaders(json = false) {
    const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
    const token = match ? decodeURIComponent(match[1]) : '';
    const headers = {};
    if (json) headers['Content-Type'] = 'application/json';
    if (token) { headers['X-CSRFToken'] = token; headers['X-CSRF-Token'] = token; }
    return headers;
  }

  async function trafficFetch(url, options = {}) {
    const method = String(options.method || 'GET').toUpperCase();
    const hasObjectBody = options.body && typeof options.body === 'object';
    const response = await fetch(url, {
      method,
      headers: { ...trafficCsrfHeaders(hasObjectBody), ...(options.headers || {}), 'Accept':'application/json' },
      body: hasObjectBody ? JSON.stringify(options.body) : (options.body || null),
      credentials: 'same-origin', cache: 'no-store'
    });
    let data = null;
    const type = response.headers.get('content-type') || '';
    if (type.includes('application/json')) { try { data = await response.json(); } catch {} }
    else { try { data = await response.text(); } catch {} }
    if (!response.ok) {
      const message = data && typeof data === 'object' && (data.detail || data.message || data.error)
        ? (data.detail || data.message || data.error)
        : (typeof data === 'string' && data.trim() ? data.trim() : `HTTP ${response.status}`);
      throw new Error(String(message).slice(0, 300));
    }
    return data;
  }

  let payload = null;
  let policies = [];
  let targets = [];
  let dirty = false;
  let activeTrafficTestIndex = null;
  const editorTags = { domains:[], cidrs:[], countries:[] };

  const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
  const uniq = (items) => Array.from(new Set((items || []).map(v => String(v || '').trim()).filter(Boolean)));

  function setHidden(el, hidden) { if (!el) return; el.hidden = !!hidden; el.style.display = hidden ? 'none' : ''; }

  function setDirty(on = true) {
    dirty = !!on;
    const badge = byId('traffic-dirty');
    if (badge) { badge.hidden = !dirty; badge.style.display = dirty ? 'inline-flex' : 'none'; }
    const notice = byId('traffic-apply-notice');
    if (notice) { notice.hidden = !dirty; notice.style.display = dirty ? 'flex' : 'none'; }
  }

  function currentLocation() { return byId('traffic-location')?.value || 'local'; }
  function currentNodeId() { return Number(byId('traffic-node')?.value || 0) || null; }

  function availableNodes() {
    const map = new Map();
    targets.filter(t => t.location === 'node' && t.node_id).forEach(t => map.set(Number(t.node_id), t.node_name || `Node ${t.node_id}`));
    return Array.from(map.entries()).map(([id,name]) => ({id,name}));
  }

  function fillNodeSelect() {
    const select = byId('traffic-node'); if (!select) return;
    const previous = Number(select.value || 0) || null;
    const nodes = availableNodes();
    select.innerHTML = nodes.map(n => `<option value="${n.id}">${escapeHtml(n.name)}</option>`).join('');
    if (previous && nodes.some(n => n.id === previous)) select.value = String(previous);
  }

  function matchingInterfaces() {
    const location = currentLocation(), nodeId = currentNodeId();
    return targets.filter(t => location === 'local' ? t.location === 'local' : (t.location === 'node' && Number(t.node_id) === Number(nodeId)));
  }

  function fillInterfaceSelect(preferred = '') {
    const select = byId('traffic-interface'); if (!select) return;
    const rows = matchingInterfaces();
    select.innerHTML = rows.map(t => `<option value="${escapeHtml(t.name)}">${escapeHtml(t.name)} · ${escapeHtml(t.address || '')}</option>`).join('');
    if (preferred && rows.some(t => t.name === preferred)) select.value = preferred;
    fillPeerSelect();
  }

  function selectedTarget() {
    const iface = byId('traffic-interface')?.value || '';
    return matchingInterfaces().find(t => t.name === iface) || null;
  }

  function fillPeerSelect(preferredAddress = '') {
    const select = byId('traffic-peer'), note = byId('traffic-peer-address'); if (!select) return;
    const peers = selectedTarget()?.peers || [];
    select.innerHTML = peers.map(p => `<option value="${escapeHtml(p.address || '')}">${escapeHtml(p.name || 'Peer')} · ${escapeHtml(p.address || '')}</option>`).join('');
    if (preferredAddress && peers.some(p => String(p.address) === String(preferredAddress))) select.value = preferredAddress;
    if (note) note.textContent = select.value ? `WireGuard source: ${select.value}` : (peers.length ? '' : 'No peers are known for this interface.');
  }

  function syncScopeUI() {
    const nodeWrap = byId('traffic-node-wrap'), peerWrap = byId('traffic-peer-wrap');
    if (nodeWrap) nodeWrap.hidden = currentLocation() !== 'node';
    if (peerWrap) peerWrap.hidden = (byId('traffic-source-mode')?.value || 'interface') !== 'peer';
  }

  function normalizeDomain(raw) {
    let value = String(raw || '').trim(); if (!value) return '';
    try {
      const maybe = value.includes('://') ? new URL(value) : new URL('https://' + value);
      value = maybe.hostname || value;
    } catch { value = value.split('/')[0]; }
    value = value.replace(/^\*\./, '').replace(/\.$/, '').toLowerCase().trim();
    return /^[a-z0-9._-]+$/.test(value) ? value : '';
  }

  function normalizeCountry(raw) {
    const value = String(raw || '').trim(); if (!value) return '';
    const upper = value.toUpperCase();
    if (COUNTRY_BY_CODE.has(upper)) return upper;
    const exact = COUNTRY_BY_NAME.get(value.toLowerCase());
    if (exact) return exact.code.toUpperCase();
    const low = value.toLowerCase();
    const loose = COUNTRY_CHOICES.filter(row => row.name.toLowerCase().startsWith(low) || row.name.toLowerCase().includes(low));
    if (loose.length === 1) return loose[0].code.toUpperCase();
    return /^[A-Za-z]{2}$/.test(value) ? upper : '';
  }

  function normalizeTag(kind, raw) {
    if (kind === 'domains') return normalizeDomain(raw);
    if (kind === 'countries') return normalizeCountry(raw);
    return String(raw || '').trim();
  }

  function tagMeta(kind, value) {
    if (kind === 'domains') return {icon:'fa-globe', label:value};
    if (kind === 'cidrs') return {icon:'fa-network-wired', label:value};
    const row = COUNTRY_BY_CODE.get(String(value || '').toUpperCase());
    return {icon:'fa-earth-asia', label:row ? `${row.name} · ${row.code}` : `Geo ${String(value || '').toUpperCase()}`};
  }

  function syncHiddenTags(kind) {
    const id = kind === 'domains' ? 'traffic-domains' : kind === 'cidrs' ? 'traffic-cidrs' : 'traffic-countries';
    const el = byId(id); if (el) el.value = editorTags[kind].join('\n');
  }

  function renderEditorTags(kind) {
    const host = byId(`traffic-${kind}-chips`); if (!host) return;
    host.innerHTML = editorTags[kind].length
      ? editorTags[kind].map((value,index) => { const meta=tagMeta(kind,value); return `<span class="traffic-editor-chip is-${kind}"><i class="fa-solid ${meta.icon}"></i><span>${escapeHtml(meta.label)}</span><button type="button" data-traffic-token-remove="${kind}" data-index="${index}" aria-label="Remove ${escapeHtml(value)}"><i class="fa-solid fa-xmark"></i></button></span>`; }).join('')
      : `<span class="traffic-token-empty">Nothing added yet</span>`;
    syncHiddenTags(kind);
  }

  function setEditorTags(kind, values) { editorTags[kind] = uniq(values).map(v => normalizeTag(kind,v)).filter(Boolean); renderEditorTags(kind); }

  function addEditorTag(kind, raw) {
    const value = normalizeTag(kind, raw);
    if (!value) { toast(kind === 'countries' ? 'Choose a country from the suggestions or enter a two-letter country code.' : `Enter a valid ${kind === 'domains' ? 'domain or URL' : 'IP/CIDR'}.`, 'warning'); return false; }
    if (!editorTags[kind].includes(value)) editorTags[kind].push(value);
    renderEditorTags(kind);
    const input = byId(kind === 'domains' ? 'traffic-domain-entry' : kind === 'cidrs' ? 'traffic-cidr-entry' : 'traffic-country-entry');
    if (input) input.value = '';
    hideTokenSuggestions(kind);
    return true;
  }

  function existingTagSuggestions(kind) {
    const all=[]; policies.forEach(p => (p[kind] || []).forEach(v => all.push(String(v || '').trim()))); return uniq(all);
  }

  function tokenSuggestions(kind, query) {
    const q=String(query||'').trim();
    if (kind === 'countries') {
      if (!q) return [];
      const low=q.toLowerCase();
      const prefix=[]; const contains=[];
      COUNTRY_CHOICES.forEach(row => {
        const name=row.name.toLowerCase(), code=row.code.toLowerCase();
        if (name.startsWith(low) || code.startsWith(low)) prefix.push(row);
        else if (name.includes(low)) contains.push(row);
      });
      const ranked=prefix.length ? prefix : contains;
      return ranked.slice(0,8).map(row => ({value:row.code,label:row.name,meta:row.code}));
    }

    let values=existingTagSuggestions(kind)
      .filter(v => !editorTags[kind].includes(normalizeTag(kind,v)));
    if (q) {
      const low=q.toLowerCase();
      values=values.sort((a,b) => {
        const aa=String(a).toLowerCase(), bb=String(b).toLowerCase();
        const ap=aa.startsWith(low)?0:1, bp=bb.startsWith(low)?0:1;
        return ap-bp || aa.localeCompare(bb);
      }).filter(v => String(v).toLowerCase().includes(low));
    }
    return uniq(values).slice(0,8).map(value => ({value,label:value,meta:'Saved'}));
  }

  function hideTokenSuggestions(kind) { const box=byId(`traffic-${kind === 'domains' ? 'domain' : kind === 'cidrs' ? 'cidr' : 'country'}-suggestions`); if (box) {box.hidden=true; box.style.display='none'; box.innerHTML='';} }

  function showTokenSuggestions(kind, query) {
    const key=kind === 'domains' ? 'domain' : kind === 'cidrs' ? 'cidr' : 'country';
    const box=byId(`traffic-${key}-suggestions`); if (!box) return;
    const rows=tokenSuggestions(kind,query);
    if (!rows.length) { hideTokenSuggestions(kind); return; }
    box.innerHTML=rows.map(row => `<button type="button" data-traffic-token-suggestion="${kind}" data-value="${escapeHtml(row.value)}"><span class="traffic-suggestion-icon"><i class="fa-solid ${kind==='countries'?'fa-earth-asia':kind==='domains'?'fa-globe':'fa-network-wired'}"></i></span><span class="traffic-suggestion-copy"><b>${escapeHtml(row.label)}</b>${row.meta?`<small>${escapeHtml(row.meta)}</small>`:''}</span><span class="traffic-suggestion-add"><i class="fa-solid fa-plus"></i></span></button>`).join('');
    box.hidden=false; box.style.display='grid';

    const input=byId(`traffic-${key}-entry`);
    const card=box.closest('.traffic-token-card');
    if(input && card){
      const gap=6;
      const inputTop=input.offsetTop;
      box.style.top='auto';
      box.style.bottom=`${Math.max(0, card.clientHeight - inputTop) + gap}px`;
      box.style.left='auto';
      box.style.right='8px';
    }
  }

  function resetEditor() {
    if (byId('traffic-policy-id')) byId('traffic-policy-id').value='';
    if (byId('traffic-policy-name')) byId('traffic-policy-name').value='';
    if (byId('traffic-policy-enabled')) byId('traffic-policy-enabled').checked=true;
    setEditorTags('domains',[]); setEditorTags('cidrs',[]); setEditorTags('countries',[]);
    if (byId('traffic-location')) byId('traffic-location').value='local';
    fillNodeSelect(); syncScopeUI(); fillInterfaceSelect();
    if (byId('traffic-source-mode')) byId('traffic-source-mode').value='interface';
    syncScopeUI(); fillPeerSelect();
    ['traffic-domain-entry','traffic-cidr-entry','traffic-country-entry'].forEach(id => { const el=byId(id); if(el) el.value=''; });
    ['domains','cidrs','countries'].forEach(hideTokenSuggestions);
  }

  function openPolicyEditor(policy = null) {
    resetEditor();
    const editing=!!policy;
    if (editing) {
      byId('traffic-policy-id').value=policy.id || '';
      byId('traffic-policy-name').value=policy.name || '';
      byId('traffic-policy-enabled').checked=policy.enabled !== false;
      byId('traffic-location').value=policy.location || 'local';
      fillNodeSelect();
      if (policy.location === 'node' && policy.node_id) byId('traffic-node').value=String(policy.node_id);
      syncScopeUI(); fillInterfaceSelect(policy.interface || '');
      byId('traffic-source-mode').value=policy.source_mode || 'interface';
      syncScopeUI(); fillPeerSelect(policy.source_ip || '');
      setEditorTags('domains', policy.domains || []); setEditorTags('cidrs', policy.cidrs || []); setEditorTags('countries', policy.countries || []);
    }
    byId('traffic-editor-title').textContent=editing ? 'Edit policy' : 'Add policy';
    byId('traffic-editor-subtitle').textContent=editing ? 'Update this policy. The saved configuration and live rules will refresh automatically.' : 'Choose who is protected and add destinations. The policy will save and activate automatically.';
    byId('traffic-policy-save').innerHTML=editing ? '<i class="fa-solid fa-check"></i> Update policy' : '<i class="fa-solid fa-plus"></i> Add policy';
    const modal=byId('traffic-policy-modal'); if (modal) { modal.hidden=false; modal.style.display='grid'; modal.setAttribute('aria-hidden','false'); }
    document.body.classList.add('traffic-modal-open');
    setTimeout(() => byId('traffic-policy-name')?.focus(), 20);
  }

  function closePolicyEditor() {
    const modal=byId('traffic-policy-modal'); if (modal) { modal.hidden=true; modal.style.display='none'; modal.setAttribute('aria-hidden','true'); }
    document.body.classList.remove('traffic-modal-open');
    resetEditor();
  }

  function policyFromEditor() {
    const location=currentLocation(), sourceMode=byId('traffic-source-mode')?.value || 'interface', iface=byId('traffic-interface')?.value || '';
    const name=(byId('traffic-policy-name')?.value || '').trim() || 'Traffic policy';
    if (!iface) throw new Error('Choose a WireGuard interface.');
    const sourceIp=sourceMode === 'peer' ? (byId('traffic-peer')?.value || '') : '';
    if (sourceMode === 'peer' && !sourceIp) throw new Error('Choose a WireGuard peer.');
    if (!editorTags.domains.length && !editorTags.cidrs.length && !editorTags.countries.length) throw new Error('Add at least one domain, IP/CIDR or country.');
    return { id:(byId('traffic-policy-id')?.value || '').trim(), name, enabled:!!byId('traffic-policy-enabled')?.checked, location, node_id:location === 'node' ? currentNodeId() : null, interface:iface, source_mode:sourceMode, source_ip:sourceIp, domains:[...editorTags.domains], cidrs:[...editorTags.cidrs], countries:[...editorTags.countries] };
  }

  function counterFor(policy) {
    let packets=0, bytes=0;
    const consume=(source) => { Object.entries(source?.counters || {}).forEach(([key,row]) => { if (String(key).startsWith(`${policy.id}:`)) { packets += Number(row?.packets || 0); bytes += Number(row?.bytes || 0); } }); };
    if (policy.location === 'local') consume(payload?.local); else consume(payload?.nodes?.[String(policy.node_id)]);
    return {packets,bytes};
  }

  function humanBytes(bytes) { let n=Number(bytes||0); if(n<1024)return `${n} B`; for(const unit of ['KiB','MiB','GiB','TiB']){n/=1024;if(n<1024||unit==='TiB')return `${n.toFixed(n>=10?1:2)} ${unit}`;} return `${bytes} B`; }

  function policyTargetChips(p, limit = 2) {
    const chips=[];
    (p.domains||[]).forEach(v=>chips.push({kind:'domain',icon:'fa-globe',text:v}));
    (p.cidrs||[]).forEach(v=>chips.push({kind:'cidr',icon:'fa-network-wired',text:v}));
    (p.countries||[]).forEach(v=>{const row=COUNTRY_BY_CODE.get(String(v).toUpperCase());chips.push({kind:'geo',icon:'fa-earth-asia',text:row?`${row.name} · ${row.code}`:`Geo ${String(v).toUpperCase()}`});});
    const shown=chips.slice(0,limit);
    const more=Math.max(0,chips.length-limit);
    return {shown,all:chips,more};
  }

  function renderPolicyTargetChip(chip, compact=false){
    return `<span class="traffic-destination-chip is-${chip.kind}${compact?' is-compact':''}"><i class="fa-solid ${chip.icon}"></i><span>${escapeHtml(chip.text)}</span></span>`;
  }


  function renderPolicies() {
    const host=byId('traffic-policy-list'), empty=byId('traffic-empty'); if(!host)return; host.innerHTML='';
    const showEmpty=policies.length===0; if(empty){empty.hidden=!showEmpty;empty.style.display=showEmpty?'flex':'none';}
    policies.forEach((p,index)=>{
      const target=targets.find(t=>t.name===p.interface&&((p.location==='local'&&t.location==='local')||(p.location==='node'&&Number(t.node_id)===Number(p.node_id))));
      const nodeName=p.location==='node'?(target?.node_name||`Node ${p.node_id}`):'Local panel';
      const counts=counterFor(p), chipState=policyTargetChips(p);
      const visible=chipState.shown.map(chip=>renderPolicyTargetChip(chip)).join('');
      const full=chipState.all.map(chip=>renderPolicyTargetChip(chip,true)).join('');
      const article=document.createElement('article'); article.className='traffic-policy-item traffic-policy-item--row'+(p.enabled===false?' is-disabled':'');
      article.innerHTML=`<div class="traffic-policy-item__state"><span class="traffic-policy-dot"></span></div><div class="traffic-policy-item__main"><div class="traffic-policy-item__top"><b>${escapeHtml(p.name||'Traffic policy')}</b><span class="traffic-mini-badge">${p.enabled===false?'Disabled':'Active'}</span></div><div class="traffic-policy-meta"><span><i class="fa-solid fa-server"></i>${escapeHtml(nodeName)}</span><span><i class="fa-solid fa-network-wired"></i>${escapeHtml(p.interface||'')}</span><span><i class="fa-solid fa-user-shield"></i>${p.source_mode==='peer'?escapeHtml(String(p.source_ip||'').split('/')[0]||'Peer'):'Every peer'}</span></div><div class="traffic-policy-footer"><div class="traffic-policy-targets"><span class="traffic-policy-footer__label">Blocked targets</span><div class="traffic-policy-destinations-wrap"><div class="traffic-policy-destinations">${visible}${chipState.more?`<button type="button" class="traffic-destination-chip traffic-destination-chip--more is-more" data-traffic-chip-toggle="${index}" aria-expanded="false"><span>+${chipState.more} more</span></button>`:''}</div>${chipState.more?`<div class="traffic-chip-popover" id="traffic-chip-popover-${index}" hidden><div class="traffic-chip-popover__head"><strong>Blocked destinations</strong><button type="button" class="traffic-chip-popover__close" data-traffic-chip-close="${index}" aria-label="Close"><i class="fa-solid fa-xmark"></i></button></div><div class="traffic-chip-popover__body">${full}</div></div>`:''}</div></div><div class="traffic-policy-tools"><div class="traffic-policy-counter traffic-policy-counter--inline" title="Traffic actually blocked by this policy"><span><b>${counts.packets.toLocaleString()}</b> pkt</span><span class="traffic-policy-counter__sep" aria-hidden="true">/</span><span><b>${humanBytes(counts.bytes)}</b></span></div><div class="traffic-policy-actions traffic-policy-actions--row"><button class="traffic-action-text" type="button" data-traffic-verify="${index}" title="Check live policy setup">Check</button><button class="traffic-action-text" type="button" data-traffic-manual="${index}" title="Test a destination against this policy">Test</button><button class="traffic-action-text" type="button" data-traffic-edit="${index}" title="Edit policy">Edit</button><button class="traffic-action-text traffic-action-delete" type="button" data-traffic-delete="${index}" title="Delete policy">Delete</button></div></div></div></div>`;
      host.appendChild(article);
    });
    const state=byId('traffic-rule-state'); if(state)state.innerHTML=`<i class="fa-solid fa-shield"></i> ${policies.length} polic${policies.length===1?'y':'ies'}`;
  }


  function renderCapability() {
    const host=byId('traffic-capability'), engine=byId('traffic-engine-state'); if(!host)return;
    const rows=[]; const local=payload?.local||{}, localCap=local.capability||{};
    rows.push({name:'Local panel',ready:!!localCap.usable,loaded:!!local.loaded,detail:localCap.usable?(local.loaded?'Traffic rules are active':'Ready for Traffic Control'):(localCap.reason==='not_installed'?'nftables is not installed':(localCap.detail||'Unavailable'))});
    availableNodes().forEach(n=>{const st=payload?.nodes?.[String(n.id)]||{},cap=st.capability||{};rows.push({name:n.name,ready:!!cap.usable,loaded:!!st.loaded,detail:cap.usable?(st.loaded?'Traffic rules are active':'Ready for Traffic Control'):(st.error||cap.detail||'Unavailable')});});
    host.innerHTML=`<div class="traffic-cap-chips">${rows.map(r=>`<span class="traffic-cap-chip ${r.ready?'is-good':'is-warn'} ${r.loaded?'is-active':''}" title="${escapeHtml(r.detail)}"><i class="fa-solid ${r.ready?'fa-circle-check':'fa-triangle-exclamation'}"></i><span class="traffic-cap-chip__name">${escapeHtml(r.name)}</span><span class="traffic-cap-chip__state">${escapeHtml(r.loaded?'Active':(r.ready?'Ready':'Unavailable'))}</span></span>`).join('')}</div>`;
    const allReady=rows.length&&rows.every(r=>r.ready); if(engine){engine.className='traffic-state '+(allReady?'good':'warn');engine.innerHTML=`<i class="fa-solid fa-circle"></i> ${allReady?'Traffic Control ready':'Needs attention'}`;}
  }

  function friendlyCheckName(row, packets) {
    const key=String(row?.key||'').toLowerCase(), status=String(row?.status||'info').toLowerCase(), label=String(row?.label||'').toLowerCase();
    if(status==='fail') return 'Needs attention';
    if(status==='warn') return 'Please review';
    if(status==='info') { if(key==='counters'||label.includes('counter')) return packets>0?'Traffic blocked':'Waiting for traffic'; if(label.includes('ipv6')) return 'Not used'; return 'For your information'; }
    if(key==='interface') return 'Active';
    if(key==='scope') return 'Correct peer';
    if(key==='table'||key==='nftables') return 'Ready';
    if(key.includes('domain')||label.includes('domain addresses')) return 'Up to date';
    if(key.includes('geo')||label.includes('geo')) return 'Country block ready';
    if(key.includes('direct')||label.includes('rule')) return 'Rule ready';
    if(key==='counters') return packets>0?'Traffic blocked':'Waiting for traffic';
    return 'Ready';
  }

  function friendlyCheckIcon(row) { const status=String(row?.status||'info'); if(status==='fail')return 'fa-circle-exclamation'; if(status==='warn')return 'fa-triangle-exclamation'; if(status==='info')return 'fa-circle-info'; return 'fa-circle-check'; }

  function policyScopeChips(policy) {
    const chips=[]; if(policy?.interface)chips.push({kind:'scope',icon:'fa-network-wired',text:policy.interface});
    if(policy?.source_mode==='peer'&&policy?.source_ip)chips.push({kind:'peer',icon:'fa-user-shield',text:`Peer ${String(policy.source_ip).split('/')[0]}`}); else chips.push({kind:'scope',icon:'fa-users',text:'Every peer'});
    return chips;
  }

  function renderProtectedChips(policy) {
    const scope=policyScopeChips(policy), targetsChips=policyTargetChips(policy,50).all;
    const render=(chip)=>`<span class="traffic-lock-chip is-${chip.kind}"><i class="fa-solid ${chip.icon}"></i>${escapeHtml(chip.text)}</span>`;
    return `<div class="traffic-verify-targets"><div class="traffic-verify-targets__group"><span class="traffic-verify-targets__label">Applies to</span><div>${scope.map(render).join('')}</div></div><div class="traffic-verify-targets__group"><span class="traffic-verify-targets__label">Blocks</span><div>${targetsChips.map(render).join('')||'<span class="traffic-token-empty">No destinations</span>'}</div></div></div>`;
  }

  function closeVerify() { setHidden(byId('traffic-verify-card'),true); }
  function closeManual() { setHidden(byId('traffic-manual-card'),true); activeTrafficTestIndex=null; }

  function renderTrafficTest(result, policy) {
    const card=byId('traffic-verify-card'), host=byId('traffic-verify-result'); if(!card||!host)return;
    const checks=Array.isArray(result?.checks)?result.checks:[], ok=!!result?.ok, counters=result?.counters||{}, packets=Number(counters.packets||0), bytes=Number(counters.bytes||0);
    let headline='Needs attention', summary='One or more live rules do not match this saved policy yet.', stateClass='is-fail', icon='fa-triangle-exclamation';
    if(ok&&packets>0){headline='Live blocking confirmed';summary=`This policy is correctly loaded and has already blocked ${packets.toLocaleString()} matching packet${packets===1?'':'s'}.`;stateClass='is-live';icon='fa-shield-heart';}
    else if(ok){headline='Ready to block';summary='The live rules match this policy. No matching client traffic has reached the rule yet.';stateClass='is-ready';icon='fa-shield-circle-check';}
    byId('traffic-verify-heading').textContent=`Check policy setup · ${policy?.name||result?.policy_name||'Traffic policy'}`;
    host.innerHTML=`<div class="traffic-test-summary ${stateClass}"><span class="traffic-test-summary__icon"><i class="fa-solid ${icon}"></i></span><span><b>${escapeHtml(headline)}</b><small>${escapeHtml(summary)}</small></span><em>${escapeHtml(headline)}</em></div>${renderProtectedChips(policy)}<div class="traffic-test-grid">${checks.map(row=>`<div class="traffic-test-row is-${escapeHtml(row.status||'info')}"><i class="fa-solid ${friendlyCheckIcon(row)}"></i><span><b>${escapeHtml(row.label||row.key||'Check')}</b><small>${escapeHtml(row.detail||'')}</small></span><em>${escapeHtml(friendlyCheckName(row,packets))}</em></div>`).join('')}</div><div class="traffic-test-counters"><span><i class="fa-solid fa-ban"></i><b>${packets.toLocaleString()}</b><small>packets actually blocked</small></span><span><i class="fa-solid fa-database"></i><b>${humanBytes(bytes)}</b><small>traffic actually blocked</small></span><span><i class="fa-solid fa-circle-info"></i><small>${packets>0?'Real forwarded traffic has hit this policy.':'The setup is ready, but only a real WireGuard client packet can increase these counters.'}</small></span></div>`;
    setHidden(card,false); card.scrollIntoView({behavior:'smooth',block:'center'});
  }

  function manualVerdictText(verdict) { if(verdict==='blocked')return 'Would be blocked'; if(verdict==='partial')return 'Some addresses would be blocked'; if(verdict==='not_applicable')return 'Not used by this peer'; return 'Would be allowed'; }
  function manualVerdictIcon(verdict) { if(verdict==='blocked')return 'fa-ban'; if(verdict==='partial')return 'fa-triangle-exclamation'; if(verdict==='not_applicable')return 'fa-circle-minus'; return 'fa-circle-check'; }

  function renderManualTrafficResult(result) {
    const host=byId('traffic-test-target-result'); if(!host)return;
    const verdict=String(result?.verdict||'not_blocked'), rows=Array.isArray(result?.results)?result.results:[];
    const summary=verdict==='blocked'?'Every usable resolved address matches this policy’s live block rule.':verdict==='partial'?'Some resolved addresses are blocked while others are currently allowed.':verdict==='not_applicable'?'The resolved address family is not used by this WireGuard peer.':'No usable resolved address matches this policy’s live block rule.';
    host.hidden=false;host.style.display='block';
    host.innerHTML=`<div class="traffic-manual-verdict is-${escapeHtml(verdict)}"><span><i class="fa-solid ${manualVerdictIcon(verdict)}"></i></span><div><b>${escapeHtml(manualVerdictText(verdict))}</b><small>${escapeHtml(summary)}</small></div><em>${escapeHtml(String(result?.target||''))}</em></div><div class="traffic-manual-resolved">${rows.length?rows.map(row=>`<div class="traffic-manual-resolved__row ${row.applicable===false?'is-skip':row.blocked?'is-blocked':'is-allowed'}"><span><i class="fa-solid ${row.applicable===false?'fa-circle-minus':row.blocked?'fa-ban':'fa-circle-check'}"></i><b>${escapeHtml(row.ip||'')}</b><small>IPv${escapeHtml(String(row.version||''))}</small></span><span>${Array.isArray(row.matches)&&row.matches.length?row.matches.map(m=>`<code>${escapeHtml(m.label||m.kind||'Matched rule')}</code>`).join(' '):`<small>${escapeHtml(row.note||(row.applicable===false?'Not used by this peer':'No matching block rule'))}</small>`}</span><em>${row.applicable===false?'Not used':row.blocked?'Blocked':'Allowed'}</em></div>`).join(''):'<div class="traffic-manual-resolved__empty">No usable destination address was resolved.</div>'}</div><div class="traffic-manual-foot"><i class="fa-solid fa-shield-halved"></i><span>${escapeHtml(result?.scope||'')}</span><small>Prediction from the live kernel rules; this does not generate traffic as the peer.</small></div>`;
  }

  function manualSuggestions(policy, query) {
    const q=String(query||'').trim().toLowerCase();
    let values=uniq([
      ...(policy?.domains||[]),
      ...(policy?.cidrs||[]).filter(v=>!String(v).includes('/')),
    ]);
    if(q) values=values.filter(v=>String(v).toLowerCase().includes(q));
    return uniq(values).slice(0,8);
  }

  function renderManualAutocomplete(query) {
    const box=byId('traffic-test-autocomplete'), policy=activeTrafficTestIndex==null?null:policies[activeTrafficTestIndex]; if(!box||!policy)return;
    const rows=manualSuggestions(policy,query);
    if(!String(query||'').trim()||!rows.length){box.hidden=true;box.style.display='none';box.innerHTML='';return;}
    box.innerHTML=rows.map(v=>`<button type="button" data-traffic-manual-suggestion="${escapeHtml(v)}"><i class="fa-solid ${/^\d/.test(v)?'fa-network-wired':'fa-globe'}"></i><span>${escapeHtml(v)}</span><small>Saved in this policy</small></button>`).join('');
    box.hidden=false;box.style.display='grid';
  }

  function renderManualQuickTargets(policy) {
    const host=byId('traffic-test-quick'); if(!host)return;
    const domains=uniq(policy?.domains||[]), exact=uniq((policy?.cidrs||[]).filter(v=>!String(v).includes('/'))), countries=uniq(policy?.countries||[]);
    const buttons=[...domains,...exact].slice(0,8).map(value=>`<button type="button" data-traffic-quick-target="${escapeHtml(value)}"><i class="fa-solid ${/^\d/.test(value)?'fa-network-wired':'fa-globe'}"></i>${escapeHtml(value)}</button>`).join('');
    const geo=countries.slice(0,5).map(code=>{const row=COUNTRY_BY_CODE.get(String(code).toUpperCase());return `<span class="traffic-quick-geo"><i class="fa-solid fa-earth-asia"></i>${escapeHtml(row?`${row.name} · ${row.code}`:`Geo ${String(code).toUpperCase()}`)}</span>`;}).join('');
    host.innerHTML=(buttons||geo)?`<span>Quick fill from this policy</span>${buttons}${geo}`:'<span>Type any domain or IP to see whether this policy would block it.</span>';
  }

  function openManualDestinationTest(index) {
    const p=policies[index]; if(!p)return;
    if(dirty){toast('Traffic Control is still applying the latest change. Try again in a moment.','warning');return;}
    if(p.enabled===false){toast('This policy is disabled, so there is no live block rule to test.','info');return;}
    activeTrafficTestIndex=index; closeVerify();
    byId('traffic-manual-heading').textContent=`Test destination · ${p.name||'Traffic policy'}`;
    byId('traffic-manual-selected').innerHTML=`<div><b>Testing this policy</b><small>The target is checked only against this policy’s live rules.</small></div><div>${policyScopeChips(p).map(c=>`<span class="traffic-lock-chip is-${c.kind}"><i class="fa-solid ${c.icon}"></i>${escapeHtml(c.text)}</span>`).join('')}${policyTargetChips(p,6).all.map(c=>`<span class="traffic-lock-chip is-${c.kind}"><i class="fa-solid ${c.icon}"></i>${escapeHtml(c.text)}</span>`).join('')}</div>`;
    renderManualQuickTargets(p);
    const result=byId('traffic-test-target-result'); if(result){result.hidden=true;result.style.display='none';result.innerHTML='';}
    const input=byId('traffic-test-target'); if(input){input.value=(p.domains||[])[0]||(p.cidrs||[]).find(v=>!String(v).includes('/'))||'';}
    renderManualAutocomplete(''); setHidden(byId('traffic-manual-card'),false);
    byId('traffic-manual-card')?.scrollIntoView({behavior:'smooth',block:'center'}); setTimeout(()=>{input?.focus();input?.select?.();},20);
  }

  async function manualTestDestination() {
    if(activeTrafficTestIndex==null){toast('Choose Test destination on a policy first.','warning');return;}
    const policy=policies[activeTrafficTestIndex]; if(!policy)return;
    if(dirty){toast('Traffic Control is still applying the latest change. Try again in a moment.','warning');return;}
    const input=byId('traffic-test-target'), target=(input?.value||'').trim(); if(!target){toast('Enter a domain, URL or IP to test.','warning');input?.focus();return;}
    const button=byId('traffic-test-target-run'); if(button)button.disabled=true;
    try{const result=await trafficFetch('/api/traffic-control/test-destination',{method:'POST',body:{policy_id:policy.id,target}});renderManualTrafficResult(result);}
    catch(e){toast('Destination test failed: '+(e?.message||'unknown'),'error');} finally{if(button)button.disabled=false;}
  }

  async function testPolicy(index) {
    const p=policies[index]; if(!p)return;
    if(dirty){toast('Traffic Control is still applying the latest change. Try again in a moment.','warning');return;}
    if(p.enabled===false){toast('This policy is disabled and is intentionally not loaded.','info');return;}
    closeManual(); const button=document.querySelector(`[data-traffic-verify="${index}"]`); if(button)button.disabled=true;
    try{toast(`Checking “${p.name||'Traffic policy'}”…`,'info');const result=await trafficFetch('/api/traffic-control/test',{method:'POST',body:{policy_id:p.id}});renderTrafficTest(result,p);toast(result?.ok?'Live policy setup is ready.':'This policy needs attention.',result?.ok?'success':'warning');await loadTraffic({preservePanels:true});}
    catch(e){toast('Policy check failed: '+(e?.message||'unknown'),'error');} finally{if(button)button.disabled=false;}
  }

  async function persistTrafficAutomatically(successMessage='Traffic Control updated.') {
    setDirty(true);
    try {
      await trafficFetch('/api/traffic-control',{method:'POST',body:{enabled:true,policies}});
      await trafficFetch('/api/traffic-control/apply',{method:'POST',body:{}});
      await loadTraffic();
      toast(successMessage,'success');
      return true;
    } catch (e) {
      setDirty(false);
      toast('Could not save/apply Traffic Control: '+(e?.message||'unknown error'),'error');
      return false;
    }
  }

  async function addOrUpdatePolicy() {
    const before=policies.map(p=>({...p,domains:[...(p.domains||[])],cidrs:[...(p.cidrs||[])],countries:[...(p.countries||[])]}));
    try {
      const p=policyFromEditor();
      const existingIndex=p.id?policies.findIndex(x=>x.id===p.id):-1;
      if(existingIndex>=0) policies[existingIndex]=p;
      else { p.id=`p_${Date.now().toString(36)}_${Math.random().toString(36).slice(2,8)}`; policies.push(p); }
      renderPolicies();
      const ok=await persistTrafficAutomatically(existingIndex>=0?'Policy updated and applied.':'Policy added and applied.');
      if(ok) closePolicyEditor();
      else { policies=before; renderPolicies(); }
    } catch(e) { toast(e.message||'Invalid traffic policy','error'); }
  }

  async function loadTraffic(options={}) {
    try{payload=await trafficFetch('/api/traffic-control');policies=Array.isArray(payload?.policies)?payload.policies.map(p=>({...p})):[];targets=Array.isArray(payload?.targets)?payload.targets:[];fillNodeSelect();syncScopeUI();fillInterfaceSelect();renderCapability();renderPolicies();setDirty(false);}
    catch(e){toast('Traffic Control load failed: '+(e?.message||'unknown'),'error');const engine=byId('traffic-engine-state');if(engine){engine.className='traffic-state danger';engine.innerHTML='<i class="fa-solid fa-circle"></i> Backend unavailable';}}
  }

  async function saveTraffic({apply=false}={}) {
    const button=byId(apply?'traffic-save-apply':'traffic-save');if(button)button.disabled=true;
    try{await trafficFetch('/api/traffic-control',{method:'POST',body:{enabled:true,policies}});if(apply){toast('Applying Traffic Control rules…','info');await trafficFetch('/api/traffic-control/apply',{method:'POST',body:{}});toast('Traffic Control rules are active.','success');}else toast('Policy configuration saved. Live rules were not changed.','info');await loadTraffic();}
    catch(e){toast((apply?'Apply failed: ':'Save failed: ')+(e?.message||'unknown'),'error');}finally{if(button)button.disabled=false;}
  }

  function setTrafficHowOpen(open) {
    const pop=byId('traffic-how-popover'), trigger=byId('traffic-how-trigger');
    if(!pop || !trigger) return;
    pop.hidden=!open;
    trigger.setAttribute('aria-expanded', open ? 'true' : 'false');
  }

  byId('traffic-add-policy')?.addEventListener('click',()=>openPolicyEditor());
  byId('traffic-policy-close')?.addEventListener('click',closePolicyEditor);byId('traffic-policy-cancel')?.addEventListener('click',closePolicyEditor);
  byId('traffic-policy-modal')?.addEventListener('click',e=>{if(e.target.closest('[data-traffic-editor-close]'))closePolicyEditor();});
  byId('traffic-how-trigger')?.addEventListener('click',e=>{e.stopPropagation(); const pop=byId('traffic-how-popover'); setTrafficHowOpen(!!pop?.hidden);});
  byId('traffic-how-close')?.addEventListener('click',()=>setTrafficHowOpen(false));
  byId('traffic-how-popover')?.addEventListener('click',e=>e.stopPropagation());
  document.addEventListener('click',e=>{const pop=byId('traffic-how-popover'), trigger=byId('traffic-how-trigger'); if(!pop || pop.hidden) return; if(e.target.closest('#traffic-how-trigger') || e.target.closest('#traffic-how-popover')) return; setTrafficHowOpen(false);});
  byId('traffic-location')?.addEventListener('change',()=>{syncScopeUI();fillNodeSelect();fillInterfaceSelect();});byId('traffic-node')?.addEventListener('change',()=>fillInterfaceSelect());byId('traffic-interface')?.addEventListener('change',()=>fillPeerSelect());byId('traffic-source-mode')?.addEventListener('change',()=>{syncScopeUI();fillPeerSelect();});byId('traffic-peer')?.addEventListener('change',()=>{const note=byId('traffic-peer-address');if(note)note.textContent=byId('traffic-peer')?.value?`WireGuard source: ${byId('traffic-peer').value}`:'';});
  byId('traffic-policy-save')?.addEventListener('click',addOrUpdatePolicy);byId('traffic-refresh')?.addEventListener('click',loadTraffic);
  byId('traffic-verify-close')?.addEventListener('click',closeVerify);byId('traffic-manual-close')?.addEventListener('click',closeManual);
  byId('traffic-test-target-run')?.addEventListener('click',manualTestDestination);byId('traffic-test-target')?.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();manualTestDestination();}});byId('traffic-test-target')?.addEventListener('input',e=>renderManualAutocomplete(e.target.value));byId('traffic-test-target')?.addEventListener('focus',e=>renderManualAutocomplete(e.target.value));
  byId('traffic-test-autocomplete')?.addEventListener('click',e=>{const b=e.target.closest('[data-traffic-manual-suggestion]');if(!b)return;const input=byId('traffic-test-target');if(input)input.value=b.dataset.trafficManualSuggestion||'';renderManualAutocomplete('');});
  byId('traffic-test-quick')?.addEventListener('click',e=>{const b=e.target.closest('[data-traffic-quick-target]');if(!b)return;const input=byId('traffic-test-target');if(input)input.value=b.dataset.trafficQuickTarget||'';manualTestDestination();});

  const tokenInputMap={domains:'traffic-domain-entry',cidrs:'traffic-cidr-entry',countries:'traffic-country-entry'};
  Object.entries(tokenInputMap).forEach(([kind,id])=>{const input=byId(id);input?.addEventListener('input',e=>showTokenSuggestions(kind,e.target.value));input?.addEventListener('focus',e=>showTokenSuggestions(kind,e.target.value));input?.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===','){e.preventDefault();addEditorTag(kind,e.target.value);}});});
  document.querySelectorAll('[data-traffic-token-add]').forEach(button=>button.addEventListener('click',()=>{const kind=button.dataset.trafficTokenAdd,input=byId(tokenInputMap[kind]);addEditorTag(kind,input?.value||'');input?.focus();}));
  document.querySelectorAll('.traffic-token-suggestions').forEach(box=>box.addEventListener('click',e=>{const b=e.target.closest('[data-traffic-token-suggestion]');if(!b)return;addEditorTag(b.dataset.trafficTokenSuggestion,b.dataset.value||'');byId(tokenInputMap[b.dataset.trafficTokenSuggestion])?.focus();}));
  document.querySelector('.traffic-policy-dialog')?.addEventListener('click',e=>{const b=e.target.closest('[data-traffic-token-remove]');if(!b)return;const kind=b.dataset.trafficTokenRemove,index=Number(b.dataset.index);if(editorTags[kind]&&Number.isInteger(index)){editorTags[kind].splice(index,1);renderEditorTags(kind);}});

  byId('traffic-policy-list')?.addEventListener('click',async e=>{const toggle=e.target.closest('[data-traffic-chip-toggle]'),closeChip=e.target.closest('[data-traffic-chip-close]'),verify=e.target.closest('[data-traffic-verify]'),manual=e.target.closest('[data-traffic-manual]'),edit=e.target.closest('[data-traffic-edit]'),del=e.target.closest('[data-traffic-delete]');if(toggle){const id=String(toggle.dataset.trafficChipToggle||'');document.querySelectorAll('.traffic-chip-popover').forEach(pop=>{if(pop.id!==`traffic-chip-popover-${id}`)pop.hidden=true;});document.querySelectorAll('[data-traffic-chip-toggle]').forEach(btn=>{if(btn!==toggle)btn.setAttribute('aria-expanded','false');});const pop=byId(`traffic-chip-popover-${id}`);if(pop){const open=pop.hidden;pop.hidden=!open;toggle.setAttribute('aria-expanded',open?'true':'false');}return;}if(closeChip){const id=String(closeChip.dataset.trafficChipClose||'');const pop=byId(`traffic-chip-popover-${id}`),btn=document.querySelector(`[data-traffic-chip-toggle="${id}"]`);if(pop)pop.hidden=true;if(btn)btn.setAttribute('aria-expanded','false');return;}if(verify){await testPolicy(Number(verify.dataset.trafficVerify));return;}if(manual){openManualDestinationTest(Number(manual.dataset.trafficManual));return;}if(edit){const p=policies[Number(edit.dataset.trafficEdit)];if(p)openPolicyEditor(p);return;}if(del){const index=Number(del.dataset.trafficDelete),p=policies[index];if(!p)return;const ok=await window.confirmDialog?.({title:'Delete traffic policy?',body:`Remove “${p.name||'Traffic policy'}”? This will also remove its live rule immediately.`,okText:'Delete',cancelText:'Cancel'});if(!ok)return;const before=policies.map(row=>({...row,domains:[...(row.domains||[])],cidrs:[...(row.cidrs||[])],countries:[...(row.countries||[])]}));policies.splice(index,1);renderPolicies();closeVerify();closeManual();const saved=await persistTrafficAutomatically('Policy deleted and live rules updated.');if(!saved){policies=before;renderPolicies();}}});

  document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!byId('traffic-policy-modal')?.hidden)closePolicyEditor();});
  document.addEventListener('click',e=>{if(!e.target.closest('.traffic-token-card'))['domains','cidrs','countries'].forEach(hideTokenSuggestions);if(!e.target.closest('.traffic-autocomplete-field')){const box=byId('traffic-test-autocomplete');if(box){box.hidden=true;box.style.display='none';}}});
  document.getElementById('set-tabs')?.addEventListener('click',e=>{if(e.target.closest('.tab')?.dataset?.tab==='traffic')loadTraffic();});
  if(document.documentElement.getAttribute('data-tab')==='traffic')loadTraffic();
})();

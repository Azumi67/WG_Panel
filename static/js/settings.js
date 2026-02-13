
(() => {
  const $  = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  function _parseTs(any){
  if (!any && any!==0) return null;
  if (any instanceof Date) return isNaN(any)?null:any;
  const n = Number(any);
  if (Number.isFinite(n) && String(any).trim()!=='') {
    const ms = n >= 1e12 ? n : n*1000;
    const d = new Date(ms); return isNaN(d)?null:d;
  }
  const s = String(any).trim(); if (!s) return null;
  const d = new Date(s); return isNaN(d)?null:d;
}
function _fmtLocal(d){
  return d.toLocaleString(undefined, {year:'numeric',month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});
}
function _fmtAgo(d){
  const sec = Math.max(0, Math.floor((Date.now()-d.getTime())/1000));
  const m = Math.floor(sec/60), h=Math.floor(m/60), d2=Math.floor(h/24);
  if (d2>0) return `${d2}d ${h%24}h ago`;
  if (h>0)  return `${h}h ${m%60}m ago`;
  if (m>0)  return `${m}m ago`;
  return `${sec}s ago`;
}


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
    ['tg-logs-modal', 'iface-logs-modal', 'tg-add-modal', 'admin-logs-modal'].forEach(id => {
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

  async function loadPanelSettings() {
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
  }

  document.addEventListener('DOMContentLoaded', async () => {
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
    function humanDate(d = new Date()) {
    const day   = d.getDate(); 
    const month = d.toLocaleString(undefined, { month: 'long' }); 
    const year  = d.getFullYear();
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    const ss = String(d.getSeconds()).padStart(2, '0');
    return `${day}_${month}_${year}_${hh}-${mm}-${ss}`;
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
            const ts  = x.ts || x.time || x.timestamp || '';
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



  (function telegram() {
    function fmtLocal(iso) {
      if (!iso) return '—'; const d = new Date(iso);
      return d.toLocaleString(undefined, { year:'numeric', month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit' });
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
        $('#tg-n-app').checked   = !!n.app_down;
        $('#tg-n-iface').checked = !!n.iface_down;
        $('#tg-n-login').checked = !!n.login_fail;
        $('#tg-n-4xx').checked   = !!n.suspicious_4xx;
        updateChips({ enabled: s.enabled, has_token: s.has_token, admins: [] });
      } catch { toast('Failed to load Telegram settings', 'error'); }
    }
    async function saveSettings() {
      const payload = {
        enabled: $('#tg-enabled').checked,
        notify: {
          app_down:   $('#tg-n-app').checked,
          iface_down: $('#tg-n-iface').checked,
          login_fail: $('#tg-n-login').checked,
          suspicious_4xx: $('#tg-n-4xx').checked
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

    function _parseTs(any) {
      if (!any && any !== 0) return null;
      if (any instanceof Date) return isNaN(any) ? null : any;
      const n = Number(any);
      if (Number.isFinite(n) && String(any).trim() !== '') {
        const ms = n >= 1e12 ? n : n * 1000;
        const d = new Date(ms); return isNaN(d) ? null : d;
      }
      const s = String(any).trim(); if (!s) return null;
      const d = new Date(s); return isNaN(d) ? null : d;
    }
    function _fmtLocal(d) {
      if (!d) return '—';
      return d.toLocaleString(undefined, { year:'numeric', month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit' });
    }
    function _fmtAgo(d) {
      if (!d) return '';
      const sec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
      const min = Math.floor(sec / 60), hr = Math.floor(min / 60), day = Math.floor(hr / 24);
      if (day > 0) return `${day}d ${hr % 24}h ago`;
      if (hr > 0) return `${hr}h ${min % 60}m ago`;
      if (min > 0) return `${min}m ago`;
      return `${sec}s ago`;
    }
    function _isoLocalToZ(s) { if (!s) return ''; const d = new Date(s); if (isNaN(d.getTime())) return ''; return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 19) + 'Z'; }
    function badge(kind) {
      const k = (kind || 'info').toLowerCase();
      const map = { error:{cls:'lvl-badge lvl-error',text:'ERROR'}, warning:{cls:'lvl-badge lvl-warning',text:'WARN'}, info:{cls:'lvl-badge lvl-info',text:'INFO'}, heartbeat:{cls:'lvl-badge lvl-heartbeat',text:'HEART'} };
      const m = map[k] || map.info; return `<span class="${m.cls}">${m.text}</span>`;
    }
    function escapeHtml(s) { return String(s).replace(/[&<>\"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
    function formatStamp(any) { const d = _parseTs(any); return { text:_fmtLocal(d), ago:_fmtAgo(d) }; }
    

    async function loadTgLogs() {
      const list = $('#tg-logs-list');
      const q = ($('#tg-q')?.value || '').trim();
      const level = ($('#tg-level')?.value || '').trim();
      const fromV = _isoLocalToZ($('#tg-from')?.value || '');
      const toV   = _isoLocalToZ($('#tg-to')?.value || '');
      const params = new URLSearchParams({ format:'json', limit:'800' });
      if (q) params.set('q', q); if (level) params.set('level', level);
      if (fromV) params.set('from', fromV); if (toV) params.set('to', toV);
      const j = await jfetch('/api/telegram/logs?' + params.toString()).catch(()=>({logs:[]}));
      const logs = Array.isArray(j.logs) ? j.logs : [];
      if (!logs.length) { list.innerHTML = `<div class="log-row" style="opacity:.7">(no logs yet)</div>`; return; }
      list.innerHTML = logs.map(x => {
        const dt = formatStamp(x.ts || x.time || x.timestamp);
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

    function pad2(n) { return String(n).padStart(2, '0'); }

    function formatStamp(any) {
      const d = (function parse(any) {
        if (!any && any !== 0) return null;
        if (any instanceof Date) return isNaN(any) ? null : any;

        const n = Number(any);
        if (Number.isFinite(n) && String(any).trim() !== '') {
          const ms = n >= 1e12 ? n : n * 1000;  
          const dd = new Date(ms);
          return isNaN(dd) ? null : dd;
        }

        const s = String(any).trim();
        if (!s) return null;
        const dd = new Date(s);
        return isNaN(dd) ? null : dd;
      })(any);

      if (!d) return { text: '—', ago: '—' };

      const text =
        `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ` +
        `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;

      const sec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
      const min = Math.floor(sec / 60);
      const hr  = Math.floor(min / 60);
      const day = Math.floor(hr / 24);

      const ago =
        day > 0 ? `${day}d ${hr % 24}h ago` :
        hr  > 0 ? `${hr}h ${min % 60}m ago` :
        min > 0 ? `${min}m ago` :
                  `${sec}s ago`;

      return { text, ago };
    }
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
      const stamp = formatStamp(x.ts || x.time || x.timestamp);

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
      a.download = `admin_logs_${new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19)}.csv`;
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
    (window.toastSafe || console.log)('Settings ready', 'success');
  });
})();

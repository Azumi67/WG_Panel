(() => {
  'use strict';
  const $ = (s, root=document) => root.querySelector(s);
  const $$ = (s, root=document) => [...root.querySelectorAll(s)];
  const defaults = {
    layout:'aurora', background:'aurora', display_mode:'hybrid', animation:'balanced',
    accent:'mint', surface:'glass', radius:'rounded', density:'comfortable',
    config_style:'cards', support_style:'buttons', theme_default:'auto',
    show_quick_stats:true, show_install:true, show_support:true, show_live_badge:true,
    portal_label:'Secure WireGuard portal', portal_title:'',
    portal_subtitle:'Your account is ready. Install WireGuard, then scan QR or import a config.',
    portal_icon:'fas fa-bolt', support:{}
  };
  const labels = {
    layout:{aurora:'Modern',cards:'Dashboard',compact:'Compact',minimal:'Minimal',split:'Split',profile:'Profile'},
    background:{aurora:'Aurora',waves:'Waves',network:'Network',orbits:'Orbits',mesh:'Mesh',lines:'Lines',none:'None'},
    display_mode:{bars:'Progress bars',rings:'Circles',hybrid:'Hybrid',focus:'Large values',minimal:'Compact rows',segments:'Segments'},
    animation:{rich:'Rich',balanced:'Balanced',soft:'Soft',minimal:'Minimal',off:'Off'},
    accent:{mint:'Mint',blue:'Blue',violet:'Violet',coral:'Coral',amber:'Amber',mono:'Monochrome'}
  };
  let previewTheme = 'auto';
  let previewDevice = 'desktop';
  let previewTimer = 0;

  function choose(name, value){
    const input = $(`input[name="${name}"][value="${CSS.escape(String(value))}"]`);
    if(input) input.checked = true;
  }
  function checked(name, fallback){ return $(`input[name="${name}"]:checked`)?.value || fallback; }
  function setValue(id, value){ const el=$('#'+id); if(el) el.value=value ?? ''; }
  function setCheck(id, value){ const el=$('#'+id); if(el) el.checked=!!value; }
  function escapeHtml(value){ return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch])); }
  function supportValues(){ const o={}; ['telegram','whatsapp','phone','email','website','instagram'].forEach(k=>o[k]=$('#sup-'+k)?.value?.trim()||''); return o; }

  window.applySettingsToForm = function(){
    const currentSettings = (typeof SUB_SETTINGS !== 'undefined' && SUB_SETTINGS) ? SUB_SETTINGS : {};
    const s = Object.assign({}, defaults, currentSettings);
    choose('sub-layout', s.layout);
    choose('sub-background', s.background);
    choose('sub-display-mode', s.display_mode);
    choose('portal-animation-choice', s.animation);
    choose('sub-accent', s.accent);
    choose('sub-surface', s.surface);
    choose('sub-radius', s.radius);
    choose('sub-density', s.density);
    choose('sub-config-style', s.config_style);
    choose('sub-support-style', s.support_style);
    choose('sub-theme-default', s.theme_default);
    const anim=$('#portal-animation'); if(anim) anim.value=s.animation||defaults.animation;
    setCheck('show-quick-stats', s.show_quick_stats !== false);
    setCheck('show-install', s.show_install !== false);
    setCheck('show-support', s.show_support !== false);
    setCheck('show-live-badge', s.show_live_badge !== false);
    setValue('portal-label', s.portal_label);
    setValue('portal-title', s.portal_title);
    setValue('portal-subtitle', s.portal_subtitle);
    setValue('portal-icon', s.portal_icon);
    const support=s.support||{}; ['telegram','whatsapp','phone','email','website','instagram'].forEach(k=>setValue('sup-'+k,support[k]||''));
    setStudioTab('layout');
    refreshStudio();
  };

  window.collectSettingsForm = function(){
    return {
      layout:checked('sub-layout',defaults.layout), background:checked('sub-background',defaults.background),
      display_mode:checked('sub-display-mode',defaults.display_mode), animation:checked('portal-animation-choice',defaults.animation),
      accent:checked('sub-accent',defaults.accent), surface:checked('sub-surface',defaults.surface),
      radius:checked('sub-radius',defaults.radius), density:checked('sub-density',defaults.density),
      config_style:checked('sub-config-style',defaults.config_style), support_style:checked('sub-support-style',defaults.support_style),
      theme_default:checked('sub-theme-default',defaults.theme_default),
      show_quick_stats:!!$('#show-quick-stats')?.checked, show_install:!!$('#show-install')?.checked,
      show_support:!!$('#show-support')?.checked, show_live_badge:!!$('#show-live-badge')?.checked,
      portal_label:$('#portal-label')?.value||'', portal_title:$('#portal-title')?.value||'',
      portal_subtitle:$('#portal-subtitle')?.value||'', portal_icon:$('#portal-icon')?.value||defaults.portal_icon,
      support:supportValues()
    };
  };
  window.updateLayoutPreview = () => refreshStudio();

  function setStudioTab(name){
    $$('.studio7-nav [data-studio7-tab]').forEach(btn=>btn.classList.toggle('active',btn.dataset.studio7Tab===name));
    $$('.studio7-panel[data-studio7-panel]').forEach(panel=>{ const active=panel.dataset.studio7Panel===name; panel.classList.toggle('active',active); panel.hidden=!active; });
  }
  $$('.studio7-nav [data-studio7-tab]').forEach(btn=>btn.addEventListener('click',()=>setStudioTab(btn.dataset.studio7Tab)));

  function setAdvancedTab(name){
    $$('.adv7-tabs [data-adv7-tab]').forEach(btn=>btn.classList.toggle('active',btn.dataset.adv7Tab===name));
    $$('.adv7-panel[data-adv7-panel]').forEach(panel=>{ const active=panel.dataset.adv7Panel===name; panel.classList.toggle('active',active); panel.hidden=!active; });
  }
  $$('.adv7-tabs [data-adv7-tab]').forEach(btn=>btn.addEventListener('click',()=>setAdvancedTab(btn.dataset.adv7Tab)));

  function updateAdvancedSummary(){
    const form=$('#sub-form'); if(!form) return;
    const tags=[];
    const allowed=form.querySelector('[name="allowed_ips"]')?.value?.trim()||'';
    const prefix=form.querySelector('[name="peer_name_prefix"]')?.value?.trim()||'';
    const selected=(window.getSelectedInternalNetworks?.()||[]).length;
    if(prefix || (allowed && allowed!=='0.0.0.0/0, ::/0')) tags.push('Routes changed');
    if($('#sub-include-internal-network')?.checked) tags.push(`${selected} private route${selected===1?'':'s'}`);
    if(form.querySelector('[name="endpoint"]')?.value?.trim() || form.querySelector('[name="peer_endpoint"]')?.value?.trim()) tags.push('Endpoint override');
    if(form.querySelector('[name="persistent_keepalive"]')?.value || form.querySelector('[name="mtu"]')?.value || form.querySelector('[name="dns"]')?.value?.trim()) tags.push('Client override');
    const summary=$('#adv7-summary'); if(summary) summary.textContent=tags.length?tags.join(' · '):'Using interface defaults';
    const count=$('#adv7-route-count'); if(count) count.textContent=`${selected} selected`;
  }
  $('#sub-form')?.addEventListener('input',updateAdvancedSummary);
  $('#sub-form')?.addEventListener('change',()=>setTimeout(updateAdvancedSummary,0));
  $('#new-defaults')?.addEventListener('toggle',()=>{ if($('#new-defaults')?.open) setAdvancedTab('routes'); updateAdvancedSummary(); });

  const routeObserver = $('#sub-auto-network-route-list') ? new MutationObserver(updateAdvancedSummary) : null;
  if(routeObserver) routeObserver.observe($('#sub-auto-network-route-list'),{childList:true,subtree:true,attributes:true});

  function resolvePreviewTheme(settings){
    if(previewTheme==='light'||previewTheme==='dark') return previewTheme;
    if(settings.theme_default==='light'||settings.theme_default==='dark') return settings.theme_default;
    return document.documentElement.dataset.theme==='light'?'light':'dark';
  }
  function supportMarkup(settings){
    if(!settings.show_support) return '';
    const icons={telegram:'fab fa-telegram',whatsapp:'fab fa-whatsapp',phone:'fas fa-phone',email:'fas fa-envelope',website:'fas fa-globe',instagram:'fab fa-instagram'};
    const active=Object.entries(settings.support||{}).filter(([,v])=>String(v||'').trim());
    const rows=active.map(([k])=>`<a href="#"><i class="${icons[k]}"></i><span>${k[0].toUpperCase()+k.slice(1)}</span></a>`).join('');
    const empty=rows?'':'<span class="support-empty">No support channels configured.</span>';
    return `<section class="support surface" id="support-box"><div class="section-head simple"><div><h2><i class="fas fa-headset"></i> Support</h2><p>Contact the service team.</p></div></div><div class="support-links">${rows}${empty}</div></section>`;
  }
  function previewDocument(settings){
    const theme=resolvePreviewTheme(settings);
    const label=escapeHtml(settings.portal_label||defaults.portal_label);
    const title=escapeHtml(settings.portal_title||'premium-user');
    const subtitle=escapeHtml(settings.portal_subtitle||defaults.portal_subtitle);
    const support=supportMarkup(settings);
    const cssUrl=`${location.origin}/static/css/subscription_public.css?v=20260806-experience-v7.0`;
    const faUrl=`${location.origin}/static/vendor/fa/css/all.min.css`;
    return `<!doctype html><html lang="en" data-preview="true" data-theme="${theme}" data-layout="${settings.layout}" data-background="${settings.background}" data-stat-style="${settings.display_mode}" data-motion="${settings.animation}" data-accent="${settings.accent}" data-surface="${settings.surface}" data-radius="${settings.radius}" data-density="${settings.density}" data-config-style="${settings.config_style}" data-support-style="${settings.support_style}" data-show-quick="${settings.show_quick_stats}" data-show-install="${settings.show_install}" data-show-support="${settings.show_support}" data-show-live="${settings.show_live_badge}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="${faUrl}"><link rel="stylesheet" href="${cssUrl}"></head><body class="preview-body"><div class="live-bg"><span class="bg-orb one"></span><span class="bg-orb two"></span><span class="bg-orb three"></span><span class="bg-wave one"></span><span class="bg-wave two"></span><span class="bg-grid"></span><span class="bg-orbits"></span><span class="bg-lines"></span></div><div class="page"><main class="portal-shell"><section class="portal-hero surface"><div class="portal-id"><div class="portal-icon"><i class="${escapeHtml(settings.portal_icon||defaults.portal_icon)}"></i></div><div class="portal-copy"><div class="portal-meta"><span class="portal-label">${label}</span><span class="hero-live"><i class="fas fa-circle"></i> Live</span></div><h1>${title}</h1><p>${subtitle}</p></div></div><div class="portal-actions"><button class="icon-action primary"><i class="fas fa-download"></i></button><button class="icon-action"><i class="fas fa-link"></i></button><button class="icon-action"><i class="fas fa-moon"></i></button><span class="auto-chip"><i class="fas fa-circle"></i><b>Auto</b></span></div></section><section class="quick-stats surface"><article><span>Status</span><b>Ready</b><small>2 configs</small></article><article><span>Data</span><b>8.4 GiB left</b><small>78% left</small></article><article><span>Time</span><b>12d 4h</b><small>Fixed expiry</small></article></section><div class="portal-content"><section class="usage-section"><div class="section-head simple"><div><h2><i class="fas fa-chart-pie"></i> Usage overview</h2><p>Live usage and expiry information.</p></div></div><div class="stats-grid"><article class="stat-card surface data-stat"><div class="stat-head"><span><i class="fas fa-database"></i> Data remaining</span></div><div class="stat-body"><div class="ring" style="--p:78;--c:var(--accent)"><span>78%</span></div><div class="stat-copy"><div class="big">8.4 GiB</div><div class="subline">2.4 GiB used from 10.8 GiB</div><div class="meter"><span style="width:78%"></span></div></div></div></article><article class="stat-card surface time-stat"><div class="stat-head"><span><i class="fas fa-clock"></i> Time remaining</span></div><div class="stat-body"><div class="ring" style="--p:42;--c:var(--accent2)"><span>42%</span></div><div class="stat-copy"><div class="big">12d 4h</div><div class="subline">Expires 18 Aug 2026</div><div class="meter"><span style="width:42%"></span></div></div></div></article></div></section><section class="install-card surface"><div><h2><i class="fas fa-mobile-screen-button"></i> Install WireGuard</h2><p>Open the official app, then scan QR or import a config.</p></div><div class="client-links"><a><i class="fas fa-desktop"></i></a><a><i class="fab fa-apple"></i></a><a><i class="fab fa-android"></i></a></div></section><section class="configs surface"><div class="section-head"><div><h2><i class="fas fa-location-dot"></i> Configs</h2><p>Choose a location, download the config, or scan QR.</p></div><span>2 configs</span></div><div class="loc-grid"><article class="loc"><div class="loc-top"><div class="loc-main"><div class="loc-name"><span class="loc-flag">🇳🇱</span><span class="loc-title">Amsterdam</span></div><span class="loc-country">Netherlands</span></div><span class="status online">Online</span></div><div class="loc-actions"><a class="loc-btn loc-download"><i class="fas fa-download"></i><span>Download</span></a><button class="loc-btn"><i class="fas fa-qrcode"></i></button><button class="loc-btn"><i class="fas fa-copy"></i></button></div></article><article class="loc"><div class="loc-top"><div class="loc-main"><div class="loc-name"><span class="loc-flag">🇩🇪</span><span class="loc-title">Frankfurt</span></div><span class="loc-country">Germany</span></div><span class="status online">Online</span></div><div class="loc-actions"><a class="loc-btn loc-download"><i class="fas fa-download"></i><span>Download</span></a><button class="loc-btn"><i class="fas fa-qrcode"></i></button><button class="loc-btn"><i class="fas fa-copy"></i></button></div></article></div></section>${support}</div></main></div></body></html>`;
  }
  function refreshStudio(){
    const settings=window.collectSettingsForm();
    const anim=$('#portal-animation'); if(anim) anim.value=settings.animation;
    const frame=$('#studio-preview-frame'); if(frame) frame.srcdoc=previewDocument(settings);
    $('#studio-layout-summary') && ($('#studio-layout-summary').textContent=labels.layout[settings.layout]||settings.layout);
    $('#studio-background-summary') && ($('#studio-background-summary').textContent=labels.background[settings.background]||settings.background);
    $('#studio-stats-summary') && ($('#studio-stats-summary').textContent=labels.display_mode[settings.display_mode]||settings.display_mode);
    $('#preview-layout-name') && ($('#preview-layout-name').textContent=labels.layout[settings.layout]||settings.layout);
    $('#preview-accent-name') && ($('#preview-accent-name').textContent=labels.accent[settings.accent]||settings.accent);
    $('#preview-stats-name') && ($('#preview-stats-name').textContent=labels.display_mode[settings.display_mode]||settings.display_mode);
    $('#preview-motion-name') && ($('#preview-motion-name').textContent=labels.animation[settings.animation]||settings.animation);
    const supportCount=Object.values(settings.support||{}).filter(v=>String(v||'').trim()).length;
    $('#studio-support-summary') && ($('#studio-support-summary').textContent=`${supportCount} active`);
  }
  function schedulePreview(){ clearTimeout(previewTimer); previewTimer=setTimeout(refreshStudio,70); }
  $('#sub-settings-modal')?.addEventListener('input',schedulePreview);
  $('#sub-settings-modal')?.addEventListener('change',schedulePreview);

  $$('[data-preview-theme]').forEach(btn=>btn.addEventListener('click',()=>{ previewTheme=btn.dataset.previewTheme; $$('[data-preview-theme]').forEach(b=>b.classList.toggle('active',b===btn)); refreshStudio(); }));
  $$('[data-preview-device]').forEach(btn=>btn.addEventListener('click',()=>{ previewDevice=btn.dataset.previewDevice==='mobile'?'mobile':'desktop'; $('.studio7-frame-stage')?.setAttribute('data-preview-device',previewDevice); $$('[data-preview-device]').forEach(b=>b.classList.toggle('active',b===btn)); }));

  function syncSelectedClasses(){
    $$('#sub-settings-modal label').forEach(label=>{ const input=$('input[type="radio"],input[type="checkbox"]',label); if(input) label.classList.toggle('is-selected',input.checked); });
  }
  $('#sub-settings-modal')?.addEventListener('change',syncSelectedClasses);

  const themeObserver=new MutationObserver(()=>{ if(previewTheme==='auto') refreshStudio(); });
  themeObserver.observe(document.documentElement,{attributes:true,attributeFilter:['data-theme']});

  $('#sub-auto-network-route-list')?.addEventListener('change',updateAdvancedSummary);
  $('#sub-networks-select-all')?.addEventListener('click',()=>setTimeout(updateAdvancedSummary,0));
  $('#sub-networks-clear')?.addEventListener('click',()=>setTimeout(updateAdvancedSummary,0));

  document.addEventListener('DOMContentLoaded',()=>{ syncSelectedClasses(); updateAdvancedSummary(); refreshStudio(); });
  syncSelectedClasses(); updateAdvancedSummary(); refreshStudio();
})();

(() => {
  'use strict';
  const $ = (s, root=document) => root.querySelector(s);
  const $$ = (s, root=document) => [...root.querySelectorAll(s)];
  const defaults = {
    layout:'aurora', background:'aurora', display_mode:'hybrid', animation:'balanced',
    accent:'mint', surface:'glass', radius:'rounded', shadow:'soft', density:'comfortable',
    page_width:'standard', config_style:'cards', config_columns:'auto', section_order:'standard',
    hero_style:'panel', support_style:'buttons', button_style:'solid', font_scale:'standard',
    theme_default:'auto', stat_size:'standard', title_align:'left', logo_size:'medium',
    show_quick_stats:true, show_percentage:true, show_used_detail:true, show_install:true, show_support:true,
    show_live_badge:true, show_status_badge:true, show_location_country:true, show_download_action:true,
    show_copy_action:true, show_theme_action:true, show_section_descriptions:true,
    portal_label:'Secure WireGuard portal', portal_title:'',
    portal_subtitle:'Your account is ready. Install WireGuard, then scan QR or import a config.',
    portal_icon:'fas fa-bolt',
    custom_primary:'#3addaa', custom_secondary:'#63a5ff', background_intensity:70, card_opacity:82, motion_speed:100, particle_density:60,
    usage_title:'Usage overview', configs_title:'Configs', install_title:'Install WireGuard', support_title:'Support', support:{}
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
  function numberValue(id,fallback){ const n=Number($('#'+id)?.value); return Number.isFinite(n)?n:fallback; }
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
    choose('sub-shadow', s.shadow);
    choose('sub-density', s.density);
    choose('sub-page-width', s.page_width);
    choose('sub-config-style', s.config_style);
    choose('sub-config-columns', s.config_columns);
    choose('sub-section-order', s.section_order);
    choose('sub-hero-style', s.hero_style);
    choose('sub-support-style', s.support_style);
    choose('sub-button-style', s.button_style);
    choose('sub-font-scale', s.font_scale);
    choose('sub-theme-default', s.theme_default);
    choose('sub-stat-size', s.stat_size);
    choose('sub-title-align', s.title_align);
    choose('sub-logo-size', s.logo_size);
    const anim=$('#portal-animation'); if(anim) anim.value=s.animation||defaults.animation;
    setCheck('show-quick-stats', s.show_quick_stats !== false);
    setCheck('show-percentage', s.show_percentage !== false);
    setCheck('show-used-detail', s.show_used_detail !== false);
    setCheck('show-install', s.show_install !== false);
    setCheck('show-support', s.show_support !== false);
    setCheck('show-live-badge', s.show_live_badge !== false);
    setCheck('show-status-badge', s.show_status_badge !== false);
    setCheck('show-location-country', s.show_location_country !== false);
    setCheck('show-download-action', s.show_download_action !== false);
    setCheck('show-copy-action', s.show_copy_action !== false);
    setCheck('show-theme-action', s.show_theme_action !== false);
    setCheck('show-section-descriptions', s.show_section_descriptions !== false);
    setValue('portal-label', s.portal_label);
    setValue('portal-title', s.portal_title);
    setValue('portal-subtitle', s.portal_subtitle);
    setValue('portal-icon', s.portal_icon);
    setValue('portal-primary-color', s.custom_primary); setValue('portal-primary-text', s.custom_primary);
    setValue('portal-secondary-color', s.custom_secondary); setValue('portal-secondary-text', s.custom_secondary);
    setValue('portal-background-intensity', s.background_intensity); setValue('portal-card-opacity', s.card_opacity);
    setValue('portal-motion-speed', s.motion_speed); setValue('portal-particle-density', s.particle_density);
    setValue('portal-usage-title', s.usage_title); setValue('portal-configs-title', s.configs_title);
    setValue('portal-install-title', s.install_title); setValue('portal-support-title', s.support_title);
    const support=s.support||{}; ['telegram','whatsapp','phone','email','website','instagram'].forEach(k=>setValue('sup-'+k,support[k]||''));
    setStudioTab('layout');
    refreshStudio();
  };

  window.collectSettingsForm = function(){
    return {
      layout:checked('sub-layout',defaults.layout), background:checked('sub-background',defaults.background),
      display_mode:checked('sub-display-mode',defaults.display_mode), animation:checked('portal-animation-choice',defaults.animation),
      accent:checked('sub-accent',defaults.accent), surface:checked('sub-surface',defaults.surface),
      radius:checked('sub-radius',defaults.radius), shadow:checked('sub-shadow',defaults.shadow), density:checked('sub-density',defaults.density),
      page_width:checked('sub-page-width',defaults.page_width), config_style:checked('sub-config-style',defaults.config_style),
      config_columns:checked('sub-config-columns',defaults.config_columns), section_order:checked('sub-section-order',defaults.section_order),
      hero_style:checked('sub-hero-style',defaults.hero_style), support_style:checked('sub-support-style',defaults.support_style),
      button_style:checked('sub-button-style',defaults.button_style), font_scale:checked('sub-font-scale',defaults.font_scale),
      theme_default:checked('sub-theme-default',defaults.theme_default), stat_size:checked('sub-stat-size',defaults.stat_size),
      title_align:checked('sub-title-align',defaults.title_align), logo_size:checked('sub-logo-size',defaults.logo_size),
      show_quick_stats:!!$('#show-quick-stats')?.checked, show_percentage:$('#show-percentage')?.checked !== false,
      show_used_detail:$('#show-used-detail')?.checked !== false, show_install:!!$('#show-install')?.checked,
      show_support:!!$('#show-support')?.checked, show_live_badge:!!$('#show-live-badge')?.checked,
      show_status_badge:$('#show-status-badge')?.checked !== false, show_location_country:$('#show-location-country')?.checked !== false,
      show_download_action:$('#show-download-action')?.checked !== false, show_copy_action:$('#show-copy-action')?.checked !== false,
      show_theme_action:$('#show-theme-action')?.checked !== false, show_section_descriptions:$('#show-section-descriptions')?.checked !== false,
      portal_label:$('#portal-label')?.value||'', portal_title:$('#portal-title')?.value||'',
      portal_subtitle:$('#portal-subtitle')?.value||'', portal_icon:$('#portal-icon')?.value||defaults.portal_icon,
      custom_primary:$('#portal-primary-color')?.value||$('#portal-primary-text')?.value||defaults.custom_primary,
      custom_secondary:$('#portal-secondary-color')?.value||$('#portal-secondary-text')?.value||defaults.custom_secondary,
      background_intensity:numberValue('portal-background-intensity',defaults.background_intensity),
      card_opacity:numberValue('portal-card-opacity',defaults.card_opacity), motion_speed:numberValue('portal-motion-speed',defaults.motion_speed),
      particle_density:numberValue('portal-particle-density',defaults.particle_density),
      usage_title:$('#portal-usage-title')?.value||defaults.usage_title, configs_title:$('#portal-configs-title')?.value||defaults.configs_title,
      install_title:$('#portal-install-title')?.value||defaults.install_title, support_title:$('#portal-support-title')?.value||defaults.support_title,
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
    return `<section class="support surface" id="support-box"><div class="section-head simple"><div><h2><i class="fas fa-headset"></i> ${escapeHtml(settings.support_title||'Support')}</h2><p>Contact the service team.</p></div></div><div class="support-links">${rows}${empty}</div></section>`;
  }
  function previewDocument(settings){
    const theme=resolvePreviewTheme(settings);
    const label=escapeHtml(settings.portal_label||defaults.portal_label);
    const title=escapeHtml(settings.portal_title||'premium-user');
    const subtitle=escapeHtml(settings.portal_subtitle||defaults.portal_subtitle);
    const support=supportMarkup(settings);
    const cssUrl=`${location.origin}/static/css/subscription_public.css?v=20260819-layout-v12`;
    const faUrl=`${location.origin}/static/vendor/fa/css/all.min.css`;
    return `<!doctype html><html lang="en" data-preview="true" data-preview-device="${previewDevice}" data-theme="${theme}" data-layout="${settings.layout}" data-background="${settings.background}" data-stat-style="${settings.display_mode}" data-motion="${settings.animation}" data-accent="${settings.accent}" data-surface="${settings.surface}" data-radius="${settings.radius}" data-shadow="${settings.shadow}" data-density="${settings.density}" data-page-width="${settings.page_width}" data-config-style="${settings.config_style}" data-config-columns="${settings.config_columns}" data-section-order="${settings.section_order}" data-hero-style="${settings.hero_style}" data-support-style="${settings.support_style}" data-button-style="${settings.button_style}" data-font-scale="${settings.font_scale}" data-stat-size="${settings.stat_size}" data-title-align="${settings.title_align}" data-logo-size="${settings.logo_size}" data-show-quick="${settings.show_quick_stats}" data-show-percentage="${settings.show_percentage}" data-show-used-detail="${settings.show_used_detail}" data-show-install="${settings.show_install}" data-show-support="${settings.show_support}" data-show-live="${settings.show_live_badge}" data-show-status="${settings.show_status_badge}" data-show-country="${settings.show_location_country}" data-show-download="${settings.show_download_action}" data-show-copy="${settings.show_copy_action}" data-show-theme-action="${settings.show_theme_action}" data-show-descriptions="${settings.show_section_descriptions}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="${faUrl}"><link rel="stylesheet" href="${cssUrl}"><style>:root{--custom-accent:${escapeHtml(settings.custom_primary||'#3addaa')};--custom-accent2:${escapeHtml(settings.custom_secondary||'#63a5ff')};--background-intensity:${Math.max(0,Math.min(1,Number(settings.background_intensity||70)/100))};--card-opacity:${Math.max(.5,Math.min(1,Number(settings.card_opacity||82)/100))};--motion-speed:${Math.max(.5,Math.min(1.5,100/Number(settings.motion_speed||100)))};--particle-density:${Math.max(0,Math.min(1,Number(settings.particle_density||60)/100))};--engine-speed:${Math.max(.5,Math.min(1.8,Number(settings.motion_speed||100)/100))};--engine-density:${Math.max(0,Math.min(1,Number(settings.particle_density||60)/100))}}</style></head><body class="preview-body"><div class="live-bg"><span class="bg-orb one"></span><span class="bg-orb two"></span><span class="bg-orb three"></span><span class="bg-wave one"></span><span class="bg-wave two"></span><span class="bg-grid"></span><span class="bg-orbits"></span><span class="bg-lines"></span></div><div class="page"><main class="portal-shell"><section class="portal-hero surface"><div class="portal-id"><div class="portal-icon"><i class="${escapeHtml(settings.portal_icon||defaults.portal_icon)}"></i></div><div class="portal-copy"><div class="portal-meta"><span class="portal-label">${label}</span><span class="hero-live"><i class="fas fa-circle"></i> Live</span></div><h1>${title}</h1><p>${subtitle}</p></div></div><div class="portal-actions"><button class="icon-action primary"><i class="fas fa-download"></i></button><button class="icon-action"><i class="fas fa-link"></i></button><button class="icon-action"><i class="fas fa-moon"></i></button><span class="auto-chip"><i class="fas fa-circle"></i><b>Auto</b></span></div></section><section class="quick-stats surface"><article><span>Status</span><b>Ready</b><small>2 configs</small></article><article><span>Data</span><b>8.4 GiB left</b><small>78% left</small></article><article><span>Time</span><b>12d 4h</b><small>Fixed expiry</small></article></section><div class="portal-content"><section class="usage-section"><div class="section-head simple"><div><h2><i class="fas fa-chart-pie"></i> ${escapeHtml(settings.usage_title||'Usage overview')}</h2><p>Live usage and expiry information.</p></div></div><div class="stats-grid"><article class="stat-card surface data-stat"><div class="stat-head"><span><i class="fas fa-database"></i> Data remaining</span></div><div class="stat-body"><div class="ring" style="--p:78;--c:var(--accent)"><span>78%</span></div><div class="stat-copy"><div class="big">8.4 GiB</div><div class="subline">2.4 GiB used from 10.8 GiB</div><div class="meter"><span style="width:78%"></span></div></div></div></article><article class="stat-card surface time-stat"><div class="stat-head"><span><i class="fas fa-clock"></i> Time remaining</span></div><div class="stat-body"><div class="ring" style="--p:42;--c:var(--accent2)"><span>42%</span></div><div class="stat-copy"><div class="big">12d 4h</div><div class="subline">Expires 18 Aug 2026</div><div class="meter"><span style="width:42%"></span></div></div></div></article></div></section><section class="install-card surface"><div><h2><i class="fas fa-mobile-screen-button"></i> ${escapeHtml(settings.install_title||'Install WireGuard')}</h2><p>Open the official app, then scan QR or import a config.</p></div><div class="client-links"><a><i class="fas fa-desktop"></i></a><a><i class="fab fa-apple"></i></a><a><i class="fab fa-android"></i></a><a><i class="fas fa-arrow-up-right-from-square"></i></a></div></section><section class="configs surface"><div class="section-head"><div><h2><i class="fas fa-location-dot"></i> ${escapeHtml(settings.configs_title||'Configs')}</h2><p>Choose a location, download the config, or scan QR.</p></div><span>2 configs</span></div><div class="loc-grid"><article class="loc"><div class="loc-top"><div class="loc-main"><div class="loc-name"><span class="loc-flag">🇳🇱</span><span class="loc-title">Amsterdam</span></div><span class="loc-country">Netherlands</span></div><span class="status online">Online</span></div><div class="loc-actions"><a class="loc-btn loc-download" title="Download config" aria-label="Download config"><i class="fas fa-download"></i></a><button class="loc-btn"><i class="fas fa-qrcode"></i></button><button class="loc-btn"><i class="fas fa-copy"></i></button></div></article><article class="loc"><div class="loc-top"><div class="loc-main"><div class="loc-name"><span class="loc-flag">🇩🇪</span><span class="loc-title">Frankfurt</span></div><span class="loc-country">Germany</span></div><span class="status online">Online</span></div><div class="loc-actions"><a class="loc-btn loc-download" title="Download config" aria-label="Download config"><i class="fas fa-download"></i></a><button class="loc-btn"><i class="fas fa-qrcode"></i></button><button class="loc-btn"><i class="fas fa-copy"></i></button></div></article></div></section>${support}</div></main></div></body></html>`;
  }
  function syncPreviewViewport(){
    const stage=$('.studio7-frame-stage');
    const frame=$('#studio-preview-frame');
    if(!stage||!frame) return;
    const logicalWidth=previewDevice==='mobile'?390:1280;
    const logicalHeight=previewDevice==='mobile'?780:820;
    const available=Math.max(240,stage.clientWidth-16);
    const scale=Math.min(1,available/logicalWidth);
    frame.style.width=logicalWidth+'px';
    frame.style.maxWidth='none';
    frame.style.height=logicalHeight+'px';
    frame.style.minHeight='0';
    frame.style.transformOrigin='top left';
    frame.style.transform=`scale(${scale})`;
    frame.style.position='absolute';
    frame.style.left='50%';
    frame.style.top='8px';
    frame.style.marginLeft=(-(logicalWidth*scale)/2)+'px';
    stage.style.minHeight=Math.max(360,Math.ceil(logicalHeight*scale)+16)+'px';
    stage.dataset.logicalWidth=String(logicalWidth);
  }

  function refreshStudio(){
    const settings=window.collectSettingsForm();
    const anim=$('#portal-animation'); if(anim) anim.value=settings.animation;
    const frame=$('#studio-preview-frame'); if(frame){ frame.srcdoc=previewDocument(settings); requestAnimationFrame(syncPreviewViewport); }
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
  $$('[data-preview-device]').forEach(btn=>btn.addEventListener('click',()=>{ previewDevice=btn.dataset.previewDevice==='mobile'?'mobile':'desktop'; $('.studio7-frame-stage')?.setAttribute('data-preview-device',previewDevice); $$('[data-preview-device]').forEach(b=>b.classList.toggle('active',b===btn)); refreshStudio(); }));
  addEventListener('resize',()=>requestAnimationFrame(syncPreviewViewport),{passive:true});
  if(window.ResizeObserver){ const ro=new ResizeObserver(()=>syncPreviewViewport()); const stage=$('.studio7-frame-stage'); if(stage) ro.observe(stage); }

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

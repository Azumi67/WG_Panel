(() => {
 'use strict';
 const defaults={brand:'Secure WireGuard profile',accent:'indigo',theme:'auto',show_apps:true,show_support:true,show_guide:true,animated:true,font_family:"rounded",text_size:"standard",density:"comfortable",corners:"rounded",page_width:"wide",button_style:"solid",background_pattern:"none",show_endpoint:true,show_address:true,show_qr:true,primary_color:"#7661ed",secondary_color:"#5895ee",custom_colors:false,surface:"soft",shadow:"subtle",hero_align:"left",icon:"shield",usage_style:"cards",show_status:true,show_usage:true,show_download:true,show_copy:true,show_activation:true,show_theme_toggle:true,welcome_text:"",notice_text:"",notice_tone:"info",section_order:"usage_first"};
 const palettes={indigo:['#4f46e5','#818cf8'],teal:['#0f766e','#2dd4bf'],rose:['#be185d','#f472b6'],amber:['#92400e','#fbbf24']};
 let settings={...defaults,...window.PEER_APPEARANCE};
 const style=document.createElement('style');document.head.append(style);
 function colors(){const dark=document.documentElement.dataset.theme==='dark';const color=settings.custom_colors&&/^#[0-9a-f]{6}$/i.test(settings.primary_color)?settings.primary_color:(palettes[settings.accent]||palettes.indigo)[dark?1:0];document.documentElement.style.setProperty('--accent',color);document.documentElement.style.setProperty('--accent-2',settings.custom_colors&&/^#[0-9a-f]{6}$/i.test(settings.secondary_color)?settings.secondary_color:color);document.documentElement.style.setProperty('--accent-glow',color+'33');}
 function apply(preview=false){
  document.querySelectorAll('.brand-lockup .eyebrow, .compact-brand span, .minimal-brand span, .pro-brand small').forEach(brand=>brand.textContent=settings.brand||defaults.brand);
  style.textContent=[!settings.show_apps?'.apps-card{display:none!important}.utility-grid{grid-template-columns:minmax(0,1fr)!important}':'',!settings.show_support?'.support-card{display:none!important}':'',!settings.show_guide?'.connection-guide{display:none!important}.config-layout{grid-template-columns:1fr!important}':'',!settings.animated?'.live-background,.ambient{display:none!important}':''].join('\n');
  let saved;try{saved=localStorage.getItem('wg-user-theme');}catch(_){}
  if(settings.theme!=='auto'&&(preview||!saved))document.documentElement.dataset.theme=settings.theme;
  for(const key of ['font_family','text_size','density','corners','page_width','button_style','background_pattern','surface','shadow','hero_align','usage_style','section_order'])document.documentElement.setAttribute('data-peer-'+key.replaceAll('_','-'),settings[key]||defaults[key]);
  document.documentElement.setAttribute('data-peer-show-qr',String(settings.show_qr));
  for(const key of ['endpoint','address']){const el=document.getElementById('peer-'+key);const box=el?.closest('article')||el?.parentElement;if(box)box.hidden=!settings['show_'+key];}
  for(const key of ['custom_colors','show_status','show_usage','show_download','show_copy','show_activation','show_theme_toggle'])document.documentElement.setAttribute('data-peer-'+key.replaceAll('_','-'),String(settings[key]));
  const icons={shield:'shield-halved',bolt:'bolt',globe:'globe',network:'diagram-project',lock:'lock'};
  document.querySelectorAll('.brand-mark i,.brand-icon i,.compact-brand>i,.minimal-brand>i').forEach(el=>el.className='fas fa-'+(icons[settings.icon]||'shield-halved'));
  const main=document.querySelector('main');
  if(main){for(const key of ['welcome_text','notice_text']){let el=document.getElementById('peer-'+key);if(!el){el=document.createElement('div');el.id='peer-'+key;el.className='peer-custom-message';main.insertBefore(el,main.children[1]||null);}el.textContent=String(settings[key]||'');el.hidden=!settings[key];el.dataset.tone=key==='notice_text'?settings.notice_tone:'info';}}
  colors();
 }
 new MutationObserver(colors).observe(document.documentElement,{attributes:true,attributeFilter:['data-theme']});
 document.addEventListener('DOMContentLoaded',()=>{
  apply();
  if(window.PREVIEW&&window.parent!==window){
   window.addEventListener('message',event=>{
    if(event.source!==window.parent||event.data?.type!=='peer-template-preview')return;
    const incoming=event.data.appearance;if(!incoming||typeof incoming!=='object')return;
    settings={...defaults,...incoming};apply(true);
    window.SOCIALS=event.data.socials||{};window.dispatchEvent(new Event('peer-support-updated'));
   });
   window.parent.postMessage({type:'peer-template-ready'},'*');
  }
 });
})();

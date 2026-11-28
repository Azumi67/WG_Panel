(() => {'use strict';
 const zone=()=>window.WG_PANEL_TIMEZONE||window.RESELLER_TIMEZONE||'UTC';
 let cachedZone, formats;
 function dateFormats() {
   const timeZone = zone();
   if (timeZone !== cachedZone) {
     formats = {
       key: new Intl.DateTimeFormat('en-CA',{timeZone,year:'numeric',month:'2-digit',day:'2-digit'}),
       day: new Intl.DateTimeFormat(undefined,{timeZone,day:'numeric',month:'short',year:'numeric'}),
       time: new Intl.DateTimeFormat(undefined,{timeZone,hour:'2-digit',minute:'2-digit',hour12:false}),
       full: new Intl.DateTimeFormat(undefined,{timeZone,dateStyle:'full',timeStyle:'short'})
     };
     cachedZone = timeZone;
   }
   return formats;
 }
 window.rpHumanDate = value => {
   if (!value) return '—';
   const d = new Date(/(?:Z|[+-]\d\d:\d\d)$/.test(value) ? value : value+'Z');
   if (!Number.isFinite(d.getTime())) return '—';
   try {
     const f = dateFormats(), key = f.key.format(d), now = new Date();
     let label;
     for (const [offset,name] of [[0,'Today'],[-1,'Yesterday'],[1,'Tomorrow']]) {
       const check = new Date(now);
       check.setUTCDate(check.getUTCDate()+offset);
       if (f.key.format(check) === key) { label = name; break; }
     }
     return (label || f.day.format(d))+', '+f.time.format(d);
   } catch { return d.toISOString(); }
 };
 window.rpRefreshDates = () => document.querySelectorAll('time[data-rp-time]').forEach(n => {
   const label = window.rpHumanDate(n.dateTime);
   if (n.textContent !== label) n.textContent = label;
   try { n.title = dateFormats().full.format(new Date(n.dateTime))+' · '+zone(); } catch {}
 });
 window.addEventListener('wgpanel:timezone-change',window.rpRefreshDates);
 document.addEventListener('DOMContentLoaded',()=>{window.rpRefreshDates();document.querySelectorAll('[data-rp-tabs]').forEach((root,k)=>{const buttons=[...root.querySelectorAll('[data-rp-tab]')],panels=[...root.querySelectorAll('[data-rp-panel]')];root.querySelector('nav').setAttribute('role','tablist');const show=key=>{buttons.forEach(b=>{b.setAttribute('aria-selected',String(b.dataset.rpTab===key));b.tabIndex=b.dataset.rpTab===key?0:-1;});panels.forEach(p=>p.hidden=p.dataset.rpPanel!==key);};buttons.forEach((b,i)=>{b.id='rp-tab-'+k+'-'+i;b.setAttribute('role','tab');const p=panels.find(p=>p.dataset.rpPanel===b.dataset.rpTab);p.id='rp-panel-'+k+'-'+i;p.setAttribute('role','tabpanel');p.setAttribute('aria-labelledby',b.id);b.setAttribute('aria-controls',p.id);b.onclick=()=>show(b.dataset.rpTab);b.onkeydown=e=>{if(!['ArrowLeft','ArrowRight','Home','End'].includes(e.key))return;e.preventDefault();const n=e.key==='Home'?0:e.key==='End'?buttons.length-1:(i+(e.key==='ArrowRight'?1:-1)+buttons.length)%buttons.length;buttons[n].click();buttons[n].focus();};});const initial=new URL(location).searchParams.get('view');show(buttons.some(b=>b.dataset.rpTab===initial)?initial:buttons[0].dataset.rpTab);});});
 document.addEventListener('change',e=>{if(!e.target.matches('[data-rp-page-size]'))return;const u=new URL(location);u.searchParams.set('per_page',e.target.value);u.searchParams.set('page','1');const active=e.target.closest('[data-rp-panel]');if(active)u.searchParams.set('view',active.dataset.rpPanel);location.assign(u);});
 document.addEventListener('click',async e=>{const b=e.target.closest('[data-rp-page-url]');if(!b)return;const root=b.closest('.rp-resource-page');b.disabled=true;try{const res=await fetch(b.dataset.rpPageUrl,{credentials:'same-origin'});if(!res.ok)throw Error();const doc=new DOMParser().parseFromString(await res.text(),'text/html'),fresh=doc.querySelector('.rp-resource-page');if(!fresh)throw Error();root.replaceWith(fresh);window.rpRefreshDates();}catch(_){b.disabled=false;let n=root.querySelector('[role=status]');if(!n){n=document.createElement('p');n.setAttribute('role','status');root.append(n);}n.textContent='Could not load this page. Try again.';}});
})();

document.addEventListener('DOMContentLoaded',()=>{const d=document.getElementById('create-account');if(!d)return;const fields=d.querySelector('[data-create-options]'),plan=d.querySelector('[name=plan_id]');if(!fields||!plan)return;d.querySelector('[data-plan-defaults]').onclick=()=>{let spec;try{spec=JSON.parse(plan.selectedOptions[0].dataset.planSpec);}catch(_){return;}fields.querySelectorAll('[name=permissions]').forEach(n=>n.checked=(spec.permissions||[]).includes(n.value));fields.querySelector('[name=panel_access]').checked=!!spec.panel_access;for(const [key,value] of Object.entries({read_per_minute:240,write_per_minute:60,create_per_minute:10,bulk_limit:50,profile_limit:50})){const n=fields.querySelector('[name="'+key+'"]');if(n)n.value=spec.operation_limits?.[key]??value;}const np=spec.network_policy||{},tg=spec.telegram_access||{},endpoint=np.endpoint||'',split=endpoint.lastIndexOf(':');fields.querySelector('[name=server_host]').value=split>=0?endpoint.slice(0,split):'';fields.querySelector('[name=server_port]').value=split>=0?endpoint.slice(split+1):'';fields.querySelector('[name=internal_routes]').value=(np.internal_routes||[]).join(', ');for(const key of ['allow_endpoint','allow_fixed','allow_internal'])fields.querySelector('[name="'+key+'"]').checked=!!np[key];fields.querySelector('[name=approved]').checked=!!tg.approved;fields.querySelectorAll('[name=telegram_features]').forEach(n=>n.checked=(tg.features||[]).includes(n.value));};plan.addEventListener('change',()=>d.querySelector('[data-plan-defaults]').click());if(d.dataset.seedPlan==='true')d.querySelector('[data-plan-defaults]').click();});

document.addEventListener('DOMContentLoaded',()=>document.querySelectorAll('[data-message-editor]').forEach(root=>{const update=()=>root.querySelectorAll('[data-preview-for]').forEach(out=>{const field=root.querySelector('[name="'+out.dataset.previewFor+'"]');out.textContent=field.value.trim()||out.dataset.fallback;root.querySelector('[data-count-for="'+field.name+'"]').textContent=field.value.length+' / '+field.maxLength;});root.addEventListener('input',update);root.querySelectorAll('[data-message-reset]').forEach(b=>b.onclick=()=>{root.querySelector('[name="'+b.dataset.messageReset+'"]').value='';update();});update();}));
document.addEventListener('submit',async e=>{const form=e.target.closest('[data-inventory-search]');if(!form)return;e.preventDefault();const root=form.closest('.rp-resource-page'),button=form.querySelector('button');button.disabled=true;try{const u=new URL(form.action);new FormData(form).forEach((v,k)=>u.searchParams.set(k,v));const res=await fetch(u,{credentials:'same-origin'});if(!res.ok)throw Error();const fresh=new DOMParser().parseFromString(await res.text(),'text/html').querySelector('.rp-resource-page');if(!fresh)throw Error();root.replaceWith(fresh);window.rpRefreshDates();}catch(_){button.disabled=false;form.querySelector('[role=status]').textContent='Could not load customers. Try again.';}});

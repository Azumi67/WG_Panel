(() => {
 'use strict';const desk=document.querySelector('.rp-desk');if(!desk)return;
 desk.querySelectorAll('input[type=checkbox]').forEach(n=>n.setAttribute('role','switch'));
 const wireBackdrop=d=>d.addEventListener('click',e=>{
   if(e.target!==d||d.dataset.saving==='true')return;
   const box=d.getBoundingClientRect();
   if(e.clientX<box.left||e.clientX>box.right||e.clientY<box.top||e.clientY>box.bottom)d.close();
 });
 desk.addEventListener('click',async e=>{
   const open=e.target.closest('[data-dialog]'),close=e.target.closest('[data-dialog-close]');
   if(close){const dialog=close.closest('dialog');if(dialog?.dataset.saving!=='true')dialog?.close();return;}
   if(!open||open.disabled)return;
   let dialog=document.getElementById(open.dataset.dialog);
   const match=/^(account|plan)-(\d+)$/.exec(open.dataset.dialog||'');
   if(!dialog&&match){

     open.disabled=true;open.setAttribute('aria-busy','true');
     const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),20000);
     const loading=document.createElement('dialog');loading.className='rp-dialog rp-loading-dialog';
     loading.setAttribute('aria-label','Loading account settings');
     loading.innerHTML='<div class="rp-operation-loading" role="status"><span class="rp-operation-spinner" aria-hidden="true"></span><div><strong>Loading settings…</strong><p>Preparing the account editor.</p></div></div>';
     desk.append(loading);loading.showModal();loading.addEventListener('cancel',()=>controller.abort());
     try{
       const resource = match[1] === 'plan' ? 'plans' : 'accounts';
       const response=await fetch('/resellers/'+resource+'/'+encodeURIComponent(match[2])+'/dialog',{
         credentials:'same-origin',cache:'no-store',headers:{'Accept':'text/html'},signal:controller.signal
       });
       if(!response.ok)throw new Error('HTTP '+response.status);
       const page=new DOMParser().parseFromString(await response.text(),'text/html');
       const fresh=page.getElementById(open.dataset.dialog);
       if(!fresh||fresh.tagName!=='DIALOG')throw new Error('Account editor is unavailable');
       desk.append(fresh);dialog=fresh;
       if (match[1] === 'account') window.rpHydrateAccountDialog?.(dialog);
       dialog.addEventListener('cancel',ev=>{if(dialog.dataset.saving==='true')ev.preventDefault();});
       wireBackdrop(dialog);
     }catch(err){
       window.toastSafe?.('Could not open reseller account: '+(err.message||'Request failed'),'error');
       return;
     }finally{clearTimeout(timer);loading.close();loading.remove();open.disabled=false;open.removeAttribute('aria-busy');}
   }
   if(dialog&&!dialog.open){if(dialog.id.startsWith('account-'))window.rpHydrateAccountDialog?.(dialog);dialog.showModal();if(dialog.classList.contains('rp-plan-dialog')) window.rpPlanDialogOpened?.(dialog);}
 });
 desk.querySelector('[data-auto-open]')?.showModal();
 desk.addEventListener('click',async e=>{const b=e.target.closest('[data-copy-value]');if(!b)return;const input=document.getElementById(b.dataset.copyValue);try{await navigator.clipboard.writeText(input.value);b.textContent='Copied';}catch(_){input.focus();input.select();b.textContent='Select and copy';}});
 desk.querySelectorAll('dialog').forEach(wireBackdrop);
 const search=desk.querySelector('[data-desk-search]'),status=desk.querySelector('[data-desk-status]');const filter=()=>desk.querySelectorAll('[data-desk-row]').forEach(row=>{row.hidden=Boolean((search?.value&&!row.textContent.toLowerCase().includes(search.value.trim().toLowerCase()))||(status?.value&&row.dataset.state!==status.value));});search?.addEventListener('input',filter);status?.addEventListener('change',filter);
})();



(() => {
 const sections=new WeakMap();
 function hydrate(dialog, selected=0){
  const body=dialog.querySelector('.rp-dialog-body');if(!body||body.querySelector('.rp-manage-nav'))return;
  dialog.classList.add('rp-manage-dialog');const access=document.createElement('section');
  while(body.firstElementChild&&body.firstElementChild.tagName!=='DETAILS')access.append(body.firstElementChild);
  const panels=[access,...body.querySelectorAll(':scope > details')];const nav=document.createElement('nav');nav.className='rp-manage-nav';nav.setAttribute('role','tablist');nav.setAttribute('aria-label','Manage reseller');const content=document.createElement('div');content.className='rp-manage-content';
  body.tabIndex=0;body.setAttribute('role','region');body.setAttribute('aria-label','Account settings');content.append(...panels);body.replaceChildren(nav,content);
  const buttons=panels.map((panel,i)=>{panel.classList.add('rp-manage-panel');if(panel.tagName==='DETAILS')panel.open=true;panel.id=dialog.id+'-panel-'+i;panel.setAttribute('role','tabpanel');const b=document.createElement('button');b.type='button';b.className='rp-btn';if(panel.classList.contains('rp-account-removal'))b.classList.add('rp-removal-tab');b.textContent=i===0?'Access & status':panel.querySelector('summary').textContent;b.id=dialog.id+'-tab-'+i;b.setAttribute('role','tab');b.setAttribute('aria-controls',panel.id);panel.setAttribute('aria-labelledby',b.id);nav.append(b);return b;});
  const picker=document.createElement('label');picker.className='rp-manage-picker';picker.textContent='Account section';const select=document.createElement('select');select.className='rp-input';select.setAttribute('aria-label','Account section');buttons.forEach((b,i)=>select.add(new Option(b.textContent,String(i))));picker.append(select);body.insertBefore(picker,nav);
  const show=index=>{if(!Number.isInteger(index)||!panels[index])return;dialog.dataset.selectedPanel=String(index);select.value=String(index);body.scrollTop=0;content.scrollTop=0;panels.forEach((p,i)=>p.hidden=i!==index);buttons.forEach((b,i)=>{b.setAttribute('aria-selected',String(i===index));b.tabIndex=i===index?0:-1;});};
  select.addEventListener('change',()=>show(Number(select.value)));buttons.forEach((b,i)=>{b.onclick=()=>show(i);b.onkeydown=e=>{if(!['ArrowRight','ArrowLeft','Home','End'].includes(e.key))return;e.preventDefault();const j=e.key==='Home'?0:e.key==='End'?buttons.length-1:(i+(e.key==='ArrowRight'?1:-1)+buttons.length)%buttons.length;show(j);buttons[j].focus();};});sections.set(dialog,section=>{const i=panels.findIndex(p=>p.dataset.manageSection===section||(section==='customers'&&p.classList.contains('rp-customer-inventory')));if(i<0)return false;show(i);(picker.offsetWidth?select:buttons[i]).focus();return true;});access.querySelector('[data-open-removal]')?.addEventListener('click',()=>{const i=panels.findIndex(p=>p.classList.contains('rp-account-removal'));if(i>=0){show(i);(picker.offsetWidth?select:buttons[i]).focus();}});show(Math.min(selected,panels.length-1));
 }
 window.rpHydrateAccountDialog=hydrate;
 document.addEventListener('click',e=>{
  const button=e.target.closest('[data-open-customers]');if(!button)return;
  const dialog=button.closest('dialog');if(!dialog)return;
  e.preventDefault();
  hydrate(dialog);
  if(sections.get(dialog)?.('customers'))return;
  const panel=dialog.querySelector('[data-manage-section=customers],.rp-customer-inventory');
  if(!panel){status(dialog,'Customer inventory is unavailable. Close the account and reload the page.',true);return;}
  const tab=Array.from(dialog.querySelectorAll('[role=tab]')).find(b=>b.getAttribute('aria-controls')===panel.id);
  if(tab){tab.click();return;}
  panel.hidden=false;panel.open=true;panel.scrollIntoView({block:'nearest'});
 });
 function status(dialog,message,error=false){let n=dialog.querySelector('.rp-save-status');if(!n){n=document.createElement('p');n.className='rp-save-status';n.setAttribute('role','status');dialog.querySelector('header').after(n);}n.textContent=message;n.dataset.error=String(error);}
 document.addEventListener('DOMContentLoaded',()=>{
  document.querySelectorAll('dialog[id^="account-"]').forEach(d=>{hydrate(d);d.addEventListener('cancel',e=>{if(d.dataset.saving==='true')e.preventDefault();});});
  document.querySelector('[data-delivery-search]')?.addEventListener('input',e=>{const q=e.target.value.toLowerCase();document.querySelectorAll('.rp-delivery tbody tr').forEach(row=>row.hidden=!row.textContent.toLowerCase().includes(q));});
 });
 document.addEventListener('submit',async e=>{
  const form=e.target,dialog=form.closest('dialog[id^="account-"]');if(!dialog||form.method.toLowerCase()!=='post'||form.hasAttribute('data-remove-account'))return;
  e.preventDefault();if(dialog.dataset.saving==='true')return;
  const dangerous=e.submitter?.dataset.accountConfirm;
  if(dangerous){const prompt={
   suspend:'Suspend this reseller and disable access for their customers?',
   rotate:'Rotate this reseller’s private link? Existing sessions and the previous link will stop working.',
   'reset-password':'Issue a new password setup link? Existing reseller sessions will be invalidated.'
  }[dangerous];if(prompt&&!window.confirm(prompt))return;}
  const data=new FormData(form),selected=Number(dialog.dataset.selectedPanel||0);dialog.dataset.saving='true';
  const assignment=/\/(management-bot|network|permissions|limits)$/.test(form.action);
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),assignment?90000:35000);
  const controls=[...dialog.querySelectorAll('button')].map(button=>({button,disabled:button.disabled}));controls.forEach(({button})=>button.disabled=true);dialog.setAttribute('aria-busy','true');const overlay=document.createElement('div');overlay.className='rp-save-overlay';overlay.setAttribute('role','status');overlay.innerHTML='<div class="rp-save-box"><span class="rp-operation-spinner" aria-hidden="true"></span><div><strong>Saving changes…</strong><p>Please wait for confirmation.</p></div></div>';dialog.append(overlay);dialog.querySelector('.rp-dialog-body').inert=true;
  try{
   let response;
   for (;;) {
     response=await fetch(form.action,{method:'POST',body:data,credentials:'same-origin',headers:{'X-Requested-With':'reseller-account','Accept':assignment?'application/json':'text/html'},signal:controller.signal});
     if(!assignment || !response.headers.get('content-type')?.includes('application/json'))break;
     const result=await response.json();
     if(result.code==='waiting_for_writer' && !controller.signal.aborted){
       overlay.querySelector('strong').textContent='Waiting to save…';
       await new Promise(resolve=>setTimeout(resolve,1000));continue;
     }
     if(!response.ok){status(dialog,result.error||'Check your settings and try again.',true);return;}
     status(dialog,result.message||'Changes saved.');
     try {
       const current=await fetch('/resellers/accounts/'+dialog.id.slice(8)+'/dialog',{credentials:'same-origin',cache:'no-store',signal:controller.signal});
       if(current.ok){
         const fresh=new DOMParser().parseFromString(await current.text(),'text/html').getElementById(dialog.id);
         if(fresh){dialog.querySelector('.rp-dialog-body').replaceWith(fresh.querySelector('.rp-dialog-body'));hydrate(dialog,selected);(dialog.querySelector('.rp-manage-picker')?.offsetWidth?dialog.querySelector('.rp-manage-picker select'):dialog.querySelector('[role="tab"][aria-selected="true"]'))?.focus();}
       }
     } catch (_) {}
     return;
   }
   const html=new DOMParser().parseFromString(await response.text(),'text/html');const fresh=html.getElementById(dialog.id);
   if(!response.ok||!fresh){status(dialog,html.querySelector('.rp-alert,#error-title + p')?.textContent||'Save was not confirmed. Check the current account before trying again.',true);return;}
   const oldRow=document.querySelector('[data-dialog="'+dialog.id+'"]')?.closest('.rp-account');const newRow=html.querySelector('[data-dialog="'+dialog.id+'"]')?.closest('.rp-account');
   if(oldRow&&newRow)oldRow.replaceWith(newRow);
   dialog.querySelector('.rp-dialog-body').replaceWith(fresh.querySelector('.rp-dialog-body'));
   hydrate(dialog,selected);status(dialog,[...html.querySelectorAll('.rp-desk > .rp-alert')].map(n=>n.textContent).join(' ')||'Changes saved.');
   (dialog.querySelector('.rp-manage-picker')?.offsetWidth?dialog.querySelector('.rp-manage-picker select'):dialog.querySelector('[role="tab"][aria-selected="true"]'))?.focus();
  }catch(_){status(dialog,'Connection interrupted. The change may have been saved; check its status before retrying.',true);}
  finally{clearTimeout(timer);overlay.remove();dialog.removeAttribute('aria-busy');dialog.querySelector('.rp-dialog-body').inert=false;window.rpRefreshDates?.();delete dialog.dataset.saving;controls.forEach(({button,disabled})=>button.disabled=disabled);}
 });
})();


(() => {
  'use strict';
  const dialogs = () => [...document.querySelectorAll('.rp-plan-dialog')];
  const cache = new Map();
  async function list(scope) {
    if (cache.has(scope) && Date.now() - cache.get(scope).time < 12000) {
      return cache.get(scope).rows;
    }
    const path = scope === 'local'
      ? '/api/get-interfaces'
      : `/api/nodes/${encodeURIComponent(scope)}/interfaces`;
    const response = await fetch(path, {credentials:'same-origin', cache:'no-store'});
    if (!response.ok) throw Error(`HTTP ${response.status}`);
    const payload = await response.json();
    const rows = Array.isArray(payload) ? payload : payload.interfaces;
    if (!Array.isArray(rows)) throw Error('Missing interface list');
    cache.set(scope, {time:Date.now(), rows});
    return rows;
  }
  async function interfaceState(dialog) {
    const targets = [...dialog.querySelectorAll('[data-rp-interface-id]')];
    const scopes = [...new Set(targets.map(label => label.dataset.rpInterfaceNode || 'local'))];
    const states = new Map();
    await Promise.all(scopes.map(async scope => {
      try { states.set(scope, await list(scope)); }
      catch (_) { states.set(scope, null); }
    }));
    for (const label of targets) {
      if (!dialog.open) break;
      const status = label.querySelector('[data-rp-interface-state]');
      const scope = label.dataset.rpInterfaceNode || 'local';
      const rows = states.get(scope);
      const stored = label.querySelector('strong')?.textContent.trim() || '';
      const name = stored.includes(':') ? stored.split(':').slice(-1)[0] : stored;
      const item = rows?.find(row => String(row.id) === label.dataset.rpInterfaceId || String(row.name || row.iface) === name);
      const running = typeof item?.is_up === 'boolean' ? item.is_up : null;
      status.dataset.state = running === true ? 'up' : running === false ? 'down' : 'unknown';
      status.textContent = running === true ? 'Running' : running === false ? 'Stopped' : 'Unavailable';
      status.title = running === null
        ? 'Live WireGuard state could not be verified.'
        : 'WireGuard interface state reported by the server.';
    }
  }
  function opened(dialog) {
    if (!dialog) return;
    const body = dialog.querySelector('.rp-dialog-body');
    if (body) body.scrollTop = 0;
    dialog.querySelectorAll('.rp-plan-invalid').forEach(n => n.remove());
    dialog.querySelectorAll('[data-rp-interface-state]').forEach(n => {
      n.textContent = 'Checking…'; n.dataset.state = 'unknown';
    });
    interfaceState(dialog).catch(() => {});
  }
  window.rpPlanDialogOpened=opened;
  document.addEventListener('click', event => {
    const button = event.target.closest('[data-dialog]');
    if (!button) return;
    const dialog = document.getElementById(button.dataset.dialog);
    if (dialog?.classList.contains('rp-plan-dialog')) opened(dialog);
  });
  dialogs().filter(d => d.hasAttribute('data-auto-open')).forEach(d => {

    queueMicrotask(() => { if (d.open) opened(d); });
  });
  document.addEventListener('invalid', event => {
    const control = event.target;
    const form = control.closest('.rp-plan-editor');
    if (!form) return;
    for (let detail = control.closest('details'); detail; detail = detail.parentElement?.closest('details')) detail.open = true;
  }, true);
  document.addEventListener('submit', event => {
    const form = event.target;
    if (!form.matches('.rp-plan-dialog form.rp-plan-editor')) return;
    form.querySelectorAll('.rp-plan-invalid').forEach(n => n.remove());
    if (form.querySelector('[name="interfaces"]:checked')) return;
    event.preventDefault();
    const section = form.querySelector('.rp-plan-interfaces');
    if (!section) return;
    const message = document.createElement('p');
    message.className = 'rp-plan-invalid';
    message.setAttribute('role','alert');
    message.textContent = 'Select at least one WireGuard interface before saving.';
    section.appendChild(message);
    section.scrollIntoView({block:'center',behavior:'smooth'});
  }, true);
  document.addEventListener('change', event => {
    if (!event.target.matches('.rp-plan-dialog [name="interfaces"]')) return;
    const form = event.target.closest('form');
    if (form?.querySelector('[name="interfaces"]:checked')) form.querySelectorAll('.rp-plan-invalid').forEach(n=>n.remove());
  });
})();

document.addEventListener('input', event => {
  const dialog = event.target.closest('.rp-plan-dialog');
  if (!dialog) return;
  const status = dialog.querySelector('[data-plan-status]');
  if (status) status.textContent = '';
  const error = dialog.querySelector('[data-save-result]');
  if (error) error.hidden = true;
});

document.addEventListener('submit', async event => {
  const form = event.target;
  if (!form.matches('.rp-plan-editor') || event.defaultPrevented) return;
  event.preventDefault();
  const dialog = form.closest('dialog');
  if (dialog.dataset.saving === 'true') return;
  const status = dialog.querySelector('[data-plan-status]');
  let errorBox = dialog.querySelector('[data-save-result]');
  if (!errorBox) {
    errorBox = document.createElement('p');
    errorBox.dataset.saveResult = '';
    errorBox.dataset.state = 'error';
    errorBox.className = 'rp-plan-save-result';
    errorBox.setAttribute('role', 'alert');
    errorBox.tabIndex = -1;
    dialog.querySelector('.rp-dialog-head').after(errorBox);
  }
  errorBox.hidden = true;
  status.textContent = 'Saving…';
  status.dataset.state = 'pending';
  dialog.dataset.saving = 'true';
  form.setAttribute('aria-busy', 'true');
  const body = new FormData(form);
  const scrollArea = dialog.querySelector('.rp-dialog-body');
  scrollArea.inert = true;
  const controls = [...dialog.querySelectorAll('button')].filter(button => !button.disabled);
  controls.forEach(button => { button.disabled = true; });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch(form.action, {method: 'POST', body, credentials: 'same-origin',
      headers: {Accept: 'application/json'}, signal: controller.signal});
    const result = await response.json();
    if (!response.ok || !result.ok) throw Error((result.error || 'The save could not be confirmed.') + (result.reference ? '  Ref. ' + result.reference : ''));
    if (result.location) {
      location.assign(result.location);
      return;
    }
    if (result.row) {
      const row = new DOMParser().parseFromString(result.row, 'text/html').querySelector('.rp-plan-row');
      const previous = document.querySelector('[data-dialog="' + dialog.id + '"]')?.closest('.rp-plan-row');
      if (row && previous) previous.replaceWith(row);
    }
    if (result.name) dialog.querySelector('h2').textContent = 'Edit plan · ' + result.name;
    status.dataset.state = 'success';
    status.textContent = 'Changes saved';
  } catch (error) {
    status.textContent = '';
    errorBox.textContent = error.name === 'AbortError' || error instanceof TypeError || error instanceof SyntaxError
      ? 'The save could not be confirmed. Check the plan before trying again.' : error.message;
    errorBox.hidden = false;
    errorBox.focus({preventScroll: true});
  } finally {
    clearTimeout(timer);
    scrollArea.inert = false;
    dialog.dataset.saving = 'false';
    form.removeAttribute('aria-busy');
    controls.forEach(button => { button.disabled = false; });
  }
});

document.addEventListener('submit', async event => {
  const form = event.target;
  if (!form.matches('[data-order-review]')) return;
  event.preventDefault();
  const card = form.closest('.rp-inbox-order');
  if (card.getAttribute('aria-busy') === 'true') return;
  const body = new FormData(form);
  const notice = card.querySelector('[data-review-feedback]');
  const buttons = [...card.querySelectorAll('button')];
  card.setAttribute('aria-busy', 'true');
  buttons.forEach(button => { button.disabled = true; });
  notice.hidden = false;
  notice.setAttribute('role', 'status');
  notice.textContent = 'Saving decision…';
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch(form.action, {method: 'POST', credentials: 'same-origin', body,
      headers: {Accept: 'application/json'}, signal: controller.signal});
    const result = await response.json();
    if (!response.ok || !result.ok) throw Error((result.error || 'The review could not be confirmed.') + (result.reference ? '  Ref. ' + result.reference : ''));
    document.dispatchEvent(new Event('purchase-reviewed'));
    const filter = new URLSearchParams(location.search).get('status');
    if (filter && filter !== result.state) {
      location.assign(location.pathname + location.search);
      return;
    }
    const replacement = new DOMParser().parseFromString(result.row, 'text/html').querySelector('.rp-inbox-order');
    if (!replacement) throw Error('Refresh purchases to check the recorded decision.');
    card.replaceWith(replacement);
    replacement.querySelector('details').open = true;
    replacement.querySelector('summary').focus({preventScroll: true});
    window.rpRefreshDates?.();
  } catch (error) {
    notice.setAttribute('role', 'alert');
    notice.textContent = error.name === 'AbortError' || error instanceof TypeError || error instanceof SyntaxError
      ? 'The result could not be confirmed. Refresh purchases before trying again.' : error.message;
    notice.focus({preventScroll: true});
  } finally {
    clearTimeout(timer);
    card.removeAttribute('aria-busy');
    buttons.forEach(button => { button.disabled = false; });
  }
});

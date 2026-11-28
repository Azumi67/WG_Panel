

(() => {
  'use strict';
  const inventory = ['peers','subscriptions'].includes(window.RESELLER_SECTION);
  const grants = new Set(window.RESELLER_PERMISSIONS || []);
  const originalFetch = window.fetch.bind(window);
  const assignedInterfaces = new Map();
  const pendingInterfaces = new Map();
  const sharedReadOptions = new Set(['method', 'headers', 'credentials', 'cache']);
  const scopedURL = input => {
    const url = new URL(input, location.origin);
    if (url.origin === location.origin && url.pathname.startsWith('/api/')) url.pathname = '/r/shared' + url.pathname;
    return url.href;
  };
  const pendingMutationKeys=new Map();
  function requestKey(){return Array.from(crypto.getRandomValues(new Uint8Array(16)),x=>x.toString(16).padStart(2,'0')).join('');}
  function operationResponse(body,status){return new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}});}
  function operationBanner(message){
    const banner=document.createElement('aside');banner.setAttribute('role','status');banner.setAttribute('aria-live','polite');banner.className='reseller-quota-note rp-operation-progress';
    if(!window.WGWorkspace)Object.assign(banner.style,{position:'fixed',top:'12px',right:'12px',zIndex:'2147483647',maxWidth:'min(420px,calc(100vw - 24px))',padding:'12px',background:'var(--nx-card,var(--card-bg,#fff))',color:'var(--nx-text,var(--text,#152238))',border:'1px solid var(--line,#94a3b8)',borderRadius:'10px',boxShadow:'0 4px 20px #0003'});
    const label=document.createElement('span');label.textContent=message+' ';
    const link=document.createElement('a');link.href='/r/operations';link.textContent='View operation history';link.hidden=true;
    const close=document.createElement('button');close.type='button';close.textContent='×';close.setAttribute('aria-label','Dismiss operation notice');close.style.marginLeft='8px';close.onclick=()=>banner.remove();
    banner.append(label,link,close);document.body.append(banner);return {banner,label,link};
  }
  async function boundedFetch(target,init,ms){
    if(window.WGRequests)return window.WGRequests.buffered(originalFetch,target,init,ms);
    const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),ms);
    const parent=init?.signal;const abort=()=>controller.abort();
    if(parent?.aborted)abort();else parent?.addEventListener('abort',abort,{once:true});
    try{return await originalFetch(target,{...init,signal:controller.signal});}
    finally{clearTimeout(timer);parent?.removeEventListener('abort',abort);}
  }
  async function statusFetch(path){
    return boundedFetch(path,{credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json','X-Reseller-Account':String(window.RESELLER_ACCOUNT_ID)}},6000);
  }
  const delayedOperations=new Map();
  function watchDelayed(id,ui){
    if(!window.WGWorkspace||delayedOperations.has(id)||delayedOperations.size>=32)return;
    const end=Date.now()+300000;
    const finish=()=>delayedOperations.delete(id);
    const schedule=()=>{if(Date.now()>=end){finish();return;}delayedOperations.set(id,setTimeout(tick,5000));};
    async function tick(){
      if(Date.now()>=end){finish();return;}
      if(document.hidden){schedule();return;}
      try{
        const response=await statusFetch('/r/api/operations/'+encodeURIComponent(id));
        if([401,403,404].includes(response.status)){finish();return;}
        if(response.ok){
          const job=await response.json();
          if(!delayedOperations.has(id))return;
          if(job.state==='completed'){
            ui.label.textContent='Operation completed. Customer list refreshed when available. ';
            finish();
            window.dispatchEvent(new CustomEvent('rp-operation-completed',{detail:{id,delayed:true}}));
            setTimeout(()=>ui.banner.remove(),8000);
            return;
          }
          if(['rejected','review','resolved'].includes(job.state)){
            ui.label.textContent=(job.message||'Open operation history for the final result.')+' ';
            ui.link.hidden=false;finish();return;
          }
        }
      }catch(_){}
      if(delayedOperations.has(id))schedule();
    }
    schedule();
  }
  async function awaitOperation(response,ui){
    if(response.status!==202)return {response,final:true};
    const accepted=await response.clone().json().catch(()=>null);
    if(!accepted?.operation?.id){if(ui){ui.label.textContent='Server did not return an operation reference. Check operation history. ';ui.link.hidden=false;}return {response:operationResponse({ok:false,error:'Missing operation reference. Check Operations.'},502),final:false};}
    const id=accepted.operation.id;ui=ui||operationBanner('Operation queued.');
    const {banner,label,link}=ui;link.href='/r/operations/'+encodeURIComponent(id);link.textContent='View status';link.hidden=false;
    label.textContent='Request queued. Earlier requests may be processed first. ';
    const deadline=Date.now()+30000;
    while(Date.now()<deadline){
      await new Promise(resolve=>setTimeout(resolve,1500));
      try{
        const status=await statusFetch('/r/api/operations/'+encodeURIComponent(id));
        if(!status.ok){if([401,403,404].includes(status.status))break;continue;}
        const job=await status.json();
        if(job.state==='completed'){
          if(delayedOperations.has(id)){clearTimeout(delayedOperations.get(id));delayedOperations.delete(id);}
          label.textContent='Operation completed. ';setTimeout(()=>banner.remove(),5000);
          const ids=job.result?.ids||[];
          return {response:operationResponse({ok:true,success:true,created:ids.length,id:ids[0],...job.result},200),final:true};
        }
        if(['rejected','review','resolved'].includes(job.state)){
          if(delayedOperations.has(id)){clearTimeout(delayedOperations.get(id));delayedOperations.delete(id);}
          label.textContent=(job.message||'Operation needs review.')+' ';link.hidden=job.state!=='review';
          return {response:operationResponse({ok:false,error:job.message||'Check operation status.',operation_id:id},409),final:job.state!=='review'};
        }
        label.textContent=(job.message||(job.state==='running'?'Processing.':'Waiting for the worker.'))+' ';
      }catch(_){}
    }
    label.textContent='Still queued, processing or unable to confirm. Do not repeat this request. ';link.hidden=false;
    watchDelayed(id,ui);
    return {response:operationResponse({ok:false,error:'Operation '+id+' is still processing or could not be confirmed. Open Operations for the result; retrying the same request uses the same reference.',operation_id:id},409),final:false};
  }
  function queuedRoute(resource){
    return /^\/r\/api\/(?:create\/(?:peer|subscription)|(?:peers|subscriptions)\/(?:\d+|bulk)\/(?:edit|delete|enable|disable|rotate|reset_data|reset_timer))$/.test(resource)||
      /^\/r\/shared\/api\/(?:nodes\/\d+\/)?(?:peers(?:\/bulk)?|peer\/[^/]+(?:\/(?:edit|delete|enable|disable|reset_data|reset_timer))?|subscriptions(?:\/\d+(?:\/(?:edit|delete|enable|disable|reset_data|reset_timer))?)?)$/.test(resource);
  }
  async function submitMutation(target,init,resource,key,headers){
    const tracked=queuedRoute(resource);const ui=tracked?operationBanner('Submitting operation…'):null;
    let response;
    try{
      response=tracked?await boundedFetch(target,{...init,headers},15000):await originalFetch(target,{...init,headers});
    }catch(err){
      if(!tracked)throw err;
      ui.label.textContent='Submission response delayed. Checking the request reference… ';
      try{
        const check=await statusFetch('/r/api/operations/request/'+encodeURIComponent(headers.get('Idempotency-Key')));
        if(check.ok){response=operationResponse({operation:await check.json()},202);}
      }catch(_){}
      if(!response){
        ui.label.textContent='Submission not confirmed. Check operation history before submitting again. ';ui.link.hidden=false;
        return operationResponse({ok:false,error:'Submission not confirmed. Check Operations; retrying the same request uses the same identifier.'},504);
      }
    }
    if(response.status===202){
      const result=await awaitOperation(response,ui);
      if(result.final)pendingMutationKeys.delete(key);
      return result.response;
    }
    if(ui){if(response.ok)ui.banner.remove();else{const failure=await response.clone().json().catch(()=>({}));ui.label.textContent=(failure.error||'Request not completed (HTTP '+response.status+').')+' ';if(failure.operations_url)ui.link.hidden=false;}}
    if(response.ok||[400,401,403,404,409,422,429].includes(response.status))pendingMutationKeys.delete(key);
    return response;
  }
  window.fetch = (input, init) => {


    const originalURL=new URL(input instanceof Request ? input.url : input,location.origin);
    if (originalURL.origin!==location.origin)return originalFetch(input,init);
    if (!grants.has('network_options') && typeof init?.body === 'string' && /\/api\/(peers|peer\/|subscriptions)/.test(originalURL.pathname)) {
      try { const body=JSON.parse(init.body);for(const key of ['allowed_ips','dns','mtu','persistent_keepalive','endpoint','peer_endpoint','sync_existing'])delete body[key];init={...init,body:JSON.stringify(body)}; } catch (_) {}
    }
                                                                                       
                                                                      
    const policy = window.RESELLER_NETWORK_POLICY || {};
    const requestUrl = new URL(input instanceof Request ? input.url : input, location.origin);
    if (requestUrl.origin === location.origin && /\/(?:api|r\/shared\/api)\/(?:peers|peer\/|subscriptions)/.test(requestUrl.pathname)
        && typeof init?.body === 'string' && !(init.body instanceof FormData)) {
      try {
        const body = JSON.parse(init.body);
        if (body && typeof body === 'object' && (policy.endpoint || !policy.allow_endpoint)) {
          delete body.endpoint;
          init = {...init, body:JSON.stringify(body)};
        }
      } catch (_) {}
    }
    const url=new URL(input instanceof Request ? input.url : input,location.origin);
    if(url.origin===location.origin){const headers=new Headers(init?.headers || (input instanceof Request ? input.headers : undefined));headers.set('X-Reseller-Account',String(window.RESELLER_ACCOUNT_ID));init={...init,headers};}
    const target = input instanceof Request ? new Request(scopedURL(input.url), input) : scopedURL(input);
    const resource = new URL(target instanceof Request ? target.url : target).pathname;
    const localList = /^\/r\/shared\/api\/(?:get-interfaces|interfaces)$/.test(resource);
    const nodeList = /^\/r\/shared\/api\/nodes\/\d+\/interfaces$/.test(resource);
    const method = init?.method || (input instanceof Request ? input.method : 'GET');
    if(url.origin===location.origin && !['GET','HEAD','OPTIONS'].includes(method.toUpperCase()) && /^\/r\/(?:shared\/)?api\//.test(resource)){
      const headers=new Headers(init?.headers);
      const key=JSON.stringify([method.toUpperCase(),resource,url.search,typeof init?.body==='string'?init.body:null]);
      if(!headers.has('Idempotency-Key')){
        if(!pendingMutationKeys.has(key)){if(pendingMutationKeys.size>=64)pendingMutationKeys.delete(pendingMutationKeys.keys().next().value);pendingMutationKeys.set(key,requestKey());}
        headers.set('Idempotency-Key',pendingMutationKeys.get(key));
      }
      if(queuedRoute(resource))headers.set('Accept','application/json');
      return submitMutation(target,init,resource,key,headers);
    }
    if (!inventory || url.origin !== location.origin || method.toUpperCase() !== 'GET' || !(localList || nodeList)) {
      return originalFetch(target, init);
    }
    const canShare = typeof target === 'string' && Object.keys(init || {}).every(option => sharedReadOptions.has(option));
    const key = JSON.stringify([localList ? 'local' : resource, url.search, init?.credentials || 'same-origin',
                                init?.cache || 'default', [...new Headers(init?.headers)]]);
    if (canShare && pendingInterfaces.has(key)) return pendingInterfaces.get(key).then(response => response.clone());
    const result = originalFetch(target, init);
    if (canShare) {
      pendingInterfaces.set(key, result);
      const release = () => pendingInterfaces.delete(key);
      result.then(release, release);
    }
    result.then(response => response.ok ? response.clone().json() : null).then(data => {
      if (!data) return;
      const rows = Array.isArray(data) ? data : data.interfaces || [];
      let changed = false;
      for (const row of rows) {
        const id = String(row.id);
        if (row.endpoint_locked && assignedInterfaces.get(id) !== row.endpoint) {
          assignedInterfaces.set(id, row.endpoint);
          changed = true;
        } else if (!row.endpoint_locked && assignedInterfaces.delete(id)) changed = true;
      }
      if (changed) permissions();
    }).catch(() => {});
    return canShare ? result.then(response => response.clone()) : result;
  };
  if (window.RESELLER_REMAINING_MS > 0) {
    let deadline = Date.now() + window.RESELLER_REMAINING_MS, timer, checking = false;
    async function checkExpiry() {
      clearTimeout(timer);
      if (document.hidden || checking) return;
      const delay = deadline - Date.now();
      if (delay > 0) {
        timer = setTimeout(checkExpiry, Math.min(delay, 2147483647));
        return;
      }
      checking = true;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);
      try {
        const r = await window.fetch('/r/billing/status', {headers:{Accept:'application/json'}, cache:'no-store',signal:controller.signal});
        if (r.status === 401 || r.status === 403) return;
        if (r.ok) {
          const info = await r.json();
          if (info.expired) {
            location.replace('/r/billing');
            return;
          }
          deadline = Date.now() + Math.max(1000, info.remaining_ms);
        }
      } catch {} finally {
        checking = false;
        clearTimeout(timeout);
      }
      timer = setTimeout(checkExpiry, Math.min(2147483647, Math.max(15000, deadline-Date.now())));
    }
    document.addEventListener('visibilitychange', checkExpiry);
    checkExpiry();
  }
  const rules = {
    create: '#create-peer-btn,#open-sub-modal', bulk: '#bulk-btn',
    peer_template: '#peer-template-open', portal_design: '#open-sub-settings,[data-template]',
    edit: '[data-peer-action="edit"],[data-edit],[data-diagnosis-edit]',
    delete: '[data-peer-action="delete"],[data-del]',
    control_access: '[data-peer-action="enable"],[data-peer-action="disable"],[data-enable],[data-disable],[data-sub-enable],[data-sub-disable]',
    download: '[data-peer-action="qr"],[data-peer-action="download"],[data-peer-action="link"],[data-copy],[data-open]',
    reset_data:'[data-peer-action="reset-data"],[data-reset-data]',reset_timer:'[data-peer-action="reset-timer"],[data-reset-timer]',manage_inbounds:'[data-inbounds],[data-remove-inbound]',
    logs: '[data-peer-action="logs"],[data-logs],[data-subscription-logs]',
    profiles: '.peerx-profile-card,#profile-manager,#sub-profile-select,#studio-profile-select,[data-profile-action]',
    attach_existing: '[data-mode="current"]'
  };
  const blocked = '#create-iface-btn,#iface-toggle-btn,#iface-delete-btn,#owner-filter,#peer-filter-owner,#iface-create-modal';
  function permissions(root = document) {
    if (!inventory) return;
    const select=selector=>[...(root.matches?.(selector)?[root]:[]),...root.querySelectorAll(selector)];
    for (const [grant, selector] of Object.entries(rules)) if (!grants.has(grant)) select(selector).forEach(el => { if(['peer_template','portal_design'].includes(grant)&&['peer-template-open','open-sub-settings'].includes(el.id)){el.hidden=false;el.disabled=true;el.title='The administrator must enable this account’s public page design permission.';el.setAttribute('aria-label',el.textContent.trim()+' — permission required');return;}if(!el.hidden)el.hidden=true;if(!el.disabled)el.disabled=true;if(el.style.display!=='none')el.style.setProperty('display','none','important'); });
    select(blocked).forEach(el => { if(!el.hidden)el.hidden=true;if(!el.disabled)el.disabled=true;if(el.style.display!=='none')el.style.setProperty('display','none','important'); });
    if (!grants.has('network_options')) select('[name="allowed_ips"],[name="dns"],[name="mtu"],[name="persistent_keepalive"],[name="endpoint"],[name="peer_endpoint"]').forEach(el => { if(!el.disabled)el.disabled=true; });
    const policy=window.RESELLER_NETWORK_POLICY||{};
    const noFixed=!grants.has('network_options')||(Object.keys(policy).length&&!policy.allow_fixed);
    const noInternal=!grants.has('network_options')||(Object.keys(policy).length&&!policy.allow_internal);
    if(noFixed)select('.peerx-fixed-endpoint-field,.fixed-endpoint-card').forEach(el=>{el.hidden=true;el.style.setProperty('display','none','important');});
    if(noInternal)select('.auto-network-toggle,.peerx-internal-switch,.advanced-routing-auto-inline').forEach(el=>{el.hidden=true;el.style.setProperty('display','none','important');el.querySelectorAll('input[type="checkbox"]').forEach(input=>{input.disabled=true;input.checked=false;});});
    if(Object.keys(policy).length){
      if(policy.endpoint||!policy.allow_endpoint)select('[name="endpoint"],#bulk-endpoint').forEach(el=>{el.readOnly=true;el.disabled=true;el.value=policy.endpoint||'';el.title='Server host and port are managed by your administrator';});
      if(!policy.allow_fixed)select('[name="peer_endpoint"]').forEach(el=>{el.disabled=true;el.value='';});
      if(!policy.allow_internal)select('[name="include_internal_network"],#peer-include-internal-network,#bulk-include-internal-network').forEach(el=>{el.disabled=true;el.checked=false;});
    }
    select('[name="endpoint"]').forEach(el=>{
      const form=el.closest('form');
      const iface=form?.querySelector('[name="iface"],[name="iface_id"]')?.value;
      const endpoint=assignedInterfaces.get(String(iface));
      if(endpoint){el.readOnly=true;el.disabled=true;el.value=endpoint;el.title='Host and port assigned by your administrator';}
    });
    if(policy.endpoint||!policy.allow_endpoint)select('.endpoint-presets-compact').forEach(el=>{el.hidden=true;el.style.setProperty('display','none','important');});
    select('[name="unlimited"]').forEach(el => { if(!el.disabled)el.disabled=true;if(el.checked)el.checked=false; });
    if (!grants.has('choose_address')) select('[name="address"],#create-address-select').forEach(el => { if(!el.disabled)el.disabled=true; });
    select('a[href^="/api/"]').forEach(el => { el.href = scopedURL(el.href); });
  }
  window.applyResellerPermissions=permissions;
  document.addEventListener('DOMContentLoaded', () => {
    for (const form of document.forms) {
      if (form.method.toLowerCase() !== 'post' || form.elements.namedItem('rp_expected_account')) continue;
      const field = document.createElement('input');
      field.type = 'hidden';
      field.name = 'rp_expected_account';
      field.value = String(window.RESELLER_ACCOUNT_ID);
      form.appendChild(field);
    }
    if (!inventory) return;
    const note=document.createElement('aside');note.className='reseller-quota-note';note.textContent='Customer limits remain within your reseller plan. All customers share your plan’s traffic allowance and expiry.';
    if((window.RESELLER_SECTION==='peers'&&!grants.has('peer_template'))||(window.RESELLER_SECTION==='subscriptions'&&!grants.has('portal_design')))note.textContent+=' Ask your administrator to enable customer page design to use the template editor.';
    document.querySelector('.peer-manage-section,.subx-hero-panel')?.before(note);
    document.querySelectorAll('[name="data_limit_value"],[name="data_limit"]').forEach(el=>{el.min='1';if(!Number(el.value))el.value='1';});
    const form = document.getElementById('create-peer-form');
    if (form) {
      form.action = '/r/shared/users';
      const field=document.createElement('input');field.type='hidden';field.name='rp_request_id';field.value=requestKey();form.appendChild(field);
    }

    permissions();
                                                                             
                                                                                 
    const pageURL=new URL(location.href);
    const resumed=pageURL.searchParams.get('operation');
    if(resumed && /^[a-f0-9]{32}$/.test(resumed)){
      const ui=operationBanner('Checking submitted operation…');
      void awaitOperation(operationResponse({operation:{id:resumed}},202),ui).then(result=>{
        if(!result.final)return;
        pageURL.searchParams.delete('operation');
        history.replaceState(history.state,'',pageURL.href);
        if(result.response.ok)window.dispatchEvent(new CustomEvent('rp-operation-completed'));
      });
    }



    let permissionFrame = 0;
    const changed = new Set();
    new MutationObserver(records => {
      for (const record of records) {
        if (record.type === 'attributes') changed.add(record.target);
        for (const node of record.addedNodes) if (node.nodeType === 1) changed.add(node);
      }
      if (!changed.size || permissionFrame) return;
      permissionFrame = requestAnimationFrame(() => {
        permissionFrame = 0;
        for (const node of changed) {
          if (!node.isConnected) continue;
          let parent = node.parentElement;
          while (parent && !changed.has(parent)) parent = parent.parentElement;
          if (!parent) permissions(node);
        }
        changed.clear();
      });
    }).observe(document.body,{childList:true,subtree:true,attributes:true,attributeFilter:['aria-hidden','open']});
  });
  document.addEventListener('click', e => {
    const logout = e.target.closest('[data-reseller-logout]');
    if (logout) {
      e.preventDefault();
      const f = document.createElement('form'); f.method = 'post'; f.action = '/r/logout';
      const token = document.createElement('input'); token.name = 'csrf_token'; token.value = document.querySelector('meta[name="csrf-token"]').content;
      f.append(token); document.body.append(f); f.submit();
    }
    const a = e.target.closest('a[href]'); if (a && new URL(a.href).pathname.startsWith('/api/')) a.href = scopedURL(a.href);
  }, true);
})();

document.addEventListener('DOMContentLoaded',()=>{
 const select=document.getElementById('rp-bulk-profile'),form=document.getElementById('bulk-form');if(!select||!form)return;
 const apply=document.getElementById('rp-bulk-apply'),undo=document.getElementById('rp-bulk-undo'),status=document.getElementById('rp-bulk-profile-status');let snapshot=null;
 const keys=['data_limit_value','data_limit_unit','time_limit_days','time_limit_hours','start_on_first_use','allowed_ips','dns','mtu','persistent_keepalive','endpoint','peer_endpoint'];
 const fields=()=>keys.map(k=>form.querySelector('[name="'+k+'"]')).filter(n=>n&&!n.disabled&&!n.readOnly);
 const load=async()=>{try{const r=await fetch('/r/shared/api/peer_profiles');if(!r.ok)throw Error();const data=await r.json();select.replaceChildren(new Option('Choose a profile',''));for(const name of data.profiles||[])select.add(new Option(name,name));status.textContent=data.profiles?.length?'':'No saved profiles yet. Save one in Create peer.';}catch(_){status.textContent='Profiles unavailable. You can still enter batch settings.';}};
 document.getElementById('bulk-btn')?.addEventListener('click',load);
 apply.onclick=async()=>{if(!select.value){status.textContent='Choose a saved profile first.';return;}apply.disabled=true;try{const r=await fetch('/r/shared/api/peer_profile?name='+encodeURIComponent(select.value));if(!r.ok)throw Error();const data=await r.json();snapshot=fields().map(n=>({n,value:n.type==='checkbox'?n.checked:n.value}));for(const n of fields()){if(data[n.name]==null)continue;if(n.type==='checkbox')n.checked=data[n.name]===true||data[n.name]==='on';else n.value=String(data[n.name]);n.dispatchEvent(new Event('change',{bubbles:true}));}undo.disabled=false;status.textContent='Defaults applied. Review the limits before creating.';}catch(_){status.textContent='Could not apply this profile. Your fields were kept.';}finally{apply.disabled=false;}};
 undo.onclick=()=>{for(const {n,value} of snapshot||[]){if(n.disabled||n.readOnly)continue;if(n.type==='checkbox')n.checked=value;else n.value=value;n.dispatchEvent(new Event('change',{bubbles:true}));}snapshot=null;undo.disabled=true;status.textContent='Previous batch settings restored.';};
});

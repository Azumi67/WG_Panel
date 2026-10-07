(() => {
  if (window.WG_PANEL_IS_ADMIN !== true) return;
  let dialog = null;
  let lastFocus = null;
  let controller = null;
  let currentReport = null;

  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const stateLabel = s => s === 'ready' ? 'Ready' : s === 'attention' ? 'Attention' : s === 'not_required' ? 'Not required' : s === 'review' ? 'Review' : 'Unknown';
  const stateIcon = s => s === 'ready' ? 'fa-check' : s === 'attention' ? 'fa-triangle-exclamation' : s === 'review' ? 'fa-eye' : s === 'not_required' ? 'fa-minus' : 'fa-circle-question';

  function peerURL(peer){
    if(peer.remote){if(!peer.node_id||!peer.public_key)throw new Error('The node or peer key is missing. Refresh the peer list and check again.');return `/api/nodes/${encodeURIComponent(peer.node_id)}/peer/${encodeURIComponent(peer.public_key)}`;}
    return `/api/peer/${Number(peer.id)}`;
  }
  async function diagnosisRequest(url,method='POST',body){
    const cookie=document.cookie.match(/(?:^|; )csrf_token=([^;]*)/);
    const token=document.querySelector('meta[name="csrf-token"]')?.content||(cookie?decodeURIComponent(cookie[1]):'');
    const res=await fetch(url,{method,credentials:'same-origin',headers:{'Content-Type':'application/json','Accept':'application/json',...(token?{'X-CSRFToken':token}:{})},...(body?{body:JSON.stringify(body)}:{})});
    if(!res.headers.get('content-type')?.includes('application/json'))throw new Error('No JSON response received. Your session may have expired.');
    const data=await res.json();
    if(!res.ok)throw new Error(data.detail||data.message||data.error||`Request failed (HTTP ${res.status}). Check again before retrying.`);
    return {...data,_partial:res.status===207||data.partial||data.ok===false||data.success===false||(data.failed_peer_ids||[]).length>0};
  }
  window.wgMountDiagnosisActions=(host,peer,refresh)=>{
    const shared=Number(peer.subscription_id)>0;
    const box=document.createElement('div');box.className='diagnosis-actions';
    const actions=[['reset_data','Reset used data','This clears recorded usage'+(shared?' for this client and its attached configurations.':' for this peer.')+' It does not extend an expired timer.'],['reset_timer','Reset timer','This restarts the time allowance'+(shared?' for the shared client.':' for this peer.')+' It does not clear exhausted data.'],['enable',shared?'Enable and reset client':'Enable peer',shared?'This enables attached configurations and resets the shared client’s data and timer.':'This requests access for this peer. Other policy limits may still block it.']];
    box.innerHTML=`<p>${shared?'Shared subscription actions':'Peer actions'}</p><div class="diagnosis-action-buttons">${actions.map(([action,label])=>`<button type="button" data-diagnosis-action="${action}">${label}</button>`).join('')}</div><div class="diagnosis-confirm" hidden><p></p><button type="button" data-apply>Confirm</button><button type="button" data-cancel>Cancel</button></div><p role="status" aria-live="polite"></p>`;
    host.append(box);let selected=null,busy=false;
    box.addEventListener('click',async e=>{
      if(busy)return;
      const b=e.target.closest('[data-diagnosis-action]'),confirm=box.querySelector('.diagnosis-confirm'),status=box.querySelector('[role=status]');
      if(b){selected=actions.find(a=>a[0]===b.dataset.diagnosisAction);confirm.hidden=false;confirm.querySelector('p').textContent=selected[2];confirm.querySelector('[data-apply]').textContent=selected[1];confirm.querySelector('[data-apply]').focus();return;}
      if(e.target.closest('[data-cancel]')){confirm.hidden=true;selected=null;return;}
      if(!e.target.closest('[data-apply]')||!selected)return;
      busy=true;box.querySelectorAll('button').forEach(b=>b.disabled=true);status.textContent='Applying…';
      try{
        const base=shared?`/api/subscriptions/${Number(peer.subscription_id)}`:peerURL(peer);
        const data=await diagnosisRequest(`${base}/${selected[0]}`);
        const warning=data._partial||data.still_blocked_reason;
        const message=data.still_blocked_reason?`Action completed, but access is still blocked: ${String(data.still_blocked_reason).replaceAll('_',' ')}. Review the other allowance.`:data._partial?(data.message||'Only part of the action completed. Check attached peers before retrying.'):(data.message||'Action completed. Checking the latest state…');
        status.textContent=message;window.toast?.(message,warning?'warning':'success');
        window.dispatchEvent(new Event('wgpanel:diagnosis-changed'));
        await refresh();
        const surface=document.querySelector('#peer-diagnose-dialog:not([hidden]) #pd17-body,#sub-diagnosis[open] .diagnosis-body');
        if(surface){const note=document.createElement('p');note.className='diagnosis-help';note.setAttribute('role','status');note.textContent=message;surface.prepend(note);}
      }catch(err){status.textContent=(err.message||'No response received.')+' Check the latest state before retrying; the action may have completed.';}
      finally{busy=false;box.querySelectorAll('button').forEach(b=>b.disabled=false);confirm.hidden=true;selected=null;}
    });
  };

  function ensure() {
    if (dialog) return dialog;
    dialog = document.createElement('div');
    dialog.id = 'peer-diagnose-dialog';
    dialog.className = 'pd17';
    dialog.hidden = true;
    dialog.setAttribute('aria-hidden','true');
    dialog.innerHTML = `<button class="pd17-backdrop" type="button" data-pd17-close tabindex="-1" aria-label="Close diagnosis"></button>
      <section class="pd17-panel" role="dialog" aria-modal="true" aria-labelledby="pd17-title" tabindex="-1">
        <div class="pd17-handle" aria-hidden="true"></div>
        <header class="pd17-head"><div class="pd17-title"><span class="pd17-title-icon"><i class="fas fa-stethoscope"></i></span><div><small>Read-only connection path</small><h2 id="pd17-title">Diagnose peer</h2></div></div><button class="pd17-close" type="button" data-pd17-close aria-label="Close"><i class="fas fa-xmark"></i></button></header>
        <div id="pd17-body"><div class="pd17-loading"><i class="fas fa-circle-notch fa-spin"></i> Running peer diagnosis…</div></div>
        <footer class="pd17-foot"><span><i class="fas fa-shield-halved"></i> Checking is read-only. Changes require an explicit action below.</span><a href="/operations" id="pd17-host-link">Run host diagnostic <i class="fas fa-arrow-right"></i></a></footer>
      </section>`;
    document.body.appendChild(dialog);
    dialog.addEventListener('click', e => {
      if (e.target.closest('[data-pd17-close]')) close();
      const edit=e.target.closest('[data-pd-edit]');
      if(edit && currentReport){
        const peer=currentReport.peer,stage=edit.dataset.pdEdit;
        const shared=stage==='access' && Number(peer.subscription_id)>0;
        close();
        const opened=shared ? window.wgOpenSubscriptionDiagnosisEditor?.(peer.subscription_id) : window.wgOpenPeerDiagnosisEditor?.(peer,stage);
        if(!opened){open();inlineEditor(edit.closest('.pd17-guidance'),peer,stage);}
      }
      if(e.target.closest('[data-pd-recheck]')&&currentReport)diagnose(Number(currentReport.peer.id));
    });
    dialog.addEventListener('keydown', e => {
      if (e.key !== 'Tab') return;
      const f = [...dialog.querySelectorAll('button:not([disabled]),a[href],input:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex="-1"])')].filter(x => x.offsetParent !== null);
      if (!f.length) return;
      const first=f[0], last=f[f.length-1];
      if (e.shiftKey && document.activeElement===first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement===last) { e.preventDefault(); first.focus(); }
    });
    return dialog;
  }

  function open() {
    const el=ensure(); lastFocus=document.activeElement; el.hidden=false; el.setAttribute('aria-hidden','false'); document.body.classList.add('pd17-open'); requestAnimationFrame(()=>el.querySelector('.pd17-panel')?.focus());
  }
  function close() {
    if (!dialog || dialog.hidden) return; if (controller) controller.abort(); dialog.hidden=true; dialog.setAttribute('aria-hidden','true'); document.body.classList.remove('pd17-open'); if(lastFocus?.focus) lastFocus.focus();
  }
  function render(report) {
    const body=document.getElementById('pd17-body'); if(!body) return;
    currentReport=report;
    const peer=report.peer||{};
    const title=document.getElementById('pd17-title'); if(title) title.textContent=`Diagnose ${peer.name || 'peer'}`;
    const attached=Number.isInteger(Number(peer.subscription_id)) && Number(peer.subscription_id)>0;
    const meta=[peer.interface,peer.address,attached ? `Attached client: ${peer.subscription_name||'#'+peer.subscription_id}` : 'Standalone peer · no subscription',peer.remote ? 'Remote node' : 'Local server'].filter(Boolean).join(' · ');
    const hostLink=document.getElementById('pd17-host-link');
    if(hostLink) hostLink.href=report.operations_href || '/operations';
    const stages=(report.stages||[]).map(stage=>{
      const needsReview=!['ready','not_required'].includes(stage.state);
      const action=stage.href?.startsWith('/operations?') ? `<a href="${esc(stage.href)}">Check this interface <i class="fas fa-arrow-right"></i></a>` : (stage.href==='/users'||stage.href==='/subscriptions') ? `<button type="button" data-pd-edit="${esc(stage.id)}">${stage.id==='access'&&attached?'Review shared client limits':'Review peer settings'}</button>` : '';
      const guidance={access:attached && stage.href==='/subscriptions' ? 'This peer belongs to the client shown above. Review that client’s shared data and time limits before enabling or resetting access.' : 'This peer’s own access and limits need review. Review its settings below. Reset only the allowance you intend to renew; enable access only when its limits allow it.',allowed_ips:'Check Allowed IPs in the highlighted field, save your changes, then download the updated configuration.',endpoint:'Check the endpoint host and port in the highlighted field. Save, download the updated configuration and reconnect the client.',interface:'Run the interface check below. Open a reported finding to review its repair steps before applying changes.',handshake:'Turn on the tunnel in the client app. Confirm its endpoint and internet connection, then run diagnosis again.'};
      const help=needsReview ? `<div class="pd17-guidance" data-stage="${esc(stage.id)}"><strong>How to fix</strong><p>${esc(guidance[stage.id]||stage.hint||'Review the client configuration, reconnect, then run diagnosis again.')}</p>${action}</div>` : '';
      return `<article class="pd17-stage" data-state="${esc(stage.state)}"><span class="pd17-stage-icon"><i class="fas ${stateIcon(stage.state)}"></i></span><div class="pd17-stage-copy"><div class="pd17-stage-top"><b>${esc(stage.label)}</b><span class="pd17-pill">${stateLabel(stage.state)}</span></div><p>${esc(stage.detail)}</p>${help}</div></article>`;
    }).join('');
    body.innerHTML=`<div class="pd17-summary" data-state="${esc(report.state)}"><span class="pd17-summary-dot"></span><div><strong>${esc(report.headline||'Diagnosis complete')}</strong><p>${esc(meta || 'Peer connection path')}</p></div></div><div class="pd17-list">${stages || '<div class="pd17-error">No diagnostic stages were returned.</div>'}</div><button type="button" class="pd-recheck" data-pd-recheck>Check again</button>`;
    const access=body.querySelector('[data-stage=access]');if(access)window.wgMountDiagnosisActions(access,peer,()=>diagnose(Number(peer.id)));
  }
  function inlineEditor(host,peer,stage){
    dialog.querySelectorAll('.pd-inline-editor').forEach(el=>el.remove());
    const shared=stage==='access'&&Number(peer.subscription_id)>0;
    if(stage==='access'){
      const limits=peer.limits||{};
      const form=document.createElement('form');form.className='pd-inline-editor diagnosis-highlight';
      form.innerHTML=`<p>${shared?'Shared client limits — affects all attached configurations.':'Peer limits'}</p><label>Data allowance<input name="data_limit_value" type="number" min="0" step="1" required value="${esc(limits.data_limit_value||0)}"></label><label>Unit<select name="data_limit_unit">${['Mi','Gi','Ti'].map(u=>`<option ${u===(limits.data_limit_unit||'Gi')?'selected':''}>${u}</option>`).join('')}</select></label><label>Time allowance (days)<input name="time_limit_days" type="number" min="0" step="any" required value="${esc(limits.time_limit_days||0)}"></label><label><input type="checkbox" name="unlimited" ${limits.unlimited?'checked':''}> Unlimited</label><p>Changing the time allowance may restart the timer. Usage resets are separate actions.</p><button type="submit">Save limits</button><p role="status"></p>`;
      host.append(form);form.querySelector('input').focus();
      const original={data_limit_value:Number(limits.data_limit_value||0),data_limit_unit:limits.data_limit_unit||'Gi',time_limit_days:Number(limits.time_limit_days||0),unlimited:!!limits.unlimited};
      form.onsubmit=async e=>{e.preventDefault();const button=form.querySelector('button'),status=form.querySelector('[role=status]');const next={data_limit_value:Number(form.elements.data_limit_value.value),data_limit_unit:form.elements.data_limit_unit.value,time_limit_days:Number(form.elements.time_limit_days.value),unlimited:form.elements.unlimited.checked};const patch=Object.fromEntries(Object.entries(next).filter(([k,v])=>original[k]!==v));if(!Object.keys(patch).length){status.textContent='No changes to save.';return;}button.disabled=true;try{const result=await diagnosisRequest(shared?`/api/subscriptions/${Number(peer.subscription_id)}`:peerURL(peer),'PUT',patch);if(result._partial)throw new Error(result.message||'Some changes could not be applied. Check again before retrying.');Object.assign(original,next);status.textContent='Limits saved. Check again to review access.';window.dispatchEvent(new Event('wgpanel:diagnosis-changed'));}catch(err){status.textContent=err.message;}finally{button.disabled=false;}};
      return;
    }
    if(!['allowed_ips','endpoint'].includes(stage))return;
    const form=document.createElement('form');form.className='pd-inline-editor diagnosis-highlight';
    form.innerHTML=`<label>${stage==='allowed_ips'?'Allowed IPs':'Endpoint'}<input name="value" required value="${esc(peer[stage]||'')}" autocomplete="off"></label><p>Save, download the updated configuration and reconnect your client.</p><button type="submit">Save changes</button><p role="status"></p>`;
    host.append(form);form.querySelector('input').focus();
    form.onsubmit=async e=>{e.preventDefault();const button=form.querySelector('button'),status=form.querySelector('[role=status]');button.disabled=true;try{const result=await diagnosisRequest(peerURL(peer),'PUT',{[stage]:form.elements.value.value});if(result._partial)throw new Error(result.message||'Some changes could not be applied. Check again before retrying.');status.textContent='Saved. Download the updated configuration before reconnecting.';window.dispatchEvent(new Event('wgpanel:diagnosis-changed'));}catch(err){status.textContent=err.message;}finally{button.disabled=false;}};
  }
  function renderError(message){const body=document.getElementById('pd17-body');if(body)body.innerHTML=`<div class="pd17-error"><b>Diagnosis could not complete.</b><div style="margin-top:4px">${esc(message||'Check panel logs and try again.')}</div></div>`;}

  async function diagnose(peerId) {
    if (!Number.isInteger(peerId) || peerId < 1) return;
    open(); const body=document.getElementById('pd17-body'); if(body)body.innerHTML='<div class="pd17-loading"><i class="fas fa-circle-notch fa-spin"></i> Running peer diagnosis…</div>';
    if(controller)controller.abort(); controller=new AbortController();
    try{
      const res=await fetch('/api/operations/peer-diagnose',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify({peer_id:peerId}),signal:controller.signal});
      const data=await res.json().catch(()=>({}));
      if(!res.ok||data.ok===false)throw new Error(data.detail||data.message||data.error||`HTTP ${res.status}`);
      render(data);
    }catch(err){if(err?.name==='AbortError')return;renderError(err?.message);}
  }

  window.addEventListener('wgpanel:peer-diagnose', e => diagnose(Number(e.detail?.peerId)));
  document.addEventListener('keydown',e=>{if(e.key==='Escape'&&dialog&&!dialog.hidden)close();});
})();

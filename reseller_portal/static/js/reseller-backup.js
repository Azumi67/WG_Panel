(() => {
  'use strict';
  const tabs=[...document.querySelectorAll('[data-rb-tab]')];
  function selectTab(tab){tabs.forEach(item=>{const active=item===tab;item.setAttribute('aria-selected',String(active));item.tabIndex=active?0:-1;document.getElementById('rb-panel-'+item.dataset.rbTab).hidden=!active;});}
  tabs.forEach((tab,index)=>{tab.onclick=()=>selectTab(tab);tab.onkeydown=e=>{let next;if(e.key==='ArrowRight')next=(index+1)%tabs.length;else if(e.key==='ArrowLeft')next=(index+tabs.length-1)%tabs.length;else if(e.key==='Home')next=0;else if(e.key==='End')next=tabs.length-1;else return;e.preventDefault();selectTab(tabs[next]);tabs[next].focus();};});
  document.querySelectorAll('[data-rb-download]').forEach(button => {
    button.addEventListener('click', async event => {
      event.preventDefault();
      if (button.getAttribute('aria-disabled') === 'true') return;
      const label=button.querySelector('span'),original=label.textContent;
      const status=button.closest('.rb-card,.rb-export').querySelector('.rb-result');
      const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),90000);
      button.setAttribute('aria-disabled','true');label.textContent='Preparing…';status.textContent='';
      try {
        const response=await fetch(button.href,{credentials:'same-origin',cache:'no-store',signal:controller.signal});
        if(!response.ok)throw Error('Could not prepare this download. Try again.');
        const mime=response.headers.get('Content-Type')||'';
        const expected=button.closest('#rb-panel-export')?'application/json':'application/zip';
        if(!mime.includes(expected))throw Error('Unexpected backup response. Sign in again and retry.');
        const blob=await response.blob(),url=URL.createObjectURL(blob),link=document.createElement('a');
        const filename=(response.headers.get('Content-Disposition')||'').match(/filename="?([A-Za-z0-9_.-]+)"?/i)?.[1];
        link.href=url;link.download=filename||button.download;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),60000);
        status.dataset.error='false';const created=response.headers.get('X-Backup-Created-At');
        status.textContent=created?`Fresh backup generated · ${new Date(created).toLocaleString()} · ${Math.ceil(blob.size/1024)} KiB. Check your downloads.`:'Download prepared. Check your browser downloads.';
      }catch(error){status.dataset.error='true';status.textContent=error.name==='AbortError'?'Download timed out. Try again.':error.message;}
      finally{clearTimeout(timer);button.removeAttribute('aria-disabled');label.textContent=original;}
    });
  });
  const form=document.getElementById('rb-restore');if(!form)return;
  let busy=false,verifiedFile=null,inspectionController=null,selection=0;
  const input=form.querySelector('[type=file]'),button=form.querySelector('button[type=submit]'),status=document.getElementById('rb-result');
  const valid=()=>input.files[0]&&input.files[0].size>0&&input.files[0].size<=8*1024*1024;
  const updateFile=async()=>{
    const revision=++selection;verifiedFile=null;inspectionController?.abort();
    const inspection=document.getElementById('rb-inspection');inspection.hidden=true;
    const file=input.files[0];
    document.getElementById('rb-file-name').textContent=file?.name||'Choose a backup file';
    const review=document.getElementById('rb-file-review');review.hidden=!file;document.getElementById('rb-file-detail').textContent=file?`${file.name} · ${(file.size/1024).toFixed(1)} KB`:'';
    button.disabled=true;status.dataset.error=String(!valid());
    status.textContent=file&&!valid()?'Choose a non-empty encrypted ZIP or legacy JSON backup (maximum 8 MiB).':'';
    if(!valid())return;
    inspection.hidden=false;inspection.dataset.error='false';inspection.textContent='Checking backup contents…';
    const controller=new AbortController();inspectionController=controller;
    const timer=setTimeout(()=>controller.abort(),90000);
    try{
      const response=await fetch(form.dataset.inspect,{method:'POST',body:new FormData(form),credentials:'same-origin',headers:{Accept:'application/json'},signal:controller.signal});
      const data=await response.json().catch(()=>null);
      if(!response.ok||!data?.ok)throw Error(data?.error||data?.message||(response.status===403?'Your account does not have permission to restore this backup.':response.status===401||response.redirected?'Your session expired. Sign in again and select the file.':`Unable to verify this backup (HTTP ${response.status}). Reload the page and try again.`));
      if(revision!==selection)return;
      verifiedFile=file;
      inspection.textContent=`Verified for this account · ${data.customers} customers\n${data.peers} peers · ${data.subscriptions} subscriptions\n${(data.fields||[]).join(' · ')}\n${data.notice||'Settings-only backup: existing customers only.'}`;
      button.disabled=busy;
    }catch(error){if(revision!==selection)return;inspection.dataset.error='true';inspection.textContent=error.name==='AbortError'?'Backup check timed out. Select the file again to retry.':error.message;}
    finally{clearTimeout(timer);}

  };
  input.addEventListener('change',updateFile);
  document.getElementById('rb-file-clear').onclick=()=>{if(busy)return;input.value='';updateFile();};
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(busy||verifiedFile!==input.files[0]||!valid()||!form.reportValidity())return;
    busy=true;button.disabled=true;
    const controller=new AbortController();let timer;
    try {
      const accepted=window.wgConfirm?await window.wgConfirm({title:'Restore customers?',body:'Recover customers from this backup. Deleted peers return paused; existing access states and consumed traffic are preserved.',okText:'Restore customers',cancelText:'Cancel'}):confirm('Recover customers from this backup?');
      if(!accepted)return;
      const body=new FormData(form);input.disabled=true;
      window.panelOperationProgress?.show('Recovering your customers…');status.textContent='';
      timer=setTimeout(()=>controller.abort(),120000);
      const response=await fetch(form.action,{method:'POST',body,credentials:'same-origin',headers:{Accept:'application/json'},signal:controller.signal});
      const data=await response.json().catch(()=>null);
      if(!response.ok||!data?.ok)throw Error(data?.error||data?.message||'Restore could not be confirmed. Check your customers before retrying.');
      status.dataset.error='false';status.textContent=`Recovery completed for ${data.restored} customers. Review your peer and subscription lists; recreated peers are paused.`;
    }catch(error){status.dataset.error='true';status.textContent=error.message||'Restore could not be confirmed. Check your customers before retrying.';}
    finally{clearTimeout(timer);busy=false;input.disabled=false;button.disabled=!valid()||verifiedFile!==input.files[0];window.panelOperationProgress?.hide();}
  });
})();

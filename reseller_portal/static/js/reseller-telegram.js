(() => {
  let busy=false;
  const page=()=>document.querySelector('.rp-telegram-page');
  function feedback(message,error=false){
    const box=page()?.querySelector('[data-telegram-feedback]');
    if(!box)return;
    box.hidden=false;box.textContent=message;box.setAttribute('role',error?'alert':'status');
    if(error)box.scrollIntoView({block:'nearest'});
  }
  function connection(state){
    if(!state)return;
    const label=page()?.querySelector('[data-command-state]'),detail=page()?.querySelector('[data-command-detail]');
    if(label){label.textContent=state.label;label.className='rp-status '+state.state;}
    if(detail)detail.textContent=state.detail;
  }
  let checking=false;
  async function health(){
    if(document.hidden||busy||checking||!page())return;
    checking=true;const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),5000);
    try{const response=await fetch('/r/api/management-bot/status',{credentials:'same-origin',cache:'no-store',signal:controller.signal});if(response.ok)connection(await response.json());}
    catch(_){}finally{clearTimeout(timer);checking=false;}
  }
  setInterval(health,15000);
  document.addEventListener('visibilitychange',()=>{if(!document.hidden)health();});
  function update(state){
    connection(state.connection);
    const root=page();
    const recipient=root.querySelector('[data-recipient]');if(recipient)recipient.textContent=state.recipient||'Not linked';
    const enable=root.querySelector('[data-save-toggle="bot_enabled"]');
    enable.checked=state.enabled;enable.disabled=!state.has_token;
    root.querySelector('[data-connection-label]').textContent=state.enabled?'Enabled':'Disabled';
    root.querySelector('[data-connection-help]').textContent=state.has_token?'Enable or pause your connected bot.':'Verify a token below to connect and enable your bot.';
    root.querySelector('[data-connect-submit]').textContent=state.has_token?'Save connection':'Verify & connect';
    const delivery=root.querySelector('[data-save-toggle="delivery"]');
    if(delivery)delivery.checked=state.notifications_enabled;
    root.querySelector('[data-token-status]').textContent = state.has_token ? 'Saved' : 'Not set';
    const alerts = root.querySelector('[data-alert-status]');
    if (alerts) alerts.textContent = state.notifications_enabled ? (state.enabled ? 'On' : 'Paused') : 'Off';
    const username = /^[a-z0-9_]{5,32}$/i.test(state.username || '') ? state.username : '';
    root.querySelector('[data-bot-name]').textContent = username ? '@' + username : 'Telegram connection';
    const open = root.querySelector('[data-open-bot]');
    open.hidden = !username;
    if (username) open.href = 'https://t.me/' + username;
    else open.removeAttribute('href');
    root.querySelector('[data-disconnect-area]').hidden = !state.has_token;
    const input = root.querySelector('[name="token"]');
    input.placeholder = state.has_token ? 'Saved; leave blank to keep' : 'Paste a dedicated bot token';
    if (!state.has_token) input.value = '';
    const poll = root.querySelector('[data-last-poll]');
    if (!state.polled_at) poll.textContent = '—';
    else {
      const time = document.createElement('time');
      time.dataset.rpTime = '';
      time.dateTime = state.polled_at;
      time.textContent = state.polled_at;
      poll.replaceChildren(time);
      window.rpRefreshDates?.();
    }
    const test=root.querySelector('input[name="action"][value="test"]')?.form.querySelector('button');
    if(test)test.disabled=!state.enabled||!state.has_token;
  }
  async function save(form,toggle){
    if(busy){if(toggle)toggle.checked=!toggle.checked;return;}
    busy=true;
    const desired=toggle?.checked;
    const data=new FormData(form);
    if(toggle){data.set('action',toggle.dataset.saveToggle);data.delete('token');data.delete('enabled');if(desired)data.set('enabled','on');}
    const controls=[...page().querySelectorAll('input,select,button')].map(el=>[el,el.disabled]);
    controls.forEach(([el])=>el.disabled=true);
    const content=page().querySelector('[data-telegram-content]');
    content.inert=true;page().setAttribute('aria-busy','true');
    const overlay=document.createElement('div');overlay.className='rp-operation-loading';overlay.setAttribute('role','status');overlay.setAttribute('aria-live','polite');
    const verifying=!toggle&&Boolean(data.get('token'));
    overlay.innerHTML='<span class="rp-operation-spinner" aria-hidden="true"></span><div><strong></strong><p></p></div>';
    overlay.querySelector('strong').textContent=verifying?'Verifying your bot…':data.get('action')==='test'?'Sending test message…':'Saving your settings…';
    overlay.querySelector('p').textContent=verifying?'Checking the bot identity and Telegram connection.':'Please wait for confirmation.';
    page().querySelector('[data-telegram-feedback]').hidden=true;page().querySelector('.rp-header').after(overlay);overlay.scrollIntoView({block:'nearest'});
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),35000);
    let state;
    try{
      const response=await fetch(form.getAttribute('action')||location.pathname,{method:'POST',body:data,credentials:'same-origin',headers:{Accept:'application/json'},signal:controller.signal});
      const result=await response.json().catch(()=>null);
      if(!response.ok||!result?.ok)throw Error(result?.error||(response.status===403?'Access is no longer available. Refresh to check your permissions.':'Could not confirm this action. Refresh to check its current status.'));
      state=result;feedback(result.message);
      if(!toggle&&!['test','notifications'].includes(data.get('action'))){const token=form.querySelector('[name="token"]');if(token){token.value='';token.placeholder=result.has_token?'Saved; leave blank to keep':'Paste a dedicated bot token';}}
    }catch(error){
      if(toggle)toggle.checked=!desired;
      feedback(error.name==='AbortError'?'The request timed out. Refresh to check its status before trying again.':error instanceof TypeError?'The panel could not be reached. Your change is not confirmed. Check the connection and reload before retrying.':error.message,true);
    }finally{
      clearTimeout(timer);overlay.remove();content.inert=false;page().removeAttribute('aria-busy');controls.forEach(([el,disabled])=>el.disabled=disabled);busy=false;
      if (state) {
        update(state);
        if (data.get('action') === 'disconnect') page().querySelector('[name="token"]').focus();
      }
    }
  }
  document.addEventListener('submit',event=>{
    const form=event.target;
    if(!form.closest('.rp-telegram-page'))return;
    event.preventDefault();
    const dialog = form.closest('dialog');
    if (dialog && dialog.open) dialog.close();
    save(form);
  });
  document.addEventListener('change',event=>{
    const toggle=event.target.closest('[data-save-toggle]');
    if(toggle)save(toggle.form,toggle);
  });
})();

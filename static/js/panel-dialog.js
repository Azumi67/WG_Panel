(() => {
  'use strict';
  let queue = Promise.resolve();
  function show({title='Please confirm',body='',okText='Continue',cancelText='Cancel',value,placeholder=''}) {
    return new Promise(resolve => {
      const opener=document.activeElement, dialog=document.createElement('dialog');
      dialog.className='panel-dialog';
      dialog.setAttribute('aria-labelledby','panel-dialog-title');
      dialog.setAttribute('aria-describedby','panel-dialog-body');
      dialog.innerHTML='<form method="dialog"><span class="panel-dialog-symbol" aria-hidden="true"><i class="fas fa-layer-group"></i></span><h2 id="panel-dialog-title"></h2><p id="panel-dialog-body"></p><label class="panel-dialog-field" hidden><span>Value</span><input autocomplete="off" maxlength="200"></label><footer><button type="button" value="cancel" class="btn secondary"></button><button value="ok" class="btn"></button></footer></form>';
      dialog.querySelector('h2').textContent=title;
      dialog.querySelector('p').textContent=body;
      const input=dialog.querySelector('input'),field=dialog.querySelector('label');
      if(value!==undefined){field.hidden=false;field.firstElementChild.textContent=title;input.value=value;input.placeholder=placeholder;}
      dialog.querySelector('[value=cancel]').textContent=cancelText;
      dialog.querySelector('[value=cancel]').onclick=()=>dialog.close('cancel');
      dialog.querySelector('[value=ok]').textContent=okText;
      dialog.addEventListener('close',()=>{const answer=dialog.returnValue==='ok'?(value===undefined?true:input.value.trim()):(value===undefined?false:null);dialog.remove();if(opener?.isConnected)opener.focus();resolve(answer);},{once:true});
      document.body.appendChild(dialog);dialog.showModal();
      (value===undefined?dialog.querySelector('[value=cancel]'):input).focus();
      if(value!==undefined)input.select();
    });
  }
  function enqueue(options){const task=queue.then(()=>show(options));queue=task.catch(()=>{});return task;}
  window.wgConfirm=options=>enqueue(typeof options==='string'?{body:options}:options);
  window.wgPrompt=(title,value='')=>enqueue({title,value,okText:'Save'});
})();

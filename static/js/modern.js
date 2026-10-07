(() => {
  'use strict';
  const root=document.documentElement;
  function choose(mode,reload=true){
    mode=mode==='legacy'?'legacy':'modern';
    root.dataset.design=mode;
    try{localStorage.setItem('wg-design',mode);}catch(_){}
    document.cookie=`wg-design=${mode}; Path=/; Max-Age=31536000; SameSite=Lax${location.protocol==='https:'?'; Secure':''}`;
    document.querySelectorAll('[data-design-choice]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.designChoice===mode)));
    if(reload&&document.body.dataset.page==='index'&&root.dataset.renderDesign!==mode){const url=new URL(location.href);url.searchParams.set('design',mode);location.assign(url.href);return;}
    window.dispatchEvent(new Event('wg-design-change'));
    window.dispatchEvent(new Event('resize'));
  }
  document.querySelectorAll('[data-design-choice]').forEach(b=>b.addEventListener('click',()=>choose(b.dataset.designChoice)));
  window.addEventListener('storage',e=>{if(e.key==='wg-design')choose(e.newValue);});
  choose(root.dataset.design||'modern');
  const dialog=document.getElementById('nx-command'), input=document.getElementById('nx-command-input'), results=document.getElementById('nx-command-results');
  if(dialog&&input&&results){
    const entries=[...document.querySelectorAll('.nx-nav a')].map(a=>({name:a.textContent.trim(),href:a.getAttribute('href')})).filter((a,i,all)=>all.findIndex(x=>x.href===a.href)===i);
    const render=()=>{results.replaceChildren();const q=input.value.toLowerCase().trim();entries.filter(e=>e.name.toLowerCase().includes(q)).forEach(e=>{const a=document.createElement('a');a.href=e.href;a.textContent=e.name;results.appendChild(a);});document.getElementById('nx-command-empty').hidden=!!results.children.length;};
    const open=()=>{render();dialog.showModal();input.focus();};
    document.querySelectorAll('[data-nx-search]').forEach(b=>b.addEventListener('click',open));
    input.addEventListener('input',render);input.addEventListener('keydown',e=>{if(e.key==='Enter'){const first=results.querySelector('a');if(first)first.click();}});
    document.querySelector('[data-nx-search-close]')?.addEventListener('click',()=>dialog.close());
    dialog.addEventListener('click',e=>{if(e.target===dialog){const r=dialog.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)dialog.close();}});
    document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'&&root.dataset.design==='modern'){e.preventDefault();dialog.open?dialog.close():open();}});
  }
  document.addEventListener('DOMContentLoaded',()=>{
    if(root.dataset.design==='modern'&&document.body.dataset.page==='settings_page'){const connection=document.getElementById('tg-acc-token');if(connection)connection.open=true;}
    if(document.body.dataset.page==='users'&&new URLSearchParams(location.search).get('create')==='1')setTimeout(()=>document.getElementById('create-peer-btn')?.click(),0);
  });
})();

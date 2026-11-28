(() => {
  'use strict';
  const original=window.fetch.bind(window);
  function getCookie(name) {
    try{const m=document.cookie.match(new RegExp('(?:^|; )'+name+'=([^;]*)'));return m?decodeURIComponent(m[1]):'';}catch(_){return '';}
  }
  window.fetch = (input, options) => {
    const init=options||{};
    const request=input instanceof Request?input:null;
    const target=new URL(request?request.url:input,window.location.href);
    if(target.origin!==window.location.origin)return original(input,init);
    const headers=new Headers(request?.headers);
    new Headers(init.headers).forEach((v,k)=>headers.set(k,v));
    const token=getCookie('csrf_token')||document.querySelector('meta[name="csrf-token"]')?.content||'';
    if(token&&!headers.has('X-CSRFToken')&&!headers.has('X-CSRF-Token')){
      headers.set('X-CSRFToken',token);headers.set('X-CSRF-Token',token);
    }
    const key=document.querySelector('meta[name="api-key"]')?.content||'';
    if(key&&!document.documentElement.hasAttribute('data-reseller-workspace')&&!headers.has('Authorization')&&!headers.has('X-API-KEY')){
      headers.set('Authorization',`Bearer ${key}`);headers.set('X-API-KEY',key);
    }
    return original(input,{...init,credentials:init.credentials??request?.credentials??'same-origin',headers});
  };
})();

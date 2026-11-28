(() => {
  'use strict';
  const original = window.fetch.bind(window);
  const pending = new Map();
  const sharedOptions = new Set(['method','headers','credentials','cache']);
  const interfacePath = /^\/(?:r\/shared\/)?api\/(?:get-interfaces|interfaces|nodes\/\d+\/interfaces)$/;
  function deadline(parent, ms) {
    const controller = new AbortController();
    const abort = () => controller.abort(parent.reason);
    if (parent?.aborted) abort();
    else parent?.addEventListener('abort', abort, {once:true});
    const timer = setTimeout(() => controller.abort(new DOMException('The server took too long to respond. Try again.', 'TimeoutError')), ms);
    const done = () => {clearTimeout(timer);parent?.removeEventListener('abort',abort);};
    controller.signal.addEventListener('abort',done,{once:true});
    return {signal:controller.signal,done};
  }
  function trackBody(response, done) {
    for (const name of ['json','text','blob','arrayBuffer','formData']) {
      const read = response[name].bind(response);
      response[name] = async (...args) => {try{return await read(...args);}finally{done();}};
    }
    const clone = response.clone.bind(response);
    response.clone = () => trackBody(clone(),done);
    if (!response.body) done();
    return response;
  }
  async function timedRead(input, init, url, request) {
      if (init.signal) return original(input,init);
    const d=deadline(request?.signal,/\/api\/nodes\//.test(url.pathname)?30000:15000);
    try{return trackBody(await original(input,{...init,signal:d.signal}),d.done);}
    catch(error){d.done();throw error;}
  }
  window.fetch = (input, init = {}) => {
    init=init||{};
    const request = input instanceof Request ? input : null;
    const url = new URL(request ? request.url : input, location.href);
    const method = String(init.method || request?.method || 'GET').toUpperCase();
    if (method !== 'GET' || url.origin !== location.origin || !/^\/(?:api\/|r\/(?:shared\/)?api\/)/.test(url.pathname)) return original(input, init);
    const share = !request && interfacePath.test(url.pathname) && Object.keys(init).every(k=>sharedOptions.has(k));
    if(!share)return timedRead(input,init,url,request);
    const key=JSON.stringify([url.href,init.credentials||'same-origin',init.cache||'default',[...new Headers(init.headers)]]);
    if(pending.has(key))return pending.get(key).then(r=>r.clone());
    const promise=timedRead(input,init,url,request);
    pending.set(key,promise);
    const release=()=>{if(pending.get(key)===promise)pending.delete(key);};
    promise.then(release,release);
    return promise.then(r=>r.clone());
  };
  async function buffered(fetcher, input, init, ms) {
    const d=deadline(init?.signal,ms);
    try {
      const response=await fetcher(input,{...init,signal:d.signal});
      const body=response.body ? await response.text() : null;
      return new Response(body,{status:response.status,statusText:response.statusText,headers:response.headers});
    } finally {d.done();}
  }
  window.WGRequests=Object.freeze({buffered});
})();

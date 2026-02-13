(function () {
  const origFetch = window.fetch.bind(window);

  function getCookie(name) {
    const m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
    return m ? decodeURIComponent(m[1]) : '';
  }
  function getApiKey() {
    return document.querySelector('meta[name="api-key"]')?.content || '';
  }

  window.fetch = function (input, init) {
    init = init || {};

    if (init.credentials == null) init.credentials = 'same-origin';

    const merged = new Headers();
    if (input instanceof Request && input.headers) {
      input.headers.forEach((v, k) => merged.set(k, v));
    }
    new Headers(init.headers || {}).forEach((v, k) => merged.set(k, v));

    const tok = getCookie('csrf_token');
    if (tok) {
      merged.set('X-CSRFToken', tok);
      merged.set('X-CSRF-Token', tok);
    }

    const key = getApiKey();
    if (key) {
      if (!merged.has('Authorization')) merged.set('Authorization', `Bearer ${key}`);
      if (!merged.has('X-API-KEY'))    merged.set('X-API-KEY', key);
    }

    init.headers = merged;
    return origFetch(input, init);
  };
})();

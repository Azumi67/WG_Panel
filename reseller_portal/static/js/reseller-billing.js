(() => {
  const proof = document.querySelector('.bill-proof-form');
  if (proof) {
    const choice = proof.querySelector('.bill-proof-choice');
    const file = proof.elements.photo;
    function selectMethod() {
      for (const field of proof.querySelectorAll('[data-proof-field]')) {
        const selected = proof.elements.proof_method.value === field.dataset.proofField;
        field.hidden = !selected;
        const input = field.querySelector('input');
        input.disabled = !selected;
        input.required = selected;
      }
    }
    choice.hidden = false;
    choice.addEventListener('change', selectMethod);
    selectMethod();
    file.addEventListener('change', () => {
      const picked = file.files[0];
      file.setCustomValidity(picked && picked.size > 5 * 1024 * 1024 ? 'Choose an image no larger than 5 MB.' : '');
      proof.querySelector('output').textContent = picked ? picked.name : '';
      if (!file.checkValidity()) file.reportValidity();
    });
  }
  for (const keep of document.querySelectorAll('[data-keep-order]')) {
    keep.hidden = false;
    keep.addEventListener('click', () => {
      const details = keep.closest('details');
      details.open = false;
      details.querySelector('summary').focus();
    });
  }
  async function postOrder(form, data) {
    const controller = new AbortController();
    const file = form.elements.photo;
    const uploading = file && !file.disabled && file.files.length > 0;
    const deadline = setTimeout(() => controller.abort(), uploading ? 120000 : 25000);
    try {
      const response = await fetch(form.action, {method:'POST', credentials:'same-origin',
        headers:{Accept:'application/json'}, body:data, signal:controller.signal});
      return {response, result:await response.json()};
    } finally {
      clearTimeout(deadline);
    }
  }
  function showStatusLink(form, status) {
    const link = document.createElement('a');
    link.href = form.closest('[data-order-url]')?.dataset.orderUrl || form.closest('[data-billing-url]').dataset.billingUrl;
    link.textContent = 'Check order status';
    status.replaceChildren('The panel hasn’t confirmed this change. ', link);
  }
  for (const form of document.querySelectorAll('form[data-order-action]')) {
    form.addEventListener('submit', async event => {
      event.preventDefault();
      if (form.dataset.submitting) return;
      form.dataset.submitting = 'true';
      const data = new FormData(form);
      const submit = form.querySelector('button[type=submit]');
      const status = form.querySelector('.bill-action-status');
      status.hidden = false;
      status.textContent = form.elements.photo?.files.length && !form.elements.photo.disabled ? 'Uploading receipt…' : 'Saving…';
      submit.disabled = true;
      try {
        for (let attempt = 0; attempt < 2; attempt++) {
          const {response, result} = await postOrder(form, data);
          if (response.ok && result.location) {
            location.assign(result.location);
            return;
          }
          if (attempt === 0 && response.status === 503 && result.code === 'write_not_started') {
            status.textContent = 'Waiting to save…';
            await new Promise(resolve => setTimeout(resolve, 1000));
            continue;
          }
          if ((response.status >= 500 && result.code !== 'write_not_started') || !result.error) {
            showStatusLink(form, status);
          } else {
            status.textContent = result.error;
          }
          break;
        }
      } catch {
        showStatusLink(form, status);
      } finally {
        delete form.dataset.submitting;
        submit.disabled = false;
      }
    });
  }
  const page = document.querySelector('[data-review-url]');
  if (!page) return;
  let timer;
  let checking = false;
  let stopped = false;
  function schedule() {
    clearTimeout(timer);
    if (!stopped && !document.hidden) timer = setTimeout(check, 15000);
  }
  async function check() {
    if (checking || stopped || document.hidden) return;
    checking = true;
    const controller = new AbortController();
    const deadline = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch(page.dataset.reviewUrl, {
        credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
        headers: {Accept: 'application/json'}
      });
      if (response.status === 401 || response.status === 403) stopped = true;
      if (response.ok) {
        const status = await response.json();
        if (status.order_state !== 'pending' || String(status.generation) !== page.dataset.generation) {
          stopped = true;
          location.replace(location.href);
        }
      }
    } catch {} finally {
      clearTimeout(deadline);
      checking = false;
      schedule();
    }
  }
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) clearTimeout(timer);
    else check();
  });
  schedule();
})();

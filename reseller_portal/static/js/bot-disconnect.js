document.addEventListener('click', event => {
  const open = event.target.closest('[data-disconnect-open]');
  if (open) {
    open.closest('[data-disconnect-area]').querySelector('dialog').showModal();
    return;
  }
  const cancel = event.target.closest('[data-disconnect-cancel]');
  if (cancel) cancel.closest('dialog').close();
});

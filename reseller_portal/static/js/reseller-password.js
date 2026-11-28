(() => {
  'use strict';
  const tell = (button, text) => {
    const status = button.closest('.rp-password-tools')?.querySelector('[data-password-status]');
    if (status) status.textContent = text;
  };
  document.querySelectorAll('[data-password-generate]').forEach(button => button.addEventListener('click', () => {
    const input = document.getElementById(button.dataset.passwordGenerate);
    if (!input) return;
    if (!globalThis.crypto?.getRandomValues) { tell(button, 'Secure generation requires HTTPS.'); return; }
    const length = Math.max(20, Math.min(64, input.minLength || 8));
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    input.value = Array.from(bytes, b => alphabet[b & 63]).join('');
    const confirm = document.getElementById(button.dataset.passwordConfirm || '');
    if (confirm) confirm.value = input.value;
    input.dispatchEvent(new Event('input', {bubbles:true}));
    tell(button, 'Generated. Copy and save it before continuing.');
  }));
  document.querySelectorAll('[data-password-copy]').forEach(button => button.addEventListener('click', async () => {
    const input = document.getElementById(button.dataset.passwordCopy);
    if (!input?.value) { tell(button, 'Enter or generate a password first.'); return; }
    try { await navigator.clipboard.writeText(input.value); tell(button, 'Password copied.'); }
    catch (_) { input.focus(); input.select(); tell(button, 'Copy the selected password using your keyboard.'); }
  }));
  document.querySelectorAll('[data-password-show]').forEach(button => button.addEventListener('click', () => {
    const input = document.getElementById(button.dataset.passwordShow);
    if (!input) return;
    input.type = input.type === 'password' ? 'text' : 'password';
    button.textContent = input.type === 'password' ? 'Show password' : 'Hide password';
  }));
  document.querySelectorAll('[data-auth-layout]').forEach(button => {
    button.setAttribute('aria-pressed',String(button.dataset.authLayout===document.documentElement.dataset.design));
    button.addEventListener('click',()=>{
      try { localStorage.setItem('wg-design',button.dataset.authLayout);localStorage.setItem('wg-auth-design','follow'); } catch (_) {}
      document.cookie=`wg-design=${button.dataset.authLayout}; Path=/; Max-Age=31536000; SameSite=Lax; Secure`;
      location.reload();
    });
  });
})();

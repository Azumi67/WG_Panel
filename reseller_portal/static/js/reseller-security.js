(() => {
  'use strict';
  const qr = document.getElementById('rp-totp-qr');
  if (qr) {
    try {
      if (window.QRCode) {
        new window.QRCode(qr, { text: qr.dataset.uri, width: 192, height: 192,
          correctLevel: window.QRCode.CorrectLevel.M });
      } else { qr.textContent = 'QR unavailable. Use the manual setup key.'; }
    } catch (_) { qr.textContent = 'QR unavailable. Use the manual setup key.'; }
  }
  const form = document.getElementById('rp-security-enrollment');
  if (!form) return;
  let submitted = false;
  form.addEventListener('submit', event => {
    if (submitted) { event.preventDefault(); return; }
    const submitter = event.submitter;
    const cancelling = !!submitter?.hasAttribute('data-security-cancel');
    if (cancelling && !form.elements.password.value) {
      event.preventDefault();
      form.elements.password.focus();
      form.elements.password.setCustomValidity('Enter your password to cancel enrollment.');
      form.elements.password.reportValidity();
      return;
    }
    submitted = true;
    form.querySelectorAll('button[type="submit"]').forEach(b => b.disabled = true);
  });
  form.elements.password.addEventListener('input', () => form.elements.password.setCustomValidity(''));
})();

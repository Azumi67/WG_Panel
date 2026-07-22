    window.toastSafe = (msg, type = 'info', ms = 2200) => {
        if (typeof window.toast === 'function') {
            try {
                const id = window.toast(msg, type, { timeout: ms });
                setTimeout(() => {
                    if (window.toast.dismiss) return window.toast.dismiss(id);
                    const el = document.querySelector('#toast-container .toast');
                    if (el) {
                        el.classList.add('hiding');
                        setTimeout(() => el.remove(), 220);
                    }
                }, ms + 80);
                return;
            } catch (_) { }
        }
        let host = document.getElementById('toast-container');
        if (!host) { host = document.createElement('div'); host.id = 'toast-container'; document.body.appendChild(host); }
        const t = document.createElement('div');
        t.className = `toast ${type}`;
        t.innerHTML = `
      <span class="toast-icon"><i class="fas fa-info-circle"></i></span>
      <span class="msg"></span>
      <button class="action" type="button" aria-label="Dismiss">OK</button>
      <div class="progress" style="--pct:1"></div>
    `;
        t.querySelector('.msg').textContent = msg;
        t.querySelector('.action').addEventListener('click', hide);
        host.appendChild(t);

        const start = performance.now();
        let raf;
        function tick(now) {
            const pct = Math.max(0, 1 - (now - start) / ms);
            t.style.setProperty('--pct', pct);
            if (pct > 0) raf = requestAnimationFrame(tick);
            else hide();
        }
        function hide() {
            cancelAnimationFrame(raf);
            t.classList.add('hiding');
            setTimeout(() => t.remove(), 200);
        }
        raf = requestAnimationFrame(tick);
    };

    (() => {
        const $ = (s, r = document) => r.querySelector(s);

        function ensureBackdrop(modal) {
            let bd = modal.querySelector('.modal-backdrop');
            if (!bd) { bd = document.createElement('div'); bd.className = 'modal-backdrop'; modal.prepend(bd); }
            return bd;
        }
        function openModal(modal) {
            if (!modal) return;
            ensureBackdrop(modal);
            modal.classList.add('open');
            document.body.classList.add('modal-open');
            const first = modal.querySelector('input, select, textarea, button:not(.modal-close)');
            if (first) first.focus({ preventScroll: true });
        }
        function closeModal(modal) {
            if (!modal) return;
            modal.classList.remove('open');
            document.body.classList.remove('modal-open');
        }

        const peerModal = $('#peer-modal');
        $('#create-peer-btn')?.addEventListener('click', () => openModal(peerModal));
        $('#modal-close')?.addEventListener('click', () => closeModal(peerModal));
        $('#create-cancel')?.addEventListener('click', () => closeModal(peerModal));
        
        const editModal = $('#edit-peer-modal');
        $('#edit-close')?.addEventListener('click', () => closeModal(editModal));
        $('#edit-cancel')?.addEventListener('click', () => closeModal(editModal));

        const bulkModal = $('#bulk-modal');
        $('#bulk-btn')?.addEventListener('click', () => openModal(bulkModal));
        $('#bulk-close')?.addEventListener('click', () => closeModal(bulkModal));
        $('#bulk-close-btn')?.addEventListener('click', () => closeModal(bulkModal));

        document.addEventListener('click', (e) => {
            const m = e.target.closest('.modal');
            if (!m) return;
            if (e.target.classList.contains('modal-backdrop')) closeModal(m);
        });

        document.addEventListener('keydown', (e) => {
            if (e.key !== 'Escape') return;
            const open = [...document.querySelectorAll('.modal.open')].pop();
            if (open) closeModal(open);
        });

        window.__ui = Object.assign(window.__ui || {}, { openModal, closeModal });
    })();

    (() => {
        const on = (el, evt, sel, fn) => el.addEventListener(evt, e => {
            const t = e.target.closest(sel);
            if (t) fn(e, t);
        });

        async function copy(text) {
            try { await navigator.clipboard.writeText(text); }
            catch {
                const ta = document.createElement('textarea');
                ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
            }
            toastSafe('Copied to clipboard', 'success', 1200);
        }

        on(document, 'click', '[data-copy], .copy-shortlink', (_e, el) => {
            const val = el.dataset.copy || el.getAttribute('data-url') || el.value || el.textContent;
            if (val) copy(val.trim());
        });

        document.addEventListener('DOMContentLoaded', () => {
        if (typeof window.toast === 'function') {
          window.toast('Peers page ready', 'info');
        } else if (typeof window.toastSafe === 'function') {
          window.toastSafe('Peers page ready', 'info', false);
        }
      });
    })();

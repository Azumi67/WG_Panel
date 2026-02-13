(function () {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

function getCSRF() {
    const m = document.cookie && document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : '';
  }
async function api(path, opts = {}) {
  const headers = { Accept: 'application/json' };
  if (opts.body) headers['Content-Type'] = 'application/json';
  const csrf = getCSRF(); if (csrf) headers['X-CSRFToken'] = csrf;
  const res = await fetch(path, {
    method: opts.method || 'GET',
    headers,
    credentials: 'same-origin',
    body: opts.body ? JSON.stringify(opts.body) : null
  });

  const ct = res.headers.get('content-type') || '';
  const tryJson = async () => (ct.includes('application/json') ? await res.json() : null);

  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const j = await tryJson();
      if (j?.message) msg = j.message;
      else if (j?.error) msg = j.error;
      else if (typeof j === 'string') msg = j;
    } catch {}
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return ct.includes('application/json') ? await res.json() : await res.text();
}

  function openModal(el) {
    if (!el) return;
    el.classList.add('open');
  }
  function closeModal(el) {
    if (!el) return;
    el.classList.remove('open');
  }

  const tblBody = $('#admins-table tbody');
  const emptyRow = $('#admins-empty');

  function renderAdmins(admins) {
    tblBody.innerHTML = '';
    if (!admins || admins.length === 0) {
      emptyRow.style.display = '';
      return;
    }
    emptyRow.style.display = 'none';
    admins.forEach(a => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${a.tg_id}</td>
        <td>${a.username ? ('@' + a.username.replace(/^@/, '')) : ''}</td>
        <td>${a.note || ''}</td>
        <td>${a.created_at || ''}</td>
        <td style="text-align:right">
          <button class="btn danger admin-del" data-id="${a.tg_id}">
            <i class="fas fa-trash"></i>
          </button>
        </td>`;
      tblBody.appendChild(tr);
    });
  }

  async function loadAdmins() {
    const { admins, has_token } = await api('/api/telegram/admins');
    renderAdmins(admins || []);
    const chip = $('#tg-bot-status');
    if (chip) {
      chip.textContent = has_token ? 'Bot token: present' : 'Bot token: missing';
      chip.className = 'chip ' + (has_token ? 'ok' : 'warn');
    }
  }

  async function loadSettings() {
    const { settings } = await api('/api/telegram/settings');
    $('#n-peer-created').checked   = !!settings.notify.peer_created;
    $('#n-peer-deleted').checked   = !!settings.notify.peer_deleted;
    $('#n-peer-blocked').checked   = !!settings.notify.peer_blocked;
    $('#n-peer-unblocked').checked = !!settings.notify.peer_unblocked;
    $('#n-peer-reset-data').checked  = !!settings.notify.peer_reset_data;
    $('#n-peer-reset-timer').checked = !!settings.notify.peer_reset_timer;
    $('#n-expiry-warning').checked = !!settings.notify.expiry_warning;
    $('#q-start').value = settings.quiet_hours.start || '';
    $('#q-end').value   = settings.quiet_hours.end || '';
    $('#lang').value    = settings.language || 'en';
  }

  async function saveSettings() {
    const payload = {
      notify: {
        peer_created:   $('#n-peer-created').checked,
        peer_deleted:   $('#n-peer-deleted').checked,
        peer_blocked:   $('#n-peer-blocked').checked,
        peer_unblocked: $('#n-peer-unblocked').checked,
        peer_reset_data:  $('#n-peer-reset-data').checked,
        peer_reset_timer: $('#n-peer-reset-timer').checked,
        expiry_warning:  $('#n-expiry-warning').checked
      },
      quiet_hours: {
        start: ($('#q-start').value || '').trim() || null,
        end:   ($('#q-end').value   || '').trim() || null
      },
      language: ($('#lang').value || 'en')
    };
    await api('/api/telegram/settings', { method: 'POST', body: payload });
    alert('Saved');
  }

  const modal = $('#admin-modal');
  function bindAddButton() {
    const btn = $('#btn-add-admin');
    if (!btn || !modal) return false;
    if (btn.dataset.bound === '1') return true;
    btn.addEventListener('click', () => {
      $('#admin-modal-title').textContent = 'Add Admin';
      $('#m-tg-id').value = '';
      $('#m-username').value = '';
      $('#m-note').value = '';
      openModal(modal);
    });
    btn.dataset.bound = '1';
    return true;
  }
  function bindModalControls() {
  $('#admin-modal-close')?.addEventListener('click', () => closeModal(modal));
  $('#admin-modal-cancel')?.addEventListener('click', () => closeModal(modal));
  const btnSave = $('#admin-modal-save');

  btnSave?.addEventListener('click', async () => {
    const tg_id = ($('#m-tg-id').value || '').trim();
    const username = ($('#m-username').value || '').trim().replace(/^@/, '');
    const note = ($('#m-note').value || '').trim();

    if (!/^\d+$/.test(tg_id)) { alert('Telegram ID must be numeric'); return; }

    const already = Array.from($('#admins-table tbody')?.querySelectorAll('tr td:first-child') || [])
      .some(td => td.textContent === tg_id);
    if (already) { alert('This Telegram ID is already in the admin list.'); return; }

    btnSave.disabled = true;
    const old = btnSave.innerHTML;
    btnSave.textContent = 'Saving…';

    try {
      await api('/api/telegram/admins', { method: 'POST', body: { tg_id, username, note } });
      closeModal(modal);
      await loadAdmins(); 
    } catch (e) {
      if (e.status === 409) {
        alert(e.message || 'Admin already exists (409).');
      } else {
        alert(e.message || 'Failed to save admin.');
      }
    } finally {
      btnSave.disabled = false;
      btnSave.innerHTML = old;
    }
  });
}

  tblBody?.addEventListener('click', async (e) => {
    const btn = e.target.closest('.admin-del');
    if (!btn) return;
    const tg_id = btn.dataset.id;
    if (!confirm(`Delete admin ${tg_id}?`)) return;
    await api('/api/telegram/admins', { method: 'DELETE', body: { tg_id } });
    await loadAdmins();
  });

  bindAddButton();
  bindModalControls();

  window.addEventListener('DOMContentLoaded', async () => {
    bindAddButton();
    bindModalControls();

    await loadAdmins();
    await loadSettings();

    $('#btn-save-settings')?.addEventListener('click', saveSettings);
  });
})();

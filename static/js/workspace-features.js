(() => {
  'use strict';
  const copy = async value => {
    if (navigator.clipboard && window.isSecureContext) {
      try { await navigator.clipboard.writeText(value); return true; } catch (_) {}
    }
    const field = document.createElement('textarea');
    field.value = value; field.style.position = 'fixed'; field.style.opacity = '0';
    document.body.append(field); field.select();
    try { return document.execCommand('copy'); } catch (_) { return false; } finally { field.remove(); }
  };
  document.addEventListener('DOMContentLoaded', () => {
    const key = document.getElementById('wg-new-key');
    const show = document.querySelector('[data-show-key]');
    if (key && show) show.addEventListener('click', () => {
      key.type = key.type === 'password' ? 'text' : 'password'; show.textContent = key.type === 'password' ? 'Show' : 'Hide';
    });
    document.querySelector('[data-copy-key]')?.addEventListener('click', async () => {
      const feedback = document.querySelector('[data-key-feedback]');
      if (key && feedback) feedback.textContent = await copy(key.value) ? 'Key copied.' : 'Copy failed. Show and select the key manually.';
    });
    document.querySelectorAll('[data-confirm-action]').forEach(button => button.addEventListener('click', event => {
      if (!window.confirm(button.dataset.confirmAction)) event.preventDefault();
    }));
    const root = document.querySelector('[data-operation-history]'); if (!root) return;
    if (root.hasAttribute('data-server-history')) {
      root.querySelectorAll('[data-copy-ref]').forEach(button => button.addEventListener('click',async()=>{button.textContent=await copy(button.dataset.copyRef)?'Copied':'Copy failed';}));
      return;
    }
    const rows = [...root.querySelectorAll('[data-op-row]')];
    const search = root.querySelector('[data-op-search]'), state = root.querySelector('[data-op-state]'), channel = root.querySelector('[data-op-channel]'), size = root.querySelector('[data-op-size]');
    const filters = [...root.querySelectorAll('[data-op-filter]')]; let page = 1, group = 'all';
    const groups = {all:null,active:['queued','running'],completed:['completed'],attention:['review','rejected']};
    const render = () => {
      const q = search.value.trim().toLowerCase(), n = Number(size.value) || 10;
      const match = rows.filter(row => (!groups[group] || groups[group].includes(row.dataset.state)) && (state.value === 'all' || state.value === row.dataset.state) && (channel.value === 'all' || channel.value === row.dataset.channel) && (!q || row.textContent.toLowerCase().includes(q)));
      const pages = Math.max(1, Math.ceil(match.length / n)); page = Math.min(pages, Math.max(1,page));
      const shown = new Set(match.slice((page-1)*n,page*n)); rows.forEach(row => row.hidden = !shown.has(row));
      root.querySelector('[data-op-empty]').hidden = match.length > 0;
      root.querySelector('[data-op-count]').textContent = `${match.length} matching`;
      root.querySelector('[data-op-page]').textContent = match.length ? `${(page-1)*n+1}–${Math.min(page*n,match.length)} of ${match.length} · Page ${page}/${pages}` : '0 results';
      root.querySelector('[data-op-prev]').disabled = page === 1; root.querySelector('[data-op-next]').disabled = page === pages;
    };
    filters.forEach(button => button.addEventListener('click', () => {group=button.dataset.opFilter; state.value='all'; page=1;filters.forEach(b=>b.setAttribute('aria-pressed',String(b===button)));render();}));
    search.addEventListener('input',()=>{page=1;render();});
    [channel,size].forEach(el=>el.addEventListener('change',()=>{page=1;render();}));
    state.addEventListener('change',()=>{group='all';filters.forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.opFilter==='all')));page=1;render();});
    root.querySelector('[data-op-prev]').addEventListener('click',()=>{page--;render();});root.querySelector('[data-op-next]').addEventListener('click',()=>{page++;render();});
    root.querySelectorAll('[data-copy-ref]').forEach(button => button.addEventListener('click',async()=>{button.textContent=await copy(button.dataset.copyRef)?'Copied':'Copy failed';}));
    render();
  });
})();

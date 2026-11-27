(() => {
  'use strict';
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-open-updates]').forEach(button => button.addEventListener('click', () => document.getElementById('sb2-update-open')?.click()));
    document.getElementById('studio-calm-preset')?.addEventListener('click', () => {
      const modal = document.getElementById('sub-settings-modal');
      const values = {'portal-animation-choice':'off','sub-entrance-animation':'none','sub-hover-animation':'none','sub-surface':'solid','sub-density':'comfortable','sub-theme-default':'auto'};
      Object.entries(values).forEach(([name,value])=>{const field=modal.querySelector(`[name="${name}"][value="${value}"]`);if(field){field.checked=true;field.dispatchEvent(new Event('change',{bubbles:true}));}});
      const animation=modal.querySelector('#portal-animation');if(animation){animation.value='off';animation.dispatchEvent(new Event('change',{bubbles:true}));}
    });
    const groups = document.querySelector('.tg-accordion');
    document.querySelectorAll('.ws-tg-tabs button').forEach(button => button.addEventListener('click', () => {
      if (!groups) return;
      groups.dataset.tgView = button.dataset.tgView;
      const url = new URL(location.href); url.searchParams.set('sub',button.dataset.tgView); history.replaceState(null,'',url);
      document.querySelectorAll('.ws-tg-tabs button').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
      const detail = document.getElementById(button.dataset.tgView === 'notifications' ? 'tg-acc-notify' : 'tg-acc-token');
      if (detail) detail.open = true;
    }));
    const sub = new URLSearchParams(location.search).get('sub');
    if (sub === 'notifications') document.querySelector('.ws-tg-tabs button[data-tg-view="notifications"]')?.click();
    const token = document.getElementById('tg-acc-token');
    if (token && document.documentElement.dataset.design === 'modern') token.open = true;
  });
})();

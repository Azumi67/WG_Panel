(() => {
  'use strict';


  const OPEN = new Set();

  const keyOf = (card) => String(card?.dataset?.id || '');

  function sectionOf(card) {
    return card?.querySelector('.peer-more-section') || null;
  }

  function toggleOf(card) {
    return card?.querySelector('.more-toggle') || null;
  }

  function setOpen(card, open) {
    if (!card) return;

    const key = keyOf(card);
    const section = sectionOf(card);
    const toggle = toggleOf(card);
    if (!section || !toggle) return;

    if (open) {
      section.hidden = false;
      section.removeAttribute('hidden');
      section.style.setProperty('display', 'block', 'important');
      section.style.setProperty('visibility', 'visible', 'important');
      section.style.setProperty('opacity', '1', 'important');
      section.style.setProperty('max-height', 'none', 'important');
      section.style.setProperty('height', 'auto', 'important');
      section.style.setProperty('overflow', 'visible', 'important');
      card.classList.add('peer-more-open');
      toggle.setAttribute('aria-expanded', 'true');
      if (key) OPEN.add(key);
    } else {
      section.hidden = true;
      section.setAttribute('hidden', '');
      section.style.setProperty('display', 'none', 'important');
      section.style.removeProperty('visibility');
      section.style.removeProperty('opacity');
      section.style.removeProperty('max-height');
      section.style.removeProperty('height');
      section.style.removeProperty('overflow');
      card.classList.remove('peer-more-open');
      toggle.setAttribute('aria-expanded', 'false');
      if (key) OPEN.delete(key);
    }
  }

  function closeOthers(exceptCard) {
    document.querySelectorAll('.peer-card.peer-more-open').forEach(card => {
      if (card !== exceptCard) setOpen(card, false);
    });
  }

  document.addEventListener('click', (event) => {
    const moreBtn = event.target.closest('.more-toggle');
    if (moreBtn) {
      const card = moreBtn.closest('.peer-card');
      if (!card) return;

      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();

      const section = sectionOf(card);
      const currentlyOpen = !!section && !section.hidden &&
        getComputedStyle(section).display !== 'none';

      if (!currentlyOpen) closeOthers(card);
      setOpen(card, !currentlyOpen);
      return;
    }

    const closeBtn = event.target.closest('.more-close');
    if (closeBtn) {
      const card = closeBtn.closest('.peer-card');
      if (!card) return;

      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      setOpen(card, false);
    }
  }, true);

  let scheduled = false;
  const sync = () => {
    scheduled = false;
    document.querySelectorAll('.peer-card').forEach(card => {
      const key = keyOf(card);
      if (!key) return;
      setOpen(card, OPEN.has(key));
    });
  };

  const observer = new MutationObserver(() => {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(sync);
  });

  const start = () => {
    const container = document.querySelector('.peers-container');
    if (!container) {
      requestAnimationFrame(start);
      return;
    }
    observer.observe(container, { childList: true, subtree: true });
    sync();
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start, { once: true });
  } else {
    start();
  }
})();

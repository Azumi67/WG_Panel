(() => {
  const sidebar = document.querySelector('.sidebar.sb2');
  const body = sidebar?.querySelector('.sb2-body');
  if (!body) return;

  const hint = document.createElement('button');
  hint.type = 'button';
  hint.className = 'sb2-overflow-hint';
  hint.hidden = true;
  body.querySelector('.sb2-bottom')?.before(hint);

  const navs = [...body.querySelectorAll('nav[aria-label="Primary"]')];
  const active = () => navs.find(nav => nav.getClientRects().length && nav.clientHeight);
  const selected = nav => nav?.querySelector('a[aria-current="page"], a.active');
  const mobile = matchMedia('(max-width: 760px)');
  const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
  let frame = 0;
  let lastSelected = null;

  function update() {
    const nav = active();
    if (!nav) {
      hint.hidden = true;
      return;
    }
    const down = nav.scrollHeight - nav.clientHeight - nav.scrollTop > 3;
    const up = nav.scrollTop > 3;
    hint.hidden = !down && !up;
    hint.textContent = down ? 'More menu items ↓' : 'Back to top ↑';
    hint.setAttribute('aria-label', down ? 'Scroll to more navigation items' : 'Scroll navigation to the top');
    hint.dataset.direction = down ? 'down' : 'up';
  }

  function reveal() {
    frame = 0;
    const nav = active();
    const link = selected(nav);
    lastSelected = link;
    if (!link || (mobile.matches && !document.body.classList.contains('wg-mobile-menu-open'))) return;
    for (let parent = link.parentElement; parent && parent !== nav; parent = parent.parentElement) {
      if (parent.tagName === 'DETAILS' && !parent.open) parent.open = true;
    }
    update();
    const bounds = nav.getBoundingClientRect();
    const target = link.getBoundingClientRect();
    const top = bounds.top + nav.clientTop;
    const bottom = top + nav.clientHeight;
    const padding = 4;
    if (target.top < top + padding) {
      nav.scrollTop += target.top - top - padding;
    } else if (target.bottom > bottom - padding) {
      nav.scrollTop += target.bottom - bottom + padding;
    }
    update();
  }

  function scheduleReveal() {
    if (!frame) frame = requestAnimationFrame(reveal);
  }

  hint.onclick = () => {
    const nav = active();
    if (nav) nav.scrollTo({top: hint.dataset.direction === 'down' ? nav.scrollTop + nav.clientHeight * .8 : 0, behavior: reducedMotion.matches ? 'instant' : 'smooth'});
  };

  const observer = new ResizeObserver(update);
  observer.observe(body);
  const selectionObserver = new MutationObserver(() => {
    if (selected(active()) !== lastSelected) scheduleReveal();
  });
  navs.forEach(nav => {
    observer.observe(nav);
    nav.addEventListener('scroll', update, {passive: true});
    selectionObserver.observe(nav, {subtree: true, attributes: true, attributeFilter: ['class', 'aria-current']});
  });
  new MutationObserver(scheduleReveal).observe(document.documentElement, {attributes: true, attributeFilter: ['data-design', 'data-workspace-density']});
  let opened = document.body.classList.contains('wg-mobile-menu-open');
  new MutationObserver(() => {
    const nowOpen = document.body.classList.contains('wg-mobile-menu-open');
    if (nowOpen && !opened) scheduleReveal();
    opened = nowOpen;
  }).observe(document.body, {attributes: true, attributeFilter: ['class']});
  window.addEventListener('resize', scheduleReveal, {passive: true});
  window.addEventListener('pageshow', scheduleReveal);
  update();
  scheduleReveal();
})();

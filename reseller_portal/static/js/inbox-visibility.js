(() => {
  'use strict';
  window.observeInbox = function (menu, acknowledge) {
    const visible = new Set();
    const pending = new WeakSet();
    let timer;
    async function flush() {
      if (menu.hidden || document.hidden) return;
      const rows = Array.from(visible).filter(row => row.isConnected && menu.contains(row) && !pending.has(row));
      if (!rows.length) return;
      rows.forEach(row => pending.add(row));
      try {
        await acknowledge(rows);
        rows.forEach(row => { observer.unobserve(row); visible.delete(row); });
      } catch (_) {
        rows.forEach(row => pending.delete(row));
        clearTimeout(timer);
        timer = setTimeout(flush, 4000);
      }
    }
    const observer = new IntersectionObserver(entries => {
      for (const entry of entries) {
        if (entry.isIntersecting && entry.intersectionRect.height >= Math.min(14, entry.boundingClientRect.height)) {
          visible.add(entry.target);
        } else visible.delete(entry.target);
      }
      clearTimeout(timer);
      timer = setTimeout(flush, 220);
    }, {threshold: [0, .01, .2, .5, 1]});
    document.addEventListener('visibilitychange', flush);
    return function (rows) {
      observer.disconnect();
      visible.clear();
      rows.forEach(row => observer.observe(row));
    };
  };
})();

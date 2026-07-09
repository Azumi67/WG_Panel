document.addEventListener('alpine:init', () => {
  Alpine.data('apiDocsPage', () => ({
    query: '',
    allOpen: false,
    noResults: false,
    baseCopied: false,
    sideObserver: null,
    toastTimer: null,

    init() {
      this.$nextTick(() => {
        this.filter();
        this.setupActiveSectionObserver();
        this.ensureCopyToast();
      });
    },

    normalizedQuery() {
      return (this.query || '').toLowerCase().trim();
    },

    filter() {
      const term = this.normalizedQuery();
      const rows = Array.from(this.$root.querySelectorAll('.route-row'));
      const indexRows = Array.from(this.$root.querySelectorAll('.route-index tbody tr'));
      const sections = Array.from(this.$root.querySelectorAll('.doc-section'));
      let visibleRows = 0;

      rows.forEach(row => {
        const ok = !term || (row.dataset.text || '').toLowerCase().includes(term);
        row.classList.toggle('hidden-by-search', !ok);
        if (ok) visibleRows += 1;
      });

      indexRows.forEach(row => {
        const ok = !term || (row.dataset.text || '').toLowerCase().includes(term);
        row.classList.toggle('hidden-by-search', !ok);
      });

      sections.forEach(section => {
        const visibleInside = Array.from(section.querySelectorAll('.route-row, tbody tr'))
          .some(item => !item.classList.contains('hidden-by-search'));
        section.classList.toggle('hidden-by-search', Boolean(term && !visibleInside));
      });

      this.noResults = Boolean(term && visibleRows === 0);
    },

    handleClick(event) {
      const copyButton = event.target.closest('[data-copy]');
      if (copyButton && this.$root.contains(copyButton)) {
        event.preventDefault();
        event.stopPropagation();
        this.copyCommand(copyButton);
        return;
      }

      const mainButton = event.target.closest('.route-main');
      if (mainButton && this.$root.contains(mainButton)) {
        this.toggleRoute(mainButton);
      }
    },

    toggleRoute(button) {
      const row = button.closest('.route-row');
      if (!row) return;
      const willOpen = !row.classList.contains('open');
      row.classList.toggle('open', willOpen);
      button.setAttribute('aria-expanded', String(willOpen));
    },

    toggleExamples() {
      this.allOpen = !this.allOpen;
      const rows = Array.from(this.$root.querySelectorAll('.route-row'));
      rows.forEach(row => {
        if (!row.classList.contains('hidden-by-search')) {
          row.classList.toggle('open', this.allOpen);
          const button = row.querySelector('.route-main');
          if (button) button.setAttribute('aria-expanded', String(this.allOpen));
        }
      });
      this.showCopyToast(this.allOpen ? 'Examples opened' : 'Examples closed', this.allOpen ? 'fa-layer-group' : 'fa-compress');
    },

    decodeText(text) {
      const box = document.createElement('textarea');
      box.innerHTML = text || '';
      return box.value;
    },

    async copyText(text) {
      const decoded = this.decodeText(text);
      if (!decoded) return false;
      try {
        await navigator.clipboard.writeText(decoded);
        return true;
      } catch (_) {
        const ta = document.createElement('textarea');
        ta.value = decoded;
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        ta.style.top = '0';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        let ok = false;
        try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
        ta.remove();
        return ok;
      }
    },

    async copyCommand(button) {
      const oldHTML = button.dataset.originalHtml || button.innerHTML;
      button.dataset.originalHtml = oldHTML;
      const ok = await this.copyText(button.dataset.copy || '');
      if (!ok) {
        this.showCopyToast('Copy failed', 'fa-triangle-exclamation');
        return;
      }

      const card = button.closest('.command-card');
      const row = button.closest('.route-row');
      button.classList.add('copied');
      if (card) card.classList.add('copied');
      if (row) row.classList.add('just-copied');
      button.innerHTML = '<i class="fa-solid fa-check"></i> Copied';
      this.showCopyToast('Command copied', 'fa-check');

      clearTimeout(button._copyTimer);
      button._copyTimer = setTimeout(() => {
        button.classList.remove('copied');
        if (card) card.classList.remove('copied');
        if (row) row.classList.remove('just-copied');
        button.innerHTML = oldHTML;
      }, 1300);
    },

    async copyBase() {
      const text = 'curl -H "Authorization: Bearer <PANEL_API_KEY>" "https://panel.example.com/api/healthz"';
      const ok = await this.copyText(text);
      if (!ok) {
        this.showCopyToast('Copy failed', 'fa-triangle-exclamation');
        return;
      }
      this.baseCopied = true;
      this.showCopyToast('Base command copied', 'fa-check');
      setTimeout(() => { this.baseCopied = false; }, 1100);
    },

    ensureCopyToast() {
      if (document.querySelector('.api-copy-toast')) return;
      const toast = document.createElement('div');
      toast.className = 'api-copy-toast';
      toast.innerHTML = '<i class="fa-solid fa-check"></i><span>Copied</span>';
      document.body.appendChild(toast);
    },

    showCopyToast(message, icon = 'fa-check') {
      this.ensureCopyToast();
      const toast = document.querySelector('.api-copy-toast');
      if (!toast) return;
      toast.innerHTML = `<i class="fa-solid ${icon}"></i><span>${message}</span>`;
      toast.classList.add('show');
      clearTimeout(this.toastTimer);
      this.toastTimer = setTimeout(() => toast.classList.remove('show'), 1400);
    },

    setupActiveSectionObserver() {
      const sections = Array.from(this.$root.querySelectorAll('.doc-section'));
      const sideLinks = Array.from(this.$root.querySelectorAll('#apiSide a'));
      if (!sections.length || !sideLinks.length || !('IntersectionObserver' in window)) return;

      if (this.sideObserver) this.sideObserver.disconnect();
      this.sideObserver = new IntersectionObserver((items) => {
        items.forEach(item => {
          if (!item.isIntersecting) return;
          sideLinks.forEach(link => {
            link.classList.toggle('active', link.getAttribute('href') === `#${item.target.id}`);
          });
        });
      }, { rootMargin: '-25% 0px -65% 0px', threshold: 0 });

      sections.forEach(section => this.sideObserver.observe(section));
    }
  }));
});

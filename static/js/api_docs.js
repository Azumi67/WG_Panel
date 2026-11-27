document.addEventListener('DOMContentLoaded', () => {
  const page = ({
    query: '',
    selectedGroup: '',
    allOpen: false,
    noResults: false,
    baseCopied: false,
    sideObserver: null,
    toastTimer: null,

    init() {
      this.$nextTick(() => {
        this.$root.querySelectorAll('#apiSide a').forEach(link=>{
          const section=document.getElementById(link.hash.slice(1));
          const count=section?.querySelectorAll('.route-row,tbody tr').length;
          if(count && link.querySelector('b'))link.querySelector('b').textContent=count;
        });
        this.selectGroup(location.hash, false);
        this.filter();
        this.setupActiveSectionObserver();
        this.ensureCopyToast();
        this.bindThemeRefresh();
      });
    },


    bindThemeRefresh() {
      window.addEventListener('wg-theme-change', () => {
        requestAnimationFrame(() => this.setupActiveSectionObserver());
      });
    },

    normalizedQuery() {
      return (this.query || '').toLowerCase().trim();
    },

    filter() {
      const term = this.normalizedQuery();
      this.$root.classList.toggle('is-searching', Boolean(term));
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
        section.classList.toggle('hidden-by-group', !term && section.id !== this.selectedGroup);
      });

      this.noResults = Boolean(term && visibleRows === 0 && !indexRows.some(row => !row.classList.contains('hidden-by-search')));
      this.syncExamples();
    },

    selectGroup(hash, clearSearch = true) {
      const sections = [...this.$root.querySelectorAll('.doc-section')];
      const id = (hash || '').slice(1);
      const target = document.getElementById(id);
      this.selectedGroup = target?.closest('.doc-section')?.id || sections.find(s=>s.id==='sec-custom-bot-api')?.id || sections[0]?.id || '';
      if (clearSearch) { this.query=''; const search=document.getElementById('apiSearch'); if(search)search.value=''; }
      this.$root.querySelectorAll('#apiSide a').forEach(link=>{
        const active=link.hash==='#'+this.selectedGroup;
        link.classList.toggle('active',active);
        if(active)link.setAttribute('aria-current','page');else link.removeAttribute('aria-current');
      });
      this.filter();
      const no=document.getElementById('noResults');if(no)no.hidden=!this.noResults;
    },

    handleClick(event) {
      const lang=event.target.closest('[data-example-language]');
      if(lang){
        const card=lang.closest('.wg-multilang');
        const example=card?.querySelector('template[data-example-code="'+lang.dataset.exampleLanguage+'"]');
        if(example){card.querySelector('pre code').textContent=example.content.textContent;card.querySelectorAll('[data-example-language]').forEach(b=>b.setAttribute('aria-pressed',String(b===lang)));}
        return;
      }
      const jump=event.target.closest('a[href^="#"]');
      if(jump && this.$root.classList.contains('api-docs') && document.getElementById(jump.hash.slice(1))?.closest('.doc-section')){
        this.selectGroup(jump.hash);
      }

      const copyButton = event.target.closest('[data-copy], [data-copy-visible]');
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
      this.syncExamples();
    },

    visibleExamples() {
      return Array.from(this.$root.querySelectorAll('.doc-section:not(.hidden-by-group):not(.hidden-by-search) .route-row:not(.hidden-by-search)'))
        .filter(row => row.querySelector('.route-detail'));
    },

    syncExamples() {
      const rows = this.visibleExamples();
      const control = document.getElementById('expandExamples');
      this.allOpen = rows.length > 0 && rows.every(row => row.classList.contains('open'));
      control.disabled = rows.length === 0;
      control.setAttribute('aria-expanded', String(this.allOpen));
      control.querySelector('span').textContent = this.allOpen ? 'Close examples' : 'Open examples';
    },

    toggleExamples() {
      const open = !this.allOpen;
      this.visibleExamples().forEach(row => {
        row.classList.toggle('open', open);
        row.querySelector('.route-main')?.setAttribute('aria-expanded', String(open));
      });
      this.syncExamples();
    },

    async copyText(text) {
      const decoded = text;
      if (!decoded) return false;
      try {
        await navigator.clipboard.writeText(decoded);
        return true;
      } catch (_) {
        const previousFocus = document.activeElement;
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
        previousFocus?.focus({preventScroll:true});
        return ok;
      }
    },

    async copyCommand(button) {
      const oldHTML = button.dataset.originalHtml || button.innerHTML;
      button.dataset.originalHtml = oldHTML;
      const command = button.hasAttribute('data-copy-visible')
        ? button.closest('.command-card')?.querySelector('pre code')?.textContent
        : button.dataset.copy;
      const ok = await this.copyText(command);
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
      this.showCopyToast('One health-check example copied. Nothing was executed.', 'fa-check');
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
      if(document.documentElement.dataset.design==='modern' && window.toast) return window.toast(message,icon==='fa-triangle-exclamation'?'error':'success');
      this.ensureCopyToast();
      const toast = document.querySelector('.api-copy-toast');
      if (!toast) return;
      toast.innerHTML = `<i class="fa-solid ${icon}"></i><span>${message}</span>`;
      toast.classList.add('show');
      clearTimeout(this.toastTimer);
      this.toastTimer = setTimeout(() => toast.classList.remove('show'), 1400);
    },

    setupActiveSectionObserver() {
      return;
    }

  });
  page.$root = document.querySelector('.api-docs, [data-api-examples]');
  if(!page.$root) return;
  page.$nextTick = callback => callback();
  page.$root.addEventListener('click', event => page.handleClick(event));
  if (page.$root.hasAttribute('data-api-examples')) return;
  document.getElementById('apiSearch').addEventListener('input', event => {page.query = event.target.value; page.filter(); document.getElementById('noResults').hidden = !page.noResults;});
  document.getElementById('expandExamples').addEventListener('click', () => page.toggleExamples());
  document.getElementById('copyBase').addEventListener('click', () => page.copyBase());
  document.getElementById('noResults').hidden = true;
  window.addEventListener('hashchange',()=>page.selectGroup(location.hash));
  page.init();
});

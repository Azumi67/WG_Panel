(() => {
    const sel = document.getElementById('peer-scope');
    const cur = document.getElementById('scope-current');
    const trigger = document.getElementById('peer-scope-trigger');
    const triggerLabel = document.getElementById('peer-scope-trigger-label');
    const menu = document.getElementById('peer-scope-menu');

    let resolveReady;
    window.peerScopeReady = new Promise(resolve => { resolveReady = resolve; });

    if (!sel || !cur || !trigger || !triggerLabel || !menu) {
        resolveReady?.();
        return;
    }

    const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));

    function updateCurrent() {
        const text = sel.options[sel.selectedIndex]?.textContent?.trim() || 'Local (this server)';
        triggerLabel.textContent = text;
        cur.textContent = sel.value ? `Node · ${text}` : 'Local server';
    }

    function closeMenu() {
        menu.hidden = true;
        trigger.setAttribute('aria-expanded', 'false');
    }

    function openMenu() {
        menu.hidden = false;
        trigger.setAttribute('aria-expanded', 'true');
    }

    function buildMenu() {
        menu.innerHTML = [...sel.options].map(opt => {
            const active = String(opt.value) === String(sel.value);
            return `
                <button type="button"
                        class="peer-scope-option ${active ? 'is-active' : ''}"
                        data-value="${esc(opt.value)}">
                    <span class="peer-scope-option-main">
                        <i class="fas fa-server" aria-hidden="true"></i>
                        <span class="peer-scope-option-label">${esc(opt.textContent)}</span>
                    </span>
                    ${active ? '<i class="fas fa-check peer-scope-check" aria-hidden="true"></i>' : ''}
                </button>
            `;
        }).join('');
    }

    async function populate() {
        try {
            const r = await fetch('/api/nodes', {
                credentials: 'same-origin',
                cache: 'no-store'
            });

            if (r.ok) {
                const payload = await r.json();
                const nodes = Array.isArray(payload) ? payload : (payload.nodes || []);

                for (const n of nodes) {
                    if ([...sel.options].some(o => String(o.value) === String(n.id))) continue;

                    const opt = document.createElement('option');
                    opt.value = n.id;
                    opt.textContent = n.name || `Node ${n.id}`;
                    sel.appendChild(opt);
                }
            }
        } catch (_) {}

        try {
            const saved = localStorage.getItem('peer_scope') || '';
            if ([...sel.options].some(o => o.value === saved)) sel.value = saved;
        } catch (_) {}

        buildMenu();
        updateCurrent();
        resolveReady?.();
        document.dispatchEvent(new CustomEvent('peer-scope-ready'));
    }

    trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        if (menu.hidden) openMenu();
        else closeMenu();
    });

    menu.addEventListener('click', (e) => {
        const btn = e.target.closest('.peer-scope-option');
        if (!btn) return;

        const value = btn.dataset.value || '';
        if (sel.value === value) {
            closeMenu();
            return;
        }

        sel.value = value;
        try { localStorage.setItem('peer_scope', sel.value); } catch (_) {}

        buildMenu();
        updateCurrent();
        closeMenu();

        sel.dispatchEvent(new Event('change', { bubbles: true }));
    });

    document.addEventListener('click', (e) => {
        if (!menu.hidden && !document.getElementById('scope-row')?.contains(e.target)) {
            closeMenu();
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeMenu();
    });

    populate();
})();

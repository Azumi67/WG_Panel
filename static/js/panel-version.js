(function () {
    const endpoint = '/api/panel/version';

    function $(id) { return document.getElementById(id); }

    function cleanVersion(v) {
        if (!v) return '—';
        const s = String(v).trim();
        return s.toLowerCase().startsWith('v') ? s : `v${s}`;
    }

    function setState(el, state) {
        if (!el) return;
        el.classList.remove('is-current', 'has-update', 'has-error', 'is-checking');
        el.classList.add(state);
    }

    function applyVersion(data) {
        const sidebar = $('sb2-version');
        const sidebarState = $('sb2-version-state');
        const dashCard = $('panel-version-card');
        const dashStatus = $('panel-version-status');
        const current = $('panel-version-current');
        const latest = $('panel-version-latest');
        const note = $('panel-version-note');
        const release = $('panel-version-release');

        const currentRaw = data.current_version || data.current || sidebar?.dataset.currentVersion || dashCard?.dataset.currentVersion;
        const latestRaw = data.latest_version || data.latest;
        const currentVersion = cleanVersion(currentRaw);
        const latestVersion = cleanVersion(latestRaw);
        const latestUrl = data.latest_url || data.repo_url || 'https://github.com/Azumi67/WG_Panel/releases';

        if ($('sb2-version-current')) $('sb2-version-current').textContent = currentVersion;
        if (current) current.textContent = currentVersion;
        if (latest) latest.textContent = latestVersion;
        if (release) release.href = latestUrl;
        if (sidebar) sidebar.href = latestUrl;

        if (data.error) {
            if (sidebarState) sidebarState.textContent = 'error';
            if (dashStatus) dashStatus.textContent = 'Error';
            if (note) note.textContent = `Could not check GitHub: ${data.error}`;
            setState(sidebar, 'has-error');
            setState(dashCard, 'has-error');
            return;
        }

        if (data.update_available) {
            if (sidebarState) sidebarState.textContent = 'update';
            if (dashStatus) dashStatus.textContent = 'Update available';
            if (note) note.textContent = `A newer version is available on GitHub: ${latestVersion}.`;
            setState(sidebar, 'has-update');
            setState(dashCard, 'has-update');
        } else {
            if (sidebarState) sidebarState.textContent = 'current';
            if (dashStatus) dashStatus.textContent = 'Up to date';
            if (note) note.textContent = latestRaw
                ? `You are running the latest known version: ${currentVersion}.`
                : 'Version shown. No release/tag was found on GitHub.';
            setState(sidebar, 'is-current');
            setState(dashCard, 'is-current');
        }
    }

    async function loadVersion(refresh) {
        const sidebar = $('sb2-version');
        const dashCard = $('panel-version-card');
        const sidebarState = $('sb2-version-state');
        const dashStatus = $('panel-version-status');
        const note = $('panel-version-note');
        const btn = $('panel-version-refresh');

        setState(sidebar, 'is-checking');
        setState(dashCard, 'is-checking');
        if (sidebarState) sidebarState.textContent = 'checking';
        if (dashStatus) dashStatus.textContent = 'Checking';
        if (note) note.textContent = 'Checking GitHub for updates…';
        if (btn) btn.disabled = true;

        try {
            const url = refresh ? `${endpoint}?refresh=1` : endpoint;
            const r = await fetch(url, { credentials: 'same-origin' });
            const data = await r.json().catch(() => ({}));
            if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
            applyVersion(data);
        } catch (err) {
            applyVersion({
                current_version: sidebar?.dataset.currentVersion || dashCard?.dataset.currentVersion || '',
                error: err && err.message ? err.message : 'Unknown error'
            });
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        const btn = $('panel-version-refresh');
        if (btn) btn.addEventListener('click', function () { loadVersion(true); });
        if ($('sb2-version') || $('panel-version-card')) loadVersion(false);
    });
})();

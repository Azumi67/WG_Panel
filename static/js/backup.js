(() => {
  const $ = (s, p = document) => p.querySelector(s);
  const $$ = (s, p = document) => Array.from(p.querySelectorAll(s));

  const csrfHeaders = (json = false) => {
    const h = typeof window.csrfHeaders === "function" ? window.csrfHeaders(json) : {};
    if (json) h["Content-Type"] = "application/json";

    const apiKey = document.querySelector('meta[name="api-key"]')?.content?.trim();
    if (apiKey && !h["Authorization"]) {
      h["Authorization"] = `Bearer ${apiKey}`;
      h["X-API-KEY"] = apiKey;
    }
    return h;
  };

  function fallbackToast(msg, type = "info") {
    const cls = type === "success" ? "ok" : type === "error" ? "err" : type;
    let stack = document.querySelector(".bk-toast-stack");
    if (!stack) {
      stack = document.createElement("div");
      stack.className = "bk-toast-stack";
      document.body.appendChild(stack);
    }
    const t = document.createElement("div");
    t.className = `bk-toast ${cls}`;
    t.textContent = String(msg || "");
    stack.appendChild(t);
    setTimeout(() => {
      t.style.opacity = "0";
      t.style.transform = "translateY(-6px)";
      setTimeout(() => t.remove(), 220);
    }, 3200);
  }

  const toast = {
    success: (m) => window.toastSuccess ? window.toastSuccess(m) : fallbackToast(m, "success"),
    info: (m) => window.toastInfo ? window.toastInfo(m) : fallbackToast(m, "info"),
    warn: (m) => window.toastWarn ? window.toastWarn(m) : fallbackToast(m, "warn"),
    error: (m) => window.toastError ? window.toastError(m) : fallbackToast(m, "error"),
  };

  const pillStatus = $("#status-pill");
  const pillNext = $("#next-run-pill") || $("#next-pill");
  const pillFull = $("#full-last");
  const pillDb = $("#db-last");
  const pillSettings = $("#settings-last");
  const pillAuto = $("#schedule-state") || $("#auto-state");

  const btnFull = $("#btn-full");
  const btnDb = $("#btn-db");
  const btnSettings = $("#btn-settings");
  const optWG = $("#include-wg") || $("#opt-wg");
  const optTG = $("#send-telegram") || $("#opt-tg");
  const livePreview = $("#live-preview-grid") || $("#backup-live-preview");
  const livePreviewWrap = $("#live-backup-preview") || $("#backup-live-preview");
  const livePreviewSubtitle = $("#live-preview-subtitle");

  const autoEnabled = $("#schedule-enabled") || $("#auto-enabled");
  const selFreq = $("#freq");
  const inpTime = $("#time");
  const selTz = $("#tz") || $("#timezone");
  const tzDisplay = $("#tz-display");
  const inpKeep = $("#keep");
  const autoWG = $("#schedule-include-wg") || $("#auto-wg");
  const autoTG = $("#schedule-send-telegram") || $("#auto-tg");
  const btnSave = $("#save-schedule") || $("#save");
  const btnSaveRun = $("#save-run-schedule");
  const autoFilesList = $("#auto-files-list");
  const autoFilesCount = $("#auto-files-count");
  const autoRunLoader = $("#auto-run-loader");
  const autoRunLoaderTitle = $("#auto-run-loader-title");
  const autoRunLoaderText = $("#auto-run-loader-text");
  const autoTelegramWrap = $("#auto-telegram-target-wrap");
  const autoTelegramAdmin = $("#auto-telegram-admin");
  const autoTelegramHelp = $("#auto-telegram-help");
  const autoInspectBox = $("#auto-inspect-box");
  const autoInspectGrid = $("#auto-inspect-grid");
  const autoInspectSubtitle = $("#auto-inspect-subtitle");
  const autoInspectFiles = $("#auto-inspect-files");
  const autoInspectModal = $("#auto-inspect-modal");
  if(autoInspectModal)document.body.appendChild(autoInspectModal);
  const autoInspectModalSubtitle = $("#auto-inspect-modal-subtitle");
  const autoInspectModalGrid = $("#auto-inspect-modal-grid");
  const autoInspectModalFiles = $("#auto-inspect-modal-files");
  const autoInspectDownload = $("#auto-inspect-download");

  const restoreDialog = $("#restore-confirm");
  if (restoreDialog) document.body.appendChild(restoreDialog);
  const restoreFile = $("#restore-file");
  const restoreBtn = $("#btn-restore");
  const restoreTrigger = $("#restore-file-trigger");
  const restoreName = $("#restore-file-name");
  const restoreHint = $("#restore-file-hint");
  const restoreWGBox = $("#restore-wg");
  const restorePreviewGrid = $("#restore-preview-grid");
  const restorePreviewSubtitle = $("#restore-preview-subtitle");
  const restoreNodeList = $("#restore-node-list");
  const restoreFileList = $("#restore-file-list");
  const restoreResult = $("#restore-result");

  const serverModeInputs = $$('input[name="server-settings-mode"]');
  const serverPill = $("#server-settings-pill");
  const savedServerBox = $("#saved-server-settings");
  const savedServerGrid = $("#saved-server-settings-grid");
  const customServerBox = $("#custom-server-settings");

  const nodeState = $("#node-restore-state");
  const nodeLines = $("#node-status-lines");
  const nodeGuideToggle = $("#node-guide-toggle");
  const nodeCommandBox = $("#node-command-box");
  const nodeInstallCommand = $("#node-install-command");
  const copyNodeCommand = $("#copy-node-command");

  let lastSchedule = null;
  let lastInspect = null;
  let cachedInstallCommand = "";
  const autoInspectCache = new Map();
  let activeAutoInspectFilename = "";

  const safe = (s) => String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

  function setBusy(btn, busy, text) {
    if (!btn) return;
    if (busy) {
      btn.dataset.oldHtml = btn.innerHTML;
      btn.disabled = true;
      btn.classList.add("is-loading");
      if (text) btn.innerHTML = `<i class="fas fa-circle-notch"></i> ${safe(text)}`;
    } else {
      btn.disabled = false;
      btn.classList.remove("is-loading");
      if (btn.dataset.oldHtml) btn.innerHTML = btn.dataset.oldHtml;
    }
  }

  function setRunStep(name, state = "") {
    const el = $(`#auto-run-step-${name}`);
    if (!el) return;
    el.classList.remove("active", "done");
    if (state) el.classList.add(state);
    const icon = el.querySelector("i");
    if (icon && state === "done") {
      icon.className = "fas fa-check-circle";
    }
  }

  function showRunLoader(title, text) {
    ["save", "build", "telegram", "refresh"].forEach((name) => setRunStep(name, ""));
    if (autoRunLoaderTitle) autoRunLoaderTitle.textContent = title || "Creating complete backup";
    if (autoRunLoaderText) autoRunLoaderText.textContent = text || "Please keep this page open.";
    if (autoRunLoader) autoRunLoader.hidden = false;
  }

  function updateRunLoader(title, text) {
    if (title && autoRunLoaderTitle) autoRunLoaderTitle.textContent = title;
    if (text && autoRunLoaderText) autoRunLoaderText.textContent = text;
  }

  function hideRunLoader() {
    if (autoRunLoader) autoRunLoader.hidden = true;
  }

  function schedTZ() {
    return selTz && selTz.value ? selTz.value : "UTC";
  }

  function autoTelegramEnabled() {
    return !!autoTG?.checked;
  }

  function setAutoTelegramEnabled(enabled) {
    if (autoTG) autoTG.checked = !!enabled;
    updateTelegramTargetVisibility();
  }

  function fmtISO(iso, withSeconds = false) {
    if (!iso) return "—";
    try {
      const d = new Date(iso);
      return d.toLocaleString("en-GB", {
        hour12: false,
        timeZone: schedTZ(),
        day: "2-digit", month: "short", year: "numeric",
        hour: "2-digit", minute: "2-digit",
        ...(withSeconds ? { second: "2-digit" } : {}),
      }) + ` (${schedTZ()})`;
    } catch { return iso; }
  }

  function fmtEpoch(ts) {
    if (!ts) return "—";
    try { return fmtISO(new Date(ts * 1000).toISOString(), true).replace(",", " ·"); }
    catch { return String(ts); }
  }

  function autoSize(bytes) {
    if (!bytes || bytes <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let i = 0, val = Number(bytes);
    while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
    return `${val.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  }

  function setLast(pill, iso) {
    if (!pill) return;
    if (iso) {
      pill.textContent = "Last: " + fmtISO(iso, false);
      pill.className = pill.id === "full-last" ? "bk-pill ok" : "bk-subline";
    } else {
      pill.textContent = "Last: No backup";
      pill.className = pill.id === "full-last" ? "bk-pill muted" : "bk-subline";
    }
  }

  function setNext(iso) {
    if (!pillNext) return;
    pillNext.textContent = "Next: " + (iso ? fmtISO(iso, false) : "—");
  }

  function updateStatus() {
    if (!pillStatus) return;
    const any = [pillFull, pillDb, pillSettings].some((p) => p && !p.textContent.includes("No backup"));
    pillStatus.textContent = any ? "Status: Ready" : "Status: No backup";
    pillStatus.className = "bk-pill " + (any ? "ok" : "muted");
  }

  function card(label, value, sub, state = "ok", icon = "fa-check") {
    return `<div class="bk-content-card ${state}">
      <div class="label">${safe(label)}</div>
      <div class="value"><i class="fas ${icon}"></i><span>${safe(value)}</span></div>
      <div class="sub">${safe(sub || "")}</div>
    </div>`;
  }

  function getSavedServerSettings(j) {
    const manifest = j?.manifest || {};
    const app = manifest.app || j?.app || {};
    const runtime = manifest.runtime || j?.runtime || {};
    const panel = manifest.panel_settings || j?.panel_settings || {};
    const metaApp = j?.app_meta || j?.meta_app || {};
    return {
      port: runtime.port || runtime.bind?.split(":").pop() || panel.http_port || app.port || "—",
      bind: runtime.bind || (runtime.port ? `0.0.0.0:${runtime.port}` : "—"),
      domain: panel.domain || app.domain || "—",
      tls: panel.tls_enabled === true ? "Enabled" : panel.tls_enabled === false ? "Disabled" : "—",
      http_port: panel.http_port || "—",
      https_port: panel.https_port || "—",
      wg_path: app.wg_conf_path || metaApp.wg_conf_path || "—",
    };
  }

  function renderServerSettings(j) {
    const s = getSavedServerSettings(j || {});
    if (savedServerGrid) {
      savedServerGrid.innerHTML = [
        ["Port", s.port], ["Bind", s.bind], ["Domain/IP", s.domain], ["TLS", s.tls],
        ["HTTP", s.http_port], ["HTTPS", s.https_port], ["WG path", s.wg_path],
      ].map(([k, v]) => `<div class="bk-kv"><div class="k">${safe(k)}</div><div class="v" title="${safe(v)}">${safe(v)}</div></div>`).join("");
    }
  }

  function currentServerMode() {
    return ($('input[name="server-settings-mode"]:checked')?.value || "keep");
  }

  function updateServerModeUI() {
    const mode = currentServerMode();
    if (savedServerBox) {
      savedServerBox.hidden = mode !== "saved";
      savedServerBox.style.display = mode === "saved" ? "grid" : "none";
    }
    if (customServerBox) {
      customServerBox.hidden = mode !== "custom";
      customServerBox.style.display = mode === "custom" ? "grid" : "none";
    }
    if (serverPill) {
      serverPill.textContent = mode === "keep" ? "Protected" : mode === "saved" ? "Saved settings" : "Custom";
      serverPill.className = "bk-pill " + (mode === "keep" ? "ok" : mode === "saved" ? "warn" : "muted");
    }
  }
  serverModeInputs.forEach((i) => i.addEventListener("change", updateServerModeUI));
  updateServerModeUI();

  function renderInspect(j, target = "restore") {
    const counts = j.counts || {};
    const contains = j.contains || {};
    const nodeResults = j.node_wg_backup || j.manifest?.node_wg_backup || [];
    const hasNode = !!(j.has_node_wg || contains.remote_node_wireguard_conf || counts.node_wg_files);
    const hasLocal = !!(j.has_wg || contains.local_wireguard_conf || counts.local_wg_files);
    const hasPanelEnv = !!(j.has_env || contains.env_file);
    const hasNodeEnv = !!(j.has_node_env || contains.remote_node_env || counts.node_env_files);
    const nodeEnvNodes = counts.node_env_nodes || Object.keys(j.node_env_nodes || {}).length || 0;
    const html = [
      card("Archive integrity", j.integrity === "sha256-checked" ? "SHA-256 checked" : j.integrity === "legacy-crc-checked" ? "Legacy ZIP checked" : "Not verified", "Checksums detect corruption, not authenticity", j.integrity ? "ok" : "warn", "fa-shield-halved"),
      card("Backup type", (j.kind || "unknown").toUpperCase(), j.created ? `Created ${j.created}` : "Detected from ZIP", j.kind === "unknown" ? "warn" : "ok", "fa-file-zipper"),
      card("Database", j.has_db || contains.database ? "Included" : "Missing", `${counts.db_files || 0} DB file(s)`, j.has_db || contains.database ? "ok" : "bad", "fa-database"),
      card("Settings", j.has_settings || contains.settings ? "Included" : "Missing", `${counts.instance_files || 0} setting file(s)`, j.has_settings || contains.settings ? "ok" : "warn", "fa-sliders"),
      card("Panel .env", hasPanelEnv ? "Included" : "Missing", hasPanelEnv ? "Panel secrets/migration key included" : "FERNET/API secrets not detected", hasPanelEnv ? "ok" : "warn", "fa-key"),
      card("WireGuard", hasLocal ? "Local configs" : "No local configs", `${counts.local_wg_files || 0} local file(s)`, hasLocal ? "ok" : "warn", "fa-network-wired"),
      card("Node configs", hasNode ? "Node configs" : "No node configs", `${counts.node_wg_files || 0} file(s) · ${counts.node_wg_nodes || 0} node(s)`, hasNode ? "ok" : "warn", "fa-server"),
      card("Node .env", hasNodeEnv ? "Included" : "Missing", `${counts.node_env_files || 0} env file(s) · ${nodeEnvNodes} node(s)`, hasNodeEnv ? "ok" : "warn", "fa-shield-halved"),
      card("Short links", contains.short_links ? "Included" : "Not detected", "Public user links/settings", contains.short_links ? "ok" : "warn", "fa-link"),
    ].join("");

    const grid = target === "backup"
      ? livePreview
      : target === "restore"
        ? restorePreviewGrid
        : null;
    if (grid) {
      grid.classList.remove("empty", "direct-notice");
      grid.style.display = "";
      grid.style.gridTemplateColumns = "";
      grid.style.width = "";
      grid.innerHTML = html;
    }
    if (target === "backup" && livePreviewSubtitle) {
      const label = j.kind && j.kind !== "unknown" ? `${j.kind.toUpperCase()} backup inspected` : "Backup inspected";
      livePreviewSubtitle.textContent = `${label}${j.created ? ` · Created ${j.created}` : ""}`;
    }
    if (target === "backup" && livePreviewWrap) livePreviewWrap.classList.add("has-content");

    if (target === "restore" && restorePreviewSubtitle) {
      restorePreviewSubtitle.textContent = `Detected ${j.kind || "backup"}. Review contents before restore.`;
    }

    if (target === "restore") { renderServerSettings(j); updateRestoreScope(); }

    const files = [
      ...(j.has_env ? ["env/.env"] : []),
      ...(j.local_wg_files || []).map((f) => `wg/${f}`),
      ...(j.node_wg_files || []).map((x) => x.path || `nodes/${x.node_id}/wg/${x.file}`),
      ...(j.node_env_files || []).map((x) => x.path || `nodes/${x.node_id}/env/.env`),
    ];
    if (target === "restore" && restoreFileList) {
      restoreFileList.innerHTML = files.length ? files.map((f) => `<span><i class="fas fa-file-code"></i>${safe(f)}</span>`).join("") : '<span><i class="fas fa-circle-info"></i>No WG config files detected</span>';
    }

    if (target === "restore") renderNodeStatus(j, nodeResults);
  }

  function renderNodeStatus(j, results) {
    const nodes = j.node_wg_nodes || {};
    const nodeEnvNodes = j.node_env_nodes || {};
    const nodeCount = Object.keys(nodes).length;
    const nodeEnvCount = Object.keys(nodeEnvNodes).length;
    const files = j.counts?.node_wg_files || 0;
    const envFiles = j.counts?.node_env_files || 0;
    const totalNodeCount = Math.max(nodeCount, nodeEnvCount);
    if (nodeState) {
      nodeState.textContent = totalNodeCount ? `${totalNodeCount} node(s)` : "No node data";
      nodeState.className = "bk-pill " + (totalNodeCount ? "ok" : "muted");
    }
    if (!nodeLines) return;
    const lines = [];
    if (!nodeCount) {
      lines.push(`<div class="bk-node-line warn"><i class="fas fa-circle-info"></i><span>No node WireGuard configs were found in this backup.</span></div>`);
    } else {
      lines.push(`<div class="bk-node-line ok"><i class="fas fa-check-circle"></i><span>Backup contains ${files} node WireGuard config file(s) for ${nodeCount} node(s).</span></div>`);
    }
    if (!nodeEnvCount) {
      lines.push(`<div class="bk-node-line warn"><i class="fas fa-key"></i><span>No node .env files were found. Update node_agent.py on each node if you need full migration secrets.</span></div>`);
    } else {
      lines.push(`<div class="bk-node-line ok"><i class="fas fa-shield-halved"></i><span>Backup contains ${envFiles} node .env file(s) for ${nodeEnvCount} node(s).</span></div>`);
    }
    if (Array.isArray(results) && results.length) {
      const failed = results.filter((r) => !r.ok);
      const ok = results.filter((r) => r.ok);
      if (ok.length) lines.push(`<div class="bk-node-line ok"><i class="fas fa-cloud-arrow-down"></i><span>${ok.length} node backup request(s) succeeded.</span></div>`);
      if (failed.length) lines.push(`<div class="bk-node-line bad"><i class="fas fa-triangle-exclamation"></i><span>${failed.length} node backup request(s) failed. Use the install command if the agent is missing.</span></div>`);
    }
    nodeLines.innerHTML = lines.join("");
  }

  async function blobLooksLikeZip(blob) {
    if (!blob || !Number.isFinite(blob.size) || blob.size < 4) return false;
    try {
      const head = new Uint8Array(await blob.slice(0, 4).arrayBuffer());
      return head[0] === 0x50 && head[1] === 0x4b && (
        (head[2] === 0x03 && head[3] === 0x04) ||
        (head[2] === 0x05 && head[3] === 0x06) ||
        (head[2] === 0x07 && head[3] === 0x08)
      );
    } catch {
      return false;
    }
  }

  async function inspectBlob(blob, filename, target = "restore") {
    if (!(await blobLooksLikeZip(blob))) {
      throw new Error("This file is not a readable ZIP. Choose a backup created by this panel, not an HTML/error download.");
    }

    const fd = new FormData();
    fd.append("file", blob, filename || "backup.zip");
    const headers = csrfHeaders();
    delete headers["Content-Type"];
    const r = await fetch("/api/backup/inspect", { method: "POST", headers, body: fd, credentials: "same-origin" });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) throw new Error(j.message || "Could not inspect backup.");
    if (target === "restore") lastInspect = j;
    renderInspect(j, target);
    return j;
  }

  async function inspectSelectedBackup(file) {
    if (!file) return;
    try {
      await inspectBlob(file, file.name, "restore");
    } catch (e) {
      console.error(e);
      lastInspect = null;
      renderInspect({ ok: false, kind: "invalid", contains: {}, counts: {}, local_wg_files: [], node_wg_files: [], node_env_files: [] }, "restore");
      if (restorePreviewSubtitle) restorePreviewSubtitle.textContent = e.message || "Could not inspect backup.";
      if (restoreHint) restoreHint.textContent = "Choose a valid backup ZIP created from this panel.";
      toast.error(e.message || "Could not inspect this backup.");
    }
  }

  async function savePrefs() {
    try {
      await fetch("/api/backup/prefs", {
        method: "POST", headers: csrfHeaders(true),
        body: JSON.stringify({ include_wg: !!optWG?.checked, send_to_telegram: !!optTG?.checked }),
      });
    } catch {}
  }

  function filenameFromResponse(resp, fallback) {
    const cd = resp.headers.get("content-disposition") || "";
    const m = cd.match(/filename\*?=(?:UTF-8''|\")?([^";]+)/i);
    return m ? decodeURIComponent(m[1].replaceAll('"', '').trim()) : fallback;
  }

  async function responsePreviewText(resp, blob) {
    try {
      const txt = await blob.text();
      const clean = txt.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
      if (clean) return clean.slice(0, 240);
    } catch {}
    try {
      return `HTTP ${resp.status || "?"} ${resp.statusText || ""}`.trim();
    } catch {
      return "The server returned a non-ZIP response.";
    }
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename || "backup.zip";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  }

  function backupEndpoint(kind) {
    return {
      full: `/api/backup/full?wg=${optWG?.checked ? "1" : "0"}&tg=${optTG?.checked ? "1" : "0"}`,
      db: "/api/backup/db",
      settings: "/api/backup/settings",
    }[kind];
  }

  function appendQuery(url, key, value) {
    const sep = url.includes("?") ? "&" : "?";
    return `${url}${sep}${encodeURIComponent(key)}=${encodeURIComponent(value)}`;
  }

  function withCacheBuster(url) {
    return appendQuery(url, "_download", Date.now());
  }


  function isIDMIntercept(resp, preview = "") {
    const text = `${resp?.status || ""} ${resp?.statusText || ""} ${preview || ""}`.toLowerCase();
    return text.includes("idm") || text.includes("internet download manager") || text.includes("advanced integration") || text.includes("intercepted by");
  }

  function directBrowserDownload(url, filename) {
    const a = document.createElement("a");
    const target = new URL(url, location.origin);
    if (target.pathname === '/api/backup/full') {
      target.searchParams.set('tg', '0');
      target.searchParams.set('auto', '0');
    }
    a.href = withCacheBuster(target.pathname + target.search);
    a.download = filename || "backup.zip";
    a.rel = "noopener";
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  function showDirectDownloadNotice(kind) {
    const label = kind === "full" ? "Full" : kind === "db" ? "Database" : "Settings";
    if (livePreviewSubtitle) {
      livePreviewSubtitle.textContent = "Download started in the browser. To inspect it, select the saved ZIP file below.";
    }
    if (livePreview) {
      livePreview.classList.remove("empty");
      livePreview.classList.add("direct-notice");
      livePreview.style.display = "block";
      livePreview.style.gridTemplateColumns = "1fr";
      livePreview.style.width = "100%";

      livePreview.innerHTML = `
        <div class="bk-idm-notice" style="width:100%;box-sizing:border-box;display:flex;align-items:flex-start;gap:12px;padding:13px 14px;border:1px solid #f59e0b55;background:#fffbeb;border-radius:14px;color:#111827;min-width:0;">
          <div style="width:38px;height:38px;border-radius:12px;background:#111827;color:#fff;display:grid;place-items:center;flex:0 0 38px;">
            <i class="fas fa-download"></i><span class="bk-action-label">Download</span>
          </div>
          <div style="min-width:0;flex:1 1 auto;">
            <div style="font-weight:950;font-size:13.5px;line-height:1.25;white-space:normal;overflow-wrap:normal;word-break:normal;">${safe(label)} backup download started</div>
            <div style="margin-top:4px;color:#64748b;font-size:12.5px;line-height:1.45;white-space:normal;overflow-wrap:normal;word-break:normal;">IDM intercepted the background ZIP check. A direct download was started without repeating Telegram delivery or scheduled storage.</div>
            <button type="button" class="bk-btn" id="bk-direct-pick" style="margin-top:10px;display:inline-flex;align-items:center;gap:7px;white-space:nowrap;">
              <i class="fas fa-file-zipper"></i> Inspect saved ZIP
            </button>
          </div>
        </div>`;
      $("#bk-direct-pick")?.addEventListener("click", () => restoreFile?.click());
    }
    toast.info(`${label} backup download started. If IDM opens, let it save the ZIP file.`);
  }

  async function downloadBackup(kind, button) {
    await savePrefs();
    const endpoint = backupEndpoint(kind);
    setBusy(button, true, kind === "full" ? "Creating" : "Preparing");
    try {
      const resp = await fetch(endpoint, {
        headers: { ...csrfHeaders(), "Accept": "application/zip, application/octet-stream, */*" },
        credentials: "same-origin",
        cache: "no-store",
      });
      const blob = await resp.blob();
      if (!resp.ok) {
        let msg = "";
        try {
          const errText = await blob.text();
          const errJson = JSON.parse(errText);
          msg = errJson.message || errJson.error || "";
        } catch {}
        throw new Error(msg || `Backup failed (${resp.status})`);
      }
      const filename = filenameFromResponse(resp, `wgpanel_${kind}_backup.zip`);
      if (!(await blobLooksLikeZip(blob))) {
        const preview = await responsePreviewText(resp, blob);
        if (isIDMIntercept(resp, preview)) {
          directBrowserDownload(endpoint, filename);
          showDirectDownloadNotice(kind);
          setTimeout(loadAll, 1200);
          return;
        }
        throw new Error(`The backup route returned a page/message instead of a ZIP. ${preview ? "Response: " + preview : ""}`);
      }
      if (livePreviewSubtitle) livePreviewSubtitle.textContent = "Inspecting downloaded ZIP…";
      try {
        await inspectBlob(blob, filename, "backup");
      } catch (e) {
        console.debug("inspect after download failed", e);
        if (livePreviewSubtitle) livePreviewSubtitle.textContent = e.message || "Downloaded, but the ZIP could not be inspected.";
        if (livePreview) {
          livePreview.innerHTML = card("Inspection", "Not available", "Download completed, but contents could not be read by the inspect API.", "warn", "fa-triangle-exclamation");
        }
      }
      downloadBlob(blob, filename);
      toast.success(`${kind === "full" ? "Full" : kind === "db" ? "Database" : "Settings"} backup downloaded.`);
      setTimeout(loadAll, 1200);
    } catch (e) {
      console.error(e);
      toast.error(e.message || "Backup failed.");
    } finally {
      setBusy(button, false);
    }
  }

  function updateTelegramTargetVisibility() {
    const enabled = !!autoTG?.checked;
    if (autoTelegramWrap) autoTelegramWrap.hidden = !enabled;
  }

  async function loadTelegramAdmins(selectedId = "") {
    if (!autoTelegramAdmin) return;

    autoTelegramAdmin.disabled = true;
    autoTelegramAdmin.classList.remove("is-error", "is-ready");
    autoTelegramAdmin.innerHTML =
      '<option value="">Loading active Telegram admins…</option>';

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);

    try {
      const response = await fetch("/api/telegram/admins", {
        headers: csrfHeaders(),
        credentials: "same-origin",
        cache: "no-store",
        signal: controller.signal,
      });

      const payload = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(
          payload.message ||
          payload.error ||
          (
            response.status === 401 || response.status === 403
              ? "Telegram admin access was denied. Allow logged-in panel users to read /api/telegram/admins."
              : `Could not load Telegram admins (HTTP ${response.status}).`
          )
        );
      }

      const rawAdmins = Array.isArray(payload)
        ? payload
        : Array.isArray(payload.admins)
          ? payload.admins
          : [];

      const admins = rawAdmins.filter((admin) => {
        const id = String(
          admin.id ??
          admin.tg_id ??
          admin.chat_id ??
          ""
        ).trim();

        return id && !Boolean(admin.muted);
      });

      if (!admins.length) {
        autoTelegramAdmin.innerHTML =
          '<option value="">No active Telegram admins</option>';
        autoTelegramAdmin.disabled = true;
        autoTelegramAdmin.classList.add("is-error");

        if (autoTelegramHelp) {
          autoTelegramHelp.textContent =
            "No active recipient was found. Add or unmute an admin in Settings → Telegram.";
        }
        return;
      }

      autoTelegramAdmin.innerHTML = admins.map((admin) => {
        const id = String(
          admin.id ??
          admin.tg_id ??
          admin.chat_id ??
          ""
        ).trim();

        const username = String(
          admin.username ??
          admin.user ??
          ""
        ).replace(/^@/, "").trim();

        const note = String(
          admin.note ??
          admin.name ??
          ""
        ).trim();

        const label = [
          username ? `@${username}` : "",
          id,
          note ? `— ${note}` : "",
        ].filter(Boolean).join(" ");

        return `<option value="${safe(id)}">${safe(label)}</option>`;
      }).join("");

      autoTelegramAdmin.disabled = false;
      autoTelegramAdmin.classList.add("is-ready");

      const wanted = String(selectedId || "").trim();

      if (
        wanted &&
        admins.some((admin) => String(
          admin.id ??
          admin.tg_id ??
          admin.chat_id ??
          ""
        ).trim() === wanted)
      ) {
        autoTelegramAdmin.value = wanted;
      }

      if (autoTelegramHelp) {
        autoTelegramHelp.textContent =
          "Each new automatic backup will be sent once to this active Telegram admin.";
      }
    } catch (error) {
      console.error("Telegram admin loading failed:", error);

      const message =
        error?.name === "AbortError"
          ? "Telegram admin request timed out."
          : (
              error.message ||
              "Could not load Telegram admins."
            );

      autoTelegramAdmin.innerHTML =
        `<option value="">${safe(message)}</option>`;
      autoTelegramAdmin.disabled = true;
      autoTelegramAdmin.classList.add("is-error");

      if (autoTelegramHelp) {
        autoTelegramHelp.textContent =
          `${message} Check the panel Telegram admin API.`;
      }

      toast.error(message);
    } finally {
      clearTimeout(timer);
    }
  }


  let autoInspectPreviousFocus=null;
  let autoInspectGeneration=0;
  autoInspectModal?.addEventListener("keydown",event=>{
    if(event.key==="Escape"){event.preventDefault();closeAutoInspectModal();}
    if(event.key==="Tab"){const items=[...autoInspectModal.querySelectorAll("button:not([disabled]),a[href]")].filter(e=>e.offsetParent!==null);const first=items[0],last=items.at(-1);if(event.shiftKey&&document.activeElement===first){event.preventDefault();last?.focus();}else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first?.focus();}}
  });
  function closeAutoInspectModal() {
    autoInspectGeneration++;
    if (autoInspectModal) {
      autoInspectModal.hidden = true;
    }
    activeAutoInspectFilename = "";
    autoInspectPreviousFocus?.focus();
  }

  function renderAutoInspectModal(result, filename) {
    const counts = result?.counts || {};
    const contains = result?.contains || {};

    const hasLocal = !!(
      result?.has_wg ||
      contains.local_wireguard_conf ||
      counts.local_wg_files
    );

    const hasNode = !!(
      result?.has_node_wg ||
      contains.remote_node_wireguard_conf ||
      counts.node_wg_files
    );

    const hasPanelEnv = !!(
      result?.has_env ||
      contains.env_file
    );

    const hasNodeEnv = !!(
      result?.has_node_env ||
      contains.remote_node_env ||
      counts.node_env_files
    );

    activeAutoInspectFilename = filename;

    if (autoInspectModalSubtitle) {
      autoInspectModalSubtitle.textContent =
        `${filename}${result?.created ? ` · Created ${result.created}` : ""}`;
    }

    if (autoInspectModalGrid) {
      autoInspectModalGrid.innerHTML = [
        card(
          "Backup type",
          String(result?.kind || "unknown").toUpperCase(),
          "Detected from saved ZIP",
          result?.kind === "unknown" ? "warn" : "ok",
          "fa-file-zipper"
        ),
        card(
          "Database",
          result?.has_db || contains.database ? "Included" : "Missing",
          `${counts.db_files || 0} file(s)`,
          result?.has_db || contains.database ? "ok" : "bad",
          "fa-database"
        ),
        card(
          "Settings",
          result?.has_settings || contains.settings ? "Included" : "Missing",
          `${counts.instance_files || 0} file(s)`,
          result?.has_settings || contains.settings ? "ok" : "warn",
          "fa-sliders"
        ),
        card(
          "Panel .env",
          hasPanelEnv ? "Included" : "Missing",
          "Panel migration secrets",
          hasPanelEnv ? "ok" : "warn",
          "fa-key"
        ),
        card(
          "Local WG",
          hasLocal ? "Included" : "Missing",
          `${counts.local_wg_files || 0} file(s)`,
          hasLocal ? "ok" : "warn",
          "fa-network-wired"
        ),
        card(
          "Node WG",
          hasNode ? "Included" : "Missing",
          `${counts.node_wg_files || 0} file(s)`,
          hasNode ? "ok" : "warn",
          "fa-server"
        ),
        card(
          "Node .env",
          hasNodeEnv ? "Included" : "Missing",
          `${counts.node_env_files || 0} file(s)`,
          hasNodeEnv ? "ok" : "warn",
          "fa-shield-halved"
        ),
      ].join("");
    }

    const files = [
      ...(result?.has_env ? ["env/.env"] : []),
      ...(result?.local_wg_files || []).map((name) => `wg/${name}`),
      ...(result?.node_wg_files || []).map(
        (item) => item.path || `nodes/${item.node_id}/wg/${item.file}`
      ),
      ...(result?.node_env_files || []).map(
        (item) => item.path || `nodes/${item.node_id}/env/.env`
      ),
    ];

    if (autoInspectModalFiles) {
      autoInspectModalFiles.innerHTML = files.length
        ? files.map(
            (name) =>
              `<span><i class="fas fa-file-code"></i>${safe(name)}</span>`
          ).join("")
        : (
            '<span><i class="fas fa-circle-info"></i>' +
            "No WG or environment files detected</span>"
          );
    }
  }

  async function inspectAutoBackup(filename) {
    if (!filename) {
      toast.error("Backup filename is missing.");
      return;
    }

    if (!autoInspectModal) {
      toast.error("Inspection window is unavailable.");
      return;
    }

    const generation=++autoInspectGeneration;
    autoInspectPreviousFocus=document.activeElement;
    autoInspectModal.hidden = false;
    autoInspectModal.querySelector("[data-auto-inspect-close]")?.nextElementSibling?.querySelector("button")?.focus();
    activeAutoInspectFilename = filename;

    if (autoInspectModalSubtitle) {
      autoInspectModalSubtitle.textContent = `Inspecting ${filename}…`;
    }

    if (autoInspectModalGrid) {
      autoInspectModalGrid.innerHTML = card(
        "Inspection",
        "Loading",
        "Reading the saved ZIP on the panel server.",
        "warn",
        "fa-circle-notch"
      );
    }

    if (autoInspectModalFiles) {
      autoInspectModalFiles.innerHTML = "";
    }

    try {
      let result = autoInspectCache.get(filename);

      if (!result) {
        const response = await fetch(
          `/api/backups/inspect/${encodeURIComponent(filename)}`,
          {
            headers: csrfHeaders(),
            credentials: "same-origin",
            cache: "no-store",
          }
        );

        result = await response.json().catch(() => ({}));

        if (!response.ok || !result.ok) {
          throw new Error(
            result.message ||
            result.error ||
            `Could not inspect automatic backup (${response.status}).`
          );
        }

        autoInspectCache.set(filename, result);
      }

      if(generation!==autoInspectGeneration)return;
      renderAutoInspectModal(result, filename);
    } catch (error) {
      if(generation!==autoInspectGeneration)return;
      console.error(error);

      if (autoInspectModalSubtitle) {
        autoInspectModalSubtitle.textContent =
          error.message || "Inspection failed.";
      }

      if (autoInspectModalGrid) {
        autoInspectModalGrid.innerHTML = card(
          "Inspection",
          "Failed",
          error.message || "Could not inspect this backup.",
          "bad",
          "fa-triangle-exclamation"
        );
      }

      toast.error(
        error.message ||
        "Could not inspect automatic backup."
      );
    }
  }

  function downloadAutoBackup(filename) {
    if (!filename) return;

    const link = document.createElement("a");
    link.href =
      `/api/backups/file/${encodeURIComponent(filename)}` +
      `?download=1&_=${Date.now()}`;
    link.download = filename;
    link.rel = "noopener";
    link.style.display = "none";

    document.body.appendChild(link);
    link.click();
    link.remove();
  }

  async function deleteAutoBackup(filename) {
    if (!filename) return;

    const confirmed = await confirmAction({
      title: "Delete automatic backup",
      message: `
        <div>
          Permanently delete
          <code>${safe(filename)}</code>?
        </div>
        <div class="bk-small bk-muted" style="margin-top:8px">
          This removes the ZIP from the panel server. Telegram copies are not deleted.
        </div>
      `,
      confirmText: "Delete",
      danger: true,
    });

    if (!confirmed) return;

    const response = await fetch(
      `/api/backups/file/${encodeURIComponent(filename)}`,
      {
        method: "DELETE",
        headers: csrfHeaders(),
        credentials: "same-origin",
        cache: "no-store",
      }
    );

    const result = await response.json().catch(() => ({}));

    if (!response.ok || !result.ok) {
      throw new Error(
        result.message ||
        result.error ||
        `Could not delete backup (${response.status}).`
      );
    }

    autoInspectCache.delete(filename);

    if (activeAutoInspectFilename === filename) {
      closeAutoInspectModal();
    }

    toast.success("Automatic backup deleted.");
    await loadAutoFiles();
  }

  async function loadAutoFiles() {
    if (!autoFilesList) return;

    autoFilesList.innerHTML =
      '<div class="bk-small bk-muted">Loading…</div>';

    try {
      const response = await fetch("/api/backups/auto", {
        headers: csrfHeaders(),
        credentials: "same-origin",
        cache: "no-store",
      });

      const result = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(
          result.message ||
          result.error ||
          `Could not load automatic backups (${response.status}).`
        );
      }

      const files = Array.isArray(result.files)
        ? result.files
        : [];

      if (autoFilesCount) {
        autoFilesCount.textContent =
          `${files.length} file${files.length === 1 ? "" : "s"}`;
      }

      if (!files.length) {
        autoFilesList.innerHTML =
          '<div class="bk-small bk-muted">No automatic backups found.</div>';
        return;
      }

      autoFilesList.innerHTML = files.map((file) => `
        <div class="bk-auto-item" data-file="${safe(file.name)}">
          <div class="bk-auto-meta">
            <div class="bk-auto-date">${safe(fmtEpoch(file.ts))}</div>
            <div class="bk-small bk-muted">
              ${safe(file.name)} · ${safe(autoSize(file.size))}
            </div>
          </div>

          <div class="bk-auto-actions">
            <button
              type="button"
              class="bk-auto-action inspect"
              data-auto-action="inspect"
              data-file="${safe(file.name)}"
              title="Inspect backup"
              aria-label="Inspect backup"
            >
              <i class="fas fa-magnifying-glass"></i>
              <span>Inspect</span>
            </button>

            <button
              type="button"
              class="bk-auto-action download"
              data-auto-action="download"
              data-file="${safe(file.name)}"
              title="Download backup"
              aria-label="Download backup"
            >
              <i class="fas fa-download"></i>
              <span>Download</span>
            </button>

            <button
              type="button"
              class="bk-auto-action restore"
              data-auto-action="restore"
              data-file="${safe(file.name)}"
              title="Restore backup"
              aria-label="Restore backup"
            >
              <i class="fas fa-rotate-left"></i>
              <span>Restore</span>
            </button>

            <button
              type="button"
              class="bk-auto-action delete"
              data-auto-action="delete"
              data-file="${safe(file.name)}"
              title="Delete backup"
              aria-label="Delete backup"
            >
              <i class="fas fa-trash-can"></i>
              <span>Delete</span>
            </button>
          </div>
        </div>
      `).join("");
    } catch (error) {
      console.error(error);
      autoFilesList.innerHTML =
        '<div class="bk-small bk-muted">Could not load automatic backups.</div>';

      if (autoFilesCount) {
        autoFilesCount.textContent = "0 files";
      }

      toast.error(
        error.message ||
        "Could not load automatic backups."
      );
    }
  }

  autoFilesList?.addEventListener("click", async (event) => {
    const button = event.target.closest(
      "button[data-auto-action]"
    );

    if (!button || !autoFilesList.contains(button)) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();

    const action = button.dataset.autoAction || "";
    const filename = button.dataset.file || "";

    if (!filename) {
      toast.error("Backup filename is missing.");
      return;
    }

    try {
      if (action === "inspect") {
        await inspectAutoBackup(filename);
      } else if (action === "download") {
        downloadAutoBackup(filename);
      } else if (action === "restore") {
        await restoreAutoBackup(filename);
      } else if (action === "delete") {
        button.disabled = true;
        await deleteAutoBackup(filename);
      }
    } catch (error) {
      console.error(error);
      toast.error(
        error.message ||
        `Could not ${action || "process"} backup.`
      );
    } finally {
      if (button.isConnected) {
        button.disabled = false;
      }
    }
  });

  async function syncPanelTimezone() {
    let timezone = String(
      window.WG_PANEL_TIMEZONE || selTz?.value || "UTC"
    ).trim() || "UTC";

    try {
      if (window.WG_PANEL_TIMEZONE_READY) {
        timezone = String(await window.WG_PANEL_TIMEZONE_READY).trim() || timezone;
      }
    } catch (_) {}

    if (selTz) selTz.value = timezone;
    if (tzDisplay) tzDisplay.textContent = timezone;
    return timezone;
  }

  async function loadAll() {
    try {
      const s = await fetch("/api/backup/status", { headers: csrfHeaders() }).then((r) => r.json());
      setLast(pillFull, s.full_last);
      setLast(pillDb, s.db_last);
      setLast(pillSettings, s.settings_last);
      updateStatus();

      const sched = await fetch("/api/backup/schedule", { headers: csrfHeaders() }).then((r) => r.json());
      lastSchedule = sched;
      if (autoEnabled) autoEnabled.checked = !!sched.enabled;
      if (pillAuto) {
        pillAuto.textContent = sched.enabled ? "Enabled" : "Disabled";
        pillAuto.className = "bk-pill " + (sched.enabled ? "ok" : "warn");
      }
      if (selFreq) selFreq.value = sched.freq || "daily";
      const scheduleTimezone = String(
        sched.timezone || window.WG_PANEL_TIMEZONE || selTz?.value || "UTC"
      ).trim() || "UTC";
      if (selTz) selTz.value = scheduleTimezone;
      if (tzDisplay) tzDisplay.textContent = scheduleTimezone;
      if (inpTime) inpTime.value = sched.time || "03:00";
      if (inpKeep) inpKeep.value = sched.keep || 7;
      if (autoWG) autoWG.checked = !!sched.include_wg;
      setAutoTelegramEnabled(!!sched.send_to_telegram);
      updateTelegramTargetVisibility();
      await loadTelegramAdmins(sched.telegram_chat_id || "");
      setNext(sched.next_run);

      const p = await fetch("/api/backup/prefs", { headers: csrfHeaders() }).then((r) => r.json());
      if (optWG) optWG.checked = !!p.include_wg;
      if (optTG) optTG.checked = !!p.send_to_telegram;

      await loadAutoFiles();
    } catch (e) {
      console.error(e);
      toast.error("Failed to load backup state.");
    }
  }

  async function saveSchedule(wantEnabled = null, options = {}) {
    const quiet = !!options.quiet;
    const payload = {
      enabled: wantEnabled === null ? !!autoEnabled?.checked : !!wantEnabled,
      freq: selFreq?.value || "daily",
      time: inpTime?.value || "03:00",
      timezone: selTz?.value || "UTC",
      keep: parseInt(inpKeep?.value || "7", 10),
      include_wg: !!autoWG?.checked,
      send_to_telegram: autoTelegramEnabled(),
      telegram_chat_id: autoTelegramEnabled() ? (autoTelegramAdmin?.value || "") : "",
    };

    if (payload.send_to_telegram && !payload.telegram_chat_id) {
      throw new Error("Choose an active Telegram recipient before saving.");
    }

    const resp = await fetch("/api/backup/schedule", {
      method: "POST",
      headers: csrfHeaders(true),
      body: JSON.stringify(payload),
      credentials: "same-origin",
      cache: "no-store",
    });

    const j = await resp.json().catch(() => ({}));
    if (!resp.ok || !j.ok) {
      throw new Error(j.error || j.message || "Could not save schedule.");
    }

    lastSchedule = j;
    setNext(j.next_run);

    if (!quiet) {
      toast.success("Auto-backup schedule saved.");
      await loadAll();
    }

    return j;
  }

  async function saveAndRunSchedule() {
    showRunLoader(
      "Saving schedule",
      "The schedule and selected Telegram recipient are being saved."
    );
    setRunStep("save", "active");

    await saveSchedule(null, { quiet: true });
    setRunStep("save", "done");
    setRunStep("build", "active");

    await triggerAutoBackup({ useLoader: true });
  }

  async function triggerAutoBackup(options = {}) {
    const useLoader = !!options.useLoader;
    const telegramEnabled = autoTelegramEnabled();
    const telegramChatId = autoTelegramAdmin?.value || "";

    if (telegramEnabled && !telegramChatId) {
      throw new Error("Choose an active Telegram recipient first.");
    }

    const params = new URLSearchParams({
      auto: "1",
      wg: autoWG?.checked ? "1" : "0",
      tg: telegramEnabled ? "1" : "0",
      chat_id: telegramChatId,
    });

    if (useLoader) {
      updateRunLoader(
        "Creating complete backup",
        "Collecting database, panel settings, local WireGuard configs, and reachable node configs."
      );
    }

    const r = await fetch(`/api/backup/full?${params.toString()}`, {
      headers: csrfHeaders(),
      credentials: "same-origin",
      cache: "no-store",
    });
    if (!r.ok) throw new Error("Could not create auto backup.");

    if (useLoader) {
      setRunStep("build", "done");
      if (telegramEnabled) {
        setRunStep("telegram", "active");
        updateRunLoader(
          "Finalizing Telegram delivery",
          "The backup was created. Waiting for Telegram delivery confirmation."
        );
      }
    }

    const telegramHeader = r.headers.get("X-Backup-Telegram-Sent");
    const telegramMessage = r.headers.get("X-Backup-Telegram-Message") || "";
    const telegramSent = telegramHeader === "1";

    if (useLoader && telegramEnabled) {
      setRunStep("telegram", "done");
    }

    if (telegramEnabled && telegramHeader === "0") {
      const uncertain = /timeout|timed out|read timed out|connection reset/i.test(telegramMessage);
      if (uncertain) {
        toast.warn("Backup saved. Telegram delivery could not be confirmed by the panel; check Telegram before retrying.");
      } else {
        toast.warn(`Auto backup saved, but Telegram reported an error${telegramMessage ? `: ${telegramMessage}` : "."}`);
      }
    } else if (telegramEnabled && telegramHeader === null) {
      toast.info("Backup saved and Telegram delivery was requested. The server did not expose a delivery-status header.");
    } else if (telegramEnabled && telegramSent) {
      toast.success("Auto backup created and sent to the selected Telegram admin.");
    } else {
      toast.success("Auto backup created in instance/backups/.");
    }

    if (useLoader) {
      setRunStep("refresh", "active");
      updateRunLoader("Refreshing saved backups", "Loading the new backup into the inspection list.");
    }

    await loadAll();

    if (useLoader) {
      setRunStep("refresh", "done");
    }
    const details = $("#auto-files-details");
    if (details) details.open = true;
  }


  async function confirmAction({
    title = "Confirm action",
    message = "",
    confirmText = "Confirm",
    danger = false,
  } = {}) {
    return new Promise((resolve) => {
      const modal = $("#restore-confirm");
      const body = $("#bk-modal-body");
      const okBtn = $("#bk-modal-ok");
      const titleEl = modal?.querySelector(".bk-modal-head strong");

      if (!modal || !body || !okBtn) {
        resolve(false);
        return;
      }

      let finished = false;
      const previousText = okBtn.textContent;
      const previousClass = okBtn.className;
      const previousTitle = titleEl?.textContent || "";

      const cleanup = () => {
        modal.removeEventListener("click", onModalClick);
        okBtn.removeEventListener("click", onConfirm);
        document.removeEventListener("keydown", onKeyDown);

        okBtn.textContent = previousText;
        okBtn.className = previousClass;

        if (titleEl) {
          titleEl.textContent = previousTitle;
        }
      };

      const finish = (value) => {
        if (finished) return;
        finished = true;
        modal.hidden = true;
        cleanup();
        resolve(value);
      };

      const onModalClick = (event) => {
        if (event.target.closest('[data-close="1"]')) {
          finish(false);
        }
      };

      const onConfirm = (event) => {
        event.preventDefault();
        event.stopPropagation();
        finish(true);
      };

      const onKeyDown = (event) => {
        if (event.key === "Escape") {
          finish(false);
        }
      };

      if (titleEl) {
        titleEl.textContent = title;
      }

      body.innerHTML = message;
      okBtn.textContent = confirmText;
      okBtn.className = danger
        ? "bk-btn danger"
        : "bk-btn primary";

      modal.hidden = false;
      modal.addEventListener("click", onModalClick);
      okBtn.addEventListener("click", onConfirm);
      document.addEventListener("keydown", onKeyDown);
    });
  }

  async function confirmRestore(htmlMessage) {
    return new Promise((resolve) => {
      const modal = $("#restore-confirm");
      const body = $("#bk-modal-body");
      const okBtn = $("#bk-modal-ok");
      if (!modal || !body || !okBtn) return resolve(false);
      let done = false;
      const close = (val) => {
        if (done) return;
        done = true;
        modal.hidden = true;
        cleanup();
        resolve(val);
      };
      const onClick = (e) => { if (e.target.closest('[data-close="1"]')) close(false); };
      const onKey = (e) => { if (e.key === "Escape") close(false); };
      const onOk = () => close(true);
      const cleanup = () => {
        modal.removeEventListener("click", onClick);
        okBtn.removeEventListener("click", onOk);
        document.removeEventListener("keydown", onKey);
      };
      body.innerHTML = htmlMessage;
      modal.hidden = false;
      modal.addEventListener("click", onClick);
      okBtn.addEventListener("click", onOk);
      document.addEventListener("keydown", onKey);
    });
  }

  function appendServerSettings(fd) {
    const mode = currentServerMode();
    fd.append("server_settings_mode", mode);
    fd.append("restore_server_settings", mode === "saved" ? "1" : "0");
    if (mode === "custom") {
      const map = {
        custom_port: "#custom-panel-port",
        custom_bind: "#custom-panel-bind",
        custom_domain: "#custom-panel-domain",
        custom_scheme: "#custom-panel-scheme",
        custom_http_port: "#custom-http-port",
        custom_https_port: "#custom-https-port",
        custom_wg_path: "#custom-wg-path",
      };
      Object.entries(map).forEach(([k, sel]) => fd.append(k, ($(sel)?.value || "").trim()));
    }
  }

  function renderRestoreResult(j) {
    if (!restoreResult) return;
    restoreResult.classList.add("show");
    const r = j.restored || {};
    const warnings = j.warnings || [];
    restoreResult.innerHTML = `
      <div class="bk-result-card ${j.ok ? "ok" : "bad"}">
        <strong>${safe(j.message || (j.ok ? "Restore completed." : "Restore failed."))}</strong>
        <div class="bk-small bk-muted" style="margin-top:6px">
          DB: ${r.db ? "yes" : "no"} · Settings: ${r.settings ? "yes" : "no"} · Local WG: ${r.wg ? "yes" : "no"} · Node WG: ${r.node_wg ? "yes" : "no"}
        </div>
        ${warnings.length ? `<div class="bk-small" style="margin-top:8px;color:#92400e">${warnings.map(safe).join("<br>")}</div>` : ""}
      </div>`;
  }

  const postgresBackend = $(".backup-shell")?.dataset.databaseBackend === "postgresql";
  const maintenanceBox = $("#restore-maintenance-status");
  const restoreStorageKey = "wgpanel_pg_restore_reference";
  const restoreKinds = $$('input[name="restore-kind"]');

  function effectiveRestoreKind(kind = $('input[name="restore-kind"]:checked')?.value || "auto") {
    return kind === "auto" ? (lastInspect?.ok ? lastInspect.kind : "auto") : kind;
  }

  function updateRestoreScope(kind = effectiveRestoreKind(), inspected = lastInspect) {
    const managed = postgresBackend && kind !== "settings";
    const dbOnly = kind === "db";
    const localRecovery = kind === "full" && !!(inspected?.has_wg || inspected?.contains?.local_wireguard_conf) && !(inspected?.has_node_wg || inspected?.contains?.remote_node_wireguard_conf);
    if (managed) {
      const keep = serverModeInputs.find(input => input.value === "keep");
      if (keep) keep.checked = true;
    }
    serverModeInputs.forEach(input => { input.disabled = managed && input.value !== "keep"; });
    if (restoreWGBox) {
      restoreWGBox.disabled = dbOnly || (managed && !localRecovery);
      if (restoreWGBox.disabled) restoreWGBox.checked = false;
    }
    const title = $("#restore-scope-title");
    const text = $("#restore-scope-text");
    const help = $("#restore-wg-help");
    if (title) title.textContent = managed ? "Managed database restore" : kind === "settings" ? "Settings restore" : "Database restore scope";
    if (text) text.textContent = managed ? "Replaces all database records, including reseller accounts and purchases. Current server settings are kept. Full restore can recover compatible local WireGuard configs after PostgreSQL. Recovery copies are automatic." : kind === "settings" ? "Restores panel files without replacing database records. Network files are optional and can affect active access." : "Database restores replace all customer and reseller records, not individual accounts. Review the archive and keep a recovery copy.";
    if (help) help.textContent = managed ? (dbOnly ? "Database-only restore keeps network files unchanged." : localRecovery ? "Optional: restore local WireGuard files after PostgreSQL verification, before services restart." : "Select a Full backup containing local WireGuard configs and no remote node configs.") : dbOnly ? "Database-only restore does not replace WireGuard files." : "Optional. Use matching trusted configs and review active interfaces before applying changes.";
    updateServerModeUI();
  }
  let maintenanceReference = "";
  let maintenanceTimer;
  let maintenancePolling = false;
  let disconnectedSince = 0;
  let loggedReference = "";
  let operationHistory = [];
  let operationInvocation = "";

  const progressDialog = $("#bk-restore-progress");
  const progressClose = $("#bk-restore-progress-close");
  const progressLogin = $("#bk-restore-progress-login");
  const progressRetry = $("#bk-restore-progress-retry");
  const terminalRestoreStates = new Set(["completed", "failed", "review"]);
  const restoreStageNames = {uploading:"Submitting backup",queued:"Queued",validating:"Validating backup",staging:"Staging PostgreSQL",aligning:"Aligning database schema",stopping:"Stopping services",backup:"Creating recovery backup",wireguard:"Restoring WireGuard",cutover:"Activating database",restarting:"Restarting services",completed:"Completed",failed:"Restore stopped",review:"Review required",reconnecting:"Reconnecting",signin:"Sign-in required",unavailable:"Status unavailable"};

  function openRestoreProgress() {
    if (progressDialog && !progressDialog.open) progressDialog.showModal();
  }

  function updateRestoreProgress(message, reference = "", state = "reconnecting", open = false) {
    if (!progressDialog) return;
    const terminal = terminalRestoreStates.has(state);
    progressDialog.dataset.state = state;
    $("#bk-restore-progress-title").textContent = state === "completed" ? "Restore completed" : state === "failed" ? "Restore failed" : state === "review" ? "Restore needs review" : state === "signin" ? "Sign in to view restore result" : state === "unavailable" ? "Restore status unavailable" : "Restoring backup";
    $("#bk-restore-progress-stage").textContent = restoreStageNames[state] || "Maintenance in progress";
    $("#bk-restore-progress-message").textContent = message || "Preparing restore…";
    const ref = $("#bk-restore-progress-reference");
    ref.hidden = !reference;
    ref.textContent = reference ? "Reference: " + reference : "";
    $("#bk-restore-progress-help").textContent = state === "completed" ? "Review customer data and WireGuard connectivity before resuming heavy traffic." : state === "review" || state === "failed" ? "Open Operation log for the recorded stages and SSH diagnostics. Do not manually roll back the database." : state === "uploading" ? "Keep this page open until the request is accepted." : state === "signin" ? "The restore reference is saved. Sign in with the administrator credentials from the backup to retrieve the final result." : state === "unavailable" ? "Automatic checks are paused. Check status again or open Operation log for SSH diagnostics. Do not submit another restore." : "Maintenance runs independently of this page. Do not submit another restore.";
    if (progressLogin) progressLogin.hidden = state !== "signin";
    if (progressRetry) progressRetry.hidden = !["signin", "unavailable"].includes(state);
    progressClose.textContent = terminal || state === "signin" || state === "unavailable" ? "Close" : "Hide";
    renderOperationLog(reference);
    progressClose.disabled = state === "uploading";
    if (open) openRestoreProgress();
  }

  progressClose?.addEventListener("click", () => progressDialog.close());
  progressDialog?.addEventListener("cancel", event => {
    if (progressDialog.dataset.state === "uploading") event.preventDefault();
  });

  const activityOpen = $("#bk-activity-open");
  const activityView = $("#bk-activity-view");
  const statusView = $("#bk-restore-status-view");
  const activityBack = $("#bk-activity-back");
  const stagesTab = $("#bk-activity-stages-tab");
  const sshTab = $("#bk-activity-ssh-tab");

  function selectActivityTab(ssh = false) {
    if (!stagesTab || !sshTab) return;
    stagesTab.setAttribute("aria-pressed", String(!ssh));
    sshTab.setAttribute("aria-pressed", String(ssh));
    $("#bk-activity-stages").hidden = ssh;
    $("#bk-activity-ssh").hidden = !ssh;
    const body = progressDialog?.querySelector(".bk-restore-progress-body");
    if (body) body.scrollTop = 0;
  }

  function showActivity(show = false, focus = false) {
    if (!activityView || !statusView) return;
    activityView.hidden = !show;
    statusView.hidden = show;
    if (progressDialog) progressDialog.dataset.view = show ? "activity" : "status";
    if (show) selectActivityTab();
    const body = progressDialog?.querySelector(".bk-restore-progress-body");
    if (body) body.scrollTop = 0;
    if (focus) (show ? activityBack : activityOpen)?.focus();
  }

  activityOpen?.addEventListener("click", () => showActivity(true, true));
  activityBack?.addEventListener("click", () => showActivity(false, true));
  stagesTab?.addEventListener("click", () => selectActivityTab());
  sshTab?.addEventListener("click", () => selectActivityTab(true));

  function resetOperationLog(reference) {
    if (loggedReference === reference) return;
    loggedReference = reference;
    operationHistory = [];
    operationInvocation = "";
    showActivity(false);
  }

  function renderOperationLog(reference) {
    const entries = $("#bk-restore-log-entries");
    const command = $("#bk-restore-journal-command");
    if (!activityOpen || !entries || !command) return;
    resetOperationLog(reference);
    activityOpen.hidden = !reference;
    const count = $("#bk-restore-log-count");
    if (count) count.textContent = `${operationHistory.length} ${operationHistory.length === 1 ? "entry" : "entries"} · View activity`;
    const signature = JSON.stringify(operationHistory);
    if (entries.dataset.signature !== signature) {
      entries.dataset.signature = signature;
      entries.replaceChildren();
      for (const [index, entry] of [...operationHistory].reverse().entries()) {
        const item = document.createElement("li");
        const marker = document.createElement("span");
        const stage = document.createElement("strong");
        const time = document.createElement("time");
        const message = document.createElement("p");
        const content = document.createElement("div");
        const heading = document.createElement("div");
        marker.className = "bk-activity-marker";
        marker.setAttribute("aria-hidden", "true");
        stage.textContent = restoreStageNames[entry.state] || entry.state || "Maintenance";
        time.textContent = entry.updated_at ? fmtEpoch(entry.updated_at) : "";
        message.textContent = entry.message || "";
        item.dataset.state = entry.state || "";
        if (index === 0) item.classList.add("latest");
        heading.className = "bk-activity-entry-head";
        heading.append(stage, time);
        content.className = "bk-activity-entry-content";
        content.append(heading, message);
        item.append(marker, content);
        entries.append(item);
      }
      if (!operationHistory.length) {
        const item = document.createElement("li");
        item.className = "bk-activity-empty";
        item.textContent = "No maintenance entries received yet.";
        entries.append(item);
      }
    }
    command.textContent = /^[0-9a-f]{32}$/.test(operationInvocation) ? `journalctl _SYSTEMD_INVOCATION_ID=${operationInvocation} -n 300 --no-pager -o short-iso` : "journalctl -u 'wg-maintenance-restore-*' -n 300 --no-pager -o short-iso";
  }

  function rememberOperation(result) {
    if (!result?.reference) return;
    resetOperationLog(result.reference);
    if (Array.isArray(result.history)) operationHistory = result.history.slice(-80);
    else if (result.updated_at && result.state && result.message) {
      const last = operationHistory[operationHistory.length - 1];
      if (!last || last.updated_at !== result.updated_at || last.state !== result.state || last.message !== result.message) operationHistory = [...operationHistory, {state:result.state,message:result.message,updated_at:result.updated_at}].slice(-80);
    }
    if (/^[0-9a-f]{32}$/.test(result.invocation_id || "")) operationInvocation = result.invocation_id;
  }

  async function copyRestoreText(value) {
    try { await navigator.clipboard.writeText(value); toast.success("Copied."); }
    catch (_) { toast.warn("Clipboard unavailable. Select the text and copy it manually."); }
  }

  $("#bk-restore-log-copy")?.addEventListener("click", () => copyRestoreText([`Restore reference: ${loggedReference}`, ...operationHistory.map(entry => `${entry.updated_at ? fmtEpoch(entry.updated_at) : ""} ${entry.state}: ${entry.message}`)].join("\n")));
  $("#bk-restore-journal-copy")?.addEventListener("click", () => copyRestoreText($("#bk-restore-journal-command")?.textContent || ""));
  progressLogin?.addEventListener("click", () => {
    try { localStorage.setItem('wg_backup_tab', 'restore'); } catch (_) {}
  });
  progressRetry?.addEventListener("click", () => {
    if (!maintenanceReference || maintenancePolling) return;
    disconnectedSince = 0;
    displayMaintenance("Checking the restore result…", maintenanceReference, "reconnecting");
    pollMaintenance(maintenanceReference);
  });

  function displayMaintenance(message, reference, state = "reconnecting", open = false) {
    updateRestoreProgress(message, reference, state, open);
    if (!maintenanceBox) return;
    maintenanceBox.hidden = false;
    maintenanceBox.classList.add("show");
    const recovery = state === "review" || state === "failed";
    maintenanceBox.innerHTML = `<div class="bk-result-card ${recovery ? "bad" : state === "completed" ? "ok" : ""}"><div class="bk-maintenance-summary"><div><strong>${safe(restoreStageNames[state] || "Restore maintenance")}</strong><div class="bk-small bk-muted">${safe(message)}</div></div><button type="button" class="bk-btn" data-restore-details>View details</button></div></div>`;
    maintenanceBox.querySelector('[data-restore-details]')?.addEventListener("click", openRestoreProgress);
  }

  function setRestoreControls(disabled) {
    if (restoreBtn) restoreBtn.disabled = disabled;
    $$('[data-auto-action="restore"]').forEach(button => { button.disabled = disabled; });
  }

  async function pollMaintenance(reference) {
    if (maintenanceReference !== reference || maintenancePolling) return;
    clearTimeout(maintenanceTimer);
    maintenancePolling = true;
    const controller = new AbortController();
    const deadline = setTimeout(() => controller.abort(), 8000);
    let next = true;
    try {
      const response = await fetch(`/api/backup/status?restore=${encodeURIComponent(reference)}`, {credentials:"same-origin",cache:"no-store",signal:controller.signal});
      if (response.redirected || response.status === 401 || response.status === 403) {
        next = false;
        displayMaintenance("The panel responded, but your administrator session is no longer authorized. Restore completion has not yet been confirmed.", reference, "signin", true);
        return;
      }
      if (response.status === 404) {
        next = false;
        maintenanceReference = "";
        setRestoreControls(false);
        try { localStorage.removeItem(restoreStorageKey); } catch (_) {}
        displayMaintenance("Restore reference was not found. Check the restore journal before submitting again.",reference,"review",true);
        return;
      }
      const result = await response.json().catch(() => ({}));
      if (!response.ok || !result.ok) throw new Error("Status temporarily unavailable");
      disconnectedSince = 0;
      rememberOperation(result);
      displayMaintenance(result.message || "Restore is running.", reference, result.state, terminalRestoreStates.has(result.state));
      if (terminalRestoreStates.has(result.state)) {
        next = false;
        maintenanceReference = "";
        setRestoreControls(false);
        try { localStorage.removeItem(restoreStorageKey); } catch (_) {}
        if (restoreResult) { restoreResult.innerHTML = ""; restoreResult.classList.remove("show"); }
        if (result.state === "completed") await loadAll();
        return;
      }
    } catch (_) {
      if (!disconnectedSince) disconnectedSince = Date.now();
      if (Date.now() - disconnectedSince >= 120000) {
        next = false;
        displayMaintenance("The panel has not returned a restore status for two minutes. Maintenance may still be running; its outcome is not confirmed.", reference, "unavailable", true);
      } else {
        displayMaintenance("The panel is temporarily unreachable. Checking for its return automatically.", reference);
      }
    } finally {
      clearTimeout(deadline);
      maintenancePolling = false;
      if (next && maintenanceReference === reference) maintenanceTimer = setTimeout(() => pollMaintenance(reference), 4000);
    }
  }

  function trackMaintenance(result) {
    maintenanceReference = result.reference;
    disconnectedSince = 0;
    try { localStorage.setItem(restoreStorageKey, result.reference); localStorage.setItem('wg_backup_tab', 'restore'); } catch (_) {}
    rememberOperation(result);
    displayMaintenance(result.message, result.reference, result.state, true);
    setRestoreControls(true);
    pollMaintenance(result.reference);
  }

  async function confirmPostgresMaintenance(withWireguard = false) {
    const modal = $("#restore-confirm");
    if (!modal) return null;
    return new Promise(resolve => {
      const body = $("#bk-modal-body");
      const button = $("#bk-modal-ok");
      const title = modal.querySelector(".bk-modal-head strong");
      const subtitle = modal.querySelector(".bk-modal-head .bk-small");
      if (!body || !button) { resolve(null); return; }
      if (title) title.textContent = "Managed PostgreSQL restore";
      if (subtitle) subtitle.textContent = "The panel will handle the maintenance window automatically.";
      body.innerHTML = `
        <div class="bk-restore-dialog">
          <div class="bk-restore-dialog__hero">
            <div>
              <div class="bk-restore-dialog__eyebrow">Managed maintenance</div>
              <h3>Replace the live database with this verified backup</h3>
              <p>The panel stages the backup, stops writers, creates a recovery copy and restarts services automatically.</p>
            </div>
            <span class="bk-restore-dialog__badge"><i class="fas fa-database"></i> PostgreSQL</span>
          </div>
          <div class="bk-restore-dialog__grid">
            <div class="bk-restore-info-card">
              <div class="bk-restore-info-card__title"><i class="fas fa-check-circle"></i> What will happen</div>
              <ul class="bk-restore-list">
                <li>Current data is retained in a recovery database and dump.</li>
                <li>Administrator and reseller sessions will expire after restart.</li>
                <li>Supported profiles, templates and endpoint settings are included in Full restore.</li>
                ${withWireguard ? "<li>After PostgreSQL verification, saved local WireGuard configurations and peer keys are recovered before services restart. Customers present in the backup keep their saved connection details if the server identity and configuration remain compatible.</li>" : ""}
              </ul>
            </div>
            <div class="bk-restore-info-card warn">
              <div class="bk-restore-info-card__title"><i class="fas fa-triangle-exclamation"></i> What stays unchanged</div>
              <ul class="bk-restore-list">
                <li>Current server settings remain active.</li>
                <li>Local bot files and encryption keys stay unchanged. ${withWireguard ? "Interface keys, addresses and routing must match; remote nodes are not restored." : "WireGuard files stay unchanged."}</li>
                <li>The restore stops if required customer or interface identities are incompatible.</li>
              </ul>
            </div>
          </div>
          ${withWireguard ? '<div class="bk-restore-info-card warn"><div class="bk-restore-info-card__title"><i class="fas fa-clock-rotate-left"></i> Backup date matters</div><p>This is a point-in-time restore, not a merge. Customers created after the backup are not included and may lose access. Changes to keys, limits and expiration dates made after the backup are also reverted. Create a fresh backup if you need to preserve the current state.</p></div>' : ""}
          <div class="bk-field bk-field-restore-password">
            <label for="pg-restore-password">Current administrator password</label>
            <input id="pg-restore-password" type="password" autocomplete="current-password" maxlength="1024" placeholder="Enter your password">
            <div class="bk-small bk-muted">Use the active administrator password for this panel.</div>
          </div>
          <label class="bk-restore-trust">
            <input id="pg-restore-trusted" type="checkbox">
            <span>I trust this backup, it uses this installation’s encryption keys, and I accept temporary downtime.</span>
          </label>
        </div>`;
      const password = $("#pg-restore-password");
      const trusted = $("#pg-restore-trusted");
      const close = value => {
        modal.hidden = true;
        if (password) password.value = "";
        if (title) title.textContent = "Confirm restore";
        if (subtitle) subtitle.textContent = "Review the backup details and confirm maintenance.";
        button.disabled = false;
        modal.removeEventListener("click", onClick);
        button.removeEventListener("click", onConfirm);
        document.removeEventListener("keydown", onKey);
        resolve(value);
      };
      const onClick = e => { if (e.target.closest('[data-close="1"]')) close(null); };
      const onKey = e => { if (e.key === "Escape") close(null); };
      const onConfirm = () => { if (trusted?.checked && password?.value) close(password.value); };
      const update = () => { button.disabled = !(trusted?.checked && password?.value); };
      password?.addEventListener("input", update);
      trusted?.addEventListener("change", update);
      button.addEventListener("click", onConfirm);
      modal.addEventListener("click", onClick);
      document.addEventListener("keydown", onKey);
      update();
      modal.hidden = false;
      password?.focus();
    });
  }

  async function doRestoreFromBlob(blob, filename, kind = "auto") {
    if (maintenanceReference) throw new Error("A restore operation is already running.");
    let password = null;
    let inspected = lastInspect;
    if (postgresBackend && kind === "auto") {
      inspected = await inspectBlob(blob, filename, "saved");
      kind = inspected.kind;
      if (!["db", "full", "settings"].includes(kind)) throw new Error("Unknown backup type. Inspect a supported backup first.");
    }
    if (postgresBackend && kind !== "settings") {
      updateRestoreScope(kind, inspected);
      if (currentServerMode() !== "keep") throw new Error("For managed PostgreSQL restore, keep current server settings.");
      password = await confirmPostgresMaintenance(!!restoreWGBox?.checked);
      if (password === null) return {cancelled:true};
    }
    const fd = new FormData();
    if (password !== null) { fd.append("restore_password",password); fd.append("restore_confirmed","1"); password = null; }
    fd.append("file", blob, filename || "backup.zip");
    fd.append("kind", kind);
    fd.append("restore_wg", restoreWGBox?.checked ? "1" : "0");
    appendServerSettings(fd);
    const headers = csrfHeaders();
    delete headers["Content-Type"];
    updateRestoreProgress("Sending the selected backup to the panel.", "", "uploading", true);
    try {
    const r = await fetch("/api/backup/restore", { method: "POST", headers, body: fd });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) throw new Error(j.message || "Restore failed.");
    if (j.queued) trackMaintenance(j);
    else {
      renderRestoreResult(j);
      updateRestoreProgress(j.message || "Restore completed.", "", j.partial ? "review" : "completed", true);
    }
    return j;
    } catch (error) {
      updateRestoreProgress(error.message || "The restore request could not be confirmed.", "", "review", true);
      throw error;
    }

  }

  async function restoreAutoBackup(filename) {
    if (!filename) return;
    const ok = await confirmRestore(`<div><strong>Restore auto backup?</strong></div><div class="bk-small bk-muted" style="margin-top:8px"><code>${safe(filename)}</code></div><div style="margin-top:10px">${postgresBackend ? "The archive will be inspected. Managed database restores keep current server settings. To select local WireGuard recovery, download the archive and use the Restore tab." : "Server settings will use the mode selected in Restore options."}</div>`);
    if (!ok) return;
    try {
      const resp = await fetch(`/api/backups/file/${encodeURIComponent(filename)}`, {
        headers: csrfHeaders(),
        credentials: "same-origin",
        cache: "no-store",
      });
      if (!resp.ok) throw new Error("Could not download auto backup file from server.");
      const blob = await resp.blob();
      const j = await doRestoreFromBlob(blob, filename, "auto");
      if (j.queued || j.cancelled) return;
      if(j.partial) toast.warn("Restore was partial. Review node results before restarting."); else toast.success(j.message || "Restore completed.");
      await loadAll();
    } catch (e) {
      console.error(e);
      toast.error(e.message || "Restore failed.");
    } finally {
      updateRestoreScope();
    }
  }

  async function loadInstallCommand() {
    if (cachedInstallCommand) return cachedInstallCommand;
    const firstNodeId = Object.keys(lastInspect?.node_wg_nodes || {})[0] || "";
    try {
      const url = firstNodeId ? `/api/backup/node-agent/install-command?node_id=${encodeURIComponent(firstNodeId)}` : "/api/backup/node-agent/install-command";
      const r = await fetch(url, { headers: csrfHeaders() });
      const j = await r.json().catch(() => ({}));
      cachedInstallCommand = [j.command, j.next_command ? `\n# Then open the node menu:\n${j.next_command}` : ""].filter(Boolean).join("\n");
    } catch {}
    if (!cachedInstallCommand) {
      cachedInstallCommand = `sudo bash -c 'command -v curl >/dev/null 2>&1 || (apt-get update -y && apt-get install -y curl ca-certificates); bash -c "$(curl -fsSL https://raw.githubusercontent.com/Azumi67/WG_Panel/refs/heads/main/agent/node.sh)"'\n\n# Then open the node menu:\nnode`;
    }
    return cachedInstallCommand;
  }

  btnFull?.addEventListener("click", () => downloadBackup("full", btnFull));
  btnDb?.addEventListener("click", () => downloadBackup("db", btnDb));
  btnSettings?.addEventListener("click", () => downloadBackup("settings", btnSettings));
  selTz?.addEventListener("change", () => { if (lastSchedule) setNext(lastSchedule.next_run); loadAutoFiles(); });
  btnSave?.addEventListener("click", async () => {
    try {
      setBusy(btnSave, true, "Saving");
      await saveSchedule();
    } catch (e) {
      toast.error(e.message || "Could not save schedule.");
    } finally {
      setBusy(btnSave, false);
    }
  });

  autoEnabled?.addEventListener("change", () => {
    if (pillAuto) {
      pillAuto.textContent = autoEnabled.checked ? "Unsaved: enabled" : "Unsaved: disabled";
      pillAuto.className = "bk-pill warn";
    }
  });

  autoTG?.addEventListener("change", () => {
    updateTelegramTargetVisibility();

    if (autoTelegramEnabled()) {
      loadTelegramAdmins(
        autoTelegramAdmin?.value ||
        lastSchedule?.telegram_chat_id ||
        ""
      );
    }
  });

  btnSaveRun?.addEventListener("click", async () => {
    try {
      setBusy(btnSaveRun, true, "Saving & running");
      await saveAndRunSchedule();
    } catch (e) {
      toast.error(e.message || "Save & run failed.");
    } finally {
      hideRunLoader();
      setBusy(btnSaveRun, false);
    }
  });

  restoreTrigger?.addEventListener("click", () => restoreFile?.click());
  restoreFile?.addEventListener("change", async () => {
    const file = restoreFile.files && restoreFile.files[0];
    if (!file) {
      if (restoreName) restoreName.textContent = "No file chosen";
      if (restoreHint) restoreHint.textContent = "Choose a ZIP to preview its contents before restore.";
      lastInspect = null;
      updateRestoreScope();
      return;
    }
    lastInspect = null;
    updateRestoreScope();
    if (restoreName) restoreName.textContent = file.name;
    if (restoreHint) restoreHint.textContent = "Inspecting backup contents…";
    await inspectSelectedBackup(file);
    if (restoreHint && lastInspect?.ok) restoreHint.textContent = "Backup inspected. Review the summary, then restore.";
  });

  restoreBtn?.addEventListener("click", async () => {
    const file = restoreFile?.files && restoreFile.files[0];
    if (!file) return toast.error("Choose a backup .zip file first.");
    if(!lastInspect?.ok) return toast.error("Inspect a valid backup before restoring.");
    const kind = effectiveRestoreKind();
    updateRestoreScope(kind);
    const mode = currentServerMode();
    const warning = mode === "saved"
      ? "Saved server settings may change this panel’s port, bind address, domain and TLS. Use only for same-server restore."
      : mode === "custom"
        ? "Custom server settings will be written after restore. Check the port and domain before continuing."
        : "Current server port/domain/TLS will be protected.";
    const ok = await confirmRestore(`<div><strong>Confirm restore</strong></div><div style="margin-top:8px">${safe(warning)}</div><div class="bk-small bk-muted" style="margin-top:10px">Server settings: <strong>${safe(mode)}</strong> · Restore type: <strong>${safe(kind)}</strong> · WG configs: <strong>${restoreWGBox?.checked ? "yes" : "no"}</strong></div>`);
    if (!ok) return;
    setBusy(restoreBtn, true, "Restoring");
    try {
      const j = await doRestoreFromBlob(file, file.name, kind);
      if (j.queued || j.cancelled) return;
      if(j.partial) toast.warn("Restore was partial. Review node results before restarting."); else toast.success(j.message || "Restore completed.");
      if (j.needs_restart) toast.info("Restart the panel service to apply restored data.");
      await loadAll();
    } catch (e) {
      console.error(e);
      toast.error(e.message || "Restore failed.");
    } finally {
      setBusy(restoreBtn, false);
      if (maintenanceReference) setRestoreControls(true);
    }
  });

  nodeGuideToggle?.addEventListener("click", async () => {
    const open = !nodeCommandBox?.classList.contains("open");
    if (open) {
      if (nodeInstallCommand) nodeInstallCommand.textContent = "Loading command…";
      nodeCommandBox?.classList.add("open");
      const cmd = await loadInstallCommand();
      if (nodeInstallCommand) nodeInstallCommand.textContent = cmd;
      nodeGuideToggle.innerHTML = '<i class="fas fa-terminal"></i> Hide install command';
    } else {
      nodeCommandBox?.classList.remove("open");
      nodeGuideToggle.innerHTML = '<i class="fas fa-terminal"></i> Show install command';
    }
  });

  $$("[data-auto-inspect-close='1']").forEach((button) => {
    button.addEventListener("click", () => {
      closeAutoInspectModal();
    });
  });

  autoInspectDownload?.addEventListener("click", () => {
    if (activeAutoInspectFilename) {
      downloadAutoBackup(activeAutoInspectFilename);
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && autoInspectModal && !autoInspectModal.hidden) {
      closeAutoInspectModal();
    }
  });

  copyNodeCommand?.addEventListener("click", async () => {
    const cmd = nodeInstallCommand?.textContent || await loadInstallCommand();
    try {
      await navigator.clipboard.writeText(cmd);
      copyNodeCommand.classList.add("copy-ok");
      toast.success("Node install command copied.");
      setTimeout(() => copyNodeCommand.classList.remove("copy-ok"), 1200);
    } catch {
      toast.error("Could not copy command.");
    }
  });

  restoreKinds.forEach(input => input.addEventListener("change", () => updateRestoreScope()));
  updateRestoreScope();
  syncPanelTimezone().finally(loadAll);


  function initBackupTabs(){
    const tabs = Array.from(document.querySelectorAll('[data-bk-tab]'));
    const panels = Array.from(document.querySelectorAll('[data-bk-panel]'));
    if (!tabs.length || !panels.length) return;
    function activate(name){
      tabs.forEach(t => t.classList.toggle('active', t.dataset.bkTab === name));
      panels.forEach(p => p.classList.toggle('active', p.dataset.bkPanel === name));
      try { localStorage.setItem('wg_backup_tab', name); } catch(_) {}
    }
    tabs.forEach(t => t.addEventListener('click', () => activate(t.dataset.bkTab)));
    let saved = 'backup';
    try { saved = localStorage.getItem('wg_backup_tab') || 'backup'; } catch(_) {}
    if (!tabs.some(t => t.dataset.bkTab === saved)) saved = 'backup';
    activate(saved);
  }
  initBackupTabs();
  if (postgresBackend) {
    try {
      const reference = localStorage.getItem(restoreStorageKey) || "";
      if (/^[0-9a-f]{32}$/.test(reference)) trackMaintenance({reference,state:"queued",message:"Checking the previous restore operation…"});
    } catch (_) {}
    if (!maintenanceReference) {
      fetch("/api/backup/status?restore=latest",{credentials:"same-origin",cache:"no-store"})
        .then(async response => {
          const result = await response.json().catch(() => null);
          if (!response.ok) return null;
          return result;
        })
        .then(result => {
          if (!result || result.error === "restore_not_found" || maintenanceReference || progressDialog?.dataset.state === "uploading") return;
          if (!result.ok || !result.reference) return;
          if (terminalRestoreStates.has(result.state)) { rememberOperation(result); displayMaintenance(result.message,result.reference,result.state); }
          else trackMaintenance(result);
        }).catch(() => {});
    }
  }
})();

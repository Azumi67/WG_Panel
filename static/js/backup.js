(() => {
  const $ = (s, p = document) => p.querySelector(s);

  const _csrfHeaders = (json = false) => {
    if (typeof window.csrfHeaders === "function") return window.csrfHeaders(json);
    const h = {};
    if (json) h["Content-Type"] = "application/json";
    return h;
  };

  const toastSuccess = (m) =>
    (window.toastSuccess ? window.toastSuccess(m) : alert(m));
  const toastInfo = (m) => (window.toastInfo ? window.toastInfo(m) : alert(m));
  const toastError = (m) => (window.toastError ? window.toastError(m) : alert(m));

  const tabButtons = Array.from(document.querySelectorAll(".bk-tab"));
  const panels = Array.from(document.querySelectorAll(".bk-panel"));

  function activateTab(name) {
    tabButtons.forEach((btn) => {
      const isActive = btn.dataset.tab === name;
      btn.classList.toggle("active", isActive);
      btn.setAttribute("aria-selected", isActive ? "true" : "false");
    });
    panels.forEach((p) => {
      const show = p.dataset.panel === name;
      p.classList.toggle("active", show);
      p.hidden = !show;
    });
  }

  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => activateTab(btn.dataset.tab));
  });

  const pillStatus = $("#status-pill");
  const pillFull = $("#full-last");
  const pillDb = $("#db-last");
  const pillSettings = $("#settings-last");

  const pillAuto = $("#auto-state");
  const pillNext = $("#next-pill");

  const btnFull = $("#btn-full");
  const btnDb = $("#btn-db");
  const btnSettings = $("#btn-settings");

  const optWG = $("#opt-wg");
  const optTG = $("#opt-tg");

  const autoEnabled = $("#auto-enabled");
  const selFreq = $("#freq");
  const inpTime = $("#time");
  const selTz = $("#timezone");
  const inpKeep = $("#keep");
  const autoWG = $("#auto-wg");
  const autoTG = $("#auto-tg");
  const btnSave = $("#save");
  const btnRunNow = $("#run-now");
  const timeRow = $("#time-row");

  const restoreFile = $("#restore-file");
  const restoreBtn = $("#btn-restore");
  const restoreTrigger = $("#restore-file-trigger");
  const restoreName = $("#restore-file-name");
  const restoreHint = $("#restore-file-hint"); 
  const restoreWGBox = $("#restore-wg");

  const autoFilesList = $("#auto-files-list");
  const autoFilesCount = $("#auto-files-count");

  let lastSchedule = null;

  if (selTz) {
    selTz.addEventListener("change", () => {
      if (lastSchedule) setNext(lastSchedule.next_run);
      loadAutoFiles();
      loadAll();
    });
  }

  function confirmRestore(htmlMessage) {
    return new Promise((resolve) => {
      const modal = document.getElementById("restore-confirm");
      const body = document.getElementById("bk-modal-body");
      const okBtn = document.getElementById("bk-modal-ok");
      if (!modal || !body || !okBtn) return resolve(false);

      let done = false;
      const close = (val) => {
        if (done) return;
        done = true;
        modal.hidden = true;
        cleanup();
        resolve(val);
      };

      const onClick = (e) => {
        const closeEl = e.target.closest('[data-close="1"]');
        if (closeEl) close(false);
      };
      const onKey = (e) => {
        if (e.key === "Escape") close(false);
      };
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

  function schedTZ() {
    return selTz && selTz.value ? selTz.value : "UTC";
  }

  function fmtISO(iso, withSeconds = false) {
    if (!iso) return "—";
    try {
      const d = new Date(iso);
      const tz = schedTZ();
      return (
        d.toLocaleString("en-GB", {
          hour12: false,
          timeZone: tz,
          day: "2-digit",
          month: "short",
          year: "numeric",
          hour: "2-digit",
          minute: "2-digit",
          ...(withSeconds ? { second: "2-digit" } : {}),
        }) + ` (${tz})`
      );
    } catch {
      return iso;
    }
  }

  function fmtEpoch(ts, withSeconds = true) {
    if (!ts) return "—";
    try {
      const d = new Date(ts * 1000);
      const tz = schedTZ();
      return (
        d.toLocaleString("en-GB", {
          hour12: false,
          timeZone: tz,
          day: "2-digit",
          month: "short",
          year: "numeric",
          hour: "2-digit",
          minute: "2-digit",
          ...(withSeconds ? { second: "2-digit" } : {}),
        }) + ` (${tz})`
      );
    } catch {
      return String(ts);
    }
  }

  function updateFreqUI() {
    if (timeRow) timeRow.style.display = "";
  }
  if (selFreq) selFreq.addEventListener("change", updateFreqUI);

  function setLast(pill, iso) {
    if (!pill) return;
    if (iso) {
      pill.textContent = "Last: " + fmtISO(iso, false);
      pill.className = "pill tiny ok";
    } else {
      pill.textContent = "Last: No backup";
      pill.className = "pill tiny muted";
    }
  }

  function setNext(iso) {
    if (!pillNext) return;
    pillNext.textContent = "Next: " + (iso ? fmtISO(iso, false) : "—");
  }

  function updateStatus() {
    if (!pillStatus) return;
    const any =
      (pillFull?.textContent.includes("Last: ") &&
        !pillFull?.textContent.includes("No backup")) ||
      (pillDb?.textContent.includes("Last: ") &&
        !pillDb?.textContent.includes("No backup")) ||
      (pillSettings?.textContent.includes("Last: ") &&
        !pillSettings?.textContent.includes("No backup"));

    pillStatus.textContent = any ? "Status: Recent backups" : "Status: No backup";
    pillStatus.className = "pill tiny " + (any ? "ok" : "muted");
  }

  async function savePrefs() {
    try {
      await fetch("/api/backup/prefs", {
        method: "POST",
        headers: _csrfHeaders(true),
        body: JSON.stringify({
          include_wg: !!optWG?.checked,
          send_to_telegram: !!optTG?.checked,
        }),
      });
    } catch {}
  }

  function autoFile(ts) {
    return fmtEpoch(ts, true).replace(",", " ·");
  }

  function autoSize(bytes) {
    if (!bytes || bytes <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    let val = bytes;
    while (val >= 1024 && i < units.length - 1) {
      val /= 1024;
      i++;
    }
    const prec = i === 0 ? 0 : 1;
    return `${val.toFixed(prec)} ${units[i]}`;
  }

  async function loadAutoFiles() {
    if (!autoFilesList || !autoFilesCount) return;
    autoFilesList.innerHTML = '<div class="tiny">Loading…</div>';

    try {
      const r = await fetch("/api/backups/auto", { headers: _csrfHeaders() });
      if (!r.ok) throw new Error("status " + r.status);
      const j = await r.json();
      const files = Array.isArray(j.files) ? j.files : [];

      autoFilesCount.textContent = `${files.length} file${
        files.length === 1 ? "" : "s"
      }`;

      if (!files.length) {
        autoFilesList.innerHTML =
          '<div class="tiny muted">No auto backups found yet.</div>';
        return;
      }

      autoFilesList.innerHTML = files
        .map((f) => {
          const niceDate = autoFile(f.ts);
          const sizeStr = autoSize(f.size);
          return `
            <div class="item">
              <div class="text">
                <div class="t1">${niceDate}</div>
                <div class="t2">
                  <span class="fname" title="${f.name}">${f.name}</span>
                  <span class="dot">•</span>
                  <span class="size">${sizeStr}</span>
                </div>
              </div>
              <button class="icon auto-restore-btn"
                      data-file="${f.name}"
                      title="Restore from this auto backup">
                <i class="fas fa-rotate-left"></i>
              </button>
            </div>`;
        })
        .join("");

      autoFilesList
        .querySelectorAll(".auto-restore-btn")
        .forEach((btn) =>
          btn.addEventListener("click", () => restoreAutoBackup(btn.dataset.file))
        );
    } catch (e) {
      console.error(e);
      autoFilesList.innerHTML =
        '<div class="tiny muted">Could not load auto backup list.</div>';
      autoFilesCount.textContent = "0 files";
    }
  }

  async function restoreAutoBackup(filename) {
    if (!filename) return;

    const ok = await confirmRestore(
      `<div style="margin-bottom:8px;">
         Restore from <code>${filename}</code>?
       </div>
       <div style="opacity:.92">
         This can overwrite your database (including peers, nodes and interfaces) and panel settings.
       </div>`
    );
    if (!ok) return;

    try {
      const resp = await fetch(
        `/api/backups/file/${encodeURIComponent(filename)}`
      );
      if (!resp.ok) {
        toastError("Could not download auto backup file from server.");
        return;
      }

      const blob = await resp.blob();
      const fd = new FormData();
      fd.append("file", blob, filename);
      fd.append("kind", "auto");
      if (restoreWGBox) fd.append("restore_wg", restoreWGBox.checked ? "1" : "0");

      const headers = _csrfHeaders();
      delete headers["Content-Type"];

      const r = await fetch("/api/backup/restore", {
        method: "POST",
        headers,
        body: fd,
      });

      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) {
        toastError(j.message || "Restore failed.");
        return;
      }

      toastSuccess(j.message || "Restore completed.");
      if (j.needs_restart) toastInfo("Restart the panel service to fully apply the restored data.");
      await loadAll();
    } catch (e) {
      console.error(e);
      toastError("Restore failed due to a network or server error.");
    }
  }

  async function triggerAutoBackup() {
    const url = `/api/backup/full?auto=1&wg=${autoWG?.checked ? "1" : "0"}&tg=${
      autoTG?.checked ? "1" : "0"
    }`;

    try {
      const resp = await fetch(url, { method: "GET", headers: _csrfHeaders() });
      if (!resp.ok) throw new Error("HTTP " + resp.status);

      toastSuccess("First auto backup created and saved in instance/backups/.");
      await loadAll();

      const details = document.getElementById("auto-files-details");
      if (details) details.open = true;
    } catch (e) {
      console.error(e);
      toastError("Could not create first auto backup – check logs.");
    }
  }

  async function loadAll() {
    try {
      const s = await fetch("/api/backup/status", {
        headers: _csrfHeaders(),
      }).then((r) => r.json());

      setLast(pillFull, s.full_last);
      setLast(pillDb, s.db_last);
      setLast(pillSettings, s.settings_last);
      updateStatus();

      const j = await fetch("/api/backup/schedule", {
        headers: _csrfHeaders(),
      }).then((r) => r.json());

      lastSchedule = j;

      if (autoEnabled) autoEnabled.checked = !!j.enabled;
      if (pillAuto) {
        pillAuto.textContent = j.enabled ? "Enabled" : "Disabled";
        pillAuto.className = "pill tiny " + (j.enabled ? "ok" : "warn");
      }

      if (selFreq) selFreq.value = j.freq || "daily";
      if (selTz) selTz.value = j.timezone || "UTC";
      if (inpTime) inpTime.value = j.time || "03:00";
      if (inpKeep) inpKeep.value = j.keep || 7;

      if (autoWG) autoWG.checked = !!j.include_wg;
      if (autoTG) autoTG.checked = !!j.send_to_telegram;

      setNext(j.next_run);
      updateFreqUI();

      const p = await fetch("/api/backup/prefs", {
        headers: _csrfHeaders(),
      }).then((r) => r.json());

      if (optWG) optWG.checked = !!p.include_wg;
      if (optTG) optTG.checked = !!p.send_to_telegram;

      await loadAutoFiles();
    } catch (e) {
      console.error(e);
      toastError("Failed to load backup state");
    }
  }

  btnFull?.addEventListener("click", async () => {
    await savePrefs();
    const url = `/api/backup/full?wg=${optWG?.checked ? "1" : "0"}&tg=${
      optTG?.checked ? "1" : "0"
    }`;
    const a = document.createElement("a");
    a.href = url;
    a.click();
    toastSuccess("Full backup started");
    setTimeout(loadAll, 1200);
  });

  btnDb?.addEventListener("click", async () => {
    const r = await fetch("/api/backup/db", { headers: _csrfHeaders() });
    if (r.ok) {
      window.location = "/api/backup/db";
      toastSuccess("Database backup ready");
      setTimeout(loadAll, 1200);
    } else {
      const j = await r.json().catch(() => ({}));
      if ((j.error || "").includes("db_not_found_or_not_sqlite")) {
        toastError("Database not found or not SQLite on this server.");
      } else {
        toastError("Database backup failed.");
      }
    }
  });

  btnSettings?.addEventListener("click", async () => {
    window.location = "/api/backup/settings";
    toastSuccess("Settings backup ready");
    setTimeout(loadAll, 1200);
  });

  autoEnabled?.addEventListener("change", async () => {
    const wasEnabled = !!(lastSchedule && lastSchedule.enabled);
    const wantEnabled = !!autoEnabled.checked;

    try {
      const payload = {
        enabled: wantEnabled,
        freq: selFreq?.value || "daily",
        time: inpTime?.value || "03:00",
        timezone: selTz?.value || "UTC",
        keep: parseInt(inpKeep?.value || "7", 10),
        include_wg: !!autoWG?.checked,
        send_to_telegram: !!autoTG?.checked,
      };

      const resp = await fetch("/api/backup/schedule", {
        method: "POST",
        headers: _csrfHeaders(true),
        body: JSON.stringify(payload),
      });

      const j = await resp.json().catch(() => ({}));
      if (!resp.ok || !j.ok) throw new Error(j.error || "HTTP " + resp.status);

      lastSchedule = j;
      setNext(j.next_run);
      toastSuccess("Auto-backup schedule saved.");

      if (!wasEnabled && j.enabled) {
        await triggerAutoBackup();
      } else {
        await loadAll();
      }
    } catch (e) {
      console.error(e);
      toastError(e.message || "Could not update auto-backup schedule.");
      autoEnabled.checked = wasEnabled;
    }
  });

  btnSave?.addEventListener("click", async () => {
    try {
      const payload = {
        enabled: !!autoEnabled?.checked,
        freq: selFreq?.value || "daily",
        time: inpTime?.value || "03:00",
        timezone: selTz?.value || "UTC",
        keep: parseInt(inpKeep?.value || "7", 10),
        include_wg: !!autoWG?.checked,
        send_to_telegram: !!autoTG?.checked,
      };

      const resp = await fetch("/api/backup/schedule", {
        method: "POST",
        headers: _csrfHeaders(true),
        body: JSON.stringify(payload),
      });

      const j = await resp.json().catch(() => ({}));
      if (!resp.ok || !j.ok) throw new Error(j.error || "HTTP " + resp.status);

      lastSchedule = j;
      setNext(j.next_run);
      toastSuccess("Auto-backup schedule saved.");
      await loadAll();
    } catch (e) {
      console.error(e);
      toastError(e.message || "Could not save schedule.");
    }
  });

  btnRunNow?.addEventListener("click", async () => {
    try {
      const url = `/api/backup/full?auto=1&wg=${autoWG?.checked ? "1" : "0"}&tg=${
        autoTG?.checked ? "1" : "0"
      }`;

      const resp = await fetch(url, { method: "GET", headers: _csrfHeaders() });
      if (!resp.ok) throw new Error("HTTP " + resp.status);

      toastSuccess("Auto backup (run once) completed and stored in instance/backups/.");
      await loadAll();

      const details = document.getElementById("auto-files-details");
      if (details) details.open = true;
    } catch (e) {
      console.error(e);
      toastError("Run once failed – check logs.");
    }
  });

  if (restoreTrigger && restoreFile) {
    restoreTrigger.addEventListener("click", () => restoreFile.click());
  }

  restoreFile?.addEventListener("change", () => {
    const file = restoreFile.files && restoreFile.files[0];
    if (!file) {
      if (restoreName) restoreName.textContent = "No file chosen";
      if (restoreHint)
        restoreHint.textContent =
          'Tip: “Auto-detect” will usually pick the correct restore mode for you.';
      return;
    }

    if (restoreName) restoreName.textContent = file.name;

    let detected = "unknown type";
    const n = file.name.toLowerCase();
    if (n.includes("_full_")) detected = "Full (DB + settings)";
    else if (n.includes("_db_")) detected = "Database only";
    else if (n.includes("_settings_")) detected = "Settings only";

    if (restoreHint)
      restoreHint.textContent = `Selected backup: ${detected}. Auto-detect will still inspect the ZIP contents to be sure.`;
  });

  restoreBtn?.addEventListener("click", async () => {
    const file = restoreFile?.files && restoreFile.files[0];
    if (!file) {
      toastError("Choose a backup .zip file first.");
      return;
    }

    const kindInput = document.querySelector('input[name="restore-kind"]:checked');
    const kind = (kindInput && kindInput.value) || "auto";
    const restoreWG = !!restoreWGBox?.checked;

    const ok = await confirmRestore(
      `<div style="margin-bottom:8px;">
         Are you sure you want to restore from this backup?
       </div>
       <div style="opacity:.92">
         This may overwrite your current database (including peers, nodes and interfaces) and/or panel settings.
       </div>`
    );
    if (!ok) return;

    const fd = new FormData();
    fd.append("file", file);
    fd.append("kind", kind);
    fd.append("restore_wg", restoreWG ? "1" : "0");

    try {
      const headers = _csrfHeaders();
      delete headers["Content-Type"];

      const r = await fetch("/api/backup/restore", {
        method: "POST",
        headers,
        body: fd,
      });

      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) {
        toastError(j.message || "Restore failed.");
        return;
      }

      toastSuccess(j.message || "Restore completed.");
      if (j.needs_restart) toastInfo("Restart the panel service to fully apply the restored data.");
      await loadAll();
    } catch (e) {
      console.error(e);
      toastError("Restore failed due to a network or server error.");
    }
  });

  loadAll();
})();

(function () {
  "use strict";

  // All backend timestamps represent UTC instants
  // APIs silently use the browser/device timezone.
  function wgPanelTimezone() {
    const value = String(window.WG_PANEL_TIMEZONE || "UTC").trim();
    return value || "UTC";
  }

  function wgPanelApplyTimezone(value, notify = true) {
    const timezone = String(value || "").trim();
    if (!timezone) return wgPanelTimezone();
    try {
      new Intl.DateTimeFormat("en", { timeZone: timezone }).format(new Date());
    } catch (_) {
      return wgPanelTimezone();
    }
    const previous = wgPanelTimezone();
    window.WG_PANEL_TIMEZONE = timezone;
    if (notify && previous !== timezone) {
      window.dispatchEvent(
        new CustomEvent("wgpanel:timezone-change", {
          detail: { timezone, previous },
        }),
      );
    }
    return timezone;
  }

  async function wgPanelRefreshTimezone() {
    const response = await fetch("/api/timezone?_=" + Date.now(), {
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    if (!response.ok)
      throw new Error("timezone endpoint returned " + response.status);
    const payload = await response.json();
    return wgPanelApplyTimezone(payload && payload.timezone);
  }

  function wgPanelDate(value) {
    if (value === null || value === undefined || value === "") return null;

    if (value instanceof Date) {
      return Number.isNaN(value.getTime()) ? null : value;
    }

    if (typeof value === "number") {
      const ms = Math.abs(value) < 1e12 ? value * 1000 : value;
      const date = new Date(ms);
      return Number.isNaN(date.getTime()) ? null : date;
    }

    let raw = String(value).trim();
    if (!raw) return null;

    if (/^\d{10,13}(?:\.\d+)?$/.test(raw)) {
      const n = Number(raw);
      const ms = raw.split(".")[0].length <= 10 ? n * 1000 : n;
      const date = new Date(ms);
      return Number.isNaN(date.getTime()) ? null : date;
    }

    if (
      /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?$/.test(raw)
    ) {
      raw = raw.replace(" ", "T") + "Z";
    }

    const date = new Date(raw);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function wgPanelFormatDateTime(value, options = {}) {
    const date = wgPanelDate(value);
    if (!date) return options.fallback ?? "–";

    const timezone = wgPanelTimezone();
    const seconds = !!options.seconds;
    const monthStyle = options.monthStyle || "2-digit";

    try {
      const parts = new Intl.DateTimeFormat("en-CA", {
        timeZone: timezone,
        year: "numeric",
        month: monthStyle,
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        ...(seconds ? { second: "2-digit" } : {}),
        hourCycle: "h23",
      }).formatToParts(date);

      const map = Object.fromEntries(
        parts.map((item) => [item.type, item.value]),
      );
      if (monthStyle === "2-digit") {
        return `${map.year}-${map.month}-${map.day} ${map.hour}:${map.minute}${seconds ? ":" + map.second : ""}`;
      }

      return new Intl.DateTimeFormat(undefined, {
        timeZone: timezone,
        year: "numeric",
        month: monthStyle,
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        ...(seconds ? { second: "2-digit" } : {}),
        hourCycle: "h23",
      }).format(date);
    } catch (error) {
      console.warn(
        "WG Panel timezone formatting failed; falling back to UTC.",
        timezone,
        error,
      );
      return new Intl.DateTimeFormat("en-CA", {
        timeZone: "UTC",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        ...(seconds ? { second: "2-digit" } : {}),
        hourCycle: "h23",
      })
        .format(date)
        .replace(",", "");
    }
  }

  function wgPanelFormatDateTimesInText(value) {
    const text = String(value ?? "");
    const isoPattern =
      /\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:?\d{2})\b/g;
    return text.replace(isoPattern, (match) =>
      wgPanelFormatDateTime(match, { seconds: true, fallback: match }),
    );
  }

  window.wgPanelTimezone = wgPanelTimezone;
  window.wgPanelApplyTimezone = wgPanelApplyTimezone;
  window.wgPanelRefreshTimezone = wgPanelRefreshTimezone;
  window.wgPanelDate = wgPanelDate;
  window.wgPanelFormatDateTime = wgPanelFormatDateTime;
  window.wgPanelFormatDateTimesInText = wgPanelFormatDateTimesInText;

  window.WG_PANEL_TIMEZONE_READY = Promise.resolve(
    window.WG_PANEL_TIMEZONE_READY,
  )
    .then((timezone) => wgPanelApplyTimezone(timezone, false))
    .catch(() => wgPanelTimezone());

  window.addEventListener("focus", () => {
    wgPanelRefreshTimezone().catch(() => {});
  });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) wgPanelRefreshTimezone().catch(() => {});
  });
  window.setInterval(() => {
    wgPanelRefreshTimezone().catch(() => {});
  }, 30000);

  window.toastSafe =
    window.toastSafe ||
    function (msg, type = "info", opts = false) {
      const map = {
        ok: "success",
        good: "success",
        success: "success",
        bad: "error",
        error: "error",
        warn: "warn",
        warning: "warn",
        info: "info",
      };
      const kind = map[type] || "info";
      let persist = false;
      let duration;
      if (typeof opts === "number") duration = opts;
      else if (typeof opts === "boolean") persist = opts;
      else if (opts && typeof opts === "object") {
        persist = !!opts.persist;
        duration = opts.duration;
      }
      if (typeof window.toast === "function") {
        const config = { persist };
        if (duration) config.duration = duration;
        return window.toast(String(msg ?? ""), kind, config);
      }
      (kind === "error" ? console.error : console.log)(msg);
      return null;
    };

  window.showToast =
    window.showToast ||
    ((m, t = "info", s = false) => window.toastSafe(m, t, s));
  window.toastInfo =
    window.toastInfo || ((m, s = false) => window.toastSafe(m, "info", s));
  window.toastWarn =
    window.toastWarn || ((m, s = false) => window.toastSafe(m, "warn", s));
  window.toastError =
    window.toastError || ((m, s = false) => window.toastSafe(m, "error", s));
  window.toastSuccess =
    window.toastSuccess ||
    ((m, s = false) => window.toastSafe(m, "success", s));

  window.csrfHeaders =
    window.csrfHeaders ||
    function (json) {
      const token =
        (document.cookie.match(/csrf_token=([^;]+)/) || [])[1] || "";
      const headers = { "X-CSRFToken": decodeURIComponent(token) };
      if (json) headers["Content-Type"] = "application/json";
      return headers;
    };

  function renderFlashes() {
    document
      .querySelectorAll("#flask-flashes [data-toast-message]")
      .forEach((row) => {
        window.toastSafe(
          row.dataset.toastMessage || "",
          row.dataset.toastCategory || "info",
        );
      });
  }

  function setupSidebar() {
    const sidebar = document.getElementById("panel-sidebar");
    const main = document.querySelector("main.main");
    const pin = document.getElementById("sb2-pin");
    const mobileButton = document.getElementById("wg-mobile-menu-btn");
    const mobileBackdrop = document.getElementById("wg-mobile-menu-backdrop");
    if (!sidebar || !main) return;

    const mq = window.matchMedia("(max-width: 760px)");
    const pinKey = "sb2:pinned";
    let lastFocus = null;

    function mobile() {
      return mq.matches;
    }

    function renderPin() {
      if (!pin) return;
      const collapsed = sidebar.classList.contains("is-collapsed");
      const icon = pin.querySelector("i");
      const label = pin.querySelector("span");
      if (icon)
        icon.className = collapsed
          ? "fas fa-angles-right"
          : "fas fa-angles-left";
      if (label)
        label.textContent = collapsed ? "Expand sidebar" : "Collapse sidebar";
      pin.setAttribute(
        "aria-label",
        collapsed ? "Expand sidebar" : "Collapse sidebar",
      );
      pin.setAttribute("aria-pressed", String(!collapsed));
    }

    function applyDesktopPreference() {
      let pinned = true;
      try {
        const stored = localStorage.getItem(pinKey);
        pinned = stored === null ? true : stored === "1";
      } catch (_) {}
      sidebar.classList.toggle("is-collapsed", !pinned);
      renderPin();
    }

    function setMobileOpen(open, restoreFocus = true) {
      open = mobile() && !!open;
      document.body.classList.toggle("wg-mobile-menu-open", open);
      if (mobileButton) {
        mobileButton.setAttribute("aria-expanded", String(open));
        mobileButton.setAttribute(
          "aria-label",
          open ? "Close menu" : "Open menu",
        );
      }
      if (open) {
        lastFocus = document.activeElement;
      } else if (
        restoreFocus &&
        lastFocus &&
        typeof lastFocus.focus === "function"
      ) {
        try {
          lastFocus.focus({ preventScroll: true });
        } catch (_) {}
      }
    }

    function toggleDesktopCollapse() {
      if (mobile()) return;
      const collapsed = sidebar.classList.toggle("is-collapsed");
      try {
        localStorage.setItem(pinKey, collapsed ? "0" : "1");
      } catch (_) {}
      renderPin();
    }

    if (mobileButton) {
      mobileButton.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        setMobileOpen(
          !document.body.classList.contains("wg-mobile-menu-open"),
          false,
        );
      });
    }

    if (mobileBackdrop) {
      mobileBackdrop.addEventListener("click", (event) => {
        event.preventDefault();
        setMobileOpen(false, true);
      });
    }

    if (pin) {
      pin.addEventListener("click", toggleDesktopCollapse);
      pin.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          toggleDesktopCollapse();
        }
      });
    }

    sidebar.addEventListener("click", (event) => {
      if (!mobile()) return;
      if (event.target.closest("nav a.sb2-link")) setMobileOpen(false, false);
    });

    document.addEventListener("keydown", (event) => {
      if (
        event.key === "Escape" &&
        document.body.classList.contains("wg-mobile-menu-open")
      ) {
        event.preventDefault();
        setMobileOpen(false, true);
      }
    });

    const updateOpen = document.getElementById("sb2-update-open");
    const updateModal = document.getElementById("panel-update-modal");
    if (updateOpen) {
      updateOpen.addEventListener(
        "pointerdown",
        () => setMobileOpen(false, false),
        true,
      );
      updateOpen.addEventListener(
        "click",
        () => {
          setMobileOpen(false, false);
          if (mobile()) document.body.classList.add("mobile-panel-update-open");
        },
        true,
      );
    }

    if (updateModal) {
      const syncUpdateState = () => {
        const isOpen =
          mobile() &&
          !updateModal.hidden &&
          updateModal.getAttribute("aria-hidden") !== "true";
        document.body.classList.toggle("mobile-panel-update-open", isOpen);
        if (isOpen) setMobileOpen(false, false);
      };
      new MutationObserver(syncUpdateState).observe(updateModal, {
        attributes: true,
        attributeFilter: ["hidden", "aria-hidden", "class"],
      });
      updateModal.addEventListener(
        "click",
        (event) => {
          if (event.target.closest("[data-pu-close]")) {
            queueMicrotask(() =>
              document.body.classList.remove("mobile-panel-update-open"),
            );
          }
        },
        true,
      );
      syncUpdateState();
    }

    const closeForForegroundControl = [
      "#theme-switcher",
      "[data-theme-choice]",
      ".panel-theme-switch",
      ".subx-theme-action",
      "#subx-panel-theme-toggle",
      "#sub-settings-modal",
      "[data-preview-theme]",
      "[data-preview-device]",
      "[data-preview-fit]",
      "[data-studio-tab]",
      "[data-studio-section]",
      "[data-template]",
      "[data-template-settings]",
      "[data-open-template]",
      "[data-open-studio]",
    ].join(",");

    document.addEventListener(
      "click",
      (event) => {
        if (!mobile()) return;
        const target = event.target?.closest?.(closeForForegroundControl);
        if (target) queueMicrotask(() => setMobileOpen(false, false));
      },
      true,
    );

    function applyMode() {
      if (mobile()) {
        document.documentElement.classList.add("wg-mobile-shell");
        sidebar.classList.remove("is-collapsed");
        setMobileOpen(false, false);
      } else {
        document.documentElement.classList.remove("wg-mobile-shell");
        setMobileOpen(false, false);
        applyDesktopPreference();
      }
    }

    if (typeof mq.addEventListener === "function")
      mq.addEventListener("change", applyMode);
    else mq.addListener?.(applyMode);

    applyMode();
  }

  function setupSubscriptionStudioForeground() {
    const modal = document.getElementById("sub-settings-modal");
    if (!modal) return;
    const mq = window.matchMedia("(max-width: 760px)");

    function sync() {
      const open =
        mq.matches &&
        (modal.classList.contains("open") ||
          modal.getAttribute("aria-hidden") === "false");
      document.body.classList.toggle("mobile-sub-studio-open", open);
      if (open) {
        document.body.classList.remove("wg-mobile-menu-open");
        document
          .getElementById("wg-mobile-menu-btn")
          ?.setAttribute("aria-expanded", "false");
      }
    }

    new MutationObserver(sync).observe(modal, {
      attributes: true,
      attributeFilter: ["class", "aria-hidden", "hidden"],
    });
    document.getElementById("open-sub-settings")?.addEventListener(
      "pointerdown",
      () => {
        document.body.classList.remove("wg-mobile-menu-open");
      },
      true,
    );
    if (typeof mq.addEventListener === "function")
      mq.addEventListener("change", sync);
    sync();
  }

  document.addEventListener("DOMContentLoaded", function () {
    renderFlashes();
    setupSidebar();
    setupSubscriptionStudioForeground();
  });
})();

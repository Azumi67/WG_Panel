"""Read-only diagnostics for the Operations workspace"""
from __future__ import annotations
import os
import shutil
import shlex
import stat
import subprocess
import time
from pathlib import Path
from .platform import detect_platform, package_install_commands


def finding(
    key,
    title,
    status,
    evidence,
    guide,
    repair=None,
    *,
    category="system",
    commands=None,
    impact="",
    manual_steps=None,
    panel_action=None,
    when_ok="",
    path_stages=None,
):
    return dict(
        id=key,
        title=title,
        status=status,
        evidence=evidence,
        guide=guide,
        repair=repair,
        category=category,
        commands=list(commands or []),
        impact=impact,
        manual_steps=list(manual_steps or []),
        panel_action=dict(panel_action) if isinstance(panel_action, dict) else None,
        when_ok=when_ok,
        path_stages=list(path_stages or []),
    )


def _repair(action: str, label: str, *, risk: str = "low", target=None, note: str = "") -> dict:
    data = {"action": action, "label": label, "risk": risk, "note": note}
    if target is not None:
        data["target"] = target
    return data


def _manual_step(title: str, text: str = "", commands=None) -> dict:
    return {"title": title, "text": text, "commands": list(commands or [])}


def _enrich_guidance(items, host, *, remote=False, root_path=None, instance_path=None):

    service = (host or {}).get("panel_service") or "wg-panel.service"
    env_q = shlex.quote(str(Path(root_path or ".") / ".env"))
    db_path = Path(instance_path or "instance") / "wg_panel.db"
    db_q = shlex.quote(str(db_path))
    backups_q = shlex.quote(str(Path(instance_path or "instance") / "backups"))

    def action(label, path, icon="fa-arrow-up-right-from-square", hint=""):
        return {"label": label, "path": path, "icon": icon, "hint": hint}

    for item in items:
        status = str(item.get("status") or "unknown")
        key = str(item.get("id") or "")
        commands = list(item.get("commands") or [])
        steps = list(item.get("manual_steps") or [])
        actions = []
        verification = {"text": "Run verification after the change.", "commands": []}

        if status == "pass":
            item.setdefault("severity", "healthy")
            item.setdefault("cause", "The check completed successfully.")
            item.setdefault("verification", {"text": "No action is required.", "commands": []})
            item.setdefault("actions", [])
            continue

        severity = "high" if status in {"warning", "unknown"} else "low"
        cause = item.get("guide") or item.get("evidence") or "The diagnostic requires review."

        if key.startswith("binary_"):
            binary = key.removeprefix("binary_")
            severity = "high" if status == "warning" else "medium"
            cause = f"{binary} is not available in the environment used by the panel service."
            if commands:
                steps = [
                    _manual_step("Install the missing component", "Run the detected package-manager commands in order.", commands),
                    _manual_step("Verify the executable", f"The command must be visible to the panel service after installation.", [f"command -v {binary}", f"{binary} --version 2>/dev/null || true"]),
                ]
            else:
                steps = [
                    _manual_step("Check the service PATH", "The package may already be installed but hidden from the service environment.", ["printf '%s\\n' \"$PATH\"", f"command -v {binary} || true", f"systemctl show {service} -p Environment -p EnvironmentFiles --no-pager"]),
                ]
            verification = {"text": f"WG Panel should be able to resolve {binary} in PATH.", "commands": [f"command -v {binary}"]}

        elif key == "panel_service":
            severity = "medium" if status == "review" else "high"
            cause = f"The configured service name ({service}) is not confirmed as the process currently serving this panel."
            actions = [
                action("Open Settings › Panel › Runtime", "/settings?tab=panel&sub=runtime&focus=rt-restart&from=operations", "fa-gear", "View the panel runtime configuration"),
                action("Open Application logs", "/logs?source=app&level=error&from=operations", "fa-file-lines", "Inspect recent startup/runtime errors"),
            ]
            steps = [
                _manual_step("Identify the real service manager", "Do this before restarting anything. If the panel uses Docker, supervisord, or another unit name, use that supervisor instead.", [f"systemctl status {service} --no-pager -l", "ps -eo pid,ppid,user,cmd | grep -E 'gunicorn|python.*app.py|wg-panel' | grep -v grep"]),
                _manual_step("Read the first startup error", "The earliest actionable error is usually more useful than repeated restart attempts.", [f"journalctl -u {service} -b -n 160 --no-pager"]),
                _manual_step("If this is the correct unit, verify its configuration", "Confirm the unit points at this installation and uses the intended service account.", [f"systemctl show {service} -p LoadState -p ActiveState -p WorkingDirectory -p ExecStart -p User -p Group --no-pager", f"systemctl cat {service}"]),
                _manual_step("Restart only after the cause is understood", "Use this only when the unit is confirmed to be the panel you are viewing.", [f"systemctl restart {service}", f"systemctl is-active {service}"]),
            ]
            verification = {"text": "The intended panel service should report active and the web/API should remain reachable.", "commands": [f"systemctl is-active {service}", f"systemctl status {service} --no-pager -l"]}
            item["when_ok"] = "If this panel is intentionally launched by Docker, supervisord, a custom systemd unit, or a development process, the default wg-panel.service state can be ignored."

        elif key == "forwarding":
            severity = "high" if status == "warning" else "low"
            cause = "Kernel IPv4 forwarding is disabled. The scan only treats this as a problem when local WireGuard hooks appear to route or masquerade peer traffic."
            actions = [action("Open Settings › Interface", "/settings?tab=iface&focus=iface-select&from=operations", "fa-network-wired", "Review the selected interface and its runtime state")]
            steps = [
                _manual_step("Confirm this host routes peers", "Look for MASQUERADE/FORWARD behavior in the intended interface before changing a kernel-wide setting."),
                _manual_step("Check the current value", commands=["sysctl net.ipv4.ip_forward"]),
                _manual_step("Enable and persist forwarding", "Only do this when the server is supposed to act as a gateway.", ["sysctl -w net.ipv4.ip_forward=1", "printf '%s\\n' 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-wg-panel-forwarding.conf", "sysctl --system"]),
                _manual_step("Verify routing", commands=["sysctl net.ipv4.ip_forward", "ip route", "nft list ruleset 2>/dev/null | sed -n '1,220p'"]),
            ]
            verification = {"text": "Forwarding must read 1 and the intended FORWARD/NAT policy must still be present.", "commands": ["sysctl net.ipv4.ip_forward", "ip route"]}
            item["when_ok"] = "If this machine only hosts the web panel and never forwards WireGuard traffic, forwarding may intentionally remain disabled."

        elif key == "env_mode":
            severity = "high" if status == "warning" else "medium"
            cause = "The environment file can be read by group or other users, or its location could not be verified."
            steps = [
                _manual_step("Inspect permissions only", "Do not print the file contents.", [f"stat -c '%a %U:%G %n' {env_q}"]),
                _manual_step("Restrict access", "Keep the owner permissions and remove group/other access.", [f"chmod go-rwx {env_q}"]),
                _manual_step("Verify", commands=[f"stat -c '%a %U:%G %n' {env_q}"]),
            ]
            verification = {"text": "Group/other permission bits should be removed.", "commands": [f"stat -c '%a %U:%G %n' {env_q}"]}

        elif key == "session_cookie_secure":
            severity = "medium"
            cause = "The Secure cookie flag is not enabled in the running configuration. This matters on a public HTTPS deployment."
            actions = [action("Open Settings › Panel › TLS", "/settings?tab=panel&sub=tls&focus=tls-enabled&from=operations", "fa-lock", "Confirm the public panel is fully HTTPS")]
            steps = [
                _manual_step("Confirm the public URL is HTTPS", "Do not enable Secure cookies on a temporary HTTP-only development endpoint until HTTPS works."),
                _manual_step("Check the environment setting", "For HTTPS production, SECURE_COOKIES should be 1.", [f"grep -n '^SECURE_COOKIES=' {env_q} 2>/dev/null || true"]),
                _manual_step("Update and restart if needed", "Edit only the SECURE_COOKIES value, then restart the correct panel service.", [f"nano {env_q}", f"systemctl restart {service}"]),
            ]
            verification = {"text": "Log in through the public HTTPS URL and confirm the session cookie is marked Secure.", "commands": []}
            item["when_ok"] = "This can be intentional on a temporary plain-HTTP development installation."

        elif key in {"session_cookie_httponly", "session_cookie_samesite"}:
            severity = "high"
            cause = "A session-cookie hardening flag in the running Flask configuration is weaker than the panel expects."
            actions = [action("Open Settings › Panel › TLS", "/settings?tab=panel&sub=tls&focus=tls-enabled&from=operations", "fa-lock", "Review the public panel security configuration")]
            steps = [
                _manual_step("Confirm the running configuration", "These are application session settings, not WireGuard settings.", [f"systemctl show {service} -p Environment -p EnvironmentFiles --no-pager", f"journalctl -u {service} -n 80 --no-pager"]),
                _manual_step("Correct the application setting", "Use HttpOnly and SameSite=Lax or Strict, restart the correct service, then test login/logout."),
            ]
            verification = {"text": "The next diagnostic should report the session-cookie check as healthy.", "commands": []}

        elif key == "proxy_trust":
            severity = "low"
            cause = "ProxyFix is enabled, but a local scan cannot prove that only a trusted reverse proxy/CDN can reach the application listener or overwrite forwarding headers."
            actions = [
                action("Open Settings › Panel › Runtime", "/settings?tab=panel&sub=runtime&focus=rt2-bind&from=operations", "fa-gear", "Review the exact bind/listener setting"),
                action("Open Application logs", "/logs?source=app&from=operations", "fa-file-lines", "Check recorded client addresses"),
            ]
            steps = [
                _manual_step("Identify the direct listener", "Confirm which address and port the app actually listens on.", ["ss -lntp", f"systemctl show {service} -p ExecStart -p Environment --no-pager"]),
                _manual_step("Confirm the firewall path", "Keep SSH and the trusted reverse proxy path reachable while restricting direct application access.", ["nft list ruleset 2>/dev/null || true", "ufw status verbose 2>/dev/null || true"]),
                _manual_step("Verify real client IP logging", "Only rely on IP-based blocking after requests through the proxy show the expected client IP."),
            ]
            verification = {"text": "A request through the public proxy should log the real client IP, while direct untrusted access to the app listener should be blocked.", "commands": []}
            item["when_ok"] = "This is advisory when the listener is already private or restricted to a trusted proxy/CDN."

        elif key == "http_protection":
            severity = "low" if status == "review" else "high"
            cause = "WG Panel HTTP protection is disabled or could not be confirmed. This may be intentional on a private deployment."
            actions = [action("Open Settings › Security › HTTP protection", "/settings?tab=security&focus=sec-enabled&from=operations", "fa-shield-halved", "Open the HTTP protection switch and policy controls")]
            steps = [
                _manual_step("Open Security settings", "Start in Monitor mode so real traffic is observed before any blocking is enabled."),
                _manual_step("Verify client-IP detection", "Confirm IP source and trusted networks first; a wrong source can block your proxy or admin path."),
                _manual_step("Enable blocking only after observation", "Choose thresholds based on your real request rate and keep a recovery path."),
            ]
            verification = {"text": "Security status should show the intended response mode and trusted-network configuration.", "commands": []}
            item["when_ok"] = "HTTP protection can remain disabled when another trusted access layer already protects a private panel."

        elif key == "firewall_backend":
            severity = "high" if status == "warning" else "low"
            cause = "Kernel-level HTTP firewall escalation is configured but nftables is not usable by the panel, or the feature is intentionally disabled."
            actions = [action("Open Settings › Security › Advanced firewall", "/settings?tab=security&open=security-advanced&focus=sec-firewall-enabled&from=operations", "fa-shield-halved", "Open the nftables escalation control directly")]
            steps = [
                _manual_step("Check nftables availability", commands=["nft --version", "nft list ruleset"]),
                _manual_step("Check the panel service permissions", "Privileges are needed only when kernel-level escalation is enabled.", [f"systemctl show {service} -p User -p Group -p CapabilityBoundingSet -p AmbientCapabilities --no-pager"]),
                _manual_step("Preserve the existing firewall", "Do not flush the ruleset. Keep SSH, panel, tunnel, WireGuard, and established-connection rules intact."),
            ]
            verification = {"text": "The Security page should report nftables as usable when host-firewall escalation is enabled.", "commands": ["nft --version"]}
            item["when_ok"] = "Application-level HTTP blocking works without kernel firewall escalation when that second layer is intentionally disabled."

        elif key.startswith("json_"):
            name = key.removeprefix("json_")
            safe_path = Path(instance_path or "instance") / name.replace("'", "")
            q = shlex.quote(str(safe_path))
            severity = "high"
            cause = f"{name} is unreadable, oversized, or not a valid JSON object. The file contents were intentionally not included in the diagnostic."
            actions = [action("Open Backup", "/backup?from=operations", "fa-box-archive", "Create or inspect a verified backup before editing settings files")]
            steps = [
                _manual_step("Back up the file", "Create a copy before editing it.", [f"cp -a {q} {q}.bak.$(date +%s)"]),
                _manual_step("Validate JSON", "This command only reports syntax validity when output is redirected.", [f"python3 -m json.tool {q} >/dev/null"]),
                _manual_step("Recover carefully", "Correct the syntax or restore a known-good copy. Do not replace the file with an empty object just to clear the warning."),
            ]
            verification = {"text": "The JSON parser should exit successfully and the panel feature using this file should load normally.", "commands": [f"python3 -m json.tool {q} >/dev/null && echo OK"]}

        elif key == "backups":
            severity = "medium"
            cause = "No recent local automatic backup was found, or the newest backup is older than the recommended window."
            actions = [action("Open Backup", "/backup?from=operations", "fa-box-archive", "Create a full backup and review retention")]
            steps = [
                _manual_step("Create a full backup", "Use Backup → Full backup and include WireGuard configuration when required."),
                _manual_step("Confirm a recent archive exists", commands=[f"find {backups_q} -maxdepth 1 -type f -name '*.zip' -printf '%TY-%Tm-%Td %TH:%TM %10s %p\\n' 2>/dev/null | sort | tail -20"]),
                _manual_step("Store a copy off-server", "A backup on the same VPS does not protect against disk loss or host compromise."),
            ]
            verification = {"text": "A recent backup should exist and a test restore should periodically be performed on an isolated installation.", "commands": []}

        elif key == "db_integrity":
            severity = "critical"
            cause = "SQLite quick_check reported a structural issue. The diagnostic withholds row/content details."
            actions = [
                action("Open Backup first", "/backup?from=operations", "fa-box-archive", "Create a verified copy before recovery"),
                action("Open Application logs", "/logs?source=app&level=error&from=operations", "fa-file-lines", "Inspect database-related application errors"),
            ]
            steps = [
                _manual_step("Stop making configuration changes", "Avoid peer/settings writes until a verified backup exists."),
                _manual_step("Create a full backup", "Use the panel Backup page before any database recovery."),
                _manual_step("Re-check an isolated copy", commands=[f"python3 -c \"import sqlite3; c=sqlite3.connect({repr(str(db_path))}); print(c.execute('PRAGMA quick_check').fetchone()[0]); c.close()\""]),
                _manual_step("Recover from a copy, not the live file", "Do not delete or recreate the production database as a repair shortcut."),
            ]
            verification = {"text": "An isolated copy should pass PRAGMA quick_check before it is considered for recovery.", "commands": []}

        elif key == "database":
            severity = "critical" if status == "unknown" else "high"
            cause = "The application could not confirm normal database connectivity."
            actions = [
                action("Open Application logs", "/logs?source=app&level=error&from=operations", "fa-file-lines", "Inspect the database error context"),
                action("Open Backup", "/backup?from=operations", "fa-box-archive", "Protect the current data before recovery"),
            ]
            steps = [
                _manual_step("Check the database path and panel logs", commands=[f"ls -lh {db_q} 2>/dev/null || true", f"journalctl -u {service} -n 120 --no-pager"]),
                _manual_step("Verify the configured connection", "Confirm DATABASE_URL, path ownership, filesystem space, and service account. Do not recreate the database to clear a connection error."),
            ]
            verification = {"text": "The panel should complete SELECT 1 and, for SQLite, a bounded quick_check.", "commands": []}

        elif key == "listen_ports":
            severity = "high"
            cause = "Two or more configured local interfaces reuse a WireGuard listen port. That is only valid when they are isolated in separate namespaces."
            actions = [
                action("Open Settings › Interface › Listen port", "/settings?tab=iface&focus=i-listen&from=operations", "fa-network-wired", "Select an interface and review its ListenPort value"),
                action("Open Peers", "/users?from=operations", "fa-users", "Return to interface/peer management"),
            ]
            steps = [
                _manual_step("Compare configured and active listeners", commands=["wg show", "ss -lnup"]),
                _manual_step("Resolve only real conflicts", "Interfaces active in the same namespace normally require unique listen ports. Change a port only after confirming the collision."),
            ]
            verification = {"text": "Each simultaneously active interface in the same namespace should have a non-conflicting UDP listen port.", "commands": ["wg show", "ss -lnup"]}

        elif key.startswith("iface_"):
            severity = "high" if "missing" in str(item.get("evidence", "")).lower() else "medium"
            cause = "The saved local WireGuard interface does not match the expected runtime/configuration state."
            iface_id = key.removeprefix("iface_") if key.removeprefix("iface_").isdigit() else ""
            settings_path = f"/settings?tab=iface&focus=iface-up&from=operations{('&iface_id=' + iface_id) if iface_id else ''}"
            actions = [
                action("Open Settings › Interface", settings_path, "fa-network-wired", "Open this exact interface and highlight its runtime control"),
                action("Open Peers", "/users?from=operations", "fa-users", "Review this interface together with its peers"),
            ]
            steps = [
                _manual_step("Inspect the interface", commands=commands[:1] or ["wg show"]),
                _manual_step("Confirm configuration and hooks", "Check Address, ListenPort, PostUp/PostDown, and required firewall/NAT behavior before starting it."),
                _manual_step("Start and verify", commands=commands[1:] if len(commands) > 1 else []),
            ]
            verification = {"text": "The intended interface should appear in wg show and its expected UDP listener should be present.", "commands": commands[:1] or ["wg show"]}
            item["when_ok"] = "A deliberately disabled interface does not need repair."

        elif key == "network_path":
            severity = "high" if status == "warning" else "low"
            cause = "This is a read-only path readiness summary. It combines WireGuard runtime, gateway forwarding, default routing, firewall tooling, and resolver readiness without sending test traffic or changing the host."
            actions = [
                action("Open Peers › Interface", "/users?from=operations", "fa-network-wired", "Review the selected WireGuard interface and peer state"),
                action("Open Settings › Interface", "/settings?tab=iface&focus=iface-select&from=operations", "fa-sliders", "Review interface networking and hooks"),
            ]
            steps = [
                _manual_step("Start with the failed stage", "Use the path strip above to identify where readiness stops. Do not change healthy stages."),
                _manual_step("Review the matching panel control", "Open the related interface or network setting and correct only the failed condition."),
                _manual_step("Run verification", "Return to Operations. A fresh verification rebuilds the path readiness result."),
            ]
            verification = {"text": "All required stages in Network path readiness should report Ready or Not required.", "commands": ["wg show", "ip route show default", "sysctl net.ipv4.ip_forward"]}
            item["when_ok"] = "Forwarding can legitimately show Not required when this host is not configured as a WireGuard gateway."

        elif key in {"nodes", "node_health", "node_version", "node_scope"}:
            severity = "high" if status == "unknown" else "low"
            cause = "Remote-node health is limited to authenticated API checks from this panel; host-level checks cannot be inferred safely."
            actions = [action("Open Nodes", "/nodes?from=operations", "fa-server", "Review node URL, enabled state, and last seen")]
            steps = [
                _manual_step("Check the node record", "Confirm its saved URL, enabled state, and last-seen status without exposing the API key."),
                _manual_step("On the node, inspect the agent", commands=["systemctl status wg-node-agent.service --no-pager -l", "journalctl -u wg-node-agent.service -n 120 --no-pager"]),
                _manual_step("Verify intended network reachability", "The panel server must reach the node listener through the configured firewall path."),
            ]
            verification = {"text": "The authenticated node health endpoint should respond consistently from the panel server.", "commands": []}
            item["when_ok"] = "Remote scan coverage is intentionally limited unless the node agent exposes a specific authenticated diagnostic endpoint."

        elif key == "ufw_state":
            severity = "low" if status == "review" else "medium"
            cause = "UFW is active on this host. An active firewall is not a problem by itself, but its rules must allow the panel and intended WireGuard traffic."
            actions = [action("Open Settings › Security › Advanced firewall", "/settings?tab=security&open=http-security-advanced&focus=hs-firewall-enabled&from=operations", "fa-shield-halved", "Review WG Panel firewall integration without replacing host policy")]
            steps = [
                _manual_step("Review UFW state", "Do not disable the firewall just to clear this advisory.", ["ufw status verbose", "ufw status numbered"]),
                _manual_step("Confirm required listeners", "Compare active WireGuard/panel listeners with the rules you intentionally allow.", ["ss -lntup", "wg show"]),
                _manual_step("Adjust only the missing rule", "Add or remove a specific rule only after confirming the intended service and source network."),
            ]
            verification = {"text": "The intended panel and WireGuard services should remain reachable while UFW stays consistent with your policy.", "commands": ["ufw status numbered", "ss -lntup"]}
            item["when_ok"] = "UFW can stay enabled. This is a review item because firewall policy is deployment-specific."

        elif key == "time_sync":
            severity = "medium" if status == "warning" else "low"
            cause = "The host clock is not confirmed as synchronized. Accurate time is important for logs, expiry timers, TLS, and troubleshooting."
            steps = [
                _manual_step("Inspect time synchronization", commands=["timedatectl status", "timedatectl show -p NTPSynchronized --value"]),
                _manual_step("Enable the host NTP client if appropriate", "On systemd hosts this normally enables the configured time synchronization service.", ["timedatectl set-ntp true"]),
                _manual_step("Verify synchronization", commands=["timedatectl show -p NTPSynchronized --value", "date --iso-8601=seconds"]),
            ]
            verification = {"text": "NTPSynchronized should report yes, or your alternate time service should report a synchronized clock.", "commands": ["timedatectl show -p NTPSynchronized --value"]}
            item["when_ok"] = "Containers or hosts using chrony/ntpd may legitimately not report synchronization through systemd-timesyncd."

        elif key == "unattended_upgrades":
            severity = "low"
            cause = "Automatic APT security updates are not confirmed as enabled. This is a host-maintenance choice, not a WireGuard fault."
            steps = [
                _manual_step("Review the current policy", commands=["systemctl is-enabled unattended-upgrades.service 2>/dev/null || true", "apt-config dump | grep -E 'APT::Periodic|Unattended-Upgrade' | head -80"]),
                _manual_step("Enable automatic security updates if desired", "Use the distribution-supported unattended-upgrades configuration and review its reboot policy before enabling it.", ["apt-get update", "apt-get install -y unattended-upgrades", "dpkg-reconfigure -plow unattended-upgrades"]),
                _manual_step("Verify the service and policy", commands=["systemctl is-enabled unattended-upgrades.service", "systemctl status unattended-upgrades.service --no-pager -l"]),
            ]
            verification = {"text": "The unattended-upgrades service/policy should be enabled only when that matches your maintenance policy.", "commands": ["systemctl is-enabled unattended-upgrades.service 2>/dev/null || true"]}
            item["when_ok"] = "Manual patching or another patch-management system can be a valid alternative."

        elif key == "pending_reboot":
            severity = "low"
            cause = "The operating system reports that a reboot is pending, usually after a kernel or core-library update."
            steps = [
                _manual_step("Review why a reboot is pending", commands=["cat /var/run/reboot-required.pkgs 2>/dev/null || true", "uname -r"]),
                _manual_step("Schedule a maintenance window", "Confirm WireGuard/panel recovery and remote access before rebooting. Do not reboot automatically from Operations."),
                _manual_step("Verify after reboot", commands=["uptime", "uname -r", "wg show", f"systemctl is-active {service} 2>/dev/null || true"]),
            ]
            verification = {"text": "The reboot-required marker should be gone and the intended panel/WireGuard services should be healthy.", "commands": ["test ! -e /var/run/reboot-required && echo 'No reboot pending' || echo 'Reboot still pending'"]}

        elif key == "keepalive_coverage":
            severity = "low"
            cause = "Some peers do not define PersistentKeepalive. That is normal for many clients, but NATed/mobile peers may need it to keep inbound reachability."
            actions = [action("Open Peers", "/users?from=operations", "fa-users", "Review peer connectivity and edit only peers that need keepalive")]
            steps = [
                _manual_step("Identify peers that actually need keepalive", "Use it mainly for peers behind NAT/firewalls that must remain reachable while idle."),
                _manual_step("Edit only those peers", "A common value is 25 seconds, but do not apply it globally without a connectivity reason."),
                _manual_step("Verify handshakes", commands=["wg show"]),
            ]
            verification = {"text": "Affected peers should maintain the expected handshake/reachability without unnecessary keepalive traffic on every peer.", "commands": ["wg show"]}
            item["when_ok"] = "PersistentKeepalive is optional and should not be enabled for every peer by default."

        elif key == "disk":
            severity = "high"
            cause = "The filesystem holding panel state has little free capacity or free space could not be confirmed."
            actions = [action("Open Backup", "/backup?from=operations", "fa-box-archive", "Protect data before removing old files")]
            steps = [
                _manual_step("Find the pressure", commands=commands or ["df -hT", "df -ih"]),
                _manual_step("Remove only reviewed data", "Prefer old logs/backups that have already been copied elsewhere. Never delete the live database or WireGuard configuration to free space."),
                _manual_step("Verify free space", commands=["df -hT", "df -ih"]),
            ]
            verification = {"text": "Free space and inode availability should return to a safe margin.", "commands": ["df -hT", "df -ih"]}

        else:
            if commands:
                steps = [_manual_step("Inspect this finding", item.get("guide") or "Review the finding before changing anything.", commands)]
                verification = {"text": "Re-run the diagnostic after the change.", "commands": commands[:1]}
            else:
                steps = [
                    _manual_step("Follow the finding-specific recommendation", item.get("guide") or "Review this condition in the relevant panel page."),
                    _manual_step("If the check itself failed", "Inspect recent application errors without exposing secrets.", [f"journalctl -u {service} -n 120 --no-pager"]),
                ]
                verification = {"text": "Re-run the diagnostic and confirm this finding no longer needs attention.", "commands": []}

        item["severity"] = severity
        item["cause"] = cause
        item["manual_steps"] = steps
        item["verification"] = verification
        item["actions"] = actions
        if actions:
            item["panel_action"] = actions[0]

    return items



def network_path_snapshot(app, context):
    """Return the read-only host path stages used by Operations and peer diagnosis."""
    stages = []
    model = context.get("InterfaceConfig")
    rows = model.query.filter_by(node_id=None).all() if model is not None else []
    names = [str(getattr(row, "name", "") or "") for row in rows if getattr(row, "name", None)]
    router_expected = any(
        any(token in str(getattr(row, "post_up", "") or "").upper() for token in ("MASQUERADE", "FORWARD"))
        for row in rows
    )

    wg = shutil.which("wg")
    active = set()
    if wg:
        try:
            proc = subprocess.run([wg, "show", "interfaces"], capture_output=True, text=True, timeout=4, check=False)
            if proc.returncode == 0:
                active = set(proc.stdout.split())
        except Exception:
            active = set()
    runtime_ok = bool(active.intersection(names)) if names else True
    stages.append({
        "id": "wireguard", "label": "WireGuard",
        "state": "ready" if runtime_ok else ("attention" if names else "not_required"),
        "detail": (f"{len(active.intersection(names))} local interface(s) active" if names else "No local interface configured"),
    })

    try:
        forwarding_value = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
    except Exception:
        forwarding_value = "unknown"
    forwarding_ok = forwarding_value == "1"
    stages.append({
        "id": "forwarding", "label": "Forwarding",
        "state": "ready" if (not router_expected or forwarding_ok) else "attention",
        "detail": "Not required" if not router_expected else ("Enabled" if forwarding_ok else "Disabled"),
    })

    ip = shutil.which("ip")
    default_route = False
    if ip:
        try:
            proc = subprocess.run([ip, "route", "show", "default"], capture_output=True, text=True, timeout=4, check=False)
            default_route = proc.returncode == 0 and bool(proc.stdout.strip())
        except Exception:
            default_route = False
    if not ip:
        route_state, route_detail = "review", "ip tool unavailable"
    elif default_route:
        route_state, route_detail = "ready", "Available"
    else:
        route_state = "attention" if router_expected else "review"
        route_detail = "Not detected"
    stages.append({"id": "route", "label": "Default route", "state": route_state, "detail": route_detail})

    firewall_tool = "nftables" if shutil.which("nft") else ("UFW" if shutil.which("ufw") else "")
    stages.append({
        "id": "firewall", "label": "Firewall",
        "state": "ready" if firewall_tool else "review",
        "detail": firewall_tool or "No supported tool detected",
    })

    resolver = Path("/etc/resolv.conf")
    resolver_ok = False
    try:
        resolver_ok = resolver.is_file() and any(
            line.strip().startswith("nameserver ") for line in resolver.read_text(errors="ignore").splitlines()
        )
    except Exception:
        resolver_ok = False
    stages.append({
        "id": "dns", "label": "Resolver",
        "state": "ready" if resolver_ok else "review",
        "detail": "Configured" if resolver_ok else "Could not confirm nameserver",
    })
    return stages

def collect(app, context):
    results = []
    host = detect_platform()

    def add(*args, **kwargs):
        results.append(finding(*args, **kwargs))

    def check(key, title, action, guide, *, category="system"):
        try:
            action()
        except Exception as exc:
            add(
                key,
                title,
                "unknown",
                "Check could not complete (" + type(exc).__name__ + ").",
                guide,
                category=category,
            )

    def disk():
        total, used, free = shutil.disk_usage(app.instance_path)
        percent = free / total * 100 if total else 0
        warning = percent < 10 or free < 512 * 1024**2
        add(
            "disk",
            "Available disk space",
            "warning" if warning else "pass",
            f"{free/1024**3:.2f} GiB free ({percent:.1f}%).",
            "Inspect disk usage before deleting anything. Remove only reviewed old logs or backups and keep a separate verified backup.",
            category="storage",
            commands=["df -hT", "du -xh /opt /var/log 2>/dev/null | sort -h | tail -40"],
            impact="Low free space can break database writes, backups, updates, and log rotation.",
        )

    check("disk", "Available disk space", disk, "Check access to the panel instance directory and disk usage.", category="storage")

    binary_specs = (
        ("wg", "WireGuard control utility", "wireguard_tools", "Install WireGuard tools"),
        ("wg-quick", "WireGuard interface helper", "wireguard_tools", "Install WireGuard tools"),
        ("nft", "nftables utility", "nftables", "Install nftables"),
        ("ip", "iproute utility", "iproute", "Install iproute tools"),
        ("systemctl", "systemd service manager", None, None),
    )
    for name, title, package_key, repair_label in binary_specs:
        found = shutil.which(name)
        commands = package_install_commands(package_key, host) if package_key and not found else []
        repair = None
        if package_key and not found and commands:
            repair = _repair(
                "install_" + package_key,
                repair_label,
                risk="low",
                note="Installs the missing package only; it does not enable a firewall ruleset or rewrite WireGuard configuration.",
            )
        add(
            "binary_" + name,
            title,
            "pass" if found else "warning",
            "Executable found in the service PATH." if found else "Executable not found in the service PATH.",
            "Use the OS-specific command below or the automatic repair when available. If the package is already installed, inspect the service PATH before reinstalling.",
            repair,
            category="packages",
            commands=commands,
            impact=("Required by WG Panel for this feature." if name != "systemctl" else "A custom container/supervisor may legitimately not provide systemctl."),
        )

    def service():
        if not shutil.which("systemctl"):
            add(
                "panel_service",
                "Panel service",
                "review",
                "systemctl is unavailable; the panel may be running in a container or under a different supervisor.",
                "Inspect the actual process supervisor used by this deployment.",
                category="service",
            )
            return
        service_name = (os.getenv("PANEL_SERVICE_NAME") or "wg-panel.service").strip() or "wg-panel.service"
        process = subprocess.run(
            ["systemctl", "show", service_name, "--property=LoadState,ActiveState"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        values = dict(line.split("=", 1) for line in process.stdout.splitlines() if "=" in line)
        loaded = values.get("LoadState") == "loaded"
        active = values.get("ActiveState") == "active"
        add(
            "panel_service",
            "Panel service",
            "pass" if loaded and active else "review",
            f"{service_name} is loaded and active." if loaded and active else f"{service_name} is not loaded/active; a custom service or container may be in use.",
            "Inspect status and recent logs. Resolve the first startup error before restarting repeatedly.",
            category="service",
            commands=[
                f"systemctl status {service_name} --no-pager -l",
                f"journalctl -u {service_name} -n 120 --no-pager",
            ],
        )

    check("panel_service", "Panel service", service, "Inspect the panel service manager on the host; systemctl may be unavailable in a container.", category="service")

    def forwarding():
        value = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
        enabled = value == "1"
        model = context.get("InterfaceConfig")
        router_expected = False
        try:
            rows = model.query.filter_by(node_id=None).all() if model is not None else []
            router_expected = any(
                any(token in str(getattr(row, "post_up", "") or "").upper() for token in ("MASQUERADE", "FORWARD"))
                for row in rows
            )
        except Exception:
            router_expected = False
        forwarding_status = "pass" if enabled else ("warning" if router_expected else "review")
        add(
            "forwarding",
            "IPv4 forwarding",
            forwarding_status,
            f"net.ipv4.ip_forward = {value}",
            "WireGuard gateways normally need IPv4 forwarding. Review the FORWARD/nftables policy first, then enable it persistently if this host routes peer traffic.",
            None if enabled or not router_expected else _repair(
                "enable_ipv4_forwarding",
                "Enable IPv4 forwarding",
                risk="medium",
                note="Writes a dedicated sysctl.d file and enables forwarding immediately. Review firewall forwarding policy first.",
            ),
            category="network",
            commands=[
                "sysctl net.ipv4.ip_forward",
                "sysctl -w net.ipv4.ip_forward=1",
                "printf '%s\\n' 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-wg-panel-forwarding.conf",
                "sysctl --system",
            ],
            impact="If this host is only a panel and never routes peers, forwarding may intentionally be disabled.",
        )

    check("forwarding", "IPv4 forwarding", forwarding, "Check /proc/sys/net/ipv4/ip_forward on the host.", category="network")

    def permissions():
        path = Path(app.root_path) / ".env"
        if not path.exists():
            add(
                "env_mode",
                "Environment file permissions",
                "unknown",
                "No .env file at the application root; environment may be supplied by the service.",
                "Review ownership and mode of the actual service environment file without printing its contents.",
                category="security",
                commands=["stat -c '%a %U:%G %n' .env 2>/dev/null || true"],
            )
            return
        mode = stat.S_IMODE(path.lstat().st_mode)
        eligible = path.is_file() and not path.is_symlink() and path.stat().st_uid == os.geteuid()
        add(
            "env_mode",
            "Environment file permissions",
            "warning" if mode & 0o077 else "pass",
            f"Permission mode {mode:03o}; contents were not read.",
            "Only the panel service account should read this file. The automatic repair removes group/other access while preserving owner bits.",
            _repair("restrict_env", "Restrict .env permissions", risk="low") if mode & 0o077 and eligible else None,
            category="security",
            commands=["chmod go-rwx .env", "stat -c '%a %U:%G %n' .env"],
            impact="An overly permissive .env can expose API keys, encryption keys, bot tokens, or service credentials to other local users.",
        )

    check("env_mode", "Environment file permissions", permissions, "Inspect ownership and permissions of .env without printing its contents.", category="security")

    for key in ("SESSION_COOKIE_HTTPONLY", "SESSION_COOKIE_SECURE", "SESSION_COOKIE_SAMESITE"):
        val = app.config.get(key)
        good = val in ("Lax", "Strict") if key.endswith("SAMESITE") else val is True
        add(
            key.lower(),
            key.replace("_", " ").title(),
            "pass" if good else "warning",
            str(val),
            "Use HttpOnly, SameSite=Lax or Strict, and Secure when serving the public panel over HTTPS. Verify login through the actual public URL after any change.",
            category="security",
        )

    add(
        "proxy_trust",
        "Reverse proxy trust boundary",
        "review",
        "ProxyFix is enabled. This scan cannot verify which public hosts can reach the panel listener.",
        "If behind a proxy/CDN, restrict direct access to the panel listener and ensure the proxy overwrites forwarded headers. Verify logged client IPs before relying on IP-based blocking.",
        category="security",
    )

    def security():
        loader = context.get("_load_http_security_settings")
        if not callable(loader):
            raise RuntimeError("security settings loader unavailable")
        settings = loader()
        enabled = bool(settings.get("enabled"))
        add(
            "http_protection",
            "HTTP protection",
            "pass" if enabled else "review",
            ("Enabled; response mode: " + str(settings.get("response_mode", "unknown"))) if enabled else "Disabled; this can be intentional on a private panel.",
            "Open Settings → Security. Verify client-IP detection and trusted networks first. Start in monitor mode, inspect events, then choose blocking thresholds appropriate to your traffic.",
            category="security",
        )

    check("http_protection", "HTTP protection", security, "Open Settings → Security and verify that settings can be loaded.", category="security")

    def firewall():
        loader = context.get("_load_http_security_settings")
        status_fn = context.get("_http_security_nft_status")
        if not callable(loader) or not callable(status_fn):
            raise RuntimeError("firewall capability helpers unavailable")
        settings = loader()
        status = status_fn(settings)
        configured = bool(settings.get("firewall_enabled"))
        usable = bool(status.get("usable"))
        add(
            "firewall_backend",
            "HTTP firewall backend",
            "warning" if configured and not usable else "pass" if usable else "review",
            f"Firewall integration: {'enabled' if configured else 'disabled'}; nftables access: {'usable' if usable else 'unavailable'}.",
            "Check nftables installation and the panel service privileges. Do not flush the ruleset or replace UFW rules. Application HTTP blocking and kernel firewall blocking are separate layers.",
            category="security",
            commands=["nft --version", "nft list ruleset"],
        )

    check("firewall_backend", "HTTP firewall backend", firewall, "Open Settings → Security and inspect firewall capabilities.", category="security")

    def ufw_state():
        ufw = shutil.which("ufw")
        if not ufw:
            add("ufw_state", "UFW firewall state", "pass", "UFW is not installed; another firewall may be in use.", "No UFW-specific action is required.", category="firewall")
            return
        completed = subprocess.run([ufw, "status"], capture_output=True, text=True, timeout=4, check=False)
        if completed.returncode != 0:
            raise RuntimeError("ufw status failed")
        first = next((line.strip() for line in completed.stdout.splitlines() if line.strip()), "")
        active = first.lower().startswith("status: active")
        add(
            "ufw_state", "UFW firewall state", "review" if active else "pass",
            "UFW is active; review intended panel/WireGuard allowances." if active else "UFW is inactive.",
            "Keep the firewall enabled when it is part of your policy; review only the rules needed by this deployment.",
            category="firewall", commands=["ufw status verbose", "ufw status numbered"],
            impact="An incorrect host firewall rule can block the panel, WireGuard UDP, or routed peer traffic."
        )
    check("ufw_state", "UFW firewall state", ufw_state, "Inspect UFW state without changing rules.", category="firewall")

    def time_sync():
        timedatectl = shutil.which("timedatectl")
        if not timedatectl:
            add("time_sync", "System time synchronization", "review", "timedatectl is unavailable; another time service or container clock may be in use.", "Verify host time synchronization using the platform's time service.", category="system")
            return
        completed = subprocess.run([timedatectl, "show", "-p", "NTPSynchronized", "--value"], capture_output=True, text=True, timeout=4, check=False)
        if completed.returncode != 0:
            raise RuntimeError("timedatectl failed")
        value = completed.stdout.strip().lower()
        synced = value == "yes"
        add("time_sync", "System time synchronization", "pass" if synced else "warning", f"NTPSynchronized = {value or 'unknown'}", "Accurate host time is required for reliable logs, expiry timers and TLS troubleshooting.", category="system", commands=["timedatectl status", "timedatectl show -p NTPSynchronized --value"])
    check("time_sync", "System time synchronization", time_sync, "Check the host time synchronization service.", category="system")

    if host.get("package_manager") == "apt":
        def unattended_upgrades():
            binary = shutil.which("unattended-upgrade")
            enabled = False
            if shutil.which("systemctl"):
                completed = subprocess.run(["systemctl", "is-enabled", "unattended-upgrades.service"], capture_output=True, text=True, timeout=4, check=False)
                enabled = completed.returncode == 0 and completed.stdout.strip() in {"enabled", "enabled-runtime", "static"}
            good = bool(binary and enabled)
            add("unattended_upgrades", "Automatic APT security updates", "pass" if good else "review", "unattended-upgrades is installed and enabled." if good else "Automatic APT security updates are not confirmed as enabled.", "Review your patch-management policy; enable unattended-upgrades only if it matches the host maintenance plan.", category="system", commands=["systemctl is-enabled unattended-upgrades.service 2>/dev/null || true", "apt-config dump | grep -E 'APT::Periodic|Unattended-Upgrade' | head -80"])
        check("unattended_upgrades", "Automatic APT security updates", unattended_upgrades, "Review APT automatic security update configuration.", category="system")

    def pending_reboot():
        pending = Path("/var/run/reboot-required").exists()
        add("pending_reboot", "Pending reboot", "review" if pending else "pass", "The operating system reports a reboot is required." if pending else "No reboot-required marker is present.", "Schedule a controlled reboot only after confirming remote access and service recovery.", category="system", commands=["cat /var/run/reboot-required.pkgs 2>/dev/null || true", "uname -r"])
    check("pending_reboot", "Pending reboot", pending_reboot, "Check the distribution reboot-required marker.", category="system")

    def keepalive_coverage():
        model = context.get("Peer")
        if model is None:
            raise RuntimeError("peer model unavailable")
        rows = model.query.all()
        local_rows = [peer for peer in rows if getattr(getattr(peer, "iface", None), "node_id", None) is None]
        configured = sum(1 for peer in local_rows if int(getattr(peer, "persistent_keepalive", 0) or 0) > 0)
        total = len(local_rows)
        missing = max(0, total - configured)
        status = "review" if total and missing else "pass"
        add("keepalive_coverage", "PersistentKeepalive coverage", status, f"{configured} of {total} local peers have PersistentKeepalive configured.", "PersistentKeepalive is optional. Review only peers behind NAT/firewalls that must remain reachable while idle.", category="wireguard", commands=["wg show"])
    check("keepalive_coverage", "PersistentKeepalive coverage", keepalive_coverage, "Review local peer PersistentKeepalive configuration.", category="wireguard")

    def settings_files():
        import json
        for name in ("template_settings.json", "backup_settings.json", "backup_schedule.json"):
            path = Path(app.instance_path) / name
            if not path.exists():
                continue
            try:
                if path.stat().st_size > 2 * 1024 * 1024:
                    raise ValueError("Too large")
                value = json.loads(path.read_text())
                valid = isinstance(value, dict)
            except Exception:
                valid = False
            add(
                "json_" + name,
                "Settings file: " + name,
                "pass" if valid else "warning",
                "Valid JSON object." if valid else "Unreadable, oversized, or invalid JSON object; contents are withheld.",
                "Make a copy before editing. Restore from a verified backup or correct JSON syntax offline. Do not replace the file with an empty object just to silence the error.",
                category="storage",
            )

    check("settings_files", "Settings file integrity", settings_files, "Check access to the panel instance directory.", category="storage")

    def backups():
        root = Path(context.get("BACKUP_AUTO_DIR", Path(app.instance_path) / "backups"))
        files = [p for p in root.glob("*.zip") if p.is_file()] if root.exists() else []
        newest = max((p.stat().st_mtime for p in files), default=0)
        age = max(0, (time.time() - newest) / 86400) if newest else None
        add(
            "backups",
            "Automatic backup freshness",
            "pass" if age is not None and age <= 7 else "warning",
            f"Newest ZIP is {age:.1f} days old; restoreability is not verified." if age is not None else "No local automatic backup ZIP found.",
            "Open Backup, create a full backup, download it off-server, inspect the archive, and periodically test restoration on an isolated installation.",
            category="storage",
            impact="A local backup on the same disk does not protect against disk loss or host compromise.",
        )

    check("backups", "Backup freshness", backups, "Check automatic backup directory access.", category="storage")

    def database():
        from sqlalchemy import text
        db = context.get("db")
        if db is None:
            raise RuntimeError("database handle unavailable")
        engine = db.engine
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            if engine.dialect.name == "sqlite":
                raw = connection.connection.driver_connection
                deadline = time.monotonic() + 2
                raw.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
                try:
                    messages = connection.execute(text("PRAGMA quick_check(1)")).scalars().all()
                finally:
                    raw.set_progress_handler(None, 0)
                good = messages == ["ok"]
                add(
                    "db_integrity",
                    "SQLite structural integrity",
                    "pass" if good else "warning",
                    "Bounded quick_check passed." if good else "SQLite reported a structural issue; details are withheld to avoid exposing data.",
                    "Stop writes and make a filesystem/database backup before recovery. Test recovery on an isolated copy; never delete the live database to repair it.",
                    category="database",
                )
            else:
                add(
                    "db_integrity",
                    "Database structural integrity",
                    "review",
                    "Automatic integrity checks are limited to SQLite.",
                    "Use database-specific integrity tooling against an isolated backup.",
                    category="database",
                )
        add(
            "database",
            "Database connectivity",
            "pass",
            "Read-only SELECT 1 succeeded.",
            "Connectivity is healthy; this does not verify every application table or accounting invariant.",
            category="database",
        )

    check("database", "Database connectivity", database, "Check database service availability and configured connection. Do not delete or recreate the database to repair connectivity.", category="database")

    def interfaces():
        model = context.get("InterfaceConfig")
        if model is None:
            raise RuntimeError("interface model unavailable")
        rows = model.query.filter_by(node_id=None).all()
        if not shutil.which("wg"):
            raise RuntimeError("wg unavailable")
        completed = subprocess.run(["wg", "show", "interfaces"], capture_output=True, text=True, timeout=4, check=False)
        if completed.returncode != 0:
            raise RuntimeError("wg show failed")
        active = set(completed.stdout.split())
        ports = {}
        for row in rows:
            ports.setdefault(row.listen_port, []).append(row.name)
        duplicates = sum(1 for names in ports.values() if len(names) > 1)
        add(
            "listen_ports",
            "Local interface port assignments",
            "warning" if duplicates else "pass",
            f"{duplicates} duplicate listen-port assignment(s) in the database.",
            "Confirm whether interfaces intentionally run in separate namespaces. Simultaneously active interfaces in the same namespace normally need unique listen ports.",
            category="wireguard",
            commands=["wg show", "ss -lnup"],
        )
        for row in rows:
            present = bool(row.path and Path(row.path).is_file())
            online = row.name in active
            repair = None
            commands = []
            safe_name = str(row.name or "")
            if safe_name and all(ch.isalnum() or ch in "_.-" for ch in safe_name):
                commands = [f"wg show {safe_name}", f"wg-quick up {safe_name}"]
            if present and not online and callable(context.get("_check_iface_up")):
                repair = _repair(
                    "start_interface",
                    "Start interface",
                    risk="medium",
                    target=int(row.id),
                    note="Runs the panel's existing interface bring-up logic. Review PostUp/PostDown hooks before using it.",
                )
            add(
                "iface_" + str(row.id),
                "Local interface: " + str(row.name),
                "pass" if present and online else "warning",
                f"Configuration file: {'present' if present else 'missing'}; runtime: {'up' if online else 'down'}.",
                "A deliberately stopped interface can be expected. Back up the configuration, confirm Address/ListenPort and firewall hooks, then start it. Restore missing files only from a verified backup; private keys are never regenerated automatically.",
                repair,
                category="wireguard",
                commands=commands,
            )
        if not rows:
            add("interfaces", "Local interfaces", "pass", "No local interfaces configured.", "Create an interface from Peers when needed.", category="wireguard")

    check("interfaces", "Local interface state", interfaces, "Check wg availability, service permissions, and database access. No interface configuration was executed by the scan.", category="wireguard")

    def network_path():
        stages = []
        model = context.get("InterfaceConfig")
        rows = model.query.filter_by(node_id=None).all() if model is not None else []
        names = [str(getattr(row, "name", "") or "") for row in rows if getattr(row, "name", None)]
        router_expected = any(
            any(token in str(getattr(row, "post_up", "") or "").upper() for token in ("MASQUERADE", "FORWARD"))
            for row in rows
        )

        wg = shutil.which("wg")
        active = set()
        if wg:
            proc = subprocess.run([wg, "show", "interfaces"], capture_output=True, text=True, timeout=4, check=False)
            if proc.returncode == 0:
                active = set(proc.stdout.split())
        runtime_ok = bool(active.intersection(names)) if names else True
        stages.append({
            "id": "wireguard", "label": "WireGuard",
            "state": "ready" if runtime_ok else ("attention" if names else "not_required"),
            "detail": (f"{len(active.intersection(names))} local interface(s) active" if names else "No local interface configured"),
        })

        forwarding_value = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() if Path("/proc/sys/net/ipv4/ip_forward").exists() else "unknown"
        forwarding_ok = forwarding_value == "1"
        stages.append({
            "id": "forwarding", "label": "Forwarding",
            "state": "ready" if (not router_expected or forwarding_ok) else "attention",
            "detail": "Not required" if not router_expected else ("Enabled" if forwarding_ok else "Disabled"),
        })

        ip = shutil.which("ip")
        default_route = False
        if ip:
            proc = subprocess.run([ip, "route", "show", "default"], capture_output=True, text=True, timeout=4, check=False)
            default_route = proc.returncode == 0 and bool(proc.stdout.strip())
        if not ip:
            route_state = "review"
            route_detail = "ip tool unavailable"
        elif default_route:
            route_state = "ready"
            route_detail = "Available"
        else:
            route_state = "attention" if router_expected else "review"
            route_detail = "Not detected"
        stages.append({
            "id": "route", "label": "Default route",
            "state": route_state,
            "detail": route_detail,
        })

        firewall_tool = "nftables" if shutil.which("nft") else ("UFW" if shutil.which("ufw") else "")
        stages.append({
            "id": "firewall", "label": "Firewall",
            "state": "ready" if firewall_tool else "review",
            "detail": firewall_tool or "No supported tool detected",
        })

        resolver = Path("/etc/resolv.conf")
        resolver_ok = False
        try:
            resolver_ok = resolver.is_file() and any(
                line.strip().startswith("nameserver ") for line in resolver.read_text(errors="ignore").splitlines()
            )
        except Exception:
            resolver_ok = False
        stages.append({
            "id": "dns", "label": "Resolver",
            "state": "ready" if resolver_ok else "review",
            "detail": "Configured" if resolver_ok else "Could not confirm nameserver",
        })

        required_attention = [stage for stage in stages if stage["state"] == "attention"]
        review = [stage for stage in stages if stage["state"] == "review"]
        if required_attention:
            status = "warning"
        elif review:
            status = "review"
        else:
            status = "pass"
        ready = sum(1 for stage in stages if stage["state"] in {"ready", "not_required"})
        add(
            "network_path",
            "Network path readiness",
            status,
            f"{ready} of {len(stages)} path stages are ready or not required.",
            "Use the path view to identify the first stage that needs attention, then correct only that stage and verify again.",
            category="network",
            commands=["wg show", "ip route show default", "sysctl net.ipv4.ip_forward", "nft list ruleset 2>/dev/null || ufw status verbose 2>/dev/null || true"],
            impact="A failed required stage can prevent peers from reaching routed networks even when the WireGuard interface itself is up.",
            path_stages=stages,
        )

    check("network_path", "Network path readiness", network_path, "Inspect WireGuard runtime, forwarding, default route, firewall tooling, and resolver readiness.", category="network")

    add(
        "nodes",
        "Remote node diagnostics",
        "review",
        "Remote hosts are not deeply scanned in this local scan.",
        "Select a node from the Server menu for authenticated API health/version checks. Host-level disk, firewall, forwarding, and file-permission checks still need to run on that node itself.",
        category="nodes",
    )
    return _enrich_guidance(results, host, root_path=app.root_path, instance_path=app.instance_path)


def _sanitize_remote_finding(raw):
    """Validate one node-agent diagnostic finding before exposing it in UI."""
    if not isinstance(raw, dict):
        return None
    status = str(raw.get("status") or "unknown").lower()
    if status not in {"pass", "warning", "review", "unknown"}:
        status = "unknown"
    repair = raw.get("repair") if isinstance(raw.get("repair"), dict) else None
    if repair:
        action = str(repair.get("action") or "")
        if action not in {
            "restrict_env", "enable_ipv4_forwarding", "start_interface",
            "install_wireguard_tools", "install_nftables", "install_iproute",
        }:
            repair = None
        else:
            repair = {
                "action": action,
                "label": str(repair.get("label") or action.replace("_", " ").title())[:120],
                "risk": str(repair.get("risk") or "low") if str(repair.get("risk") or "low") in {"low", "medium"} else "medium",
                "note": str(repair.get("note") or "")[:300],
            }
            if raw.get("repair", {}).get("target") is not None:
                repair["target"] = str(raw["repair"]["target"])[:64]
    path_stages = []
    for stage in raw.get("path_stages") or []:
        if not isinstance(stage, dict):
            continue
        state = str(stage.get("state") or stage.get("status") or "review")[:24]
        if state not in {"ready", "not_required", "attention", "review"}:
            state = "review"
        path_stages.append({
            "id": str(stage.get("id") or "")[:40],
            "label": str(stage.get("label") or "")[:80],
            "state": state,
            "detail": str(stage.get("detail") or "")[:180],
        })
    return finding(
        str(raw.get("id") or "remote_check")[:96],
        str(raw.get("title") or "Remote node check")[:180],
        status,
        str(raw.get("evidence") or "")[:500],
        str(raw.get("guide") or "Review this finding on the node.")[:700],
        repair,
        category=str(raw.get("category") or "nodes")[:64],
        commands=[str(x)[:500] for x in (raw.get("commands") or [])[:12]],
        impact=str(raw.get("impact") or "")[:500],
        path_stages=path_stages,
    )


def collect_node_report(context, node):
    """Return a full authenticated Operations report for a remote node.

    New node agents expose host-local diagnostics. Older agents fall back to
    the legacy health/version checks so updating the panel does not make an
    existing node unusable.
    """
    getter = context.get("node_get")
    if not callable(getter):
        raise RuntimeError("node client unavailable")

    try:
        payload = getter(node, "/api/operations/diagnostic", timeout=12)
        if not isinstance(payload, dict) or payload.get("ok") is False:
            raise ValueError("Invalid node diagnostic response")
        remote_profile = payload.get("system") if isinstance(payload.get("system"), dict) else {}
        profile = {
            "hostname": str(remote_profile.get("hostname") or getattr(node, "name", "Remote node"))[:120],
            "os": str(remote_profile.get("os") or "Linux node")[:160],
            "id": str(remote_profile.get("id") or "linux")[:40],
            "id_like": str(remote_profile.get("id_like") or "")[:120],
            "version": str(remote_profile.get("version") or "")[:64],
            "codename": str(remote_profile.get("codename") or "")[:64],
            "kernel": str(remote_profile.get("kernel") or "")[:120],
            "architecture": str(remote_profile.get("architecture") or "")[:80],
            "package_manager": str(remote_profile.get("package_manager") or "")[:40],
            "package_manager_path": "",  
            "systemd": bool(remote_profile.get("systemd")),
            "sysctl": bool(remote_profile.get("sysctl")),
            "nftables": bool(remote_profile.get("nftables")),
            "wireguard": bool(remote_profile.get("wireguard")),
            "wg_quick": bool(remote_profile.get("wg_quick")),
            "iproute": bool(remote_profile.get("iproute")),
            "panel_service": "wg-node-agent.service",
            "remote_agent": True,
            "node_agent_version": str(remote_profile.get("node_agent_version") or "")[:64],
        }
        items = []
        for raw in payload.get("checks") or []:
            item = _sanitize_remote_finding(raw)
            if item:
                items.append(item)
        if not items:
            raise ValueError("Node diagnostic returned no checks")
        enriched = _enrich_guidance(items, profile, remote=True)
        for item in enriched:
            item["remote"] = True
            item["node_id"] = getattr(node, "id", None)
            item["node_name"] = getattr(node, "name", "") or ""
            if str(item.get("status") or "") != "pass":
                item["actions"] = [{
                    "label": "Open Nodes",
                    "path": f"/nodes?node_id={getattr(node, 'id', '')}&from=operations",
                    "icon": "fa-server",
                    "hint": "Review this node, its interfaces, and agent state",
                }]
                item["panel_action"] = item["actions"][0]
                inspect_commands = list(item.get("commands") or [])[:4]
                if item.get("repair"):
                    item["manual_steps"] = [
                        _manual_step("Review the node finding", item.get("guide") or "Confirm this condition on the selected node.", inspect_commands[:1]),
                        _manual_step("Choose automatic repair or SSH", "Automatic repair uses the node agent allowlist. If you prefer manual recovery, run only the finding-specific commands on this node.", inspect_commands[1:]),
                        _manual_step("Verify from Operations", "Return here and run verification. The issue is not closed until the node reports the healthy state."),
                    ]
                else:
                    item["manual_steps"] = [
                        _manual_step("Open the selected node", "Use Nodes to confirm agent reachability, interface assignment, and the server you intend to change."),
                        _manual_step("Inspect only this condition", item.get("guide") or "Review this condition on the node before changing anything.", inspect_commands),
                        _manual_step("Verify from Operations", "After the manual change, run verification against the same node."),
                    ]
                item["verification"] = {
                    "text": "Run a fresh diagnostic against this node and confirm the finding is healthy.",
                    "commands": inspect_commands[:1],
                }
                if str(item.get("id") or "").startswith("iface_"):
                    item["cause"] = "The WireGuard configuration exists on the selected node, but its runtime state does not match the expected active state."
                elif item.get("id") == "env_mode":
                    item["cause"] = "The node agent environment file is readable by users other than its owner. Secret values were not read by the diagnostic."
                elif item.get("id") == "network_path":
                    item["cause"] = "The selected node reported its own WireGuard, forwarding, route, firewall and resolver readiness. No test traffic was sent."
        return {"system": profile, "checks": enriched, "legacy": False}
    except Exception:
        results = []
        try:
            health = getter(node, "/api/health", timeout=4)
            if not isinstance(health, dict):
                raise ValueError("Invalid node response")
            results.append(finding(
                "node_health", "Node API health",
                "warning" if health.get("ok") is False else "pass",
                "Authenticated health endpoint responded.",
                "Update the node agent to enable full host diagnostics from Operations.",
                category="nodes",
            ))
            version = str(health.get("version", "not reported"))[:64]
            results.append(finding(
                "node_version", "Node version", "review", version,
                "Update the node agent when practical. Full remote Operations requires the v16 diagnostic contract.",
                category="nodes",
            ))
        except Exception as exc:
            results.append(finding(
                "node_health", "Node API health", "unknown",
                "Health request failed (" + type(exc).__name__ + ").",
                "Check the node service, API listener, firewall path, and saved URL/key in Nodes. Do not expose the API key in logs or screenshots.",
                category="nodes",
            ))
        results.append(finding(
            "node_scope", "Remote diagnostic coverage", "review",
            "This node agent does not expose the v16 Operations diagnostic endpoint.",
            "Update the node agent to unlock host-local WireGuard, forwarding, route, firewall, DNS, disk, time and rollback-aware repair checks.",
            category="nodes",
        ))
        profile = {
            "hostname": str(getattr(node, "name", "Remote node") or "Remote node")[:120],
            "os": "Remote node (legacy agent)", "id": "linux", "id_like": "", "version": "", "codename": "",
            "kernel": "", "architecture": "", "package_manager": "", "package_manager_path": "",
            "systemd": False, "sysctl": False, "nftables": False, "wireguard": False,
            "wg_quick": False, "iproute": False, "panel_service": "wg-node-agent.service",
            "remote_agent": True,
        }
        return {"system": profile, "checks": _enrich_guidance(results, profile, remote=True), "legacy": True}


def collect_node(context, node):
    """Backward-compatible list-only wrapper used by older call sites/tests."""
    return collect_node_report(context, node)["checks"]

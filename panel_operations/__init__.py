"""Operations endpoints"""
from __future__ import annotations
import fcntl
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user

from auth import admin_required
from .checks import collect, collect_node, collect_node_report
from .platform import command_guide, detect_platform, package_install_argv


_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
_PACKAGE_ACTIONS = {
    "install_wireguard_tools": ("wireguard_tools", ("wg", "wg-quick")),
    "install_nftables": ("nftables", ("nft",)),
    "install_iproute": ("iproute", ("ip",)),
}


def register_operations(app, context):
    bp = Blueprint("operations", __name__)
    root = Path(app.instance_path) / "operations"

    @contextmanager
    def locked():
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(root / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield

    @contextmanager
    def history_connection():
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        connection = sqlite3.connect(root / "history.sqlite3", timeout=3)
        try:
            with connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts REAL, actor TEXT, kind TEXT, payload TEXT)"
                )
                yield connection
        finally:
            connection.close()

    def record(kind, payload):
        with history_connection() as connection:
            connection.execute(
                "INSERT INTO events(ts, actor, kind, payload) VALUES(?,?,?,?)",
                (time.time(), str(current_user.get_id()), kind, json.dumps(payload)),
            )
            connection.execute(
                "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 150)"
            )

    def counts(checks):
        out = {"pass": 0, "warning": 0, "review": 0, "unknown": 0}
        for item in checks or []:
            key = str(item.get("status") or "unknown")
            out[key] = out.get(key, 0) + 1
        return out


    def _snapshot_dir():
        path = root / "repair-snapshots"
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        return path

    def _write_snapshot(action, payload):
        token = uuid.uuid4().hex
        data = {
            "version": 1,
            "action": action,
            "created_at": time.time(),
            "actor": str(current_user.get_id()),
            "payload": payload,
        }
        path = _snapshot_dir() / f"{token}.json"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        return {
            "token": token,
            "action": action,
            "expires_at": data["created_at"] + 86400,
            "label": "Restore previous state",
        }

    def _read_snapshot(token):
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{32}", token):
            raise ValueError("Invalid rollback token.")
        path = _snapshot_dir() / f"{token}.json"
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError as exc:
            raise ValueError("Rollback snapshot is no longer available.") from exc
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            data = json.load(stream)
        if not isinstance(data, dict) or data.get("version") != 1:
            raise ValueError("Rollback snapshot is invalid.")
        created = float(data.get("created_at") or 0)
        if created <= 0 or time.time() - created > 86400:
            try:
                path.unlink()
            except OSError:
                pass
            raise ValueError("Rollback snapshot has expired.")
        return path, data

    def _rollback_snapshot(token):
        _require_root()
        path, data = _read_snapshot(token)
        action = str(data.get("action") or "")
        payload = data.get("payload") if isinstance(data.get("payload"), dict) else {}

        if action == "restrict_env":
            env_path = Path(app.root_path) / ".env"
            fd = os.open(env_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                    raise RuntimeError("The .env file is no longer eligible for rollback.")
                before_mode = int(payload.get("mode"))
                expected_mode = int(payload.get("expected_mode"))
                if before_mode < 0 or before_mode > 0o7777 or expected_mode < 0 or expected_mode > 0o7777:
                    raise RuntimeError("The saved permission mode is invalid.")
                current = stat.S_IMODE(info.st_mode)
                if current != expected_mode:
                    raise RuntimeError("The .env permissions changed after the repair; refusing to overwrite the newer state.")
                os.fchmod(handle.fileno(), before_mode)
                verified = stat.S_IMODE(os.fstat(handle.fileno()).st_mode) == before_mode
                if not verified:
                    raise RuntimeError("Permission rollback verification failed.")
            result = {
                "action": action,
                "before": f"{current:03o}",
                "after": f"{before_mode:03o}",
                "verified": True,
                "message": f"Previous .env permissions restored: {current:03o} → {before_mode:03o}.",
            }

        elif action == "enable_ipv4_forwarding":
            proc_path = Path("/proc/sys/net/ipv4/ip_forward")
            previous_runtime = str(payload.get("runtime") or "0")
            if previous_runtime not in {"0", "1"}:
                raise RuntimeError("The saved forwarding value is invalid.")
            target = Path("/etc/sysctl.d/99-wg-panel-forwarding.conf")
            had_file = bool(payload.get("had_file"))
            backup_name = str(payload.get("backup_name") or "")
            expected_runtime = str(payload.get("expected_runtime") or "1")
            expected_content = str(payload.get("expected_content") or "")
            if expected_runtime not in {"0", "1"} or not expected_content:
                raise RuntimeError("The forwarding rollback snapshot is incomplete.")
            if proc_path.read_text().strip() != expected_runtime:
                raise RuntimeError("IPv4 forwarding changed after the repair; refusing to overwrite the newer state.")
            if target.is_symlink() or not target.is_file() or target.read_text(errors="ignore") != expected_content:
                raise RuntimeError("The forwarding configuration changed after the repair; refusing to overwrite the newer state.")
            backup = None
            if had_file:
                if not re.fullmatch(r"99-wg-panel-forwarding\.conf\.\d+\.[0-9a-f]{8}\.bak", backup_name):
                    raise RuntimeError("The rollback backup reference is invalid.")
                backup = root / "repair-backups" / backup_name
                if not backup.is_file() or backup.is_symlink():
                    raise RuntimeError("The rollback backup is unavailable.")
                shutil.copyfile(backup, target)
                file_mode = int(payload.get("file_mode") or 0o644)
                if file_mode < 0 or file_mode > 0o7777:
                    raise RuntimeError("The saved forwarding file mode is invalid.")
                os.chmod(target, file_mode)
            else:
                if target.exists():
                    if target.is_symlink() or not target.is_file():
                        raise RuntimeError("Refusing to remove a non-regular forwarding configuration path.")
                    target.unlink()

            sysctl = shutil.which("sysctl")
            if sysctl:
                completed = subprocess.run(
                    [sysctl, "-w", f"net.ipv4.ip_forward={previous_runtime}"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10, check=False,
                )
                if completed.returncode != 0:
                    raise RuntimeError("sysctl could not restore IPv4 forwarding.")
            else:
                proc_path.write_text(previous_runtime)
            if proc_path.read_text().strip() != previous_runtime:
                raise RuntimeError("IPv4 forwarding rollback did not verify.")
            if backup is not None:
                backup.unlink(missing_ok=True)
            result = {
                "action": action,
                "verified": True,
                "after": previous_runtime,
                "message": "Previous IPv4 forwarding state restored and verified.",
            }
        else:
            raise ValueError("This repair does not support automatic rollback.")

        path.unlink(missing_ok=True)
        return result

    def _require_root():
        if os.geteuid() != 0:
            raise PermissionError("The panel service must run as root for this repair.")

    def _run_fixed_steps(steps, timeout=180):
        _require_root()
        summaries = []
        for argv in steps:
            completed = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                check=False,
                env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
            )
            summaries.append({"program": Path(argv[0]).name, "returncode": int(completed.returncode)})
            if completed.returncode != 0:
                raise RuntimeError(f"{Path(argv[0]).name} returned exit status {completed.returncode}")
        return summaries

    def _repair_restrict_env():
        path = Path(app.root_path) / ".env"
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise RuntimeError("Repair requires a regular .env file owned by the panel service account.")
            before = stat.S_IMODE(info.st_mode)
            after = before & ~0o077
            rollback = _write_snapshot("restrict_env", {"mode": before, "expected_mode": after})
            os.fchmod(handle.fileno(), after)
            verified = stat.S_IMODE(os.fstat(handle.fileno()).st_mode) == after
            if not verified:
                raise RuntimeError("Permission verification failed")
        return {
            "action": "restrict_env",
            "before": f"{before:03o}",
            "after": f"{after:03o}",
            "verified": True,
            "message": f".env permissions verified: {before:03o} → {after:03o}.",
            "rollback": rollback,
        }

    def _repair_package(action):
        package_key, binaries = _PACKAGE_ACTIONS[action]
        profile = detect_platform()
        steps = package_install_argv(package_key, profile)
        if not steps:
            raise RuntimeError("Automatic package installation is not available for this OS/package manager.")
        before = {binary: bool(shutil.which(binary)) for binary in binaries}
        execution = _run_fixed_steps(steps)
        after = {binary: bool(shutil.which(binary)) for binary in binaries}
        verified = all(after.values())
        if not verified:
            raise RuntimeError("Package manager completed but the expected executable is still unavailable in PATH.")
        return {
            "action": action,
            "verified": True,
            "before": before,
            "after": after,
            "steps": execution,
            "message": "Package installation completed and the required executable is now available.",
        }

    def _repair_forwarding():
        _require_root()
        proc_path = Path("/proc/sys/net/ipv4/ip_forward")
        before_runtime = proc_path.read_text().strip()
        target = Path("/etc/sysctl.d/99-wg-panel-forwarding.conf")
        backup = None
        target_mode = None
        if target.exists() or target.is_symlink():
            info = target.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise RuntimeError("Refusing to replace a non-regular sysctl configuration path.")
            target_mode = stat.S_IMODE(info.st_mode)
            backup_dir = root / "repair-backups"
            backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            backup = backup_dir / f"99-wg-panel-forwarding.conf.{int(time.time())}.{uuid.uuid4().hex[:8]}.bak"
            shutil.copyfile(target, backup)
            os.chmod(backup, 0o600)

        managed_content = "# Managed by WG Panel Operations\nnet.ipv4.ip_forward = 1\n"
        rollback = _write_snapshot("enable_ipv4_forwarding", {
            "runtime": before_runtime,
            "had_file": bool(backup),
            "backup_name": backup.name if backup else "",
            "file_mode": target_mode,
            "expected_runtime": "1",
            "expected_content": managed_content,
        })

        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=".wg-panel-forwarding-", dir=str(target.parent), text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(managed_content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temp_name, 0o644)
            os.replace(temp_name, target)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

        sysctl = shutil.which("sysctl")
        if sysctl:
            completed = subprocess.run(
                [sysctl, "-w", "net.ipv4.ip_forward=1"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError("sysctl could not enable IPv4 forwarding.")
        else:
            proc_path.write_text("1")

        after_runtime = proc_path.read_text().strip()
        if after_runtime != "1":
            raise RuntimeError("IPv4 forwarding did not verify as enabled.")
        return {
            "action": "enable_ipv4_forwarding",
            "verified": True,
            "before": before_runtime,
            "after": after_runtime,
            "backup_created": bool(backup),
            "message": "IPv4 forwarding is enabled now and persisted in /etc/sysctl.d/99-wg-panel-forwarding.conf.",
            "rollback": rollback,
        }

    def _repair_start_interface(target):
        if type(target) is not int or target < 1:
            raise ValueError("A valid interface target is required.")
        model = context.get("InterfaceConfig")
        db = context.get("db")
        bring_up = context.get("_check_iface_up")
        if model is None or db is None or not callable(bring_up):
            raise RuntimeError("Interface repair helpers are unavailable.")
        iface = db.session.get(model, target)
        if iface is None or getattr(iface, "node_id", None) is not None:
            raise LookupError("Local interface not found.")
        name = str(getattr(iface, "name", "") or "")
        if not _INTERFACE_RE.fullmatch(name):
            raise RuntimeError("Interface name is not safe for automatic repair.")
        path = Path(str(getattr(iface, "path", "") or ""))
        if not path.is_file() or path.is_symlink():
            raise RuntimeError("Interface configuration is missing or is not a regular file.")
        bring_up(iface)
        wg = shutil.which("wg")
        if not wg:
            raise RuntimeError("wg is unavailable after the bring-up attempt.")
        completed = subprocess.run([wg, "show", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4, check=False)
        if completed.returncode != 0:
            raise RuntimeError("The interface did not verify as active.")
        return {
            "action": "start_interface",
            "target": target,
            "interface": name,
            "verified": True,
            "message": f"{name} is active and verified by wg show.",
        }

    @bp.after_request
    def private(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return response

    @bp.get("/operations")
    @admin_required
    def page():
        return render_template("operations.html")

    @bp.get("/api/operations/history")
    @admin_required
    def history():
        with history_connection() as connection:
            rows = connection.execute(
                "SELECT id,ts,actor,kind,payload FROM events ORDER BY id DESC LIMIT 40"
            ).fetchall()
        return jsonify(
            events=[
                dict(id=r[0], ts=r[1], actor=r[2], kind=r[3], payload=json.loads(r[4]))
                for r in rows
            ]
        )

    @bp.get("/api/operations/nodes")
    @admin_required
    def nodes():
        model = context.get("Node")
        if model is None:
            return jsonify(nodes=[])
        rows = model.query.filter_by(enabled=True).all()
        return jsonify(nodes=[dict(id=n.id, name=n.name) for n in rows])

    @bp.get("/api/operations/guide")
    @admin_required
    def guide():
        profile = detect_platform()
        return jsonify(system=profile, groups=command_guide(profile))

    @bp.post("/api/operations/scan")
    @admin_required
    def scan():
        try:
            with locked():
                with history_connection() as connection:
                    previous = connection.execute("SELECT MAX(ts) FROM events WHERE kind='scan'").fetchone()[0]
                if previous and time.time() - previous < 10:
                    return jsonify(error="Please wait 10 seconds between scans."), 429
                data = request.get_json(silent=True)
                if not isinstance(data, dict):
                    return jsonify(error="Expected a JSON object."), 400
                node_id = data.get("node_id")
                if node_id is not None:
                    if type(node_id) is not int or node_id < 1:
                        return jsonify(error="Invalid node ID."), 400
                    model = context.get("Node")
                    db = context.get("db")
                    if model is None or db is None:
                        return jsonify(error="Node support is unavailable."), 409
                    node = db.session.get(model, node_id)
                    if node is None or not node.enabled:
                        return jsonify(error="Enabled node not found."), 404
                    remote_report = collect_node_report(context, node)
                    checks = remote_report.get("checks") or []
                    report = dict(
                        ts=time.time(),
                        scope="Node: " + node.name,
                        remote=True,
                        node_id=node.id,
                        system=remote_report.get("system"),
                        legacy_remote=bool(remote_report.get("legacy")),
                        checks=checks,
                        counts=counts(checks),
                    )
                else:
                    checks = collect(app, context)
                    report = dict(
                        ts=time.time(),
                        scope="Local panel server",
                        remote=False,
                        system=detect_platform(),
                        checks=checks,
                        counts=counts(checks),
                    )
                record("scan", report)
                return jsonify(report)
        except BlockingIOError:
            return jsonify(error="Another scan or repair is running."), 409
        except Exception:
            app.logger.exception("Operations scan failed")
            return jsonify(error="Scan could not complete. Check the panel service log."), 500

    @bp.post("/api/operations/verify")
    @admin_required
    def verify():
        """Run a fresh read-only verification without the normal scan cooldown.

        This is used immediately after a repair or a manual recovery step so
        the user can confirm the selected finding from the same workflow.
        """
        try:
            with locked():
                data = request.get_json(silent=True)
                if not isinstance(data, dict):
                    return jsonify(error="Expected a JSON object."), 400
                node_id = data.get("node_id")
                if node_id is not None:
                    if type(node_id) is not int or node_id < 1:
                        return jsonify(error="Invalid node ID."), 400
                    model = context.get("Node")
                    db = context.get("db")
                    if model is None or db is None:
                        return jsonify(error="Node support is unavailable."), 409
                    node = db.session.get(model, node_id)
                    if node is None or not node.enabled:
                        return jsonify(error="Enabled node not found."), 404
                    remote_report = collect_node_report(context, node)
                    checks = remote_report.get("checks") or []
                    report = dict(
                        ts=time.time(),
                        scope="Node: " + node.name,
                        remote=True,
                        node_id=node.id,
                        system=remote_report.get("system"),
                        legacy_remote=bool(remote_report.get("legacy")),
                        checks=checks,
                        counts=counts(checks),
                    )
                else:
                    checks = collect(app, context)
                    report = dict(
                        ts=time.time(),
                        scope="Local panel server",
                        remote=False,
                        system=detect_platform(),
                        checks=checks,
                        counts=counts(checks),
                    )
                record("verification", report)
                return jsonify(report)
        except BlockingIOError:
            return jsonify(error="Another scan or repair is running."), 409
        except Exception:
            app.logger.exception("Operations verification failed")
            return jsonify(error="Verification could not complete. Check the panel service log."), 500

    @bp.post("/api/operations/repair")
    @admin_required
    def repair():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or data.get("confirm") is not True:
            return jsonify(error="Select a supported repair and confirm it."), 400
        action = data.get("action")
        if not isinstance(action, str):
            return jsonify(error="Select a supported repair and confirm it."), 400
        allowed = {"restrict_env", "enable_ipv4_forwarding", "start_interface", *_PACKAGE_ACTIONS.keys()}
        if action not in allowed:
            return jsonify(error="Select a supported repair and confirm it."), 400

        node_id = data.get("node_id")
        if node_id is not None and (type(node_id) is not int or node_id < 1):
            return jsonify(error="Invalid node ID."), 400

        try:
            with locked():
                if node_id is not None:
                    model = context.get("Node")
                    db = context.get("db")
                    poster = context.get("node_post")
                    if model is None or db is None or not callable(poster):
                        return jsonify(error="Node repair support is unavailable."), 409
                    node = db.session.get(model, node_id)
                    if node is None or not node.enabled:
                        return jsonify(error="Enabled node not found."), 404
                    payload = {"action": action, "confirm": True}
                    if action == "start_interface":
                        target = data.get("target")
                        if not isinstance(target, str) or not _INTERFACE_RE.fullmatch(target):
                            return jsonify(error="A valid node interface target is required."), 400
                        payload["target"] = target
                    record("repair_started", {"action": action, "node_id": node_id, "scope": "remote", **({"target": payload.get("target")} if payload.get("target") else {})})
                    result = poster(node, "/api/operations/repair", payload, timeout=200)
                    if not isinstance(result, dict) or result.get("ok") is False:
                        raise RuntimeError("The node did not confirm the repair.")
                    clean = dict(result)
                    clean["node_id"] = node_id
                    clean["node_name"] = node.name
                    clean["remote"] = True
                    record("repair", clean)
                    return jsonify(clean)

                started = {"action": action, "scope": "local"}
                if action == "start_interface":
                    target = data.get("target")
                    if type(target) is not int or target < 1:
                        return jsonify(error="A valid interface target is required."), 400
                    started["target"] = target
                record("repair_started", started)

                if action == "restrict_env":
                    result = _repair_restrict_env()
                elif action in _PACKAGE_ACTIONS:
                    result = _repair_package(action)
                elif action == "enable_ipv4_forwarding":
                    result = _repair_forwarding()
                elif action == "start_interface":
                    result = _repair_start_interface(data.get("target"))
                else:
                    raise ValueError("Unsupported repair")

                result["remote"] = False
                record("repair", result)
                return jsonify(ok=True, **result)
        except BlockingIOError:
            return jsonify(error="Another operation is running."), 409
        except (ValueError, LookupError) as exc:
            return jsonify(error=str(exc)), 400
        except PermissionError as exc:
            return jsonify(error=str(exc)), 409
        except Exception:
            app.logger.exception("Operations repair failed: %s", action)
            try:
                record("repair_failed", {
                    "action": action,
                    "node_id": node_id,
                    "scope": "remote" if node_id is not None else "local",
                    "message": "Repair did not complete; review the guided recovery plan and service log.",
                })
            except Exception:
                app.logger.debug("Could not record failed Operations repair", exc_info=True)
            return jsonify(error="Repair did not complete. Review the guided recovery plan and service log before retrying."), 500


    @bp.post("/api/operations/rollback")
    @admin_required
    def rollback():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or data.get("confirm") is not True:
            return jsonify(error="Select a rollback and confirm it."), 400
        token = data.get("token")
        node_id = data.get("node_id")
        if node_id is not None and (type(node_id) is not int or node_id < 1):
            return jsonify(error="Invalid node ID."), 400
        try:
            with locked():
                if node_id is not None:
                    model = context.get("Node")
                    db = context.get("db")
                    poster = context.get("node_post")
                    if model is None or db is None or not callable(poster):
                        return jsonify(error="Node rollback support is unavailable."), 409
                    node = db.session.get(model, node_id)
                    if node is None or not node.enabled:
                        return jsonify(error="Enabled node not found."), 404
                    result = poster(node, "/api/operations/rollback", {"token": token, "confirm": True}, timeout=60)
                    if not isinstance(result, dict) or result.get("ok") is False:
                        raise RuntimeError("The node did not confirm the rollback.")
                    clean = dict(result)
                    clean.update({"node_id": node_id, "node_name": node.name, "remote": True})
                    record("rollback", clean)
                    return jsonify(clean)

                result = _rollback_snapshot(token)
                result["remote"] = False
                record("rollback", result)
                return jsonify(ok=True, **result)
        except BlockingIOError:
            return jsonify(error="Another operation is running."), 409
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        except PermissionError as exc:
            return jsonify(error=str(exc)), 409
        except Exception:
            app.logger.exception("Operations rollback failed")
            try:
                record("rollback_failed", {"node_id": node_id, "scope": "remote" if node_id is not None else "local", "message": "Rollback did not complete; review the service log."})
            except Exception:
                app.logger.debug("Could not record failed Operations rollback", exc_info=True)
            return jsonify(error="Rollback did not complete. Review the service log before retrying."), 500


    app.register_blueprint(bp)

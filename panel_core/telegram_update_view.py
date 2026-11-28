

def _update_state(status: dict) -> str:
    return str(
        (status or {}).get("status")
        or "idle"
    ).strip().lower()


def _update_stage(status: dict) -> str:
    return str(
        (status or {}).get("stage")
        or _update_state(status)
        or "idle"
    ).strip().lower()


def _update_busy(status: dict) -> bool:
    return _update_state(status) in {
        "queued",
        "running",
        "backup",
        "downloading",
        "download",
        "extract",
        "install",
        "installing",
        "dependencies",
        "validate",
        "validating",
        "restart",
        "restarting",
        "rollback",
        "rolling_back",
    }


def _update_terminal(status: dict) -> bool:
    return _update_state(status) in {
        "completed",
        "complete",
        "done",
        "success",
        "rollback_completed",
        "failed",
        "error",
        "rollback_failed",
        "cancelled",
        "canceled",
    }


def _update_percent(status: dict) -> int:
    try:
        return max(
            0,
            min(
                100,
                int(
                    (status or {}).get("percent")
                    or 0
                ),
            ),
        )
    except Exception:
        return 0


def _update_status_icon(status: dict) -> str:
    state = _update_state(status)
    stage = _update_stage(status)

    if state in {
        "completed",
        "complete",
        "done",
        "success",
    }:
        return "●"

    if state == "rollback_completed":
        return "○"

    if state in {
        "failed",
        "error",
        "rollback_failed",
        "cancelled",
        "canceled",
        "offline",
    }:
        return "⊘"

    if state in {
        "restart",
        "restarting",
    } or stage in {
        "restart",
        "restarting",
    }:
        return "◐"

    if state in {
        "rollback",
        "rolling_back",
    } or stage in {
        "rollback",
        "rolling_back",
    }:
        return "○"

    if state in {
        "install",
        "installing",
        "dependencies",
    } or stage in {
        "install",
        "installing",
        "dependencies",
    }:
        return "◆"

    if state in {
        "validate",
        "validating",
    } or stage in {
        "validate",
        "validating",
    }:
        return "◐"

    if state in {
        "queued",
    }:
        return "○"

    if _update_busy(status):
        return "◉"

    return "○"


def _update_stage_label(status: dict) -> str:
    state = _update_state(status)
    stage = _update_stage(status)

    labels = {
        "idle": "Ready",
        "queued": "Queued",
        "running": "Working",
        "backup": "Creating rollback backup",
        "download": "Downloading main",
        "downloading": "Downloading main",
        "extract": "Preparing files",
        "install": "Installing",
        "installing": "Installing",
        "dependencies": "Installing dependencies",
        "validate": "Validating",
        "validating": "Validating",
        "restart": "Restarting",
        "restarting": "Restarting",
        "rollback": "Rolling back",
        "rolling_back": "Rolling back",
        "completed": "Completed",
        "complete": "Completed",
        "done": "Completed",
        "success": "Completed",
        "rollback_completed": "Previous version restored",
        "rollback_failed": "Rollback failed",
        "failed": "Failed",
        "error": "Failed",
        "cancelled": "Cancelled",
        "canceled": "Cancelled",
        "offline": "Offline",
    }

    return labels.get(
        stage,
        labels.get(
            state,
            stage.replace("_", " ").title(),
        ),
    )

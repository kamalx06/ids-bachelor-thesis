from __future__ import annotations

import atexit
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from logging_config import get_logger

logger = get_logger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
PID_FILE = REPO_ROOT / "storage" / "ids-sensor.pid"
HEARTBEAT_FILE = REPO_ROOT / "storage" / "ids-sensor.heartbeat"
MAIN_SCRIPT = REPO_ROOT / "ids_engine.py"
LEGACY_MAIN = REPO_ROOT / "main.py"

_DEFAULT_STALE_SEC = float(os.getenv("IDS_HEARTBEAT_STALE_SEC", "30") or "30")


def sensor_pid_file() -> Path:
    return PID_FILE


def heartbeat_file() -> Path:
    return HEARTBEAT_FILE


def touch_sensor_heartbeat() -> None:
    HEARTBEAT_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {"ts": time.time(), "pid": os.getpid()}
    HEARTBEAT_FILE.write_text(json.dumps(payload), encoding="utf-8")


def _read_heartbeat_age() -> float | None:
    if not HEARTBEAT_FILE.is_file():
        return None
    try:
        data = json.loads(HEARTBEAT_FILE.read_text(encoding="utf-8"))
        ts = float(data.get("ts", 0))
        if ts <= 0:
            return None
        return time.time() - ts
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def is_sensor_running(*, stale_sec: float = _DEFAULT_STALE_SEC) -> bool:
    """True when PID is alive and heartbeat is fresh (if present)."""
    if not PID_FILE.is_file():
        return False
    try:
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return False

    if not _pid_alive(pid):
        return False

    age = _read_heartbeat_age()
    if age is None:
        return True
    return age <= stale_sec


def get_sensor_health() -> dict[str, Any]:
    """
    Structured health payload for /ids/health and dashboard polling.
    """
    online = is_sensor_running()
    pid = None
    heartbeat_age = _read_heartbeat_age()

    if PID_FILE.is_file():
        try:
            pid = int(PID_FILE.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            pid = None

    return {
        "online": online,
        "status": "online" if online else "offline",
        "label": "LIVE" if online else "OFFLINE",
        "pid": pid,
        "heartbeat_age_sec": round(heartbeat_age, 2) if heartbeat_age is not None else None,
        "heartbeat_stale_sec": _DEFAULT_STALE_SEC,
    }


def write_sensor_pid(pid: int | None = None) -> None:
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(pid or os.getpid()), encoding="utf-8")
    touch_sensor_heartbeat()


def clear_sensor_pid() -> None:
    try:
        if PID_FILE.is_file():
            PID_FILE.unlink()
        if HEARTBEAT_FILE.is_file():
            HEARTBEAT_FILE.unlink()
    except OSError:
        pass


def register_sensor_pid_cleanup() -> None:
    atexit.register(clear_sensor_pid)


def _engine_script() -> Path:
    if MAIN_SCRIPT.is_file():
        return MAIN_SCRIPT
    return LEGACY_MAIN


def start_sensor_background(*, verbose: bool = False) -> subprocess.Popen | None:
    """
    Start ids_engine.py in the background. Returns Popen handle or None if skipped.
    """
    script = _engine_script()
    if not script.is_file():
        logger.warning("IDS engine script not found at %s", script)
        return None

    if is_sensor_running():
        logger.info("IDS sensor already running (pid file %s)", PID_FILE)
        return None

    env = os.environ.copy()
    env["IDS_START_WEB_UI"] = "false"
    env["WEBUI_START_IDS_SENSOR"] = "false"

    stdout = None if verbose else subprocess.DEVNULL
    stderr = None if verbose else subprocess.DEVNULL

    proc = subprocess.Popen(
        [sys.executable, str(script)],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=stdout,
        stderr=stderr,
    )
    logger.info("IDS sensor started (%s) pid=%s", script.name, proc.pid)
    return proc

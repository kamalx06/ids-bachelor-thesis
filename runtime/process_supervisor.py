from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from logging_config import get_logger

logger = get_logger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
IDS_ENGINE_SCRIPT = REPO_ROOT / "ids_engine.py"
WEB_SERVER_SCRIPT = REPO_ROOT / "uni-srver.py"


class ProcessSupervisor:
    def __init__(self) -> None:
        self._shutdown = False
        self._ids_proc: subprocess.Popen | None = None
        self._web_proc: subprocess.Popen | None = None

    def _base_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["WEBUI_START_IDS_SENSOR"] = "false"
        env["IDS_START_WEB_UI"] = "false"
        return env

    def start_ids_engine(self) -> subprocess.Popen:
        if not IDS_ENGINE_SCRIPT.is_file():
            raise FileNotFoundError(f"IDS engine script not found: {IDS_ENGINE_SCRIPT}")

        env = self._base_env()
        env["IDS_ENGINE_STANDALONE"] = "true"

        proc = subprocess.Popen(
            [sys.executable, str(IDS_ENGINE_SCRIPT)],
            cwd=str(REPO_ROOT),
            env=env,
        )
        self._ids_proc = proc
        logger.info("IDS engine started pid=%s", proc.pid)
        return proc

    def start_web_server(self) -> subprocess.Popen:
        if not WEB_SERVER_SCRIPT.is_file():
            raise FileNotFoundError(f"Web server script not found: {WEB_SERVER_SCRIPT}")

        env = self._base_env()

        proc = subprocess.Popen(
            [sys.executable, str(WEB_SERVER_SCRIPT)],
            cwd=str(REPO_ROOT),
            env=env,
        )
        self._web_proc = proc
        logger.info("Web server started pid=%s", proc.pid)
        return proc

    def _terminate(self, proc: subprocess.Popen | None, name: str, timeout: float = 8.0) -> None:
        if proc is None or proc.poll() is not None:
            return
        logger.info("Stopping %s (pid=%s)...", name, proc.pid)
        try:
            if os.name == "nt":
                proc.terminate()
            else:
                proc.send_signal(signal.SIGTERM)
        except Exception:
            proc.kill()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)

    def shutdown(self) -> None:
        self._shutdown = True
        self._terminate(self._ids_proc, "IDS engine")
        self._terminate(self._web_proc, "Web server")

    def _register_signal_handlers(self) -> None:
        def _handler(signum, frame):
            logger.info("Shutdown signal received (%s)", signum)
            self.shutdown()
            raise SystemExit(0)

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _handler)
            except (ValueError, OSError):
                pass

    def run_forever(self) -> int:
        self._register_signal_handlers()

        self.start_web_server()
        time.sleep(1.0)
        self.start_ids_engine()

        logger.info(
            "Supervisor active — Web UI and IDS engine are separate processes. "
            "IDS crash will not stop the dashboard."
        )

        last_ids_restart = 0.0
        restart_cooldown = float(os.getenv("IDS_RESTART_COOLDOWN_SEC", "30") or "30")
        auto_restart = (os.getenv("IDS_AUTO_RESTART", "false") or "false").lower() == "true"

        while not self._shutdown:
            if self._web_proc and self._web_proc.poll() is not None:
                logger.error(
                    "Web server exited with code %s — supervisor stopping.",
                    self._web_proc.returncode,
                )
                self.shutdown()
                return int(self._web_proc.returncode or 1)

            if self._ids_proc and self._ids_proc.poll() is not None:
                code = self._ids_proc.returncode
                logger.warning(
                    "IDS engine exited (code=%s). Web UI remains available; dashboard shows OFFLINE.",
                    code,
                )
                self._ids_proc = None
                if auto_restart and (time.time() - last_ids_restart) >= restart_cooldown:
                    logger.info("Auto-restarting IDS engine...")
                    self.start_ids_engine()
                    last_ids_restart = time.time()

            time.sleep(2.0)

        return 0

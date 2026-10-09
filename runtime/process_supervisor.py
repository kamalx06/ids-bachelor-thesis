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
SSL_ENGINE_SCRIPT = REPO_ROOT / "ssl_inspect" / "engine.py"


class ProcessSupervisor:
    def __init__(self) -> None:
        self._shutdown = False
        self._ids_proc: subprocess.Popen | None = None
        self._web_proc: subprocess.Popen | None = None
        self._ssl_proc: subprocess.Popen | None = None

    def _base_env(self) -> dict[str, str]:
        env = os.environ.copy()
        # Belt-and-braces: even if someone flips WEBUI_START_IDS_SENSOR=true
        # in .env, the supervisor still owns process lifecycle — the web UI
        # must not start its own sensor.
        env["WEBUI_START_IDS_SENSOR"] = "false"
        return env

    def start_ids_engine(self) -> subprocess.Popen:
        if not IDS_ENGINE_SCRIPT.is_file():
            raise FileNotFoundError(f"IDS engine script not found: {IDS_ENGINE_SCRIPT}")

        env = self._base_env()

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

    def start_ssl_interceptor(self) -> subprocess.Popen:
        if not SSL_ENGINE_SCRIPT.is_file():
            raise FileNotFoundError(f"SSL engine script not found: {SSL_ENGINE_SCRIPT}")

        env = self._base_env()
        # Do not swallow stderr — when the interceptor exits unexpectedly,
        # the only clue is what mitmdump printed. Let it reach the parent's
        # log stream so a failure is visible at the point it happens.
        proc = subprocess.Popen(
            [sys.executable, "-m", "ssl_inspect.engine"],
            cwd=str(REPO_ROOT),
            env=env,
        )
        self._ssl_proc = proc
        logger.info("SSL interceptor started pid=%s (module invocation)", proc.pid)
        return proc

    def shutdown(self) -> None:
        self._shutdown = True
        self._terminate(self._ssl_proc, "SSL interceptor")
        self._terminate(self._ids_proc, "IDS engine")
        self._terminate(self._web_proc, "Web server")

    def _register_signal_handlers(self) -> None:
        def _handler(signum, frame):
            if self._shutdown:
                # Second signal during shutdown — force-exit rather than
                # re-entering _terminate mid-wait.
                logger.warning("Second shutdown signal (%s); forcing exit.", signum)
                raise SystemExit(1)
            logger.info("Shutdown signal received (%s)", signum)
            self._shutdown = True
            # Don't call shutdown() or raise SystemExit here. Setting the
            # flag is enough: the sleep in run_forever() is interrupted by
            # the signal, the loop condition `while not self._shutdown`
            # evaluates False, and shutdown runs once, in the normal flow.

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _handler)
            except (ValueError, OSError):
                pass

    def run_forever(self) -> int:
        self._register_signal_handlers()

        self.start_web_server()
        # Give Flask a moment to bind the socket. The health check below
        # catches the case where it crashes during startup, so this is a
        # soft delay, not a hard requirement.
        time.sleep(1.0)

        # Verify the web server survived its startup window before spawning
        # the IDS engine. If it crashed immediately (bad config, port in use),
        # we don't want to start a sensor that will just be orphaned.
        if self._web_proc and self._web_proc.poll() is not None:
            logger.error(
                "Web server exited during startup (code=%s) — not starting IDS engine.",
                self._web_proc.returncode,
            )
            return int(self._web_proc.returncode or 1)

        try:
            self.start_ids_engine()
        except Exception:
            logger.error("Failed to start IDS engine — shutting down supervisor.", exc_info=True)
            self.shutdown()
            return 1

        ssl_enabled = (
            os.getenv("SSL_DECRYPTION_ENABLED", "false") or "false"
        ).lower() == "true"
        if ssl_enabled:
            try:
                self.start_ssl_interceptor()
            except Exception:
                logger.error(
                    "Failed to start SSL interceptor — continuing without it. "
                    "Set SSL_DECRYPTION_ENABLED=true and check the logs.",
                    exc_info=True,
                )

        logger.info(
            "Supervisor active — Web UI, IDS engine%s are separate processes.",
            ", SSL interceptor" if ssl_enabled and self._ssl_proc else "",
        )

        last_ids_restart = 0.0
        restart_cooldown = float(os.getenv("IDS_RESTART_COOLDOWN_SEC", "30") or "30")
        auto_restart = (os.getenv("IDS_AUTO_RESTART", "false") or "false").lower() == "true"

        while not self._shutdown:
            if self._web_proc and self._web_proc.poll() is not None:
                code = self._web_proc.returncode
                logger.error(
                    "Web server exited with code %s — supervisor stopping.", code,
                )
                self.shutdown()
                # A clean exit (0) here is unexpected; treat it as failure
                # so a caller (systemd, shell) can react to the supervisor
                # stopping for a reason other than a signal.
                return code if code else 1

            if self._ids_proc and self._ids_proc.poll() is not None:
                code = self._ids_proc.returncode
                logger.warning(
                    "IDS engine exited (code=%s). Web UI remains available; dashboard shows OFFLINE.",
                    code,
                )
                self._ids_proc = None

            if self._ssl_proc and self._ssl_proc.poll() is not None:
                code = self._ssl_proc.returncode
                logger.warning(
                    "SSL interceptor exited (code=%s). Web UI and IDS engine "
                    "continue; decrypted traffic analysis is paused.",
                    code,
                )
                self._ssl_proc = None
                if auto_restart and (time.time() - last_ids_restart) >= restart_cooldown:
                    logger.info("Auto-restarting IDS engine...")
                    self.start_ids_engine()
                    last_ids_restart = time.time()

            time.sleep(2.0)

        self.shutdown()
        return 0

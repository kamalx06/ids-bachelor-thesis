"""
Watchdog for packet workers and log writer — restarts stalled threads.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Callable

from logging_config import get_logger

logger = get_logger(__name__)

_WATCHDOG_INTERVAL = float(os.getenv("IDS_WATCHDOG_INTERVAL", "15") or "15")
_STALL_THRESHOLD = float(os.getenv("IDS_WORKER_STALL_SEC", "120") or "120")


class WorkerMonitor:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._heartbeats: dict[str, float] = {}
        self._restart_counts: dict[str, int] = {}
        self._running = False
        self._thread: threading.Thread | None = None

    def heartbeat(self, worker_id: str) -> None:
        with self._lock:
            self._heartbeats[worker_id] = time.time()

    def register_restart(self, worker_id: str) -> None:
        with self._lock:
            self._restart_counts[worker_id] = self._restart_counts.get(worker_id, 0) + 1
        logger.warning("Worker %s restarted (count=%d)", worker_id, self._restart_counts[worker_id])

    def start(
        self,
        *,
        health_fn: Callable[[], dict],
        restart_worker_fn: Callable[[str], None],
        worker_ids: list[str],
    ) -> None:
        self._running = True
        self._thread = threading.Thread(
            target=self._loop,
            args=(health_fn, restart_worker_fn, worker_ids),
            daemon=True,
            name="ids-watchdog",
        )
        self._thread.start()
        logger.info("Worker watchdog started (interval=%.0fs)", _WATCHDOG_INTERVAL)

    def _loop(
        self,
        health_fn: Callable[[], dict],
        restart_worker_fn: Callable[[str], None],
        worker_ids: list[str],
    ) -> None:
        while self._running:
            time.sleep(_WATCHDOG_INTERVAL)
            now = time.time()
            health = health_fn()
            logger.debug("IDS health: %s", health)

            with self._lock:
                beats = dict(self._heartbeats)

            for wid in worker_ids:
                last = beats.get(wid, now)
                if now - last > _STALL_THRESHOLD:
                    logger.error(
                        "Watchdog: worker %s stalled (%.0fs idle); restarting",
                        wid,
                        now - last,
                    )
                    restart_worker_fn(wid)

    def stop(self) -> None:
        self._running = False

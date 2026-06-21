"""
Bounded packet and log queues with backpressure, drop accounting, and health metrics.
"""

from __future__ import annotations

import os
import threading
import time
from queue import Empty, Full, Queue  # noqa: F401 — Empty used by dequeue_packet
from typing import Any, Callable

from logging_config import get_logger

logger = get_logger(__name__)

_QUEUE_MAXSIZE = max(1000, int(os.getenv("IDS_QUEUE_MAXSIZE", "25000") or "25000"))
_RAW_QUEUE_MAXSIZE = max(1000, int(os.getenv("IDS_RAW_QUEUE_MAXSIZE", "10000") or "10000"))
_LOG_QUEUE_MAXSIZE = max(1000, int(os.getenv("IDS_LOG_QUEUE_MAXSIZE", "50000") or "50000"))
_PRESSURE_SAMPLE_AT = float(os.getenv("IDS_PRESSURE_SAMPLE_AT", "0.80") or "0.80")
_DROP_LOG_INTERVAL = float(os.getenv("IDS_DROP_LOG_INTERVAL", "5") or "5")
_MAX_RETRIES = max(0, int(os.getenv("IDS_PACKET_MAX_RETRIES", "2") or "2"))


class PacketQueues:
    def __init__(self) -> None:
        self.packet_queue: Queue[dict] = Queue(maxsize=_QUEUE_MAXSIZE)
        self.raw_queue: Queue[Any] = Queue(maxsize=_RAW_QUEUE_MAXSIZE)
        self.log_queue: Queue[dict | None] = Queue(maxsize=_LOG_QUEUE_MAXSIZE)
        self._drop_lock = threading.Lock()
        self._dropped_packets = 0
        self._dropped_raw = 0
        self._dropped_logs = 0
        self._last_drop_log_at = 0.0
        self._sample_counter = 0
        self._processed = 0
        self._failed = 0
        self._retried = 0

    def pressure(self) -> float:
        packet_fill = self.packet_queue.qsize() / float(_QUEUE_MAXSIZE)
        raw_fill = self.raw_queue.qsize() / float(_RAW_QUEUE_MAXSIZE)
        return max(packet_fill, raw_fill)

    def should_sample_under_pressure(self) -> bool:
        if self.pressure() < _PRESSURE_SAMPLE_AT:
            return False
        self._sample_counter += 1
        return (self._sample_counter % 4) != 0

    def enqueue_raw_packet(self, pkt) -> bool:
        try:
            self.raw_queue.put_nowait(pkt)
            return True
        except Full:
            self._record_dropped_raw()
            return False

    def _record_dropped_raw(self) -> None:
        with self._drop_lock:
            self._dropped_raw += 1
            now = time.time()
            if now - self._last_drop_log_at < _DROP_LOG_INTERVAL:
                return
            count = self._dropped_raw
            self._dropped_raw = 0
            self._last_drop_log_at = now
        logger.warning(
            "Raw capture queue full; dropped %d packet(s) in %.0fs (qsize=%d/%d)",
            count,
            _DROP_LOG_INTERVAL,
            self.raw_queue.qsize(),
            _RAW_QUEUE_MAXSIZE,
        )

    def dequeue_raw_packet(self, timeout: float = 1.0) -> Any | None:
        try:
            return self.raw_queue.get(timeout=timeout)
        except Empty:  # pylint: disable=try-except-raise
            return None

    def enqueue_packet(self, item: dict) -> bool:
        try:
            self.packet_queue.put_nowait(item)
            return True
        except Full:
            self._record_dropped_packet()
            return False

    def _record_dropped_packet(self) -> None:
        with self._drop_lock:
            self._dropped_packets += 1
            now = time.time()
            if now - self._last_drop_log_at < _DROP_LOG_INTERVAL:
                return
            count = self._dropped_packets
            self._dropped_packets = 0
            self._last_drop_log_at = now
        logger.warning(
            "Packet queue full; dropped %d packet(s) in %.0fs (qsize=%d/%d)",
            count,
            _DROP_LOG_INTERVAL,
            self.packet_queue.qsize(),
            _QUEUE_MAXSIZE,
        )

    def enqueue_log(self, entry: dict) -> bool:
        try:
            self.log_queue.put_nowait(entry)
            return True
        except Full:
            with self._drop_lock:
                self._dropped_logs += 1
            logger.warning("Log queue full; dropped DB persist for one event")
            return False

    def dequeue_packet(self, timeout: float = 1.0) -> dict | None:
        try:
            return self.packet_queue.get(timeout=timeout)
        except Empty:  # pylint: disable=try-except-raise
            return None

    def process_with_retry(
        self,
        handler: Callable[[dict], None],
        packet_dict: dict,
    ) -> None:
        attempts = 0
        while attempts <= _MAX_RETRIES:
            try:
                handler(packet_dict)
                self._processed += 1
                return
            except Exception:
                attempts += 1
                self._retried += 1
                if attempts > _MAX_RETRIES:
                    self._failed += 1
                    logger.error(
                        "Packet processing failed after %d retries",
                        _MAX_RETRIES,
                        exc_info=True,
                    )
                    return
                time.sleep(min(0.05 * attempts, 0.25))

    def health(self) -> dict[str, Any]:
        return {
            "packet_qsize": self.packet_queue.qsize(),
            "packet_maxsize": _QUEUE_MAXSIZE,
            "raw_qsize": self.raw_queue.qsize(),
            "raw_maxsize": _RAW_QUEUE_MAXSIZE,
            "log_qsize": self.log_queue.qsize(),
            "log_maxsize": _LOG_QUEUE_MAXSIZE,
            "pressure": round(self.pressure(), 4),
            "processed": self._processed,
            "failed": self._failed,
            "retried": self._retried,
            "dropped_logs": self._dropped_logs,
        }

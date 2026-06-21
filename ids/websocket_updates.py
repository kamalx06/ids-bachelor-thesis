"""
Server-Sent Events (SSE) broadcaster for live dashboard updates.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from typing import Any

_listeners: list[queue.Queue] = []
_lock = threading.Lock()


def subscribe() -> queue.Queue:
    q: queue.Queue = queue.Queue(maxsize=100)
    with _lock:
        _listeners.append(q)
    return q


def unsubscribe(q: queue.Queue) -> None:
    with _lock:
        if q in _listeners:
            _listeners.remove(q)


def broadcast(event_type: str, payload: dict[str, Any]) -> None:
    message = {"type": event_type, "data": payload, "ts": time.time()}
    with _lock:
        listeners = list(_listeners)
    for q in listeners:
        try:
            q.put_nowait(message)
        except queue.Full:
            pass


def sse_stream():
    """Flask Response generator for text/event-stream."""
    q = subscribe()
    try:
        yield "event: connected\ndata: {}\n\n"
        while True:
            try:
                msg = q.get(timeout=25)
                yield f"event: {msg['type']}\ndata: {json.dumps(msg['data'])}\n\n"
            except queue.Empty:
                yield ": heartbeat\n\n"
    finally:
        unsubscribe(q)

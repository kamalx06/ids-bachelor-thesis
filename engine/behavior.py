import os
import threading
import time
from collections import defaultdict, deque

_FLOOD_THRESHOLD = int(os.getenv("IDS_FLOOD_THRESHOLD", "120") or "120")
_FLOOD_WINDOW = float(os.getenv("IDS_FLOOD_WINDOW", "3") or "3")
_PORT_SCAN_THRESHOLD = int(os.getenv("IDS_PORT_SCAN_THRESHOLD", "15") or "15")
_PORT_SCAN_WINDOW = float(os.getenv("IDS_PORT_SCAN_WINDOW", "8") or "8")
_MAX_WINDOW = max(_FLOOD_WINDOW, _PORT_SCAN_WINDOW)

_BEHAVIOR_SHARDS = max(16, int(os.getenv("IDS_BEHAVIOR_SHARDS", "64") or "64"))


def _new_activity():
    return deque(maxlen=1000)


_behavior_locks = [threading.Lock() for _ in range(_BEHAVIOR_SHARDS)]
_ip_activity = [defaultdict(_new_activity) for _ in range(_BEHAVIOR_SHARDS)]


def _shard_index(src_ip: str) -> int:
    return hash(src_ip) % _BEHAVIOR_SHARDS


def detect(src_ip, dst_port=None):
    """
    Detect suspicious behaviors for a given IP.
    Returns: None, or a string representing the behavior
    """
    if not src_ip:
        return None

    shard = _shard_index(str(src_ip))
    lock = _behavior_locks[shard]
    activity_map = _ip_activity[shard]

    with lock:
        now = time.time()
        activity = activity_map.get(src_ip)
        if activity is None:
            activity = _new_activity()
            activity_map[src_ip] = activity
            # Opportunistic eviction: if the shard has grown large, drop
            # IPs that have been idle for the whole window. Cheap because
            # only triggered at capacity.
            if len(activity_map) > 10_000:
                stale = [
                    ip for ip, dq in activity_map.items()
                    if not dq or now - dq[-1]["time"] > _MAX_WINDOW
                ]
                for ip in stale:
                    activity_map.pop(ip, None)

        activity.append({"time": now, "dst_port": dst_port})

        while activity and now - activity[0]["time"] > _MAX_WINDOW:
            activity.popleft()

        flood_count = 0
        port_set: set = set()
        for event in reversed(activity):
            age = now - event["time"]
            if age > _MAX_WINDOW:
                break
            if age <= _FLOOD_WINDOW:
                flood_count += 1
                if flood_count > _FLOOD_THRESHOLD:
                    return "flood"
            if age <= _PORT_SCAN_WINDOW:
                port = event.get("dst_port")
                if port is not None:
                    port_set.add(port)
                    if len(port_set) >= _PORT_SCAN_THRESHOLD:
                        return "port_scan"

    return None

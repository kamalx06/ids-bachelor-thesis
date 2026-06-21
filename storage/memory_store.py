from collections import deque

logs = deque(maxlen=10000)

# Legacy shape — kept for imports; values synced from MySQL persistence layer
stats = {
    "total": 0,
    "safe": 0,
    "suspicious": 0,
    "dangerous": 0,
    "unique_attackers": set(),
    "dangerous_ips": set(),
    "dangerous_urls": set(),
}


def sync_stats_from_persistence() -> None:
    from storage.persistence import get_live_stats

    live = get_live_stats()
    stats["total"] = live["total"]
    stats["safe"] = live["safe"]
    stats["suspicious"] = live["suspicious"]
    stats["dangerous"] = live["dangerous"]
    stats["unique_attackers"] = live["unique_attackers"]
    stats["dangerous_ips"] = live["dangerous_ips"]
    stats["dangerous_urls"] = live["dangerous_urls"]

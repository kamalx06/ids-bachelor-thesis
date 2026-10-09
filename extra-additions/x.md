Good ideas — both features are worth doing, but they have very different scopes. SSL decryption is a **substantial addition** (new process, new attack surface, client-trust deployment), and the Analytics page is a **moderate addition** (new table, aggregation job, one new page). I'll lay out the architecture for each, give you the schema and hard-to-get-right pieces, and flag the decisions you'll need to make.

Before writing any code, let me explain what each feature really involves, because a naive implementation will bite you.

---

## Part 1 — SSL Decryption

### What "NGFW-style SSL decryption" actually is

It's a **transparent TLS MITM proxy**. The flow:

```
Client  ──── TCP:443 ────▶  IDS (intercepts)  ──── TCP:443 ────▶  Real server
                              │
                              ├─ Presents a leaf cert for the SNI
                              │  signed by your local CA
                              ├─ Terminates TLS from the client
                              ├─ Opens a *separate* TLS connection to the server
                              ├─ Pipes plaintext between the two
                              └─ Emits plaintext events for analysis
```

For it to work end-to-end:

1. **Clients must trust your local CA.** Otherwise every HTTPS site throws a cert warning.
2. **Traffic must flow through the IDS.** Either the IDS is the gateway, or you use iptables `REDIRECT`/`TPROXY` to push TCP/443 into the proxy.
3. **Some traffic must bypass.** Certificate-pinned apps (banking, some mobile SDKs, some CDNs) will break if you MITM them. NGFW has a bypass list; you need one too.

### Recommended approach: use `mitmproxy` as the TLS engine

Do **not** write your own TLS interception. It's a solved problem and doing it manually will consume your thesis budget. `mitmproxy` is mature, supports transparent mode, and exposes flow events via an addon API.

```
┌─────────────────┐     TCP:443      ┌──────────────────┐
│   Client        │ ────────────────▶│  iptables        │
└─────────────────┘  (redirect rule) │  REDIRECT        │
                                     │  → :8443         │
                                     └────────┬─────────┘
                                              │
                                              ▼
                                     ┌──────────────────┐
                                     │  mitmproxy       │
                                     │  (transparent    │
                                     │   mode, :8443)   │
                                     └────────┬─────────┘
                                              │  flow events
                                              ▼
                                     ┌──────────────────┐
                                     │  ids_ssl_addon   │
                                     │  (Python)        │
                                     └────────┬─────────┘
                                              │  plaintext
                                              ▼
                                     ┌──────────────────┐
                                     │  Existing        │
                                     │  analyze_packet  │
                                     └──────────────────┘
```

### New components

| File | Purpose |
|---|---|
| `ssl/__init__.py` | Package marker |
| `ssl/ca.py` | CA generation, leaf cert issuance, storage |
| `ssl/interceptor.py` | mitmproxy addon — emits plaintext events |
| `ssl/iptables_setup.py` | Script to install/remove redirect rules |
| `ssl/runner.py` | Launches mitmproxy in transparent mode |
| `ssl/bypass.py` | Bypass list logic (SNI, IP, cert-pinned) |
| `templates/ssl.html` | Web UI page |
| `static/js/ssl.js` | Client-side interactions |
| `uni-srver.py` (new routes) | CA download, cert list, bypass list CRUD |

### Database schema (add to `bootstrap_db.py`)

```sql
-- Root CA and issued leaf certificates
CREATE TABLE IF NOT EXISTS ssl_certificates (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    cert_type VARCHAR(16) NOT NULL,          -- 'root_ca' | 'leaf'
    common_name VARCHAR(255) NOT NULL,       -- hostname or CA name
    serial_hex VARCHAR(64) NOT NULL,
    not_before DATETIME(6) NOT NULL,
    not_after DATETIME(6) NOT NULL,
    cert_pem LONGTEXT NOT NULL,
    key_pem LONGTEXT NULL,                    -- NULL for leaf certs (keys not stored)
    key_encrypted BOOLEAN NOT NULL DEFAULT 0, -- root CA private key encrypted at rest
    revoked BOOLEAN NOT NULL DEFAULT 0,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_used_at DATETIME(6) NULL,
    UNIQUE KEY uq_cert_cn_type (common_name, cert_type),
    INDEX ix_ssl_cert_expiry (not_after),
    INDEX ix_ssl_cert_type (cert_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Per-SNI bypass policy
CREATE TABLE IF NOT EXISTS ssl_bypass_rules (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    match_type VARCHAR(16) NOT NULL,          -- 'sni' | 'ip' | 'cidr' | 'category'
    pattern VARCHAR(255) NOT NULL,
    reason VARCHAR(255) NULL,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_bypass (match_type, pattern),
    INDEX ix_bypass_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Aggregated stats for the SSL page
CREATE TABLE IF NOT EXISTS ssl_session_stats (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    bucket_start DOUBLE NOT NULL,             -- per-minute bucket
    sni VARCHAR(255) NULL,
    decrypted_count INT NOT NULL DEFAULT 0,
    bypassed_count INT NOT NULL DEFAULT 0,
    failed_count INT NOT NULL DEFAULT 0,
    UNIQUE KEY uq_ssl_stat_bucket (bucket_start, sni),
    INDEX ix_ssl_stat_ts (bucket_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### The critical security decisions you need to make

**1. Where is the root CA private key stored?**

Three options, in order of increasing safety:

| Option | Where | Pro | Con |
|---|---|---|---|
| **A** | Plaintext PEM in `ssl/ca/root.key` on disk | Simple | Anyone with read access to the file forges certs |
| **B** | Encrypted PEM in MySQL, key derived from `SSL_CA_PASSPHRASE` env var | Survives process restart, matches your existing `MySQL`/`.env` model | Passphrase in env is still a secret to protect |
| **C** | OS keyring / KMS | Best | Overkill for a thesis |

For a thesis, go with **Option B**. The web UI never exposes the passphrase; it only lets you generate a *new* CA (which rotates everything). This means a DB dump alone doesn't leak the CA.

**2. Clients trust the CA how?**

Document that it's a manual step. For testing:
- **Linux**: `cp ca.pem /usr/local/share/ca-certificates/ids-ca.crt && update-ca-certificates`
- **Firefox**: `about:config` → `security.enterprise_roots.enabled = true`, or import via `about:preferences#privacy`
- **macOS**: Keychain Access → System → import + set to Always Trust

Provide a `GET /ssl/ca.pem` endpoint so the user can download it from the web UI. Add copy buttons for the install commands.

**3. Legal and ethical**

MITM on traffic you don't own is illegal in most jurisdictions. Add a loud warning on the SSL page that this must only be enabled on networks you own or have explicit written consent to monitor. This isn't just polish — for a bachelor thesis defense, showing you understand the legal boundary is worth points.

### The interceptor addon

This is the piece that ties mitmproxy into your existing pipeline. Skeleton:

```python
# ssl/interceptor.py
from __future__ import annotations

import time
from mitmproxy import http, ctx

from ids.ai_analysis import analyze_packet
from storage.persistence import enqueue_packet_log
from logging_config import get_logger

logger = get_logger(__name__)


class IDSInterceptor:
    """
    mitmproxy addon: converts decrypted HTTP flows into the same packet
    dicts the live sensor feeds to analyze_packet(), so SSL-decrypted
    traffic goes through the exact same detection pipeline.
    """

    def request(self, flow: http.HTTPFlow) -> None:
        self._emit(flow, direction="request")

    def response(self, flow: http.HTTPFlow) -> None:
        self._emit(flow, direction="response")

    def _emit(self, flow: http.HTTPFlow, *, direction: str) -> None:
        try:
            req = flow.request
            body = ""
            if req.content:
                body = req.content.decode("utf-8", errors="ignore")[:8192]

            src_ip, src_port = flow.client_conn.peername or ("", 0)
            dst_ip, dst_port = flow.server_conn.peername or ("", 0)

            # Build a packet-shaped dict. The fields match what
            # engine.feature_extractor produces, so downstream code does
            # not need to know whether the traffic was TLS-decrypted.
            data = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": int(src_port),
                "dst_port": int(dst_port),
                "protocol": "TCP",
                "url": req.pretty_url,
                "http": {
                    "method": req.method,
                    "host": req.host,
                    "path": req.path,
                    "url": req.pretty_url,
                    "headers": dict(req.headers),
                    "query": dict(req.query),
                    "body": body,
                },
                "decrypted": True,          # flag so downstream can tell
                "packet_send_time": time.time(),
                "features": None,            # no flow-level features from mitmproxy
            }

            result = analyze_packet(data, dns_reasons=None, queue_pressure=0.0)

            log_entry = {
                "time": time.time(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": int(src_port),
                "dst_port": int(dst_port),
                "protocol": "TCP",
                "url": data["url"],
                "http": data["http"],
                "status": result["classification"],
                "reasons": result["reasons"],
                "ai_label": result.get("ai_label"),
                "ai_score": result.get("ai_score"),
                "risk_score": result["risk_score"],
                "confidence": result.get("confidence"),
                "anomaly_score": result.get("anomaly_score"),
                "ti_ip": result.get("ti_ip"),
                "ti_url": result.get("ti_url"),
                "ai_explanation": result.get("explanation"),
            }
            enqueue_packet_log(log_entry)

        except Exception:
            logger.error("SSL interceptor failed to emit flow", exc_info=True)
```

**Important:** `analyze_packet` calls `predict(data["features"])`, and mitmproxy doesn't give you the same flow-level features the Scapy path produces. Two options:

- **A — Feature-less path.** In `analyze_packet`, guard against `features is None` and skip the ML steps, using only behavioral heuristics + payload analysis. Cleaner for SSL, but loses ML classification on decrypted traffic.
- **B — Synthesize features.** Build a minimal feature vector from HTTP metadata (duration, byte counts, port). Won't be as accurate as live Scapy flows, but ML still contributes.

I'd do **A** for a thesis — it's honest, and the SSL-decrypted content analysis (payload analyzer, TI URL lookup) is the real value here anyway. The behavioral heuristics will still catch SQL injection and command injection in the plaintext body.

### Web UI — SSL page

New template `templates/ssl.html`, admin-only, with:

- **CA card**: shows CN, expiry, fingerprint. Buttons: *Regenerate CA* (destructive, warns it invalidates all client trust), *Download CA (PEM)*, *Download CA (DER)*.
- **Leaf certs table**: hostname, issued at, expiry, last used. Filter by search. Sort. Row actions: *Revoke*, *Force re-issue on next connection*.
- **Bypass rules**: match type + pattern + reason. Add/edit/delete. Suggested defaults pre-populated on first run (see below).
- **Stats card**: connections decrypted today, connections bypassed today, failures (SNI missing, cert pinning detected).

Suggested bypass defaults to insert at first bootstrap:

| match_type | pattern | reason |
|---|---|---|
| `category` | `banking` | Cert-pinned financial sites |
| `sni` | `*.icloud.com` | Apple cert pinning |
| `sni` | `*.googleapis.com` | Android GMS pinning |
| `sni` | `*.apple.com` | Apple cert pinning |
| `sni` | `*.mozilla.org` | Firefox updates |
| `sni` | `*.windowsupdate.com` | Windows updates |

### iptables setup script

```python
# ssl/iptables_setup.py
"""
Redirect TCP/443 through the SSL interceptor.

These rules only apply to forwarded traffic (not to the IDS's own outbound
connections), so the IDS itself can still reach AbuseIPDB, VirusTotal, etc.
"""
import argparse
import subprocess
import sys

LISTEN_PORT = 8443


def install_rules() -> None:
    # Redirect inbound TCP/443 destined for other hosts into the proxy.
    subprocess.run([
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-p", "tcp", "--dport", "443",
        "-j", "REDIRECT", "--to-port", str(LISTEN_PORT),
    ], check=True)
    print(f"Installed redirect 443 -> {LISTEN_PORT}")


def remove_rules() -> None:
    subprocess.run([
        "iptables", "-t", "nat", "-D", "PREROUTING",
        "-p", "tcp", "--dport", "443",
        "-j", "REDIRECT", "--to-port", str(LISTEN_PORT),
    ], check=True)
    print("Removed redirect rule")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=("install", "remove"))
    args = p.parse_args()

    if sys.platform != "linux":
        print("SSL interception setup only supports Linux.", file=sys.stderr)
        sys.exit(1)

    (install_rules if args.action == "install" else remove_rules)()
```

Run as root: `sudo python -m ssl.iptables_setup install`. Add a matching button on the SSL web page that displays the exact command for the user to copy (don't try to run it from the web UI — Flask isn't running as root, and it shouldn't be).

### What you're signing up for

Roughly:

| Task | Effort |
|---|---|
| CA generation, storage, encryption | 1 day |
| mitmproxy integration + addon | 1–2 days |
| iptables setup + testing on a VM | 1 day |
| Web UI page | 2 days |
| Client trust installation + docs | half day |
| Bypass rules + testing | 1 day |
| Defense-quality docs + threat model | 1 day |

~8 days of focused work. Doable, but it's a significant chunk.

---

## Part 2 — Analytics page

This is more tractable and can be done independently.

### Schema — a new aggregation table

```sql
CREATE TABLE IF NOT EXISTS threat_patterns (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    bucket_type VARCHAR(16) NOT NULL,          -- 'hourly' | 'daily' | 'weekly' | 'monthly'
    bucket_start DOUBLE NOT NULL,              -- epoch seconds
    src_ip VARCHAR(45) NULL,
    host VARCHAR(255) NULL,
    threat_category VARCHAR(64) NULL,          -- reason token, e.g. 'http_sqli'
    event_count INT NOT NULL DEFAULT 0,
    dangerous_count INT NOT NULL DEFAULT 0,
    suspicious_count INT NOT NULL DEFAULT 0,
    max_risk_score DOUBLE NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    INDEX ix_tp_bucket (bucket_type, bucket_start),
    INDEX ix_tp_ip (src_ip, bucket_start),
    INDEX ix_tp_host (host, bucket_start),
    INDEX ix_tp_category (threat_category, bucket_start),
    INDEX ix_tp_lookup (bucket_type, src_ip, host, threat_category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### Aggregation job

New file `storage/analytics.py`:

```python
from __future__ import annotations

import time
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.dialects.mysql import insert as mysql_insert

from storage.db import get_session
from storage.models import PacketLog, ThreatPattern
from logging_config import get_logger

logger = get_logger(__name__)


# Define the four bucket types and how to compute the bucket_start
BUCKETS = {
    "hourly": lambda ts: int(ts // 3600) * 3600,
    "daily": lambda ts: int(ts // 86400) * 86400,
    "weekly": lambda ts: int(ts // (7 * 86400)) * (7 * 86400),
    "monthly": lambda ts: int(datetime.fromtimestamp(ts, tz=timezone.utc)
                              .replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                              .timestamp()),
}


def _aggregate_bucket(bucket_type: str, since_ts: float) -> int:
    """Aggregate packet_logs into threat_patterns for one bucket type."""
    session = get_session()
    try:
        # Group by (bucket_start, src_ip, host, first reason)
        # host is extracted from the url column
        rows = session.execute(
            select(
                PacketLog.timestamp,
                PacketLog.src_ip,
                PacketLog.url,
                PacketLog.classification,
                PacketLog.risk_score,
                PacketLog.reasons_json,
            ).where(PacketLog.timestamp >= since_ts)
             .where(PacketLog.classification.in_(("suspicious", "dangerous")))
        ).all()

        bucket_fn = BUCKETS[bucket_type]
        agg: dict[tuple, dict] = {}

        for ts, src_ip, url, cls, risk, reasons_json in rows:
            bucket_start = bucket_fn(float(ts))
            # Extract host from url
            host = None
            if url:
                try:
                    from urllib.parse import urlparse
                    host = urlparse(url if "://" in url else f"http://{url}").hostname
                except Exception:
                    pass
            # Extract primary threat category from reasons_json
            category = None
            if reasons_json:
                import json
                try:
                    reasons = json.loads(reasons_json)
                    if isinstance(reasons, list):
                        # Prefer http_* or payload_* reason
                        for r in reasons:
                            if isinstance(r, str) and (r.startswith("http_") or r.startswith("payload_")):
                                category = r
                                break
                        if category is None and reasons:
                            category = str(reasons[0])
                except Exception:
                    pass

            key = (bucket_start, src_ip, host, category)
            entry = agg.setdefault(key, {
                "event_count": 0,
                "dangerous_count": 0,
                "suspicious_count": 0,
                "max_risk_score": 0.0,
            })
            entry["event_count"] += 1
            if cls == "dangerous":
                entry["dangerous_count"] += 1
            else:
                entry["suspicious_count"] += 1
            entry["max_risk_score"] = max(entry["max_risk_score"], float(risk or 0))

        # Upsert into threat_patterns
        written = 0
        for (bucket_start, src_ip, host, category), entry in agg.items():
            stmt = (
                mysql_insert(ThreatPattern)
                .values(
                    bucket_type=bucket_type,
                    bucket_start=bucket_start,
                    src_ip=src_ip,
                    host=host,
                    threat_category=category,
                    event_count=entry["event_count"],
                    dangerous_count=entry["dangerous_count"],
                    suspicious_count=entry["suspicious_count"],
                    max_risk_score=entry["max_risk_score"],
                )
                .on_duplicate_key_update(
                    event_count=ThreatPattern.event_count + entry["event_count"],
                    dangerous_count=ThreatPattern.dangerous_count + entry["dangerous_count"],
                    suspicious_count=ThreatPattern.suspicious_count + entry["suspicious_count"],
                    max_risk_score=func.greatest(ThreatPattern.max_risk_score, entry["max_risk_score"]),
                )
            )
            session.execute(stmt)
            written += 1

        session.commit()
        return written
    except Exception:
        session.rollback()
        logger.error("Analytics aggregation failed for bucket=%s", bucket_type, exc_info=True)
        return 0
    finally:
        session.close()


def run_analytics_aggregation(lookback_hours: int = 48) -> dict[str, int]:
    """Aggregate the last N hours into all four bucket types."""
    since_ts = time.time() - lookback_hours * 3600
    results = {}
    for bucket_type in BUCKETS:
        results[bucket_type] = _aggregate_bucket(bucket_type, since_ts)
    return results
```

Then a background worker (like your existing `start_retention_worker`):

```python
def start_analytics_worker():
    while True:
        try:
            run_analytics_aggregation(lookback_hours=48)
        except Exception:
            import logging
            logging.getLogger(__name__).error("Analytics worker failed", exc_info=True)
        time.sleep(3600)  # hourly
```

Start it in `uni-srver.py`'s `__main__` block alongside `start_retention_worker`.

### API endpoints

```python
# uni-srver.py

@app.route("/analytics/heatmap")
@login_required
@role_required("admin", "soc")
def analytics_heatmap():
    """Day-of-week × hour heatmap of dangerous events, last N weeks."""
    weeks = request.args.get("weeks", default=8, type=int)
    ...
    return api_ok({"labels": [...], "data": [...]})

@app.route("/analytics/recurring-ips")
@login_required
@role_required("admin", "soc")
def analytics_recurring_ips():
    """IPs that appear on >= N distinct days in the last M days."""
    min_days = request.args.get("min_days", default=3, type=int)
    lookback_days = request.args.get("days", default=30, type=int)
    ...
    return api_ok([...])

@app.route("/analytics/recurring-hosts")
@login_required
@role_required("admin", "soc")
def analytics_recurring_hosts():
    """Hosts that appear on >= N distinct days."""
    ...

@app.route("/analytics/top-threats")
@login_required
@role_required("admin", "soc")
def analytics_top_threats():
    """Threat categories ranked, with sparkline-ready timeseries."""
    ...
```

### Web UI — Analytics page

New template `templates/analytics.html`, route `/analytics`, link from the main nav. Sections:

1. **Weekly heatmap** — 7×24 grid (day-of-week × hour-of-day), colored by dangerous event count. Answer: *"which hours/days do I get attacked?"*
2. **Recurring attackers** — table of IPs appearing on multiple distinct days, with first-seen, last-seen, total events, threat types. Answer: *"who keeps coming back?"*
3. **Recurring hosts** — same for domains. Answer: *"which domains keep showing up?"*
4. **Threat category breakdown** — bar chart + trend line per category. Answer: *"what kind of attacks am I facing?"*
5. **Monthly pattern list** — "Every Friday around 14:00 UTC, IP 1.2.3.4 launches an HTTP SQLi attack" style cards, generated by finding bucket rows with high counts and stable periodicity.

For point 5, use a simple periodicity detector: for each `src_ip` or `host`, compute the distribution of events across the 7 day-of-week buckets. If one day-of-week contains ≥60% of events, flag it. Do the same for hour-of-day, week-of-month.

```python
def detect_periodic_pattern(src_ip: str, days: int = 60) -> dict | None:
    """
    Return {'dow': 4, 'share': 0.72, ...} if the IP attacks on a
    consistent day-of-week, else None.
    """
    # Query threat_patterns daily buckets for this IP, last N days.
    # Group by day-of-week, compute share of total events.
    # If max share >= 0.60 and at least 3 distinct weeks, it's periodic.
    ...
```

Add to the analytics page as cards: *"Recurring Fridays — IP 1.2.3.4, 8 weeks running, avg 14 events per Friday"*.

### Historical backfill

The aggregation job only fills forward. To populate the analytics page from day one:

```bash
python -m storage.analytics --backfill --days 30
```

Read all `packet_logs` from the last 30 days, bucket them, upsert into `threat_patterns`. Run once after deployment.

### Effort estimate

| Task | Effort |
|---|---|
| Schema + model | half day |
| Aggregation job + backfill CLI | 1 day |
| API endpoints (4–5 routes) | 1 day |
| Web UI page with charts | 2 days |
| Periodicity detector | 1 day |
| Polish + tests | 1 day |

~6 days. Doable in parallel with the SSL work if you split time.

---

## Suggested order

1. **Analytics first** — no security implications, ships fast, immediately useful, and it's a nice way to validate that the DB/aggregation design works before taking on SSL.
2. **SSL decryption second** — big, but self-contained. Do the CA part first, get one host decrypting, then build the UI.

## Questions before I write the actual code

For each feature, I'd want to confirm:

**SSL:**
1. Is `mitmproxy` acceptable as a dependency, or do you need a from-scratch implementation for the thesis? (I strongly recommend the former.)
2. Where should the root CA private key live — plaintext file, or encrypted in MySQL with a passphrase in `.env`?
3. Is this inline (IDS-as-gateway) or are you targeting a specific topology? The iptables rules differ.
4. Do you want me to write the CA module first, or the whole feature end-to-end?

**Analytics:**
1. Are 4 bucket types (hourly/daily/weekly/monthly) too many? 2 (daily + weekly) might be enough.
2. Do you want the periodicity detector in the first pass, or just the raw aggregations?
3. Should the analytics page live under `/analytics` (new top-level nav item) or as a tab within `/dashboard`?

Answer those and I'll produce the actual code files — schema additions for `bootstrap_db.py`, the `storage/analytics.py` module, the SSL modules, and the HTML/JS for both pages. If you want me to start with one feature only, tell me which, and I'll do that end-to-end first.
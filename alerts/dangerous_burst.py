"""
Rate-limited email alerts when a single source IP exceeds a burst of high-risk
events within a rolling time window.

The alert body is designed for SOC triage: it names the source (with
geography and reputation when available), summarises what was targeted,
scores severity relative to the threshold, and links to a filtered view
of the dashboard for investigation.

Two separate thresholds are supported:
  - fast bursts: many dangerous events in a short window (default 10 / 20m)
  - slow scans:  many suspicious-but-elevated events in the same window
                 (default 50, risk >= 0.45). Fires at a much higher count
                 so ordinary noise does not trigger it.
"""

from __future__ import annotations

import ipaddress
import os
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

from alerts.email_alert import send_alert
from logging_config import get_logger

logger = get_logger(__name__)

# --- Fast burst thresholds -------------------------------------------------
_WINDOW_SEC = int(os.getenv("IDS_BURST_ALERT_WINDOW_SEC", str(20 * 60)) or (20 * 60))
_THRESHOLD = int(os.getenv("IDS_BURST_ALERT_MIN_EVENTS", "10") or "10")
_DEDUP_SEC = int(os.getenv("IDS_BURST_ALERT_DEDUP_SEC", str(10 * 60)) or (10 * 60))
_DANGEROUS_RISK = float(os.getenv("IDS_DANGEROUS_THRESHOLD", "0.78") or "0.78")

# --- Slow-scan thresholds --------------------------------------------------
_SLOW_RISK = float(os.getenv("IDS_BURST_ALERT_SLOW_RISK", "0.45") or "0.45")
_SLOW_THRESHOLD = int(os.getenv("IDS_BURST_ALERT_SLOW_MIN_EVENTS", "50") or "50")

# --- Alert channel protection ----------------------------------------------
_GLOBAL_DEDUP_SEC = int(os.getenv("IDS_BURST_ALERT_GLOBAL_DEDUP_SEC", "30") or "30")

_LOCK = threading.Lock()
# Per-source bucket: [(ts, reasons, context), ...]
# `context` carries dst_ip, dst_port, url, mitre for aggregation at send time.
_EVENTS: dict[str, list[tuple[float, frozenset[str], dict]]] = defaultdict(list)
_LAST_EMAIL: dict[str, float] = {}

_EVICT_EVERY = 5000
_evict_counter = 0
_MAX_IDLE_SEC = max(_WINDOW_SEC, _DEDUP_SEC)

# Global rate limiter (protects the mail channel from distributed scans)
_last_global_send: float = 0.0
_global_suppressed: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_html(
    *,
    src_ip: str,
    tier: str,
    count: int,
    threshold: int,
    kind: str,
    internal: bool,
    reputation: dict | None,
    recurrence: str | None,
    velocity: float,
    trend: str,
    suggested_action: str,
    dst_counter: Counter,
    url_counter: Counter,
    mitre_entries: dict[str, dict],
    merged: set[str],
) -> str:
    """Render the same content as the plaintext body, but as HTML."""
    from html import escape

    # Colour-code severity. Analysts triage colour-first.
    tier_colour = {
        "critical": "#dc2626",
        "high":     "#ea580c",
        "elevated": "#ca8a04",
        "info":     "#0284c7",
    }.get(tier, "#475569")

    def row(label, value):
        return (
            f'<tr>'
            f'<td style="padding:4px 12px 4px 0;color:#64748b;'
            f'font-size:13px;white-space:nowrap;vertical-align:top">{escape(label)}</td>'
            f'<td style="padding:4px 0;color:#0f172a;font-size:13px">'
            f'{value}</td>'
            f'</tr>'
        )

    def list_block(title, items):
        if not items:
            return ""
        lis = "".join(
            f'<li style="margin:2px 0;font-family:ui-monospace,Menlo,monospace;'
            f'font-size:12px">{escape(str(i))}</li>'
            for i in items
        )
        return (
            f'<h3 style="margin:18px 0 6px;font-size:13px;color:#334155;'
            f'text-transform:uppercase;letter-spacing:0.04em">{escape(title)}</h3>'
            f'<ul style="margin:0;padding-left:20px">{lis}</ul>'
        )

    # MITRE tactic grouping
    mitre_html = ""
    if mitre_entries:
        by_tactic: dict[str, list[dict]] = {}
        for entry in mitre_entries.values():
            by_tactic.setdefault(entry["tactic"], []).append(entry)
        rows = []
        for tactic in sorted(by_tactic):
            entries = sorted(by_tactic[tactic], key=lambda e: e["technique"])
            techs = ", ".join(
                f'<code style="background:#f1f5f9;padding:1px 5px;'
                f'border-radius:3px;font-size:12px">{escape(e["technique"])}</code>'
                for e in entries
            )
            rows.append(
                f'<tr>'
                f'<td style="padding:3px 12px 3px 0;color:#64748b;'
                f'font-size:12px;white-space:nowrap;vertical-align:top">'
                f'{escape(tactic)}</td>'
                f'<td style="padding:3px 0">{techs}</td>'
                f'</tr>'
            )
        mitre_html = (
            '<h3 style="margin:18px 0 6px;font-size:13px;color:#334155;'
            'text-transform:uppercase;letter-spacing:0.04em">'
            'Attack profile</h3>'
            f'<table style="border-collapse:collapse">{"".join(rows)}</table>'
        )

    # Reputation badge
    rep_html = "no cached verdict"
    if reputation:
        v = (reputation.get("verdict") or "unknown").lower()
        rep_colour = {
            "malicious": "#dc2626",
            "suspicious": "#ea580c",
        }.get(v, "#475569")
        score = reputation.get("score")
        rep_html = (
            f'<span style="color:{rep_colour};font-weight:600">'
            f'{escape(v)}</span>'
            + (f' (score {score})' if score is not None else "")
        )

    def counter_block(title, counter):
        if not counter:
            return ""
        items = "".join(
            f'<li style="margin:2px 0;font-family:ui-monospace,Menlo,monospace;'
            f'font-size:12px">{escape(str(k))} — {v} events</li>'
            for k, v in counter.most_common(5)
        )
        return (
            f'<h3 style="margin:18px 0 6px;font-size:13px;color:#334155;'
            f'text-transform:uppercase;letter-spacing:0.04em">{escape(title)}</h3>'
            f'<ul style="margin:0;padding-left:20px">{items}</ul>'
        )

    # Final HTML
    return f"""<!DOCTYPE html>
<html><body style="margin:0;padding:24px;background:#f8fafc;
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  color:#0f172a">
  <div style="max-width:640px;margin:0 auto;background:#fff;
    border:1px solid #e2e8f0;border-radius:8px;overflow:hidden">

    <!-- Severity banner -->
    <div style="padding:14px 20px;background:{tier_colour};color:#fff">
      <div style="font-size:11px;text-transform:uppercase;
        letter-spacing:0.08em;opacity:0.85">
        Enterprise AI IDS · {escape(kind)} burst
      </div>
      <div style="font-size:20px;font-weight:600;margin-top:2px">
        {escape(tier.upper())} — {escape(src_ip)}
      </div>
    </div>

    <!-- Suggested action -->
    <div style="padding:14px 20px;background:#fffbeb;border-bottom:1px solid #fde68a">
      <div style="font-size:11px;text-transform:uppercase;color:#92400e;
        letter-spacing:0.08em;font-weight:600">Suggested action</div>
      <div style="margin-top:4px;font-size:13px;color:#78350f">
        {escape(suggested_action)}
      </div>
    </div>

    <!-- Summary table -->
    <div style="padding:16px 20px">
      <table style="border-collapse:collapse;width:100%">
        {row("Source", escape(src_ip) + (' <span style="color:#64748b">(internal)</span>' if internal else ' <span style="color:#64748b">(external)</span>'))}
        {row("Reputation", rep_html)}
        {row("Recurrence", escape(recurrence) if recurrence else "first appearance")}
        {row("Events", f"{count} in the last {_WINDOW_SEC // 60} min")}
        {row("Threshold", f"{threshold} ({escape(kind)})")}
        {row("Velocity", f"{velocity:.2f} events/sec — {escape(trend)}")}
      </table>

      {counter_block("Top targets", dst_counter)}
      {counter_block("Top URLs", url_counter)}
      {mitre_html}
      {list_block("Reason tokens", sorted(merged)[:15])}
    </div>

    <!-- Footer -->
    <div style="padding:12px 20px;background:#f8fafc;border-top:1px solid #e2e8f0;
      font-size:11px;color:#64748b">
      This alert was generated automatically. Review the IDS dashboard for
      full context. Tune thresholds with <code>IDS_BURST_ALERT_*</code>.
    </div>
  </div>
</body></html>"""

def _is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _burst_eligible(classification: str | None, risk_score: float | None) -> str | None:
    """Return 'fast', 'slow', or None."""
    c = (classification or "").lower()
    if c == "dangerous":
        return "fast"
    if c == "suspicious" and risk_score is not None:
        r = float(risk_score)
        if r >= _DANGEROUS_RISK:
            return "fast"
        if r >= _SLOW_RISK:
            return "slow"
    return None


def _event_context(dst_ip, dst_port, url, mitre) -> dict:
    # Keep the full entries (technique + tactic + name) so the email can
    # group by tactic rather than dumping a flat list of IDs.
    techs: list[dict] = []
    if mitre:
        for m in mitre:
            if isinstance(m, dict) and m.get("technique"):
                techs.append({
                    "technique": str(m["technique"]),
                    "tactic": str(m.get("tactic") or "Unmapped"),
                    "name": str(m.get("name") or ""),
                })
    return {
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "url": url,
        "mitre": techs,
    }


def _evict_idle_locked(now: float) -> None:
    stale_cutoff = now - _MAX_IDLE_SEC
    stale_ips = [
        ip for ip, events in _EVENTS.items()
        if not events or events[-1][0] < stale_cutoff
    ]
    for ip in stale_ips:
        _EVENTS.pop(ip, None)
        _LAST_EMAIL.pop(ip, None)


def _threat_types(reasons: list | None) -> frozenset[str]:
    out: set[str] = set()
    if not reasons:
        return frozenset()
    for r in reasons:
        if not isinstance(r, str) or not r.strip():
            continue
        out.add(r.strip())
    return frozenset(out)


def _severity_tier(count: int, threshold: int, reputation: dict | None, internal: bool) -> str:
    ratio = count / max(threshold, 1)
    if reputation and (reputation.get("verdict") or "").lower() == "malicious":
        return "critical"
    if ratio >= 10:
        return "critical"
    if internal or ratio >= 3:
        return "high"
    if ratio >= 1.2:
        return "elevated"
    return "info"

def _suggested_action(tier: str, internal: bool, kind: str) -> str:
    """
    One-line response guidance for tier-1 triage. Deliberately conservative:
    the alert recommends, the analyst decides.
    """
    if internal:
        # Internal source is always a compromise indicator.
        if tier == "critical":
            return ("Isolate the internal host from the network and begin "
                    "incident response — it may be compromised and used as "
                    "a pivot or exfiltration origin.")
        return ("Investigate the internal host. Internal sources generating "
                "attack traffic usually indicate a compromised endpoint.")

    # External source
    if tier == "critical":
        return ("Block at the perimeter now. High-volume external attack "
                "with corroborating reputation and history.")
    if tier == "high":
        return ("Block at the perimeter if the target is exposed; otherwise "
                "review target logs to confirm the attempts failed.")
    if tier == "elevated":
        return ("Monitor. Add the source to the watch list; escalate if "
                "the pattern continues or a target shows signs of success.")
    if kind == "slow":
        return ("Low-and-slow pattern from an external source. Review target "
                "logs for any successful request; block if the target is "
                "internet-facing.")
    return "Log only. No action required."

def _fmt_utc(dt) -> str:
    if dt is None:
        return "unknown"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ---------------------------------------------------------------------------
# Cached lookups (best-effort; failures never break the alert path)
# ---------------------------------------------------------------------------

def _lookup_cached_reputation(ip: str) -> dict | None:
    try:
        from sqlalchemy import select
        from storage.db import get_session
        from storage.models import ThreatIntelCache

        session = get_session()
        try:
            now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
            row = session.execute(
                select(ThreatIntelCache)
                .where(ThreatIntelCache.lookup_key == ip)
                .where(ThreatIntelCache.lookup_type == "ip")
                .where(ThreatIntelCache.expires_at > now_naive)
                .order_by(ThreatIntelCache.cached_at.desc())
                .limit(1)
            ).scalar_one_or_none()
            if row is None:
                return None
            return {"verdict": row.verdict, "score": row.score}
        finally:
            session.close()
    except Exception:
        logger.debug("Reputation lookup failed for %s", ip, exc_info=True)
        return None


def _lookup_dangerous_ip_history(ip: str) -> dict | None:
    try:
        from sqlalchemy import select
        from storage.db import get_session
        from storage.models import DangerousIp

        session = get_session()
        try:
            row = session.execute(
                select(DangerousIp).where(DangerousIp.ip_address == ip)
            ).scalar_one_or_none()
            if row is None:
                return None
            return {
                "first_seen": row.first_seen,
                "last_seen": row.last_seen,
                "event_count": row.event_count,
            }
        finally:
            session.close()
    except Exception:
        logger.debug("History lookup failed for %s", ip, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def maybe_alert_dangerous_burst(
    *,
    src_ip: str | None,
    classification: str | None,
    risk_score: float | None,
    reasons: list | None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    url: str | None = None,
    mitre: list | None = None,
) -> None:
    if not src_ip:
        return

    kind = _burst_eligible(classification, risk_score)
    if kind is None:
        return

    global _evict_counter, _last_global_send, _global_suppressed

    now = time.time()
    cutoff = now - _WINDOW_SEC
    types = _threat_types(reasons)
    ctx = _event_context(dst_ip, dst_port, url, mitre)

    with _LOCK:
        _evict_counter += 1
        if _evict_counter % _EVICT_EVERY == 0:
            _evict_idle_locked(now)

        bucket = _EVENTS[src_ip]
        bucket.append((now, types, ctx))
        bucket[:] = [(t, ts, c) for t, ts, c in bucket if t >= cutoff]

        # Fast and slow share the same bucket. The count comparison picks
        # whichever threshold the current traffic pattern is clearing.
        threshold = _THRESHOLD if kind == "fast" else _SLOW_THRESHOLD

        if len(bucket) <= threshold:
            return

        last = _LAST_EMAIL.get(src_ip, 0.0)
        if now - last < _DEDUP_SEC:
            return

        # Global channel guard: if another alert went out in the last
        # _GLOBAL_DEDUP_SEC, suppress this one but count it so the next
        # email can report how many were coalesced.
        if now - _last_global_send < _GLOBAL_DEDUP_SEC:
            _global_suppressed += 1
            return

        _last_global_send = now
        _LAST_EMAIL[src_ip] = now
        count = len(bucket)
        suppressed_snapshot = _global_suppressed
        _global_suppressed = 0

        merged: set[str] = set()
        dst_counter: Counter[str] = Counter()
        url_counter: Counter[str] = Counter()
        mitre_entries: dict[str, dict] = {}   # technique -> full entry
        for _, ts, c in bucket:
            merged.update(ts)
            if c.get("dst_ip"):
                dst_counter[c["dst_ip"]] += 1
            if c.get("url"):
                url_counter[c["url"]] += 1
            for entry in c.get("mitre") or ():
                if isinstance(entry, dict) and entry.get("technique"):
                    mitre_entries[entry["technique"]] = entry

        # Burst span and velocity
        first_ts = bucket[0][0]
        last_ts = bucket[-1][0]
        span_sec = max(1.0, last_ts - first_ts)
        velocity = count / span_sec  # events per second

        # Trend: compare the most recent half-window against the older half.
        half_cutoff = now - (_WINDOW_SEC / 2)
        recent = sum(1 for t, _, _ in bucket if t >= half_cutoff)
        older = count - recent
        if older == 0 and recent > 0:
            trend = "new"
        elif recent > older * 1.5:
            trend = "accelerating"
        elif recent < older * 0.5:
            trend = "decelerating"
        else:
            trend = "steady"

    # --- everything below runs outside the lock ---

    internal = _is_internal(src_ip)
    reputation = _lookup_cached_reputation(src_ip)
    history = _lookup_dangerous_ip_history(src_ip)
    tier = _severity_tier(count, threshold, reputation, internal)

    # Recurrence hint: how long has this IP been active, and how much has
    # it done? A first-seen days ago plus hundreds of events is a repeat
    # offender. A first-seen ten minutes ago plus the current burst is a
    # new appearance.
    recurrence = None
    if history and history.get("first_seen"):
        age_days = (datetime.now(timezone.utc) - (
            history["first_seen"] if history["first_seen"].tzinfo
            else history["first_seen"].replace(tzinfo=timezone.utc)
        )).total_seconds() / 86400
        if age_days < 0.05:
            recurrence = "new today"
        elif age_days < 1:
            recurrence = "seen within the last 24 hours"
        elif age_days < 7:
            recurrence = f"active for {int(age_days)} day(s)"
        else:
            recurrence = f"active for {int(age_days)} days"

    action = _suggested_action(tier, internal, kind)

    body = _build_body(
        src_ip=src_ip,
        kind=kind,
        tier=tier,
        count=count,
        threshold=threshold,
        internal=internal,
        reputation=reputation,
        history=history,
        merged=merged,
        dst_counter=dst_counter,
        url_counter=url_counter,
        mitre_entries=mitre_entries,
        suppressed=suppressed_snapshot,
        velocity=velocity,
        trend=trend,
        recurrence=recurrence,
        suggested_action=action,
    )

    html = _build_html(
        src_ip=src_ip,
        tier=tier,
        count=count,
        threshold=threshold,
        kind=kind,
        internal=internal,
        reputation=reputation,
        recurrence=recurrence,
        velocity=velocity,
        trend=trend,
        suggested_action=action,
        dst_counter=dst_counter,
        url_counter=url_counter,
        mitre_entries=mitre_entries,
        merged=merged,
    )

    # JSON attachment so SOAR/ticketing systems can parse without scraping
    # the body. Kept small — just the fields the alert already shows.
    import json
    detail = {
        "src_ip": src_ip,
        "kind": kind,
        "severity": tier,
        "internal": internal,
        "count": count,
        "threshold": threshold,
        "window_sec": _WINDOW_SEC,
        "velocity_per_sec": round(velocity, 4),
        "trend": trend,
        "recurrence": recurrence,
        "reputation": reputation,
        "top_targets": dict(dst_counter.most_common(10)),
        "top_urls": dict(url_counter.most_common(10)),
        "mitre": list(mitre_entries.values()),
        "reasons": sorted(merged)[:50],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    attachment = (
        f"burst-{src_ip.replace(':','_')}-{int(now)}.json",
        "application/json",
        json.dumps(detail, indent=2, ensure_ascii=False).encode("utf-8"),
    )

    try:
        send_alert(
            f"[IDS][{tier.upper()}] Burst alert: {src_ip} "
            f"({count} events / {_WINDOW_SEC // 60} min)",
            body,
            html=html,
            attachments=[attachment],
        )
    except Exception:
        logger.error(
            "Burst alert delivery raised despite send_alert's contract",
            exc_info=True,
        )


# ---------------------------------------------------------------------------
# Email body
# ---------------------------------------------------------------------------

def _build_body(
    *,
    src_ip: str,
    kind: str,
    tier: str,
    count: int,
    threshold: int,
    internal: bool,
    reputation: dict | None,
    history: dict | None,
    merged: set[str],
    dst_counter: Counter,
    url_counter: Counter,
    mitre_entries: dict[str, dict],
    suppressed: int,
    velocity: float,
    trend: str,
    recurrence: str | None,
    suggested_action: str,
) -> str:
    lines: list[str] = []

    # --- Summary (what the analyst reads first) ----------------------------
    lines.append(f"ACTION:    {suggested_action}")
    lines.append("")

    # --- Source identity ---------------------------------------------------
    direction = "Internal" if internal else "External"
    lines.append(f"Source:    {src_ip}  ({direction})")

    if reputation:
        verdict = reputation.get("verdict") or "unknown"
        score = reputation.get("score")
        if score is not None:
            lines.append(f"Rep:       {verdict} (provider score {score})")
        else:
            lines.append(f"Rep:       {verdict}")
    else:
        lines.append("Rep:       no cached verdict (lookup not yet run or skipped)")

    if history:
        hist_line = (
            f"History:   {history['event_count']} events since "
            f"{_fmt_utc(history['first_seen'])}"
        )
        if recurrence:
            hist_line += f" — {recurrence}"
        lines.append(hist_line)
    else:
        lines.append("History:   first appearance on this sensor")

    lines.append("")

    # --- Event profile -----------------------------------------------------
    lines.append(f"Events:    {count} in the last {_WINDOW_SEC // 60} minutes")
    lines.append(f"Threshold: {threshold} ({kind} burst)")
    lines.append(f"Severity:  {tier} ({count / max(threshold, 1):.1f}x threshold)")
    lines.append(f"Velocity:  {velocity:.2f} events/sec ({trend})")

    if kind == "slow":
        lines.append(
            "           Note: slow scan — no single event crossed the dangerous "
            "threshold, but the pattern is persistent."
        )

    if suppressed:
        lines.append("")
        lines.append(
            f"Note:      {suppressed} additional burst(s) were detected in the "
            f"last {_GLOBAL_DEDUP_SEC} seconds and suppressed to protect the "
            f"mail channel."
        )

    # --- Targets -----------------------------------------------------------
    if dst_counter:
        lines.append("")
        lines.append("Top targets:")
        for dst, n in dst_counter.most_common(5):
            lines.append(f"  {dst:<22} ({n} events)")

    if url_counter:
        lines.append("")
        lines.append("Top URLs:")
        for u, n in url_counter.most_common(5):
            display = u if len(u) <= 100 else u[:97] + "..."
            lines.append(f"  {display}  ({n})")

    # --- Attack profile by tactic -----------------------------------------
    if mitre_entries:
        by_tactic: dict[str, list[dict]] = {}
        for entry in mitre_entries.values():
            by_tactic.setdefault(entry["tactic"], []).append(entry)

        lines.append("")
        lines.append("Attack profile (grouped by MITRE ATT&CK tactic):")
        for tactic in sorted(by_tactic):
            entries = sorted(by_tactic[tactic], key=lambda e: e["technique"])
            techs = ", ".join(
                f"{e['technique']}"
                + (f" ({e['name']})" if e.get("name") else "")
                for e in entries
            )
            lines.append(f"  {tactic}: {techs}")

    # --- Reasons (raw) -----------------------------------------------------
    lines.append("")
    lines.append("Reason tokens observed:")
    if merged:
        for item in sorted(merged)[:15]:
            lines.append(f"  {item}")
        if len(merged) > 15:
            lines.append(f"  ... and {len(merged) - 15} more")
    else:
        lines.append("  (no structured reasons; see IDS logs)")

    return "\n".join(lines)
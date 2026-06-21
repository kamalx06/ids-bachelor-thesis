"""
Hybrid AI scoring: ML + behavioral heuristics + optional TI.

- ai_score: raw ML output (dashboard trend / top-IP bars)
- risk_score: adjusted + signals, used for safe / suspicious / dangerous
"""

from __future__ import annotations

import os
from typing import Any

from ai.classifier import predict, model_is_trusted
from engine.behavior import detect as detect_behavior
from engine.payload_analyzer import analyze_payload
from logging_config import get_logger

logger = get_logger(__name__)

_SUSPICIOUS_THRESHOLD = float(os.getenv("IDS_SUSPICIOUS_THRESHOLD", "0.52") or "0.52")
_DANGEROUS_THRESHOLD = float(os.getenv("IDS_DANGEROUS_THRESHOLD", "0.78") or "0.78")

# Benign traffic: small lift. Attack signals: larger lift (see _has_attack_signals).
_MAX_SCORE_BOOST = float(os.getenv("IDS_MAX_SCORE_BOOST", "0.18") or "0.18")
_MAX_ATTACK_BOOST = float(os.getenv("IDS_MAX_ATTACK_BOOST", "0.35") or "0.35")

_BEHAVIOR_BOOST = {
    "port_scan": 0.20,
    "flood": 0.28,
    "dns_tunnel": 0.14,
    "dns_tunnel_suspected": 0.16,
    "dns_suspicious": 0.10,
}

_ATTACK_REASON_PREFIXES = (
    "http_",
    "payload_",
    "ml_attack",
    "strong_anomaly",
    "high_rf_attack",
    "combined_ml",
)


def _risk_from_verdict(verdict: str) -> float:
    v = (verdict or "unknown").lower()
    if v == "malicious":
        return 0.85
    if v == "suspicious":
        return 0.45
    if v == "safe":
        return 0.0
    return 0.08


def _source_score(enrichment: dict | None) -> float:
    if not enrichment:
        return 0.0
    raw = enrichment.get("score")
    if raw is not None:
        try:
            return max(0.0, min(1.0, float(raw)))
        except (TypeError, ValueError):
            pass
    return _risk_from_verdict(str(enrichment.get("verdict") or "unknown"))


def _has_attack_signals(
    reasons: list[str],
    *,
    behavior: str | None,
    rf_pred: int,
) -> bool:
    if behavior in ("port_scan", "flood"):
        return True
    if rf_pred == 1:
        return True
    for r in reasons:
        if not isinstance(r, str):
            continue
        rl = r.lower()
        if r in ("ml_attack", "anomaly", "strong_anomaly_detected", "high_rf_attack_probability"):
            return True
        if any(rl.startswith(p) for p in _ATTACK_REASON_PREFIXES):
            return True
    return False


def _content_attack_reasons(data: dict) -> list[str]:
    """Detect SQLi/XSS/etc. in HTTP path/body (ids_engine path, not legacy sniffer)."""
    found: list[str] = []
    http = data.get("http") or {}
    parts: list[str] = []
    if isinstance(http, dict):
        for key in ("path", "body", "url"):
            val = http.get(key)
            if val:
                parts.append(str(val))
    if data.get("url"):
        parts.append(str(data["url"]))
    preview = data.get("payload") or data.get("payload_preview")
    if preview:
        parts.append(str(preview))

    blob = " ".join(parts)
    if not blob.strip():
        return found

    # Skip generic payload scan on bare hostnames without request context
    has_request_context = bool(
        (isinstance(http, dict) and (http.get("path") or http.get("method")))
        or ("?" in blob)
        or ("=" in blob)
        or ("/" in blob and len(blob) > 12)
    )
    if not has_request_context and len(blob) < 24:
        return found

    for category in analyze_payload(blob):
        token = f"http_{category.lower()}"
        if token not in found:
            found.append(token)
    return found


def _heuristic_signals(data: dict) -> tuple[float, list[str]]:
    boost = 0.0
    reasons: list[str] = []

    meta = data.get("meta") or {}
    entropy = float(meta.get("payload_entropy") or 0.0)
    if entropy > 7.2:
        boost += min(0.10, (entropy - 7.0) * 0.06)
        reasons.append("high_payload_entropy")

    unusual_port = meta.get("unusual_port")
    if unusual_port:
        boost += 0.06
        reasons.append(f"unusual_port_{unusual_port}")

    pps = float(meta.get("flow_packets_per_s") or 0.0)
    if pps > 500:
        boost += min(0.12, pps / 6000.0)
        reasons.append("traffic_burst")

    if data.get("is_https") and data.get("dst_port") not in (443, 8443):
        boost += 0.04
        reasons.append("https_port_mismatch")

    return boost, reasons


def _capped_adjusted_score(
    ml_score: float,
    *,
    behavior: str | None,
    dns_reasons: list[str] | None,
    heuristic_boost: float,
    attack_signals: bool,
) -> float:
    ml = max(0.0, min(1.0, float(ml_score)))
    extra = float(heuristic_boost or 0.0)

    if behavior:
        extra += _BEHAVIOR_BOOST.get(behavior, 0.10)

    if dns_reasons:
        extra += min(0.12, 0.03 * len(dns_reasons))

    cap = _MAX_ATTACK_BOOST if attack_signals else _MAX_SCORE_BOOST
    extra = min(cap, extra)
    if extra <= 0:
        return ml

    adjusted = ml + extra * (1.0 - ml * 0.45)
    return min(1.0, min(adjusted, ml + cap))


def _ti_floor_risk(ti_ip: dict | None, ti_url: dict | None) -> float:
    """Minimum fused risk when threat intel confirms malicious activity."""
    floor = 0.0
    for enrichment in (ti_ip, ti_url):
        if not enrichment:
            continue
        verdict = str(enrichment.get("verdict") or "").lower()
        raw_score = enrichment.get("score")
        try:
            score = float(raw_score) if raw_score is not None else 0.0
        except (TypeError, ValueError):
            score = 0.0
        if verdict == "malicious" or score >= 0.90:
            floor = max(floor, 0.88)
        elif verdict == "suspicious" or score >= 0.50:
            floor = max(floor, 0.58)
    return floor


def _final_risk(
    ml_score: float,
    adjusted_score: float,
    reasons: list[str],
    ti_ip: dict | None,
    ti_url: dict | None,
    zeek: dict | None,
    *,
    attack_signals: bool,
) -> float:
    ml = max(0.0, min(1.0, float(ml_score)))
    fused = max(ml, float(adjusted_score))

    ti = max(_source_score(ti_ip), _source_score(ti_url))
    if ti > 0:
        ti_weight = 0.28 if attack_signals else 0.16
        if ti >= 0.85:
            ti_weight = 0.45 if attack_signals else 0.32
        gate = 0.50 if attack_signals else 0.30
        fused = min(1.0, fused + ti * min(1.0, max(gate, ml / 0.55)) * ti_weight)

    if zeek and zeek.get("logs_available"):
        fused = min(1.0, fused + _source_score(zeek) * 0.12)

    ti_floor = _ti_floor_risk(ti_ip, ti_url)
    if ti_floor > 0:
        fused = max(fused, ti_floor)

    max_lift = _MAX_ATTACK_BOOST if attack_signals else _MAX_SCORE_BOOST
    return min(1.0, max(fused, ml + (max_lift * 0.5 if attack_signals else max_lift * 0.3)))


def _classify_from_risk(
    fused_risk: float,
    ml_label: str,
    reasons: list[str],
    behavior: str | None,
    *,
    rf_pred: int,
    attack_signals: bool,
) -> str:
    if fused_risk >= _DANGEROUS_THRESHOLD:
        return "dangerous"
    if fused_risk >= _SUSPICIOUS_THRESHOLD:
        return "suspicious"

    # Threat intel floors — known-bad indicators should not read as safe
    if any(str(r).startswith("reputation_ip_malicious") for r in reasons):
        return "dangerous" if fused_risk >= 0.72 else "suspicious"
    if any(str(r).startswith("reputation_url_malicious") for r in reasons):
        return "dangerous" if fused_risk >= 0.70 else "suspicious"
    if any(str(r).startswith("reputation_ip_suspicious") for r in reasons):
        return "suspicious"

    # Heuristic floors — do not rely on fused alone for obvious attacks
    if behavior == "flood":
        return "dangerous" if fused_risk >= 0.55 else "suspicious"
    if behavior == "port_scan":
        return "dangerous" if fused_risk >= 0.65 else "suspicious"
    if rf_pred == 1 and fused_risk >= 0.48:
        return "dangerous" if fused_risk >= 0.62 else "suspicious"
    if "ml_attack" in reasons and fused_risk >= 0.45:
        return "dangerous" if fused_risk >= 0.60 else "suspicious"
    if attack_signals and any(str(r).startswith("http_") for r in reasons):
        return "dangerous" if fused_risk >= 0.58 else "suspicious"
    if attack_signals and fused_risk >= 0.50:
        return "suspicious"
    if ml_label == "dangerous" and fused_risk >= 0.55:
        return "dangerous"
    if ml_label == "suspicious" and fused_risk >= 0.42:
        return "suspicious"

    return "safe"


def analyze_packet(
    data: dict,
    *,
    ti_ip: dict | None = None,
    ti_url: dict | None = None,
    zeek: dict | None = None,
    dns_reasons: list[str] | None = None,
    queue_pressure: float = 0.0,
    skip_heavy_enrichment: bool = False,
) -> dict[str, Any]:
    rf_pred, iso_pred, ml_score, ml_label, ai_reasons, detail = predict(data["features"])

    behavior = detect_behavior(data["src_ip"], data.get("dst_port"))
    heuristic_boost, heuristic_reasons = _heuristic_signals(data)

    reasons: list[str] = list(ai_reasons or [])
    reasons.extend(heuristic_reasons)
    reasons.extend(_content_attack_reasons(data))

    if behavior:
        reasons.append(behavior)
    if dns_reasons:
        for dr in dns_reasons:
            if dr not in reasons:
                reasons.append(dr)

    if rf_pred == 1:
        reasons.append("ml_attack")
    if iso_pred == -1 and detail.get("anomaly_strength", 0) >= 0.40:
        reasons.append("anomaly")

    ml = float(ml_score)
    if not model_is_trusted():
        ml *= 0.92
        reasons.append("ml_model_untrusted")

    attack_signals = _has_attack_signals(reasons, behavior=behavior, rf_pred=rf_pred)

    adjusted = _capped_adjusted_score(
        ml,
        behavior=behavior,
        dns_reasons=dns_reasons,
        heuristic_boost=heuristic_boost,
        attack_signals=attack_signals,
    )

    if ti_ip is None and ti_url is None and zeek is None:
        from ids.threat_intel import enrich

        ti_ip, ti_url, zeek, ti_reasons = enrich(
            data,
            ai_score=adjusted,
            behavior=behavior,
            queue_pressure=queue_pressure,
            skip_heavy=skip_heavy_enrichment,
            model_trusted=model_is_trusted(),
        )
        for r in ti_reasons:
            if r not in reasons:
                reasons.append(r)
        attack_signals = _has_attack_signals(reasons, behavior=behavior, rf_pred=rf_pred)

    fused_risk = _final_risk(
        ml,
        adjusted,
        reasons,
        ti_ip,
        ti_url,
        zeek,
        attack_signals=attack_signals,
    )
    classification = _classify_from_risk(
        fused_risk,
        ml_label,
        reasons,
        behavior,
        rf_pred=rf_pred,
        attack_signals=attack_signals,
    )

    explanation = {
        "ml_score": round(ml_score, 4),
        "adjusted_score": round(adjusted, 4),
        "fused_risk": round(fused_risk, 4),
        "ml_label": ml_label,
        "rf_prob": detail.get("rf_prob"),
        "anomaly_strength": detail.get("anomaly_strength"),
        "iso_score": detail.get("iso_score"),
        "behavior": behavior,
        "attack_signals": attack_signals,
        "heuristic_boost": round(heuristic_boost, 4),
        "thresholds": {
            "suspicious": _SUSPICIOUS_THRESHOLD,
            "dangerous": _DANGEROUS_THRESHOLD,
        },
        "reasons": reasons,
    }

    return {
        "classification": classification,
        "reasons": reasons,
        "risk_score": fused_risk,
        "ai_score": ml,
        "ai_label": ml_label,
        "confidence": detail.get("confidence"),
        "anomaly_score": detail.get("anomaly_strength"),
        "rf_prob": detail.get("rf_prob"),
        "anomaly_strength": detail.get("anomaly_strength"),
        "explanation": explanation,
        "ti_ip": ti_ip,
        "ti_url": ti_url,
        "zeek": zeek,
    }

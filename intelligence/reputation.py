from __future__ import annotations

import ipaddress
import os
import time
from pathlib import Path
from urllib.parse import urlparse

import dotenv
import requests

from logging_config import get_logger

dotenv.load_dotenv()

REPUTATION_KEY = os.environ.get("REPUTATION_KEY")
ABUSEIPDB_URL = os.environ.get("ABUSEIPDB_URL")
VIRUSTOTAL_URL = os.environ.get("VIRUSTOTAL_URL")
VT_KEY = os.environ.get("VT_KEY")
IPAPI_ENABLED = (os.getenv("IPAPI_ENABLED", "true") or "true").lower() == "true"
BLOCKLIST_PATH = os.getenv(
    "TI_BLOCKLIST_PATH",
    str(Path(__file__).resolve().parent.parent / "config" / "blocklist_ips.txt"),
)

logger = get_logger(__name__)

_CACHE: dict[tuple[str, str], tuple[float, dict]] = {}
_DEFAULT_TTL_SECONDS = int(os.environ.get("TI_CACHE_TTL_SECONDS", "3600") or "3600")

# Loaded once; reload if mtime changes
_blocklist_mtime: float = 0.0
_blocklist_ips: set[str] = set()


def _cache_get(indicator_type: str, indicator: str) -> dict | None:
    key = (indicator_type, indicator)
    hit = _CACHE.get(key)
    if not hit:
        return None
    expires_at, value = hit
    if time.time() >= expires_at:
        _CACHE.pop(key, None)
        return None
    return value


def _cache_set(indicator_type: str, indicator: str, value: dict, ttl_seconds: int | None = None) -> None:
    ttl = int(ttl_seconds or _DEFAULT_TTL_SECONDS)
    ttl = max(60, min(ttl, 24 * 3600))
    _CACHE[(indicator_type, indicator)] = (time.time() + ttl, value)


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.strip())
        return bool(
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
        )
    except ValueError:
        return False


def _load_blocklist() -> set[str]:
    global _blocklist_mtime, _blocklist_ips
    path = Path(BLOCKLIST_PATH)
    if not path.is_file():
        return set()

    mtime = path.stat().st_mtime
    if mtime == _blocklist_mtime:
        return _blocklist_ips

    ips: set[str] = set()
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ips.add(line.split("#")[0].strip())
    except Exception:
        logger.error("Failed to load blocklist from %s", path, exc_info=True)

    _blocklist_ips = ips
    _blocklist_mtime = mtime
    return _blocklist_ips


def _check_blocklist(ip: str) -> dict | None:
    if ip in _load_blocklist():
        return {
            "provider": "local_blocklist",
            "verdict": "malicious",
            "score": 1.0,
            "raw": {"listed": True},
        }
    return None


def _lookup_abuseipdb(ip: str) -> dict:
    result = {
        "provider": "abuseipdb",
        "verdict": "unknown",
        "score": None,
        "raw": None,
    }
    if not REPUTATION_KEY or not ABUSEIPDB_URL:
        return result

    try:
        headers = {"Key": REPUTATION_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        r = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=3)
        data = r.json() if r is not None else {}
        abuse_score = float(data.get("data", {}).get("abuseConfidenceScore", 0) or 0)
        result["score"] = max(0.0, min(1.0, abuse_score / 100.0))
        result["raw"] = {
            "abuseConfidenceScore": abuse_score,
            "totalReports": data.get("data", {}).get("totalReports"),
            "countryCode": data.get("data", {}).get("countryCode"),
        }
        if abuse_score >= 70:
            result["verdict"] = "malicious"
        elif abuse_score >= 30:
            result["verdict"] = "suspicious"
        else:
            result["verdict"] = "safe"
    except Exception:
        logger.error("AbuseIPDB lookup failed for %s", ip, exc_info=True)
    return result


def _lookup_ip_api(ip: str) -> dict:
    """Free ip-api.com metadata (no key): proxy/hosting hints."""
    result = {
        "provider": "ip-api",
        "verdict": "unknown",
        "score": None,
        "raw": None,
    }
    if not IPAPI_ENABLED or is_private_ip(ip):
        return result

    try:
        url = f"http://ip-api.com/json/{ip}"
        params = {"fields": "status,message,country,isp,proxy,hosting,query"}
        r = requests.get(url, params=params, timeout=2)
        data = r.json() if r is not None else {}
        if data.get("status") != "success":
            return result

        result["raw"] = {
            "country": data.get("country"),
            "isp": data.get("isp"),
            "proxy": data.get("proxy"),
            "hosting": data.get("hosting"),
        }
        score = 0.0
        if data.get("proxy"):
            score = max(score, 0.45)
        if data.get("hosting"):
            score = max(score, 0.35)
        result["score"] = score
        if score >= 0.5:
            result["verdict"] = "suspicious"
        elif score > 0:
            result["verdict"] = "suspicious"
        else:
            result["verdict"] = "safe"
    except Exception:
        logger.debug("ip-api lookup failed for %s", ip, exc_info=True)
    return result


def _merge_provider_results(indicator: str, indicator_type: str, providers: list[dict]) -> dict:
    """Combine provider verdicts into one enrichment object."""
    verdict_rank = {"safe": 0, "unknown": 1, "suspicious": 2, "malicious": 3}
    best_verdict = "unknown"
    best_score = 0.0

    for p in providers:
        v = p.get("verdict") or "unknown"
        if verdict_rank.get(v, 0) > verdict_rank.get(best_verdict, 0):
            best_verdict = v
        s = p.get("score")
        if s is not None:
            best_score = max(best_score, float(s))

    return {
        "type": indicator_type,
        "indicator": indicator,
        "provider": "aggregated",
        "verdict": best_verdict,
        "score": best_score if best_score > 0 else None,
        "providers": providers,
    }


def lookup_ip(ip: str) -> dict:
    """
    Multi-source IP reputation (cached).
    """
    cached = _cache_get("ip", ip)
    if cached is not None:
        return cached

    if is_private_ip(ip):
        result = {
            "type": "ip",
            "indicator": ip,
            "provider": "local",
            "verdict": "safe",
            "score": 0.0,
            "providers": [{"provider": "local", "verdict": "safe", "note": "private_range"}],
        }
        _cache_set("ip", ip, result, ttl_seconds=600)
        return result

    providers: list[dict] = []

    block = _check_blocklist(ip)
    if block:
        providers.append(block)

    providers.append(_lookup_abuseipdb(ip))
    ip_meta = _lookup_ip_api(ip)
    if ip_meta.get("score") is not None or ip_meta.get("verdict") != "unknown":
        providers.append(ip_meta)

    result = _merge_provider_results(ip, "ip", providers)
    _cache_set("ip", ip, result)
    return result


def _lookup_virustotal(domain: str, url: str) -> dict:
    result = {
        "provider": "virustotal",
        "verdict": "unknown",
        "score": None,
        "raw": None,
    }
    if not VT_KEY or not VIRUSTOTAL_URL or not domain:
        return result

    try:
        url_id = requests.utils.quote(domain, safe="")
        headers = {"x-apikey": VT_KEY}
        response = requests.get(f"{VIRUSTOTAL_URL}/{url_id}", headers=headers, timeout=3)
        data = response.json() if response is not None else {}

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        total = max(1, malicious + suspicious + undetected)

        result["score"] = max(0.0, min(1.0, (malicious + 0.5 * suspicious) / total))
        result["raw"] = {"malicious": malicious, "suspicious": suspicious, "undetected": undetected}

        if malicious > 0:
            result["verdict"] = "malicious"
        elif suspicious > 0:
            result["verdict"] = "suspicious"
        else:
            result["verdict"] = "safe"
    except Exception:
        logger.error("VirusTotal lookup failed for %s", url, exc_info=True)
    return result


def _heuristic_url_check(url: str, domain: str) -> dict:
    """Local URL heuristics without external API."""
    result = {
        "provider": "heuristic",
        "verdict": "unknown",
        "score": 0.0,
        "raw": {},
    }
    if not domain:
        return result

    lowered = (url or "").lower()
    domain_l = domain.lower()

    risky_tlds = (".tk", ".ml", ".ga", ".cf", ".gq", ".zip", ".mov")
    risky_keywords = ("login", "verify", "account", "secure", "update", "wallet", "php?")

    score = 0.0
    if any(domain_l.endswith(tld) for tld in risky_tlds):
        score = max(score, 0.5)
        result["raw"]["risky_tld"] = True
    if any(k in lowered for k in risky_keywords) and any(c.isdigit() for c in domain_l):
        score = max(score, 0.55)
        result["raw"]["phishing_pattern"] = True
    if domain_l.count(".") >= 3:
        score = max(score, 0.4)
        result["raw"]["deep_subdomain"] = True

    result["score"] = score
    if score >= 0.5:
        result["verdict"] = "suspicious"
    elif score > 0:
        result["verdict"] = "suspicious"
    else:
        result["verdict"] = "safe"
    return result


def lookup_url(url: str) -> dict:

    cached = _cache_get("url", url)
    if cached is not None:
        return cached

    parsed = urlparse(url if "://" in url else f"http://{url}")
    domain = (parsed.netloc or parsed.path or "").strip().lower()

    providers = [_heuristic_url_check(url, domain)]
    vt = _lookup_virustotal(domain, url)
    if vt.get("verdict") != "unknown" or vt.get("score"):
        providers.append(vt)

    result = _merge_provider_results(url, "url", providers)
    result["domain"] = domain
    _cache_set("url", url, result)
    return result


def check_blocklist(ip: str) -> dict | None:
    """Fast local blocklist lookup (no external API calls)."""
    return _check_blocklist(ip)


def check_ip(ip: str) -> str:
    """Backward-compatible: returns only verdict string."""
    return lookup_ip(ip).get("verdict") or "unknown"


def check_url(url: str) -> str:
    """Backward-compatible: returns only verdict string."""
    return lookup_url(url).get("verdict") or "unknown"

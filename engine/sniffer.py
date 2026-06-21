from scapy.all import sniff, IP, TCP, UDP, Raw
from engine.feature_extractor import extract
from engine.behavior import detect as detect_behavior
from ai.classifier import predict
from intelligence.reputation import check_ip, check_url
from ids.event_timestamp import resolve_event_epoch_seconds, scapy_packet_epoch_seconds
from alerts.email_alert import send_alert
from storage.memory_store import logs, stats
from storage.persistent_store import save_log
from engine.parser_http import parse_http, analyze_http_content
from engine.payload_analyzer import analyze_payload
from storage.persistent_store import save_training_data
import os
import time
import re
import random
from scapy.utils import wrpcap

PCAP_FILE = "storage/captures.pcap"

# Regex to extract HTTP URLs from packet payload
URL_REGEX = re.compile(rb"(?:GET|POST)\s+([^\s]+)")

# Payload logging controls
LOG_PAYLOADS = (os.getenv("LOG_PAYLOADS", "false") or "false").lower() == "true"

def extract_http_url(pkt):
    """Extract URL from HTTP layer if present"""
    if pkt.haslayer(Raw):
        data = pkt[Raw].load
        match = URL_REGEX.search(data)
        if match:
            return match.group(1).decode(errors="ignore")
    return None

def classify_packet(data):
    """
    Runs hybrid AI + behavior + reputation + Zeek detection
    """
    # --- Hybrid AI prediction ---
    rf_pred, iso_pred, score, label, ai_reasons = predict(data["features"])

    data["ai_score"] = score
    data["ai_reasons"] = ai_reasons

    reasons = []
    reasons.extend(ai_reasons)

    if rf_pred == 1:
        reasons.append("ml_attack")
    if iso_pred == -1:
        reasons.append("anomaly")

    # --- Behavior detection ---
    behavior = detect_behavior(data["src_ip"], data.get("dst_port"))
    if behavior:
        reasons.append(behavior)

    if "http_suspicious" in data:
        reasons.extend([f"http_{r}" for r in data["http_suspicious"]])

    if "payload_suspicious" in data:
        reasons.extend([f"payload_{r}" for r in data["payload_suspicious"]])

    # --- Reputation checks ---
    ip_risk = check_ip(data["src_ip"])
    if ip_risk:
        reasons.append(f"reputation_ip_{ip_risk}")

    if "url" in data and data["url"]:
        url_risk = check_url(data["url"])
        if url_risk:
            reasons.append(f"reputation_url_{url_risk}")

    # --- Zeek flags ---
    zeek_flag = zeek_check(data["src_ip"])
    if zeek_flag:
        reasons.append(zeek_flag)

    # --- Determine severity ---
    if label == "dangerous" or "ml_attack" in reasons or len(reasons) >= 2:
        from alerts.email_alert import send_alert
        from storage.memory_store import stats
        stats["dangerous_ips"].add(data["src_ip"])
        if "url" in data:
            stats["dangerous_urls"].add(data["url"])
        send_alert(
            "Dangerous Traffic Detected",
            f"IP: {data['src_ip']}\nURL: {data.get('url')}\nReasons: {reasons}\nAI Score: {score:.2f}"
        )
        return "dangerous", reasons
    elif label == "suspicious" or "anomaly" in reasons:
        return "suspicious", reasons

    return "safe", reasons


def handle_packet(pkt):
    wrpcap(PCAP_FILE, pkt, append=True)

    data = extract(pkt)
    if not data:
        return

    http_data = parse_http(pkt)

    if http_data:
        data["url"] = http_data["url"]
        data["http"] = http_data

        # Analyze HTTP content
        http_findings = analyze_http_content(http_data)
        if http_findings:
            data["http_suspicious"] = http_findings

    label, reasons = classify_packet(data)
    
    if label in ["dangerous", "suspicious"] or random.random() < 0.05:
        save_training_data(data["features"], label)

    stats["total"] += 1
    stats[label] += 1
    if label == "dangerous":
        stats["unique_attackers"].add(data["src_ip"])
        stats["dangerous_ips"].add(data["src_ip"])
        if "url" in data:
            stats["dangerous_urls"].add(data["url"])

    payload = None
    payload_findings = []

    if pkt.haslayer(Raw):
        raw_preview = pkt[Raw].load[:1000].decode(errors="ignore")  # limit size
        payload_findings = analyze_payload(raw_preview)

        if payload_findings:
            data["payload_suspicious"] = payload_findings

        # Only persist payload content when explicitly enabled; always allow analysis above.
        if LOG_PAYLOADS:
            payload = raw_preview

    wire = scapy_packet_epoch_seconds(pkt)
    event_ts = resolve_event_epoch_seconds(
        packet_send_time=wire,
        fallback_ingestion_time=time.time(),
    )

    log_entry = {
        "time": event_ts,
        "src_ip": data["src_ip"],
        "dst_ip": data["dst_ip"],
        "dst_port": data.get("dst_port"),
        "url": data.get("url"),
        "status": label,
        "ai_score": data.get("ai_score"),
        "reasons": reasons,
        "suspicious_hits": data.get("suspicious_hits", []),
        "payload": payload,
        "payload_findings": payload_findings,    
        "http_method": data.get("http", {}).get("method"),
        "http_host": data.get("http", {}).get("host"),
        "http_path": data.get("http", {}).get("path"),
        "http_findings": data.get("http_suspicious", []),
    }

    logs.append(log_entry)      # In-memory for API
    save_log(log_entry)         # Persistent storage
    
def start_sniffer(interface=None):
    """
    Start packet capture.
    interface: Optional network interface (e.g., 'eth0', 'en0')
    """
    print("[+] Starting network sniffer...")
    sniff(prn=handle_packet, store=False, iface=interface)

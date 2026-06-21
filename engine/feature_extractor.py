import math
from collections import Counter

from scapy.all import IP, TCP, UDP, ICMP

from ids.event_timestamp import scapy_packet_epoch_seconds

from ai.cic_features import vector_from_flow_snapshot
from .flow_manager import update_flow

# Well-known ports — traffic outside these on client-initiated flows is slightly riskier
_COMMON_PORTS = {
    "web": {80, 443, 8080, 8443},
    "dns_time": {53, 123},
    "remote": {22, 3389},
    "mail": {25, 110, 143},
    "mail_secure": {587, 993, 995},
    "databases": {3306, 5432, 27017},
}

def _protocol_name(proto: int, pkt) -> str:
    if pkt.haslayer(ICMP):
        return "ICMP"
    if proto == 1:
        return "TCP"
    if proto == 2:
        return "UDP"
    return "OTHER"


def _payload_entropy(pkt) -> float:
    try:
        from scapy.all import Raw

        if not pkt.haslayer(Raw):
            return 0.0
        data = bytes(pkt[Raw].load)
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        entropy = 0.0
        for c in counts.values():
            p = c / length
            entropy -= p * math.log2(p)
        return entropy
    except Exception:
        return 0.0

def _classify_port(port: int):
    if not port:
        return None

    for category, ports in _COMMON_PORTS.items():
        if port in ports:
            return category

    return "unknown"

def extract(pkt):
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    proto, sport, dport = 0, 0, 0
    tcp_layer = None

    if pkt.haslayer(TCP):
        proto = 1
        tcp_layer = pkt[TCP]
        sport = int(tcp_layer.sport)
        dport = int(tcp_layer.dport)
    elif pkt.haslayer(UDP):
        proto = 2
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
    elif pkt.haslayer(ICMP):
        proto = 3
        sport = 0
        dport = 0

    flow_key = (ip.src, ip.dst, sport, dport, proto)
    wire_ts = scapy_packet_epoch_seconds(pkt)
    snapshot = update_flow(
        flow_key, len(pkt), dport, proto=proto, tcp_layer=tcp_layer, packet_time=wire_ts
    )
    features = vector_from_flow_snapshot(snapshot)

    protocol_name = _protocol_name(proto, pkt)
    unusual_port = None
    port_category = _classify_port(dport)
    if dport and port_category == "unknown" and dport > 1024:
        unusual_port = dport

    data = {
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "src_port": sport,
        "dst_port": dport,
        "protocol": protocol_name,
        "features": features,
        "meta": {
            "payload_entropy": _payload_entropy(pkt),
            "port_category": port_category,
            "unusual_port": unusual_port,
            "flow_packets_per_s": snapshot.get("flow_packets_per_s", 0),
            "flow_bytes_per_s": snapshot.get("flow_bytes_per_s", 0),
            "total_fwd_packets": snapshot.get("total_fwd_packets", 0),
        },
        "packets": snapshot.get("total_fwd_packets", 0) + snapshot.get("total_bwd_packets", 0),
        "bytes": snapshot.get("total_fwd_bytes", 0) + snapshot.get("total_bwd_bytes", 0),
        "duration": snapshot.get("flow_duration_us", 0) / 1_000_000.0,
    }
    if wire_ts is not None:
        data["packet_send_time"] = wire_ts

    if proto == 1 and dport == 443:
        data["is_https"] = True

    return data

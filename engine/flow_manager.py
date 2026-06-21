import math
import os
import threading
import time
from collections import defaultdict

_FLOW_SHARDS = max(16, int(os.getenv("IDS_FLOW_SHARDS", "128") or "128"))


def _new_flow() -> dict:
    return {
        "fwd_packets": 0,
        "bwd_packets": 0,
        "fwd_bytes": 0,
        "bwd_bytes": 0,
        "start": time.time(),
        "destination_port": 0,
        "protocol": 0,
        "syn_flag_count": 0,
        "ack_flag_count": 0,
        "rst_flag_count": 0,
        "fin_flag_count": 0,
        "psh_flag_count": 0,
        "length_sum": 0.0,
        "length_sq_sum": 0.0,
    }


_flow_locks = [threading.Lock() for _ in range(_FLOW_SHARDS)]
_flow_tables = [defaultdict(_new_flow) for _ in range(_FLOW_SHARDS)]


def _shard_index(key) -> int:
    return hash(key) % _FLOW_SHARDS


def update_flow(key, pkt_len, dport, proto=0, tcp_layer=None, packet_time=None):
    """
    Update bidirectional flow stats and return a CIC-aligned feature snapshot.

    Live capture uses a directional 5-tuple key, so packets on this key are counted
    as forward; backward counts stay 0 unless reverse traffic hits a paired flow.

    packet_time: epoch seconds from the frame (e.g. Scapy pkt.time); if missing, wall clock is used.
    """
    shard = _shard_index(key)
    lock = _flow_locks[shard]
    flow_table = _flow_tables[shard]

    with lock:
        flow = flow_table[key]

        t_now = time.time()
        if packet_time is not None:
            try:
                tf = float(packet_time)
                if math.isfinite(tf) and tf > 0:
                    t_now = tf
            except (TypeError, ValueError):
                pass

        if flow["fwd_packets"] == 0 and flow["bwd_packets"] == 0:
            flow["start"] = t_now
            flow["destination_port"] = int(dport)
            flow["protocol"] = int(proto)

        flow["fwd_packets"] += 1
        flow["fwd_bytes"] += int(pkt_len)
        flow["length_sum"] += float(pkt_len)
        flow["length_sq_sum"] += float(pkt_len) * float(pkt_len)

        if tcp_layer is not None:
            from ai.cic_features import count_tcp_flag

            flow["syn_flag_count"] += count_tcp_flag(tcp_layer, "S")
            flow["ack_flag_count"] += count_tcp_flag(tcp_layer, "A")
            flow["rst_flag_count"] += count_tcp_flag(tcp_layer, "R")
            flow["fin_flag_count"] += count_tcp_flag(tcp_layer, "F")
            flow["psh_flag_count"] += count_tcp_flag(tcp_layer, "P")

        duration_s = max(t_now - flow["start"], 1e-6)
        duration_us = duration_s * 1_000_000.0
        total_packets = flow["fwd_packets"] + flow["bwd_packets"]
        total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]

        if total_packets > 0:
            mean_len = flow["length_sum"] / total_packets
            variance = max(
                0.0,
                (flow["length_sq_sum"] / total_packets) - (mean_len * mean_len),
            )
            std_len = variance**0.5
        else:
            mean_len = 0.0
            std_len = 0.0

        return {
            "destination_port": flow["destination_port"],
            "flow_duration_us": duration_us,
            "total_fwd_packets": flow["fwd_packets"],
            "total_bwd_packets": flow["bwd_packets"],
            "total_fwd_bytes": flow["fwd_bytes"],
            "total_bwd_bytes": flow["bwd_bytes"],
            "flow_bytes_per_s": total_bytes / duration_s,
            "flow_packets_per_s": total_packets / duration_s,
            "fwd_packets_per_s": flow["fwd_packets"] / duration_s,
            "bwd_packets_per_s": flow["bwd_packets"] / duration_s,
            "syn_flag_count": flow["syn_flag_count"],
            "ack_flag_count": flow["ack_flag_count"],
            "rst_flag_count": flow["rst_flag_count"],
            "fin_flag_count": flow["fin_flag_count"],
            "psh_flag_count": flow["psh_flag_count"],
            "packet_length_mean": mean_len,
            "packet_length_std": std_len,
            "protocol": flow["protocol"],
        }

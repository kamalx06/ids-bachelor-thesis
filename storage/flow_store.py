flows = {}

def update_flow_record(src, dst, sport, dport, proto, size):
    key = (src, dst, sport, dport, proto)

    if key not in flows:
        flows[key] = {
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
            "proto": proto,
            "packets": 0,
            "bytes": 0
        }

    flows[key]["packets"] += 1
    flows[key]["bytes"] += size

    return flows[key]

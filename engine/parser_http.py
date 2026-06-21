from scapy.all import Raw
import re
from urllib.parse import urlparse, parse_qs

REQUEST_LINE = re.compile(rb"(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP")
HEADER_REGEX = re.compile(rb"([^:\r\n]+):\s*([^\r\n]+)")

def parse_http(pkt):
    """Enterprise-level HTTP parser"""
    if not pkt.haslayer(Raw):
        return None

    try:
        data = pkt[Raw].load

        # --- Request line ---
        match = REQUEST_LINE.search(data)
        if not match:
            return None

        method = match.group(1).decode()
        path = match.group(2).decode(errors="ignore")

        # --- Headers ---
        headers = {}
        for h in HEADER_REGEX.findall(data):
            key = h[0].decode(errors="ignore").lower()
            val = h[1].decode(errors="ignore")
            headers[key] = val

        # --- Host + full URL ---
        host = headers.get("host", "")
        full_url = f"http://{host}{path}" if host else path

        # --- Parse URL ---
        parsed = urlparse(full_url)
        query_params = parse_qs(parsed.query)

        # --- Extract body (for POST etc.) ---
        body = None
        if b"\r\n\r\n" in data:
            body = data.split(b"\r\n\r\n", 1)[1][:500].decode(errors="ignore")

        return {
            "method": method,
            "host": host,
            "path": path,
            "url": full_url,
            "headers": headers,
            "query": query_params,
            "body": body
        }

    except Exception:
        return None

"""
Install / remove the iptables redirect that pushes TCP/443 through the
interceptor. Run as root:

    sudo python -m ssl.iptables install
    sudo python -m ssl.iptables remove
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

LISTEN_PORT = int(os.getenv("SSL_INTERCEPT_PORT", "8443") or "8443")


def install() -> None:
    subprocess.run([
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-p", "tcp", "--dport", "443",
        "-j", "REDIRECT", "--to-port", str(LISTEN_PORT),
    ], check=True)
    print(f"[OK] Redirected TCP/443 → {LISTEN_PORT}")
    print("Hint: exclude the IDS host itself with")
    print(f"      iptables -t nat -I PREROUTING 1 -s <IDS_IP> -j RETURN")


def remove() -> None:
    subprocess.run([
        "iptables", "-t", "nat", "-D", "PREROUTING",
        "-p", "tcp", "--dport", "443",
        "-j", "REDIRECT", "--to-port", str(LISTEN_PORT),
    ], check=True)
    print("[OK] Removed redirect rule")


if __name__ == "__main__":
    if sys.platform != "linux":
        print("SSL interception is Linux-only.", file=sys.stderr)
        sys.exit(1)

    p = argparse.ArgumentParser()
    p.add_argument("action", choices=("install", "remove"))
    args = p.parse_args()

    (install if args.action == "install" else remove)()
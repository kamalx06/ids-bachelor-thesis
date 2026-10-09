"""
Install / remove / inspect the iptables redirect that pushes TCP/443
through the TLS interceptor. Must be run as root.

    sudo python -m ssl_inspect.iptables install
    sudo python -m ssl_inspect.iptables remove
    sudo python -m ssl_inspect.iptables status

The install action is idempotent: it checks for the rule first and
reports "already present" rather than appending a duplicate. --wait is
passed to every invocation to avoid colliding with concurrent iptables
operations from a host firewall daemon.

Note that SNI bypass rules (which skip interception for specific
hostnames) are managed separately by ssl_inspect/bypass.py, not here.
This module only handles the base redirect.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

LISTEN_PORT = int(os.getenv("SSL_INTERCEPT_PORT", "8443") or "8443")

# The exact rule specification. Kept as one tuple so install/remove/status
# all agree on the same match criteria.
_RULE = [
    "-p", "tcp", "--dport", "443",
    "-j", "REDIRECT", "--to-port", str(LISTEN_PORT),
]


def _iptables(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["iptables", "--wait", *args],
        check=check,
        text=True,
        capture_output=True,
    )


def _rule_present() -> bool:
    """Return True if the redirect rule already exists in the NAT table."""
    result = _iptables("-t", "nat", "-C", "PREROUTING", *_RULE, check=False)
    return result.returncode == 0


def install() -> None:
    if _rule_present():
        print(f"[OK] Redirect already present (TCP/443 → {LISTEN_PORT}); nothing to do.")
        return
    _iptables("-t", "nat", "-A", "PREROUTING", *_RULE)
    print(f"[OK] Redirected TCP/443 → {LISTEN_PORT}")
    print("Hint: exclude the IDS host itself from interception with")
    print(f"      iptables -t nat -I PREROUTING 1 -s <IDS_IP> -j RETURN")


def remove() -> None:
    if not _rule_present():
        print("[OK] No redirect rule to remove.")
        return
    _iptables("-t", "nat", "-D", "PREROUTING", *_RULE)
    print("[OK] Removed redirect rule")


def status() -> None:
    print(f"Checking for: TCP/443 → REDIRECT to port {LISTEN_PORT}")
    if _rule_present():
        print(f"[ACTIVE] TCP/443 is redirected to port {LISTEN_PORT}")
    else:
        print("[INACTIVE] No redirect rule present")

    # Show the full NAT PREROUTING chain so the operator can see where the
    # redirect sits relative to any SNI bypass RETURN rules.
    result = _iptables("-t", "nat", "-L", "PREROUTING", "-n", "--line-numbers", check=False)
    if result.returncode == 0 and result.stdout.strip():
        print()
        print("Current NAT PREROUTING chain:")
        for line in result.stdout.splitlines():
            print("  " + line)


if __name__ == "__main__":
    if sys.platform != "linux":
        print("TLS interception is Linux-only.", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Manage the TLS interceptor iptables redirect",
    )
    parser.add_argument("action", choices=("install", "remove", "status"))
    args = parser.parse_args()

    {"install": install, "remove": remove, "status": status}[args.action]()
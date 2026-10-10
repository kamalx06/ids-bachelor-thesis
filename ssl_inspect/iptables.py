"""
Install / remove / inspect the iptables redirect that pushes TCP/443
through the TLS interceptor.

    sudo python -m ssl_inspect.iptables install
    sudo python -m ssl_inspect.iptables remove
    sudo python -m ssl_inspect.iptables status

The install action is idempotent: it checks for the rule first and
reports "already present" rather than appending a duplicate. --wait is
passed to every invocation to avoid colliding with concurrent iptables
operations from a host firewall daemon.

Privileges: the iptables binary refuses to run for non-root callers
even when the caller holds CAP_NET_ADMIN. Two supported ways to satisfy
this:

    1. Run the command as root: `sudo python -m ssl_inspect.iptables …`
    2. Run as an unprivileged user with a passwordless sudoers rule for
       the specific iptables invocations. See the README section
       "Running as a non-root user", Option B. When configured, the
       command runs normally without sudo.

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


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _iptables_cmd(*args: str) -> list[str]:
    """
    Build the iptables argv, prefixing with `sudo -n` when not root.

    `-n` tells sudo to fail immediately if a password would be required.
    Combined with the sudoers rule from the README, this lets the command
    work either as root or as an unprivileged user without a prompt.
    """
    base = ["iptables", "--wait", *args]
    if _is_root():
        return base
    return ["sudo", "-n", *base]


def _iptables(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        _iptables_cmd(*args),
        check=False,
        text=True,
        capture_output=True,
    )

    if check and result.returncode != 0:
        stderr = (result.stderr or "").strip()

        # iptables exit codes:
        #   1 = parameter problem, 2 = command error, 3 = resource problem,
        #   4 = permission denied (running as non-root without a sudoers rule)
        permission_hint = (
            "Permission denied" in stderr
            or "you must be root" in stderr
            or stderr.startswith("sudo:")
        )

        if permission_hint:
            print(
                "[ERROR] iptables requires elevated privileges.\n"
                "        Either run this command with sudo:\n"
                f"          sudo python3.13 -m ssl_inspect.iptables {' '.join(args[:1])}\n"
                "        Or configure passwordless sudo for iptables — see\n"
                "          README §Running as a non-root user, Option B",
                file=sys.stderr,
            )
            raise SystemExit(2)

        print(f"[ERROR] iptables failed (exit {result.returncode}): {stderr}", file=sys.stderr)
        raise SystemExit(2)

    return result


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

    result = _iptables("-t", "nat", "-L", "PREROUTING", "-n", "--line-numbers", check=False)
    if result.returncode == 0 and result.stdout.strip():
        print()
        print("Current NAT PREROUTING chain:")
        for line in result.stdout.splitlines():
            print("  " + line)


def _check_privileges() -> None:
    """
    Preflight probe: can we actually run iptables?

    Root → yes.
    Non-root → try `sudo -n iptables -L -n` and see if it succeeds
    without a prompt. If it fails, exit with a clear message.
    """
    if _is_root():
        return

    try:
        probe = subprocess.run(
            ["sudo", "-n", "iptables", "--wait", "-t", "nat", "-L", "PREROUTING", "-n"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if probe.returncode == 0:
            return
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    print(
        "[ERROR] Cannot run iptables from this process.\n"
        "        Either run this command with sudo:\n"
        "          sudo python3.13 -m ssl_inspect.iptables <action>\n"
        "        Or configure passwordless sudo for iptables — see\n"
        "          README §Running as a non-root user, Option B",
        file=sys.stderr,
    )
    sys.exit(2)


if __name__ == "__main__":
    if sys.platform != "linux":
        print("TLS interception is Linux-only.", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Manage the TLS interceptor iptables redirect",
    )
    parser.add_argument("action", choices=("install", "remove", "status"))
    args = parser.parse_args()

    _check_privileges()

    {"install": install, "remove": remove, "status": status}[args.action]()
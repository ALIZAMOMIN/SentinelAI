"""
SentinelAI — DNS Query Sensing Module

Scoped per the build-priority call: Windows `ipconfig /displaydns` is the one
fully working, zero-extra-permissions path for the hackathon demo. macOS/Linux
stubs are included and clearly marked as roadmap — wiring them up needs a
privileged local agent (tcpdump / resolvectl), which is an honest "production
roadmap" line in the pitch, not a missing feature to hide.

Output: {"domain": last_seen_iso_or_None} so the normalizer can cheaply check
"was this tool's stated vendor domain actually contacted."
"""

from __future__ import annotations

import platform
import re
import subprocess
from datetime import datetime, timezone


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


_RECORD_NAME_RE = re.compile(r"Record Name[ .]*:\s*(\S+)", re.IGNORECASE)


def _scan_windows() -> dict[str, str]:
    try:
        result = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}

    now = _now_iso()
    domains: dict[str, str] = {}
    for match in _RECORD_NAME_RE.finditer(result.stdout):
        domain = match.group(1).rstrip(".").lower()
        domains[domain] = now
    return domains


def _scan_linux() -> dict[str, str]:
    # Roadmap: `resolvectl statistics` gives counters, not per-domain history;
    # real coverage needs systemd-resolved query logging enabled + journalctl,
    # or a local resolver (dnsmasq/unbound) with query-log turned on.
    return {}


def _scan_macos() -> dict[str, str]:
    # Roadmap: macOS has no persistent DNS query log by default. `dscacheutil`
    # only exposes currently cached entries, not history. A real implementation
    # needs a short-lived `sudo tcpdump -i any port 53` capture with explicit
    # user consent (elevated permissions), which is a v2/production item.
    return {}


def scan_dns_activity() -> dict:
    """
    Returns:
      {
        "platform": "Windows" | "Darwin" | "Linux",
        "supported": bool,
        "observed_domains": {domain: last_seen_iso},
      }
    """
    system = platform.system()
    if system == "Windows":
        observed = _scan_windows()
        supported = True
    elif system == "Darwin":
        observed = _scan_macos()
        supported = False
    else:
        observed = _scan_linux()
        supported = False

    return {
        "platform": system,
        "supported": supported,
        "observed_domains": observed,
    }


if __name__ == "__main__":
    import json

    print(json.dumps(scan_dns_activity(), indent=2))

"""
SentinelAI — Enrichment Prechecks

These are best-effort enrichments layered onto whatever the four sensing
mechanisms detect, matching the `prechecks` block in your Tool schema.
Everything here degrades gracefully (returns None/defaults) if a dependency
or API key is missing, so the sensing pipeline never blocks on them.

Env vars (all optional):
  VIRUSTOTAL_API_KEY
  HIBP_API_KEY
"""

from __future__ import annotations

import os
import socket
from datetime import datetime, timezone
from typing import Any

import requests

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
HIBP_API_KEY = os.environ.get("HIBP_API_KEY")


def virustotal_domain_report(domain: str | None) -> dict[str, Any]:
    if not domain or not VT_API_KEY:
        return {"malicious_votes": 0, "suspicious_votes": 0}

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VT_API_KEY},
            timeout=8,
        )
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious_votes": stats.get("malicious", 0),
            "suspicious_votes": stats.get("suspicious", 0),
        }
    except (requests.RequestException, KeyError, ValueError):
        return {"malicious_votes": 0, "suspicious_votes": 0}


def hibp_domain_breach_check(domain: str | None) -> dict[str, Any]:
    """Checks whether the vendor domain shows up as a known breach source."""
    if not domain or not HIBP_API_KEY:
        return {"breached": False}

    try:
        resp = requests.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            params={"Domain": domain},
            headers={"hibp-api-key": HIBP_API_KEY},
            timeout=8,
        )
        if resp.status_code == 404:
            return {"breached": False}
        resp.raise_for_status()
        breaches = resp.json()
        return {"breached": len(breaches) > 0}
    except requests.RequestException:
        return {"breached": False}


def whois_domain_age_days(domain: str | None) -> int | None:
    """Uses the `python-whois` package if installed; returns None otherwise
    rather than failing the whole scan."""
    if not domain:
        return None
    try:
        import whois  # python-whois
    except ImportError:
        return None

    try:
        record = whois.whois(domain)
        created = record.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - created).days
    except Exception:
        return None


def run_prechecks(domain: str | None) -> dict[str, Any]:
    return {
        "virustotal": virustotal_domain_report(domain),
        "hibp_breach_check": hibp_domain_breach_check(domain),
        "whois_domain_age_days": whois_domain_age_days(domain),
    }

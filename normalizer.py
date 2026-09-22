"""
SentinelAI — Sensing Layer Normalizer

Merges raw output from all sensing mechanisms:
  - browser_extension_scan   (pushed in from the Chrome extension)
  - mcp_connector_scan       (mcp_scanner.py)
  - dns_check                (dns_scanner.py)
  - oauth_connected_apps     (oauth_stub.py / manual import — see note below)

...into one normalized Tool object per detected tool, matching exactly the
schema your LangGraph agent's "Perceive" node expects. This is the seam
between the sensing layer and the agent.

Merge key: vendor domain when available (most reliable — a tool detected via
extension scan AND matched via DNS should collapse into one record), falling
back to a slugified name when no domain is known (e.g. MCP servers with no
vendor URL).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from prechecks import run_prechecks


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")

'''
def _merge_key(record: dict[str, Any]) -> str:
    vendor = record.get("vendor")
    if vendor:
        return _slug(vendor)
    return _slug(record["name"])
'''

def _merge_key(record: dict[str, Any]) -> str:
    """
    Identify a record without accidentally collapsing unrelated
    extensions, MCP servers, OAuth apps, and DNS observations.
    """

    source_type = record.get("source_type") or "unknown"
    meta = record.get("meta") or {}

    # Chrome extension identity is globally stable.
    extension_id = meta.get("extension_id")
    if extension_id:
        return f"extension:{extension_id}"

    # Explicit MCP identity, if your MCP scanner provides one.
    mcp_id = meta.get("mcp_server_id") or record.get("mcp_server_id")
    if mcp_id:
        return f"mcp:{_slug(str(mcp_id))}"

    # OAuth providers should remain distinct from browser extensions.
    oauth_id = meta.get("oauth_client_id") or record.get("oauth_client_id")
    if oauth_id:
        return f"oauth:{_slug(str(oauth_id))}"

    # Vendor domain is useful for correlation, but don't let it
    # automatically collapse unrelated source types.
    vendor_domain = record.get("vendor_domain")
    if vendor_domain:
        return f"{source_type}:domain:{_slug(vendor_domain)}"

    name = record.get("name") or "unknown-tool"
    return f"{source_type}:name:{_slug(name)}"


def _merge_permissions(a: dict, b: dict) -> dict:
    requested = sorted(set(a.get("requested", []) + b.get("requested", [])))
    prev = sorted(set(a.get("previous_snapshot", []) + b.get("previous_snapshot", [])))
    drift = a.get("drift_detected", False) or b.get("drift_detected", False)
    drift_since = a.get("drift_since") or b.get("drift_since")
    return {
        "requested": requested,
        "previous_snapshot": prev,
        "drift_detected": drift,
        "drift_since": drift_since,
    }


def merge_records(raw_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse raw partial records from every sensing source into one
    record per real-world tool, unioning detected_via and permissions."""
    merged: dict[str, dict[str, Any]] = {}

    for record in raw_records:
        key = _merge_key(record)
        if key not in merged:
            merged[key] = {**record, "detected_via": list(record.get("detected_via", []))}
            continue

        existing = merged[key]
        existing["detected_via"] = sorted(
            set(existing["detected_via"]) | set(record.get("detected_via", []))
        )
        existing["permissions"] = _merge_permissions(
            existing.get("permissions", {}), record.get("permissions", {})
        )
        # prefer whichever record has a vendor/stated_function populated
        existing["vendor"] = existing.get("vendor") or record.get("vendor")
        existing["stated_function"] = existing.get("stated_function") or record.get(
            "stated_function"
        )
        existing["first_seen"] = min(existing["first_seen"], record["first_seen"])
        existing["last_scanned"] = max(existing["last_scanned"], record["last_scanned"])

    return list(merged.values())

'''
def _extract_domain_keywords(record: dict[str, Any]) -> list[str]:
    keywords = []
    vendor = record.get("vendor") or ""
    vendor_domain = record.get("vendor_domain") or ""
    if vendor_domain:
        keywords.append(vendor_domain.lower())
    if vendor:
        keywords.append(vendor.lower())
        slug_vendor = _slug(vendor).replace("-", "")
        if len(slug_vendor) > 3:
            keywords.append(slug_vendor)
    return [k for k in keywords if k]

'''
def _extract_domain_keywords(record: dict[str, Any]) -> list[str]:
    keywords: list[str] = []

    vendor_domain = record.get("vendor_domain")
    if vendor_domain:
        keywords.append(vendor_domain.lower().strip())

    return keywords

def attach_network_behavior(record: dict[str, Any], dns_observed: dict[str, str]) -> dict[str, Any]:
    keywords = _extract_domain_keywords(record)
    observed = []
    for d in dns_observed:
        if any(kw in d for kw in keywords):
            observed.append(d)

    record["network_behavior"] = {
        "observed_domains": sorted(set(observed)),
        "matches_stated_vendor_domain": bool(observed),
    }
    if observed and "dns_check" not in record["detected_via"]:
        record["detected_via"] = sorted(set(record["detected_via"]) | {"dns_check"})
    return record


'''
def attach_prechecks(record: dict[str, Any]) -> dict[str, Any]:
    keywords = _extract_domain_keywords(record)
    domain_to_check = keywords[0] if keywords else record.get("vendor")
    record["prechecks"] = run_prechecks(domain_to_check)
    return record
'''
def _domain_for_prechecks(record: dict[str, Any]) -> str | None:
    domain = record.get("vendor_domain")

    if domain:
        return domain.lower().strip()

    return None

def attach_prechecks(record: dict[str, Any]) -> dict[str, Any]:
    domain = _domain_for_prechecks(record)
    record["prechecks"] = run_prechecks(domain)
    return record

def finalize_tool_id(record: dict[str, Any]) -> dict[str, Any]:
    """Rewrite tool_id to a stable, human-legible slug once merging is done —
    the per-source ids (ext-*, mcp-*) were only needed for the merge step."""
    record["tool_id"] = _slug(record.get("name") or record.get("vendor") or "unknown-tool")
    return record


def format_schema_keys(record: dict[str, Any]) -> dict[str, Any]:
    """Order output keys exactly as specified in the Perceive node schema."""
    return {
        "tool_id": record.get("tool_id"),
        "name": record.get("name"),
        "vendor": record.get("vendor"),
        "source_type": record.get("source_type"),
        "stated_function": record.get("stated_function"),
        "detected_via": record.get("detected_via", []),
        "permissions": record.get("permissions", {}),
        "network_behavior": record.get("network_behavior", {}),
        "prechecks": record.get("prechecks", {}),
        "first_seen": record.get("first_seen"),
        "last_scanned": record.get("last_scanned"),
        "vendor_domain": record.get("vendor_domain"),
    }


def build_tool_payload(
    extension_records: list[dict[str, Any]],
    mcp_records: list[dict[str, Any]],
    oauth_records: list[dict[str, Any]],
    dns_result: dict[str, Any],
) -> list[dict[str, Any]]:
    """Main entry point: run the full merge -> enrich -> finalize pipeline
    and return the exact list-of-Tool-objects JSON your agent's Perceive
    node consumes."""
    raw = [*extension_records, *mcp_records, *oauth_records]
    merged = merge_records(raw)

    dns_observed = dns_result.get("observed_domains", {})
    output = []
    for record in merged:
        record = attach_network_behavior(record, dns_observed)
        record = attach_prechecks(record)
        record = finalize_tool_id(record)
        record.pop("meta", None)  # internal debugging field, not part of agent schema
        output.append(format_schema_keys(record))

    return output

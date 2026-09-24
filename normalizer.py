"""
SentinelAI — Sensing Layer Normalizer

Merges raw output from all sensing mechanisms:

    - browser extension scan
    - MCP connector scan
    - web/browser MCP scan
    - DNS activity
    - OAuth connected applications

Into one normalized Tool object per detected tool.

This version contains detailed DEBUG logging for:

    - input counts
    - individual source records
    - MCP records
    - web MCP records
    - OAuth records
    - extension records
    - merge keys
    - merged records
    - DNS observations
    - network correlation
    - prechecks
    - privacy metadata
    - tool IDs
    - final normalized output

Pipeline:

    raw sensing records
            |
            v
        merge_records()
            |
            v
    attach unattributed DNS activity
            |
            v
    attach_network_behavior()
            |
            v
       attach_prechecks()
            |
            v
      privacy metadata
            |
            v
      finalize_tool_id()
            |
            v
       format_schema_keys()
            |
            v
       LangGraph /tools
"""

from __future__ import annotations

import re

from datetime import datetime, timezone

from typing import Any

from prechecks import run_prechecks


# -------------------------------------------------------------------
# DEBUG LOGGING
# -------------------------------------------------------------------

DEBUG = True


def _debug(*args: Any) -> None:
    """
    Central debug logger.

    Set DEBUG = False above to disable all debug output.
    """

    if DEBUG:
        print("[Normalizer DEBUG]", *args)


def _debug_record(label: str, record: dict[str, Any]) -> None:
    """
    Print a readable summary of a sensing record.
    """

    if not DEBUG:
        return

    if not isinstance(record, dict):
        print(f"[Normalizer DEBUG] {label}: <non-dict> {record!r}")
        return

    print(f"\n[Normalizer DEBUG] ===== {label} =====")
    print("[Normalizer DEBUG] source_type:", record.get("source_type"))
    print("[Normalizer DEBUG] name:", record.get("name"))
    print("[Normalizer DEBUG] vendor:", record.get("vendor"))
    print("[Normalizer DEBUG] vendor_domain:", record.get("vendor_domain"))
    print("[Normalizer DEBUG] detected_via:", record.get("detected_via"))
    print("[Normalizer DEBUG] permissions:", record.get("permissions"))
    print("[Normalizer DEBUG] endpoint:", record.get("endpoint"))
    print("[Normalizer DEBUG] client:", record.get("client"))
    print("[Normalizer DEBUG] confidence:", record.get("confidence"))
    print("[Normalizer DEBUG] transport:", record.get("transport"))
    print("[Normalizer DEBUG] signals:", record.get("signals"))
    print("[Normalizer DEBUG] methods:", record.get("methods"))
    print("[Normalizer DEBUG] tool_names:", record.get("tool_names"))
    print("[Normalizer DEBUG] resource_names:", record.get("resource_names"))
    print("[Normalizer DEBUG] meta:", record.get("meta"))
    print("[Normalizer DEBUG] first_seen:", record.get("first_seen"))
    print("[Normalizer DEBUG] last_scanned:", record.get("last_scanned"))
    print("[Normalizer DEBUG] ===============================")


def _debug_final_record(index: int, record: dict[str, Any]) -> None:
    """
    Print final normalized Tool object.
    """

    if not DEBUG:
        return

    print(f"\n[Normalizer DEBUG] ========== FINAL TOOL #{index} ==========")
    print("[Normalizer DEBUG] tool_id:", record.get("tool_id"))
    print("[Normalizer DEBUG] name:", record.get("name"))
    print("[Normalizer DEBUG] vendor:", record.get("vendor"))
    print("[Normalizer DEBUG] source_type:", record.get("source_type"))
    print("[Normalizer DEBUG] vendor_domain:", record.get("vendor_domain"))
    print("[Normalizer DEBUG] detected_via:", record.get("detected_via"))
    print("[Normalizer DEBUG] permissions:", record.get("permissions"))
    print("[Normalizer DEBUG] network_behavior:", record.get("network_behavior"))
    print("[Normalizer DEBUG] prechecks:", record.get("prechecks"))
    print("[Normalizer DEBUG] privacy_policy:", record.get("privacy_policy"))
    print("[Normalizer DEBUG] source_metadata:", record.get("source_metadata"))
    print("[Normalizer DEBUG] first_seen:", record.get("first_seen"))
    print("[Normalizer DEBUG] last_scanned:", record.get("last_scanned"))
    print("[Normalizer DEBUG] =======================================")


# -------------------------------------------------------------------
# TIME
# -------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# -------------------------------------------------------------------
# SLUG
# -------------------------------------------------------------------

def _slug(text: str) -> str:

    if not text:
        return "unknown"

    return re.sub(
        r"[^a-z0-9]+", "-", str(text).lower()
    ).strip("-") or "unknown"


# -------------------------------------------------------------------
# MERGE KEY
# -------------------------------------------------------------------

def _merge_key(record: dict[str, Any]) -> str:
    """
    Identify a record without accidentally collapsing unrelated
    extensions, MCP servers, OAuth applications, and DNS observations.

    Priority:

        1. Chrome extension ID
        2. MCP server ID
        3. OAuth client ID
        4. source + vendor domain
        5. source + name
    """

    source_type = record.get("source_type") or "unknown"

    meta = record.get("meta") or {}

    # ---------------------------------------------------------------
    # Chrome extension
    # ---------------------------------------------------------------

    extension_id = meta.get("extension_id") or record.get("extension_id")

    if extension_id:
        key = f"extension:{extension_id}"
        _debug("MERGE KEY | extension:", key)
        return key

    # ---------------------------------------------------------------
    # MCP
    # ---------------------------------------------------------------

    mcp_id = meta.get("mcp_server_id") or record.get("mcp_server_id")

    if mcp_id:
        key = f"mcp:{_slug(str(mcp_id))}"
        _debug("MERGE KEY | MCP:", key)
        return key

    # ---------------------------------------------------------------
    # OAuth
    # ---------------------------------------------------------------

    oauth_id = meta.get("oauth_client_id") or record.get("oauth_client_id")

    if oauth_id:

        provider = meta.get("provider") or "unknown"

        key = f"oauth:{_slug(provider)}:{_slug(str(oauth_id))}"

        _debug("MERGE KEY | OAuth:", key)

        return key

    # ---------------------------------------------------------------
    # WEB MCP
    # ---------------------------------------------------------------

    if source_type in {"web", "web_mcp", "browser_mcp", "ai_web"}:

        endpoint = record.get("endpoint") or meta.get("endpoint")

        client = record.get("client") or meta.get("client") or "web"

        if endpoint:

            key = f"web-mcp:{_slug(str(client))}:{_slug(str(endpoint))}"

            _debug("MERGE KEY | WEB MCP:", key)

            return key

    # ---------------------------------------------------------------
    # Vendor domain
    # ---------------------------------------------------------------

    vendor_domain = record.get("vendor_domain")

    if vendor_domain:

        key = f"{source_type}:domain:{_slug(vendor_domain)}"

        _debug("MERGE KEY | DOMAIN:", key)

        return key

    # ---------------------------------------------------------------
    # Name fallback
    # ---------------------------------------------------------------

    name = record.get("name") or record.get("vendor") or "unknown-tool"

    key = f"{source_type}:name:{_slug(name)}"

    _debug("MERGE KEY | NAME:", key)

    return key


# -------------------------------------------------------------------
# PERMISSION MERGING
# -------------------------------------------------------------------

def _merge_permissions(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:

    a = a or {}
    b = b or {}

    requested = sorted(
        set(a.get("requested", []) or []) | set(b.get("requested", []) or [])
    )

    previous_snapshot = sorted(
        set(a.get("previous_snapshot", []) or [])
        | set(b.get("previous_snapshot", []) or [])
    )

    drift_detected = bool(a.get("drift_detected", False)) or bool(
        b.get("drift_detected", False)
    )

    drift_since = a.get("drift_since") or b.get("drift_since")

    result = {
        "requested": requested,
        "previous_snapshot": previous_snapshot,
        "drift_detected": drift_detected,
        "drift_since": drift_since,
    }

    _debug("PERMISSIONS MERGED:", result)

    return result


# -------------------------------------------------------------------
# NETWORK BEHAVIOR
# -------------------------------------------------------------------

def _extract_domain_keywords(record: dict[str, Any]) -> list[str]:

    keywords: list[str] = []

    vendor_domain = record.get("vendor_domain")

    if vendor_domain:

        domain = str(vendor_domain).lower().strip()

        if domain:
            keywords.append(domain)

    _debug("NETWORK KEYWORDS:", keywords)

    return keywords


def attach_network_behavior(
    record: dict[str, Any],
    dns_observed: dict[str, Any],
) -> dict[str, Any]:
    """
    Correlate DNS observations with the vendor domain.

    We deliberately do NOT match arbitrary vendor names against DNS
    names because that can create false positives.
    """

    _debug("NETWORK CHECK START:", record.get("name"))

    keywords = _extract_domain_keywords(record)

    if not isinstance(dns_observed, dict):
        dns_observed = {}

    _debug("DNS domains available:", list(dns_observed.keys()))

    observed: list[str] = []

    for domain in dns_observed:

        domain_text = str(domain).lower().strip()

        if not domain_text:
            continue

        for keyword in keywords:

            if domain_text == keyword or domain_text.endswith("." + keyword):

                _debug("DNS MATCH:", domain_text, "<->", keyword)

                observed.append(domain_text)

                break

    observed = sorted(set(observed))

    record["network_behavior"] = {
        "observed_domains": observed,
        "matches_stated_vendor_domain": bool(observed),
    }

    detected_via = set(record.get("detected_via", []) or [])

    if observed:
        detected_via.add("dns_check")

    record["detected_via"] = sorted(detected_via)

    _debug("NETWORK CHECK RESULT:", record["network_behavior"])

    return record


# -------------------------------------------------------------------
# UNATTRIBUTED DNS ACTIVITY
#
# attach_network_behavior() above only ever *correlates* DNS activity
# against a tool that was already detected some other way (extension,
# MCP, OAuth). A domain that shows up in the DNS cache but isn't the
# vendor_domain of any already-detected tool has nothing to attach
# to, and was previously just dropped on the floor. The functions
# below turn those leftover domains into their own minimal tool
# records instead, so "something is talking to a domain we don't
# otherwise recognize" stays visible.
# -------------------------------------------------------------------

# Domains that legitimately show up in a DNS cache but aren't a real
# third-party vendor: reverse-DNS PTR lookups, local/VM hostnames,
# mDNS-style names. This is a heuristic, not a guarantee -- if you
# see real vendors getting filtered out (or obvious junk getting
# through), tune this list.
_EXCLUDED_DNS_SUFFIXES = (
    ".in-addr.arpa",
    ".ip6.arpa",
    ".local",
    ".home",
    ".lan",
    ".internal",
    ".mshome.net",  # default Windows/Hyper-V VM network suffix
)

# Cap how many unattributed-DNS stub records get built (and therefore
# how many extra run_prechecks() calls happen) per /tools call. A
# noisy DNS cache full of OS/telemetry domains shouldn't turn every
# scan into dozens of outbound precheck requests.
_MAX_UNATTRIBUTED_DNS_RECORDS = 50


def _is_plausible_vendor_domain(domain: str) -> bool:
    """
    Filter out DNS cache entries that clearly aren't a real
    third-party vendor domain. Anything that passes this is treated
    as worth surfacing.
    """

    if not domain:
        return False

    domain = domain.strip().lower()

    if not domain or "." not in domain:
        return False

    for suffix in _EXCLUDED_DNS_SUFFIXES:
        if domain.endswith(suffix):
            return False

    return True


def _domains_already_covered(merged_records: list[dict[str, Any]]) -> set[str]:
    """
    Vendor domains already represented by a detected tool, so we
    don't create a duplicate "unattributed" entry for a domain that's
    already attached to something real.
    """

    covered: set[str] = set()

    for record in merged_records:

        vendor_domain = record.get("vendor_domain")

        if vendor_domain:
            covered.add(str(vendor_domain).strip().lower())

    return covered


def _build_unattributed_dns_records(
    dns_observed: dict[str, Any],
    covered_domains: set[str],
) -> list[dict[str, Any]]:
    """
    Build one minimal raw record per DNS domain that:

      - looks like a real vendor domain (_is_plausible_vendor_domain)
      - isn't already the vendor_domain of a detected tool

    These get merged in like any other raw record, so they still flow
    through attach_network_behavior() (which will self-match, since
    vendor_domain == the observed domain), attach_prechecks(),
    attach_privacy_policy(), and finalize_tool_id() below.
    """

    records: list[dict[str, Any]] = []

    for domain, last_seen in dns_observed.items():

        if len(records) >= _MAX_UNATTRIBUTED_DNS_RECORDS:

            _debug(
                "UNATTRIBUTED DNS CAP REACHED, skipping remaining domains"
            )

            break

        domain_text = str(domain).strip().lower()

        if not _is_plausible_vendor_domain(domain_text):
            _debug("DNS DOMAIN SKIPPED (not a plausible vendor):", domain_text)
            continue

        if domain_text in covered_domains:
            _debug("DNS DOMAIN SKIPPED (already attributed):", domain_text)
            continue

        timestamp = last_seen or _now_iso()

        records.append(
            {
                "name": domain_text,
                "vendor": domain_text,
                "vendor_domain": domain_text,
                "source_type": "network_dns_activity",
                "stated_function": (
                    "Domain observed in local DNS activity with no "
                    "other detected tool attributed to it."
                ),
                "detected_via": ["dns_check"],
                "permissions": {
                    "requested": [],
                    "previous_snapshot": [],
                    "drift_detected": False,
                    "drift_since": None,
                },
                "first_seen": timestamp,
                "last_scanned": timestamp,
            }
        )

        _debug("DNS DOMAIN -> unattributed record:", domain_text)

    return records


# -------------------------------------------------------------------
# PRECHECKS
# -------------------------------------------------------------------

def _domain_for_prechecks(record: dict[str, Any]) -> str | None:

    domain = record.get("vendor_domain")

    if not domain:
        return None

    domain = str(domain).strip().lower()

    if not domain:
        return None

    domain = re.sub(r"^https?://", "", domain)

    domain = domain.split("/", 1)[0]

    domain = domain.split(":", 1)[0]

    return domain or None


def attach_prechecks(record: dict[str, Any]) -> dict[str, Any]:

    domain = _domain_for_prechecks(record)

    _debug("PRECHECK START:", record.get("name"), "| domain:", domain)

    try:

        record["prechecks"] = run_prechecks(domain)

        _debug("PRECHECK RESULT:", record["prechecks"])

    except Exception as exc:

        print(f"[Normalizer] precheck failed for {domain}: {exc}")

        record["prechecks"] = {"status": "error", "error": str(exc)}

        _debug("PRECHECK ERROR:", record["prechecks"])

    return record


# -------------------------------------------------------------------
# PRIVACY POLICY METADATA
# -------------------------------------------------------------------

def attach_privacy_policy(record: dict[str, Any]) -> dict[str, Any]:
    """
    Preserve privacy-policy metadata collected by an upstream scanner.
    """

    _debug("PRIVACY CHECK START:", record.get("name"))

    privacy = record.get("privacy_policy") or {}

    if not isinstance(privacy, dict):
        privacy = {}

    meta = record.get("meta") or {}

    homepage = (
        privacy.get("homepage_url")
        or privacy.get("homepage")
        or meta.get("homepage")
    )

    privacy_url = privacy.get("url") or privacy.get("privacy_policy_url")

    record["privacy_policy"] = {
        "url": privacy_url,
        "homepage_url": homepage,
        "status": privacy.get("status", "not_discovered"),
        "last_checked": privacy.get("last_checked"),
        "word_count": privacy.get("word_count"),
        "signals": privacy.get("signals", {}),
    }

    _debug("PRIVACY RESULT:", record["privacy_policy"])

    return record


# -------------------------------------------------------------------
# MERGE RECORDS
# -------------------------------------------------------------------

def merge_records(raw_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Collapse raw partial records from every sensing source into one
    record per real-world tool.
    """

    merged: dict[str, dict[str, Any]] = {}

    _debug("================================================")
    _debug("MERGE RECORDS START")
    _debug("Raw record count:", len(raw_records))
    _debug("================================================")

    for index, record in enumerate(raw_records, start=1):

        if not isinstance(record, dict):
            _debug(f"Record #{index} skipped: not a dict")
            continue

        _debug_record(f"RAW RECORD #{index}", record)

        key = _merge_key(record)

        _debug(f"Record #{index} merge key:", key)

        # -----------------------------------------------------------
        # FIRST RECORD
        # -----------------------------------------------------------

        if key not in merged:

            initial = {**record}

            initial["detected_via"] = list(record.get("detected_via", []) or [])

            initial["permissions"] = record.get("permissions", {}) or {}

            merged[key] = initial

            _debug("NEW MERGED TOOL:", key)

            continue

        # -----------------------------------------------------------
        # EXISTING RECORD
        # -----------------------------------------------------------

        existing = merged[key]

        _debug("MERGING INTO EXISTING TOOL:", key)

        # -----------------------------------------------------------
        # detected_via
        # -----------------------------------------------------------

        existing_detected = set(existing.get("detected_via", []) or [])

        new_detected = set(record.get("detected_via", []) or [])

        existing["detected_via"] = sorted(existing_detected | new_detected)

        _debug("Merged detected_via:", existing["detected_via"])

        # -----------------------------------------------------------
        # permissions
        # -----------------------------------------------------------

        existing["permissions"] = _merge_permissions(
            existing.get("permissions", {}),
            record.get("permissions", {}),
        )

        # -----------------------------------------------------------
        # Simple metadata fields
        # -----------------------------------------------------------

        fields_to_prefer = [
            "name",
            "vendor",
            "vendor_domain",
            "stated_function",
            "source_type",
        ]

        for field in fields_to_prefer:

            existing_value = existing.get(field)

            new_value = record.get(field)

            if not existing_value and new_value:

                existing[field] = new_value

                _debug("Metadata filled:", field, "=", new_value)

        # -----------------------------------------------------------
        # Network behavior
        # -----------------------------------------------------------

        existing_network = existing.get("network_behavior") or {}

        new_network = record.get("network_behavior") or {}

        existing_domains = set(existing_network.get("observed_domains", []) or [])

        new_domains = set(new_network.get("observed_domains", []) or [])

        if existing_network or new_network:

            existing["network_behavior"] = {
                "observed_domains": sorted(existing_domains | new_domains),
                "matches_stated_vendor_domain": bool(
                    existing_network.get("matches_stated_vendor_domain", False)
                    or new_network.get("matches_stated_vendor_domain", False)
                ),
            }

            _debug("Merged network_behavior:", existing["network_behavior"])

        # -----------------------------------------------------------
        # Privacy policy
        # -----------------------------------------------------------

        existing_privacy = existing.get("privacy_policy") or {}

        new_privacy = record.get("privacy_policy") or {}

        if not existing_privacy and new_privacy:

            existing["privacy_policy"] = new_privacy

        else:

            if not isinstance(existing_privacy, dict):
                existing_privacy = {}

            if not isinstance(new_privacy, dict):
                new_privacy = {}

            for key_name, value in new_privacy.items():

                if not existing_privacy.get(key_name) and value:

                    existing_privacy[key_name] = value

            existing["privacy_policy"] = existing_privacy

        # -----------------------------------------------------------
        # prechecks
        # -----------------------------------------------------------

        existing_prechecks = existing.get("prechecks") or {}

        new_prechecks = record.get("prechecks") or {}

        if not existing_prechecks and new_prechecks:

            existing["prechecks"] = new_prechecks

        # -----------------------------------------------------------
        # timestamps
        # -----------------------------------------------------------

        existing_first = existing.get("first_seen")

        new_first = record.get("first_seen")

        if existing_first and new_first:

            existing["first_seen"] = min(existing_first, new_first)

        elif new_first:

            existing["first_seen"] = new_first

        existing_last = existing.get("last_scanned")

        new_last = record.get("last_scanned")

        if existing_last and new_last:

            existing["last_scanned"] = max(existing_last, new_last)

        elif new_last:

            existing["last_scanned"] = new_last

        # -----------------------------------------------------------
        # Preserve useful metadata internally
        # -----------------------------------------------------------

        existing_meta = existing.get("meta") or {}

        new_meta = record.get("meta") or {}

        if isinstance(existing_meta, dict) and isinstance(new_meta, dict):

            for meta_key, meta_value in new_meta.items():

                if meta_key not in existing_meta or not existing_meta.get(meta_key):

                    existing_meta[meta_key] = meta_value

                    _debug("Metadata merged:", meta_key, "=", meta_value)

            existing["meta"] = existing_meta

    _debug("================================================")
    _debug("MERGE RECORDS COMPLETE")
    _debug("Unique merged tools:", len(merged))
    _debug("================================================")

    for index, (key, record) in enumerate(merged.items(), start=1):

        _debug(f"MERGED TOOL #{index}:", key)

        _debug_record(f"MERGED TOOL #{index}", record)

    return list(merged.values())


# -------------------------------------------------------------------
# TOOL ID
# -------------------------------------------------------------------

def finalize_tool_id(record: dict[str, Any]) -> dict[str, Any]:
    """
    Rewrite tool_id to a stable human-readable slug.
    """

    name = record.get("name") or record.get("vendor") or "unknown-tool"

    record["tool_id"] = _slug(name)

    _debug("TOOL ID:", name, "->", record["tool_id"])

    return record


# -------------------------------------------------------------------
# AGENT SCHEMA
# -------------------------------------------------------------------

def format_schema_keys(record: dict[str, Any]) -> dict[str, Any]:

    meta = record.get("meta") or {}

    # ---------------------------------------------------------------
    # Preserve browser MCP evidence
    # ---------------------------------------------------------------

    source_metadata = {
        **(record.get("source_metadata", {}) or {}),
        "endpoint": record.get("endpoint") or meta.get("endpoint"),
        "client": record.get("client") or meta.get("client"),
        "confidence": record.get("confidence"),
        "transport": record.get("transport"),
        "signals": record.get("signals", []) or [],
        "methods": record.get("methods", []) or [],
        "tool_names": record.get("tool_names", []) or [],
        "resource_names": record.get("resource_names", []) or [],
    }

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
        "privacy_policy": record.get("privacy_policy", {}),
        "first_seen": record.get("first_seen"),
        "last_scanned": record.get("last_scanned"),
        "source_metadata": source_metadata,
        "vendor_domain": record.get("vendor_domain"),
    }


# -------------------------------------------------------------------
# MAIN ENTRY POINT
# -------------------------------------------------------------------

def build_tool_payload(
    extension_records: list[dict[str, Any]],
    mcp_records: list[dict[str, Any]],
    web_records: list[dict[str, Any]],
    oauth_records: list[dict[str, Any]],
    dns_result: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Main sensing-layer pipeline.

    INPUT:

        extension_records
        mcp_records
        web_records
        oauth_records
        dns_result

    OUTPUT:

        normalized list of Tool objects.
    """

    _debug("\n========================================================")
    _debug("SENTINELAI NORMALIZER START")
    _debug("========================================================")

    # ---------------------------------------------------------------
    # INPUT COUNTS
    # ---------------------------------------------------------------

    _debug("Extension records:", len(extension_records or []))
    _debug("MCP records:", len(mcp_records or []))
    _debug("Web MCP records:", len(web_records or []))
    _debug("OAuth records:", len(oauth_records or []))
    _debug("DNS result type:", type(dns_result).__name__)

    # ---------------------------------------------------------------
    # EXTENSION DEBUG
    # ---------------------------------------------------------------

    _debug("\n========================================================")
    _debug("BROWSER EXTENSION RECORDS")
    _debug("========================================================")

    for index, record in enumerate(extension_records or [], start=1):

        _debug_record(f"EXTENSION #{index}", record)

    # ---------------------------------------------------------------
    # MCP DEBUG
    # ---------------------------------------------------------------

    _debug("\n========================================================")
    _debug("MCP RECORDS")
    _debug("========================================================")

    for index, record in enumerate(mcp_records or [], start=1):

        _debug_record(f"MCP #{index}", record)

        if isinstance(record, dict):

            _debug(
                f"MCP #{index} details:",
                {
                    "mcp_server_id": record.get("mcp_server_id"),
                    "endpoint": record.get("endpoint"),
                    "client": record.get("client"),
                    "transport": record.get("transport"),
                    "confidence": record.get("confidence"),
                    "methods": record.get("methods"),
                    "tool_names": record.get("tool_names"),
                    "resource_names": record.get("resource_names"),
                    "signals": record.get("signals"),
                },
            )

    # ---------------------------------------------------------------
    # WEB MCP DEBUG
    # ---------------------------------------------------------------

    _debug("\n========================================================")
    _debug("WEB MCP RECORDS")
    _debug("========================================================")

    for index, record in enumerate(web_records or [], start=1):

        _debug_record(f"WEB MCP #{index}", record)

        if isinstance(record, dict):

            _debug(
                f"WEB MCP #{index} details:",
                {
                    "endpoint": record.get("endpoint"),
                    "client": record.get("client"),
                    "transport": record.get("transport"),
                    "confidence": record.get("confidence"),
                    "signals": record.get("signals"),
                    "methods": record.get("methods"),
                    "tool_names": record.get("tool_names"),
                    "resource_names": record.get("resource_names"),
                },
            )

    # ---------------------------------------------------------------
    # OAUTH DEBUG
    # ---------------------------------------------------------------

    _debug("\n========================================================")
    _debug("OAUTH RECORDS")
    _debug("========================================================")

    for index, record in enumerate(oauth_records or [], start=1):

        _debug_record(f"OAUTH #{index}", record)

    # ---------------------------------------------------------------
    # DNS DEBUG
    # ---------------------------------------------------------------

    _debug("\n========================================================")
    _debug("DNS INPUT")
    _debug("========================================================")

    _debug("DNS result:", dns_result)

    # ---------------------------------------------------------------
    # Combine every sensing source
    # ---------------------------------------------------------------

    raw_records = [
        *(extension_records or []),
        *(mcp_records or []),
        *(web_records or []),
        *(oauth_records or []),
    ]

    _debug("\n========================================================")
    _debug("ALL RAW RECORDS")
    _debug("========================================================")

    _debug("Total raw records:", len(raw_records))

    # ---------------------------------------------------------------
    # Merge records
    # ---------------------------------------------------------------

    merged = merge_records(raw_records)

    print("[Normalizer DEBUG] raw records:", len(raw_records))

    print(
        "[Normalizer DEBUG] Extension raw records:",
        sum(
            1
            for record in raw_records
            if record.get("source_type")
            in {"extension", "browser_extension", "chrome_extension"}
        ),
    )

    print(
        "[Normalizer DEBUG] MCP raw records:",
        sum(
            1
            for record in raw_records
            if record.get("source_type") in {"mcp", "mcp_server", "mcp_connector"}
        ),
    )

    print(
        "[Normalizer DEBUG] Web MCP raw records:",
        sum(
            1
            for record in raw_records
            if record.get("source_type")
            in {"web", "web_mcp", "browser_mcp", "ai_web"}
        ),
    )

    print(
        "[Normalizer DEBUG] OAuth raw records:",
        sum(
            1
            for record in raw_records
            if record.get("source_type") == "oauth_connected_app"
        ),
    )

    print("[Normalizer DEBUG] merged records:", len(merged))

    print(
        "[Normalizer DEBUG] merged OAuth records:",
        sum(1 for record in merged if record.get("source_type") == "oauth_connected_app"),
    )

    print(
        "[Normalizer DEBUG] merged MCP records:",
        sum(
            1
            for record in merged
            if record.get("source_type") in {"mcp", "mcp_server", "mcp_connector"}
        ),
    )

    print(
        "[Normalizer DEBUG] merged Web MCP records:",
        sum(
            1
            for record in merged
            if record.get("source_type")
            in {"web", "web_mcp", "browser_mcp", "ai_web"}
        ),
    )

    print(
        "[Normalizer DEBUG] OAuth names:",
        [
            record.get("name")
            for record in merged
            if record.get("source_type") == "oauth_connected_app"
        ],
    )

    # ---------------------------------------------------------------
    # Print all merged records
    # ---------------------------------------------------------------

    _debug("\n========================================================")
    _debug("MERGED RECORD SUMMARY")
    _debug("========================================================")

    for index, record in enumerate(merged, start=1):

        _debug_record(f"MERGED #{index}", record)

    # ---------------------------------------------------------------
    # DNS
    # ---------------------------------------------------------------

    if not isinstance(dns_result, dict):
        dns_result = {}

    dns_observed = dns_result.get("observed_domains", {})

    # Some scanners may return a list instead of a dictionary.

    if isinstance(dns_observed, list):

        dns_observed = {str(domain): "" for domain in dns_observed}

    _debug("\n========================================================")
    _debug("NORMALIZED DNS OBSERVATIONS")
    _debug("========================================================")

    _debug("DNS observed domains:", list(dns_observed.keys()))

    # ---------------------------------------------------------------
    # Unattributed DNS activity
    #
    # Without this step, any DNS domain that doesn't match an
    # already-detected tool's vendor_domain is computed by
    # attach_network_behavior() and then silently thrown away.
    # This surfaces it as its own minimal tool record instead.
    # ---------------------------------------------------------------

    covered_domains = _domains_already_covered(merged)

    _debug("Domains already attributed to a detected tool:", sorted(covered_domains))

    unattributed_dns_records = _build_unattributed_dns_records(
        dns_observed,
        covered_domains,
    )

    _debug("Unattributed DNS records created:", len(unattributed_dns_records))

    merged.extend(unattributed_dns_records)

    # ---------------------------------------------------------------
    # Enrich every tool
    # ---------------------------------------------------------------

    output: list[dict[str, Any]] = []

    _debug("\n========================================================")
    _debug("ENRICHMENT PIPELINE START")
    _debug("========================================================")

    for index, record in enumerate(merged, start=1):

        _debug(f"\n------------ PROCESSING TOOL #{index} ------------")

        _debug_record(f"BEFORE ENRICHMENT #{index}", record)

        # -----------------------------------------------------------
        # Network evidence
        # -----------------------------------------------------------

        _debug(f"Tool #{index}: attaching network behavior")

        record = attach_network_behavior(record, dns_observed)

        # -----------------------------------------------------------
        # External prechecks
        # -----------------------------------------------------------

        _debug(f"Tool #{index}: attaching prechecks")

        record = attach_prechecks(record)

        # -----------------------------------------------------------
        # Privacy-policy metadata
        # -----------------------------------------------------------

        _debug(f"Tool #{index}: attaching privacy policy")

        record = attach_privacy_policy(record)

        # -----------------------------------------------------------
        # Stable ID
        # -----------------------------------------------------------

        _debug(f"Tool #{index}: finalizing tool ID")

        record = finalize_tool_id(record)

        _debug_record(f"AFTER ENRICHMENT #{index}", record)

        # -----------------------------------------------------------
        # Remove internal metadata.
        #
        # OAuth client IDs, grant IDs, account subject IDs, etc.
        # should not be sent to the LangGraph schema unless you
        # explicitly decide to expose them.
        # -----------------------------------------------------------

        if "meta" in record:

            _debug(f"Tool #{index}: removing internal meta")

            record.pop("meta", None)

        normalized = format_schema_keys(record)

        output.append(normalized)

        _debug_final_record(index, normalized)

    # ---------------------------------------------------------------
    # FINAL OUTPUT SUMMARY
    # ---------------------------------------------------------------

    _debug("\n========================================================")
    _debug("FINAL NORMALIZED TOOL OUTPUT")
    _debug("========================================================")

    _debug("Final tool count:", len(output))

    for index, tool in enumerate(output, start=1):

        _debug(
            f"FINAL #{index}:",
            {
                "tool_id": tool.get("tool_id"),
                "name": tool.get("name"),
                "vendor": tool.get("vendor"),
                "source_type": tool.get("source_type"),
                "detected_via": tool.get("detected_via"),
                "vendor_domain": tool.get("vendor_domain"),
                "endpoint": (tool.get("source_metadata", {}) or {}).get("endpoint"),
                "client": (tool.get("source_metadata", {}) or {}).get("client"),
                "transport": (tool.get("source_metadata", {}) or {}).get("transport"),
            },
        )

    _debug("\n========================================================")
    _debug("SENTINELAI NORMALIZER COMPLETE")
    _debug("========================================================\n")

    return output
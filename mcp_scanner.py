"""
SentinelAI — MCP Connector Sensing Module

Scans known MCP client config locations (Claude Desktop today; the CANDIDATE_PATHS
list is where you add Cursor/Windsurf/other MCP hosts as they ship configs) and
turns each configured server into a partial Tool record (source_type: "mcp_connector").

This has to run as a local process — a browser extension cannot read arbitrary
filesystem paths — which is why it lives in the local agent alongside the
DNS scanner, not in the Chrome extension.
"""

from __future__ import annotations

import json
import os
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _candidate_config_paths() -> list[tuple[str, Path]]:
    home = Path.home()
    system = platform.system()

    paths: list[tuple[str, Path]] = []

    if system == "Darwin":
        paths.append((
            "claude_desktop",
            home / "Library/Application Support/Claude/claude_desktop_config.json",
        ))
    elif system == "Windows":
        appdata = os.environ.get(
            "APPDATA",
            str(home / "AppData/Roaming"),
        )
        paths.append((
            "claude_desktop",
            Path(appdata) / "Claude/claude_desktop_config.json",
        ))
    else:
        paths.append((
            "claude_desktop",
            home / ".config/Claude/claude_desktop_config.json",
        ))

    return paths


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _server_to_tool_id(server_name: str) -> str:
    return f"mcp-{server_name.strip().lower().replace(' ', '-')}"


def _guess_vendor(command: str, args: list[str]) -> str | None:
    """Best-effort vendor guess from the invoked package/binary name."""
    joined = " ".join([command, *args])
    if "npx" in command or "npx" in joined:
        # e.g. "npx -y @vendor/mcp-server-x" -> "@vendor/mcp-server-x"
        for token in args:
            if token.startswith("@") or "mcp-server" in token or "mcp_server" in token:
                return token
    return None

def scan_mcp_configs(
    state_store: dict[str, dict] | None = None,
) -> list[dict[str, Any]]:
    """
    Returns a list of partial Tool records, one per configured MCP server
    found across all detected client configs.
    """
    now = _now_iso()
    state_store = state_store or {}
    records: list[dict[str, Any]] = []

    for client_name, config_path in _candidate_config_paths():
        if not config_path.exists():
            continue

        config = _read_json(config_path)
        if not config:
            continue

        mcp_servers = config.get("mcpServers", {})

        for server_name, server_cfg in mcp_servers.items():
            command = server_cfg.get("command", "")
            args = server_cfg.get("args", []) or []
            env_keys = sorted(
                (server_cfg.get("env") or {}).keys()
            )

            tool_id = _server_to_tool_id(server_name)
            prev = state_store.get(tool_id)

            record = {
                "tool_id": tool_id,
                "name": server_name,
                "vendor": _guess_vendor(command, args),
                "source_type": "mcp_connector",
                "stated_function": None,
                "detected_via": ["mcp_connector_scan"],
                "permissions": {
                    "requested": [
                        f"env:{k}"
                        for k in env_keys
                    ],
                    "previous_snapshot": (
                        prev.get("env_keys", [])
                        if prev
                        else []
                    ),
                    "drift_detected": (
                        bool(prev)
                        and sorted(prev.get("env_keys", []))
                        != env_keys
                    ),
                    "drift_since": (
                        now
                        if (
                            prev
                            and sorted(prev.get("env_keys", []))
                            != env_keys
                        )
                        else (
                            prev.get("drift_since")
                            if prev
                            else None
                        )
                    ),
                },
                "meta": {
                    "client": client_name,
                    "config_path": str(config_path),
                    "command": command,
                    "args": args,
                },
                "first_seen": (
                    prev.get("first_seen")
                    if prev
                    else now
                ),
                "last_scanned": now,
            }

            records.append(record)

    return records

def build_state_snapshot(records: list[dict[str, Any]]) -> dict[str, dict]:
    """Reduce scan output to the minimal state needed to preserve first_seen/drift
    across runs. Persist the return value of this (e.g. to a JSON file) and pass
    it back in as `state_store` on the next call to scan_mcp_configs()."""
    snapshot: dict[str, dict] = {}
    for r in records:
        snapshot[r["tool_id"]] = {
            "env_keys": [p[4:] for p in r["permissions"]["requested"] if p.startswith("env:")],
            "first_seen": r["first_seen"],
            "drift_since": r["permissions"]["drift_since"],
        }
    return snapshot


if __name__ == "__main__":
    # Standalone smoke test: `python mcp_scanner.py`
    found = scan_mcp_configs()
    print(json.dumps(found, indent=2))

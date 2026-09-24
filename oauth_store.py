# oauth_store.py

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent

STATE_DIR = BASE_DIR / ".state"
STATE_DIR.mkdir(exist_ok=True)

CONNECTIONS_FILE = STATE_DIR / "oauth_connections.json"
OAUTH_RECORDS_FILE = STATE_DIR / "oauth_records.json"
AUDIT_RESULTS_FILE = STATE_DIR / "audit_results.json"


def _load_json(
    path: Path,
    default: Any,
) -> Any:

    if not path.exists():
        return default

    try:
        return json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

    except Exception:
        return default


def _save_json(
    path: Path,
    data: Any,
) -> None:

    path.write_text(
        json.dumps(
            data,
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    # Best effort protection on Unix/Linux/macOS.
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


# -------------------------------------------------------------------
# OAUTH CONNECTIONS
# -------------------------------------------------------------------

def load_connections() -> list[dict[str, Any]]:
    return _load_json(
        CONNECTIONS_FILE,
        [],
    )


def save_connection(
    *,
    user_id: str,
    provider: str,
    data: dict[str, Any],
) -> dict[str, Any]:

    connections = load_connections()

    new_record = {
        "user_id": user_id,
        "provider": provider,
        **data,
    }

    replaced = False

    for index, connection in enumerate(connections):

        if (
            connection.get("user_id") == user_id
            and connection.get("provider") == provider
        ):

            connections[index] = new_record

            replaced = True

            break

    if not replaced:
        connections.append(new_record)

    _save_json(
        CONNECTIONS_FILE,
        connections,
    )

    return new_record


def get_connection(
    *,
    user_id: str,
    provider: str,
) -> dict[str, Any] | None:

    connections = load_connections()

    for connection in connections:

        if (
            connection.get("user_id") == user_id
            and connection.get("provider") == provider
        ):

            return connection

    return None


def delete_connection(
    *,
    user_id: str,
    provider: str,
) -> None:

    connections = load_connections()

    connections = [
        item
        for item in connections
        if not (
            item.get("user_id") == user_id
            and item.get("provider") == provider
        )
    ]

    _save_json(
        CONNECTIONS_FILE,
        connections,
    )


# -------------------------------------------------------------------
# OAUTH SCAN RECORDS
# -------------------------------------------------------------------

def load_oauth_records() -> list[dict[str, Any]]:

    return _load_json(
        OAUTH_RECORDS_FILE,
        [],
    )


def save_oauth_records(
    records: list[dict[str, Any]],
) -> None:

    _save_json(
        OAUTH_RECORDS_FILE,
        records,
    )


# -------------------------------------------------------------------
# AUDIT RESULTS
# -------------------------------------------------------------------

def load_audit_results() -> list[dict[str, Any]]:

    return _load_json(
        AUDIT_RESULTS_FILE,
        [],
    )


def save_audit_results(
    results: list[dict[str, Any]],
) -> None:

    _save_json(
        AUDIT_RESULTS_FILE,
        results,
    )
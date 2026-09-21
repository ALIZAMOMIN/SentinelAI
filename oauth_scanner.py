"""
SentinelAI — OAuth Connected-Apps Sensing Module

Two paths, matching the honest assessment from before:

1. Microsoft Graph (`microsoft_graph_scan`) — genuinely live and automatable:
   the signed-in user's own /me/oauth2PermissionGrants endpoint. Requires a
   delegated-permission access token (acquire via MSAL in your frontend/auth
   flow and pass it in here — this module does not do the OAuth dance itself).

2. Google (`import_google_manual_export`) — Google doesn't expose this to
   third-party apps for arbitrary users, so the realistic path is: the user
   visits myaccount.google.com/permissions once, and either pastes the app
   names or you guide them through Google Takeout / Security Checkup export.
   This function just normalizes whatever list they hand you into the same
   Tool-record shape as everything else — no scraping, nothing fragile.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import requests

GRAPH_GRANTS_URL = "https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants"
GRAPH_SP_URL = "https://graph.microsoft.com/v1.0/servicePrincipals/{id}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def microsoft_graph_scan(access_token: str) -> list[dict[str, Any]]:
    """Requires a delegated access token with at least the
    `Directory.Read.All` or `DelegatedPermissionGrant.Read.All` scope,
    acquired by your own auth flow (MSAL.js in the extension/web app)."""
    now = _now_iso()
    headers = {"Authorization": f"Bearer {access_token}"}

    try:
        resp = requests.get(GRAPH_GRANTS_URL, headers=headers, timeout=10)
        resp.raise_for_status()
        grants = resp.json().get("value", [])
    except requests.RequestException:
        return []

    records = []
    for grant in grants:
        client_id = grant.get("clientId")
        scopes = (grant.get("scope") or "").split()

        app_name = client_id  # fallback if the service principal lookup fails
        try:
            sp_resp = requests.get(
                GRAPH_SP_URL.format(id=client_id), headers=headers, timeout=10
            )
            if sp_resp.ok:
                app_name = sp_resp.json().get("displayName", client_id)
        except requests.RequestException:
            pass

        records.append(
            {
                "tool_id": f"oauth-ms-{client_id}",
                "name": app_name,
                "vendor": None,
                "source_type": "oauth_connected_app",
                "stated_function": None,
                "detected_via": ["oauth_connected_apps_scan"],
                "permissions": {
                    "requested": scopes,
                    "previous_snapshot": scopes,
                    "drift_detected": False,
                    "drift_since": None,
                },
                "first_seen": now,
                "last_scanned": now,
            }
        )

    return records


def import_google_manual_export(app_names: list[str]) -> list[dict[str, Any]]:
    """Normalizes a user-provided list of app names (pasted from
    myaccount.google.com/permissions) into partial Tool records. No live
    scraping — this is the honest fallback for the Google side."""
    now = _now_iso()
    return [
        {
            "tool_id": f"oauth-google-manual-{i}",
            "name": name,
            "vendor": None,
            "source_type": "oauth_connected_app",
            "stated_function": None,
            "detected_via": ["oauth_connected_apps_scan"],
            "permissions": {
                "requested": [],
                "previous_snapshot": [],
                "drift_detected": False,
                "drift_since": None,
            },
            "meta": {"import_method": "manual_google_export"},
            "first_seen": now,
            "last_scanned": now,
        }
        for i, name in enumerate(app_names)
    ]

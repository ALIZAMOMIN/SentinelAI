from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import requests


# ============================================================
# CONFIGURATION
# ============================================================

MICROSOFT_GRAPH_GRANTS_URL = (
    "https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants"
)

MICROSOFT_GRAPH_SP_URL = (
    "https://graph.microsoft.com/v1.0/servicePrincipals/{id}"
)

GOOGLE_USERINFO_URL = (
    "https://openidconnect.googleapis.com/v1/userinfo"
)


# ============================================================
# HELPERS
# ============================================================

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    timeout: int = 10,
) -> dict[str, Any] | None:
    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=timeout,
        )

        if not response.ok:
            return None

        return response.json()

    except (requests.RequestException, ValueError):
        return None


# ============================================================
# MICROSOFT
# ============================================================

def microsoft_graph_scan(
    access_token: str,
) -> list[dict[str, Any]]:
    """
    Scan Microsoft Entra delegated OAuth permission grants
    for the signed-in Microsoft work/school user.

    The access token must have sufficient Microsoft Graph
    delegated permissions.

    Microsoft currently documents Directory.Read.All as the
    least-privileged delegated permission for this operation.
    """

    if not access_token:
        return []

    now = _now_iso()

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    data = _safe_get(
        MICROSOFT_GRAPH_GRANTS_URL,
        headers=headers,
    )

    if not data:
        return []

    grants = data.get("value", [])

    records: list[dict[str, Any]] = []

    for grant in grants:
        client_id = grant.get("clientId")

        if not client_id:
            continue

        scopes = sorted(
            set(
                (grant.get("scope") or "")
                .split()
            )
        )

        app_name = client_id

        # Try to resolve the application/service principal name.
        service_principal = _safe_get(
            MICROSOFT_GRAPH_SP_URL.format(id=client_id),
            headers=headers,
        )

        if service_principal:
            app_name = (
                service_principal.get("displayName")
                or client_id
            )

        record = {
            "tool_id": f"oauth-ms-{client_id}",
            "name": app_name,
            "vendor": app_name,
            "vendor_domain": None,
            "source_type": "oauth_connected_app",
            "stated_function": None,

            "detected_via": [
                "microsoft_oauth_grants_scan"
            ],

            "permissions": {
                "requested": scopes,
                "previous_snapshot": scopes,
                "drift_detected": False,
                "drift_since": None,
            },

            "meta": {
                "provider": "microsoft",
                "oauth_client_id": client_id,
                "consent_type": grant.get("consentType"),
                "principal_id": grant.get("principalId"),
                "resource_id": grant.get("resourceId"),
                "grant_id": grant.get("id"),
            },

            "first_seen": now,
            "last_scanned": now,
        }

        records.append(record)

    return records


# ============================================================
# MICROSOFT TOKEN VALIDATION / IDENTITY
# ============================================================

def microsoft_user_info(
    access_token: str,
) -> dict[str, Any] | None:
    """
    Get basic identity information from Microsoft Graph.

    Requires a token capable of calling /me.
    """

    if not access_token:
        return None

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    return _safe_get(
        "https://graph.microsoft.com/v1.0/me",
        headers=headers,
    )


# ============================================================
# GOOGLE
# ============================================================

def google_user_info(
    access_token: str,
) -> dict[str, Any] | None:
    """
    Get basic Google account identity information from a
    Google OAuth/OIDC access token.

    IMPORTANT:
    Google OAuth does NOT provide a general API through this
    endpoint for enumerating every third-party application
    connected to the user's Google account.
    """

    if not access_token:
        return None

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    return _safe_get(
        GOOGLE_USERINFO_URL,
        headers=headers,
    )


def google_identity_record(
    access_token: str,
) -> dict[str, Any] | None:
    """
    Convert Google account identity into a SentinelAI record.
    """

    user = google_user_info(access_token)

    if not user:
        return None

    now = _now_iso()

    subject = (
        user.get("sub")
        or user.get("email")
        or "unknown"
    )

    email = user.get("email")

    return {
        "tool_id": f"oauth-google-account-{subject}",
        "name": "Google Account",
        "vendor": "Google",
        "vendor_domain": "google.com",
        "source_type": "oauth_account",
        "stated_function": (
            "Google account connected to SentinelAI"
        ),

        "detected_via": [
            "google_oauth_identity"
        ],

        "permissions": {
            "requested": [],
            "previous_snapshot": [],
            "drift_detected": False,
            "drift_since": None,
        },

        "meta": {
            "provider": "google",
            "account_subject": subject,
            "email": email,
        },

        "first_seen": now,
        "last_scanned": now,
    }


# ============================================================
# GOOGLE MANUAL CONNECTED-APP IMPORT
# ============================================================

def import_google_manual_export(
    app_names: list[str],
) -> list[dict[str, Any]]:
    """
    Import application names supplied by the user from their
    Google account's third-party connections/permissions page.

    This is intentionally manual because a normal Google OAuth
    token does not provide a general API for enumerating every
    third-party connection on the user's account.
    """

    now = _now_iso()

    records: list[dict[str, Any]] = []

    for index, raw_name in enumerate(app_names):
        name = str(raw_name).strip()

        if not name:
            continue

        records.append(
            {
                "tool_id": (
                    f"oauth-google-manual-{index}"
                ),

                "name": name,

                "vendor": name,

                "vendor_domain": None,

                "source_type": (
                    "oauth_connected_app"
                ),

                "stated_function": None,

                "detected_via": [
                    "google_manual_oauth_export"
                ],

                "permissions": {
                    "requested": [],
                    "previous_snapshot": [],
                    "drift_detected": False,
                    "drift_since": None,
                },

                "meta": {
                    "provider": "google",
                    "import_method": (
                        "manual_google_export"
                    ),
                    "oauth_client_id": (
                        f"google-manual-{index}"
                    ),
                },

                "first_seen": now,
                "last_scanned": now,
            }
        )

    return records


# ============================================================
# COMBINED AUTH SCAN
# ============================================================

def scan_auth_sources(
    *,
    microsoft_access_token: str | None = None,
    google_access_token: str | None = None,
    google_manual_apps: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Run whichever authentication sources are available.

    This does NOT ask for passwords.

    OAuth tokens must already have been obtained through the
    appropriate provider consent flow.
    """

    records: list[dict[str, Any]] = []

    if microsoft_access_token:
        records.extend(
            microsoft_graph_scan(
                microsoft_access_token
            )
        )

    if google_access_token:
        identity = google_identity_record(
            google_access_token
        )

        if identity:
            records.append(identity)

    if google_manual_apps:
        records.extend(
            import_google_manual_export(
                google_manual_apps
            )
        )

    return records
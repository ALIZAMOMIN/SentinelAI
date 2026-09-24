from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import requests


GOOGLE_USERINFO_URL = (
    "https://openidconnect.googleapis.com/v1/userinfo"
)


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat()
    )


def _safe_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any] | None:

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=20,
        )

        if not response.ok:
            print(
                f"[OAuth scanner] GET {url} "
                f"failed: {response.status_code}"
            )
            return None

        return response.json()

    except Exception as exc:
        print(
            f"[OAuth scanner] GET {url} "
            f"error: {exc}"
        )
        return None


# -------------------------------------------------------------------
# GOOGLE
# -------------------------------------------------------------------

def google_user_info(
    access_token: str,
) -> dict[str, Any] | None:

    return _safe_get(
        GOOGLE_USERINFO_URL,
        headers={
            "Authorization": (
                f"Bearer {access_token}"
            ),
            "Accept": "application/json",
        },
    )


def google_identity_record(
    access_token: str,
) -> dict[str, Any] | None:

    user = google_user_info(
        access_token
    )

    if not user:
        return None

    subject = user.get(
        "sub"
    )

    email = user.get(
        "email"
    )

    now = _now_iso()

    return {
        "tool_id": (
            "oauth-google-account"
        ),

        "name": (
            "Google Account"
        ),

        "source_type": (
            "oauth_account"
        ),

        "detected_via": [
            "google_userinfo"
        ],

        "permissions": {
            "requested": [
                "openid",
                "userinfo.email",
                "userinfo.profile",
            ]
        },

        "meta": {
            "provider": "google",
            "account_subject": subject,
            "email": email,
            "email_verified": user.get(
                "email_verified"
            ),
        },

        "privacy_policy": {
            "url": (
                "https://policies.google.com/privacy"
            ),
            "status": "known",
        },

        "first_seen": now,
        "last_scanned": now,
    }


# -------------------------------------------------------------------
# GOOGLE MANUAL IMPORT
# -------------------------------------------------------------------

def import_google_manual_export(
    app_names: list[str],
) -> list[dict[str, Any]]:

    records: list[dict[str, Any]] = []

    now = _now_iso()

    for app_name in app_names:

        if not app_name:
            continue

        name = app_name.strip()

        if not name:
            continue

        records.append(
            {
                "tool_id": (
                    "oauth-google-"
                    + name.lower()
                    .replace(" ", "-")
                ),

                "name": name,

                "source_type": (
                    "oauth_connected_app"
                ),

                "detected_via": [
                    "google_manual_oauth_export"
                ],

                "permissions": {
                    "requested": []
                },

                "meta": {
                    "provider": "google",
                    "manual_import": True,
                },

                "privacy_policy": {
                    "url": None,
                    "status": (
                        "not_discovered"
                    ),
                },

                "first_seen": now,
                "last_scanned": now,
            }
        )

    return records


# -------------------------------------------------------------------
# GOOGLE WORKSPACE TOKEN AUDIT
# -------------------------------------------------------------------

def google_workspace_token_scan(
    access_token: str,
) -> list[dict[str, Any]]:

    records: list[dict[str, Any]] = []

    page_token: str | None = None

    while True:

        params: dict[str, Any] = {
            "maxResults": 1000,
        }

        if page_token:
            params["pageToken"] = page_token

        try:
            response = requests.get(
                "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/token",
                headers={
                    "Authorization": (
                        f"Bearer {access_token}"
                    ),
                    "Accept": "application/json",
                },
                params=params,
                timeout=20,
            )

        except Exception as exc:
            print(
                "Google Workspace token audit error:",
                exc,
            )
            break

        if response.status_code != 200:

            print(
                "Google Workspace token audit failed:",
                response.status_code,
                response.text,
            )

            break

        try:
            data = response.json()

        except Exception as exc:

            print(
                "Google Workspace token audit JSON error:",
                exc,
            )

            break

        for item in data.get(
            "items",
            [],
        ):

            actor = item.get(
                "actor",
                {},
            )

            user_email = actor.get(
                "email"
            )

            for event in item.get(
                "events",
                [],
            ):

                params_map: dict[
                    str,
                    Any,
                ] = {}

                for parameter in event.get(
                    "parameters",
                    [],
                ):

                    name = parameter.get(
                        "name"
                    )

                    if not name:
                        continue

                    if "value" in parameter:

                        params_map[name] = (
                            parameter["value"]
                        )

                    elif "multiValue" in parameter:

                        params_map[name] = (
                            parameter["multiValue"]
                        )

                app_name = params_map.get(
                    "app_name"
                )

                client_id = params_map.get(
                    "client_id"
                )

                client_type = params_map.get(
                    "client_type"
                )

                scope = params_map.get(
                    "scope"
                )

                if not app_name and not client_id:
                    continue

                if isinstance(
                    scope,
                    str,
                ):

                    scopes = scope.split()

                elif isinstance(
                    scope,
                    list,
                ):

                    scopes = scope

                else:

                    scopes = []

                stable_id = (
                    client_id
                    or app_name
                )

                now = _now_iso()

                records.append(
                    {
                        "tool_id": (
                            f"oauth-google-{stable_id}"
                        ),

                        "name": (
                            app_name
                            or client_id
                        ),

                        "source_type": (
                            "oauth_connected_app"
                        ),

                        "detected_via": [
                            "google_workspace_token_audit"
                        ],

                        "permissions": {
                            "requested": scopes
                        },

                        "meta": {
                            "provider": "google",
                            "oauth_client_id": client_id,
                            "client_type": client_type,
                            "google_workspace_user": (
                                user_email
                            ),
                            "event": (
                                event.get(
                                    "name"
                                )
                            ),
                            "event_time": (
                                item.get(
                                    "id",
                                    {},
                                ).get(
                                    "time"
                                )
                            ),
                        },

                        "privacy_policy": {
                            "url": None,
                            "status": (
                                "not_discovered"
                            ),
                        },

                        "first_seen": now,
                        "last_scanned": now,
                    }
                )

        page_token = data.get(
            "nextPageToken"
        )

        if not page_token:
            break

    return records


# -------------------------------------------------------------------
# COMBINED AUTH SCANNER
# -------------------------------------------------------------------
'''
def scan_auth_sources(
    *,
    google_access_token: str | None = None,
    google_manual_apps: list[str] | None = None,
    google_workspace_access_token: str | None = None,
) -> list[dict[str, Any]]:

    records: list[
        dict[str, Any]
    ] = []

    # Google account identity
    if google_access_token:

        identity = (
            google_identity_record(
                google_access_token
            )
        )

        if identity:
            records.append(
                identity
            )

    # Manually imported Google apps
    if google_manual_apps:

        records.extend(
            import_google_manual_export(
                google_manual_apps
            )
        )

    # Google Workspace token audit
    if google_workspace_access_token:

        records.extend(
            google_workspace_token_scan(
                google_workspace_access_token
            )
        )

    return records

'''


def scan_auth_sources(
    *,
    google_access_token: str | None = None,
    google_manual_apps: list[str] | None = None,
    google_workspace_access_token: str | None = None,
) -> list[dict[str, Any]]:

    records: list[dict[str, Any]] = []

    # Google account identity.
    if google_access_token:

        identity = google_identity_record(
            google_access_token
        )

        if identity:
            records.append(identity)

    # Manually imported Google connected apps.
    if google_manual_apps:

        records.extend(
            import_google_manual_export(
                google_manual_apps
            )
        )

    # NOTE:
    # Personal Google accounts do not use the
    # Google Workspace Admin Reports token audit
    # to discover connected apps.
    #
    # Browser discovery of:
    #
    #   https://myaccount.google.com/linkedapps
    #
    # is handled by the Chrome extension.

    return records
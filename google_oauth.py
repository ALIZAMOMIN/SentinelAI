from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow


GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]

GOOGLE_REDIRECT_URI = os.environ.get(
    "GOOGLE_REDIRECT_URI",
    "http://127.0.0.1:8787/oauth/google/callback",
)


GOOGLE_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",

    # Google Workspace OAuth token activity
    #"https://www.googleapis.com/auth/admin.reports.audit.readonly",
]


def create_google_flow(
    *,
    state: str | None = None,
) -> Flow:

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": (
                    "https://accounts.google.com/o/oauth2/auth"
                ),
                "token_uri": (
                    "https://oauth2.googleapis.com/token"
                ),
                "redirect_uris": [
                    GOOGLE_REDIRECT_URI
                ],
            }
        },
        scopes=GOOGLE_SCOPES,
        state=state,
        redirect_uri=GOOGLE_REDIRECT_URI,
    )

    return flow


def build_google_credentials(
    *,
    access_token: str | None,
    refresh_token: str | None,
    token_expiry: str | None = None,
) -> Credentials:

    expiry = None

    if token_expiry:
        try:
            expiry = datetime.fromisoformat(
                token_expiry
            )

            if expiry.tzinfo is None:
                expiry = expiry.replace(
                    tzinfo=timezone.utc
                )

        except Exception:
            expiry = None

    return Credentials(
        token=access_token,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scopes=GOOGLE_SCOPES,
        expiry=expiry,
    )


def refresh_google_credentials(
    *,
    access_token: str | None,
    refresh_token: str | None,
    token_expiry: str | None = None,
) -> dict[str, Any]:

    credentials = build_google_credentials(
        access_token=access_token,
        refresh_token=refresh_token,
        token_expiry=token_expiry,
    )

    if not credentials.refresh_token:
        raise RuntimeError(
            "Google refresh token is not available. "
            "Reconnect the Google account."
        )

    credentials.refresh(Request())

    if not credentials.token:
        raise RuntimeError(
            "Google token refresh returned no access token."
        )

    return {
        "access_token": credentials.token,
        "refresh_token": (
            credentials.refresh_token
            or refresh_token
        ),
        "token_expiry": (
            credentials.expiry.isoformat()
            if credentials.expiry
            else None
        ),
    }
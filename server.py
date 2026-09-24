# server.py
from __future__ import annotations

import os
import re
import secrets
import json
import hashlib
from pathlib import Path
from typing import Any

# -------------------------------------------------------------------
# OAUTHLIB / LOCAL DEVELOPMENT
# -------------------------------------------------------------------

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

from dotenv import load_dotenv

load_dotenv()

# -------------------------------------------------------------------
# FASTAPI
# -------------------------------------------------------------------

from fastapi import (
    FastAPI,
    HTTPException,
    Request,
)

from fastapi.middleware.cors import CORSMiddleware

from fastapi.responses import (
    FileResponse,
    RedirectResponse,
)

from fastapi.staticfiles import StaticFiles

from pydantic import BaseModel

from starlette.middleware.sessions import SessionMiddleware


# -------------------------------------------------------------------
# YOUR EXISTING SCANNERS
# -------------------------------------------------------------------

from dns_scanner import scan_dns_activity

from mcp_scanner import (
    build_state_snapshot,
    scan_mcp_configs,
)

from normalizer import build_tool_payload


# -------------------------------------------------------------------
# GOOGLE OAUTH
# -------------------------------------------------------------------

from google_oauth import (
    create_google_flow,
    refresh_google_credentials,
)

from oauth_scanner import (
    google_identity_record,
    google_workspace_token_scan,
)

from oauth_store import (
    get_connection,
    load_oauth_records,
    save_connection,
    save_oauth_records,
    load_audit_results,
    save_audit_results,
)


# -------------------------------------------------------------------
# LANGGRAPH
# -------------------------------------------------------------------

from graph import build_graph


# -------------------------------------------------------------------
# PATHS
# -------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

STATE_DIR = BASE_DIR / ".state"

STATE_DIR.mkdir(exist_ok=True)


MCP_STATE_FILE = (
    STATE_DIR / "mcp_state.json"
)


LATEST_EXT_RECORDS_FILE = (
    STATE_DIR / "latest_extension_records.json"
)


GOOGLE_MANUAL_FILE = (
    STATE_DIR / "google_manual.json"
)


LATEST_TOOLS_FILE = (
    STATE_DIR / "latest_tools.json"
)


LATEST_OAUTH_RECORDS_FILE = (
    STATE_DIR / "latest_oauth_records.json"
)


LATEST_AUDIT_RESULTS_FILE = (
    STATE_DIR / "latest_audit_results.json"
)


LATEST_WEB_RECORDS_FILE = (
    STATE_DIR / "latest_web_records.json"
)


LATEST_DNS_FILE = (
    STATE_DIR / "latest_dns_records.json"
)


# -------------------------------------------------------------------
# APP
# -------------------------------------------------------------------

app = FastAPI(
    title="SentinelAI Local Sensing Agent"
)


# -------------------------------------------------------------------
# SESSION
# -------------------------------------------------------------------

SESSION_SECRET = os.environ.get(
    "SESSION_SECRET"
)

if not SESSION_SECRET:

    SESSION_SECRET = secrets.token_urlsafe(32)

    print(
        "[WARNING] SESSION_SECRET is not set. "
        "A temporary secret is being generated."
    )


app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=False,
    same_site="lax",
)


# -------------------------------------------------------------------
# CORS
# -------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------------------------------------------------------------------
# STATIC
# -------------------------------------------------------------------

STATIC_DIR = BASE_DIR / "static"

if STATIC_DIR.exists():

    app.mount(
        "/static",
        StaticFiles(
            directory=str(STATIC_DIR)
        ),
        name="static",
    )


# -------------------------------------------------------------------
# EXTENSION / WEB STATE
# -------------------------------------------------------------------

_web_records: list[
    dict[str, Any]
] = []


if LATEST_WEB_RECORDS_FILE.exists():

    try:

        loaded_web_records = json.loads(
            LATEST_WEB_RECORDS_FILE.read_text(
                encoding="utf-8"
            )
        )

        if isinstance(
            loaded_web_records,
            list,
        ):
            _web_records = loaded_web_records
        else:
            _web_records = []

    except Exception:

        _web_records = []


_extension_records: list[
    dict[str, Any]
] = []


if LATEST_EXT_RECORDS_FILE.exists():

    try:

        loaded_extension_records = json.loads(
            LATEST_EXT_RECORDS_FILE.read_text(
                encoding="utf-8"
            )
        )

        if isinstance(
            loaded_extension_records,
            list,
        ):
            _extension_records = (
                loaded_extension_records
            )
        else:
            _extension_records = []

    except Exception:

        _extension_records = []


# -------------------------------------------------------------------
# HELPERS
# -------------------------------------------------------------------

DEV_USER_ID = "local-user"


def get_user_id(
    request: Request,
) -> str:

    return request.session.get(
        "user_id",
        DEV_USER_ID,
    )


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


def _load_mcp_state():

    return _load_json(
        MCP_STATE_FILE,
        {},
    )


def _save_mcp_state(
    state,
):

    _save_json(
        MCP_STATE_FILE,
        state,
    )


def _load_google_manual():

    return _load_json(
        GOOGLE_MANUAL_FILE,
        [],
    )


def _save_oauth_json(
    records: list[dict[str, Any]],
) -> None:

    _save_json(
        LATEST_OAUTH_RECORDS_FILE,
        records,
    )


# -------------------------------------------------------------------
# STABLE RECORD IDENTITY
# -------------------------------------------------------------------

def _normalize_identity_value(
    value: Any,
) -> str:

    if value is None:
        return ""

    if isinstance(
        value,
        (dict, list),
    ):

        try:

            return json.dumps(
                value,
                sort_keys=True,
                default=str,
                separators=(
                    ",",
                    ":",
                ),
            ).lower()

        except Exception:

            return str(value).lower()

    return (
        str(value)
        .strip()
        .lower()
    )


def _stable_record_key(
    record: dict[str, Any],
    namespace: str = "record",
) -> str:

    """
    Build a stable identity for a record.

    Priority:
      1. explicit tool_id
      2. source-specific IDs
      3. stable descriptive fields
      4. hash fallback

    Timestamps are deliberately NOT part of the identity.
    """

    source_type = (
        record.get("source_type")
        or record.get("sourceType")
        or namespace
    )

    source_type = _normalize_identity_value(
        source_type
    )

    # ---------------------------------------------------------------
    # Strong identifiers
    # ---------------------------------------------------------------

    strong_id = (
        record.get("tool_id")
        or record.get("id")
        or record.get("extension_id")
        or record.get("google_subject")
        or record.get("account_subject")
    )

    if strong_id:

        return (
            f"{namespace}|"
            f"{source_type}|"
            f"id|"
            f"{_normalize_identity_value(strong_id)}"
        )


    # ---------------------------------------------------------------
    # Stable descriptive identity
    # ---------------------------------------------------------------

    identity_fields = {

        "source_type":
            source_type,

        "name":
            record.get("name"),

        "tool_name":
            record.get("tool_name"),

        "vendor":
            record.get("vendor"),

        "vendor_domain":
            record.get("vendor_domain"),

        "provider":
            record.get("meta", {}).get(
                "provider"
            )
            if isinstance(
                record.get("meta"),
                dict,
            )
            else None,

        "email":
            record.get("email"),

        "endpoint":
            record.get("endpoint")
            or (
                record.get(
                    "meta",
                    {},
                ).get("endpoint")
                if isinstance(
                    record.get("meta"),
                    dict,
                )
                else None
            ),

        "connector_name":
            record.get(
                "connector_name"
            ),

        "client":
            record.get("client")
            or (
                record.get(
                    "meta",
                    {},
                ).get("client")
                if isinstance(
                    record.get("meta"),
                    dict,
                )
                else None
            ),

    }


    canonical = json.dumps(
        identity_fields,
        sort_keys=True,
        default=str,
        separators=(
            ",",
            ":",
        ),
    )


    digest = hashlib.sha256(
        canonical.encode(
            "utf-8"
        )
    ).hexdigest()[:24]


    return (
        f"{namespace}|"
        f"{source_type}|"
        f"hash|"
        f"{digest}"
    )


# -------------------------------------------------------------------
# GENERIC MERGE
# -------------------------------------------------------------------

def _merge_record_lists(
    existing_records: list[dict[str, Any]],
    incoming_records: list[dict[str, Any]],
    *,
    namespace: str,
) -> list[dict[str, Any]]:

    """
    Merge records without allowing one source/scan to erase
    another source/scan.

    Existing records are preserved.
    Matching records are updated.
    New records are appended.
    """

    merged: dict[
        str,
        dict[str, Any]
    ] = {}

    order: list[str] = []


    # ---------------------------------------------------------------
    # Existing
    # ---------------------------------------------------------------

    for record in existing_records:

        if not isinstance(
            record,
            dict,
        ):
            continue

        key = _stable_record_key(
            record,
            namespace,
        )

        if key not in merged:

            merged[key] = dict(
                record
            )

            order.append(key)

        else:

            merged[key] = {
                **merged[key],
                **record,
            }


    # ---------------------------------------------------------------
    # Incoming
    # ---------------------------------------------------------------

    for record in incoming_records:

        if not isinstance(
            record,
            dict,
        ):
            continue

        key = _stable_record_key(
            record,
            namespace,
        )


        if key in merged:

            previous = merged[key]

            merged_record = {
                **previous,
                **record,
            }

            # Preserve first_seen if the incoming record does not
            # contain it.
            if (
                previous.get("first_seen")
                and not record.get("first_seen")
            ):

                merged_record["first_seen"] = (
                    previous.get(
                        "first_seen"
                    )
                )


            # Preserve the latest scan timestamp when appropriate.
            incoming_last_scanned = (
                record.get(
                    "last_scanned"
                )
            )

            previous_last_scanned = (
                previous.get(
                    "last_scanned"
                )
            )

            if not incoming_last_scanned:

                merged_record["last_scanned"] = (
                    previous_last_scanned
                )


            merged[key] = (
                merged_record
            )

        else:

            merged[key] = dict(
                record
            )

            order.append(key)


    return [
        merged[key]
        for key in order
    ]


# -------------------------------------------------------------------
# OAUTH MERGE
# -------------------------------------------------------------------

def merge_oauth_records(
    incoming_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    existing_records = (
        load_oauth_records()
    )

    merged_records = (
        _merge_record_lists(
            existing_records,
            incoming_records,
            namespace="oauth",
        )
    )

    save_oauth_records(
        merged_records
    )

    _save_oauth_json(
        merged_records
    )

    print(
        "[OAuth] Existing records:",
        len(existing_records),
    )

    print(
        "[OAuth] Incoming records:",
        len(incoming_records),
    )

    print(
        "[OAuth] Total after merge:",
        len(merged_records),
    )

    return merged_records


# -------------------------------------------------------------------
# EXTENSION MERGE
# -------------------------------------------------------------------

def merge_extension_records(
    incoming_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    global _extension_records

    if not incoming_records:

        # Do NOT erase the existing inventory because an extension
        # scanner happened to send an empty response.
        return _extension_records

    _extension_records = (
        _merge_record_lists(
            _extension_records,
            incoming_records,
            namespace="extension",
        )
    )

    _save_json(
        LATEST_EXT_RECORDS_FILE,
        _extension_records,
    )

    return _extension_records


# -------------------------------------------------------------------
# RECONCILE WEB-DISCOVERED OAUTH RECORDS
# -------------------------------------------------------------------

def reconcile_persistent_records() -> None:

    """
    Recover browser-discovered OAuth connected apps into the OAuth
    store without deleting anything already there.

    This is especially useful when an older version of the server
    accidentally overwrote latest_oauth_records.json.
    """

    recovered_records: list[
        dict[str, Any]
    ] = []


    # ---------------------------------------------------------------
    # Browser observations
    # ---------------------------------------------------------------

    for record in _web_records:

        if not isinstance(
            record,
            dict,
        ):
            continue

        source_type = str(
            record.get(
                "source_type",
                "",
            )
        ).lower()

        if source_type == (
            "oauth_connected_app"
        ):

            recovered_records.append(
                record
            )


    # ---------------------------------------------------------------
    # Manual Google records
    # ---------------------------------------------------------------

    manual_records = (
        _load_google_manual()
    )

    if isinstance(
        manual_records,
        list,
    ):

        recovered_records.extend(
            [
                record
                for record in manual_records
                if isinstance(
                    record,
                    dict,
                )
            ]
        )


    # ---------------------------------------------------------------
    # Merge if anything was recovered
    # ---------------------------------------------------------------

    if recovered_records:

        merge_oauth_records(
            recovered_records
        )


# -------------------------------------------------------------------
# GOOGLE TOKEN HELPER
# -------------------------------------------------------------------

def get_valid_google_access_token(
    *,
    user_id: str,
) -> str | None:

    google = get_connection(
        user_id=user_id,
        provider="google",
    )

    if not google:
        return None

    if google.get(
        "disconnected",
        False,
    ):
        return None

    access_token = google.get(
        "access_token"
    )

    refresh_token = google.get(
        "refresh_token"
    )

    token_expiry = google.get(
        "token_expiry"
    )

    if not access_token:
        return None


    if not refresh_token:

        print(
            "[Google OAuth] No refresh token available. "
            "Using existing access token."
        )

        return access_token


    try:

        refreshed = (
            refresh_google_credentials(

                access_token=access_token,

                refresh_token=refresh_token,

                token_expiry=token_expiry,

            )
        )


        refreshed_access_token = (
            refreshed.get(
                "access_token"
            )
        )


        refreshed_refresh_token = (
            refreshed.get(
                "refresh_token"
            )
            or refresh_token
        )


        refreshed_expiry = (
            refreshed.get(
                "token_expiry"
            )
        )


        if not refreshed_access_token:

            raise RuntimeError(
                "Google token refresh returned "
                "no access token."
            )


        updated_connection = {

            **google,

            "access_token":
                refreshed_access_token,

            "refresh_token":
                refreshed_refresh_token,

            "token_expiry":
                refreshed_expiry,

            "disconnected":
                False,

        }


        updated_connection.pop(
            "user_id",
            None,
        )

        updated_connection.pop(
            "provider",
            None,
        )


        save_connection(

            user_id=user_id,

            provider="google",

            data=updated_connection,

        )


        print(
            "[Google OAuth] Access token refreshed successfully."
        )


        return refreshed_access_token


    except Exception as exc:

        print(
            "[Google OAuth] Token refresh failed:",
            exc,
        )

        return access_token


# -------------------------------------------------------------------
# BASIC ROUTES
# -------------------------------------------------------------------

@app.get("/")
async def dashboard():

    return FileResponse(
        BASE_DIR / "index.html"
    )


@app.get("/health")
def health():

    return {
        "status": "ok"
    }


# -------------------------------------------------------------------
# EXTENSION INGESTION
# -------------------------------------------------------------------

class ExtensionIngestPayload(BaseModel):

    records: list[
        dict[str, Any]
    ]


@app.post("/ingest/extensions")
def ingest_extensions(
    payload: ExtensionIngestPayload,
):

    print(
        "\n"
        "================================================"
    )

    print(
        "[SERVER DEBUG] EXTENSION INGEST"
    )

    print(
        "================================================"
    )

    print(
        "[SERVER DEBUG] Received extension records:",
        len(payload.records),
    )


    for index, record in enumerate(
        payload.records,
        start=1,
    ):

        print(
            f"\n[SERVER DEBUG] Extension record #{index}"
        )

        print(
            "[SERVER DEBUG] source_type:",
            record.get("source_type"),
        )

        print(
            "[SERVER DEBUG] name:",
            record.get("name"),
        )

        print(
            "[SERVER DEBUG] vendor:",
            record.get("vendor"),
        )

        print(
            "[SERVER DEBUG] vendor_domain:",
            record.get("vendor_domain"),
        )

        print(
            "[SERVER DEBUG] detected_via:",
            record.get("detected_via"),
        )

        print(
            "[SERVER DEBUG] permissions:",
            record.get("permissions"),
        )

        print(
            "[SERVER DEBUG] meta:",
            record.get("meta"),
        )


    previous_count = len(
        _extension_records
    )


    merged_records = (
        merge_extension_records(
            payload.records
        )
    )


    print(
        "\n[SERVER DEBUG] Extension records saved to:",
        LATEST_EXT_RECORDS_FILE,
    )

    print(
        "[SERVER DEBUG] Previous extension count:",
        previous_count,
    )

    print(
        "[SERVER DEBUG] Incoming extension count:",
        len(payload.records),
    )

    print(
        "[SERVER DEBUG] Stored extension count:",
        len(merged_records),
    )

    print(
        "================================================\n"
    )


    return {

        "ok": True,

        "received":
            len(payload.records),

        "total_extensions":
            len(merged_records),

    }


# -------------------------------------------------------------------
# WEB / GOOGLE / MCP BROWSER INGESTION
# -------------------------------------------------------------------

class WebIngestPayload(BaseModel):

    records: list[
        dict[str, Any]
    ]


@app.post("/ingest/web")
def ingest_web(
    payload: WebIngestPayload,
):

    global _web_records

    incoming_records = (
        payload.records
    )


    if not incoming_records:

        return {

            "ok": True,

            "received": 0,

            "total_web_records":
                len(_web_records),

        }


    previous_web_count = (
        len(_web_records)
    )


    # ---------------------------------------------------------------
    # Merge browser observations
    # ---------------------------------------------------------------

    _web_records = (
        _merge_record_lists(
            _web_records,
            incoming_records,
            namespace="web",
        )
    )


    # ---------------------------------------------------------------
    # Persist browser observations
    # ---------------------------------------------------------------

    _save_json(
        LATEST_WEB_RECORDS_FILE,
        _web_records,
    )


    print(
        "[WEB INGEST] Previous:",
        previous_web_count,
    )

    print(
        "[WEB INGEST] Incoming:",
        len(incoming_records),
    )

    print(
        "[WEB INGEST] Total:",
        len(_web_records),
    )


    # ---------------------------------------------------------------
    # Preserve OAuth connected apps in OAuth store
    # ---------------------------------------------------------------

    oauth_records = [

        record

        for record in _web_records

        if str(
            record.get(
                "source_type",
                "",
            )
        ).lower()
        ==
        "oauth_connected_app"

    ]


    if oauth_records:

        merged_oauth = (
            merge_oauth_records(
                oauth_records
            )
        )

    else:

        merged_oauth = (
            load_oauth_records()
        )


    # ---------------------------------------------------------------
    # MCP count
    # ---------------------------------------------------------------

    mcp_count = sum(

        1

        for record in _web_records

        if str(
            record.get(
                "source_type",
                "",
            )
        ).lower()

        in {

            "web_mcp",

            "browser_mcp",

            "mcp_web_activity",

        }

    )


    return {

        "ok": True,

        "received":
            len(incoming_records),

        "total_web_records":
            len(_web_records),

        "web_mcp_records":
            mcp_count,

        "total_oauth_records":
            len(merged_oauth),

    }


# -------------------------------------------------------------------
# GOOGLE MANUAL IMPORT
# -------------------------------------------------------------------

class GoogleManualImportPayload(BaseModel):

    app_names: list[str]


@app.post("/ingest/google-manual")
def ingest_google_manual(
    payload: GoogleManualImportPayload,
):

    from oauth_scanner import (
        import_google_manual_export
    )


    records = (
        import_google_manual_export(
            payload.app_names
        )
    )


    _save_json(
        GOOGLE_MANUAL_FILE,
        records,
    )


    merged_records = (
        merge_oauth_records(
            records
        )
    )


    return {

        "ok": True,

        "received":
            len(records),

        "total_oauth_records":
            len(merged_records),

    }


# -------------------------------------------------------------------
# GOOGLE OAUTH START
# -------------------------------------------------------------------

@app.get("/oauth/google/start")
def google_start(
    request: Request,
):

    user_id = get_user_id(request)


    flow = create_google_flow()


    authorization_url, state = (
        flow.authorization_url(

            access_type="offline",

            include_granted_scopes="true",

            prompt="consent",

        )
    )


    request.session[
        "google_oauth_state"
    ] = state


    request.session[
        "oauth_user_id"
    ] = user_id


    request.session[
        "google_code_verifier"
    ] = getattr(

        flow,

        "code_verifier",

        None,

    )


    print(
        "[Google OAuth] Starting OAuth flow"
    )

    print(
        "[Google OAuth] State saved:",
        bool(state),
    )

    print(
        "[Google OAuth] PKCE verifier saved:",
        bool(
            getattr(
                flow,
                "code_verifier",
                None,
            )
        ),
    )

    print(
        "[Google OAuth] Redirect URI:",
        getattr(
            flow,
            "redirect_uri",
            None,
        ),
    )


    return RedirectResponse(
        authorization_url,
        status_code=302,
    )


# -------------------------------------------------------------------
# GOOGLE OAUTH CALLBACK
# -------------------------------------------------------------------

@app.get("/oauth/google/callback")
def google_callback(
    request: Request,
):

    print(
        "\n"
        "================================================"
    )

    print(
        "[Google OAuth] CALLBACK RECEIVED"
    )

    print(
        "================================================"
    )


    expected_state = (
        request.session.get(
            "google_oauth_state"
        )
    )


    received_state = (
        request.query_params.get(
            "state"
        )
    )


    saved_code_verifier = (
        request.session.get(
            "google_code_verifier"
        )
    )


    print(
        "[Google OAuth] Callback URL:",
        str(request.url),
    )

    print(
        "[Google OAuth] Expected state:",
        bool(expected_state),
    )

    print(
        "[Google OAuth] Received state:",
        bool(received_state),
    )

    print(
        "[Google OAuth] State matches:",
        expected_state == received_state,
    )

    print(
        "[Google OAuth] PKCE verifier available:",
        bool(saved_code_verifier),
    )


    # ---------------------------------------------------------------
    # Google returned an OAuth error
    # ---------------------------------------------------------------

    google_error = (
        request.query_params.get(
            "error"
        )
    )


    if google_error:

        error_description = (
            request.query_params.get(
                "error_description"
            )
        )


        raise HTTPException(

            status_code=400,

            detail=(

                f"Google OAuth error: "
                f"{google_error}"

                +

                (
                    f" - {error_description}"
                    if error_description
                    else ""
                )

            ),

        )


    # ---------------------------------------------------------------
    # Validate state
    # ---------------------------------------------------------------

    if (

        not expected_state

        or not received_state

        or expected_state != received_state

    ):

        raise HTTPException(

            status_code=400,

            detail=(

                "Invalid Google OAuth state. "
                "Use the same host consistently: "
                "127.0.0.1 or localhost."

            ),

        )


    user_id = (
        request.session.get(
            "oauth_user_id",
            DEV_USER_ID,
        )
    )


    try:

        # -----------------------------------------------------------
        # Recreate OAuth flow
        # -----------------------------------------------------------

        flow = create_google_flow(
            state=expected_state
        )


        if saved_code_verifier:

            flow.code_verifier = (
                saved_code_verifier
            )


        # -----------------------------------------------------------
        # Token exchange
        # -----------------------------------------------------------

        print(
            "[Google OAuth] Fetching token..."
        )


        flow.fetch_token(

            authorization_response=
                str(request.url)

        )


        print(
            "[Google OAuth] Token exchange successful."
        )


        credentials = (
            flow.credentials
        )


        access_token = (
            credentials.token
        )


        refresh_token = (
            credentials.refresh_token
        )


        if not access_token:

            raise HTTPException(

                status_code=400,

                detail=(
                    "Google did not return "
                    "an access token."
                ),

            )


        # -----------------------------------------------------------
        # Google identity
        # -----------------------------------------------------------

        identity = (
            google_identity_record(
                access_token
            )
        )


        if not identity:

            raise HTTPException(

                status_code=400,

                detail=(
                    "Unable to identify "
                    "the Google account."
                ),

            )


        google_email = (
            identity
            .get(
                "meta",
                {}
            )
            .get(
                "email"
            )
        )


        print(
            "[Google OAuth] Identity:",
            google_email,
        )


        # -----------------------------------------------------------
        # Save/update Google credentials only
        # -----------------------------------------------------------

        save_connection(

            user_id=user_id,

            provider="google",

            data={

                "google_subject":
                    identity[
                        "meta"
                    ].get(
                        "account_subject"
                    ),

                "email":
                    google_email,

                "access_token":
                    access_token,

                "refresh_token":
                    refresh_token,

                "token_expiry":
                    (
                        credentials.expiry.isoformat()
                        if credentials.expiry
                        else None
                    ),

                "disconnected":
                    False,

            },

        )


        # -----------------------------------------------------------
        # Google scan results
        # -----------------------------------------------------------

        google_records = [
            identity
        ]


        try:

            google_apps = (
                google_workspace_token_scan(
                    access_token
                )
            )


            google_records.extend(
                google_apps
            )


            print(
                "[Google OAuth] Workspace apps discovered:",
                len(google_apps),
            )


        except Exception as exc:

            print(
                "[Google OAuth] Workspace scan failed:",
                repr(exc),
            )


        # -----------------------------------------------------------
        # MERGE — NEVER REPLACE EXISTING OAuth INVENTORY
        # -----------------------------------------------------------

        merged_oauth_records = (
            merge_oauth_records(
                google_records
            )
        )


        print(
            "[Google OAuth] Total OAuth records after merge:",
            len(merged_oauth_records),
        )


        # -----------------------------------------------------------
        # Recover browser-discovered connected apps too
        # -----------------------------------------------------------

        reconcile_persistent_records()


        # -----------------------------------------------------------
        # Clear temporary state
        # -----------------------------------------------------------

        request.session.pop(
            "google_oauth_state",
            None,
        )

        request.session.pop(
            "oauth_user_id",
            None,
        )

        request.session.pop(
            "google_code_verifier",
            None,
        )


        print(
            "[Google OAuth] OAuth flow completed successfully."
        )


        print(
            "================================================\n"
        )


        return RedirectResponse(
            "/?google=connected",
            status_code=302,
        )


    except HTTPException:

        raise


    except Exception as exc:

        import traceback

        print(
            "\n"
            "[Google OAuth] CALLBACK ERROR"
        )

        print(
            "[Google OAuth] Exception:",
            repr(exc),
        )

        traceback.print_exc()

        print(
            "================================================\n"
        )


        raise HTTPException(

            status_code=400,

            detail=(

                "Google OAuth failed: "
                f"{type(exc).__name__}: {exc}"

            ),

        )


# -------------------------------------------------------------------
# OAUTH STATUS
# -------------------------------------------------------------------

@app.get("/oauth/status")
def oauth_status(
    request: Request,
):

    # Recover browser OAuth observations before reporting status.
    reconcile_persistent_records()


    user_id = get_user_id(
        request
    )


    google = get_connection(

        user_id=user_id,

        provider="google",

    )


    connected = bool(

        google

        and google.get(
            "access_token"
        )

        and not google.get(
            "disconnected",
            False,
        )

    )


    records = (
        load_oauth_records()
    )


    oauth_app_count = sum(

        1

        for record in records

        if str(
            record.get(
                "source_type",
                "",
            )
        ).lower()

        == "oauth_connected_app"

    )


    return {

        "google": {

            "connected":
                connected,

            "email":

                (
                    google or {}
                ).get(
                    "email"
                )
                if connected
                else None,

            "connected_app_count":
                oauth_app_count,

            "total_oauth_records":
                len(records),

        },

    }


# -------------------------------------------------------------------
# GOOGLE DISCONNECT
# -------------------------------------------------------------------

@app.post("/oauth/google/disconnect")
def google_disconnect(
    request: Request,
):

    user_id = get_user_id(
        request
    )


    google = get_connection(

        user_id=user_id,

        provider="google",

    )


    if not google:

        return {

            "ok": True,

            "connected": False,

            "preserved_records":
                len(
                    load_oauth_records()
                ),

        }


    # ---------------------------------------------------------------
    # IMPORTANT:
    #
    # Do NOT delete OAuth inventory here.
    #
    # Disconnect removes Sentinel's usable Google credentials,
    # but previously observed third-party-app records remain
    # available as security evidence/history.
    # ---------------------------------------------------------------

    save_connection(

        user_id=user_id,

        provider="google",

        data={

            "email":
                google.get(
                    "email"
                ),

            "google_subject":
                google.get(
                    "google_subject"
                ),

            "access_token":
                None,

            "refresh_token":
                None,

            "token_expiry":
                None,

            "disconnected":
                True,

        },

    )


    request.session.pop(
        "google_oauth_state",
        None,
    )

    request.session.pop(
        "oauth_user_id",
        None,
    )

    request.session.pop(
        "google_code_verifier",
        None,
    )


    preserved_records =load_oauth_records()


    return {

        "ok": True,

        "connected": False,

        "preserved_records":
            len(
                preserved_records
            ),

    }


# -------------------------------------------------------------------
# SCAN GOOGLE AUTH SOURCE
# -------------------------------------------------------------------

@app.post("/oauth/scan")
def scan_oauth_sources(
    request: Request,
):

    # Always restore browser-observed OAuth apps first.
    reconcile_persistent_records()


    user_id = get_user_id(
        request
    )


    records: list[
        dict[str, Any]
    ] = []


    # ---------------------------------------------------------------
    # Google
    # ---------------------------------------------------------------

    google = get_connection(

        user_id=user_id,

        provider="google",

    )


    if google:

        access_token = (
            get_valid_google_access_token(
                user_id=user_id,
            )
        )


        if access_token:

            # -------------------------------------------------------
            # Google identity
            # -------------------------------------------------------

            try:

                identity = (
                    google_identity_record(
                        access_token
                    )
                )


                if identity:

                    records.append(
                        identity
                    )


            except Exception as exc:

                print(
                    "[OAuth scan] Google identity error:",
                    repr(exc),
                )


            # -------------------------------------------------------
            # Google Workspace
            # -------------------------------------------------------

            try:

                google_apps = (
                    google_workspace_token_scan(
                        access_token
                    )
                )


                records.extend(
                    google_apps
                )


                print(
                    "[OAuth scan] Workspace apps discovered:",
                    len(google_apps),
                )


            except Exception as exc:

                print(
                    "[OAuth scan] Workspace scan error:",
                    repr(exc),
                )


    # ---------------------------------------------------------------
    # Manual Google records
    # ---------------------------------------------------------------

    manual_google = (
        _load_google_manual()
    )


    if isinstance(
        manual_google,
        list,
    ):

        records.extend(
            [
                record
                for record in manual_google
                if isinstance(
                    record,
                    dict,
                )
            ]
        )


    # ---------------------------------------------------------------
    # MERGE — NEVER REPLACE
    # ---------------------------------------------------------------

    merged_oauth_records = (
        merge_oauth_records(
            records
        )
    )


    # ---------------------------------------------------------------
    # Recover browser observations one more time
    # ---------------------------------------------------------------

    reconcile_persistent_records()


    final_records = (
        load_oauth_records()
    )


    return {

        "ok": True,

        "records_found":
            len(records),

        "total_records":
            len(final_records),

        "records":
            records,

        "all_records":
            final_records,

    }


# -------------------------------------------------------------------
# BUILD /TOOLS
# -------------------------------------------------------------------

@app.get("/tools")
@app.get("/connected/tools")
def get_tools():

    # ---------------------------------------------------------------
    # IMPORTANT:
    #
    # Before building the normalized tool list, restore any OAuth
    # applications that were discovered by the browser/web sensor.
    # This prevents an OAuth scan from making browser observations
    # disappear.
    # ---------------------------------------------------------------

    reconcile_persistent_records()


    # ---------------------------------------------------------------
    # MCP
    # ---------------------------------------------------------------

    mcp_state = (
        _load_mcp_state()
    )


    mcp_records = (
        scan_mcp_configs(
            state_store=mcp_state
        )
    )


    _save_mcp_state(
        build_state_snapshot(
            mcp_records
        )
    )


    # ---------------------------------------------------------------
    # DNS
    # ---------------------------------------------------------------

    dns_result = (
        scan_dns_activity()
    )


    _save_json(
        LATEST_DNS_FILE,
        dns_result,
    )


    # ---------------------------------------------------------------
    # Google manual
    # ---------------------------------------------------------------

    google_manual = (
        _load_google_manual()
    )


    # ---------------------------------------------------------------
    # OAuth records
    # ---------------------------------------------------------------

    oauth_records = (
        load_oauth_records()
    )


    # ---------------------------------------------------------------
    # Build normalized payload
    # ---------------------------------------------------------------

    tools = build_tool_payload(

        extension_records=
            _extension_records,

        mcp_records=
            mcp_records,

        web_records=
            _web_records,

        oauth_records=
            oauth_records,

        dns_result=
            dns_result,

    )


    # ---------------------------------------------------------------
    # Persist latest normalized output
    # ---------------------------------------------------------------

    _save_json(
        LATEST_TOOLS_FILE,
        tools,
    )


    print(
        "[TOOLS] Extensions:",
        len(_extension_records),
    )

    print(
        "[TOOLS] MCP:",
        len(mcp_records),
    )

    print(
        "[TOOLS] Web:",
        len(_web_records),
    )

    print(
        "[TOOLS] OAuth:",
        len(oauth_records),
    )

    print(
        "[TOOLS] Final normalized tools:",
        len(tools),
    )


    return tools


# -------------------------------------------------------------------
# RUN LANGGRAPH AUDIT
# -------------------------------------------------------------------

@app.post("/audit/run")
def run_audit():

    tools = get_tools()


    if not tools:

        return {

            "ok": True,

            "message": (
                "No security records were "
                "found to audit."
            ),

            "audited": 0,

            "results": [],

        }


    graph_app = build_graph()


    results: list[
        dict[str, Any]
    ] = []


    for tool in tools:

        try:

            graph_result = (
                graph_app.invoke(
                    {
                        "tool_record":
                            tool
                    }
                )
            )


            results.append(

                {

                    "tool_id":
                        tool.get(
                            "tool_id"
                        ),

                    "name":
                        tool.get(
                            "name"
                        ),

                    "tool":
                        tool,

                    "audit":
                        graph_result,

                    "status":
                        "completed",

                }

            )


        except Exception as exc:

            print(
                "[AUDIT] Failed for "
                f"{tool.get('name')}: {exc}"
            )


            results.append(

                {

                    "tool_id":
                        tool.get(
                            "tool_id"
                        ),

                    "name":
                        tool.get(
                            "name"
                        ),

                    "tool":
                        tool,

                    "audit":
                        None,

                    "status":
                        "failed",

                    "error":
                        str(exc),

                }

            )


    save_audit_results(
        results
    )


    return {

        "ok": True,

        "audited":
            len(results),

        "results":
            results,

    }


# -------------------------------------------------------------------
# GET LAST AUDIT
# -------------------------------------------------------------------

@app.get("/audit/results")
def get_audit_results():

    return {

        "ok": True,

        "results":
            load_audit_results(),

    }


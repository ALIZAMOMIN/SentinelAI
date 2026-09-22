from __future__ import annotations


from fastapi.responses import HTMLResponse 
from fastapi.staticfiles import StaticFiles 
from fastapi.templating import Jinja2Templates

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from dns_scanner import scan_dns_activity
from mcp_scanner import build_state_snapshot, scan_mcp_configs
from normalizer import build_tool_payload
from oauth_scanner import import_google_manual_export

from fastapi.responses import FileResponse
BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="SentinelAI Local Sensing Agent"
)

app.mount("/static", StaticFiles(directory="static"), name="static") 
templates = Jinja2Templates(directory="templates")

# ------------------------------------------------------------
# CORS
# ------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------------------------------
# STATE
# ------------------------------------------------------------

STATE_DIR = (
    Path(__file__).parent / ".state"
)

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


# ------------------------------------------------------------
# EXTENSION RECORD CACHE
# ------------------------------------------------------------

_extension_records: list[
    dict[str, Any]
] = []


if LATEST_EXT_RECORDS_FILE.exists():

    try:

        _extension_records = json.loads(
            LATEST_EXT_RECORDS_FILE.read_text()
        )

    except Exception:

        _extension_records = []


# ------------------------------------------------------------
# STATE HELPERS
# ------------------------------------------------------------

def _load_mcp_state() -> dict:

    if not MCP_STATE_FILE.exists():
        return {}

    try:

        return json.loads(
            MCP_STATE_FILE.read_text()
        )

    except Exception:

        return {}


def _save_mcp_state(
    state: dict
) -> None:

    MCP_STATE_FILE.write_text(
        json.dumps(
            state,
            indent=2
        )
    )


def _load_google_manual() -> list[
    dict[str, Any]
]:

    if not GOOGLE_MANUAL_FILE.exists():
        return []

    try:

        return json.loads(
            GOOGLE_MANUAL_FILE.read_text()
        )

    except Exception:

        return []


# ------------------------------------------------------------
# REQUEST MODELS
# ------------------------------------------------------------

class ExtensionIngestPayload(
    BaseModel
):

    records: list[
        dict[str, Any]
    ]


class GoogleManualImportPayload(
    BaseModel
):

    app_names: list[str]


# ------------------------------------------------------------
# ROOT
# ------------------------------------------------------------
'''
@app.get("/")
def root():

    return {
        "name":
            "SentinelAI Local Sensing Agent",

        "status":
            "ok",

        "endpoints": {

            "health":
                "/health",

            "tools":
                "/tools",

            "docs":
                "/docs",

            "extension_ingest":
                "/ingest/extensions",

            "google_manual":
                "/ingest/google-manual"
        }
    }
'''

@app.get("/")
async def dashboard():
    return FileResponse(BASE_DIR / "index.html")


@app.get("/health")
def health():

    return {
        "status": "ok"
    }


# ------------------------------------------------------------
# EXTENSION INGEST
# ------------------------------------------------------------

@app.post(
    "/ingest/extensions"
)
def ingest_extensions(
    payload: ExtensionIngestPayload
):

    global _extension_records

    _extension_records = (
        payload.records
    )

    LATEST_EXT_RECORDS_FILE.write_text(
        json.dumps(
            _extension_records,
            indent=2
        )
    )

    return {

        "ok": True,

        "received":
            len(_extension_records)
    }


# ------------------------------------------------------------
# GOOGLE MANUAL IMPORT
# ------------------------------------------------------------

@app.post(
    "/ingest/google-manual"
)
def ingest_google_manual(
    payload:
        GoogleManualImportPayload
):

    records = (
        import_google_manual_export(
            payload.app_names
        )
    )

    GOOGLE_MANUAL_FILE.write_text(
        json.dumps(
            records,
            indent=2
        )
    )

    return {

        "ok": True,

        "received":
            len(records)
    }


# ------------------------------------------------------------
# TOOLS
# ------------------------------------------------------------

@app.get("/tools")
def get_tools():

    # MCP
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


    # DNS
    dns_result = (
        scan_dns_activity()
    )


    # OAuth/manual imports
    google_manual = (
        _load_google_manual()
    )


    # Merge everything through
    # the sensing normalizer.
    tools = build_tool_payload(

        extension_records=
            _extension_records,

        mcp_records=
            mcp_records,

        oauth_records=
            google_manual,

        dns_result=
            dns_result
    )


    return tools
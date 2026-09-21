"""
SentinelAI — Local Sensing Agent

Small FastAPI service that:
  1. Receives extension scan batches from the Chrome extension (POST /ingest/extensions)
  2. Runs the MCP config scanner + DNS scanner locally
  3. Merges everything through normalizer.py
  4. Exposes GET /tools -> the final JSON array your LangGraph agent's
     "Perceive" node consumes directly.

Run:
    pip install -r requirements.txt
    uvicorn server:app --port 8787

Then point the LangGraph agent's Perceive node at:
    GET http://127.0.0.1:8787/tools
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from dns_scanner import scan_dns_activity
from mcp_scanner import build_state_snapshot, scan_mcp_configs
from normalizer import build_tool_payload
from oauth_scanner import import_google_manual_export

app = FastAPI(title="SentinelAI Local Sensing Agent")

STATE_DIR = Path(__file__).parent / ".state"
STATE_DIR.mkdir(exist_ok=True)
MCP_STATE_FILE = STATE_DIR / "mcp_state.json"
LATEST_EXT_RECORDS_FILE = STATE_DIR / "latest_extension_records.json"

# In-memory caches, persisted to disk so state survives restarts
_extension_records: list[dict[str, Any]] = []
if LATEST_EXT_RECORDS_FILE.exists():
    _extension_records = json.loads(LATEST_EXT_RECORDS_FILE.read_text())


def _load_mcp_state() -> dict:
    if MCP_STATE_FILE.exists():
        return json.loads(MCP_STATE_FILE.read_text())
    return {}


def _save_mcp_state(state: dict) -> None:
    MCP_STATE_FILE.write_text(json.dumps(state, indent=2))


class ExtensionIngestPayload(BaseModel):
    records: list[dict[str, Any]]


class GoogleManualImportPayload(BaseModel):
    app_names: list[str]


@app.post("/ingest/extensions")
def ingest_extensions(payload: ExtensionIngestPayload):
    """Called by extension-scanner/background.js on every scan cycle."""
    global _extension_records
    _extension_records = payload.records
    LATEST_EXT_RECORDS_FILE.write_text(json.dumps(_extension_records, indent=2))
    return {"ok": True, "received": len(payload.records)}


@app.post("/ingest/google-manual")
def ingest_google_manual(payload: GoogleManualImportPayload):
    """Optional: accept a pasted list of Google-connected app names."""
    records = import_google_manual_export(payload.app_names)
    path = STATE_DIR / "google_manual.json"
    path.write_text(json.dumps(records, indent=2))
    return {"ok": True, "received": len(records)}


def _load_google_manual() -> list[dict[str, Any]]:
    path = STATE_DIR / "google_manual.json"
    if path.exists():
        return json.loads(path.read_text())
    return []


@app.get("/tools")
def get_tools():
    """The one endpoint your LangGraph agent's Perceive node calls."""
    mcp_state = _load_mcp_state()
    mcp_records = scan_mcp_configs(state_store=mcp_state)
    _save_mcp_state(build_state_snapshot(mcp_records))

    dns_result = scan_dns_activity()
    google_manual = _load_google_manual()

    tools = build_tool_payload(
        extension_records=_extension_records,
        mcp_records=mcp_records,
        oauth_records=google_manual,  # extend with microsoft_graph_scan(token) results too
        dns_result=dns_result,
    )
    return tools


@app.get("/health")
def health():
    return {"status": "ok"}

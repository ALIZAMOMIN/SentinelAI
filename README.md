# SentinelAI — Personal AI Attack Surface Auditor

SentinelAI is a local security-sensing and AI auditing application designed to identify and investigate connected AI tools, browser extensions, MCP connectors, OAuth-connected applications, and network/DNS evidence.

The project combines local sensing, persistent evidence storage, normalization, LangGraph-based investigation, Hugging Face LLM inference, and a browser dashboard.

---

## Features

### Dashboard

The dashboard provides:

* Local agent status
* Connected tool count
* Last scan information
* Google account connection state
* SentinelAI audit controls

### Browser Extensions

SentinelAI can detect and ingest browser extensions including:

* Extension name
* Extension ID
* Vendor
* Vendor domain
* Permissions
* Detection source
* Permission changes / drift
* Additional extension metadata

Extension observations are persisted locally.

### MCP Connectors

SentinelAI scans supported local MCP configuration locations and identifies configured MCP connectors/servers.

MCP state is persisted between scans so that a new scan does not unnecessarily erase previous state.

### OAuth / Google

Google OAuth supports:

* Google account identity
* Google access tokens
* Google refresh tokens
* Token refresh
* Google Workspace application scanning
* Browser-discovered Google connected applications
* Manual Google application import
* Connection status
* Local disconnect

Previously discovered third-party applications are preserved when Google is reconnected.

### DNS Activity

SentinelAI can collect DNS/network evidence and correlate observed domains against known tools.

Raw DNS results are persisted independently of the normalized tool data.

### AI Security Audit

The SentinelAI audit:

1. Refreshes the current sensing inventory.
2. Scans MCP configuration.
3. Scans DNS activity.
4. Loads persistent extension data.
5. Loads persistent OAuth data.
6. Loads browser/web observations.
7. Normalizes all sources into a common tool format.
8. Runs the LangGraph investigation pipeline.
9. Produces structured risk results.
10. Saves the audit results.
11. Updates the frontend.

---

# Architecture

```text
                     ┌─────────────────────┐
                     │     Browser UI      │
                     │                     │
                     │     index.html      │
                     │     script.js       │
                     │     setup.js        │
                     └──────────┬──────────┘
                                │
                                │ HTTP
                                ▼
                     ┌─────────────────────┐
                     │      FastAPI        │
                     │      server.py      │
                     └──────────┬──────────┘
                                │
             ┌──────────────────┼──────────────────┐
             │                  │                  │
             ▼                  ▼                  ▼
      Extension Scanner   MCP Scanner       DNS Scanner
             │                  │                  │
             └──────────────────┼──────────────────┘
                                │
                     ┌──────────▼──────────┐
                     │    Web / OAuth     │
                     │     Evidence       │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │     Normalizer      │
                     │  build_tool_payload │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │  Combined Tool List │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │      LangGraph      │
                     │    Investigation    │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │ Hugging Face LLM    │
                     │ gpt-oss-120b        │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │ Structured Audit    │
                     │ Result              │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │ SentinelAI Dashboard │
                     └─────────────────────┘
```

---

---

# Requirements

Recommended:

* Python 3.10+
* FastAPI
* Uvicorn
* Pydantic
* python-dotenv
* google-auth
* google-auth-oauthlib
* huggingface_hub
* LangGraph
* LangChain packages used by the project
* `ddgs` if DuckDuckGo search is used

Install from your dependency file when available:

```bash
pip install -r requirements.txt
```

For Hugging Face:

```bash
pip install -U huggingface_hub
```

If your project uses LangChain's OpenAI-compatible client:

```bash
pip install -U langchain-openai
```

---

# Environment Configuration

Create a `.env` file in the project root.

Example:

```env
HF_TOKEN_=hf_your_huggingface_token
SESSION_SECRET=replace_with_a_long_random_secret
```

The project currently uses `HF_TOKEN_` intentionally.

Do not rename it unless you also change the code.

---

# Hugging Face Configuration

The project uses Hugging Face Inference Providers for AI auditing.

The current model is:

```python
DEFAULT_MODEL = "openai/gpt-oss-120b:fastest"
```

The cost-optimized alternative is:

```python
DEFAULT_MODEL = "openai/gpt-oss-120b:cheapest"
```

The Hugging Face `InferenceClient` should be configured like:

```python
from huggingface_hub import InferenceClient

client = InferenceClient(
    model="openai/gpt-oss-120b:fastest",
    provider="auto",
    token=os.environ["HF_TOKEN_"],
)
```

Do not pass both `model` and `base_url` to the current `InferenceClient`.

---

# Google OAuth Configuration

Google OAuth is handled through:

```text
google_oauth.py
oauth_scanner.py
oauth_store.py
server.py
```

The local callback should exactly match the redirect URI configured in Google Cloud.

Example:

```text
http://127.0.0.1:8787/oauth/google/callback
```

Use the same host throughout the OAuth flow.

Do not start the application at:

```text
http://localhost:8787
```

and expect the callback to use:

```text
http://127.0.0.1:8787
```

Use one consistently.

---

# Starting SentinelAI

Start the FastAPI application:

```bash
uvicorn server:app --host 127.0.0.1 --port 8787 --reload
```

Open:

```text
http://127.0.0.1:8787
```

---

# Main API Endpoints

## Health

```http
GET /health
```

Example:

```json
{
  "status": "ok"
}
```

---

## Tool Inventory

```http
GET /tools
```

Also available at:

```http
GET /connected/tools
```

This endpoint rebuilds the normalized security inventory.

It includes data from:

* Extensions
* MCP
* Browser/web observations
* OAuth
* DNS activity

---

## Extension Ingestion

```http
POST /ingest/extensions
```

Example payload:

```json
{
  "records": [
    {
      "tool_id": "example-extension",
      "name": "Example Extension",
      "source_type": "extension"
    }
  ]
}
```

Extension records are merged into the persistent extension inventory.

---

## Web / Browser Ingestion

```http
POST /ingest/web
```

Example:

```json
{
  "records": [
    {
      "source_type": "oauth_connected_app",
      "name": "Notion"
    }
  ]
}
```

Supported browser/web observations are persisted and merged.

OAuth connected applications discovered through browser sensing are also preserved in the OAuth store.

---

## Manual Google Import

```http
POST /ingest/google-manual
```

Example:

```json
{
  "app_names": [
    "Notion",
    "Slack",
    "Canva"
  ]
}
```

---

## Google OAuth Start

```http
GET /oauth/google/start
```

Starts the Google OAuth authorization flow.

The server stores:

* OAuth state
* OAuth user ID
* PKCE verifier

in the development session.

---

## Google OAuth Callback

```http
GET /oauth/google/callback
```

Handles:

1. State validation
2. PKCE restoration
3. Authorization code exchange
4. Google account identification
5. Credential persistence
6. Google Workspace scanning
7. OAuth record merging
8. Redirect back to the dashboard

After success:

```text
/?google=connected
```

---

## Google OAuth Status

```http
GET /oauth/status
```

Example:

```json
{
  "google": {
    "connected": true,
    "email": "example@gmail.com",
    "connected_app_count": 3,
    "total_oauth_records": 4
  }
}
```

The frontend uses this endpoint to decide whether to show:

```text
Connect Google
```

or:

```text
Connected as example@gmail.com
Disconnect Google
```

---

## Google Disconnect

```http
POST /oauth/google/disconnect
```

Disconnect removes the locally usable Google credentials.

It does not intentionally delete historical third-party OAuth observations.

That means:

```text
Google connected
    ↓
Notion
Slack
Canva
    ↓
Disconnect Google
    ↓
Google credentials removed
    ↓
Notion / Slack / Canva records remain
```

---

## OAuth Scan

```http
POST /oauth/scan
```

Scans Google-supported sources when a Google connection is available.

The new results are merged with the existing OAuth inventory.

---

## Run SentinelAI Audit

```http
POST /audit/run
```

This is the primary AI audit endpoint.

---

## Get Last Audit

```http
GET /audit/results
```

Returns previously saved audit results.

---

# What Happens During an Audit

When the user clicks:

```text
Run SentinelAI Audit
```

the flow is:

```text
Click button
     ↓
POST /audit/run
     ↓
get_tools()
     ↓
Recover persistent OAuth/browser observations
     ↓
Scan MCP
     ↓
Scan DNS
     ↓
Load extensions
     ↓
Load OAuth
     ↓
Load web records
     ↓
Normalize everything
     ↓
Build LangGraph
     ↓
Audit every tool
     ↓
Save results
     ↓
Return results
     ↓
Frontend renders results
```

---

# Audit Result Structure

A typical structured model result can look like:

```json
{
  "verdict_line": "QuickReply AI poses moderate risk.",
  "risk_score": 6,
  "risk_level": "medium",
  "recommendation": {
    "action": "monitor",
    "instructions": "Continue monitoring and address any emerging issues promptly."
  }
}
```

The model can return multiple fields because it is still one JSON object.

The important requirement is:

```text
one model call → one JSON object
```

not:

```text
one model call → one field
```

---

# Investigation Trace

The audit may produce trace stages such as:

```text
PERCEIVE
PLAN
ACT
REASON
```

Example:

```text
[PERCEIVE]
Permissions snapshot:
clipboardRead, storage, host:<all_urls>

Permission drift detected.

[PLAN]
Scope exceeds the stated function.
Checking vendor standing next.

[ACT]
Searched vendor security/privacy information.

[REASON]
No relevant public information found.
```

The frontend converts these stages into the Investigation section.

---

# Score Breakdown

An audit can return individual risk factors such as:

```text
Scope severity: 3.0
Permission drift: 3.0
Vendor trust signals: 0.0
Data sensitivity nearby: 0.0
```

The frontend renders these as the Score Breakdown section.

Example:

```text
TOTAL: 6.0 / 10
Risk level: medium
```

---

# Recommendation

Recommendations can include:

```text
MONITOR
```

```text
RESTRICT
```

```text
REVOKE
```

The exact recommendation is produced by the audit graph.

The frontend displays the recommendation and its instructions.

---

# Persistent State

SentinelAI stores local state under:

```text
.state/
```

Important files:

| File                            | Purpose                     |
| ------------------------------- | --------------------------- |
| `mcp_state.json`                | MCP state snapshots         |
| `latest_extension_records.json` | Extension observations      |
| `latest_web_records.json`       | Browser/web observations    |
| `latest_oauth_records.json`     | OAuth inventory             |
| `google_manual.json`            | Manual Google imports       |
| `latest_tools.json`             | Latest normalized inventory |
| `latest_dns_records.json`       | Raw DNS results             |
| `latest_audit_results.json`     | Latest audit results        |

---

# Data Preservation

The application is designed around **merge rather than replace** semantics.

This prevents a new scan from unintentionally deleting information found by another scanner.

For example:

```text
Extension scanner
      ↓
8 extensions
```

followed later by:

```text
Google OAuth scan
      ↓
1 Google account
```

should result in:

```text
8 extensions
+
Google account
```

rather than:

```text
Google account only
```

Likewise:

```text
Browser discovery
      ↓
Notion
Slack
Canva
```

followed by:

```text
Google OAuth reconnect
```

should preserve:

```text
Notion
Slack
Canva
Google account
```

---

# Record Merging

The backend uses stable record identities where possible.

Priority is generally:

1. `tool_id`
2. Explicit source-specific IDs
3. Stable identity fields
4. Deterministic hash fallback

Timestamps are not used as the primary record identity so that repeated scans update existing records rather than creating unnecessary duplicates.

---

# Extension Data Preservation

Extension ingestion uses merging rather than blindly replacing:

```python
merge_extension_records(...)
```

An empty extension result should not automatically erase previously stored extension observations.

---

# OAuth Data Preservation

OAuth ingestion uses:

```python
merge_oauth_records(...)
```

instead of replacing the entire OAuth inventory with only the latest scan.

Browser-discovered OAuth applications can also be reconciled from:

```text
.state/latest_web_records.json
```

into:

```text
.state/latest_oauth_records.json
```

This helps protect against accidental loss caused by older versions of the backend.

---

# Frontend Views

The main dashboard contains:

```text
Dashboard
Tools
Extensions
MCP Connectors
OAuth / Google
DNS Activity
Settings
```

The Tools view contains the complete normalized inventory.

The other views filter the same normalized tool array.

For example:

```text
TOOLS
 ├── Extensions
 ├── MCP
 ├── OAuth
 └── DNS evidence
```

Clicking an item in a category can open the full investigation in Tools.

---

# Security Considerations

This project is currently designed for local development.

## OAuth Credentials

OAuth access and refresh tokens are sensitive.

Never commit them to Git.

Do not commit:

```text
.env
.state/
Google client secrets
```

---

## Session Secret

Set a stable secret for production:

```env
SESSION_SECRET=...
```

The development fallback generates a temporary secret when one is not provided.

---

## OAuth Insecure Transport

Local development currently uses:

```python
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
```

This should not be used in a production deployment over the public internet.

---

## CORS

The development configuration currently allows broad CORS.

For production, restrict allowed origins.

---

## Local State

The `.state/` directory may contain security-sensitive observations.

Protect it and do not publish it.

---

# Troubleshooting

## `Cannot select auto-router when using non-Hugging Face API key`

Check the Hugging Face token:

```env
HF_TOKEN_=hf_...
```

and the client:

```python
InferenceClient(
    model=DEFAULT_MODEL,
    provider="auto",
    token=os.environ["HF_TOKEN_"],
)
```

Do not use an OpenAI, Anthropic, Groq, or other provider key as the Hugging Face token.

---

## `Received both model and base_url arguments`

Do not configure:

```python
InferenceClient(
    model=DEFAULT_MODEL,
    base_url="https://router.huggingface.co/v1",
)
```

Use:

```python
InferenceClient(
    model=DEFAULT_MODEL,
    provider="auto",
    token=os.environ["HF_TOKEN_"],
)
```

---

## `429 Too Many Requests`

Example:

```text
429 Too Many Requests
engine_overloaded
Model busy, retry later
```

This generally means the selected inference provider is overloaded or temporarily unavailable.

Possible mitigations:

* Use `:fastest` instead of `:cheapest`
* Add retry/backoff
* Reduce request bursts
* Use an explicit provider if appropriate
* Check provider availability

Recommended default for multi-tool audits:

```python
DEFAULT_MODEL = "openai/gpt-oss-120b:fastest"
```

---

## `'NoneType' object has no attribute 'lower'`

Some audit code is calling:

```python
value.lower()
```

when the value is missing.

Use:

```python
str(value or "").lower()
```

for optional fields.

Common examples:

```text
vendor
name
source_type
description
stated_function
```

---

## Ollama Socket Warnings

If you see:

```text
127.0.0.1:11434
```

something in the project is still connecting to Ollama.

Search for:

```text
ChatOllama
11434
OLLAMA
```

If Hugging Face is intended to be the only LLM backend, remove or replace the remaining Ollama client.

---

## DuckDuckGo Package Warning

If you see:

```text
duckduckgo_search has been renamed to ddgs
```

update the package:

```bash
pip uninstall duckduckgo_search
pip install -U ddgs
```

Then update the relevant Python import.

---

## Google OAuth Fails After Consent

Check:

1. The redirect URI matches Google Cloud configuration.
2. The same host is used throughout the flow.
3. OAuth state is preserved.
4. PKCE verifier is preserved.
5. The session cookie is available.
6. `SESSION_SECRET` is stable.

Use one of:

```text
http://127.0.0.1:8787
```

or:

```text
http://localhost:8787
```

consistently.

---

## Scope Changed During Google OAuth

If OAuthLib reports that the granted scopes differ from the originally requested scopes, the development configuration includes:

```python
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"
```

This should be configured before the OAuth flow is created.

---

## Google Connected but UI Says "Connect Google"

The frontend should query:

```http
GET /oauth/status
```

and use the returned:

```json
{
  "google": {
    "connected": true
  }
}
```

to display the connected state.

---

# Recommended `.gitignore`

```gitignore
.env
.env.*
!.env.example

.state/

__pycache__/
*.py[cod]

.venv/
venv/
env/

.vscode/
.idea/

*.log
```

---

# Development Workflow

Start the server:

```bash
uvicorn server:app --host 127.0.0.1 --port 8787 --reload
```

Open:

```text
http://127.0.0.1:8787
```

Recommended workflow:

```text
1. Verify Local Agent
2. Check Extensions
3. Check MCP
4. Connect Google
5. Check OAuth / Google
6. Check DNS
7. Run SentinelAI Audit
8. Review Investigation
9. Review Score Breakdown
10. Review Assessment
11. Review Recommendation
```

---

# Audit Data Lifecycle

The intended data lifecycle is:

```text
Scanner
   ↓
Observation
   ↓
Persistent storage
   ↓
Merge
   ↓
Normalization
   ↓
LangGraph
   ↓
Structured AI result
   ↓
Audit persistence
   ↓
Frontend
```

The goal is that different data sources do not erase each other.

For example:

```text
Extension scan
    ↓
updates extension evidence
    ↓
does not erase OAuth
```

```text
Google scan
    ↓
updates Google/OAuth evidence
    ↓
does not erase extensions
```

```text
MCP scan
    ↓
updates MCP evidence
    ↓
does not erase OAuth
```

```text
DNS scan
    ↓
updates DNS evidence
    ↓
does not erase other sources
```

---

# Current Limitations

The current implementation is primarily local-development oriented.

Known limitations include:

* OAuth credential storage is development-oriented.
* A single development user ID is currently used.
* Scanner coverage depends on local OS/browser configuration.
* DNS evidence depends on local system visibility.
* Google Workspace scanning depends on available account permissions/API access.
* Hugging Face provider availability can affect audit execution.
* Audit scoring depends on the configured LangGraph implementation.
* Live investigation streaming is not currently part of the basic `/audit/run` response.
* Production authentication and authorization are not fully implemented.

---

# Future Improvements

Potential improvements include:

* Persistent database storage
* Per-user authentication
* Encrypted OAuth credential storage
* Live audit progress streaming
* Background audit jobs
* Provider failover
* Rate-limit aware scheduling
* Audit history and comparison
* Historical risk trend charts
* Expanded MCP client support
* More browser integrations
* Production HTTPS
* Restricted CORS
* Role-based access control
* Stronger secrets management

---

# Project Status

SentinelAI is a local security-sensing and AI auditing application.

The core pipeline is:


Local Sensors
      ↓
FastAPI
      ↓
Persistent Evidence
      ↓
Normalizer
      ↓
LangGraph
      ↓
Hugging Face LLM
      ↓
Structured Audit
      ↓
SentinelAI Dashboard


The application is intended to provide a unified view of the AI-related attack surface observed on a local system while preserving evidence across different sensing sources.

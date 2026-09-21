# SentinelAI — Sensing Layer

Implements the four sensing mechanisms and normalizes them into the `Tool`
JSON schema your LangGraph agent's **Perceive** node consumes.

## Architecture

```
Chrome extension (background.js)
  └─ chrome.management.getAll()  ──POST──▶  local agent :8787/ingest/extensions
                                                   │
Local agent (Python, FastAPI)                     │
  ├─ mcp_scanner.py   → reads claude_desktop_config.json (mcpServers block)
  ├─ dns_scanner.py   → Windows ipconfig /displaydns (macOS/Linux: roadmap stub)
  ├─ oauth_scanner.py → Microsoft Graph live scan + Google manual-import fallback
  ├─ prechecks.py     → VirusTotal / HIBP / WHOIS enrichment (all optional, env-gated)
  └─ normalizer.py    → merges everything by vendor domain, outputs final Tool[] JSON
                                                   │
                          GET :8787/tools  ────────┘
                                                   │
                                          LangGraph agent's Perceive node
```

Why split this way: `chrome.management` only works from inside your own
extension, and reading `~/Library/Application Support/Claude/...` or running
`ipconfig` needs real filesystem/process access a browser extension doesn't
have. So the extension does exactly the one thing it's uniquely positioned to
do (permission scanning) and ships results to a local agent that owns
everything requiring OS-level access, plus the merge/normalize step.

## Build priority (matches what's solid vs. roadmap)

| Mechanism | Status | File |
|---|---|---|
| Browser extension permission scan | ✅ Fully working | `extension-scanner/background.js` |
| MCP connector scan | ✅ Fully working | `local-agent/mcp_scanner.py` |
| DNS check (Windows) | ✅ Working; macOS/Linux stubbed as roadmap | `local-agent/dns_scanner.py` |
| OAuth connected apps | ⚠️ MS Graph live, Google manual-import fallback | `local-agent/oauth_scanner.py` |

## Running it

```bash
cd local-agent
pip install -r requirements.txt
uvicorn server:app --port 8787
```

Load the extension unpacked (`extension-scanner/`) with `"management"` and
`host_permissions: ["http://127.0.0.1:8787/*"]` in your manifest — it'll POST
scan batches to the agent every 15 minutes and on install/startup.

Then your LangGraph agent's Perceive node just does:

```python
import requests
tools = requests.get("http://127.0.0.1:8787/tools").json()  # List[Tool]
```

That's the exact array-of-objects shape from your spec — `tool_id`, `vendor`,
`detected_via`, `permissions.drift_detected`, `network_behavior`,
`prechecks`, all merged across whichever sensing sources actually saw that
tool.

## Optional enrichment keys

Set these to turn on the corresponding `prechecks` fields; without them the
fields come back as `null`/`false` rather than failing the scan:

```bash
export VIRUSTOTAL_API_KEY=...
export HIBP_API_KEY=...
pip install python-whois   # enables whois_domain_age_days
```

## Notes for the demo pitch

- Say explicitly that macOS/Linux DNS visibility and the full Google
  OAuth-apps read are "production roadmap — requires an elevated local
  agent," same as real enterprise DLP/CASB tools. That's honest and it's
  still credible in front of judges.
- `merge_records()` in `normalizer.py` is the piece worth walking through
  live if asked "how do four different signals become one tool" — it's the
  core of why this is an agent-ready sensing layer and not just four
  disconnected scripts.

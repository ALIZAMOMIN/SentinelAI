// SentinelAI — Browser Extension Sensing Module
//
// Responsibilities:
//   1. Enumerate OTHER installed extensions and their permissions.
//   2. Detect supported AI websites currently open.
//   3. Inject/coordinate the shared web sensing content script.
//   4. Receive AI/MCP/Google observations from content scripts.
//   5. Detect Google personal linked apps from browser-visible Google Account UI.
//   6. Diff extension permissions against previous snapshots.
//   7. Send normalized partial records to the local SentinelAI agent.
//
// IMPORTANT:
//   - This module does NOT collect passwords, cookies, auth tokens,
//     prompts, or conversation contents.
//   - Website MCP detection is evidence-based/heuristic.
//   - Local MCP configuration scanning remains the responsibility
//     of the SentinelAI local agent.
//   - Google personal connected-app detection uses only browser-visible
//     Google Account UI.
//   - This scanner is ON-DEMAND ONLY.
//   - There is NO recurring timer/alarm.
//   - There is NO automatic startup scan.
//   - Google observations are accepted only from Google Account pages.
//   - The same web-sensor.js is used for AI and Google pages.
//   - web-sensor.js runs in MAIN world.
//   - web-sensor-bridge.js runs in the extension isolated world.

const LOCAL_AGENT_EXTENSIONS_URL =
  "http://127.0.0.1:8787/ingest/extensions";

const LOCAL_AGENT_WEB_URL =
  "http://127.0.0.1:8787/ingest/web";

const SNAPSHOT_KEY =
  "sentinelai_ext_snapshots";

const WEB_SNAPSHOT_KEY =
  "sentinelai_web_snapshots";

const SENSOR_FILE =
  "content/web-sensor.js";

const SENSOR_BRIDGE_FILE =
  "content/web-sensor-bridge.js";

const TEST_WEB_HOSTS = [
  "127.0.0.1",
  "localhost"
];

// NOTE: this is the page that actually lists third-party apps with
// account access. Google previously used /linkedapps for this; that
// path has moved. If Google moves it again, update this one constant
// (and nothing else needs to change).
const GOOGLE_CONNECTIONS_URL =
  "https://myaccount.google.com/connections";

const AI_SITES = [
  {
    id: "claude_web",
    name: "Claude",
    hostnames: [
      "claude.ai"
    ]
  },

  {
    id: "chatgpt_web",
    name: "ChatGPT",
    hostnames: [
      "chatgpt.com",
      "chat.openai.com"
    ]
  },

  {
    id: "gemini_web",
    name: "Gemini",
    hostnames: [
      "gemini.google.com"
    ]
  }
];


// -----------------------------------------------------------------------------
// Generic helpers
// -----------------------------------------------------------------------------

function nowIso() {
  return new Date().toISOString();
}


function getAiSiteFromUrl(url) {
  try {
    const parsed = new URL(url);

    for (const site of AI_SITES) {
      if (site.hostnames.includes(parsed.hostname)) {
        return site;
      }
    }
  } catch (_) {
    // Ignore malformed URLs.
  }

  return null;
}


// IMPORTANT:
// Keep this as a top-level function.
// This intentionally matches the whole myaccount.google.com host, not
// just /connections, so that the generic "google_linked_apps_page"
// signal can still be accepted from anywhere on the Google Account UI.
// The connections-specific navigation/injection logic below is what
// actually targets the page that has the app list.
function isGoogleAccountPage(url) {
  try {
    const parsed = new URL(url);

    return (
      parsed.hostname === "myaccount.google.com" ||
      parsed.hostname.endsWith(".myaccount.google.com")
    );
  } catch (_) {
    return false;
  }
}


function isGoogleConnectionsPage(url) {
  try {
    const parsed = new URL(url);

    return (
      isGoogleAccountPage(url) &&
      parsed.pathname.startsWith("/connections")
    );
  } catch (_) {
    return false;
  }
}


function normalizeConnectorName(value) {
  if (!value || typeof value !== "string") {
    return null;
  }

  return value
    .trim()
    .replace(/\s+/g, " ")
    .slice(0, 200);
}


function stableWebToolId(siteId, connectorName) {
  const normalized = String(connectorName || "unknown")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

  return `web-mcp-${siteId || "unknown"}-${normalized || "unknown"}`;
}


function stableMcpObservationId(siteId, endpoint) {
  const normalized = String(endpoint || "unknown")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 140);

  return `web-mcp-${siteId || "unknown"}-${normalized || "unknown"}`;
}


function getOriginSafely(url) {
  try {
    return new URL(url).origin;
  } catch (_) {
    return null;
  }
}


// -----------------------------------------------------------------------------
// Endpoint sanitization
// -----------------------------------------------------------------------------

function sanitizeEndpoint(endpoint) {
  if (!endpoint || typeof endpoint !== "string") {
    return null;
  }

  try {
    const url = new URL(endpoint);

    if (url.protocol !== "https:" && url.protocol !== "http:") {
      return null;
    }

    // Never send URL credentials.
    url.username = "";
    url.password = "";

    // Never send fragments.
    url.hash = "";

    // Remove sensitive query parameters.
    const sensitiveParams = [
      "token",
      "access_token",
      "refresh_token",
      "auth",
      "authorization",
      "api_key",
      "apikey",
      "key",
      "secret",
      "password",
      "session",
      "signature",
      "sig",
      "code",
      "state"
    ];

    for (const param of sensitiveParams) {
      url.searchParams.delete(param);
    }

    return url.toString();
  } catch (_) {
    return null;
  }
}


// -----------------------------------------------------------------------------
// Installed extension scanning
// -----------------------------------------------------------------------------

async function loadSnapshots() {
  const stored = await chrome.storage.local.get(SNAPSHOT_KEY);
  return stored[SNAPSHOT_KEY] || {};
}


async function saveSnapshots(snapshots) {
  await chrome.storage.local.set({ [SNAPSHOT_KEY]: snapshots });
}


function permsEqual(a = [], b = []) {
  if (a.length !== b.length) {
    return false;
  }

  const sa = [...a].sort();
  const sb = [...b].sort();

  return sa.every((value, index) => value === sb[index]);
}


function toToolId(ext) {
  return `ext-${ext.id}`;
}


function guessVendorDomain(ext) {
  try {
    if (ext.homepageUrl) {
      return new URL(ext.homepageUrl).hostname;
    }
  } catch (_) {
    // Ignore malformed URL.
  }

  return null;
}


async function scanExtensions() {
  console.log("[SentinelAI EXT DEBUG] Starting extension scan...");

  const now = nowIso();

  const extensions = await chrome.management.getAll();

  console.log(
    "[SentinelAI EXT DEBUG] Chrome management returned:",
    extensions.length,
    "items"
  );

  const snapshots = await loadSnapshots();

  const nextSnapshots = { ...snapshots };

  const records = [];

  for (const ext of extensions) {

    // Don't report SentinelAI itself.
    if (ext.id === chrome.runtime.id) {
      continue;
    }

    // Ignore themes/apps/etc.
    if (ext.type !== "extension") {
      continue;
    }

    const currentPerms = ext.permissions || [];
    const currentHostPerms = ext.hostPermissions || [];

    const combinedCurrent = [
      ...currentPerms,
      ...currentHostPerms.map(host => `host:${host}`)
    ];

    const prev = snapshots[ext.id];

    const previousCombined = prev
      ? [
          ...(prev.permissions || []),
          ...(prev.hostPermissions || []).map(host => `host:${host}`)
        ]
      : null;

    const driftDetected = prev
      ? !permsEqual(combinedCurrent, previousCombined)
      : false;

    const record = {
      tool_id: toToolId(ext),
      name: ext.shortName || ext.name,
      vendor: ext.name || null,
      source_type: "extension",
      stated_function: ext.description || null,

      source_metadata: {
        store: "Chrome Web Store",
        store_domain: "chromewebstore.google.com",
        homepage_url: ext.homepageUrl || null
      },

      vendor_domain: guessVendorDomain(ext),

      detected_via: ["browser_extension_scan"],

      permissions: {
        requested: combinedCurrent,
        previous_snapshot: previousCombined || combinedCurrent,
        drift_detected: driftDetected,
        drift_since: driftDetected ? now : prev?.drift_since || null
      },

      meta: {
        extension_id: ext.id,
        enabled: ext.enabled,
        install_type: ext.installType,
        may_disable: ext.mayDisable,
        update_url: ext.updateUrl || null
      },

      first_seen: prev?.first_seen || now,
      last_scanned: now
    };

    records.push(record);

    nextSnapshots[ext.id] = {
      permissions: currentPerms,
      hostPermissions: currentHostPerms,
      seenAt: now,
      first_seen: record.first_seen,
      drift_since: record.permissions.drift_since
    };
  }

  await saveSnapshots(nextSnapshots);

  console.log(
    "[SentinelAI EXT DEBUG] Extension records produced:",
    records.length
  );

  return records;
}


// -----------------------------------------------------------------------------
// Push installed-extension records
// -----------------------------------------------------------------------------

async function pushExtensionRecords(records) {
  console.log(
    "[SentinelAI EXT PUSH DEBUG] Sending",
    records.length,
    "extension records"
  );

  try {
    const response = await fetch(LOCAL_AGENT_EXTENSIONS_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ records })
    });

    console.log("[SentinelAI EXT PUSH DEBUG] Server response:", {
      status: response.status,
      ok: response.ok
    });

    if (!response.ok) {
      console.warn(
        "[SentinelAI] Extension ingest rejected:",
        response.status
      );
    }

  } catch (error) {
    console.warn(
      "[SentinelAI] Local agent unavailable for extension scan:",
      error?.message || String(error)
    );

    await chrome.storage.local.set({
      sentinelai_last_extension_scan: records
    });
  }
}


// -----------------------------------------------------------------------------
// AI website tab detection
// -----------------------------------------------------------------------------

async function scanAiTabs() {
  console.log("[SentinelAI AI DEBUG] Scanning open tabs...");

  let tabs = [];

  try {
    tabs = await chrome.tabs.query({});
  } catch (error) {
    console.warn(
      "[SentinelAI] Unable to enumerate tabs:",
      error?.message || String(error)
    );

    return [];
  }

  console.log("[SentinelAI AI DEBUG] Open tabs:", tabs.length);

  const records = [];

  for (const tab of tabs) {
    if (!tab.url) {
      continue;
    }

    const site = getAiSiteFromUrl(tab.url);

    if (!site) {
      continue;
    }

    console.log("[SentinelAI AI DEBUG] AI tab found:", {
      tabId: tab.id,
      site: site.name,
      url: tab.url
    });

    records.push({
      source_type: "ai_web",
      detected_via: ["browser_tab_scan"],

      client: {
        id: site.id,
        name: site.name,
        surface: "browser"
      },

      tab: {
        tab_id: tab.id,
        url_origin: getOriginSafely(tab.url),
        title: tab.title || null
      },

      timestamp: nowIso()
    });
  }

  console.log("[SentinelAI AI DEBUG] AI tabs detected:", records.length);

  return records;
}


// -----------------------------------------------------------------------------
// Web observation normalization
// -----------------------------------------------------------------------------

function buildMcpRecord(observation, site, sender) {
  const endpoint = sanitizeEndpoint(observation?.endpoint);

  const signals = Array.isArray(observation?.signals)
    ? observation.signals.slice(0, 30)
    : [];

  const evidence = Array.isArray(observation?.evidence)
    ? observation.evidence.slice(0, 10)
    : [];

  const observationId = stableMcpObservationId(site.id, endpoint);

  return {
    tool_id: observationId,
    name: `${site.name} MCP activity`,
    vendor: site.name,
    source_type: "mcp_web_activity",
    stated_function: "Observed MCP/JSON-RPC/connector activity in the browser",
    detected_via: ["browser_protocol_observation"],

    client: {
      id: site.id,
      name: site.name,
      surface: "browser"
    },

    tab: {
      tab_id: sender?.tab?.id || null,
      url_origin: getOriginSafely(sender?.tab?.url || "")
    },

    permissions: {
      requested: [],
      drift_detected: false,
      drift_since: null
    },

    observation: {
      type: "mcp_activity_signal",
      endpoint,
      confidence: observation?.confidence || "medium",
      transport: observation?.transport || "unknown",
      signals,
      evidence
    },

    meta: {
      detection: "browser_network_protocol_sensor",
      protocol: "mcp_or_jsonrpc",
      body_forwarded: false
    },

    first_seen: observation?.timestamp || nowIso(),
    last_scanned: observation?.timestamp || nowIso()
  };
}


function buildConnectorUiRecord(observation, site, sender) {
  return {
    tool_id: stableWebToolId(site.id, "connector-ui"),
    name: `${site.name} connector UI`,
    vendor: site.name,
    source_type: "ai_web_connector_ui",
    detected_via: ["browser_content_sensor"],

    client: {
      id: site.id,
      name: site.name,
      surface: "browser"
    },

    tab: {
      tab_id: sender?.tab?.id || null,
      url_origin: getOriginSafely(sender?.tab?.url || "")
    },

    observation: {
      type: "connector_ui_signal",
      evidence: Array.isArray(observation?.evidence)
        ? observation.evidence.slice(0, 20)
        : []
    },

    meta: {
      detection: "browser_visible_connector_ui"
    },

    timestamp: observation?.timestamp || nowIso()
  };
}


// -----------------------------------------------------------------------------
// Receive observations from content scripts
// -----------------------------------------------------------------------------

async function handleWebObservation(message, sender) {
  console.log("[SentinelAI MESSAGE DEBUG] Web observation received:", message);

  console.log("[SentinelAI MESSAGE DEBUG] Sender:", {
    tabId: sender?.tab?.id || null,
    url: sender?.tab?.url || null,
    title: sender?.tab?.title || null
  });

  const observation = message?.observation;

  if (!observation) {
    console.warn("[SentinelAI MESSAGE DEBUG] Empty observation.");
    return;
  }

  const senderUrl = sender?.tab?.url || sender?.url || "";

  const site = getAiSiteFromUrl(senderUrl);

  const googleAccountPage = isGoogleAccountPage(senderUrl);

  const testPage = isTestWebPage(senderUrl);

  const effectiveSite =
    site ||
    (testPage
      ? { id: "sentinel_test_web", name: "SentinelAI Test Page" }
      : null);

  console.log("[SentinelAI MESSAGE DEBUG] Page classification:", {
    senderUrl,
    isAiSite: Boolean(site),
    aiSite: site?.name || null,
    isGoogleAccountPage: googleAccountPage
  });

  // Ignore unrelated websites.
  //
  // Allowed:
  //   - ChatGPT
  //   - Claude
  //   - Gemini
  //   - Google Account pages
  //   - localhost / 127.0.0.1 SentinelAI test page
  if (!site && !testPage && !googleAccountPage) {
    console.log(
      "[SentinelAI MESSAGE DEBUG] Ignoring unrelated website:",
      senderUrl
    );

    return;
  }

  const observationType = observation.type || null;

  console.log("[SentinelAI MESSAGE DEBUG] Observation type:", observationType);


  // ---------------------------------------------------------------------------
  // Google linked app
  // ---------------------------------------------------------------------------

  if (observationType === "google_linked_app") {
    if (!googleAccountPage) {
      console.warn(
        "[SentinelAI Google DEBUG] Rejected Google linked-app observation from non-Google page:",
        senderUrl
      );

      return;
    }

    const rawAppName = observation.app_name || "";

    const appName = normalizeConnectorName(rawAppName);

    if (!appName) {
      console.warn(
        "[SentinelAI Google DEBUG] App name rejected:",
        rawAppName
      );

      return;
    }

    const normalized = appName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");

    const toolId = `oauth-google-${normalized}`;

    const googleRecord = {
      tool_id: toolId,
      name: appName,
      source_type: "oauth_connected_app",
      detected_via: ["google_linked_apps_page"],

      permissions: {
        requested: []
      },

      meta: {
        provider: "google",
        account_type: "personal",
        discovery: "browser_visible_linked_apps",
        google_account_page: true
      },

      privacy_policy: {
        url: null,
        status: "not_discovered"
      },

      first_seen: observation.timestamp || nowIso(),
      last_scanned: observation.timestamp || nowIso()
    };

    console.log("[SentinelAI Google DEBUG] Sending OAuth record:", googleRecord);

    await pushWebObservation(googleRecord);

    return;
  }


  // ---------------------------------------------------------------------------
  // Google linked-app page signal
  // ---------------------------------------------------------------------------

  if (observationType === "google_linked_apps_page") {
    if (!googleAccountPage) {
      console.warn(
        "[SentinelAI Google DEBUG] Rejected Google page observation from non-Google page."
      );

      return;
    }

    const googlePageRecord = {
      source_type: "google_linked_apps_page",
      detected_via: ["google_account_browser_ui"],

      client: {
        id: "google_account",
        name: "Google Account",
        surface: "browser"
      },

      tab: {
        tab_id: sender?.tab?.id || null,
        url_origin: getOriginSafely(senderUrl)
      },

      observation: {
        type: observationType,
        evidence: Array.isArray(observation.evidence)
          ? observation.evidence.slice(0, 20)
          : []
      },

      timestamp: observation.timestamp || nowIso()
    };

    await pushWebObservation(googlePageRecord);

    return;
  }


  // ---------------------------------------------------------------------------
  // MCP browser activity
  // ---------------------------------------------------------------------------

  if (observationType === "mcp_activity_signal") {
    if (!effectiveSite) {
      console.warn(
        "[SentinelAI MCP DEBUG] Rejected MCP observation from unsupported page:",
        senderUrl
      );

      return;
    }

    console.log("[SentinelAI MCP DEBUG] Accepting MCP observation:", {
      senderUrl,
      testPage,
      site: effectiveSite.name,
      observation
    });

    const mcpRecord = buildMcpRecord(observation, effectiveSite, sender);

    console.log("[SentinelAI MCP DEBUG] MCP observation normalized:", mcpRecord);

    await storeWebObservation(mcpRecord);
    await pushWebObservation(mcpRecord);

    return;
  }


  // ---------------------------------------------------------------------------
  // Connector UI
  // ---------------------------------------------------------------------------

  if (observationType === "connector_ui_signal") {
    if (!site) {
      return;
    }

    const connectorRecord = buildConnectorUiRecord(observation, site, sender);

    console.log("[SentinelAI AI DEBUG] Connector UI observation:", connectorRecord);

    await storeWebObservation(connectorRecord);
    await pushWebObservation(connectorRecord);

    return;
  }


  // ---------------------------------------------------------------------------
  // Generic AI web observation
  // ---------------------------------------------------------------------------

  if (!site) {
    return;
  }

  const aiObservation = {
    source_type: "ai_web",
    detected_via: ["browser_content_sensor"],

    client: {
      id: site.id,
      name: site.name,
      surface: "browser"
    },

    tab: {
      tab_id: sender?.tab?.id || null,
      url_origin: getOriginSafely(senderUrl)
    },

    observation: {
      type: observationType || "unknown",
      connector_name: normalizeConnectorName(observation.connector_name),
      endpoint: sanitizeEndpoint(observation.endpoint),
      evidence: Array.isArray(observation.evidence)
        ? observation.evidence.slice(0, 20)
        : []
    },

    timestamp: observation.timestamp || nowIso()
  };

  await storeWebObservation(aiObservation);
  await pushWebObservation(aiObservation);
}


// -----------------------------------------------------------------------------
// Local web observation cache
// -----------------------------------------------------------------------------

async function loadWebSnapshots() {
  const stored = await chrome.storage.local.get(WEB_SNAPSHOT_KEY);
  return stored[WEB_SNAPSHOT_KEY] || {};
}


async function saveWebSnapshots(snapshots) {
  await chrome.storage.local.set({ [WEB_SNAPSHOT_KEY]: snapshots });
}


async function storeWebObservation(observation) {
  console.log("[SentinelAI WEB CACHE DEBUG] Storing:", observation);

  const snapshots = await loadWebSnapshots();

  const siteId = observation?.client?.id || "unknown";

  const connector = observation?.observation?.connector_name;
  const endpoint = observation?.observation?.endpoint;

  let toolId;

  if (connector) {
    toolId = stableWebToolId(siteId, connector);
  } else if (endpoint) {
    toolId = stableMcpObservationId(siteId, endpoint);
  } else {
    toolId = `web-${siteId}-observation`;
  }

  const previous = snapshots[toolId];

  snapshots[toolId] = {
    ...observation,
    tool_id: observation.tool_id || toolId,

    first_seen:
      previous?.first_seen ||
      observation.first_seen ||
      observation.timestamp ||
      nowIso(),

    last_seen:
      observation.last_scanned || observation.timestamp || nowIso()
  };

  await saveWebSnapshots(snapshots);

  console.log("[SentinelAI WEB CACHE DEBUG] Cached:", toolId);
}


// -----------------------------------------------------------------------------
// Push web observations to local agent
// -----------------------------------------------------------------------------

async function pushWebObservation(observation) {
  console.log("[SentinelAI PUSH DEBUG] Preparing:", {
    source_type: observation?.source_type,
    tool_id: observation?.tool_id,
    name: observation?.name,
    observation_type: observation?.observation?.type
  });

  try {
    const response = await fetch(LOCAL_AGENT_WEB_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ records: [observation] })
    });

    console.log("[SentinelAI PUSH DEBUG] Server response:", {
      status: response.status,
      ok: response.ok
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

  } catch (error) {
    console.warn(
      "[SentinelAI] Local agent unavailable for web observation:",
      error?.message || String(error)
    );

    const existing = await chrome.storage.local.get(
      "sentinelai_pending_web_observations"
    );

    const pending = existing?.sentinelai_pending_web_observations || [];

    pending.push(observation);

    await chrome.storage.local.set({
      sentinelai_pending_web_observations: pending.slice(-200)
    });
  }
}


// -----------------------------------------------------------------------------
// Shared web sensor injection
// -----------------------------------------------------------------------------
//
// Bridge:
//   isolated world
//
// Sensor:
//   MAIN world
//
// This order is intentional.
// -----------------------------------------------------------------------------

async function injectSensorIntoTab(tab) {
  if (!tab || !tab.id) {
    return false;
  }

  const url = tab.url || "";

  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    return false;
  }

  try {
    // Bridge first.
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: [SENSOR_BRIDGE_FILE]
    });

    // Actual network sensor in MAIN world.
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      world: "MAIN",
      files: [SENSOR_FILE]
    });

    console.log("[SentinelAI SENSOR DEBUG] Sensor injected:", {
      tabId: tab.id,
      url
    });

    return true;

  } catch (error) {
    console.warn("[SentinelAI SENSOR DEBUG] Injection failed:", {
      tabId: tab.id,
      url,
      error: error?.message || String(error)
    });

    return false;
  }
}


// -----------------------------------------------------------------------------
// Scan AI tabs and inject sensor
// -----------------------------------------------------------------------------
async function runAiWebScan() {
  console.log("[SentinelAI AI DEBUG] Starting AI/web sensor scan...");

  const tabs = await chrome.tabs.query({});

  const results = [];

  for (const tab of tabs) {
    if (!tab || !tab.id) {
      continue;
    }

    const url = tab.url || "";

    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      continue;
    }

    const site = getAiSiteFromUrl(url);
    const testPage = isTestWebPage(url);

    /*
     * Normal production targets:
     *   ChatGPT
     *   Claude
     *   Gemini
     *
     * Development target:
     *   localhost / 127.0.0.1
     */
    if (!site && !testPage) {
      continue;
    }

    const injected = await injectSensorIntoTab(tab);

    results.push({
      source_type: site ? "ai_web" : "sentinel_test_web",

      site: {
        id: site?.id || "sentinel_test_web",
        name: site?.name || "SentinelAI Test Page"
      },

      tab_id: tab.id,
      url_origin: getOriginSafely(url),
      sensor_injected: injected,
      timestamp: nowIso()
    });

    console.log("[SentinelAI SENSOR DEBUG] Target scanned:", {
      tabId: tab.id,
      url,
      target: site?.name || "SentinelAI Test Page",
      injected
    });
  }

  console.log("[SentinelAI AI DEBUG] AI/web sensor scan complete:", results);

  return results;
}

// -----------------------------------------------------------------------------
// Google Account scan
// -----------------------------------------------------------------------------

async function runGoogleAccountScan() {
  let tempTab = null;

  try {
    const tabs = await chrome.tabs.query({
      url: ["https://myaccount.google.com/*"]
    });

    let tab = tabs.find(t => t?.id);

    // Prefer a tab that's already on the /connections page specifically,
    // since that's the only page that actually has the app list.
    const connectionsTab = tabs.find(t =>
      t?.url?.startsWith(GOOGLE_CONNECTIONS_URL)
    );

    if (connectionsTab) {
      tab = connectionsTab;
    }

    // Open temporary background tab if necessary.
    if (!tab) {
      tempTab = await chrome.tabs.create({
        url: GOOGLE_CONNECTIONS_URL,
        active: false
      });

      tab = tempTab;

      console.log("[SentinelAI GOOGLE DEBUG] Temporary Google tab:", tab.id);
    }

    if (!tab || !tab.id) {
      return false;
    }

    // Navigate existing Google Account tab to /connections if it's
    // sitting on some other myaccount.google.com page.
    if (!tab.url?.startsWith(GOOGLE_CONNECTIONS_URL)) {
      await chrome.tabs.update(tab.id, {
        url: GOOGLE_CONNECTIONS_URL
      });
    }

    await waitForTabComplete(tab.id);

    // Google's account UI is a client-rendered SPA; give the app list
    // time to actually render before we inject and read the DOM.
    await sleep(1500);

    // Get fresh tab information after navigation.
    let freshTab;

    try {
      freshTab = await chrome.tabs.get(tab.id);
    } catch (_) {
      freshTab = { ...tab, url: GOOGLE_CONNECTIONS_URL };
    }

    const injected = await injectSensorIntoTab(freshTab);

    console.log("[SentinelAI GOOGLE DEBUG] Google sensor injected:", injected);

    await sleep(2000);

    return true;

  } catch (error) {
    console.error("[SentinelAI GOOGLE DEBUG] Google scan failed:", error);
    return false;

  } finally {
    if (tempTab?.id) {
      try {
        await chrome.tabs.remove(tempTab.id);

        console.log(
          "[SentinelAI GOOGLE DEBUG] Closed temporary Google tab:",
          tempTab.id
        );

      } catch (error) {
        console.debug(
          "[SentinelAI GOOGLE DEBUG] Could not close temporary tab:",
          error
        );
      }
    }
  }
}


function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}


function waitForTabComplete(tabId, timeoutMs = 15000) {
  return new Promise(resolve => {
    let finished = false;

    const cleanup = () => {
      if (finished) {
        return;
      }

      finished = true;

      chrome.tabs.onUpdated.removeListener(listener);
      clearTimeout(timeout);
    };

    const listener = (updatedTabId, changeInfo) => {
      if (updatedTabId === tabId && changeInfo.status === "complete") {
        cleanup();
        resolve();
      }
    };

    const timeout = setTimeout(() => {
      cleanup();
      resolve();
    }, timeoutMs);

    chrome.tabs.onUpdated.addListener(listener);

    chrome.tabs
      .get(tabId)
      .then(tab => {
        if (tab.status === "complete") {
          cleanup();
          resolve();
        }
      })
      .catch(() => {
        cleanup();
        resolve();
      });
  });
}


// -----------------------------------------------------------------------------
// Combined scan
// -----------------------------------------------------------------------------

async function runScanCycle() {
  console.log("================================================");
  console.log("[SentinelAI SCAN DEBUG] ===== SCAN START =====");
  console.log("================================================");


  // ---------------------------------------------------------------------------
  // Extensions
  // ---------------------------------------------------------------------------

  console.log("[SentinelAI SCAN DEBUG] Step 1: scanning extensions...");

  const extensionRecords = await scanExtensions();

  await pushExtensionRecords(extensionRecords);

  console.log("[SentinelAI SCAN DEBUG] Step 1 complete:", extensionRecords.length);


  // ---------------------------------------------------------------------------
  // AI web
  // ---------------------------------------------------------------------------

  console.log("[SentinelAI SCAN DEBUG] Step 2: scanning AI websites...");

  const aiWebResult = await runAiWebScan();

  console.log("[SentinelAI SCAN DEBUG] Step 2 complete:", aiWebResult.length);


  // ---------------------------------------------------------------------------
  // Google
  // ---------------------------------------------------------------------------

  console.log("[SentinelAI SCAN DEBUG] Step 3: scanning Google Account...");

  const googleResult = await runGoogleAccountScan();

  console.log("[SentinelAI SCAN DEBUG] Step 3 complete:", googleResult);


  console.log("[SentinelAI SCAN DEBUG] ===== SCAN COMPLETE =====");


  return {
    extensions: extensionRecords,
    ai_web: aiWebResult,
    google: googleResult
  };
}


// -----------------------------------------------------------------------------
// Lifecycle
// -----------------------------------------------------------------------------
//
// IMPORTANT:
// No automatic scanning.
// No recurring alarm.
// No startup scan.
//
// Scan only when popup sends:
//     SENTINELAI_SCAN_NOW
// -----------------------------------------------------------------------------

chrome.runtime.onInstalled.addListener(() => {
  console.log("[SentinelAI] Extension installed.");
  console.log("[SentinelAI] Scanner is idle until Scan now is clicked.");
});


// -----------------------------------------------------------------------------
// Messages
// -----------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  console.log("[SentinelAI MESSAGE DEBUG] Received:", {
    type: msg?.type,
    senderTabId: sender?.tab?.id || null,
    senderUrl: sender?.tab?.url || null
  });


  // -------------------------------------------------------------------------
  // Manual scan
  // -------------------------------------------------------------------------

  if (msg?.type === "SENTINELAI_SCAN_NOW") {
    runScanCycle()
      .then(result => {
        sendResponse({ ok: true, ...result });
      })
      .catch(error => {
        console.error("[SentinelAI SCAN DEBUG] Scan failed:", error);

        sendResponse({
          ok: false,
          error: error?.message || String(error)
        });
      });

    return true;
  }


  // -------------------------------------------------------------------------
  // Web / MCP / Google observation
  // -------------------------------------------------------------------------

  if (msg?.type === "SENTINELAI_WEB_OBSERVATION") {
    handleWebObservation(msg, sender)
      .then(() => {
        sendResponse({ ok: true });
      })
      .catch(error => {
        console.error("[SentinelAI] Observation handling failed:", error);

        sendResponse({
          ok: false,
          error: error?.message || String(error)
        });
      });

    return true;
  }


  console.log("[SentinelAI MESSAGE DEBUG] Unknown message:", msg?.type);

  return false;
});


function isTestWebPage(url) {
  try {
    const parsed = new URL(url);

    return (
      TEST_WEB_HOSTS.includes(parsed.hostname) &&
      (parsed.protocol === "http:" || parsed.protocol === "https:")
    );
  } catch (_) {
    return false;
  }
}

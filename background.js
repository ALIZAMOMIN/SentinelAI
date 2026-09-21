// SentinelAI — Browser Extension Sensing Module
// Runs inside the SentinelAI Chrome extension (service worker / background.js).
// Requires "management" permission in manifest.json (already present per your build).
//
// Responsibilities:
//   1. Enumerate every OTHER installed extension and its granted permissions.
//   2. Diff current permissions against the last-seen snapshot to detect drift.
//   3. Emit partial Tool records (source_type: "extension") to the local agent,
//      which owns MCP/DNS scanning + merging + the final normalized JSON.
//
// This is real, working data — chrome.management is a first-party API, no
// scraping or faking involved.

const LOCAL_AGENT_INGEST_URL = "http://127.0.0.1:8787/ingest/extensions";
const SNAPSHOT_KEY = "sentinelai_ext_snapshots"; // chrome.storage.local key

/**
 * Load the last-seen permission snapshot per extension id.
 * Shape: { [extensionId]: { permissions: string[], hostPermissions: string[], seenAt: string } }
 */
async function loadSnapshots() {
  const stored = await chrome.storage.local.get(SNAPSHOT_KEY);
  return stored[SNAPSHOT_KEY] || {};
}

async function saveSnapshots(snapshots) {
  await chrome.storage.local.set({ [SNAPSHOT_KEY]: snapshots });
}

function permsEqual(a = [], b = []) {
  if (a.length !== b.length) return false;
  const sa = [...a].sort();
  const sb = [...b].sort();
  return sa.every((v, i) => v === sb[i]);
}

/**
 * Build a stable tool_id from the extension's own id — the agent's normalizer
 * will re-key this against vendor/domain when merging with MCP/DNS signals.
 */
function toToolId(ext) {
  return `ext-${ext.id}`;
}

function guessVendorDomain(ext) {
  // homepageUrl is the most reliable first-party signal the API exposes.
  try {
    if (ext.homepageUrl) return new URL(ext.homepageUrl).hostname;
  } catch (_) {
    /* ignore malformed url */
  }
  return null;
}

async function scanExtensions() {
  const now = new Date().toISOString();
  const extensions = await chrome.management.getAll();
  const snapshots = await loadSnapshots();
  const nextSnapshots = { ...snapshots };
  const records = [];

  for (const ext of extensions) {
    if (ext.id === chrome.runtime.id) continue; // skip self
    if (ext.type !== "extension") continue; // skip themes/apps/hosted apps

    const currentPerms = ext.permissions || [];
    const currentHostPerms = ext.hostPermissions || [];
    const combinedCurrent = [...currentPerms, ...currentHostPerms.map((h) => `host:${h}`)];

    const prev = snapshots[ext.id];
    const previousCombined = prev
      ? [...(prev.permissions || []), ...(prev.hostPermissions || []).map((h) => `host:${h}`)]
      : null;

    const driftDetected = prev ? !permsEqual(combinedCurrent, previousCombined) : false;

    const record = {
      tool_id: toToolId(ext),
      name: ext.shortName || ext.name,
      vendor: guessVendorDomain(ext) || null,
      source_type: "extension",
      stated_function: ext.description || null,
      detected_via: ["browser_extension_scan"],
      permissions: {
        requested: combinedCurrent,
        previous_snapshot: previousCombined || combinedCurrent,
        drift_detected: driftDetected,
        drift_since: driftDetected ? now : prev?.drift_since || null,
      },
      meta: {
        extension_id: ext.id,
        enabled: ext.enabled,
        install_type: ext.installType, // "development" | "normal" | "sideload" | "admin"
        may_disable: ext.mayDisable,
        update_url: ext.updateUrl || null,
      },
      first_seen: prev?.first_seen || now,
      last_scanned: now,
    };

    records.push(record);

    nextSnapshots[ext.id] = {
      permissions: currentPerms,
      hostPermissions: currentHostPerms,
      seenAt: now,
      first_seen: record.first_seen,
      drift_since: record.permissions.drift_since,
    };
  }

  await saveSnapshots(nextSnapshots);
  return records;
}

async function pushToLocalAgent(records) {
  try {
    const res = await fetch(LOCAL_AGENT_INGEST_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ records }),
    });
    if (!res.ok) {
      console.warn("[SentinelAI] local agent rejected batch:", res.status);
    }
  } catch (err) {
    // Local agent not running — cache locally so nothing is lost, agent can
    // pull via chrome.storage on next reconnect if you wire a native-messaging
    // fallback later.
    console.warn("[SentinelAI] local agent unreachable, caching results:", err.message);
    await chrome.storage.local.set({ sentinelai_last_scan: records });
  }
}

async function runScanCycle() {
  const records = await scanExtensions();
  await pushToLocalAgent(records);
  return records;
}

// Run on install/startup, then periodically.
chrome.runtime.onInstalled.addListener(() => {
  runScanCycle();
  chrome.alarms.create("sentinelai-ext-scan", { periodInMinutes: 15 });
});

chrome.runtime.onStartup.addListener(runScanCycle);

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "sentinelai-ext-scan") runScanCycle();
});

// Allow the popup/devtools to trigger an on-demand scan and read results.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "SENTINELAI_SCAN_NOW") {
    runScanCycle().then((records) => sendResponse({ ok: true, records }));
    return true; // keep the message channel open for the async response
  }
});

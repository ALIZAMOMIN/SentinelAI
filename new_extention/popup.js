const LOCAL_AGENT_URL = "http://127.0.0.1:8787";
const TOOLS_URL = `${LOCAL_AGENT_URL}/tools`;

// Existing UI
const toolCountEl = document.getElementById("tool-count");
const highCountEl = document.getElementById("high-count");
const localMcpCountEl = document.getElementById("local-mcp-count");
const webMcpCountEl = document.getElementById("web-mcp-count");
const extensionCountEl = document.getElementById("extension-count");

// New Google 3rd-party app count
const oauthAppCountEl = document.getElementById("oauth-app-count");

const statusDotEl = document.getElementById("status-dot");
const statusTextEl = document.getElementById("status-text");
const scanButtonEl = document.getElementById("scan-button");
const dashboardButtonEl = document.getElementById("dashboard-button");


/* -------------------------------------------------------
   Helpers
------------------------------------------------------- */

function getSourceType(tool) {
  return String(
    tool?.source_type ||
    tool?.sourceType ||
    ""
  ).toLowerCase();
}

function normalizeRiskLevel(tool) {
  const risk = String(
    tool?.risk_level ||
    tool?.riskLevel ||
    tool?.risk ||
    ""
  ).toLowerCase();

  if (risk === "high") return "high";
  if (risk === "medium") return "medium";
  if (risk === "low") return "low";

  return "";
}

function getProvider(tool) {
  return String(
    tool?.meta?.provider ||
    tool?.provider ||
    ""
  ).toLowerCase();
}


/* -------------------------------------------------------
   Status
------------------------------------------------------- */

function setOnline() {
  if (statusDotEl) {
    statusDotEl.classList.add("online");
    statusDotEl.classList.remove("offline");
  }

  if (statusTextEl) {
    statusTextEl.textContent = "Agent online";
  }
}

function setOffline() {
  if (statusDotEl) {
    statusDotEl.classList.remove("online");
    statusDotEl.classList.add("offline");
  }

  if (statusTextEl) {
    statusTextEl.textContent = "Agent offline";
  }
}


/* -------------------------------------------------------
   Source classification
------------------------------------------------------- */

function isLocalMcp(tool) {
  const source = getSourceType(tool);

  return (
    source === "mcp_connector" ||
    source === "mcp" ||
    source === "local_mcp"
  );
}

function isWebMcp(tool) {
  const source = getSourceType(tool);

  return (
    source === "web" ||
    source === "web_mcp" ||
    source === "browser_mcp" ||
    source === "mcp_web_activity"
  );
}
/*
function isGoogleThirdPartyApp(tool) {
  const source = getSourceType(tool);
  const provider = getProvider(tool);

  return (
    source === "oauth_connected_app" &&
    (
      provider === "google" ||
      provider === ""
    )
  );
}
*/

function isGoogleThirdPartyApp(tool) {
  return getSourceType(tool) === "oauth_connected_app";
}

/* -------------------------------------------------------
   Render dashboard summary
------------------------------------------------------- */

function renderCounts(tools) {
  if (!Array.isArray(tools)) {
    tools = [];
  }

  const localMcp = tools.filter(isLocalMcp);

  const webMcp = tools.filter(isWebMcp);

  const extensions = tools.filter(
    tool => getSourceType(tool) === "extension"
  );

  const googleThirdPartyApps = tools.filter(
    isGoogleThirdPartyApp
  );

  const highRisk = tools.filter(
    tool => normalizeRiskLevel(tool) === "high"
  );


  // Existing counts
  if (localMcpCountEl) {
    localMcpCountEl.textContent = localMcp.length;
  }

  if (webMcpCountEl) {
    webMcpCountEl.textContent = webMcp.length;
  }

  if (extensionCountEl) {
    extensionCountEl.textContent = extensions.length;
  }

  if (toolCountEl) {
    toolCountEl.textContent = tools.length;
  }

  if (highCountEl) {
    highCountEl.textContent = highRisk.length;
  }


  // New Google 3rd-party app count
  if (oauthAppCountEl) {
    oauthAppCountEl.textContent = googleThirdPartyApps.length;
  }


  console.log("[SentinelAI] Scan summary:", {
    totalTools: tools.length,
    googleThirdPartyApps: googleThirdPartyApps.length,
    localMcp: localMcp.length,
    webMcp: webMcp.length,
    extensions: extensions.length,
    highRisk: highRisk.length
  });
}


/* -------------------------------------------------------
   Load current SentinelAI results
------------------------------------------------------- */

async function loadTools() {
  try {
    setOffline();

    const response = await fetch(TOOLS_URL, {
      method: "GET",
      cache: "no-store"
    });

    if (!response.ok) {
      throw new Error(
        `Agent returned HTTP ${response.status}`
      );
    }

    const tools = await response.json();

    if (!Array.isArray(tools)) {
      throw new Error(
        "/tools did not return an array"
      );
    }

    setOnline();

    renderCounts(tools);

  } catch (error) {
    console.error(
      "[SentinelAI popup] Failed to load tools:",
      error
    );

    setOffline();

    if (toolCountEl) {
      toolCountEl.textContent = "—";
    }

    if (highCountEl) {
      highCountEl.textContent = "—";
    }

    if (localMcpCountEl) {
      localMcpCountEl.textContent = "—";
    }

    if (webMcpCountEl) {
      webMcpCountEl.textContent = "—";
    }

    if (extensionCountEl) {
      extensionCountEl.textContent = "—";
    }

    if (oauthAppCountEl) {
      oauthAppCountEl.textContent = "—";
    }
  }
}


/* -------------------------------------------------------
   Manual Scan
------------------------------------------------------- */

async function scanNow() {
  if (!scanButtonEl) {
    return;
  }

  scanButtonEl.classList.add("loading");
  scanButtonEl.textContent = "Scanning...";
  scanButtonEl.disabled = true;

  try {
    const response = await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(
        {
          type: "SENTINELAI_SCAN_NOW"
        },
        result => {
          if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
            return;
          }

          if (result && result.ok) {
            resolve(result);
            return;
          }

          reject(
            new Error(
              result?.error || "Scan failed"
            )
          );
        }
      );
    });

    console.log(
      "[SentinelAI] Manual scan completed:",
      response
    );

    /*
     * Give the background service worker a moment to finish
     * forwarding the observations to the local agent.
     *
     * This is NOT a timer or recurring scan.
     * It only waits once for the current click operation.
     */
    await new Promise(resolve => setTimeout(resolve, 300));

    // Reload results after this manual scan.
    await loadTools();

  } catch (error) {
    console.error(
      "[SentinelAI] Manual scan failed:",
      error
    );

    // Still try to display whatever the backend currently has.
    await loadTools();

  } finally {
    scanButtonEl.classList.remove("loading");
    scanButtonEl.textContent = "Scan now";
    scanButtonEl.disabled = false;
  }
}


/* -------------------------------------------------------
   Dashboard
------------------------------------------------------- */

function openDashboard() {
  chrome.tabs.create({
    url: `${LOCAL_AGENT_URL}/`
  });
}


/* -------------------------------------------------------
   Events
------------------------------------------------------- */

if (scanButtonEl) {
  scanButtonEl.addEventListener(
    "click",
    scanNow
  );
}

if (dashboardButtonEl) {
  dashboardButtonEl.addEventListener(
    "click",
    openDashboard
  );
}


/* -------------------------------------------------------
   Initial popup load
------------------------------------------------------- */

loadTools();

/* ----------------------------------------------------------
   CONFIGURATION
---------------------------------------------------------- */

const LOCAL_AGENT_URL = window.location.origin;

const TOOLS_URL = `${LOCAL_AGENT_URL}/tools`;


/* ----------------------------------------------------------
   APPLICATION STATE
---------------------------------------------------------- */

let TOOLS = [];

let selectedToolId = null;


/* ----------------------------------------------------------
   DOM REFERENCES
---------------------------------------------------------- */

const toolListEl = document.getElementById("tool-list");

const panelEl = document.getElementById("panel");

const countEl = document.getElementById("tool-count");

const statusDotEl = document.getElementById("status-dot");

const statusTextEl = document.getElementById("status-text");

const lastScanEl = document.getElementById("last-scan");

const dashboardToolCountEl =
  document.getElementById("dashboard-tool-count");

const dashboardAgentStatusEl =
  document.getElementById("dashboard-agent-status");

const dashboardLastScanEl =
  document.getElementById("dashboard-last-scan");

const reduceMotion =
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;


/* ----------------------------------------------------------
   UTILITY HELPERS
---------------------------------------------------------- */

function escapeHtml(value) {

  if (value === null || value === undefined) {
    return "";
  }

  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}


function formatScore(score) {

  if (
    score === null ||
    score === undefined ||
    Number.isNaN(Number(score))
  ) {
    return "—";
  }

  return Number(score).toFixed(1);
}


function normalizeRiskLevel(level, score) {

  if (level) {

    const normalized =
      String(level).toLowerCase();

    if (
      ["high", "medium", "low"].includes(
        normalized
      )
    ) {
      return normalized;
    }
  }

  if (
    score !== null &&
    score !== undefined &&
    !Number.isNaN(Number(score))
  ) {

    const n = Number(score);

    if (n >= 7) {
      return "high";
    }

    if (n >= 4) {
      return "medium";
    }

    return "low";
  }

  return "unknown";
}


function capitalize(value) {

  if (!value) {
    return "";
  }

  const text =
    String(value);

  return (
    text.charAt(0).toUpperCase() +
    text.slice(1)
  );
}


function formatTimestamp(timestamp) {

  if (!timestamp) {
    return "Unknown";
  }

  try {

    const date =
      new Date(timestamp);

    if (
      Number.isNaN(
        date.getTime()
      )
    ) {
      return String(timestamp);
    }

    return date.toLocaleString();

  } catch (_) {

    return String(timestamp);
  }
}


function formatSource(source) {

  if (!source) {
    return "Unknown source";
  }

  if (Array.isArray(source)) {
    return source.join(", ");
  }

  return String(source)
    .replaceAll("_", " ");
}


function normalizeList(value) {

  if (!value) {
    return [];
  }

  if (Array.isArray(value)) {
    return value;
  }

  return [value];
}


/* ----------------------------------------------------------
   SOURCE NORMALIZATION
---------------------------------------------------------- */

function normalizeSourceValue(value) {

  if (
    value === null ||
    value === undefined
  ) {
    return "";
  }

  if (Array.isArray(value)) {

    return value
      .map(item =>
        String(item)
          .trim()
          .toLowerCase()
      )
      .join(" ");
  }

  return String(value)
    .trim()
    .toLowerCase();
}


function getSourceType(tool) {

  return normalizeSourceValue(
    tool?.sourceType
  );
}


function getToolText(tool) {

  const metaValues =
    tool?.meta &&
    typeof tool.meta === "object"
      ? Object.values(tool.meta)
      : [];

  return [

    tool?.sourceType,

    tool?.source_type,

    tool?.name,

    tool?.vendor,

    tool?.detected_via,

    tool?.connector_name,

    tool?.client,

    tool?.type,

    tool?.connector_type,

    ...metaValues

  ]
    .filter(
      value =>
        value !== null &&
        value !== undefined
    )
    .map(
      value =>
        normalizeSourceValue(value)
    )
    .join(" ");
}


/* ----------------------------------------------------------
   SOURCE CATEGORY DETECTION

   These functions deliberately accept multiple possible
   values because normalizer.py/scanners may use different
   source_type names.
---------------------------------------------------------- */

function isExtensionTool(tool) {

  const source =
    getSourceType(tool);

  const text =
    getToolText(tool);

  return (

    source.includes("extension") ||

    source.includes("browser_extension") ||

    source.includes("chrome_extension") ||

    source.includes("chrome extension") ||

    source === "extension" ||

    source === "browser" ||

    source === "chrome" ||

    text.includes("browser extension") ||

    text.includes("chrome extension") ||

    text.includes("extension scanner") ||

    text.includes("installed extension")

  );
}


function isMcpTool(tool) {

  const source =
    getSourceType(tool);

  const text =
    getToolText(tool);

  return (

    source.includes("mcp") ||

    source.includes("model_context_protocol") ||

    source.includes("model context protocol") ||

    source.includes("mcp_config") ||

    source.includes("mcp_server") ||

    source.includes("mcp connector") ||

    text.includes("model context protocol") ||

    text.includes("mcp connector") ||

    text.includes("mcp server") ||

    text.includes("mcp config") ||

    text.includes("claude desktop")

  );
}


function isOAuthTool(tool) {

  const source =
    getSourceType(tool);

  const text =
    getToolText(tool);

  return (

    source.includes("oauth") ||

    source.includes("google_oauth") ||

    source.includes("oauth_account") ||

    source.includes("oauth_connected_app") ||

    source.includes("connected_account") ||

    source.includes("connected_app") ||

    text.includes("oauth") ||

    text.includes("connected app") ||

    text.includes("connected account")

  );
}


/* ----------------------------------------------------------
   BACKEND -> UI ADAPTER

   Handles raw /tools records.
---------------------------------------------------------- */

function normalizeForUI(raw) {

  const id =
    raw.tool_id ??
    raw.id ??
    raw.extension_id ??
    raw.name ??
    crypto.randomUUID();

  const score =
    raw.risk_score ??
    raw.riskScore ??
    raw.score ??
    null;

  const riskLevel =
    normalizeRiskLevel(
      raw.risk_level ??
      raw.riskLevel,
      score
    );

  const permissions =
    raw.permissions ?? {};

  const requestedPermissions =
    Array.isArray(permissions)
      ? permissions
      : (
          permissions.requested ??
          raw.requested_permissions ??
          []
        );

  const driftDetected =
    permissions.drift_detected ??
    raw.permission_drift ??
    raw.drift_detected ??
    false;

  let recommendation =
    raw.recommendation ?? null;

  if (
    typeof recommendation === "string"
  ) {

    recommendation = {

      action: "monitor",

      label: "Monitor",

      text: recommendation

    };
  }

  if (!recommendation) {

    recommendation = {

      action: "monitor",

      label: "Monitor",

      text:
        "Continue monitoring this tool for permission, network, and behavior changes."

    };
  }

  const factors =
    normalizeList(
      raw.factors ??
      raw.risk_factors ??
      raw.riskFactors
    );

  const steps =
    normalizeList(
      raw.steps ??
      raw.investigation_steps ??
      raw.investigationSteps
    );


  /*
     IMPORTANT:
     Preserve more possible source fields so the category
     detection functions above can correctly identify
     extensions, MCP and OAuth records.
  */

  const sourceType =
    raw.source_type ??
    raw.sourceType ??
    raw.detected_via ??
    raw.connector_type ??
    raw.type ??
    raw.meta?.source_type ??
    raw.meta?.sourceType ??
    raw.meta?.type ??
    "Unknown";


  return {

    id,

    name:
      raw.name ??
      raw.tool_name ??
      id,

    vendor:
      raw.vendor ??
      "Unknown vendor",

    sourceType,

    statedFunction:
      raw.stated_function ??
      raw.statedFunction ??
      raw.description ??
      "No stated function available.",

    riskScore:
      score,

    riskLevel,

    verdict:
      raw.verdict ??
      raw.risk_summary ??
      raw.summary ??
      "No risk assessment available.",

    steps,

    factors,

    recommendation,

    permissions:
      requestedPermissions,

    driftDetected,

    firstSeen:
      raw.first_seen ??
      raw.firstSeen ??
      null,

    lastScanned:
      raw.last_scanned ??
      raw.lastScanned ??
      null,

    networkBehavior:
      raw.network_behavior ??
      raw.networkBehavior ??
      null,

    prechecks:
      raw.prechecks ??
      null,

    privacyPolicy:
      raw.privacy_policy ??
      null,

    meta:
      raw.meta ??
      {}

  };
}


/* ----------------------------------------------------------
   RESHAPE AUDIT RESULT
---------------------------------------------------------- */

function mergeAuditIntoTool(entry) {

  const tool =
    entry.tool || {};

  const audit =
    entry.audit || {};

  const steps =
    (audit.trace || [])
      .map(step => ({

        title:
          capitalize(
            step.stage || ""
          ),

        description:
          step.text || ""

      }));

  const factors =
    (audit.factors || [])
      .map(f => ({

        name:
          f.label,

        value:
          f.contribution

      }));

  const recommendation =
    audit.recommendation
      ? {

          action:
            audit.recommendation.action,

          label:
            capitalize(
              audit.recommendation.action ||
              "Monitor"
            ),

          text:
            audit.recommendation.instructions

        }

      : null;


  return {

    ...tool,

    risk_score:
      audit.risk_score ??
      null,

    risk_level:
      audit.risk_level ??
      null,

    verdict:
      audit.verdict_line ??
      null,

    steps,

    factors,

    recommendation

  };
}


/* ----------------------------------------------------------
   APPLY AUDIT RESULTS
---------------------------------------------------------- */

function applySentinelAuditResults(results) {

  if (
    !Array.isArray(results) ||
    !results.length
  ) {
    return;
  }

  TOOLS =
    results.map(
      entry =>
        normalizeForUI(
          mergeAuditIntoTool(entry)
        )
    );

  syncDashboardCards();

  renderRows();

  renderWatchlistView();

  renderExtensionsView();

  renderMcpView();

  renderOAuthView();

  renderDnsView();


  const stillExists =
    TOOLS.some(
      tool =>
        tool.id === selectedToolId
    );

  if (!stillExists) {

    selectedToolId =
      TOOLS[0].id;
  }

  renderPanel(
    selectedToolId
  );
}


window.applySentinelAuditResults =
  applySentinelAuditResults;


/* ----------------------------------------------------------
   STATUS
---------------------------------------------------------- */

function setAgentStatus(online) {

  if (online) {

    statusDotEl.classList.remove(
      "offline"
    );

    statusTextEl.textContent =
      "Local agent";

    if (dashboardAgentStatusEl) {

      dashboardAgentStatusEl.textContent =
        "Online";
    }

  } else {

    statusDotEl.classList.add(
      "offline"
    );

    statusTextEl.textContent =
      "Agent offline";

    if (dashboardAgentStatusEl) {

      dashboardAgentStatusEl.textContent =
        "Offline";
    }
  }
}


function syncDashboardCards() {

  if (dashboardToolCountEl) {

    dashboardToolCountEl.textContent =
      String(TOOLS.length);
  }

  if (dashboardLastScanEl) {

    dashboardLastScanEl.textContent =
      lastScanEl.textContent ||
      "Never";
  }
}


/* ----------------------------------------------------------
   LOAD TOOLS
---------------------------------------------------------- */

async function loadTools() {

  try {

    setAgentStatus(false);


    panelEl.innerHTML = `

      <div class="state">

        <div class="state-inner">

          <div class="state-icon">
            ...
          </div>

          <h1 class="state-title">
            Loading inventory
          </h1>

          <p class="state-text">
            Sentinel is retrieving the latest sensing data.
          </p>

        </div>

      </div>

    `;


    const response =
      await fetch(

        TOOLS_URL,

        {
          method: "GET",
          cache: "no-store"
        }

      );


    if (!response.ok) {

      throw new Error(
        `Local agent returned HTTP ${response.status}`
      );
    }


    const rawTools =
      await response.json();


    if (!Array.isArray(rawTools)) {

      throw new Error(
        "The /tools endpoint did not return an array."
      );
    }


    TOOLS =
      rawTools.map(
        normalizeForUI
      );


    /*
       Debug output.

       Open browser DevTools -> Console and this will show
       exactly how each tool is being classified.
    */

    console.table(

      TOOLS.map(tool => ({

        id:
          tool.id,

        name:
          tool.name,

        sourceType:
          tool.sourceType,

        extension:
          isExtensionTool(tool),

        mcp:
          isMcpTool(tool),

        oauth:
          isOAuthTool(tool),

        dns:
          Boolean(
            tool.networkBehavior
              ?.observed_domains
              ?.length
          )

      }))

    );


    setAgentStatus(true);


    lastScanEl.textContent =
      `Last scan ${new Date().toLocaleTimeString()}`;


    if (countEl) {

      countEl.textContent =
        String(TOOLS.length);
    }


    syncDashboardCards();


    renderWatchlistView();

    renderExtensionsView();

    renderMcpView();

    renderOAuthView();

    renderDnsView();


    if (TOOLS.length === 0) {

      renderRows();

      renderEmptyState();

      return;
    }


    const stillExists =
      TOOLS.some(
        tool =>
          tool.id === selectedToolId
      );


    if (!stillExists) {

      selectedToolId =
        TOOLS[0].id;
    }


    renderRows();

    renderPanel(
      selectedToolId
    );


  } catch (error) {

    console.error(
      "[Sentinel] Failed to load tools:",
      error
    );


    TOOLS = [];


    renderRows();


    if (countEl) {

      countEl.textContent =
        "—";
    }


    renderErrorState(
      error
    );


    setAgentStatus(false);
  }
}

window.loadSentinelTools = loadTools;
/* ----------------------------------------------------------
   TOOL SIDEBAR
---------------------------------------------------------- */

function renderRows() {

  if (!TOOLS.length) {

    toolListEl.innerHTML = `

      <div
        style="
          padding: 18px 12px;
          color: var(--text-dim);
          font-size: 12px;
          line-height: 1.5;
        "
      >
        No tools detected.
      </div>

    `;

    return;
  }


  toolListEl.innerHTML =

    TOOLS
      .map(tool => {

        const active =
          tool.id === selectedToolId
            ? " active"
            : "";


        return `

          <button
            type="button"
            class="tool-row risk-${escapeHtml(tool.riskLevel)}${active}"
            data-tool-id="${escapeHtml(tool.id)}"
          >

            <div class="row-top">

              <span class="name">
                ${escapeHtml(tool.name)}
              </span>

              <span
                class="score risk-${escapeHtml(
                  tool.riskLevel
                )}"
              >
                ${formatScore(
                  tool.riskScore
                )}
              </span>

            </div>


            <div class="meta">

              ${escapeHtml(
                tool.sourceType
              )}

              ·

              ${escapeHtml(
                tool.vendor
              )}

            </div>

          </button>

        `;

      })
      .join("");


  document
    .querySelectorAll(
      ".tool-row"
    )
    .forEach(button => {

      button.addEventListener(

        "click",

        () =>
          selectTool(
            button.dataset.toolId
          )

      );

    });
}


/* ----------------------------------------------------------
   SELECT TOOL
---------------------------------------------------------- */

function selectTool(id) {

  const tool =
    TOOLS.find(
      item =>
        item.id === id
    );


  if (!tool) {
    return;
  }


  selectedToolId =
    id;


  renderRows();


  renderPanel(id);


  const investigation =
    document.querySelector(
      ".investigation"
    );


  investigation?.classList.add(
    "tool-open"
  );
}


/* ----------------------------------------------------------
   MAIN PANEL
---------------------------------------------------------- */

function renderPanel(id) {

  const tool =
    TOOLS.find(
      item =>
        item.id === id
    );


  if (!tool) {

    renderEmptyState();

    return;
  }


  const riskClass =
    tool.riskLevel === "high"

      ? "risk-high"

      : tool.riskLevel === "medium"

        ? "risk-medium"

        : tool.riskLevel === "low"

          ? "risk-low"

          : "risk-unknown";


  panelEl.innerHTML = `

    <div class="panel-header">

      <div class="score-badge ${riskClass}">

        <span class="num">
          ${formatScore(
            tool.riskScore
          )}
        </span>

        <span class="max">
          / 10
        </span>

      </div>


      <div class="titles">

        <h1>
          ${escapeHtml(
            tool.name
          )}
        </h1>


        <div class="vendor">
          ${escapeHtml(
            tool.vendor
          )}
        </div>


        <div class="badge-row">

          <span class="source-badge">
            ${escapeHtml(
              tool.sourceType
            )}
          </span>


          <span class="source-badge">
            Stated function:
            ${escapeHtml(
              tool.statedFunction
            )}
          </span>

        </div>


        <div
          class="verdict ${riskClass}"
        >
          ${escapeHtml(
            tool.verdict
          )}
        </div>

      </div>

    </div>


    <section class="trace">

      <h2>
        Investigation
      </h2>

      ${renderSteps(
        tool.steps
      )}

    </section>


    <section class="factors">

      <h2>
        Score breakdown
      </h2>

      ${renderFactors(
        tool.factors,
        tool.riskLevel
      )}

    </section>


    <section class="trace">

      <h2>
        Permissions
      </h2>

      ${
        tool.driftDetected

          ? `

              <div
                style="
                  color: var(--red);
                  font-size: 0.76rem;
                  margin-bottom: 0.75rem;
                "
              >
                Permission drift detected
              </div>

            `

          : ""
      }


      ${renderPermissions(
        tool.permissions,
        tool.driftDetected
      )}

    </section>


    <section class="trace">

      <h2>
        Assessment
      </h2>


      <div class="verdict">
        ${escapeHtml(
          tool.verdict
        )}
      </div>

    </section>


    <section class="recommendation">

      ${renderRecommendation(
        tool.recommendation
      )}

    </section>


    <section class="trace">

      <h2>
        Observation metadata
      </h2>


      <div class="factor-list">

        <div class="factor">

          <div class="factor-name">
            First seen
          </div>

          <div class="factor-value">
            ${escapeHtml(
              formatTimestamp(
                tool.firstSeen
              )
            )}
          </div>

        </div>


        <div class="factor">

          <div class="factor-name">
            Last scanned
          </div>

          <div class="factor-value">
            ${escapeHtml(
              formatTimestamp(
                tool.lastScanned
              )
            )}
          </div>

        </div>


        <div class="factor">

          <div class="factor-name">
            Source
          </div>

          <div class="factor-value">
            ${escapeHtml(
              tool.sourceType
            )}
          </div>

        </div>


        <div class="factor">

          <div class="factor-name">
            Tool ID
          </div>

          <div class="factor-value">
            ${escapeHtml(
              tool.id
            )}
          </div>

        </div>

      </div>

    </section>

  `;


  animatePanel();
}


/* ----------------------------------------------------------
   INVESTIGATION STEPS
---------------------------------------------------------- */

function renderSteps(steps) {

  if (!steps.length) {

    return `

      <div class="verdict">

        No investigation trace was provided by the local agent.
        Click "Run SentinelAI Audit" to investigate.

      </div>

    `;
  }


  return steps
    .map(
      (step, index) => {

        let title;
        let description;


        if (Array.isArray(step)) {

          title =
            step[0] ??
            `Investigation step ${index + 1}`;

          description =
            step[1] ??
            "";


        } else if (
          typeof step === "string"
        ) {

          title =
            `Investigation step ${index + 1}`;

          description =
            step;


        } else {

          title =
            step.title ??
            step.name ??
            step.action ??
            `Investigation step ${index + 1}`;

          description =
            step.description ??
            step.detail ??
            step.result ??
            "";
        }


        return `

          <div class="trace-step">

            <div class="stage-label">
              ${escapeHtml(
                title
              )}
            </div>

            <div class="text">
              ${formatRichText(
                description
              )}
            </div>

          </div>

        `;
      }
    )
    .join("");
}


function formatRichText(value) {

  const escaped =
    escapeHtml(value);


  return escaped.replace(

    /&lt;span class=&quot;mono-bit&quot;&gt;(.*?)&lt;\/span&gt;/g,

    '<span class="mono-bit">$1</span>'

  );
}


/* ----------------------------------------------------------
   RISK FACTORS
---------------------------------------------------------- */

function renderFactors(
  factors,
  riskLevel
) {

  if (!factors.length) {

    return `

      <div class="verdict">
        No individual risk factors were returned.
      </div>

    `;
  }


  return factors
    .map(
      factor => {

        let name;
        let value;


        if (Array.isArray(factor)) {

          name =
            factor[0] ??
            "Risk factor";

          value =
            factor[1] ??
            0;


        } else if (
          typeof factor === "string"
        ) {

          name =
            "Risk factor";

          value =
            factor;


        } else {

          name =
            factor.name ??
            factor.factor ??
            factor.type ??
            "Risk factor";

          value =
            factor.value ??
            factor.score ??
            factor.description ??
            factor.detail ??
            factor.reason ??
            "";
        }


        const numericValue =
          Number(value);


        const hasNumericValue =
          !Number.isNaN(
            numericValue
          );


        const displayValue =
          hasNumericValue
            ? numericValue.toFixed(1)
            : String(value);


        const width =
          hasNumericValue
            ? Math.max(
                0,
                Math.min(
                  100,
                  numericValue * 10
                )
              )
            : 0;


        return `

          <div class="factor">

            <div class="factor-label">

              <span>
                ${escapeHtml(
                  name
                )}
              </span>

              <span>
                ${escapeHtml(
                  displayValue
                )}
              </span>

            </div>


            <div class="factor-bar-track">

              <div
                class="factor-bar-fill risk-${escapeHtml(
                  riskLevel
                )}"
                data-width="${width}%"
              ></div>

            </div>

          </div>

        `;
      }
    )
    .join("");
}


/* ----------------------------------------------------------
   PERMISSIONS
---------------------------------------------------------- */

function renderPermissions(
  permissions,
  driftDetected
) {

  if (!permissions.length) {

    return `

      <div class="verdict">

        No permissions were reported by the sensing agent.

      </div>

    `;
  }


  const html =
    permissions
      .map(
        permission => {

          const permissionText =
            String(permission);


          const dangerous =
            /tabs|history|cookies|webrequest|management|debugger|downloads|nativeMessaging|<all_urls>|http:|https:/i
              .test(
                permissionText
              );


          return `

            <span
              class="permission ${
                dangerous
                  ? "danger"
                  : ""
              }"
            >
              ${escapeHtml(
                permissionText
              )}
            </span>

          `;
        }
      )
      .join("");


  return `

    <div class="permission-list">
      ${html}
    </div>


    ${
      driftDetected

        ? `

            <div
              style="
                margin-top: 13px;
                color: var(--red);
                font-size: 11px;
                line-height: 1.5;
              "
            >
              The current permission set differs from the previous observed snapshot.
            </div>

          `

        : ""
    }

  `;
}


/* ----------------------------------------------------------
   RECOMMENDATION
---------------------------------------------------------- */

function renderRecommendation(
  recommendation
) {

  const action =
    recommendation?.action ??
    recommendation?.label ??
    "Monitor";


  const label =
    recommendation?.label ??
    capitalize(
      String(action)
    );


  const text =
    recommendation?.text ??
    recommendation?.description ??
    recommendation?.reason ??
    "Continue monitoring this tool.";


  return `

    <span
      class="action-tag ${escapeHtml(
        String(action).toLowerCase()
      )}"
    >
      ${escapeHtml(
        label
      )}
    </span>


    <p>
      ${escapeHtml(
        text
      )}
    </p>

  `;
}


/* ----------------------------------------------------------
   PANEL ANIMATION
---------------------------------------------------------- */

function animatePanel() {

  const steps =
    panelEl.querySelectorAll(
      ".trace-step"
    );


  const bars =
    panelEl.querySelectorAll(
      ".factor-bar-fill"
    );


  steps.forEach(
    (element, index) => {

      const delay =
        reduceMotion
          ? 0
          : index * 260;


      setTimeout(

        () =>
          element.classList.add(
            "revealed"
          ),

        delay

      );

    }
  );


  const barDelay =
    reduceMotion
      ? 0
      : steps.length * 260 + 150;


  setTimeout(

    () => {

      bars.forEach(
        bar => {

          bar.style.width =
            bar.getAttribute(
              "data-width"
            );

        }
      );

    },

    barDelay

  );
}


/* ----------------------------------------------------------
   EMPTY STATE
---------------------------------------------------------- */

function renderEmptyState() {

  panelEl.innerHTML = `

    <div class="state">

      <div class="state-inner">

        <div class="state-icon">
          —
        </div>

        <h1 class="state-title">
          No tools detected
        </h1>

        <p class="state-text">

          Sentinel is connected to the local agent,
          but the current sensing pipeline has not
          returned any tools yet.

        </p>

        <div class="state-code">
          GET /tools → []
        </div>

      </div>

    </div>

  `;
}


/* ----------------------------------------------------------
   ERROR STATE
---------------------------------------------------------- */

function renderErrorState(error) {

  panelEl.innerHTML = `

    <div class="state">

      <div class="state-inner">

        <div
          class="state-icon"
          style="
            color: var(--red);
            border-color: rgba(221, 97, 82, 0.25);
          "
        >
          !
        </div>


        <h1 class="state-title">
          Local agent unavailable
        </h1>


        <p class="state-text">

          Sentinel could not connect to the local FastAPI
          sensing agent. Make sure the server is running
          on port 8787.

        </p>


        <div class="state-code">
          uvicorn server:app --host 127.0.0.1 --port 8787
        </div>


        <p
          style="
            margin-top: 13px;
            color: var(--text-dim);
            font-size: 11px;
          "
        >
          ${escapeHtml(
            error?.message ??
            "Unknown connection error"
          )}
        </p>

      </div>

    </div>

  `;
}


/* ----------------------------------------------------------
   OLD SCAN NOW CODE

   Kept commented out because setup.js owns the current
   "Run SentinelAI Audit" flow.
---------------------------------------------------------- */

/*

async function runScan() {

  scanButtonEl.classList.add("loading");

  scanButtonEl.textContent =
    "Scanning...";

  try {

    if (
      typeof chrome !== "undefined" &&
      chrome.runtime &&
      chrome.runtime.sendMessage
    ) {

      try {

        await new Promise(
          resolve => {

            chrome.runtime.sendMessage(

              {
                type:
                  "SENTINELAI_SCAN_NOW"
              },

              () =>
                resolve()

            );

          }
        );

      } catch (_) {}

    }


    await new Promise(
      resolve =>
        setTimeout(
          resolve,
          400
        )
    );


    await loadTools();


  } finally {

    scanButtonEl.classList.remove(
      "loading"
    );

    scanButtonEl.textContent =
      "Scan now";

  }

}


scanButtonEl.addEventListener(
  "click",
  runScan
);

*/


/* ----------------------------------------------------------
   INITIAL LOAD
---------------------------------------------------------- */

loadTools();


/* ----------------------------------------------------------
   VIEW NAVIGATION
---------------------------------------------------------- */

const navItems =
  document.querySelectorAll(
    ".nav-item"
  );


const pageViews =
  document.querySelectorAll(
    ".page-view"
  );


function showView(viewName) {

  pageViews.forEach(
    view =>
      view.classList.remove(
        "active"
      )
  );


  navItems.forEach(
    item =>
      item.classList.remove(
        "active"
      )
  );


  const view =
    document.getElementById(
      `view-${viewName}`
    );


  const nav =
    document.querySelector(
      `.nav-item[data-view="${viewName}"]`
    );


  if (view) {

    view.classList.add(
      "active"
    );
  }


  if (nav) {

    nav.classList.add(
      "active"
    );
  }
}


navItems.forEach(
  item => {

    item.addEventListener(
      "click",
      () => {

        const view =
          item.dataset.view;


        showView(view);


        if (
          view === "tools"
        ) {

          document
            .querySelector(
              ".investigation"
            )
            ?.classList.remove(
              "tool-open"
            );
        }

      }
    );

  }
);


const backButton =
  document.getElementById(
    "back-to-tools"
  );


backButton?.addEventListener(
  "click",
  () => {

    document
      .querySelector(
        ".investigation"
      )
      ?.classList.remove(
        "tool-open"
      );

  }
);


/* ----------------------------------------------------------
   GOOGLE HANDLING

   #connect-google is intentionally handled by setup.js.
---------------------------------------------------------- */


/* ----------------------------------------------------------
   ACTIVITY LOG
---------------------------------------------------------- */

const ACTIVITY_LOG = [];


function logActivity(message) {

  ACTIVITY_LOG.unshift({

    message,

    time:
      new Date()

  });


  if (
    ACTIVITY_LOG.length > 30
  ) {

    ACTIVITY_LOG.pop();

  }


  renderActivityView();
}


function renderActivityView() {

  const panel =
    document.getElementById(
      "activity-panel"
    );


  if (!panel) {
    return;
  }


  if (
    !ACTIVITY_LOG.length
  ) {

    panel.innerHTML = `

      <div class="empty-state">

        <div class="empty-icon">
          ◷
        </div>

        <h2>
          No activity yet
        </h2>

        <p>
          Scan activity will appear here.
        </p>

      </div>

    `;

    return;
  }


  panel.innerHTML =
    ACTIVITY_LOG
      .map(
        entry => `

          <div class="activity-row">

            <span class="meta">
              ${escapeHtml(
                entry.message
              )}
            </span>

            <span class="time">
              ${entry.time.toLocaleTimeString()}
            </span>

          </div>

        `
      )
      .join("");
}


/* ----------------------------------------------------------
   WATCHLIST VIEW
---------------------------------------------------------- */

function renderWatchlistView() {

  const panel =
    document.getElementById(
      "watchlist-panel"
    );


  if (!panel) {
    return;
  }


  const flagged =
    TOOLS.filter(
      t =>

        t.riskLevel === "high" ||

        [
          "revoke",
          "restrict"
        ].includes(
          t.recommendation?.action
        )
    );


  if (!flagged.length) {

    panel.innerHTML = `

      <div class="empty-state">

        <div class="empty-icon">
          ◇
        </div>

        <h2>
          Nothing flagged
        </h2>

        <p>

          Tools needing attention after an audit
          will appear here.

        </p>

      </div>

    `;

    return;
  }


  panel.innerHTML =
    flagged
      .map(
        t => `

          <div class="watchlist-row">

            <div>

              <div class="name">
                ${escapeHtml(
                  t.name
                )}
              </div>

              <div class="meta">

                ${escapeHtml(
                  t.vendor
                )}

                ·

                ${escapeHtml(
                  t.recommendation?.label ||
                  "Flagged"
                )}

              </div>

            </div>


            <span
              class="score risk-${escapeHtml(
                t.riskLevel
              )}"
            >
              ${formatScore(
                t.riskScore
              )}
            </span>

          </div>

        `
      )
      .join("");
}


/* ----------------------------------------------------------
   CATEGORY VIEWS
---------------------------------------------------------- */

function jumpToToolInvestigation(id) {

  showView("tools");

  selectTool(id);
}


function renderCategoryList(
  containerId,
  tools,
  emptyIcon,
  emptyTitle,
  emptyText,
  rowRenderer
) {

  const panel =
    document.getElementById(
      containerId
    );


  if (!panel) {
    return;
  }


  if (!tools.length) {

    panel.innerHTML = `

      <div class="empty-state">

        <div class="empty-icon">
          ${emptyIcon}
        </div>

        <h2>
          ${escapeHtml(
            emptyTitle
          )}
        </h2>

        <p>
          ${escapeHtml(
            emptyText
          )}
        </p>

      </div>

    `;

    return;
  }


  panel.innerHTML =
    tools
      .map(
        rowRenderer
      )
      .join("");


  panel
    .querySelectorAll(
      "[data-tool-id]"
    )
    .forEach(
      row => {

        row.addEventListener(
          "click",
          () =>
            jumpToToolInvestigation(
              row.dataset.toolId
            )
        );

      }
    );
}


/* ----------------------------------------------------------
   EXTENSIONS VIEW
---------------------------------------------------------- */

function renderExtensionsView() {

  const extensionTools =
    TOOLS.filter(
      isExtensionTool
    );


  renderCategoryList(

    "extensions-panel",

    extensionTools,

    "▣",

    "No browser extensions found",

    "SentinelAI has not detected any browser extensions yet.",

    t => `

      <div
        class="watchlist-row"
        data-tool-id="${escapeHtml(
          t.id
        )}"
        style="cursor:pointer;"
      >

        <div>

          <div class="name">
            ${escapeHtml(
              t.name
            )}
          </div>

          <div class="meta">

            ${escapeHtml(
              t.vendor
            )}

            ·

            ${t.permissions.length}

            permission${
              t.permissions.length === 1
                ? ""
                : "s"
            }

          </div>

        </div>


        <span
          class="score risk-${escapeHtml(
            t.riskLevel
          )}"
        >
          ${formatScore(
            t.riskScore
          )}
        </span>

      </div>

    `
  );
}


/* ----------------------------------------------------------
   MCP VIEW
---------------------------------------------------------- */

function renderMcpView() {

  const mcpTools =
    TOOLS.filter(
      isMcpTool
    );


  renderCategoryList(

    "mcp-panel",

    mcpTools,

    "⌘",

    "No MCP connectors found",

    "SentinelAI checks known Claude Desktop / MCP client config locations.",

    t => `

      <div
        class="watchlist-row"
        data-tool-id="${escapeHtml(
          t.id
        )}"
        style="cursor:pointer;"
      >

        <div>

          <div class="name">
            ${escapeHtml(
              t.name
            )}
          </div>

          <div class="meta">

            ${escapeHtml(
              t.vendor
            )}

            ·

            ${t.permissions.length}

            capabilit${
              t.permissions.length === 1
                ? "y"
                : "ies"
            }

          </div>

        </div>


        <span
          class="score risk-${escapeHtml(
            t.riskLevel
          )}"
        >
          ${formatScore(
            t.riskScore
          )}
        </span>

      </div>

    `
  );
}


/* ----------------------------------------------------------
   OAUTH VIEW
---------------------------------------------------------- */

function renderOAuthView() {

  const oauthTools =
    TOOLS.filter(
      isOAuthTool
    );


  renderCategoryList(

    "oauth-panel",

    oauthTools,

    "◎",

    "No connected apps found",

    "Connect Google from the Dashboard, then run a scan to populate this.",

    t => `

      <div
        class="watchlist-row"
        data-tool-id="${escapeHtml(
          t.id
        )}"
        style="cursor:pointer;"
      >

        <div>

          <div class="name">
            ${escapeHtml(
              t.name
            )}
          </div>


          <div class="meta">

            ${escapeHtml(
              t.vendor
            )}

            ·

            ${t.permissions.length}

            scope${
              t.permissions.length === 1
                ? ""
                : "s"
            }

          </div>

        </div>


        <span
          class="score risk-${escapeHtml(
            t.riskLevel
          )}"
        >
          ${formatScore(
            t.riskScore
          )}
        </span>

      </div>

    `
  );
}


/* ----------------------------------------------------------
   DNS VIEW
---------------------------------------------------------- */

function renderDnsView() {

  const dnsTools =
    TOOLS.filter(
      t =>
        (
          t.networkBehavior
            ?.observed_domains
            ?.length ||
          0
        ) > 0
    );


  renderCategoryList(

    "dns-panel",

    dnsTools,

    "◌",

    "No DNS activity observed",

    "Tools whose network traffic matches their vendor domain will appear here.",

    t => `

      <div
        class="watchlist-row"
        data-tool-id="${escapeHtml(
          t.id
        )}"
        style="cursor:pointer;"
      >

        <div>

          <div class="name">
            ${escapeHtml(
              t.name
            )}
          </div>


          <div class="meta">

            ${
              t.networkBehavior
                .observed_domains
                .map(
                  escapeHtml
                )
                .join(", ")
            }

          </div>

        </div>


        <span
          class="score risk-${escapeHtml(
            t.riskLevel
          )}"
        >
          ${formatScore(
            t.riskScore
          )}
        </span>

      </div>

    `
  );
}


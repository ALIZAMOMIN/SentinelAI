(() => {
  "use strict";

  /*
   * SentinelAI MAIN-WORLD web sensor.
   *
   * This file MUST be injected with:
   *
   * chrome.scripting.executeScript({
   *   world: "MAIN",
   *   files: ["content/web-sensor.js"]
   * });
   *
   * It cannot use chrome.runtime directly.
   * It communicates with web-sensor-bridge.js
   * through window.postMessage().
   */


  if (window.__SENTINELAI_WEB_SENSOR_LOADED__) {
    return;
  }

  window.__SENTINELAI_WEB_SENSOR_LOADED__ = true;


  const MESSAGE_SOURCE = "sentinelai-web-sensor";


  // ---------------------------------------------------------------------------
  // Configuration
  // ---------------------------------------------------------------------------

  const MCP_PATH_HINTS = [
    "/mcp",
    "/mcp/",
    "/mcp-server",
    "/mcp-server/",
    "/model-context-protocol",
    "/jsonrpc",
    "/rpc",
    "/sse",
    "/stream"
  ];


  const MCP_METHODS = new Set([
    "initialize",
    "initialized",

    "tools/list",
    "tools/call",

    "resources/list",
    "resources/read",
    "resources/templates/list",
    "resources/subscribe",
    "resources/unsubscribe",

    "prompts/list",
    "prompts/get",

    "completion/complete",

    "logging/setlevel",

    "roots/list",

    "sampling/createMessage",

    "ping"
  ]);


  const CONNECTOR_TERMS = [
    "mcp",
    "model context protocol",
    "connector",
    "connectors",
    "integration",
    "integrations",
    "connected app",
    "connected apps",
    "plugin",
    "plugins",
    "tool",
    "tools"
  ];


  const SENSITIVE_QUERY_PARAMS = [
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


  // ---------------------------------------------------------------------------
  // Generic helpers
  // ---------------------------------------------------------------------------

  function nowIso() {
    return new Date().toISOString();
  }


  function postObservation(observation) {
    try {
      window.postMessage(
        {
          source: MESSAGE_SOURCE,
          observation
        },
        window.location.origin
      );
    } catch (_) {
      // Ignore messaging failures.
    }
  }


  function sanitizeUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== "string") {
      return null;
    }

    try {
      const url = new URL(rawUrl, window.location.href);

      if (url.protocol !== "http:" && url.protocol !== "https:") {
        return null;
      }

      url.username = "";
      url.password = "";
      url.hash = "";

      for (const param of SENSITIVE_QUERY_PARAMS) {
        url.searchParams.delete(param);
      }

      return url.toString();

    } catch (_) {
      return null;
    }
  }


  function getUrlPath(rawUrl) {
    try {
      const url = new URL(rawUrl, window.location.href);
      return `${url.pathname}${url.search}`.toLowerCase();
    } catch (_) {
      return "";
    }
  }


  function urlHasMcpHint(rawUrl) {
    const path = getUrlPath(rawUrl);
    return MCP_PATH_HINTS.some(hint => path.includes(hint));
  }


  // ---------------------------------------------------------------------------
  // JSON-RPC / MCP inspection
  // ---------------------------------------------------------------------------

  function isJsonRpcObject(value) {
    if (!value || typeof value !== "object") {
      return false;
    }

    return (
      value.jsonrpc === "2.0" ||
      typeof value.method === "string" ||
      typeof value.result === "object" ||
      typeof value.error === "object"
    );
  }


  function extractMethods(value, output = []) {
    if (!value) {
      return output;
    }

    if (Array.isArray(value)) {
      for (const item of value.slice(0, 20)) {
        extractMethods(item, output);
      }

      return output;
    }

    if (typeof value !== "object") {
      return output;
    }

    if (typeof value.method === "string") {
      output.push(value.method);
    }

    if (value.result && typeof value.result === "object") {
      extractMethods(value.result, output);
    }

    if (value.error && typeof value.error === "object") {
      extractMethods(value.error, output);
    }

    return output;
  }


  function inspectJsonValue(value) {
    const signals = [];

    if (!isJsonRpcObject(value)) {
      return signals;
    }

    const methods = extractMethods(value);

    for (const method of methods) {
      if (MCP_METHODS.has(method)) {
        signals.push(`method:${method}`);
      }

      if (
        typeof method === "string" &&
        (method.startsWith("tools/") ||
          method.startsWith("resources/") ||
          method.startsWith("prompts/"))
      ) {
        signals.push(`mcp_method:${method}`);
      }
    }


    if (value.result && typeof value.result === "object") {

      if (Array.isArray(value.result.tools)) {
        signals.push("result:tools");
      }

      if (Array.isArray(value.result.resources)) {
        signals.push("result:resources");
      }

      if (Array.isArray(value.result.prompts)) {
        signals.push("result:prompts");
      }

      if (value.result.serverInfo && typeof value.result.serverInfo === "object") {
        signals.push("result:serverInfo");
      }

      if (value.result.capabilities && typeof value.result.capabilities === "object") {
        signals.push("result:capabilities");
      }
    }

    return [...new Set(signals)];
  }


  function inspectText(text) {
    if (!text || typeof text !== "string") {
      return [];
    }

    /*
     * Safety:
     * never send the body to the extension.
     * It is only inspected locally.
     */

    const trimmed = text.trim();

    if (!trimmed || trimmed.length > 500000) {
      return [];
    }


    try {
      const parsed = JSON.parse(trimmed);
      return inspectJsonValue(parsed);

    } catch (_) {
      const signals = [];

      for (const method of MCP_METHODS) {
        if (trimmed.includes(`"${method}"`) || trimmed.includes(`'${method}'`)) {
          signals.push(`method:${method}`);
        }
      }

      return [...new Set(signals)];
    }
  }


  function confidenceFor(signals, urlHint) {
    const strongSignals = signals.filter(
      signal =>
        signal.startsWith("method:") ||
        signal.startsWith("mcp_method:") ||
        signal === "result:tools" ||
        signal === "result:resources" ||
        signal === "result:prompts"
    );

    if (strongSignals.length > 0) {
      return "high";
    }

    if (urlHint || signals.length > 0) {
      return "medium";
    }

    return "low";
  }


  function emitMcpObservation({ rawUrl, transport, signals = [], extraEvidence = [] }) {
    const cleanEndpoint = sanitizeUrl(rawUrl);

    if (!cleanEndpoint) {
      return;
    }

    const urlHint = urlHasMcpHint(rawUrl);

    const uniqueSignals = [...new Set(signals)];

    if (urlHint) {
      uniqueSignals.push("url:mcp_hint");
    }

    const finalSignals = [...new Set(uniqueSignals)];

    if (finalSignals.length === 0) {
      return;
    }

    postObservation({
      type: "mcp_activity_signal",
      endpoint: cleanEndpoint,
      confidence: confidenceFor(finalSignals, urlHint),
      transport,
      signals: finalSignals.slice(0, 30),

      evidence: ["browser_protocol_observation", ...extraEvidence].slice(0, 10),

      timestamp: nowIso()
    });
  }


  // ---------------------------------------------------------------------------
  // FETCH interception
  // ---------------------------------------------------------------------------

  const originalFetch = window.fetch;


  if (typeof originalFetch === "function") {

    window.fetch = async function (...args) {

      let requestUrl = null;
      let requestBody = null;


      try {
        const input = args[0];
        const init = args[1];


        if (typeof input === "string") {
          requestUrl = input;

        } else if (input && typeof input.url === "string") {
          requestUrl = input.url;
        }


        if (init && typeof init.body === "string") {
          requestBody = init.body;
        }


        if (!requestBody && input && typeof input.body === "string") {
          requestBody = input.body;
        }

      } catch (_) {}


      const requestSignals = [];


      if (requestBody) {
        requestSignals.push(...inspectText(requestBody));
      }


      if (requestUrl && (urlHasMcpHint(requestUrl) || requestSignals.length > 0)) {
        emitMcpObservation({
          rawUrl: requestUrl,
          transport: "fetch",
          signals: requestSignals,
          extraEvidence: ["fetch_request"]
        });
      }


      let response;

      try {
        response = await originalFetch.apply(this, args);

      } catch (error) {
        throw error;
      }


      try {
        const responseUrl = response?.url || requestUrl || window.location.href;

        const contentType = response?.headers?.get("content-type") || "";

        const responseSignals = [];


        if (
          contentType.includes("json") ||
          contentType.includes("text/event-stream") ||
          urlHasMcpHint(responseUrl)
        ) {

          try {
            const cloned = response.clone();
            const text = await cloned.text();

            responseSignals.push(...inspectText(text));

          } catch (_) {}
        }


        if (
          urlHasMcpHint(responseUrl) ||
          responseSignals.length > 0 ||
          requestSignals.length > 0
        ) {
          emitMcpObservation({
            rawUrl: responseUrl,
            transport: "fetch",
            signals: [...requestSignals, ...responseSignals],
            extraEvidence: ["fetch_request_or_response"]
          });
        }

      } catch (_) {}


      return response;
    };
  }


  // ---------------------------------------------------------------------------
  // XMLHttpRequest
  // ---------------------------------------------------------------------------

  const originalXhrOpen = XMLHttpRequest.prototype.open;
  const originalXhrSend = XMLHttpRequest.prototype.send;


  XMLHttpRequest.prototype.open = function (method, url, ...rest) {

    try {
      this.__sentinelai_url = url;
      this.__sentinelai_method = method;
    } catch (_) {}


    return originalXhrOpen.call(this, method, url, ...rest);
  };


  XMLHttpRequest.prototype.send = function (body) {

    const xhr = this;


    try {
      const rawUrl = xhr.__sentinelai_url;

      const requestSignals = [];


      if (typeof body === "string") {
        requestSignals.push(...inspectText(body));
      }


      if (rawUrl && (urlHasMcpHint(rawUrl) || requestSignals.length > 0)) {
        emitMcpObservation({
          rawUrl,
          transport: "xhr",
          signals: requestSignals,
          extraEvidence: ["xhr_request"]
        });
      }


      const onLoad = () => {

        try {
          const responseSignals = [];

          const contentType = xhr.getResponseHeader("content-type") || "";


          if (
            contentType.includes("json") ||
            contentType.includes("text") ||
            urlHasMcpHint(rawUrl)
          ) {

            if (typeof xhr.responseText === "string") {
              responseSignals.push(...inspectText(xhr.responseText));
            }
          }


          if (
            urlHasMcpHint(rawUrl) ||
            requestSignals.length > 0 ||
            responseSignals.length > 0
          ) {
            emitMcpObservation({
              rawUrl,
              transport: "xhr",
              signals: [...requestSignals, ...responseSignals],
              extraEvidence: ["xhr_request_or_response"]
            });
          }

        } catch (_) {}
      };


      xhr.addEventListener("load", onLoad, { once: true });

    } catch (_) {}


    return originalXhrSend.call(this, body);
  };


  // ---------------------------------------------------------------------------
  // EventSource / SSE
  // ---------------------------------------------------------------------------

  if (typeof window.EventSource === "function") {

    const OriginalEventSource = window.EventSource;


    window.EventSource = function (url, config) {

      try {
        if (urlHasMcpHint(url)) {
          emitMcpObservation({
            rawUrl: url,
            transport: "sse",
            signals: ["transport:sse"],
            extraEvidence: ["eventsource_connection"]
          });
        }

      } catch (_) {}


      return new OriginalEventSource(url, config);
    };


    window.EventSource.prototype = OriginalEventSource.prototype;
    window.EventSource.CONNECTING = OriginalEventSource.CONNECTING;
    window.EventSource.OPEN = OriginalEventSource.OPEN;
    window.EventSource.CLOSED = OriginalEventSource.CLOSED;
  }


  // ---------------------------------------------------------------------------
  // WebSocket
  // ---------------------------------------------------------------------------

  if (typeof window.WebSocket === "function") {

    const OriginalWebSocket = window.WebSocket;


    window.WebSocket = function (url, protocols) {

      const socket =
        protocols === undefined
          ? new OriginalWebSocket(url)
          : new OriginalWebSocket(url, protocols);


      try {

        if (urlHasMcpHint(url)) {
          emitMcpObservation({
            rawUrl: url,
            transport: "websocket",
            signals: ["transport:websocket"],
            extraEvidence: ["websocket_connection"]
          });
        }


        socket.addEventListener("message", event => {

          try {
            const signals =
              typeof event.data === "string" ? inspectText(event.data) : [];


            if (signals.length > 0 || urlHasMcpHint(url)) {
              emitMcpObservation({
                rawUrl: url,
                transport: "websocket",
                signals,
                extraEvidence: ["websocket_message"]
              });
            }

          } catch (_) {}
        });

      } catch (_) {}


      return socket;
    };


    window.WebSocket.prototype = OriginalWebSocket.prototype;
    window.WebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
    window.WebSocket.OPEN = OriginalWebSocket.OPEN;
    window.WebSocket.CLOSING = OriginalWebSocket.CLOSING;
    window.WebSocket.CLOSED = OriginalWebSocket.CLOSED;
  }


  // ---------------------------------------------------------------------------
  // Performance resource scan
  // ---------------------------------------------------------------------------

  function scanPerformanceResources() {
    try {
      const resources = performance.getEntriesByType("resource");


      for (const resource of resources) {

        const rawUrl = resource.name;


        if (!urlHasMcpHint(rawUrl)) {
          continue;
        }


        emitMcpObservation({
          rawUrl,
          transport: "browser_resource",
          signals: ["resource:mcp_hint"],
          extraEvidence: ["browser_resource_url"]
        });
      }

    } catch (_) {}
  }


  // ---------------------------------------------------------------------------
  // Connector UI detection
  // ---------------------------------------------------------------------------

  function scanConnectorUi() {
    try {

      const elements = document.querySelectorAll(
        "button, [role='button'], [role='menuitem'], a"
      );


      const found = new Set();


      for (const element of elements) {

        const text = (
          element.getAttribute("aria-label") ||
          element.getAttribute("title") ||
          element.innerText ||
          ""
        )
          .trim()
          .toLowerCase();


        if (!text) {
          continue;
        }


        for (const term of CONNECTOR_TERMS) {

          if (text.includes(term)) {
            found.add(term);
          }
        }
      }


      for (const term of found) {

        postObservation({
          type: "connector_ui_signal",
          evidence: [term],
          timestamp: nowIso()
        });
      }

    } catch (_) {}
  }


  // ---------------------------------------------------------------------------
  // Google linked apps
  // ---------------------------------------------------------------------------

  function isGoogleAccountPage() {
    try {
      const url = new URL(window.location.href);

      return (
        url.hostname === "myaccount.google.com" ||
        url.hostname.endsWith(".myaccount.google.com")
      );

    } catch (_) {
      return false;
    }
  }


  // The app list itself only lives on /connections (it used to be
  // /permissions, then /linkedapps -- Google has moved this before and
  // may move it again). Gate the actual DOM-extraction pass on this,
  // separately from the broader isGoogleAccountPage() host check, so a
  // scan doesn't try to extract app names from some other Google
  // Account subpage that doesn't have them.
  function isGoogleConnectionsPage() {
    if (!isGoogleAccountPage()) {
      return false;
    }

    try {
      const url = new URL(window.location.href);
      return url.pathname.startsWith("/connections");
    } catch (_) {
      return false;
    }
  }


  function normalizeAppCandidate(text) {
    if (!text || typeof text !== "string") {
      return null;
    }


    const value = text.replace(/\s+/g, " ").trim();


    if (value.length < 2 || value.length > 150) {
      return null;
    }


    return value;
  }


  function scanGoogleLinkedApps() {
    if (!isGoogleConnectionsPage()) {
      console.log(
        "[SentinelAI Google] Not the connections page, skipping:",
        location.href
      );

      return;
    }

    console.log("[SentinelAI Google] ===== LINKED APP SCAN START =====");
    console.log("[SentinelAI Google] URL:", location.href);
    console.log("[SentinelAI Google] Title:", document.title);

    const bodyText = document.body?.innerText || "";

    console.log(
      "[SentinelAI Google] Body preview:",
      bodyText.slice(0, 5000)
    );

    const pageSignalTerms = [
      "linked apps",
      "linked app",
      "third-party apps",
      "third-party app",
      "sign in with google",
      "access to your google account",
      "has some access to your google account",
      "see details",
      "google has some access"
    ];

    const foundSignals = pageSignalTerms.filter(signal =>
      bodyText.toLowerCase().includes(signal)
    );

    console.log("[SentinelAI Google] Found page signals:", foundSignals);

    // Dump interactive elements. Kept for ongoing selector debugging --
    // Google doesn't expose stable data-testid-style hooks here, so
    // this is the fastest way to see what actually needs to be
    // targeted when Google next changes the markup.
    const interactive = [
      ...document.querySelectorAll(
        "button, a, [role='button'], [role='link'], [role='heading']"
      )
    ];

    console.log("[SentinelAI Google] Interactive elements:", interactive.length);

    interactive.slice(0, 300).forEach((el, index) => {
      const text = (el.innerText || el.textContent || "")
        .replace(/\s+/g, " ")
        .trim();

      const aria = el.getAttribute("aria-label") || "";
      const title = el.getAttribute("title") || "";
      const href = el.href || "";

      if (text || aria || title || href) {
        console.log("[SentinelAI Google] ELEMENT", index, {
          tag: el.tagName,
          text: text.slice(0, 200),
          aria: aria.slice(0, 200),
          title: title.slice(0, 200),
          href: href.slice(0, 300)
        });
      }
    });

    // Page-level signal, same shape as before.
    postObservation({
      type: "google_linked_apps_page",
      page_url: sanitizeUrl(location.href),
      timestamp: nowIso(),
      signals: foundSignals
    });

    // -------------------------------------------------------------------
    // Per-app extraction.
    //
    // Heuristic first pass: walk headings/links/buttons, drop obvious
    // chrome (nav labels, help text, etc.), and treat what's left as
    // app-name candidates. This is NOT verified against Google's
    // current /connections markup -- use the element dump above (or
    // DevTools -> Inspect on a real app row) to tighten the ignore
    // list and filters below if candidates come out missing or noisy.
    // -------------------------------------------------------------------

    const elements = document.querySelectorAll(
      "h1, h2, h3, h4, [role='heading'], a, button"
    );

    const candidates = new Set();

    const ignored = [
      "google account",
      "privacy",
      "security",
      "personal info",
      "data & privacy",
      "people & sharing",
      "payments & subscriptions",
      "help",
      "search",
      "home",
      "see all",
      "learn more",
      "manage",
      "remove access",
      "see details",
      "sign in with google",
      "linked apps",
      "linked app",
      "third-party apps",
      "third-party app",
      "access to your google account"
    ];

    for (const element of elements) {

      try {
        const rect = element.getBoundingClientRect();

        if (rect.width === 0 || rect.height === 0) {
          continue;
        }

        const text = normalizeAppCandidate(
          element.innerText ||
            element.textContent ||
            element.getAttribute("aria-label") ||
            ""
        );

        if (!text) {
          continue;
        }

        const lower = text.toLowerCase();

        if (ignored.some(value => lower === value)) {
          continue;
        }

        if (
          lower.length > 100 ||
          lower.includes("you can") ||
          lower.includes("learn how") ||
          lower.includes("review or") ||
          lower.includes("select the")
        ) {
          continue;
        }

        candidates.add(text);

      } catch (_) {}
    }

    console.log("[SentinelAI Google] App name candidates:", [...candidates]);

    for (const appName of [...candidates].slice(0, 50)) {

      postObservation({
        type: "google_linked_app",
        app_name: appName,
        evidence: ["visible_google_account_ui"],
        timestamp: nowIso()
      });
    }

    console.log("[SentinelAI Google] ===== LINKED APP SCAN END =====");
  }


  // ---------------------------------------------------------------------------
  // Initial scan
  // ---------------------------------------------------------------------------

  function runInitialScan() {
    scanPerformanceResources();
    scanConnectorUi();
    scanGoogleLinkedApps();
  }

  console.log("[SentinelAI SENSOR DEBUG] Running one-shot initial scan.");

  runInitialScan();

})();
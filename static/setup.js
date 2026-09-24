/* ----------------------------------------------------------
   SENTINELAI SETUP / GOOGLE OAUTH
---------------------------------------------------------- */

const GOOGLE_STATUS_URL =
  "/oauth/status";

const GOOGLE_CONNECT_URL =
  "/oauth/google/start";

const GOOGLE_DISCONNECT_URL =
  "/oauth/google/disconnect";

const AUDIT_URL =
  "/audit/run";


/* ----------------------------------------------------------
   DOM
---------------------------------------------------------- */

const googleSetupCard =
  document.getElementById(
    "setup-google"
  );

const connectGoogleButton =
  document.getElementById(
    "connect-google"
  );

const disconnectGoogleButton =
  document.getElementById(
    "disconnect-google"
  );

const runAuditButton =
  document.getElementById(
    "run-audit"
  );

const auditStatus =
  document.getElementById(
    "audit-status"
  );


/* ----------------------------------------------------------
   GOOGLE UI HELPERS
---------------------------------------------------------- */

function getGoogleStatusElement() {

  if (!googleSetupCard) {
    return null;
  }

  return googleSetupCard.querySelector(
    ".setup-card-status"
  );
}


function getGoogleIndicator() {

  if (!googleSetupCard) {
    return null;
  }

  return googleSetupCard.querySelector(
    ".setup-status"
  );
}


function setGoogleUI(
  connected,
  email = null
) {

  const indicator =
    getGoogleIndicator();

  const status =
    getGoogleStatusElement();


  if (
    connected
  ) {

    /* ------------------------------------------------------
       CONNECTED
    ------------------------------------------------------ */

    if (indicator) {

      indicator.classList.remove(
        "pending"
      );

      indicator.classList.add(
        "connected"
      );
    }


    if (connectGoogleButton) {

      connectGoogleButton.style.display =
        "none";

    }


    if (disconnectGoogleButton) {

      disconnectGoogleButton.style.display =
        "inline-flex";

      disconnectGoogleButton.disabled =
        false;

    }


    if (status) {

      if (email) {

        status.textContent =
          `Connected as ${email}`;

      } else {

        status.textContent =
          "Google account connected";

      }

    }

  } else {

    /* ------------------------------------------------------
       DISCONNECTED
    ------------------------------------------------------ */

    if (indicator) {

      indicator.classList.remove(
        "connected"
      );

      indicator.classList.add(
        "pending"
      );
    }


    if (connectGoogleButton) {

      connectGoogleButton.style.display =
        "inline-flex";

      connectGoogleButton.disabled =
        false;

    }


    if (disconnectGoogleButton) {

      disconnectGoogleButton.style.display =
        "none";

      disconnectGoogleButton.disabled =
        false;

    }


    if (status) {

      status.textContent =
        "Not connected";

    }
  }
}


/* ----------------------------------------------------------
   GET REAL GOOGLE CONNECTION STATE
---------------------------------------------------------- */

async function refreshGoogleStatus() {

  try {

    const response =
      await fetch(
        GOOGLE_STATUS_URL,
        {
          method: "GET",
          cache: "no-store",
          credentials: "same-origin"
        }
      );


    if (!response.ok) {

      throw new Error(
        `OAuth status returned HTTP ${response.status}`
      );
    }


    const data =
      await response.json();


    const google =
      data?.google || {};


    setGoogleUI(
      Boolean(
        google.connected
      ),
      google.email || null
    );


    return google;


  } catch (error) {

    console.error(
      "[Sentinel] Failed to load Google OAuth status:",
      error
    );


    /*
       Do not assume connected when status lookup fails.
       Show the safe/disconnected state.
    */

    setGoogleUI(
      false,
      null
    );

    return null;
  }
}


/* ----------------------------------------------------------
   GOOGLE CONNECT
---------------------------------------------------------- */

connectGoogleButton?.addEventListener(
  "click",
  () => {

    connectGoogleButton.disabled =
      true;

    connectGoogleButton.textContent =
      "Connecting...";

    window.location.href =
      GOOGLE_CONNECT_URL;
  }
);


/* ----------------------------------------------------------
   GOOGLE DISCONNECT
---------------------------------------------------------- */

disconnectGoogleButton?.addEventListener(
  "click",
  async () => {

    if (
      disconnectGoogleButton.disabled
    ) {
      return;
    }


    disconnectGoogleButton.disabled =
      true;

    disconnectGoogleButton.textContent =
      "Disconnecting...";


    try {

      const response =
        await fetch(
          GOOGLE_DISCONNECT_URL,
          {
            method: "POST",
            credentials: "same-origin",
            headers: {
              "Content-Type":
                "application/json"
            }
          }
        );


      if (!response.ok) {

        const text =
          await response.text();

        throw new Error(
          `Disconnect failed (${response.status}): ${text}`
        );
      }


      const data =
        await response.json();


      if (
        data?.connected === false
      ) {

        setGoogleUI(
          false,
          null
        );

      } else {

        await refreshGoogleStatus();

      }


      /*
         Refresh the inventory because Google OAuth records
         may have been removed from the backend.
      */

      if (
        typeof window.applySentinelAuditResults ===
        "function"
      ) {
        /*
           Do nothing here.
           Audit results should not be replaced by empty data.
        */
      }


      /*
         Reload the sensing inventory if script.js exposes
         loadTools globally in a future version.
      */

      if (
        typeof window.loadSentinelTools ===
        "function"
      ) {

        await window.loadSentinelTools();

      }


    } catch (error) {

      console.error(
        "[Sentinel] Google disconnect failed:",
        error
      );


      /*
         Check the actual backend state instead
         of guessing.
      */

      await refreshGoogleStatus();


    } finally {

      if (disconnectGoogleButton) {

        disconnectGoogleButton.textContent =
          "Disconnect Google";

        disconnectGoogleButton.disabled =
          false;
      }

    }
  }
);


/* ----------------------------------------------------------
   RUN SENTINELAI AUDIT
---------------------------------------------------------- */

runAuditButton?.addEventListener(
  "click",
  async () => {

    if (
      runAuditButton.disabled
    ) {
      return;
    }


    runAuditButton.disabled =
      true;

    runAuditButton.textContent =
      "Running Audit...";


    if (auditStatus) {

      auditStatus.textContent =
        "SentinelAI is auditing your connected tools...";
    }


    try {

      const response =
        await fetch(
          AUDIT_URL,
          {
            method: "POST",
            credentials: "same-origin",
            headers: {
              "Content-Type":
                "application/json"
            }
          }
        );


      if (!response.ok) {

        const text =
          await response.text();

        throw new Error(
          `Audit failed (${response.status}): ${text}`
        );
      }


      const data =
        await response.json();


      if (
        window.applySentinelAuditResults
      ) {

        window.applySentinelAuditResults(
          data.results || []
        );

      }


      if (auditStatus) {

        auditStatus.textContent =
          `Audit complete — ${data.audited ?? 0} tools audited.`;
      }


    } catch (error) {

      console.error(
        "[Sentinel] Audit failed:",
        error
      );


      if (auditStatus) {

        auditStatus.textContent =
          `Audit failed: ${error.message}`;
      }


    } finally {

      runAuditButton.disabled =
        false;

      runAuditButton.textContent =
        "Run SentinelAI Audit";

    }
  }
);


/* ----------------------------------------------------------
   CALLBACK DETECTION
---------------------------------------------------------- */

function handleGoogleCallbackState() {

  const params =
    new URLSearchParams(
      window.location.search
    );


  const googleState =
    params.get(
      "google"
    );


  if (
    googleState ===
    "connected"
  ) {

    /*
       The OAuth callback has just redirected here.
       Query the backend for the actual stored state.
    */

    refreshGoogleStatus();


    /*
       Remove ?google=connected from the address bar
       without reloading the page.
    */

    const cleanUrl =
      window.location.origin +
      window.location.pathname;

    window.history.replaceState(
      {},
      document.title,
      cleanUrl
    );

  } else {

    refreshGoogleStatus();

  }
}


/* ----------------------------------------------------------
   INITIALIZE
---------------------------------------------------------- */

document.addEventListener(
  "DOMContentLoaded",
  () => {

    handleGoogleCallbackState();

  }
);
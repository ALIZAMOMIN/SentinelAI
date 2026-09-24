(() => {
  "use strict";

  console.log(
    "[SentinelAI BRIDGE DEBUG] Bridge starting..."
  );

  if (
    window.__SENTINELAI_WEB_BRIDGE_LOADED__
  ) {
    console.log(
      "[SentinelAI BRIDGE DEBUG] Bridge already loaded."
    );

    return;
  }

  window.__SENTINELAI_WEB_BRIDGE_LOADED__ =
    true;

  const MESSAGE_SOURCE =
    "sentinelai-web-sensor";


  window.addEventListener(
    "message",
    event => {

      if (
        event.source !== window
      ) {
        return;
      }

      const data =
        event.data;


      if (
        !data ||
        data.source !==
          MESSAGE_SOURCE
      ) {
        return;
      }


      console.log(
        "[SentinelAI BRIDGE DEBUG] Window observation received:",
        data
      );


      if (
        !data.observation
      ) {
        console.warn(
          "[SentinelAI BRIDGE DEBUG] Observation missing."
        );

        return;
      }


      try {

        chrome.runtime.sendMessage({
          type:
            "SENTINELAI_WEB_OBSERVATION",

          observation:
            data.observation
        });

        console.log(
          "[SentinelAI BRIDGE DEBUG] Sent observation to background."
        );

      } catch (error) {

        console.error(
          "[SentinelAI BRIDGE DEBUG] Failed to send to background:",
          error
        );
      }
    }
  );


  console.log(
    "[SentinelAI BRIDGE DEBUG] Bridge ready."
  );

})();
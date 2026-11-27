// frontend/assets/js/report-action.js
(function () {
  function shouldShowReportButton({ verdict, riskLevel }) {
    const v = String(verdict || "").toUpperCase();
    const r = String(riskLevel || "").toUpperCase();

    if (v === "SAFE" || v === "LEGITIMATE") {
      return false;
    }
    return (
      v === "SUSPICIOUS" ||
      v === "MALICIOUS" ||
      v === "SPOOFED" ||
      r === "HIGH RISK" ||
      r === "MEDIUM RISK"
    );
  }

    function initReportControl({
    buttonEl,
    statusEl,
    noteInputEl,
    moduleType,
    getPayload,
  }) {
    if (!buttonEl) return;

    function setReportedState(message = "Already Reported") {
      buttonEl.disabled = true;
      buttonEl.textContent = message;
      buttonEl.classList.add("reported-locked");
      if (statusEl) {
        statusEl.textContent = "You have already submitted a report for this target.";
        statusEl.classList.remove("hidden");
      }
    }

    function setReadyState() {
      buttonEl.disabled = false;
      buttonEl.textContent = "Report Scan";
      buttonEl.classList.remove("reported-locked");
      if (statusEl) {
        statusEl.textContent = "";
        statusEl.classList.add("hidden");
      }
    }

    async function refreshForCurrentTarget() {
      const payload = getPayload();
      if (!payload || !shouldShowReportButton(payload)) {
        buttonEl.classList.add("hidden");
        if (noteInputEl) noteInputEl.classList.add("hidden");
        if (statusEl) statusEl.classList.add("hidden");
        return;
      }

      buttonEl.classList.remove("hidden");
      if (noteInputEl) noteInputEl.classList.remove("hidden");
      setReadyState();

      try {
        const apiBase = window.CYVORA_CONFIG?.API_BASE_URL || "http://127.0.0.1:8000";
        const token = await window.CyvoraAuth?.getBearerToken?.();
        if (!token) return;

        const params = new URLSearchParams({
          module_type: moduleType,
          target_value: payload.targetValue,
        });
        const resp = await fetch(`${apiBase}/api/v1/reports/status/?${params}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (resp.ok) {
          const data = await resp.json();
          if (data.reported) {
            setReportedState("Already Reported");
          }
        }
      } catch (_) {}
    }

    buttonEl.addEventListener("click", async () => {
      const payload = getPayload();
      if (!payload || !shouldShowReportButton(payload)) return;

      buttonEl.disabled = true;
      buttonEl.textContent = "Reporting...";

      try {
        const apiBase = window.CYVORA_CONFIG?.API_BASE_URL || "http://127.0.0.1:8000";
        const token = await window.CyvoraAuth?.getBearerToken?.();
        const headers = { "Content-Type": "application/json" };
        if (token) headers["Authorization"] = `Bearer ${token}`;

        const resp = await fetch(`${apiBase}/api/v1/reports/submit/`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            module_type: moduleType,
            target_value: payload.targetValue,
            verdict: payload.verdict,
            risk_level: payload.riskLevel,
            source_record_id: payload.sourceRecordId || null,
            notes: noteInputEl ? noteInputEl.value.trim() : "",
          }),
        });

        if (resp.status === 409) {
          setReportedState("Already Reported");
          return;
        }
        if (!resp.ok) {
          throw new Error(`Report failed (${resp.status})`);
        }

        setReportedState("Reported");
        if (statusEl) {
          statusEl.textContent = "Report recorded. You cannot report this same target again.";
          statusEl.classList.remove("hidden");
        }
      } catch (err) {
        buttonEl.disabled = false;
        buttonEl.textContent = "Report Scan";
        if (statusEl) {
          statusEl.textContent = err.message || "Could not submit report right now.";
          statusEl.classList.remove("hidden");
        }
      }
    });

    return { refreshForCurrentTarget };
  }

  window.CyvoraReportAction = {
    shouldShowReportButton,
    initReportControl,
  };
})();
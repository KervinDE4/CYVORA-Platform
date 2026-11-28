// frontend/assets/js/call-trust.js



(function () {
  const OFFICIAL_TRUNKS = {
    "+26825186000": "First National Bank (FNB) Eswatini",
    "+26824056000": "Standard Bank Eswatini",
    "+26876060999": "MTN MoMo Eswatini",
    "+26824064000": "Eswatini Revenue Service (ERS)",
    "+27113560000": "Verified Regional Trunk",
  };

  const DEMAND_LABELS = {
    otp_pin_reset: "OTP / 2FA / PIN Reset",
    account_freeze_alert: "Account Freeze / Security Alert",
    fee_clearance_payment: "Fee / Tax / Clearance Payment",
    remote_access_apk: "Remote Access / APK Install",
    kyc_id_card_details: "KYC / ID / Card Details",
    urgent_loan_prize_refund: "Urgent Loan / Prize / Refund",
  };

  const passportInput = document.getElementById("passportToken");
  const stirStatus = document.getElementById("stirShakenStatus");
  const selectedDemands = new Set();
  let latestCallTrustResult = null;

  const form = document.getElementById("callerProbeForm");
  const numberInput = document.getElementById("inboundNumber");
  const institutionSelect = document.getElementById("claimedInstitution");
  const chipsContainer = document.getElementById("callerDemandsGroup");
  const demandCountEl = document.getElementById("selectedDemandsCount");
  const btnVerify = document.getElementById("btnVerifyAuth");
  const errorBanner = document.getElementById("probeError");
  const ledgerList = document.getElementById("recentLedgerList");

  const dossierBannerTitle = document.getElementById("dossierBannerTitle");
  const dossierMeta = document.getElementById("dossierMeta");
  const dossierRiskPill = document.getElementById("dossierRiskPill");
  const confidenceValue = document.getElementById("confidenceValue");
  const confidenceLabel = document.getElementById("confidenceLabel");
  const metaTarget = document.getElementById("metaTarget");
  const metaIdentity = document.getElementById("metaIdentity");
  const metaDemands = document.getElementById("metaDemands");
  const metaAttestation = document.getElementById("metaAttestation");
  const forensicsList = document.getElementById("forensicsList");
  const btnToggleForensics = document.getElementById("btnToggleForensics");
  const forensicsBody = document.getElementById("forensicsBody");

  const callReportController = window.CyvoraReportAction?.initReportControl({
  buttonEl: document.getElementById("btnReportCallTrust"),
  statusEl: document.getElementById("callTrustReportStatus"),
  noteInputEl: document.getElementById("callTrustReportNote"),
  moduleType: "call_trust",
  getPayload: () => {
    if (!latestCallTrustResult) return null;
    return {
      targetValue: latestCallTrustResult.phone_number,
      verdict: latestCallTrustResult.verdict,
      riskLevel: latestCallTrustResult.risk_level,
      sourceRecordId: latestCallTrustResult.id || null,
    };
  },
});

  function normalizePhone(raw) {
    return (raw || "").replace(/[^\d+]/g, "");
  }

  function updateDemandCount() {
    demandCountEl.textContent = `${selectedDemands.size} selected`;
  }

  chipsContainer?.addEventListener("click", (e) => {
    const chip = e.target.closest(".demand-chip");
    if (!chip) return;
    const key = chip.dataset.demand;
    if (selectedDemands.has(key)) {
      selectedDemands.delete(key);
      chip.classList.remove("selected");
    } else {
      selectedDemands.add(key);
      chip.classList.add("selected");
    }
    updateDemandCount();
  });

  btnToggleForensics?.addEventListener("click", () => {
    forensicsBody.classList.toggle("hidden");
  });

  function evaluateLocalFallback(phoneRaw, institution, demands) {
    const normalized = normalizePhone(phoneRaw);
    const isOfficial = Boolean(OFFICIAL_TRUNKS[normalized]);
    let confidence = isOfficial ? 94 : 18;
    confidence -= demands.length * 14;
    if (demands.includes("otp_pin_reset") || demands.includes("remote_access_apk")) {
      confidence -= 10;
    }
    confidence = Math.max(4, Math.min(99, confidence));

    const isSpoofed = !isOfficial || confidence < 45;
    const riskLevel = confidence < 35 ? "HIGH RISK" : confidence < 70 ? "MEDIUM RISK" : "LOW RISK";
    const riskClass = confidence < 35 ? "high" : confidence < 70 ? "medium" : "low";

    const demandNames = demands.map((d) => DEMAND_LABELS[d] || d);
    const notes = [
      isOfficial
        ? `Matched verified outbound trunk for ${OFFICIAL_TRUNKS[normalized]}.`
        : `Inbound number ${phoneRaw} is not on the verified outbound trunk list for "${institution}".`,
      demands.length
        ? `Caller demands flagged (${demandNames.join(", ")}): legitimate institutions do not request OTPs, PINs, or remote apps over unsolicited calls.`
        : "No high-pressure caller demands selected; verify callback via official published number.",
      "Safety directive: hang up and call back using an official bank/utility number from your statement or card.",
    ];

    return {
      phone_number: phoneRaw,
      claimed_institution: institution,
      caller_demands: demands,
      confidence_score: confidence,
      verdict: isSpoofed ? "SPOOFED" : "LEGITIMATE",
      risk_level: riskLevel,
      risk_class: riskClass,
      attestation: isOfficial ? "Level A (Full Attestation)" : "Level C (Gateway Only / Untrusted)",
      notes,
    };
  }

  function renderResult(res) {
    const spoofed = String(res.verdict).toUpperCase() === "SPOOFED";
    dossierBannerTitle.textContent = spoofed
      ? "CRITICAL SPOOFING WARNING — UNAUTHORIZED CALLER"
      : "VERIFIED OUTBOUND IDENTITY — AUTHENTICATED CALLER";
    dossierBannerTitle.style.color = spoofed ? "var(--red)" : "var(--green)";

    dossierMeta.textContent = `DOSSIER REF: #CT-${Math.floor(1000 + Math.random() * 9000)} · JUST ANALYZED`;
    dossierRiskPill.textContent = res.risk_level || (spoofed ? "HIGH RISK" : "LOW RISK");
    dossierRiskPill.className = `risk-pill ${res.risk_class || (spoofed ? "high" : "low")}`;

    confidenceValue.textContent = `${res.confidence_score}%`;
    confidenceValue.style.color = spoofed ? "var(--red)" : "var(--green)";
    confidenceLabel.textContent = spoofed ? "SEVERELY COMPROMISED" : "HIGH TRUST";
    confidenceLabel.style.color = spoofed ? "var(--red)" : "var(--green)";

    metaTarget.textContent = res.phone_number;
    metaIdentity.textContent = res.claimed_institution;
    const demandsText = (res.caller_demands || []).map((d) => DEMAND_LABELS[d] || d).join(", ");
    metaDemands.textContent = demandsText || "None selected";
    const stir = res.stir_shaken || { status: "not_provided", message: "No PASSporT result returned." };
    metaAttestation.textContent = stir.status.replaceAll("_", " ").toUpperCase();
    if (stirStatus) {
      stirStatus.dataset.state = stir.status;
      stirStatus.textContent = `STIR/SHAKEN: ${stir.status.replaceAll("_", " ")} — ${stir.message}`;
    }

    // Render API/user-controlled values as text, never as HTML.
    forensicsList.replaceChildren();
    (res.notes || []).forEach((note) => {
      const item = document.createElement("li");
      item.textContent = String(note);
      forensicsList.appendChild(item);
    });

    const li = document.createElement("li");
    const phoneLabel = document.createElement("span");
    phoneLabel.textContent = String(res.phone_number || "");
    const verdictLabel = document.createElement("span");
    verdictLabel.className = spoofed ? "tag-spoofed" : "tag-legit";
    verdictLabel.textContent = spoofed ? "SPOOFED" : "LEGITIMATE";
    li.append(phoneLabel, verdictLabel);
    ledgerList.prepend(li);

    latestCallTrustResult = res;
    if (typeof callReportController?.refreshForCurrentTarget === "function") {
      callReportController.refreshForCurrentTarget();
    }

  }

  async function initUserBadge() {
    try {
      const supabase = window.CyvoraAuth?.getSupabaseClient?.();
      if (supabase) {
        const { data } = await supabase.auth.getSession();
        const email = data?.session?.user?.email;
        if (email) {
          document.getElementById("userEmailBadge").textContent = email;
        }
      }
    } catch (_) {}
  }
  async function loadRecentHistory() {
  try {
    const apiBase = window.CYVORA_CONFIG?.API_BASE_URL || "http://127.0.0.1:8000";
    const token = await window.CyvoraAuth?.getBearerToken?.();
    if (!token) return;

    const resp = await fetch(`${apiBase}/api/v1/call-trust/history/`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!resp.ok) return;

    const rows = await resp.json();
    if (!Array.isArray(rows) || !rows.length) return;

    ledgerList.replaceChildren();
    rows.slice(0, 6).forEach((row) => {
      const spoofed = String(row.verdict).toUpperCase() === "SPOOFED";
      const item = document.createElement("li");
      const phoneLabel = document.createElement("span");
      phoneLabel.textContent = String(row.phone_number || "");
      const verdictLabel = document.createElement("span");
      verdictLabel.className = spoofed ? "tag-spoofed" : "tag-legit";
      verdictLabel.textContent = spoofed ? "SPOOFED" : "LEGITIMATE";
      item.append(phoneLabel, verdictLabel);
      ledgerList.appendChild(item);
    });
  } catch (_) {}
}

  document.getElementById("btnSignOut")?.addEventListener("click", async () => {
    try {
      const supabase = window.CyvoraAuth?.getSupabaseClient?.();
      if (supabase) await supabase.auth.signOut();
    } finally {
      window.location.href = "login.html";
    }
  });

  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    errorBanner.classList.add("hidden");
    errorBanner.textContent = "";

    const phone_number = numberInput.value.trim();
    const claimed_institution = institutionSelect.value;
    const caller_demands = Array.from(selectedDemands);

    btnVerify.disabled = true;
    btnVerify.textContent = "Verifying...";

    try {
      const apiBase = window.CYVORA_CONFIG?.API_BASE_URL || "http://127.0.0.1:8000";
      const token = await window.CyvoraAuth?.getBearerToken?.();
      const headers = { "Content-Type": "application/json" };
      if (token) headers["Authorization"] = `Bearer ${token}`;

      const resp = await fetch(`${apiBase}/api/v1/call-trust/verify/`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          phone_number,
          claimed_institution,
          caller_demands,
        }),
      });

      if (!resp.ok) {
        throw new Error(`Backend endpoint returned ${resp.status}`);
      }

      const data = await resp.json();
      renderResult({
        id: data.id || null,
        phone_number,
        claimed_institution,
        caller_demands,
        confidence_score: data.confidence_score ?? 12,
        verdict: data.verdict ?? "SPOOFED",
        risk_level: data.risk_level ?? "HIGH RISK",
        risk_class: data.risk_class ?? "high",
        attestation: data.attestation ?? "Level C (Gateway Only / Untrusted)",
        notes: data.notes ?? [],
      });
    } catch (err) {
      // Keep the local estimate available, but never present it as a confirmed backend check.
      errorBanner.textContent =
        `Backend verification unavailable (${err?.message || "network error"}). Showing a local estimate only; do not treat it as a confirmed verification.`;
      errorBanner.classList.remove("hidden");
      const fallback = evaluateLocalFallback(phone_number, claimed_institution, caller_demands);
      renderResult(fallback);
    } finally {
      btnVerify.disabled = false;
      btnVerify.textContent = "Verify Authenticity";
    }
  });

  initUserBadge();
  updateDemandCount();
})();
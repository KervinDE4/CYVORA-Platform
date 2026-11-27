// frontend/assets/js/ui/threatScanRenderer.js
function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderScanResult(containerEl, scan) {
  if (!containerEl || !scan) return;
  containerEl.classList.remove("hidden");

  const verdict = (scan.verdict || "safe").toLowerCase();
  const verdictClass =
    verdict === "malicious"
      ? "verdict-malicious"
      : verdict === "suspicious"
      ? "verdict-suspicious"
      : "verdict-safe";

  const dna = scan.threat_dna || (scan.findings && scan.findings.threat_dna) || {};
  const impact = scan.impact_prediction || (scan.findings && scan.findings.impact_prediction) || {};
  const story = scan.attack_story || (scan.findings && scan.findings.attack_story) || [];
  const forensics = scan.forensics_snapshot || (scan.findings && scan.findings.forensics_snapshot) || {};
  const indicators = (scan.findings && scan.findings.indicators) || [];
  const confidence = scan.confidence_score ?? (scan.findings && scan.findings.confidence_score) ?? 0;
  const similarThreats = scan.similar_threats ?? 0;
  const communityReports = scan.community_reports ?? 0;
  const explanation = scan.ai_explanation || scan.ai_summary || "";

  const dnaEntries = [
    ["Social Engineering", dna.social_engineering ?? 0],
    ["Credential Theft", dna.credential_theft ?? 0],
    ["Financial Fraud", dna.financial_fraud ?? 0],
    ["Identity Theft", dna.identity_theft ?? 0],
    ["Malware Delivery", dna.malware_delivery ?? 0]
  ];

  const dnaHtml = dnaEntries
    .map(
      ([label, pct]) => `
      <div class="dna-row">
        <div class="dna-label"><span>${escapeHtml(label)}</span><span>${Number(pct)}%</span></div>
        <div class="dna-track"><div class="dna-fill" style="width:${Math.min(100, Math.max(0, Number(pct)))}%"></div></div>
      </div>
    `
    )
    .join("");

  const outcomesHtml = (impact.potential_outcomes || [])
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");

  const storyHtml = story
    .map(
      (step) =>
        `<li><strong>Step ${escapeHtml(step.step)}: ${escapeHtml(step.title)}</strong> — <span class="muted">${escapeHtml(step.detail)}</span></li>`
    )
    .join("");

  const indicatorsHtml = indicators.length
    ? indicators
        .map(
          (ind) =>
            `<li><strong>${escapeHtml(ind.title)}</strong> [${escapeHtml(ind.severity || "info")}] — <span class="muted">${escapeHtml(ind.detail)}</span></li>`
        )
        .join("")
    : `<li class="muted">No high-risk indicators triggered.</li>`;

  containerEl.innerHTML = `
    <div class="card">
      <div class="form-row" style="justify-content:space-between;align-items:center;">
        <div>
          <span class="verdict-pill ${verdictClass}">${escapeHtml(verdict)}</span>
          <strong style="margin-left:10px;font-size:1.1rem;">Risk Score: ${escapeHtml(scan.risk_score)} / 100</strong>
          <span class="muted" style="margin-left:10px;">Confidence: ${escapeHtml(confidence)}%</span>
        </div>
        <div class="muted" style="font-size:0.85rem;">
          Similar Threats: <strong>${escapeHtml(similarThreats)}</strong> | Community Reports: <strong>${escapeHtml(communityReports)}</strong>
        </div>
      </div>
      <p style="margin:10px 0 0;">${escapeHtml(explanation)}</p>
      <div class="form-row" style="margin-top:14px;">
        <button type="button" class="btn secondary" id="btnAdvisor">Ask Security Advisor</button>
        <button type="button" class="btn secondary" id="btnTakedown">Generate Takedown Packet</button>
        <button type="button" class="btn danger" id="btnEscalate">Escalate to Scam Report</button>
      </div>
      <div id="advisorOutput" class="advisor-box hidden"></div>
    </div>

    <div class="grid-2">
      <div class="card">
        <h3 style="margin-top:0;">CYVORA Threat DNA</h3>
        ${dnaHtml}
      </div>

      <div class="card">
        <h3 style="margin-top:0;">Victim Impact Predictor</h3>
        <p class="muted" style="margin-top:0;">Severity: <strong>${escapeHtml(impact.severity || "low")}</strong> | Confidence: <strong>${escapeHtml(impact.confidence ?? 0)}%</strong></p>
        <ul class="indicator-list">${outcomesHtml}</ul>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <h3 style="margin-top:0;">Attack Story Reconstruction</h3>
        <ol class="story-list">${storyHtml}</ol>
      </div>

      <div class="card">
        <h3 style="margin-top:0;">Digital Forensics Snapshot & IOCs</h3>
        <p class="muted" style="margin-top:0;">
          Category: <strong>${escapeHtml(forensics.threat_category || "N/A")}</strong> |
          Risk Level: <strong>${escapeHtml(forensics.risk_level || "N/A")}</strong> |
          IOCs: <strong>${escapeHtml(forensics.ioc_count ?? 0)}</strong>
        </p>
        <ul class="indicator-list">${indicatorsHtml}</ul>
      </div>
    </div>
  `;
}

function renderAdvisorGuidance(targetEl, guidance) {
  if (!targetEl || !guidance) return;
  targetEl.classList.remove("hidden");
  targetEl.innerHTML = `
    <h4 style="margin:0 0 8px;">CYVORA Security Advisor</h4>
    <p style="margin:4px 0;"><strong>Why It's Dangerous:</strong> ${escapeHtml(guidance.why_dangerous)}</p>
    <p style="margin:4px 0;"><strong>What Happens Next:</strong> ${escapeHtml(guidance.what_happens_next)}</p>
    <p style="margin:4px 0;"><strong>What To Do Now:</strong> ${escapeHtml(guidance.what_to_do_now)}</p>
    <p style="margin:4px 0;"><strong>What Never To Share:</strong> ${escapeHtml(guidance.what_never_to_share)}</p>
  `;
}

function renderScanHistory(tbodyEl, items) {
  if (!tbodyEl) return;
  if (!Array.isArray(items) || items.length === 0) {
    tbodyEl.innerHTML = `<tr><td colspan="5" class="muted">No scans recorded yet.</td></tr>`;
    return;
  }

  tbodyEl.innerHTML = items
    .map(
      (item) => `
      <tr>
        <td>${escapeHtml(item.scan_type)}</td>
        <td>${escapeHtml((item.input_value || "").slice(0, 56))}</td>
        <td><strong>${escapeHtml(item.risk_score)}/100</strong></td>
        <td>${escapeHtml(item.verdict)}</td>
        <td class="muted">${escapeHtml((item.created_at || "").slice(0, 19).replace("T", " "))}</td>
      </tr>
    `
    )
    .join("");
}

window.ThreatScanRenderer = {
  renderScanResult,
  renderAdvisorGuidance,
  renderScanHistory
};
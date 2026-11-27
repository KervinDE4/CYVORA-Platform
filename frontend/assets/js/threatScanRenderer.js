// Call this once on page load for ThreatScan
const threatReportController = window.CyvoraReportAction?.initReportControl({
  buttonEl: document.getElementById("btnReportThreatScan"),
  statusEl: document.getElementById("threatScanReportStatus"),
  noteInputEl: document.getElementById("threatScanReportNote"),
  moduleType: "threat_scan",
  getPayload: () => {
    const res = window.latestThreatScanResult;
    if (!res) return null;

    const verdict = String(res.verdict || "").toUpperCase();
    const score = Number(res.risk_score ?? res.score ?? 0);
    const riskLevel =
      res.risk_level ||
      (score >= 70 || verdict === "MALICIOUS"
        ? "HIGH RISK"
        : score >= 35 || verdict === "SUSPICIOUS"
          ? "MEDIUM RISK"
          : "LOW RISK");

    return {
      targetValue: res.input_value || res.input || res.target || "",
      verdict,
      riskLevel,
      sourceRecordId: res.id || null,
    };
  },
});

// Inside your ThreatScan render function, right after rendering `scanData`:
window.latestThreatScanResult = scanData;
if (threatReportController) {
  threatReportController.refreshForCurrentTarget();
}
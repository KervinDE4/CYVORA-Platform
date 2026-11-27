// frontend/assets/js/api/threatScanApi.js
const THREAT_SCAN_PREFIX = "/api/v1/threat-scan";

function getBaseUrl() {
  return (window.CYVORA_CONFIG?.API_BASE_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");
}

async function authHeaders(extra = {}) {
  const token = await window.CyvoraAuth.getBearerToken();
  const headers = { ...extra };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

async function parseResponse(resp) {
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const message = data.detail || data.error || `Request failed (${resp.status})`;
    throw new Error(message);
  }
  return data;
}

async function analyzeThreat({ scan_type, input_value, channel = "", file = null }) {
  const url = `${getBaseUrl()}${THREAT_SCAN_PREFIX}/analyze/`;

  let resp;
  if (file) {
    const formData = new FormData();
    formData.append("scan_type", scan_type);
    formData.append("input_value", input_value || file.name);
    formData.append("channel", channel || "");
    formData.append("file", file);
    const headers = await authHeaders();
    resp = await fetch(url, { method: "POST", headers, body: formData });
  } else {
    const headers = await authHeaders({ "Content-Type": "application/json" });
    resp = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({ scan_type, input_value, channel })
    });
  }
  return parseResponse(resp);
}

async function fetchScanHistory(verdict = "") {
  const query = verdict ? `?verdict=${encodeURIComponent(verdict)}` : "";
  const url = `${getBaseUrl()}${THREAT_SCAN_PREFIX}/history/${query}`;
  const headers = await authHeaders();
  const resp = await fetch(url, { method: "GET", headers });
  return parseResponse(resp);
}

async function fetchSecurityAdvisor(scanId) {
  const url = `${getBaseUrl()}${THREAT_SCAN_PREFIX}/advisor/`;
  const headers = await authHeaders({ "Content-Type": "application/json" });
  const resp = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({ scan_id: scanId })
  });
  return parseResponse(resp);
}

async function fetchTakedownPacket(scanId) {
  const url = `${getBaseUrl()}${THREAT_SCAN_PREFIX}/${encodeURIComponent(scanId)}/takedown-packet/`;
  const headers = await authHeaders();
  const resp = await fetch(url, { method: "GET", headers });
  return parseResponse(resp);
}

async function escalateScan(scanId) {
  const url = `${getBaseUrl()}${THREAT_SCAN_PREFIX}/${encodeURIComponent(scanId)}/escalate/`;
  const headers = await authHeaders({ "Content-Type": "application/json" });
  const resp = await fetch(url, { method: "POST", headers });
  return parseResponse(resp);
}

window.ThreatScanApi = {
  analyzeThreat,
  fetchScanHistory,
  fetchSecurityAdvisor,
  fetchTakedownPacket,
  escalateScan
};
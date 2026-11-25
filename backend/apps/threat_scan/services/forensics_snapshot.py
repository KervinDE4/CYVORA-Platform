# backend/apps/threat_scan/services/forensics_snapshot.py

MITRE_TACTIC_LABELS = {
    "T1566": "Initial Access: Phishing",
    "T1566.002": "Initial Access: Spearphishing Link",
    "T1598": "Reconnaissance: Phishing for Information",
    "T1204": "Execution: User Execution",
}


def build_forensics_snapshot(
    scan_type: str,
    risk_score: int,
    indicators: list[dict],
    mitre_codes: list[str],
    url_results: list[dict],
    regional_intel: dict,
    threat_dna: dict,
) -> dict:
    extracted_hosts = [u.get("host") for u in url_results if u.get("host")]
    ioc_count = len(indicators) + len(extracted_hosts)

    tactics = [MITRE_TACTIC_LABELS.get(code, f"MITRE {code}") for code in mitre_codes]
    if not tactics and risk_score >= 30:
        tactics.append("Social Engineering / Deceptive Lure")

    if regional_intel.get("primary_category"):
        threat_category = regional_intel["primary_category"]
    elif threat_dna.get("credential_theft", 0) >= 60 and threat_dna.get("financial_fraud", 0) >= 50:
        threat_category = "Banking Phishing"
    elif threat_dna.get("malware_delivery", 0) >= 55:
        threat_category = "Malware / Trojan Delivery"
    elif threat_dna.get("social_engineering", 0) >= 50:
        threat_category = "Social Engineering Scam"
    elif risk_score >= 30:
        threat_category = "Suspicious / Unverified Payload"
    else:
        threat_category = "Benign / No Threat Classified"

    risk_level = (
        "Critical" if risk_score >= 80 else
        "High" if risk_score >= 60 else
        "Medium" if risk_score >= 30 else
        "Low"
    )

    return {
        "ioc_count": ioc_count,
        "suspected_tactics": tactics,
        "threat_category": threat_category,
        "risk_level": risk_level,
        "observed_hosts": extracted_hosts,
    }
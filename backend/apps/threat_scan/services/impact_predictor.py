# backend/apps/threat_scan/services/impact_predictor.py


def predict_victim_impact(risk_score: int, threat_dna: dict, regional_intel: dict, confidence_score: int) -> dict:
    if risk_score >= 80:
        severity = "critical"
    elif risk_score >= 60:
        severity = "high"
    elif risk_score >= 30:
        severity = "medium"
    else:
        severity = "low"

    outcomes = []
    if threat_dna.get("credential_theft", 0) >= 45:
        outcomes.append("Credential Theft")
    if threat_dna.get("financial_fraud", 0) >= 50:
        outcomes.append("Bank Account Takeover")
    if threat_dna.get("identity_theft", 0) >= 40:
        outcomes.append("Identity Fraud")
    if any("momo" in b.lower() or "wallet" in (regional_intel.get("primary_category") or "").lower() for b in regional_intel.get("targeted_brands", [])) or threat_dna.get("financial_fraud", 0) >= 55:
        outcomes.append("Mobile Money Fraud")
    if threat_dna.get("malware_delivery", 0) >= 45:
        outcomes.append("Device Compromise / Spyware Installation")
    if threat_dna.get("social_engineering", 0) >= 50 and not outcomes:
        outcomes.append("Follow-Up Targeted Scam Escalation")

    if not outcomes:
        outcomes.append("Minimal Immediate Impact (Maintain Standard Caution)")

    impact_confidence = min(99, max(40, round((confidence_score * 0.7) + (risk_score * 0.3))))

    return {
        "severity": severity,
        "confidence": impact_confidence,
        "potential_outcomes": outcomes,
    }
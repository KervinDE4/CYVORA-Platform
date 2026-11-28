"""Cautious impact hypotheses for CYVORA ThreatScan.

These are possible outcomes, not statements that a victim has suffered harm.
The predictor relies on evidence-linked Threat DNA and never infers compromise
from a brand mention, generic financial vocabulary, or file scan type alone.
"""


def predict_victim_impact(
    risk_score: int,
    threat_dna: dict,
    regional_intel: dict,
    confidence_score: int,
) -> dict:
    risk = max(0, min(100, int(risk_score or 0)))
    confidence = max(0, min(100, int(confidence_score or 0)))

    if risk >= 90:
        severity = "critical"
    elif risk >= 71:
        severity = "high"
    elif risk >= 31:
        severity = "medium"
    else:
        severity = "low"

    outcomes = []
    if threat_dna.get("credential_theft", 0) >= 45:
        outcomes.append("Possible credential exposure")
    if threat_dna.get("financial_fraud", 0) >= 40:
        outcomes.append("Possible financial or payment fraud")
    if threat_dna.get("identity_theft", 0) >= 45:
        outcomes.append("Possible identity-data misuse")
    if (
        threat_dna.get("financial_fraud", 0) >= 60
        and regional_intel.get("primary_category") == "Mobile Money Reversal / Voucher Scam"
    ):
        outcomes.append("Possible mobile-money or wallet fraud")
    if threat_dna.get("malware_delivery", 0) >= 50:
        outcomes.append("Possible malicious payload exposure")

    if not outcomes:
        outcomes.append("No specific downstream impact established from the available evidence")

    return {
        "severity": severity,
        "confidence": confidence,
        "potential_outcomes": outcomes,
        "limitations": [
            "These are potential outcomes, not confirmed incidents.",
            "This scan does not establish that credentials were submitted, funds moved, identity data was misused, or code executed.",
        ],
    }

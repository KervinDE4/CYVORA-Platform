"""Evidence-led threat-category indicators for CYVORA ThreatScan.

DNA values are heuristic relevance scores, not probabilities or proof of impact.
Only explicit detector indicator IDs contribute; a file scan or brand mention
alone must not imply malware or identity theft.
"""

CATEGORY_WEIGHTS = {
    "social_engineering": {
        "artificial_urgency": 25,
        "lure_keywords": 15,
        "messaging_vector_risk": 8,
    },
    "credential_theft": {
        "credential_harvest_cue": 65,
        "cleartext_sensitive_path": 45,
    },
    "financial_fraud": {
        "financial_social_bait": 40,
        "regional_momo_reversal": 70,
    },
    "identity_theft": {
        # Reserved for specific identity-document or identity-data indicators
        # when the detector implements them. Generic words such as "account"
        # or "government" are intentionally insufficient.
        "identity_document_request": 65,
        "identity_data_harvest": 70,
    },
    "malware_delivery": {
        # These IDs must be emitted by a file/payload detector before they
        # contribute. Merely scanning a PDF or URL is not malware evidence.
        "malware_payload_detected": 75,
        "suspicious_file_payload": 55,
    },
}


def compute_threat_dna(
    scan_type: str,
    risk_score: int,
    indicators: list[dict],
    regional_intel: dict,
) -> dict:
    """Return bounded, evidence-linked category scores from 0 to 100."""
    del scan_type, regional_intel  # Context alone is not sufficient evidence.
    indicator_ids = {
        str(ind.get("id"))
        for ind in indicators
        if isinstance(ind, dict) and ind.get("id")
    }

    risk = max(0, min(100, int(risk_score or 0)))
    result = {}
    for category, weights in CATEGORY_WEIGHTS.items():
        raw_score = sum(weight for indicator_id, weight in weights.items() if indicator_id in indicator_ids)
        # A category cannot outrun the overall scan risk score.
        result[category] = min(100, risk, raw_score)

    return result

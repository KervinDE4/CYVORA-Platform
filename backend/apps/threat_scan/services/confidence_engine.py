# backend/apps/threat_scan/services/confidence_engine.py

SEVERITY_WEIGHTS = {
    "critical": 24,
    "high": 16,
    "medium": 10,
    "low": 5,
}


def calculate_confidence_score(
    risk_score: int,
    indicators: list[dict],
    regional_intel: dict,
    community_intel: dict,
) -> int:
    # Base confidence starts at 55 for clean scans and scales with corroborating evidence
    if not indicators and risk_score < 30:
        base = 78
        if community_intel.get("similar_threats", 0) == 0:
            return 82
        return max(50, 82 - min(25, community_intel["similar_threats"] * 5))

    evidence_points = 45
    for ind in indicators:
        sev = (ind.get("severity") or "low").lower()
        evidence_points += SEVERITY_WEIGHTS.get(sev, 5)

    evidence_points += regional_intel.get("confidence_boost", 0)

    similar = community_intel.get("similar_threats", 0)
    reports = community_intel.get("community_reports", 0)
    if similar > 0:
        evidence_points += min(15, similar * 2)
    if reports > 0:
        evidence_points += min(12, reports * 3)

    return min(99, max(50, evidence_points))
# backend/apps/threat_scan/services/confidence_engine.py
"""Estimate confidence from distinct evidence, not the verdict label alone."""

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 18,
    "medium": 10,
    "low": 4,
}


def calculate_confidence_score(
    risk_score: int,
    indicators: list[dict],
    regional_intel: dict,
    community_intel: dict,
) -> int:
    """Return a bounded evidence-confidence estimate.

    A single weak heuristic must not create high confidence. Repeated copies of
    the same indicator are counted once; independent indicators and corroborating
    community reports can increase confidence.
    """
    unique_indicators = {}
    for indicator in indicators:
        indicator_id = indicator.get("id")
        if indicator_id:
            unique_indicators.setdefault(indicator_id, indicator)

    similar = max(0, int(community_intel.get("similar_threats", 0) or 0))
    reports = max(0, int(community_intel.get("community_reports", 0) or 0))

    if not unique_indicators:
        # A low-risk scan with no findings is a reasonably supported clean
        # assessment, but community matches should reduce certainty in it.
        clean_confidence = 78 if risk_score < 30 else 35
        corroboration = min(12, similar * 3 + reports * 2)
        return min(90, clean_confidence + corroboration)

    evidence_points = 25
    for indicator in unique_indicators.values():
        severity = (indicator.get("severity") or "low").lower()
        evidence_points += SEVERITY_WEIGHTS.get(severity, SEVERITY_WEIGHTS["low"])

    # Distinct indicator IDs are a modest corroboration signal, not proof that
    # the underlying observations are fully independent.
    if len(unique_indicators) >= 2:
        evidence_points += min(16, (len(unique_indicators) - 1) * 6)

    regional_support = max(0, int(regional_intel.get("confidence_boost", 0) or 0))
    evidence_points += min(8, regional_support)

    evidence_points += min(12, similar * 2 + reports * 3)
    return min(98, max(20, evidence_points))

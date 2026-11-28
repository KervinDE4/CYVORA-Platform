"""Central ThreatScan risk classification policy.

Scores are produced by deterministic detection services. This module only maps
those scores to user-facing verdicts; it does not let an LLM decide verdicts.
"""

SAFE_MAX = 30
SUSPICIOUS_MAX = 70
MAX_RISK_SCORE = 100


def verdict_from_score(score: int) -> str:
    """Return safe/suspicious/malicious using CYVORA's published thresholds."""
    normalized = max(0, min(MAX_RISK_SCORE, int(score)))
    if normalized <= SAFE_MAX:
        return "safe"
    if normalized <= SUSPICIOUS_MAX:
        return "suspicious"
    return "malicious"

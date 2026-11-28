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


def combine_message_url_scores(message_score: int, url_score: int) -> int:
    """Combine message and URL evidence without rewarding weak co-occurrence.

    A modest corroboration bonus applies only when both evidence streams have
    meaningful signal. This prevents two weak non-zero scores from crossing
    the suspicious threshold simply because they appear in one message.
    """
    message = max(0, min(MAX_RISK_SCORE, int(message_score)))
    url = max(0, min(MAX_RISK_SCORE, int(url_score)))
    combined = max(message, url)

    if message >= 25 and url >= 25:
        corroboration = min(12, min(message, url) // 4)
        combined += corroboration

    return min(MAX_RISK_SCORE, combined)

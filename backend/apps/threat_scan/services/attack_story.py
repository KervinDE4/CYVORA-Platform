"""Evidence-led attack-path descriptions for ThreatScan.

Observed indicators and possible attacker actions are deliberately separated.
A reconstructed path is a hypothesis, not proof of victim compromise.
"""
from .attack_profiles import build_attack_profile


def reconstruct_attack_story(
    scan_type: str,
    verdict: str,
    threat_dna: dict,
    regional_intel: dict,
    indicators: list[dict] | None = None,
    attack_profile: dict | None = None,
) -> list[dict]:
    indicators = indicators or []
    profile = attack_profile or build_attack_profile(scan_type, indicators)
    story = []

    for indicator in profile.get("evidence", [])[:5]:
        story.append({
            "step": len(story) + 1,
            "title": f"Observed: {indicator['title']}",
            "detail": (
                f"CYVORA matched indicator '{indicator['indicator_id']}' "
                f"(severity: {indicator['severity']}). This is evidence in the submitted content."
            ),
            "evidence_status": "observed",
        })

    if not story:
        story.append({
            "step": 1,
            "title": "Submitted content inspected",
            "detail": (
                f"CYVORA analysed the submitted {scan_type} content. "
                "No indicator supporting a specific attack profile was recorded."
            ),
            "evidence_status": "observed",
        })

    if verdict in {"suspicious", "malicious"}:
        for item in profile.get("possible_steps", []):
            story.append({
                "step": len(story) + 1,
                "title": item["title"],
                "detail": item["detail"],
                "evidence_status": "possible",
            })

    return story

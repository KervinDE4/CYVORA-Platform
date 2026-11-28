"""Evidence-led attack-path descriptions for ThreatScan.

These are hypotheses, not forensic proof of compromise. The scan can observe
submitted content and indicators; it cannot infer that a victim clicked,
entered credentials, or lost funds.
"""


def reconstruct_attack_story(
    scan_type: str,
    verdict: str,
    threat_dna: dict,
    regional_intel: dict,
    indicators: list[dict] | None = None,
) -> list[dict]:
    indicators = indicators or []
    brands = regional_intel.get("targeted_brands") or []
    observed = []

    for indicator in indicators[:5]:
        title = str(indicator.get("title") or "Detection indicator")[:120]
        detail = str(indicator.get("detail") or "A detection rule matched this submitted content.")[:280]
        observed.append({
            "step": len(observed) + 1,
            "title": title,
            "detail": detail,
            "evidence_status": "observed",
        })

    if not observed:
        observed.append({
            "step": 1,
            "title": "Submitted content inspected",
            "detail": f"CYVORA analysed the submitted {scan_type} content. No specific malicious indicator was recorded.",
            "evidence_status": "observed",
        })

    # Add a clearly labelled possible next step only when findings justify it.
    possible = []
    indicator_ids = {str(item.get("id", "")) for item in indicators}
    if verdict in {"suspicious", "malicious"}:
        if indicator_ids & {"credential_harvest_cue", "brand_combosquatting", "typosquatting_similarity", "cleartext_sensitive_path"}:
            target = brands[0] if brands else "an impersonated service"
            possible.append({
                "title": "Possible credential-harvesting attempt",
                "detail": f"If a user follows the submitted link, it could lead to a deceptive page impersonating {target}. No credential submission is established by this scan.",
            })
        if indicator_ids & {"regional_momo_reversal", "financial_social_bait"}:
            possible.append({
                "title": "Possible financial social engineering",
                "detail": "The content may be intended to pressure a recipient into revealing a PIN, approving a transaction, or returning funds. No transfer is established by this scan.",
            })
        if threat_dna.get("malware_delivery", 0) >= 50:
            possible.append({
                "title": "Possible malware delivery",
                "detail": "The submitted content has file or payload-related signals. This scan does not establish that code executed or a device was compromised.",
            })

    for item in possible:
        observed.append({
            "step": len(observed) + 1,
            "title": item["title"],
            "detail": item["detail"],
            "evidence_status": "possible",
        })

    return observed

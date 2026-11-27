from .call_copilot import analyze_call_script
from .caller_reputation import evaluate_caller_reputation
from .phone_normalizer import normalize_phone_number


def _verdict_from_score(score: int, verified_caller: dict | None) -> str:
    if verified_caller and score < 30:
        return "verified_safe"
    if score >= 65:
        return "high_risk"
    if score >= 30:
        return "suspicious"
    return "suspicious" if not verified_caller else "verified_safe"


def run_call_trust_check(
    phone_number: str,
    call_script: str = "",
    channel: str = "voice_call",
) -> dict:
    norm = normalize_phone_number(phone_number)
    rep = evaluate_caller_reputation(norm["normalized"], norm["format_flags"])
    script_res = analyze_call_script(call_script)

    combined_score = min(
        100,
        max(rep["score"], script_res["score"])
        + (15 if rep["score"] >= 25 and script_res["score"] >= 25 else 0),
    )

    # Keep score low if a verified official caller matched with zero script/reputation red flags
    if rep["verified_caller"] and not script_res["indicators"] and rep["community_reports"] == 0:
        combined_score = min(combined_score, 10)

    all_indicators = []
    seen_ids = set()
    for ind in rep["indicators"] + script_res["indicators"]:
        ind_id = ind.get("id")
        if ind_id not in seen_ids:
            seen_ids.add(ind_id)
            all_indicators.append(ind)

    verdict = _verdict_from_score(combined_score, rep["verified_caller"])

    findings = {
        "channel": channel or "voice_call",
        "region": norm["country_label"],
        "is_valid_format": norm["is_valid_format"],
        "verified_caller": rep["verified_caller"],
        "community_phone_hits": rep["community_hits"],
        "community_reports": rep["community_reports"],
        "red_flags": all_indicators,
        "copilot_guidance": script_res["copilot_guidance"],
    }

    return {
        "normalized_phone": norm["normalized"],
        "risk_score": combined_score,
        "verdict": verdict,
        "findings": findings,
    }
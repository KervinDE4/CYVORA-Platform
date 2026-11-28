# backend/apps/threat_scan/services/engine.py
from .ai_advisor import generate_ai_threat_explanation
from .attack_story import reconstruct_attack_story
from .community_intel import correlate_and_record_threat_intel
from .confidence_engine import calculate_confidence_score
from .forensics_snapshot import build_forensics_snapshot
from .impact_predictor import predict_victim_impact
from .regional_intel import analyze_regional_scam_context
from .risk_scoring import combine_message_url_scores, verdict_from_score
from .text_heuristics import analyze_message_text, extract_urls_from_text
from .threat_dna import compute_threat_dna
from .url_analyzer import analyze_url


def _containment_steps(verdict: str, channel: str) -> list[dict]:
    steps = [
        {
            "step": 1,
            "title": "Zero User Engagement",
            "action": "Do not enter banking PINs, passwords, ID numbers, or OTP codes on linked pages or replies.",
        }
    ]

    if verdict in {"suspicious", "malicious"}:
        ch_label = channel.replace("_", " ").title() if channel else "the sender channel"
        steps.append({
            "step": 2,
            "title": "Isolate Sender & Channel",
            "action": f"Do not forward the link/message; block and report the sender on {ch_label}.",
        })
        steps.append({
            "step": 3,
            "title": "Protect Credentials & Escalate",
            "action": "If you already interacted, change passwords/PINs immediately via an official app/bookmark and file an incident report.",
        })
    else:
        steps.append({
            "step": 2,
            "title": "Verify Context Before Acting",
            "action": "Even when no strong red flags appear, confirm unexpected requests through an official contact channel.",
        })

    return steps


def run_threat_scan(scan_type: str, input_value: str, channel: str = "") -> dict:
    scan_type = (scan_type or "url").lower().strip()
    raw_input = (input_value or "").strip()

    all_indicators = []
    mitre_set = set()
    url_results = []
    message_result = None
    combined_score = 0

    if scan_type == "url":
        u_res = analyze_url(raw_input)
        url_results.append(u_res)
        combined_score = u_res["score"]
        all_indicators.extend(u_res["indicators"])
        mitre_set.update(u_res["mitre_techniques"])

    elif scan_type == "message":
        m_res = analyze_message_text(raw_input, channel=channel)
        message_result = m_res
        all_indicators.extend(m_res["indicators"])
        mitre_set.update(m_res["mitre_techniques"])

        for found_url in m_res["extracted_urls"]:
            u_res = analyze_url(found_url)
            url_results.append(u_res)
            all_indicators.extend(u_res["indicators"])
            mitre_set.update(u_res["mitre_techniques"])

        max_url_score = max([u["score"] for u in url_results], default=0)
        combined_score = combine_message_url_scores(m_res["score"], max_url_score)

    else:
        embedded_urls = extract_urls_from_text(raw_input)
        m_res = analyze_message_text(raw_input, channel=channel)
        message_result = m_res
        all_indicators.extend(m_res["indicators"])
        mitre_set.update(m_res["mitre_techniques"])

        for found_url in embedded_urls:
            u_res = analyze_url(found_url)
            url_results.append(u_res)
            all_indicators.extend(u_res["indicators"])
            mitre_set.update(u_res["mitre_techniques"])

        max_url_score = max([u["score"] for u in url_results], default=0)
        combined_score = min(100, max(m_res["score"], max_url_score))

    # [Feature 7] Regional Scam Intelligence (Southern Africa)
    primary_host = url_results[0]["host"] if url_results else ""
    regional_intel = analyze_regional_scam_context(raw_input=raw_input, host=primary_host)
    if regional_intel["indicators"]:
        all_indicators.extend(regional_intel["indicators"])
        mitre_set.update(["T1566.002", "T1598"])
        combined_score = min(100, combined_score + regional_intel["score_boost"])

    verdict = verdict_from_score(combined_score)
    mitre_sorted = sorted(mitre_set)
    containment = _containment_steps(verdict, channel)

    # [Feature 1] CYVORA Threat DNA
    threat_dna = compute_threat_dna(scan_type, combined_score, all_indicators, regional_intel)

    # [Feature 9] Digital Forensics Snapshot
    forensics_snapshot = build_forensics_snapshot(
        scan_type=scan_type,
        risk_score=combined_score,
        indicators=all_indicators,
        mitre_codes=mitre_sorted,
        url_results=url_results,
        regional_intel=regional_intel,
        threat_dna=threat_dna,
    )

    # [Feature 6] Community Threat Intelligence
    community_intel = correlate_and_record_threat_intel(
        scan_type=scan_type,
        raw_input=raw_input,
        risk_score=combined_score,
        url_results=url_results,
        regional_intel=regional_intel,
        threat_category=forensics_snapshot["threat_category"],
    )

    # [Feature 8] Threat Confidence Engine
    confidence_score = calculate_confidence_score(
        risk_score=combined_score,
        indicators=all_indicators,
        regional_intel=regional_intel,
        community_intel=community_intel,
    )

    # [Feature 2] Victim Impact Predictor
    impact_prediction = predict_victim_impact(
        risk_score=combined_score,
        threat_dna=threat_dna,
        regional_intel=regional_intel,
        confidence_score=confidence_score,
    )

    # [Feature 3] Attack Story Reconstruction
    attack_story = reconstruct_attack_story(
        scan_type=scan_type,
        verdict=verdict,
        threat_dna=threat_dna,
        regional_intel=regional_intel,
        indicators=all_indicators,
    )

    findings = {
        # Existing structure preserved
        "channel": channel or "unspecified",
        "risk_level": forensics_snapshot["risk_level"].lower(),
        "mitre_attack": mitre_sorted,
        "indicators": all_indicators,
        "url_analysis": url_results,
        "message_analysis": message_result,
        "containment_steps": containment,
        # New investigation intelligence layers
        "threat_dna": threat_dna,
        "impact_prediction": impact_prediction,
        "attack_story": attack_story,
        "confidence_score": confidence_score,
        "forensics_snapshot": forensics_snapshot,
        "regional_intelligence": {
            "regions": regional_intel["regions"],
            "targeted_brands": regional_intel["targeted_brands"],
            "primary_category": regional_intel["primary_category"],
        },
        "community_intelligence": {
            "similar_threats": community_intel["similar_threats"],
            "community_reports": community_intel["community_reports"],
        },
    }

    # [Feature 4] Concise AI Threat Explainer
    ai_explanation = generate_ai_threat_explanation(
        scan_type=scan_type,
        input_value=raw_input,
        risk_score=combined_score,
        verdict=verdict,
        findings=findings,
    )
    findings["ai_explanation"] = ai_explanation

    return {
        "risk_score": combined_score,
        "verdict": verdict,
        "findings": findings,
        "ai_summary": ai_explanation,
    }
from .text_heuristics import analyze_message_text, extract_urls_from_text
from .url_analyzer import analyze_url


def _verdict_from_score(score: int) -> str:
    if score >= 65:
        return "malicious"
    if score >= 30:
        return "suspicious"
    return "safe"


def _containment_steps(verdict: str, channel: str, indicators: list[dict]) -> list[dict]:
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
        combined_score = min(100, max(m_res["score"], max_url_score) + (15 if m_res["score"] and max_url_score else 0))

    else:
        # For 'file' or 'qr' inputs, analyze extracted text/URL if present and score payload metadata
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

    verdict = _verdict_from_score(combined_score)
    containment = _containment_steps(verdict, channel, all_indicators)

    if verdict == "malicious":
        summary = (
            f"High-risk {scan_type} indicators detected (score {combined_score}/100). "
            "Treat as untrusted, avoid credential/OTP entry, and escalate to incident reporting."
        )
    elif verdict == "suspicious":
        summary = (
            f"Moderate risk signals found (score {combined_score}/100). "
            "Verify sender authenticity independently before taking any action."
        )
    else:
        summary = f"No major phishing or spoofing heuristics triggered (score {combined_score}/100)."

    findings = {
        "channel": channel or "unspecified",
        "risk_level": "critical" if combined_score >= 80 else ("high" if combined_score >= 60 else ("medium" if combined_score >= 30 else "low")),
        "mitre_attack": sorted(mitre_set),
        "indicators": all_indicators,
        "url_analysis": url_results,
        "message_analysis": message_result,
        "containment_steps": containment,
    }

    return {
        "risk_score": combined_score,
        "verdict": verdict,
        "findings": findings,
        "ai_summary": summary,
    }
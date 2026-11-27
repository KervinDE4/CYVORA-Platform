# backend/apps/threat_scan/services/ai_advisor.py
import json
import os
from asyncio import timeout

import requests
import time

def _call_llm_json_or_text(prompt: str, expect_json: bool = False) -> str | dict | None:
    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    openai_key = os.environ.get("OPENAI_API_KEY", "").strip()

    if gemini_key:
        model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={gemini_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 320,
                **({"responseMimeType": "application/json"} if expect_json else {}),
            },
        }
        try:
            resp = requests.post(url, json=payload, timeout=12)
            resp.raise_for_status()
            text = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
            return json.loads(text) if expect_json else text
        except Exception:
            return None

    if openai_key:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {openai_key}", "Content-Type": "application/json"}
        payload = {
            "model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 320,
            **({"response_format": {"type": "json_object"}} if expect_json else {}),
        }
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=12)
            resp.raise_for_status()
            text = resp.json()["choices"][0]["message"]["content"].strip()
            return json.loads(text) if expect_json else text
        except Exception:
            return None

    return None


def generate_ai_threat_explanation(
    scan_type: str,
    input_value: str,
    risk_score: int,
    verdict: str,
    findings: dict,
) -> str:
    indicators = findings.get("indicators") or []
    mitre = findings.get("mitre_attack") or []
    top_reasons = [ind.get("title", "") for ind in indicators[:4] if ind.get("title")]

    prompt = (
        "You are CYVORA Threat Explainer. Explain this scan result to an everyday user in 2 to 3 short, punchy sentences "
        "(maximum 65 words total—never tedious). Clearly state: (1) why it was flagged or cleared, "
        "(2) the key indicators and MITRE ATT&CK tactic in plain words, and (3) why the risk score is "
        f"{risk_score}/100 ({verdict}).\n"
        f"Scan type: {scan_type}\n"
        f"Input: {input_value[:250]}\n"
        f"Indicators: {top_reasons}\n"
        f"MITRE ATT&CK: {mitre}"
    )

    ai_text = _call_llm_json_or_text(prompt, expect_json=False)
    if isinstance(ai_text, str) and ai_text:
        return ai_text

    # Deterministic concise fallback (guaranteed fast & clear offline)
    if verdict == "safe":
        return (
            f"This {scan_type} scored {risk_score}/100 (Safe) because no brand spoofing, malicious domains, "
            "or credential-harvesting patterns were found. Always verify unexpected requests before sharing sensitive details."
        )

    reason_phrase = ", ".join(top_reasons[:3]).lower() if top_reasons else "suspicious behavioral patterns"
    mitre_phrase = f" (mapped to {', '.join(mitre)})" if mitre else ""
    return (
        f"This {scan_type} scored {risk_score}/100 ({verdict.title()}) because it exhibits {reason_phrase}{mitre_phrase}. "
        "Each indicator increases the likelihood of credential or financial theft—do not interact or enter PINs/OTPs."
    )


def generate_security_advisor_guidance(scan_obj) -> dict:
    findings = scan_obj.findings or {}
    indicators = [i.get("title") for i in findings.get("indicators", [])[:4]]
    outcomes = (findings.get("impact_prediction") or {}).get("potential_outcomes", [])

    prompt = (
        "You are CYVORA Security Advisor. Return strictly valid JSON with keys: "
        '"why_dangerous", "what_happens_next", "what_to_do_now", "what_never_to_share". '
        "Keep every value concise (1-2 clear sentences, plain language, actionable).\n"
        f"Scan Type: {scan_obj.scan_type}\n"
        f"Verdict: {scan_obj.verdict} ({scan_obj.risk_score}/100)\n"
        f"Input: {scan_obj.input_value[:250]}\n"
        f"Indicators: {indicators}\n"
        f"Predicted Outcomes: {outcomes}"
    )

    ai_json = _call_llm_json_or_text(prompt, expect_json=True)
    if isinstance(ai_json, dict) and all(
        k in ai_json for k in ("why_dangerous", "what_happens_next", "what_to_do_now", "what_never_to_share")
    ):
        return {
            "why_dangerous": str(ai_json["why_dangerous"]),
            "what_happens_next": str(ai_json["what_happens_next"]),
            "what_to_do_now": str(ai_json["what_to_do_now"]),
            "what_never_to_share": str(ai_json["what_never_to_share"]),
        }

    # Deterministic structured fallback
    if scan_obj.verdict == "safe":
        return {
            "why_dangerous": "No high-risk phishing or malware patterns were detected in this scan, though zero-day lures can still appear legitimate.",
            "what_happens_next": "Proceeding normally carries low technical risk if you know and trust the sender.",
            "what_to_do_now": "Confirm the sender's identity independently before clicking payment links or downloading attachments.",
            "what_never_to_share": "Never share your banking PIN, SMS OTP codes, passwords, or national ID photos over chat or email.",
        }

    outcome_text = ", ".join(outcomes[:3]) if outcomes else "account compromise and financial loss"
    return {
        "why_dangerous": f"This {scan_obj.scan_type} uses deceptive signals ({', '.join(indicators[:2]) or 'social engineering lures'}) designed to trick you into handing over access.",
        "what_happens_next": f"If you interact or submit details, attackers can trigger {outcome_text.lower()} within minutes.",
        "what_to_do_now": "Close the page or chat immediately, block the sender, and change passwords/PINs via your bank's official app if you already clicked.",
        "what_never_to_share": "Never share your mobile money/ATM PIN, SMS one-time passwords (OTP), online banking password, or CVV.",
    }
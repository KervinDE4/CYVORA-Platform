import re

URL_PATTERN = re.compile(r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)", re.IGNORECASE)

CREDENTIAL_PATTERNS = [
    r"\b(otp|one[\s-]?time[\s-]?pin|pin|password|passcode|cvv|atm\s*pin|bank\s*pin)\b",
    r"\b(enter|confirm|verify|update|reset)\s+(your\s+)?(account|pin|password|details|card)\b",
]

URGENCY_PATTERNS = [
    r"\b(urgent|immediately|within\s+\d+\s*(hours?|mins?|minutes?)|suspended|blocked|locked|final\s+notice|expire[sd]?)\b",
    r"\b(ngokushesha|kumele|valekile|khawuleza)\b",  # Common SiSwati urgency/action cues
]

FINANCIAL_BAIT_PATTERNS = [
    r"\b(momo|mobile\s*money|ewallet|e-?wallet|refund|reversal|wrong\s*transfer|winner|won|reward|loan|grant)\b",
]


def extract_urls_from_text(text: str) -> list[str]:
    if not text:
        return []
    matches = URL_PATTERN.findall(text)
    cleaned = []
    for m in matches:
        item = m.rstrip(".,!?;:)")
        if item.lower().startswith("www."):
            item = f"https://{item}"
        if item not in cleaned:
            cleaned.append(item)
    return cleaned


def analyze_message_text(text: str, channel: str = "") -> dict:
    content = (text or "").strip()
    lowered = content.lower()
    score = 0
    indicators = []
    mitre_techniques = []

    if not content:
        return {"score": 0, "indicators": [], "extracted_urls": [], "mitre_techniques": []}

    extracted_urls = extract_urls_from_text(content)
    if extracted_urls:
        score += 15
        indicators.append({
            "id": "embedded_links",
            "title": f"Embedded Link(s) Found ({len(extracted_urls)})",
            "severity": "medium",
            "detail": f"Message includes external link(s): {', '.join(extracted_urls[:3])}.",
        })
        mitre_techniques.append("T1566.002")

    if any(re.search(pat, lowered) for pat in CREDENTIAL_PATTERNS):
        score += 35
        indicators.append({
            "id": "credential_harvest_cue",
            "title": "Credential or OTP / PIN Harvesting Request",
            "severity": "critical",
            "detail": "Message asks for or references PINs, OTP codes, passwords, or sensitive account details.",
        })
        mitre_techniques.append("T1598")

    if any(re.search(pat, lowered) for pat in URGENCY_PATTERNS):
        score += 25
        indicators.append({
            "id": "artificial_urgency",
            "title": "High-Pressure Urgency & Account Suspension Threat",
            "severity": "high",
            "detail": "Uses time pressure or threat of account restriction to rush victim decision-making.",
        })
        mitre_techniques.append("T1566")

    if any(re.search(pat, lowered) for pat in FINANCIAL_BAIT_PATTERNS):
        score += 20
        indicators.append({
            "id": "financial_social_bait",
            "title": "Mobile Money / Financial Lure Pattern",
            "severity": "high",
            "detail": "References mobile money, refunds/reversals, prizes, or urgent funds—a common scam vector.",
        })

    if channel.lower() in {"whatsapp", "sms", "telegram", "social_dm"} and (extracted_urls or score >= 25):
        score += 10
        indicators.append({
            "id": "messaging_vector_risk",
            "title": f"High-Velocity Messaging Channel ({channel})",
            "severity": "low",
            "detail": "Messaging apps and SMS are heavily used for fast link/social-engineering delivery.",
        })

    return {
        "score": min(score, 100),
        "indicators": indicators,
        "extracted_urls": extracted_urls,
        "mitre_techniques": sorted(set(mitre_techniques)),
    }
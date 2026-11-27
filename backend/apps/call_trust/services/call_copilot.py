import re

SCRIPT_RULES = [
    {
        "id": "otp_pin_request_on_call",
        "title": "PIN / OTP / Password Requested on Call",
        "severity": "critical",
        "points": 45,
        "patterns": [
            r"\b(otp|one[\s-]?time[\s-]?pin|pin|password|passcode|cvv|atm\s*pin)\b",
            r"\b(read\s+(out|me)|share|tell\s+me|confirm)\s+(your\s+)?(code|pin|otp|password)\b",
        ],
        "detail": "Banks, mobile money operators, and support desks do not ask callers to read out PINs, passwords, or OTPs.",
    },
    {
        "id": "fake_authority_or_fraud_desk",
        "title": "Impersonation of Bank Fraud, Police, Tax, or Support",
        "severity": "high",
        "points": 30,
        "patterns": [
            r"\b(fraud\s*(department|desk|team|alert)|bank\s*security|momo\s*support|sars|ers|police|investigator)\b",
            r"\b(unauthorized\s*(transaction|debit|transfer)|account\s*(compromised|hacked|frozen|suspended))\b",
        ],
        "detail": "Scammers frequently pose as fraud teams or authorities to create sudden fear and bypass verification.",
    },
    {
        "id": "momo_or_payment_reversal_lure",
        "title": "Mobile Money / Transfer Reversal or Refund Pressure",
        "severity": "high",
        "points": 28,
        "patterns": [
            r"\b(wrong\s*(transfer|payment|momo)|sent\s*by\s*mistake|reversal|refund|ewallet|e-?wallet|voucher)\b",
            r"\b(send\s*(it\s*)?back|pay\s*(a\s*)?(fee|tax|clearance|release))\b",
        ],
        "detail": "Matches common mobile money reversal and advance-fee call traps in Southern Africa.",
    },
    {
        "id": "remote_access_or_ussd_prompt",
        "title": "Remote Access App or Unprompted Approval Request",
        "severity": "critical",
        "points": 40,
        "patterns": [
            r"\b(anydesk|teamviewer|remote\s*access|screen\s*share|install\s*(an\s*)?app|approve\s*(the\s*)?(prompt|request))\b",
        ],
        "detail": "Installing remote-control tools or approving unprompted prompts can give callers direct control over your device or funds.",
    },
]


def analyze_call_script(call_script: str) -> dict:
    text = (call_script or "").strip()
    lowered = text.lower()
    score = 0
    indicators = []

    if text:
        for rule in SCRIPT_RULES:
            if any(re.search(pat, lowered) for pat in rule["patterns"]):
                score += rule["points"]
                indicators.append({
                    "id": rule["id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "detail": rule["detail"],
                })

    copilot_guidance = {
        "safe_response": (
            "Do not make decisions on the spot. Hang up, wait a moment, and call back only using "
            "an official number from your bank card, mobile carrier site, or trusted directory."
        ),
        "never_share": [
            "PIN",
            "OTP / Verification Codes",
            "Online Banking or App Password",
            "Card CVV or Full Card Details",
            "Remote Access / Screen Share",
        ],
    }

    return {
        "score": min(100, score),
        "indicators": indicators,
        "copilot_guidance": copilot_guidance,
    }
"""Evidence-led threat profiles for CYVORA ThreatScan.

Profiles are selected from deterministic indicator IDs. They describe likely
attack patterns, not confirmed victim activity or malware execution.
"""

PROFILE_CATALOG = {
    "credential_phishing": {
        "title": "Credential phishing",
        "summary": "The submitted content contains signals consistent with an attempt to obtain account credentials.",
        "trigger_ids": {
            "credential_harvest_cue",
            "cleartext_sensitive_path",
            "typosquatting_similarity",
        },
        "possible_steps": [
            ("Deceptive contact or link", "An attacker may use a message or lookalike destination to draw the recipient to a sign-in page."),
            ("Credential collection", "A deceptive page may ask for a username, password, PIN, or one-time code. This scan does not show that any information was submitted."),
            ("Account misuse", "If valid credentials were captured and reused, an account could be at risk. No account access is established by this scan."),
        ],
        "mitre": ["T1566.002", "T1598"],
    },
    "financial_social_engineering": {
        "title": "Financial or mobile-money social engineering",
        "summary": "The submitted content contains financial-lure or sensitive wallet-PIN solicitation signals.",
        "trigger_ids": {"financial_social_bait", "regional_momo_reversal"},
        "possible_steps": [
            ("Financial lure", "The sender may use a refund, prize, mistaken transfer, reversal, or payment story to gain the recipient's trust."),
            ("Request for action or secret", "The recipient may be pressured to disclose a wallet PIN, approve a transaction, or return funds."),
            ("Potential financial loss", "If the recipient complies, funds or wallet access could be at risk. No transfer is confirmed by this scan."),
        ],
        "mitre": ["T1566", "T1598"],
    },
    "brand_impersonation": {
        "title": "Brand impersonation or lookalike destination",
        "summary": "A detected URL references or resembles a protected brand outside its configured official domains.",
        "trigger_ids": {"brand_combosquatting", "typosquatting_similarity"},
        "possible_steps": [
            ("Lookalike destination", "The URL may be designed to appear connected to a known organisation."),
            ("Trust exploitation", "An attacker may use the familiar brand name to encourage the recipient to open the page or follow instructions."),
            ("Possible follow-on fraud", "The destination could be used for credential collection or another scam. This scan does not establish what the page does after loading."),
        ],
        "mitre": ["T1566.002"],
    },
    "malware_delivery": {
        "title": "Possible malicious file or payload delivery",
        "summary": "The submitted file or URL has signals associated with payload delivery. Static content inspection does not prove execution.",
        "trigger_ids": {"high_risk_tld", "ip_literal_url"},
        "possible_steps": [
            ("Payload delivery", "The sender may be attempting to persuade the recipient to download or open a file."),
            ("Execution attempt", "If a compatible malicious file is opened and allowed to run, it may execute code. This scan has not observed execution."),
            ("Potential device impact", "Depending on the payload, a device could be exposed to data theft, unwanted access, or disruption. Compromise is not confirmed."),
        ],
        "mitre": ["T1566.001", "T1204"],
    },
    "suspicious_url_infrastructure": {
        "title": "Suspicious URL infrastructure",
        "summary": "The URL contains infrastructure or obfuscation characteristics that warrant caution, but these signals alone do not prove phishing.",
        "trigger_ids": {"malformed_host", "punycode_homograph", "url_obfuscation", "high_risk_tld", "ip_literal_url"},
        "possible_steps": [
            ("Unusual destination", "The URL uses an unusual host, encoding, address format, or domain characteristic."),
            ("Destination inspection needed", "The actual page behaviour and ownership should be checked using safe, isolated analysis before drawing a stronger conclusion."),
        ],
        "mitre": ["T1566.002"],
    },
}


def build_attack_profile(scan_type: str, indicators: list[dict]) -> dict:
    """Return the strongest supported profile and its evidence references."""
    indicator_ids = {
        str(item.get("id", ""))
        for item in indicators
        if isinstance(item, dict) and item.get("id")
    }

    matches = []
    for profile_id, profile in PROFILE_CATALOG.items():
        matched = sorted(indicator_ids & profile["trigger_ids"])
        if matched:
            matches.append((len(matched), profile_id, profile, matched))

    if not matches:
        return {
            "profile_id": "unclassified",
            "title": "No specific attack pattern established",
            "summary": (
                "The available indicators do not support a specific attack sequence. "
                "This does not guarantee that the submitted content is safe."
            ),
            "evidence": [],
            "possible_steps": [],
            "limitations": [
                "Only the submitted content and available deterministic indicators were assessed.",
                "No victim interaction, credential submission, transaction, or device execution was observed.",
            ],
            "mitre_techniques": [],
        }

    # Prefer the profile supported by the greatest number of distinct indicators.
    # Catalog order provides a stable tie-breaker.
    _, profile_id, profile, matched_ids = max(matches, key=lambda item: item[0])
    evidence = [
        {
            "indicator_id": item.get("id"),
            "title": str(item.get("title") or item.get("id"))[:120],
            "severity": str(item.get("severity") or "info")[:20],
        }
        for item in indicators
        if isinstance(item, dict) and item.get("id") in matched_ids
    ]

    return {
        "profile_id": profile_id,
        "title": profile["title"],
        "summary": profile["summary"],
        "evidence": evidence,
        "possible_steps": [
            {"step": index, "title": title, "detail": detail, "evidence_status": "possible"}
            for index, (title, detail) in enumerate(profile["possible_steps"], start=1)
        ],
        "limitations": [
            "Possible steps are an analytical scenario, not observed events.",
            "This scan does not establish that a person clicked, shared a secret, transferred money, or executed a file.",
        ],
        "mitre_techniques": profile["mitre"],
    }

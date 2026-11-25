# backend/apps/threat_scan/services/threat_dna.py


def compute_threat_dna(scan_type: str, risk_score: int, indicators: list[dict], regional_intel: dict) -> dict:
    indicator_ids = {ind.get("id", "") for ind in indicators}
    blob = " ".join(f"{ind.get('title', '')} {ind.get('detail', '')}".lower() for ind in indicators)

    social_eng = 10 if risk_score > 0 else 0
    cred_theft = 5 if risk_score > 0 else 0
    fin_fraud = 5 if risk_score > 0 else 0
    id_theft = 5 if risk_score > 0 else 0
    malware = 5 if risk_score > 0 else 0

    if {"artificial_urgency", "lure_keywords", "messaging_vector_risk", "embedded_links"} & indicator_ids:
        social_eng += 55
    if any(w in blob for w in ("urgent", "suspend", "reward", "verify", "lure", "impersonat")):
        social_eng += 25

    if {"brand_combosquatting", "typosquatting_similarity", "credential_harvest_cue", "cleartext_sensitive_path"} & indicator_ids:
        cred_theft += 65
    if any(w in blob for w in ("pin", "otp", "password", "login", "credential")):
        cred_theft += 20

    if {"financial_social_bait", "regional_momo_reversal"} & indicator_ids or any(
        w in blob for w in ("bank", "fnb", "capitec", "standard bank", "nedbank", "momo", "ewallet", "payment", "refund", "sars")
    ):
        fin_fraud += 65
        id_theft += 35

    if any(w in blob for w in ("id number", "kyc", "account", "tax", "sars", "ers", "government", "passport")):
        id_theft += 40

    if scan_type == "file" or {"ip_literal_url", "high_risk_tld"} & indicator_ids or any(
        w in blob for w in ("exe", "apk", "payload", "dropper", "macro", "attachment", "download")
    ):
        malware += 55 if scan_type == "file" else 25

    # Scale smoothly with overall risk_score so low-risk scans don't show inflated DNA bars
    scale = max(0.25, min(1.0, (risk_score / 85.0) if risk_score else 0.0))

    def _cap(val: float) -> int:
        return min(100, max(0, round(val * scale)))

    return {
        "social_engineering": _cap(social_eng),
        "credential_theft": _cap(cred_theft),
        "financial_fraud": _cap(fin_fraud),
        "identity_theft": _cap(id_theft),
        "malware_delivery": _cap(malware),
    }
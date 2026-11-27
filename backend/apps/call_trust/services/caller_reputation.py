import hashlib
from django.db import DatabaseError
from apps.call_trust.models import VerifiedCaller
from apps.threat_scan.models import ThreatIntelligenceIndicator


def _phone_fingerprint(normalized_phone: str) -> str:
    raw = f"phone:{normalized_phone.strip().lower()}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def evaluate_caller_reputation(normalized_phone: str, format_flags: list[dict]) -> dict:
    score = 0
    indicators = list(format_flags)
    verified_caller_info = None
    community_hits = 0
    community_reports = 0

    for flag in format_flags:
        sev = (flag.get("severity") or "low").lower()
        score += 25 if sev == "high" else (15 if sev == "medium" else 5)

    if not normalized_phone:
        return {
            "score": min(100, max(score, 50)),
            "verified_caller": None,
            "community_hits": 0,
            "community_reports": 0,
            "indicators": indicators,
        }

    try:
        caller = VerifiedCaller.objects.filter(
            phone_e164=normalized_phone,
            is_verified=True,
        ).first()
        if caller:
            verified_caller_info = {
                "organization_name": caller.organization_name,
                "region_code": caller.region_code,
                "category": caller.category,
                "is_verified": caller.is_verified,
            }
            # Verified official numbers reduce baseline risk
            score = max(0, score - 40)
            indicators.append({
                "id": "verified_official_caller",
                "title": f"Verified Caller: {caller.organization_name}",
                "severity": "info",
                "detail": f"Matched verified {caller.category} record for {caller.organization_name}.",
            })
    except DatabaseError:
        pass

    try:
        fp = _phone_fingerprint(normalized_phone)
        intel = ThreatIntelligenceIndicator.objects.filter(fingerprint=fp).first()
        if intel:
            community_hits = intel.detection_count or 0
            community_reports = intel.community_report_count or 0
            if community_hits > 0 or community_reports > 0:
                boost = min(55, (community_reports * 15) + (community_hits * 6))
                score += boost
                indicators.append({
                    "id": "community_reported_phone",
                    "title": "Previously Flagged in CYVORA Threat Intelligence",
                    "severity": "critical" if community_reports >= 2 else "high",
                    "detail": (
                        f"Number '{normalized_phone}' has {community_hits} prior sighting(s) and "
                        f"{community_reports} community report(s)."
                    ),
                })
    except DatabaseError:
        pass

    return {
        "score": min(100, max(0, score)),
        "verified_caller": verified_caller_info,
        "community_hits": community_hits,
        "community_reports": community_reports,
        "indicators": indicators,
    }
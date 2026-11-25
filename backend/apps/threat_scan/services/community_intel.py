# backend/apps/threat_scan/services/community_intel.py
import hashlib
import re
from django.db import DatabaseError
from django.db.models import F
from backend.apps.threat_scan.models import ThreatIntelligenceIndicator

PHONE_REGEX = re.compile(r"(\+?\d[\d\s\-]{7,15}\d)")


def _fingerprint(indicator_type: str, normalized_value: str) -> str:
    raw = f"{indicator_type}:{normalized_value.strip().lower()}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def extract_candidate_indicators(
    scan_type: str,
    raw_input: str,
    url_results: list[dict],
    regional_intel: dict,
) -> list[tuple[str, str, str | None]]:
    candidates = []

    for u in url_results:
        host = (u.get("host") or "").strip().lower()
        if host:
            brand = (regional_intel.get("targeted_brands") or [None])[0]
            candidates.append(("domain", host, brand))

    for match in PHONE_REGEX.findall(raw_input or ""):
        digits = re.sub(r"[^\d+]", "", match)
        if len(digits) >= 8:
            candidates.append(("phone", digits, None))

    for brand in regional_intel.get("targeted_brands") or []:
        candidates.append(("brand", brand.lower(), brand))

    if not candidates and raw_input:
        payload_digest = hashlib.sha256(raw_input.strip().lower().encode("utf-8")).hexdigest()[:32]
        candidates.append(("payload_hash", payload_digest, None))

    # Deduplicate preserving order
    seen = set()
    unique = []
    for item in candidates:
        key = (item[0], item[1])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def correlate_and_record_threat_intel(
    scan_type: str,
    raw_input: str,
    risk_score: int,
    url_results: list[dict],
    regional_intel: dict,
    threat_category: str,
) -> dict:
    candidates = extract_candidate_indicators(scan_type, raw_input, url_results, regional_intel)
    fingerprints = [_fingerprint(ind_type, val) for ind_type, val, _ in candidates]

    similar_threats = 0
    community_reports = 0

    try:
        existing = list(ThreatIntelligenceIndicator.objects.filter(fingerprint__in=fingerprints))
        similar_threats = sum(row.detection_count for row in existing)
        community_reports = sum(row.community_report_count for row in existing)

        # Persist/increment intelligence only when suspicious or malicious (risk_score >= 30)
        if risk_score >= 30:
            existing_map = {row.fingerprint: row for row in existing}
            region_code = (regional_intel.get("regions") or [None])[0]

            for ind_type, norm_val, brand in candidates:
                fp = _fingerprint(ind_type, norm_val)
                if fp in existing_map:
                    ThreatIntelligenceIndicator.objects.filter(fingerprint=fp).update(
                        detection_count=F("detection_count") + 1,
                        highest_risk_score=max(existing_map[fp].highest_risk_score, risk_score),
                    )
                else:
                    ThreatIntelligenceIndicator.objects.create(
                        fingerprint=fp,
                        indicator_type=ind_type,
                        normalized_value=norm_val,
                        scam_brand=brand,
                        threat_category=threat_category,
                        region_code=region_code[:10] if region_code else None,
                        detection_count=1,
                        community_report_count=0,
                        highest_risk_score=risk_score,
                    )
    except DatabaseError:
        # Fail-open if table hasn't been migrated yet so existing scan flow never breaks
        pass

    return {
        "similar_threats": similar_threats,
        "community_reports": community_reports,
        "matched_fingerprints": fingerprints[:5],
    }
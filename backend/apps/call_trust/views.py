# backend/apps/call_trust/views.py

import hashlib
from django.db import DatabaseError
from django.db.models import F
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.threat_scan.models import ThreatIntelligenceIndicator
from apps.call_trust.models import CallCheck
from apps.call_trust.services.serializers import (
    CallCheckSerializer,
    CallTrustReportSerializer,
    CallTrustVerifySerializer,
)
from apps.call_trust.services.engine import run_call_trust_check
from .services.phone_normalizer import normalize_phone_number

from .models import CallCheck

OFFICIAL_TRUNKS = {
    "+26825186000": "First National Bank (FNB) Eswatini",
    "+26824056000": "Standard Bank Eswatini",
    "+26876060999": "MTN MoMo Eswatini",
    "+26824064000": "Eswatini Revenue Service (ERS)",
    "+27113560000": "Verified Regional Trunk",
}

DEMAND_LABELS = {
    "otp_pin_reset": "OTP / 2FA / PIN Reset",
    "account_freeze_alert": "Account Freeze / Security Alert",
    "fee_clearance_payment": "Fee / Tax / Clearance Payment",
    "remote_access_apk": "Remote Access / APK Install",
    "kyc_id_card_details": "KYC / ID / Card Details",
    "urgent_loan_prize_refund": "Urgent Loan / Prize / Refund",
}


def _normalize_phone(raw: str) -> str:
    return "".join(ch for ch in (raw or "") if ch.isdigit() or ch == "+")


def _get_jwt_user_id(request):
    user = getattr(request, "user", None)
    if user and getattr(user, "id", None):
        return str(user.id)
    auth = getattr(request, "auth", None)
    if isinstance(auth, dict) and auth.get("sub"):
        return str(auth["sub"])
    return None


class CallTrustVerifyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        phone_number = (request.data.get("phone_number") or "").strip()
        claimed_institution = (request.data.get("claimed_institution") or "").strip()
        raw_demands = request.data.get("caller_demands") or []

        if not phone_number:
            return Response(
                {"detail": "phone_number is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        caller_demands = [
            str(item).strip()
            for item in raw_demands
            if isinstance(item, str) and str(item).strip()
        ]

        normalized = _normalize_phone(phone_number)
        matched_org = OFFICIAL_TRUNKS.get(normalized)
        is_official = bool(matched_org)

        # Base confidence from trunk attestation, reduced by selected caller demands
        confidence = 94 if is_official else 18
        confidence -= len(caller_demands) * 14
        if "otp_pin_reset" in caller_demands or "remote_access_apk" in caller_demands:
            confidence -= 10
        confidence = max(4, min(99, confidence))

        is_spoofed = (not is_official) or (confidence < 45)
        verdict_api = "SPOOFED" if is_spoofed else "LEGITIMATE"
        verdict_db = "spoofed" if is_spoofed else "legitimate"
        risk_level = (
            "HIGH RISK" if confidence < 35 else "MEDIUM RISK" if confidence < 70 else "LOW RISK"
        )
        risk_class = (
            "high" if confidence < 35 else "medium" if confidence < 70 else "low"
        )

        demand_names = [DEMAND_LABELS.get(d, d) for d in caller_demands]
        notes = [
            (
                f"Matched verified outbound trunk for {matched_org}."
                if is_official
                else f"Number {phone_number} is not listed as an official trunk for '{claimed_institution}'."
            ),
            (
                f"Caller demands evaluated ({', '.join(demand_names)}): high-risk social engineering signals detected."
                if demand_names
                else "No high-pressure caller demands selected."
            ),
            "Verify callback independently via an official institution number before sharing credentials or funds.",
        ]

        findings = {
            "normalized_phone": normalized,
            "matched_official_trunk": matched_org,
            "caller_demands": caller_demands,
            "notes": notes,
        }

        user_id = _get_jwt_user_id(request)
        if not user_id:
            return Response(
                {"detail": "Authenticated user ID missing."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Persist using the fields and verdict choices declared by CallCheck.
        # Confidence is retained in findings; risk_score is the inverse risk measure.
        db_verdict = (
            CallCheck.Verdict.HIGH_RISK
            if is_spoofed
            else CallCheck.Verdict.VERIFIED_SAFE
        )
        findings["confidence_score"] = confidence
        findings["risk_level"] = risk_level
        create_kwargs = {
            "user_id": user_id,
            "phone_number": phone_number,
            "normalized_phone": normalized,
            "risk_score": 100 - confidence,
            "claimed_institution": claimed_institution,
            "caller_demands": caller_demands,
            "verdict": db_verdict,
            "findings": findings,
        }

        record = CallCheck.objects.create(**create_kwargs)

        return Response(
            {
                "id": str(record.id),
                "phone_number": record.phone_number,
                "claimed_institution": record.claimed_institution,
                "caller_demands": record.caller_demands,
                "confidence_score": record.confidence_score,
                "verdict": verdict_api,
                "risk_level": risk_level,
                "risk_class": risk_class,
                "attestation": (
                    "Level A (Full Attestation)"
                    if is_official
                    else "Level C (Gateway Only / Untrusted)"
                ),
                "notes": notes,
            },
            status=status.HTTP_201_CREATED,
        )


class CallTrustHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = CallCheck.objects.all()
        user_id = _get_jwt_user_id(request)
        if user_id:
            qs = qs.filter(user_id=user_id)

        items = [
            {
                "id": str(row.id),
                "phone_number": row.phone_number,
                "claimed_institution": row.claimed_institution,
                "caller_demands": row.caller_demands or [],
                "confidence_score": int(row.findings.get("confidence_score", 100 - row.risk_score)),
                "risk_level": row.findings.get(
                    "risk_level",
                    "HIGH RISK" if row.risk_score >= 65 else "MEDIUM RISK" if row.risk_score >= 30 else "LOW RISK",
                ),
                "verdict": (
                    "SPOOFED" if row.verdict == CallCheck.Verdict.HIGH_RISK
                    else "LEGITIMATE" if row.verdict == CallCheck.Verdict.VERIFIED_SAFE
                    else "SUSPICIOUS"
                ),
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in qs[:20]
        ]
        return Response(items, status=status.HTTP_200_OK)

class CallTrustReportView(APIView):
    """POST /api/v1/call-trust/report/"""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = CallTrustReportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        raw_phone = serializer.validated_data["phone_number"]
        scam_category = serializer.validated_data.get("scam_category", "Suspicious Call / Impersonation")

        norm = normalize_phone_number(raw_phone)
        normalized = norm["normalized"] or raw_phone.strip()
        fingerprint = hashlib.sha256(f"phone:{normalized.lower()}".encode("utf-8")).hexdigest()

        community_reports = 1
        try:
            existing = ThreatIntelligenceIndicator.objects.filter(fingerprint=fingerprint).first()
            if existing:
                ThreatIntelligenceIndicator.objects.filter(pk=existing.pk).update(
                    community_report_count=F("community_report_count") + 1,
                    detection_count=F("detection_count") + 1,
                )
                existing.refresh_from_db()
                community_reports = existing.community_report_count
            else:
                created = ThreatIntelligenceIndicator.objects.create(
                    fingerprint=fingerprint,
                    indicator_type="phone",
                    normalized_value=normalized,
                    scam_brand=None,
                    threat_category=scam_category,
                    region_code=norm["country_label"][:10] if norm["country_label"] else None,
                    detection_count=1,
                    community_report_count=1,
                    highest_risk_score=80,
                )
                community_reports = created.community_report_count
        except DatabaseError:
            pass

        return Response(
            {
                "reported": True,
                "normalized_phone": normalized,
                "community_reports": community_reports,
            },
            status=status.HTTP_201_CREATED,
        )

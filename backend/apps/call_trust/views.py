from django.shortcuts import render
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


class CallTrustVerifyView(APIView):
    """POST /api/v1/call-trust/verify/"""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = CallTrustVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone_number = serializer.validated_data["phone_number"]
        call_script = serializer.validated_data.get("call_script", "")
        channel = serializer.validated_data.get("channel", "voice_call")

        result = run_call_trust_check(
            phone_number=phone_number,
            call_script=call_script,
            channel=channel,
        )

        check_obj = CallCheck.objects.create(
            user_id=request.user.id,
            phone_number=phone_number,
            normalized_phone=result["normalized_phone"] or phone_number,
            call_script=call_script,
            risk_score=result["risk_score"],
            verdict=result["verdict"],
            findings=result["findings"],
        )

        return Response(CallCheckSerializer(check_obj).data, status=status.HTTP_201_CREATED)


class CallTrustHistoryView(APIView):
    """GET /api/v1/call-trust/history/"""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = CallCheck.objects.filter(user_id=request.user.id)[:30]
        return Response(CallCheckSerializer(qs, many=True).data, status=status.HTTP_200_OK)


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


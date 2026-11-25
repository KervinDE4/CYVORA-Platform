from django.shortcuts import render, get_object_or_404
# backend/apps/threat_scan/views.py
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
import re
from .models import Scan
from .serializers import ScanRecordSerializer, ThreatScanAnalyzeSerializer, ThreatScanAdvisorRequestSerializer
from .services.engine import run_threat_scan
from .services.ai_advisor import generate_security_advisor_guidance

class ThreatScanAnalyzeView(APIView):
    """POST /api/v1/threat-scan/analyze/"""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ThreatScanAnalyzeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        scan_type = serializer.validated_data["scan_type"]
        input_value = serializer.validated_data["input_value"]
        channel = serializer.validated_data.get("channel", "")

        result = run_threat_scan(scan_type=scan_type, input_value=input_value, channel=channel)

        scan_obj = Scan.objects.create(
            user_id=request.user.id,
            scan_type=scan_type,
            input_value=input_value,
            risk_score=result["risk_score"],
            verdict=result["verdict"],
            findings=result["findings"],
            ai_summary=result["ai_summary"],
        )

        return Response(ScanRecordSerializer(scan_obj).data, status=status.HTTP_201_CREATED)


class ThreatScanHistoryView(APIView):
    """GET /api/v1/threat-scan/history/"""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        verdict_filter = request.query_params.get("verdict", "").strip().lower()
        qs = Scan.objects.filter(user_id=request.user.id)
        if verdict_filter in {"safe", "suspicious", "malicious"}:
            qs = qs.filter(verdict=verdict_filter)
        qs = qs[:30]
        return Response(ScanRecordSerializer(qs, many=True).data, status=status.HTTP_200_OK)
# Create your views here.

class ThreatScanAdvisorView(APIView):
    """POST /api/v1/threat-scan/advisor/"""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ThreatScanAdvisorRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        scan_obj = get_object_or_404(
            Scan,
            id=serializer.validated_data["scan_id"],
            user_id=request.user.id,
        )

        guidance = generate_security_advisor_guidance(scan_obj)
        return Response(guidance, status=status.HTTP_200_OK)
import logging
from rest_framework.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from pypdf import PdfReader
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Scan
from .serializers import (
    ScanRecordSerializer,
    ThreatScanAnalyzeSerializer,
    ThreatScanAdvisorRequestSerializer,
)
from .services.engine import run_threat_scan
from .services.ai_advisor import generate_security_advisor_guidance

logger = logging.getLogger(__name__)

MAX_PDF_PAGES = 20
MAX_EXTRACTED_TEXT = 10000


def _extract_pdf_text(uploaded_file):
    """Extract bounded text from an uploaded PDF; never scan only its filename."""
    uploaded_file.seek(0)
    reader = PdfReader(uploaded_file)

    if reader.is_encrypted:
        raise ValidationError({"file": "Password-protected PDFs are not supported yet."})

    if len(reader.pages) > MAX_PDF_PAGES:
        raise ValidationError({"file": f"PDFs are limited to {MAX_PDF_PAGES} pages."})

    extracted = []
    for page in reader.pages:
        page_text = page.extract_text() or ""
        if page_text:
            extracted.append(page_text)

    text = "\n".join(extracted).strip()
    if not text:
        raise ValidationError({
            "file": "No readable text was found in this PDF. Scanned-image PDFs need OCR, which is not enabled yet."
        })

    return text[:MAX_EXTRACTED_TEXT]


class ThreatScanAnalyzeView(APIView):
    """POST /api/v1/threat-scan/analyze/"""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ThreatScanAnalyzeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        scan_type = serializer.validated_data["scan_type"]
        input_value = serializer.validated_data.get("input_value", "")
        channel = serializer.validated_data.get("channel", "")
        uploaded_file = serializer.validated_data.get("file")

        if uploaded_file is not None:
            try:
                extracted_text = _extract_pdf_text(uploaded_file)
            except ValidationError:
                raise
            except Exception as exc:
                logger.warning("ThreatScan PDF extraction failed: %s", exc, exc_info=True)
                return Response(
                    {"detail": "The PDF could not be read. Please upload a valid, text-based PDF."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            input_value = f"PDF filename: {uploaded_file.name}\n{extracted_text}"

        try:
            result = run_threat_scan(
                scan_type=scan_type,
                input_value=input_value,
                channel=channel,
            )

            scan_obj = Scan.objects.create(
                user_id=request.user.id,
                scan_type=scan_type,
                input_value=input_value,
                risk_score=result["risk_score"],
                verdict=result["verdict"],
                findings=result["findings"],
                ai_summary=result["ai_summary"],
            )
            return Response(
                ScanRecordSerializer(scan_obj).data,
                status=status.HTTP_201_CREATED,
            )
        except Exception:
            logger.exception(
                "ThreatScan analysis failed (scan_type=%s, user_id=%s)",
                scan_type,
                request.user.id,
            )
            return Response(
                {"detail": "ThreatScan could not complete this analysis. The server error has been logged."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ThreatScanHistoryView(APIView):
    """GET /api/v1/threat-scan/history/"""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        verdict_filter = request.query_params.get("verdict", "").strip().lower()
        try:
            qs = Scan.objects.filter(user_id=request.user.id)
            if verdict_filter in {"safe", "suspicious", "malicious"}:
                qs = qs.filter(verdict=verdict_filter)
            qs = qs[:30]
            return Response(
                ScanRecordSerializer(qs, many=True).data,
                status=status.HTTP_200_OK,
            )
        except Exception:
            logger.exception(
                "ThreatScan history retrieval failed (user_id=%s)",
                request.user.id,
            )
            return Response(
                {"detail": "ThreatScan history could not be loaded. The server error has been logged."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


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

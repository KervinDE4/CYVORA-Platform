import logging

from rest_framework.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from pypdf import PdfReader
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Scan, ScamReport
from .serializers import (
    ScanRecordSerializer,
    ThreatScanAnalyzeSerializer,
    ThreatScanAdvisorRequestSerializer,
    ThreatScanEscalationSerializer,
)
from .services.engine import run_threat_scan
from .services.ai_advisor import generate_security_advisor_guidance

logger = logging.getLogger(__name__)

MAX_PDF_PAGES = 20
MAX_EXTRACTED_TEXT = 10000

INPUT_TYPE_TO_DB = {
    Scan.ScanType.URL: "url",
    Scan.ScanType.MESSAGE: "text",
    Scan.ScanType.FILE: "pdf",
    Scan.ScanType.CALL: "phone_check",
    Scan.ScanType.QR: "screenshot",
}
VERDICT_TO_DB = {"safe": "clean", "suspicious": "suspicious", "malicious": "malicious"}
VERDICT_FROM_DB = {"clean": "safe", "suspicious": "suspicious", "malicious": "malicious"}


def _extract_pdf_text(uploaded_file):
    uploaded_file.seek(0)
    reader = PdfReader(uploaded_file)

    if reader.is_encrypted:
        raise ValidationError({"file": "Password-protected PDFs are not supported yet."})
    if len(reader.pages) > MAX_PDF_PAGES:
        raise ValidationError({"file": f"PDFs are limited to {MAX_PDF_PAGES} pages."})

    extracted = [page.extract_text() or "" for page in reader.pages]
    text = "\n".join(part for part in extracted if part).strip()
    if not text:
        raise ValidationError({
            "file": "No readable text was found. Scanned-image PDFs require OCR, which is not enabled yet."
        })
    return text[:MAX_EXTRACTED_TEXT]


class ThreatScanAnalyzeView(APIView):
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
                input_value = f"PDF filename: {uploaded_file.name}\n{_extract_pdf_text(uploaded_file)}"
            except ValidationError:
                raise
            except Exception:
                logger.exception("ThreatScan PDF extraction failed")
                return Response(
                    {"detail": "The PDF could not be read. Please upload a valid, text-based PDF."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        try:
            result = run_threat_scan(scan_type=scan_type, input_value=input_value, channel=channel)
            db_input_type = INPUT_TYPE_TO_DB[scan_type]
            db_verdict = VERDICT_TO_DB[result["verdict"]]
            findings = result["findings"]
            containment_steps = findings.get("containment_steps", [])

            scan_obj = Scan.objects.create(
                user_id=request.user.id,
                module_type="threat_scan",
                input_type=db_input_type,
                channel=channel or None,
                target_value=input_value,
                verdict=db_verdict,
                risk_score=result["risk_score"],
                headline=f"{scan_type.title()} analysis: {result['verdict'].title()}",
                summary=result["ai_summary"],
                indicators=findings,
                containment_steps=containment_steps,
            )
            response_data = ScanRecordSerializer(scan_obj).data
            response_data["verdict"] = VERDICT_FROM_DB.get(scan_obj.verdict, scan_obj.verdict)
            return Response(response_data, status=status.HTTP_201_CREATED)
        except Exception:
            logger.exception(
                "ThreatScan analysis failed (scan_type=%s, user_id=%s)",
                scan_type,
                request.user.id,
            )
            return Response(
                {"detail": "ThreatScan could not complete this analysis. Check the backend application logs for the recorded exception."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ThreatScanHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        verdict_filter = request.query_params.get("verdict", "").strip().lower()
        try:
            qs = Scan.objects.filter(user_id=request.user.id, module_type="threat_scan")
            if verdict_filter in VERDICT_TO_DB:
                qs = qs.filter(verdict=VERDICT_TO_DB[verdict_filter])
            records = list(qs[:30])
            data = ScanRecordSerializer(records, many=True).data
            for item, record in zip(data, records):
                item["verdict"] = VERDICT_FROM_DB.get(record.verdict, record.verdict)
            return Response(data, status=status.HTTP_200_OK)
        except Exception:
            logger.exception("ThreatScan history retrieval failed (user_id=%s)", request.user.id)
            return Response(
                {"detail": "ThreatScan history could not be loaded. Check the backend application logs for the recorded exception."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ThreatScanAdvisorView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "threat_scan_ai"

    def post(self, request):
        serializer = ThreatScanAdvisorRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        scan_obj = get_object_or_404(
            Scan,
            id=serializer.validated_data["scan_id"],
            user_id=request.user.id,
            module_type="threat_scan",
        )
        guidance = generate_security_advisor_guidance(scan_obj)
        return Response(guidance, status=status.HTTP_200_OK)



def _escalation_category(scan_obj):
    """Map the scan's actual input type to an allowed report category."""
    if scan_obj.input_type == "phone_check":
        return "caller_spoofing"
    if scan_obj.input_type in {"url", "screenshot"}:
        return "malicious_link"
    if scan_obj.input_type in {"text", "pdf"}:
        return "sms_whatsapp_phishing"
    return None


def _build_escalation_description(scan_obj, user_description=""):
    """Create a concise, evidence-led report without asserting victim impact."""
    parts = [
        "Submitted from CYVORA ThreatScan for human review.",
        f"Scan type: {scan_obj.input_type}.",
        f"Scan verdict: {scan_obj.verdict}.",
        f"Risk score: {scan_obj.risk_score}/100.",
    ]
    if scan_obj.headline:
        parts.append(f"Headline: {scan_obj.headline[:300]}.")
    if user_description:
        parts.append(f"User-provided context: {user_description.strip()[:2000]}")
    parts.append("This report is unverified and requires human review.")
    return chr(10).join(parts)


class ThreatScanEscalateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, scan_id):
        scan_obj = get_object_or_404(
            Scan,
            id=scan_id,
            user_id=request.user.id,
            module_type="threat_scan",
        )

        serializer = ThreatScanEscalationSerializer(data=request.data or {})
        serializer.is_valid(raise_exception=True)

        existing = ScamReport.objects.filter(
            user_id=request.user.id,
            scan_id=scan_obj.id,
        ).first()
        if existing:
            return Response(
                {
                    "detail": "This scan has already been escalated.",
                    "report_id": str(existing.id),
                    "status": existing.status,
                },
                status=status.HTTP_200_OK,
            )

        category = _escalation_category(scan_obj)
        if category is None:
            return Response(
                {"detail": "This scan type cannot currently be escalated."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            report = ScamReport.objects.create(
                user_id=request.user.id,
                scan_id=scan_obj.id,
                category=category,
                offender_contact=serializer.validated_data.get("offender_contact") or None,
                description=_build_escalation_description(
                    scan_obj,
                    serializer.validated_data.get("description", ""),
                ),
                status="pending",
            )
        except Exception:
            logger.exception(
                "ThreatScan escalation failed (scan_id=%s, user_id=%s)",
                scan_obj.id,
                request.user.id,
            )
            return Response(
                {"detail": "The report could not be saved. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {
                "detail": "Your report has been submitted for review.",
                "report_id": str(report.id),
                "status": report.status,
                "category": report.category,
                "created_at": report.created_at,
            },
            status=status.HTTP_201_CREATED,
        )

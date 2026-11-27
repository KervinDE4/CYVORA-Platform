from django.shortcuts import render
# backend/apps/reports/views.py
import hashlib
from urllib.parse import urlparse, urlunparse

from django.db import IntegrityError, transaction
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import IncidentReport


def _get_jwt_user_id(request):
    user = getattr(request, "user", None)
    if user and getattr(user, "id", None):
        return str(user.id)
    auth = getattr(request, "auth", None)
    if isinstance(auth, dict) and auth.get("sub"):
        return str(auth["sub"])
    return None


def _canonicalize_target(module_type: str, raw_target: str) -> str:
    cleaned = (raw_target or "").strip()
    if module_type == "call_trust":
        digits_and_plus = "".join(ch for ch in cleaned if ch.isdigit() or ch == "+")
        digits_only = digits_and_plus.lstrip("+")
        # Normalize 00 prefix if present
        if digits_only.startswith("00"):
            digits_only = digits_only[2:]
        return f"phone:{digits_only}"

    # ThreatScan URL / payload canonicalization
    lowered = cleaned.lower()
    if "://" in lowered:
        parsed = urlparse(lowered)
        host = parsed.hostname or ""
        path = parsed.path.rstrip("/") or "/"
        return f"url:{host}{path}"
    return f"payload:{' '.join(lowered.split())}"


def _fingerprint_target(module_type: str, raw_target: str) -> str:
    canonical = _canonicalize_target(module_type, raw_target)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class IncidentReportSubmitView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_id = _get_jwt_user_id(request)
        if not user_id:
            return Response(
                {"detail": "Authenticated user ID missing."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        module_type = (request.data.get("module_type") or "").strip()
        target_value = (request.data.get("target_value") or "").strip()
        verdict = (request.data.get("verdict") or "").strip().upper()
        risk_level = (request.data.get("risk_level") or "HIGH RISK").strip().upper()
        notes = (request.data.get("notes") or "").strip()
        source_record_id = request.data.get("source_record_id") or None

        if module_type not in ("threat_scan", "call_trust"):
            return Response(
                {"detail": "module_type must be 'threat_scan' or 'call_trust'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not target_value:
            return Response(
                {"detail": "target_value is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Guard against reporting safe/legitimate results
        safe_verdicts = {"SAFE", "LEGITIMATE"}
        if verdict in safe_verdicts and risk_level == "LOW RISK":
            return Response(
                {"detail": "Safe or low-risk results do not require incident reporting."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        fingerprint = _fingerprint_target(module_type, target_value)

        existing = IncidentReport.objects.filter(
            user_id=user_id,
            module_type=module_type,
            target_fingerprint=fingerprint,
        ).first()
        if existing:
            return Response(
                {
                    "detail": "You have already reported this target.",
                    "already_reported": True,
                    "report_id": str(existing.id),
                },
                status=status.HTTP_409_CONFLICT,
            )

        try:
            with transaction.atomic():
                report = IncidentReport.objects.create(
                    user_id=user_id,
                    module_type=module_type,
                    source_record_id=source_record_id,
                    target_value=target_value,
                    target_fingerprint=fingerprint,
                    verdict=verdict or "SUSPICIOUS",
                    risk_level=risk_level,
                    notes=notes,
                )
        except IntegrityError:
            return Response(
                {
                    "detail": "You have already reported this target.",
                    "already_reported": True,
                },
                status=status.HTTP_409_CONFLICT,
            )

        return Response(
            {
                "id": str(report.id),
                "already_reported": False,
                "message": "Incident report submitted to CYVORA intelligence.",
            },
            status=status.HTTP_201_CREATED,
        )


class IncidentReportStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_id = _get_jwt_user_id(request)
        if not user_id:
            return Response(
                {"detail": "Authenticated user ID missing."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        module_type = (request.query_params.get("module_type") or "").strip()
        target_value = (request.query_params.get("target_value") or "").strip()
        if module_type not in ("threat_scan", "call_trust") or not target_value:
            return Response({"reported": False}, status=status.HTTP_200_OK)

        fingerprint = _fingerprint_target(module_type, target_value)
        exists = IncidentReport.objects.filter(
            user_id=user_id,
            module_type=module_type,
            target_fingerprint=fingerprint,
        ).exists()
        return Response({"reported": exists}, status=status.HTTP_200_OK)
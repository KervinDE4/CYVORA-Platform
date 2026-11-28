# backend/apps/threat_scan/urls.py
from django.urls import path
from .views import (\n    ThreatScanAnalyzeView,\n    ThreatScanHistoryView,\n    ThreatScanAdvisorView,\n    ThreatScanEscalateView,\n)

urlpatterns = [
    path("analyze/", ThreatScanAnalyzeView.as_view(), name="threat-scan-analyze"),
    path("history/", ThreatScanHistoryView.as_view(), name="threat-scan-history"),
    path("advisor/", ThreatScanAdvisorView.as_view(), name="threat-scan-advisor"),\n    path("<uuid:scan_id>/escalate/", ThreatScanEscalateView.as_view(), name="threat-scan-escalate"),
]
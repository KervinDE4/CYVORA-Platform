from django.urls import path

from .views import (
    ThreatScanAnalyzeView,
    ThreatScanHistoryView,
    ThreatScanAdvisorView,
    ThreatScanEscalateView,
)

urlpatterns = [
    path("analyze/", ThreatScanAnalyzeView.as_view(), name="threat-scan-analyze"),
    path("history/", ThreatScanHistoryView.as_view(), name="threat-scan-history"),
    path("advisor/", ThreatScanAdvisorView.as_view(), name="threat-scan-advisor"),
    path("<uuid:scan_id>/escalate/", ThreatScanEscalateView.as_view(), name="threat-scan-escalate"),
]

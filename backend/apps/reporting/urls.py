# backend/apps/reports/urls.py
from django.urls import path
from .views import IncidentReportStatusView, IncidentReportSubmitView

urlpatterns = [
    path("submit/", IncidentReportSubmitView.as_view(), name="report-submit"),
    path("status/", IncidentReportStatusView.as_view(), name="report-status"),
]
from django.urls import path
from .views import CallTrustHistoryView, CallTrustReportView, CallTrustVerifyView

urlpatterns = [
    path("verify/", CallTrustVerifyView.as_view(), name="call-trust-verify"),
    path("history/", CallTrustHistoryView.as_view(), name="call-trust-history"),
    path("report/", CallTrustReportView.as_view(), name="call-trust-report"),
]
import uuid

from django.db import models
from django.utils import timezone


class Scan(models.Model):
    """Django representation of the existing shared public.scans table."""

    class ScanType(models.TextChoices):
        URL = "url", "URL"
        MESSAGE = "message", "Message"
        CALL = "call", "Call"
        FILE = "file", "File"
        QR = "qr", "QR"

    class Verdict(models.TextChoices):
        SAFE = "safe", "Safe"
        SUSPICIOUS = "suspicious", "Suspicious"
        MALICIOUS = "malicious", "Malicious"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.UUIDField(db_index=True)
    module_type = models.CharField(max_length=30, default="threat_scan")
    input_type = models.CharField(max_length=30)
    channel = models.CharField(max_length=30, null=True, blank=True)
    target_value = models.TextField(null=True, blank=True)
    claimed_identity = models.TextField(null=True, blank=True)
    verdict = models.CharField(max_length=20)
    risk_score = models.IntegerField(default=0)
    headline = models.TextField()
    summary = models.TextField()
    indicators = models.JSONField(default=dict)
    containment_steps = models.JSONField(default=list)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        managed = False
        db_table = "scans"
        ordering = ["-created_at"]

    @property
    def scan_type(self):
        return {
            "url": "url",
            "text": "message",
            "pdf": "file",
            "phone_check": "call",
            "screenshot": "qr",
        }.get(self.input_type, self.input_type)

    @property
    def input_value(self):
        return self.target_value or ""

    @property
    def findings(self):
        if isinstance(self.indicators, dict):
            return self.indicators
        if isinstance(self.indicators, list):
            return {"indicators": self.indicators}
        return {}

    @property
    def ai_summary(self):
        return self.summary

    def __str__(self):
        return f"{self.module_type}:{self.input_type}:{self.verdict} ({self.risk_score})"


class ThreatIntelligenceIndicator(models.Model):
    class IndicatorType(models.TextChoices):
        DOMAIN = "domain", "Domain"
        PHONE = "phone", "Phone"
        BRAND = "brand", "Brand"
        PAYLOAD_HASH = "payload_hash", "Payload Hash"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    fingerprint = models.CharField(max_length=64, unique=True)
    indicator_type = models.CharField(max_length=20, choices=IndicatorType.choices)
    normalized_value = models.TextField()
    scam_brand = models.CharField(max_length=100, blank=True, null=True)
    threat_category = models.CharField(max_length=100, default="General Phishing")
    region_code = models.CharField(max_length=10, blank=True, null=True)
    detection_count = models.IntegerField(default=1)
    community_report_count = models.IntegerField(default=0)
    highest_risk_score = models.IntegerField(default=0)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        managed = False
        db_table = "threat_intelligence_indicators"
        ordering = ["-last_seen_at"]

    def __str__(self):
        return f"{self.indicator_type}:{self.normalized_value} ({self.detection_count})"

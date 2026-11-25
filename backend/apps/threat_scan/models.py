from django.db import models

# backend/apps/threat_scan/models.py
import uuid
from django.db import models


class Scan(models.Model):
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
    scan_type = models.CharField(max_length=20, choices=ScanType.choices)
    input_value = models.TextField()
    risk_score = models.IntegerField(default=0)
    verdict = models.CharField(max_length=20, choices=Verdict.choices, default=Verdict.SAFE)
    findings = models.JSONField(default=dict)
    ai_summary = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        managed = False
        db_table = "scans"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.scan_type}:{self.verdict} ({self.risk_score})"
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
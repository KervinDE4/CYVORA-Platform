from django.db import models
import uuid


class VerifiedCaller(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    phone_e164 = models.CharField(max_length=25, unique=True)
    organization_name = models.CharField(max_length=150)
    region_code = models.CharField(max_length=2, default='SZ')
    category = models.CharField(max_length=50, default='Financial/ Telecom')
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    claimed_institution = models.CharField(max_length=160, blank=True, default="")
    caller_demands = models.JSONField(default=list)
    confidence_score = models.IntegerField(default=50)

    class Meta:
        managed = False
        db_table = 'verified_callers'

    def __str__(self):
        return f'{self.organization_name} {self.phone_e164}'

class CallCheck(models.Model):
    class Verdict(models.TextChoices):
        VERIFIED_SAFE = 'verified_safe', 'Verified Safe'
        SUSPICIOUS = 'suspicious', 'Suspicious'
        HIGH_RISK = 'high_risk', 'High Risk'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.UUIDField(db_index=True)
    phone_number = models.CharField(max_length=50)
    normalized_phone = models.CharField(max_length=25, db_index=True)
    call_script = models.TextField(blank=True, default="")
    risk_score = models.IntegerField(default=0)
    claimed_institution = models.CharField(max_length=160, blank=True, default="")
    caller_demands = models.JSONField(default=list)
    verdict = models.CharField(
        max_length=30,
        choices=Verdict.choices,
        default=Verdict.SUSPICIOUS,
    )
    findings = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        managed = False
        db_table = 'call_checks'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.normalized_phone}:{self.verdict}({self.risk_score})'


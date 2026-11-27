# backend/apps/reports/models.py
import uuid
from django.db import models


class IncidentReport(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.UUIDField(db_index=True)
    module_type = models.CharField(max_length=30)
    source_record_id = models.UUIDField(null=True, blank=True)
    target_value = models.TextField()
    target_fingerprint = models.CharField(max_length=64, db_index=True)
    verdict = models.CharField(max_length=30)
    risk_level = models.CharField(max_length=30, default="HIGH RISK")
    notes = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        managed = False
        db_table = "incident_reports"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.module_type}:{self.target_value} ({self.verdict})"


from django.db import models

# Create your models here.

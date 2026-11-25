from rest_framework import serializers
from .models import Scan


class ThreatScanAnalyzeSerializer(serializers.Serializer):
    scan_type = serializers.ChoiceField(choices=Scan.ScanType.values, default=Scan.ScanType.URL)
    input_value = serializers.CharField(max_length=10000, trim_whitespace=True)
    channel = serializers.CharField(max_length=50, required=False, allow_blank=True, default="")

class ThreatScanAdvisorRequestSerializer(serializers.Serializer):
    scan_id = serializers.UUIDField()

class ScanRecordSerializer(serializers.ModelSerializer):
    threat_dna = serializers.SerializerMethodField()
    impact_prediction = serializers.SerializerMethodField()
    attack_story = serializers.SerializerMethodField()
    ai_explanation = serializers.SerializerMethodField()
    confidence_score = serializers.SerializerMethodField()
    forensics_snapshot = serializers.SerializerMethodField()
    similar_threats = serializers.SerializerMethodField()
    community_reports = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = [
            "id",
            "user_id",
            "scan_type",
            "input_value",
            "risk_score",
            "verdict",
            "findings",
            "ai_summary",
            "created_at",
            "threat_dna",
            "impact_prediction",
            "attack_story",
            "ai_explanation",
            "confidence_score",
            "forensics_snapshot",
            "similar_threats",
            "community_reports",
        ]
        read_only_fields = fields

    def get_threat_dna(self, obj):
        return (obj.findings or {}).get("threat_dna", {})

    def get_impact_prediction(self, obj):
        return (obj.findings or {}).get("impact_prediction", {})

    def get_attack_story(self, obj):
        return (obj.findings or {}).get("attack_story", [])

    def get_ai_explanation(self, obj):
        return (obj.findings or {}).get("ai_explanation") or obj.ai_summary or ""

    def get_confidence_score(self, obj):
        return (obj.findings or {}).get("confidence_score", 0)

    def get_forensics_snapshot(self, obj):
        return (obj.findings or {}).get("forensics_snapshot", {})

    def get_similar_threats(self, obj):
        return ((obj.findings or {}).get("community_intelligence") or {}).get("similar_threats", 0)

    def get_community_reports(self, obj):
        return ((obj.findings or {}).get("community_intelligence") or {}).get("community_reports", 0)
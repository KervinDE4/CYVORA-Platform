from rest_framework import serializers
from .models import Scan


class ThreatScanAnalyzeSerializer(serializers.Serializer):
    scan_type = serializers.ChoiceField(choices=Scan.ScanType.values, default=Scan.ScanType.URL)
    input_value = serializers.CharField(max_length=10000, required=False, allow_blank=True, trim_whitespace=True)
    channel = serializers.CharField(max_length=30, required=False, allow_blank=True, default="")
    file = serializers.FileField(required=False, write_only=True)

    ALLOWED_CHANNELS = {"", "whatsapp", "sms", "email", "telegram", "social_dm", "voice_call"}

    def validate(self, attrs):
        uploaded_file = attrs.get("file")
        scan_type = attrs.get("scan_type", Scan.ScanType.URL)
        input_value = (attrs.get("input_value") or "").strip()
        channel = (attrs.get("channel") or "").strip().lower()

        if channel not in self.ALLOWED_CHANNELS:
            raise serializers.ValidationError({"channel": "Unsupported channel."})

        if uploaded_file is not None:
            if scan_type != Scan.ScanType.FILE:
                raise serializers.ValidationError({"file": "Select the File / PDF scan type before uploading a file."})
            if not uploaded_file.name.lower().endswith(".pdf"):
                raise serializers.ValidationError({"file": "Only PDF files are supported."})
            if uploaded_file.size > 5 * 1024 * 1024:
                raise serializers.ValidationError({"file": "PDF size must not exceed 5 MB."})
            if uploaded_file.content_type not in (None, "", "application/pdf", "application/octet-stream"):
                raise serializers.ValidationError({"file": "The uploaded file must be a PDF."})
            uploaded_file.seek(0)
            if uploaded_file.read(5) != b"%PDF-":
                raise serializers.ValidationError({"file": "The uploaded file does not have a valid PDF header."})
            uploaded_file.seek(0)
        elif scan_type == Scan.ScanType.FILE:
            raise serializers.ValidationError({"file": "Please attach a PDF file to run a file scan."})
        elif not input_value:
            raise serializers.ValidationError({"input_value": "Enter a URL, message, or payload to scan."})

        return attrs


class ThreatScanAdvisorRequestSerializer(serializers.Serializer):
    scan_id = serializers.UUIDField()


class ScanRecordSerializer(serializers.ModelSerializer):
    scan_type = serializers.SerializerMethodField()
    input_value = serializers.SerializerMethodField()
    findings = serializers.SerializerMethodField()
    ai_summary = serializers.SerializerMethodField()
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
            "id", "user_id", "scan_type", "input_value", "risk_score",
            "verdict", "findings", "ai_summary", "created_at", "threat_dna",
            "impact_prediction", "attack_story", "ai_explanation",
            "confidence_score", "forensics_snapshot", "similar_threats",
            "community_reports",
        ]
        read_only_fields = fields

    def get_scan_type(self, obj):
        return obj.scan_type

    def get_input_value(self, obj):
        return obj.input_value

    def get_findings(self, obj):
        return obj.findings

    def get_ai_summary(self, obj):
        return obj.ai_summary

    def _findings(self, obj):
        return obj.findings

    def get_threat_dna(self, obj):
        return self._findings(obj).get("threat_dna", {})

    def get_impact_prediction(self, obj):
        return self._findings(obj).get("impact_prediction", {})

    def get_attack_story(self, obj):
        value = self._findings(obj).get("attack_story", [])
        return value if isinstance(value, list) else []

    def get_ai_explanation(self, obj):
        return self._findings(obj).get("ai_explanation") or obj.ai_summary or ""

    def get_confidence_score(self, obj):
        return self._findings(obj).get("confidence_score", 0)

    def get_forensics_snapshot(self, obj):
        return self._findings(obj).get("forensics_snapshot", {})

    def get_similar_threats(self, obj):
        community = self._findings(obj).get("community_intelligence") or {}
        return community.get("similar_threats", 0) if isinstance(community, dict) else 0

    def get_community_reports(self, obj):
        community = self._findings(obj).get("community_intelligence") or {}
        return community.get("community_reports", 0) if isinstance(community, dict) else 0

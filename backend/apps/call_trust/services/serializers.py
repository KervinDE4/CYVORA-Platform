from rest_framework import serializers
from apps.call_trust.models import CallCheck


class CallTrustVerifySerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=50, trim_whitespace=True)
    call_script = serializers.CharField(
        max_length=5000,
        required=False,
        allow_blank=True,
        default="",
    )
    claimed_institution = serializers.CharField(max_length=160, required=False, allow_blank=True, default="")
    caller_demands = serializers.ListField(child=serializers.CharField(max_length=60), required=False, default=list)
    passport_token = serializers.CharField(max_length=16384, required=False, allow_blank=True, write_only=True)
    channel = serializers.CharField(
        max_length=40,
        required=False,
        allow_blank=True,
        default="voice_call",
    )


class CallCheckSerializer(serializers.ModelSerializer):
    class Meta:
        model = CallCheck
        fields = [
            "id",
            "user_id",
            "phone_number",
            "normalized_phone",
            "call_script",
            "risk_score",
            "verdict",
            "findings",
            "created_at",
        ]
        read_only_fields = fields


class CallTrustReportSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=50, trim_whitespace=True)
    reason = serializers.CharField(max_length=500, required=False, allow_blank=True, default="")
    scam_category = serializers.CharField(
        max_length=100,
        required=False,
        allow_blank=True,
        default="Suspicious Call / Impersonation",
    )
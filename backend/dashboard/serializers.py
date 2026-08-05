from rest_framework import serializers
from audits.models import Audit, Finding, AuditStatistic
from inventory.models import Device


class DashboardSummarySerializer(serializers.Serializer):
    total_audits = serializers.IntegerField()
    total_devices = serializers.IntegerField()
    online_devices = serializers.IntegerField()
    average_security_score = serializers.FloatField()
    latest_security_score = serializers.IntegerField(allow_null=True)
    vulnerability_summary = serializers.DictField()
    latest_audit = serializers.DictField(allow_null=True)
    recent_audits = serializers.ListField()

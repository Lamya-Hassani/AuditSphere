from rest_framework import serializers

from .models import (
    Audit,
    AuditStatistic,
    AuditDevice,
    Finding,
    Recommendation,
)


class RecommendationSerializer(serializers.ModelSerializer):

    class Meta:
        model = Recommendation
        fields = "__all__"


class FindingSerializer(serializers.ModelSerializer):

    class Meta:
        model = Finding
        fields = "__all__"


class AuditDeviceSerializer(serializers.ModelSerializer):

    device_ip = serializers.CharField(source="device.ip", read_only=True)
    device_hostname = serializers.CharField(source="device.hostname", read_only=True)
    findings = FindingSerializer(
        many=True,
        read_only=True
    )

    class Meta:
        model = AuditDevice
        fields = "__all__"


class AuditStatisticSerializer(serializers.ModelSerializer):

    class Meta:
        model = AuditStatistic
        fields = "__all__"


class AuditSerializer(serializers.ModelSerializer):

    devices = AuditDeviceSerializer(
        many=True,
        read_only=True
    )

    statistics = AuditStatisticSerializer(
        read_only=True
    )

    recommendations = RecommendationSerializer(
        many=True,
        read_only=True
    )

    executed_by_username = serializers.CharField(source="executed_by.username", read_only=True, default=None)

    class Meta:
        model = Audit
        fields = "__all__"
from rest_framework import serializers

from .models import (
    Audit,
    AuditStatistic,
    AuditDevice,
    Finding,
    Recommendation,
)
from inventory.models import Port


class RecommendationSerializer(serializers.ModelSerializer):

    class Meta:
        model = Recommendation
        fields = "__all__"


class FindingSerializer(serializers.ModelSerializer):

    class Meta:
        model = Finding
        fields = "__all__"


class AuditPortSerializer(serializers.ModelSerializer):
    """Inline port records attached to an AuditDevice."""

    class Meta:
        model = Port
        fields = ["number", "protocol", "state", "service", "product", "version"]


class AuditDeviceSerializer(serializers.ModelSerializer):

    device_ip       = serializers.CharField(source="device.ip",               read_only=True)
    device_hostname = serializers.CharField(source="device.hostname",          read_only=True)
    device_mac      = serializers.CharField(source="device.mac",               read_only=True)
    device_vendor   = serializers.CharField(source="device.vendor",            read_only=True)
    device_os       = serializers.CharField(source="device.operating_system",  read_only=True)

    # Open ports stored against the inventory Device
    ports = serializers.SerializerMethodField()

    findings = FindingSerializer(many=True, read_only=True)

    class Meta:
        model = AuditDevice
        fields = "__all__"

    def get_ports(self, obj):
        """Return all ports on the linked inventory device."""
        qs = obj.device.ports.all()
        return AuditPortSerializer(qs, many=True).data


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
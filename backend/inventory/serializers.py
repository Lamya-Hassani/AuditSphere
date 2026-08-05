from rest_framework import serializers
from .models import Device, Port
from audits.models import AuditDevice, Finding


class PortSerializer(serializers.ModelSerializer):

    class Meta:
        model = Port
        fields = "__all__"


class DeviceSerializer(serializers.ModelSerializer):
    ports = PortSerializer(many=True, read_only=True)
    open_ports_count = serializers.SerializerMethodField()
    latest_risk_level = serializers.SerializerMethodField()

    class Meta:
        model = Device
        fields = [
            "id",
            "ip",
            "hostname",
            "mac",
            "vendor",
            "operating_system",
            "status",
            "created_at",
            "updated_at",
            "ports",
            "open_ports_count",
            "latest_risk_level",
        ]

    def get_open_ports_count(self, obj):
        return obj.ports.filter(state="open").count()

    def get_latest_risk_level(self, obj):
        latest_audit_device = (
            AuditDevice.objects.filter(device=obj)
            .order_by("-audit__scan_date")
            .first()
        )
        return latest_audit_device.risk_level if latest_audit_device else "unknown"


class DeviceDetailSerializer(DeviceSerializer):
    recent_findings = serializers.SerializerMethodField()

    class Meta(DeviceSerializer.Meta):
        fields = DeviceSerializer.Meta.fields + ["recent_findings"]

    def get_recent_findings(self, obj):
        latest_audit_device = (
            AuditDevice.objects.filter(device=obj)
            .order_by("-audit__scan_date")
            .first()
        )
        if not latest_audit_device:
            return []
        findings = Finding.objects.filter(audit_device=latest_audit_device)
        return [
            {
                "id": f.id,
                "service": f.service,
                "port": f.port,
                "product": f.product,
                "version": f.version,
                "severity": f.severity,
                "description": f.description,
                "recommendation": f.recommendation,
                "points": f.points,
            }
            for f in findings
        ]

from datetime import datetime

from audits.models import (
    Audit,
    AuditStatistic,
    AuditDevice,
    Finding,
    Recommendation,
)

from inventory.models import (
    Device,
    Port,
)

from .api_client import run_scan


def execute_audit(target, user=None):
    """
    Executes a scan through the FastAPI service,
    saves the complete audit into MariaDB,
    then returns the created Audit object.
    """

    data = run_scan(target)

    # -----------------------------
    # Audit
    # -----------------------------

    audit = Audit.objects.create(
        target=data["target"],
        scan_date=datetime.fromisoformat(data["scan_date"]),
        engine_version=data["engine_version"],
        scanner_version=data["audit_metadata"]["scanner"],
        rules_version=data["audit_metadata"]["rules_version"],
        scan_type=data["audit_metadata"]["scan_type"],
        laboratory_security_score=data["laboratory_security_score"],
        executed_by=user,
        status="completed",
    )

    # -----------------------------
    # Statistics
    # -----------------------------

    AuditStatistic.objects.create(
        audit=audit,
        devices=data["statistics"]["devices"],
        critical=data["statistics"]["critical"],
        high=data["statistics"]["high"],
        medium=data["statistics"]["medium"],
        low=data["statistics"]["low"],
    )

    # -----------------------------
    # Global recommendations
    # -----------------------------

    for recommendation in data["recommendations"]:
        Recommendation.objects.create(
            audit=audit,
            text=recommendation,
        )

    # -----------------------------
    # Devices
    # -----------------------------

    for device_json in data["devices"]:

        device_info = device_json["device"]

        device, created = Device.objects.get_or_create(
            ip=device_info["ip"],
            defaults={
                "hostname": device_info["hostname"],
                "mac": device_info["mac"],
                "vendor": device_info["vendor"],
                "operating_system": device_info["os"],
                "status": device_info["status"],
            },
        )

        # Update inventory if the device already exists
        if not created:

            device.hostname = device_info["hostname"]
            device.mac = device_info["mac"]
            device.vendor = device_info["vendor"]
            device.operating_system = device_info["os"]
            device.status = device_info["status"]

            device.save()

        # -----------------------------
        # Ports
        # -----------------------------

        Port.objects.filter(device=device).delete()

        for port in device_info["ports"]:

            Port.objects.create(
                device=device,
                number=port["number"],
                protocol=port["protocol"],
                state=port["state"],
                service=port["service"],
                product=port["product"],
                version=port["version"],
            )

        # -----------------------------
        # AuditDevice
        # -----------------------------

        audit_device = AuditDevice.objects.create(
            audit=audit,
            device=device,
            risk_score=device_json["risk_score"],
            security_score=device_json["security_score"],
            risk_level=device_json["risk_level"],
            risk_categories=device_json["risk_categories"],
            score_breakdown=device_json["score_breakdown"],
        )

        # -----------------------------
        # Findings
        # -----------------------------

        for finding in device_json["findings"]:

            Finding.objects.create(
                audit_device=audit_device,
                service=finding["service"],
                port=finding["port"],
                product=finding["product"],
                version=finding["version"],
                severity=finding["severity"],
                description=finding["description"],
                recommendation=finding["recommendation"],
                points=finding["points"],
            )

    return audit
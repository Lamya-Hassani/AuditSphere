from datetime import datetime

from audits.models import (
    Audit,
    AuditStatistic,
    AuditDevice,
    Finding,
    Recommendation,
)
from inventory.models import Device, Port

from .api_client import run_scan


SCAN_TYPE_MAP = {
    "full": "Laboratory Network Audit",
    "discovery": "Host Discovery",
    "ports": "Port Sweep",
}


def _get_previous_report(target):
    """Get the latest completed full audit for comparison."""

    previous = (
        Audit.objects
        .filter(
            target=target,
            status="completed",
            scan_type="Laboratory Network Audit",
        )
        .prefetch_related(
            "devices__device__ports",
            "devices__findings",
            "statistics",
        )
        .order_by("-scan_date")
        .first()
    )

    if not previous:
        return None

    try:
        stats = previous.statistics
        statistics = {
            "devices": stats.devices,
            "critical": stats.critical,
            "high": stats.high,
            "medium": stats.medium,
            "low": stats.low,
        }
    except AuditStatistic.DoesNotExist:
        statistics = {}

    devices = []

    for audit_device in previous.devices.all():
        device = audit_device.device

        ports = [
            {
                "number": port.number,
                "protocol": port.protocol,
                "state": port.state,
                "service": port.service,
                "product": port.product,
                "version": port.version,
            }
            for port in device.ports.all()
        ]

        findings = [
            {
                "port": finding.port,
                "service": finding.service,
                "severity": finding.severity,
                "description": finding.description,
                "recommendation": finding.recommendation,
                "points": finding.points,
                "cve_id": finding.cve_id,
                "cvss": finding.cvss_score,
                "source": finding.source,
            }
            for finding in audit_device.findings.all()
        ]

        devices.append({
            "device": {
                "ip": device.ip,
                "hostname": device.hostname,
                "mac": device.mac,
                "vendor": device.vendor,
                "status": device.status,
                "os": device.operating_system,
                "ports": ports,
            },
            "risk_score": audit_device.risk_score,
            "security_score": audit_device.security_score,
            "risk_level": audit_device.risk_level,
            "risk_categories": audit_device.risk_categories,
            "score_breakdown": audit_device.score_breakdown,
            "findings": findings,
        })

    return {
        "target": previous.target,
        "laboratory_security_score": previous.laboratory_security_score,
        "statistics": statistics,
        "devices": devices,
    }


def _parse_scan_date(value):
    """Convert the engine date to a Python datetime."""

    if not value:
        return datetime.now()

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return datetime.now()


def _get_device_data(device_json, scan_mode):
    """Normalize device data returned by the scan engine."""

    device = (
        device_json.get("device", {})
        if scan_mode == "full"
        else device_json
    )

    sec_score = device_json.get("security_score", 100)
    risk_level = device_json.get("risk_level")
    if not risk_level or risk_level == "N/A":
        if sec_score == 100:
            risk_level = "Safe"
        elif sec_score >= 90:
            risk_level = "Low"
        elif sec_score >= 70:
            risk_level = "Medium"
        elif sec_score >= 50:
            risk_level = "High"
        else:
            risk_level = "Critical"

    return {
        "ip": device.get("ip"),
        "hostname": device.get("hostname"),
        "mac": device.get("mac"),
        "vendor": device.get("vendor"),
        "status": device.get("status", "up"),
        "os": device.get("os"),
        "ports": (
            device.get("ports", [])
            if scan_mode != "discovery"
            else []
        ),
        "risk_score": device_json.get("risk_score", 0),
        "security_score": sec_score,
        "risk_level": risk_level,
        "risk_categories": device_json.get("risk_categories", []),
        "score_breakdown": device_json.get("score_breakdown", {}),
        "findings": device_json.get("findings", []),
    }


def _update_device(device, data):
    """Update an existing inventory device."""

    device.hostname = data.get("hostname") or device.hostname
    device.mac = data.get("mac") or device.mac
    device.vendor = data.get("vendor") or device.vendor
    device.operating_system = (
        data.get("os") or device.operating_system
    )
    device.status = data.get("status", device.status)
    device.save()


def _save_ports(device, ports):
    """Replace the device ports with the latest scan result."""

    if not ports:
        return

    Port.objects.filter(device=device).delete()

    for port in ports:
        Port.objects.create(
            device=device,
            number=port.get("number", 0),
            protocol=port.get("protocol", "tcp"),
            state=port.get("state", "open"),
            service=port.get("service", "unknown"),
            product=port.get("product"),
            version=port.get("version"),
        )


def _save_findings(audit_device, findings):
    """Save findings generated by the audit engine."""

    for finding in findings:
        Finding.objects.create(
            audit_device=audit_device,
            service=finding.get("service", "unknown"),
            port=finding.get("port", 0),
            product=finding.get("product"),
            version=finding.get("version"),
            severity=finding.get("severity", "Low"),
            description=finding.get("description", ""),
            recommendation=finding.get("recommendation", ""),
            points=finding.get("points", 0),
            cve_id=finding.get("cve_id"),
            cvss_score=finding.get("cvss"),
            fixed_version=finding.get("fixed_version"),
            source=finding.get("source", "rule"),
        )


def execute_audit(target, mode="full", user=None):
    """Run a scan and store its result in the database."""

    if mode not in SCAN_TYPE_MAP:
        raise ValueError(f"Unsupported scan mode: {mode}")

    previous_report = (
        _get_previous_report(target)
        if mode == "full"
        else None
    )

    data = run_scan(
        target=target,
        mode=mode,
        previous_report=previous_report,
    )

    if not isinstance(data, dict):
        raise ValueError("Invalid response received from scan engine.")

    scan_mode = data.get("scan_mode", mode)
    metadata = data.get("audit_metadata") or data.get("metadata") or {}

    scan_type = metadata.get("scan_type") or SCAN_TYPE_MAP.get(
        scan_mode,
        "Network Scan",
    )

    audit = Audit.objects.create(
        target=data.get("target", target),
        scan_date=_parse_scan_date(data.get("scan_date")),
        engine_version=data.get("engine_version", "1.0.0"),
        scanner_version=metadata.get("scanner", "Nmap 7.99"),
        rules_version=metadata.get("rules_version", "2026.1"),
        scan_type=scan_type,
        laboratory_security_score=data.get(
            "laboratory_security_score",
            100,
        ),
        executed_by=user,
        status="completed",
    )

    statistics = data.get("statistics") or {}
    devices = data.get("devices", [])

    AuditStatistic.objects.create(
        audit=audit,
        devices=statistics.get("devices", len(devices)),
        critical=statistics.get("critical", 0),
        high=statistics.get("high", 0),
        medium=statistics.get("medium", 0),
        low=statistics.get("low", 0),
    )

    for recommendation in data.get("recommendations", []):
        if isinstance(recommendation, dict):
            text = recommendation.get("text", "")
        else:
            text = str(recommendation)

        if text:
            Recommendation.objects.create(
                audit=audit,
                text=text,
            )

    if data.get("comparison"):
        audit.comparison_data = data["comparison"]
        audit.save(update_fields=["comparison_data"])

    scanned_ips = set()

    for device_json in devices:
        device_data = _get_device_data(
            device_json,
            scan_mode,
        )

        ip = device_data.get("ip")

        if not ip:
            continue

        scanned_ips.add(ip)

        device, created = Device.objects.get_or_create(
            ip=ip,
            defaults={
                "hostname": device_data.get("hostname"),
                "mac": device_data.get("mac"),
                "vendor": device_data.get("vendor"),
                "operating_system": device_data.get("os"),
                "status": device_data.get("status", "up"),
            },
        )

        if not created:
            _update_device(device, device_data)

        _save_ports(
            device,
            device_data.get("ports", []),
        )

        audit_device = AuditDevice.objects.create(
            audit=audit,
            device=device,
            risk_score=device_data.get("risk_score", 0),
            security_score=device_data.get("security_score", 100),
            risk_level=device_data.get("risk_level", "N/A"),
            risk_categories=device_data.get("risk_categories", []),
            score_breakdown=device_data.get("score_breakdown", {}),
        )

        _save_findings(
            audit_device,
            device_data.get("findings", []),
        )

    # Mark inventory devices in the target scan scope as 'down' if not detected
    _update_unresponsive_devices(target, scanned_ips)

    return audit


def _update_unresponsive_devices(target, scanned_ips):
    """
    If a device in inventory belongs to the scanned target subnet or IP scope
    but was NOT detected active in the latest scan, update its status to 'down'.
    """
    import ipaddress
    try:
        target_net = ipaddress.ip_network(target, strict=False)
        for dev in Device.objects.all():
            try:
                dev_ip = ipaddress.ip_address(dev.ip)
                if dev_ip in target_net and dev.ip not in scanned_ips:
                    if dev.status != "down":
                        dev.status = "down"
                        dev.save(update_fields=["status"])
            except ValueError:
                continue
    except ValueError:
        # If target is a single host or string that isn't a subnet
        Device.objects.filter(ip=target).exclude(ip__in=scanned_ips).update(status="down")
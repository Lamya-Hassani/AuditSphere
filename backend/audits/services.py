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


def _get_previous_report(target, current_mode):
    """
    Fetch the most recent completed full-audit for this target from the DB
    and serialise it into a plain dict the engine can consume.
    Returns None if no previous audit exists.
    """
    previous = (
        Audit.objects
        .filter(target=target, status="completed", scan_type="Laboratory Network Audit")
        .prefetch_related("devices__device__ports", "devices__findings", "statistics")
        .order_by("-scan_date")
        .first()
    )
    if not previous:
        return None

    try:
        stats = previous.statistics
        stat_dict = {
            "devices":  stats.devices,
            "critical": stats.critical,
            "high":     stats.high,
            "medium":   stats.medium,
            "low":      stats.low,
        }
    except Exception:
        stat_dict = {}

    devices = []
    for ad in previous.devices.all():
        dev = ad.device
        ports = [
            {
                "number":   p.number,
                "protocol": p.protocol,
                "state":    p.state,
                "service":  p.service,
                "product":  p.product,
                "version":  p.version,
            }
            for p in dev.ports.all()
        ]
        findings = [
            {
                "port":        f.port,
                "service":     f.service,
                "severity":    f.severity,
                "description": f.description,
            }
            for f in ad.findings.all()
        ]
        devices.append({
            "device": {
                "ip":       dev.ip,
                "hostname": dev.hostname,
                "mac":      dev.mac,
                "vendor":   dev.vendor,
                "status":   dev.status,
                "os":       dev.operating_system,
                "ports":    ports,
            },
            "risk_score":      ad.risk_score,
            "security_score":  ad.security_score,
            "risk_level":      ad.risk_level,
            "risk_categories": ad.risk_categories,
            "score_breakdown": ad.score_breakdown,
            "findings":        findings,
        })

    return {
        "laboratory_security_score": previous.laboratory_security_score,
        "statistics": stat_dict,
        "devices": devices,
        "target": previous.target,
    }


def execute_audit(target, mode="full", user=None):
    """
    Executes a scan through the FastAPI service,
    saves the audit result into MariaDB for all three modes,
    then returns the created Audit object.
    """

    # Fetch previous full audit for comparison (full mode only)
    previous_report = None
    if mode == "full":
        previous_report = _get_previous_report(target, mode)

    data = run_scan(target, mode=mode, previous_report=previous_report)

    scan_mode = data.get("scan_mode", mode)
    meta = data.get("audit_metadata") or data.get("metadata") or {}

    scan_type_map = {
        "full":      "Laboratory Network Audit",
        "discovery": "Host Discovery",
        "ports":     "Port Sweep",
    }
    scan_type = meta.get("scan_type") or scan_type_map.get(scan_mode, "Network Scan")

    scan_date_str = data.get("scan_date")
    try:
        scan_date = datetime.fromisoformat(scan_date_str) if scan_date_str else datetime.now()
    except ValueError:
        scan_date = datetime.now()

    # -------------------------
    # Create Audit record
    # -------------------------
    audit = Audit.objects.create(
        target=data.get("target") or target,
        scan_date=scan_date,
        engine_version=data.get("engine_version", "1.0.0"),
        scanner_version=meta.get("scanner", "Nmap 7.99"),
        rules_version=meta.get("rules_version", "2026.1"),
        scan_type=scan_type,
        laboratory_security_score=data.get("laboratory_security_score", 100),
        executed_by=user,
        status="completed",
    )

    # -------------------------
    # Statistics
    # -------------------------
    raw_stats = data.get("statistics") or {}
    device_count = len(data.get("devices", []))

    AuditStatistic.objects.create(
        audit=audit,
        devices=raw_stats.get("devices", device_count),
        critical=raw_stats.get("critical", 0),
        high=raw_stats.get("high", 0),
        medium=raw_stats.get("medium", 0),
        low=raw_stats.get("low", 0),
    )

    # -------------------------
    # Global recommendations (full mode only)
    # -------------------------
    for rec_text in data.get("recommendations", []):
        Recommendation.objects.create(audit=audit, text=rec_text)

    # -------------------------
    # Comparison data (stored as a recommendation for display purposes)
    # -------------------------
    comparison = data.get("comparison")
    if comparison:
        audit.comparison = comparison  # Will be handled by the model/serializer

    # -------------------------
    # Devices
    # -------------------------
    for device_json in data.get("devices", []):

        if scan_mode == "discovery":
            ip          = device_json.get("ip")
            hostname    = device_json.get("hostname")
            mac         = device_json.get("mac")
            vendor      = device_json.get("vendor")
            status      = device_json.get("status", "up")
            os_name     = None
            ports_list  = []
            risk_score  = 0
            sec_score   = 100
            risk_level  = "N/A"
            risk_cats   = []
            score_bkdn  = {}
            findings_list = []

        elif scan_mode == "ports":
            ip          = device_json.get("ip")
            hostname    = device_json.get("hostname")
            mac         = device_json.get("mac")
            vendor      = device_json.get("vendor")
            status      = device_json.get("status", "up")
            os_name     = device_json.get("os")
            ports_list  = device_json.get("ports", [])
            risk_score  = 0
            sec_score   = 100
            risk_level  = "N/A"
            risk_cats   = []
            score_bkdn  = {}
            findings_list = []

        else:
            dev_info      = device_json.get("device", {})
            ip            = dev_info.get("ip")
            hostname      = dev_info.get("hostname")
            mac           = dev_info.get("mac")
            vendor        = dev_info.get("vendor")
            status        = dev_info.get("status", "up")
            os_name       = dev_info.get("os")
            ports_list    = dev_info.get("ports", [])
            risk_score    = device_json.get("risk_score", 0)
            sec_score     = device_json.get("security_score", 100)
            risk_level    = device_json.get("risk_level", "Safe")
            risk_cats     = device_json.get("risk_categories", [])
            score_bkdn    = device_json.get("score_breakdown", {})
            findings_list = device_json.get("findings", [])

        if not ip:
            continue

        device, created = Device.objects.get_or_create(
            ip=ip,
            defaults={
                "hostname":          hostname,
                "mac":               mac,
                "vendor":            vendor,
                "operating_system":  os_name,
                "status":            status,
            },
        )

        if not created:
            device.hostname          = hostname or device.hostname
            device.mac               = mac or device.mac
            device.vendor            = vendor or device.vendor
            device.operating_system  = os_name or device.operating_system
            device.status            = status
            device.save()

        if ports_list:
            Port.objects.filter(device=device).delete()
            for port in ports_list:
                Port.objects.create(
                    device=device,
                    number=port.get("number") or 0,
                    protocol=port.get("protocol") or "tcp",
                    state=port.get("state") or "open",
                    service=port.get("service") or "unknown",
                    product=port.get("product"),
                    version=port.get("version"),
                )

        audit_device = AuditDevice.objects.create(
            audit=audit,
            device=device,
            risk_score=risk_score,
            security_score=sec_score,
            risk_level=risk_level,
            risk_categories=risk_cats,
            score_breakdown=score_bkdn,
        )

        for finding in findings_list:
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
                source=finding.get("source", "rule"),
            )

    # Store comparison on the audit object if the model supports it
    if comparison and hasattr(audit, "comparison_data"):
        from django.db import connection
        try:
            audit.comparison_data = comparison
            audit.save(update_fields=["comparison_data"])
        except Exception:
            pass  # Field may not exist yet until migration runs

    return audit
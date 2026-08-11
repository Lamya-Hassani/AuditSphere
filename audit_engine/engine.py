from datetime import datetime
import platform
import socket
import shutil
from pathlib import Path

from scanner.discovery import discover_hosts, discover_hosts_detailed
from scanner.detailed_scan import run_detailed_scan
from scanner.port_sweep import run_port_sweep
from scanner.parser import parse_scan

from analyzer.analyzer import analyzer

from comparator.compare import compare_audits
from exporter.json_exporter import report_to_dict
from inventory.inventory_manager import update_inventory
from logger.logger import logger

from models.laboratory_report import LaboratoryReport
from models.scan_result import ScanResult

from config.config_loader import load_config


def cleanup():
    config = load_config()

    if config["engine"].get("keep_temp_files", True):
        return

    temp_folder = Path(
        config["engine"].get("scan_directory", "temp")
    )

    if temp_folder.exists():
        shutil.rmtree(temp_folder)

def run_discovery_audit(target, start_time):

    logger.info("Mode: Host Discovery (nmap -sn)")

    hosts = discover_hosts_detailed(target)

    logger.info(f"{len(hosts)} active hosts discovered")

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    metadata = {
        "engine": "Cybersecurity Audit Engine",
        "engine_version": "1.0.0",
        "rules_version": "2026.1",
        "scan_type": "Host Discovery",
        "nmap_command": "nmap -sn <target>",
        "generated_at": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_duration": f"{duration:.2f} seconds",
        "scanner": "Nmap 7.99",
        "parser": "Internal XML Parser",
        "target": target,
        "status": "Completed",
        "total_devices": len(hosts)
    }

    cleanup()

    return {
        "scan_mode": "discovery",
        "devices": hosts,
        "metadata": metadata,
        "scan_date": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "engine_version": "1.0.0"
    }

def run_port_sweep_audit(target, start_time):

    logger.info("Mode: Port Sweep (nmap -sV --open -T4)")

    active_hosts = discover_hosts(target)

    logger.info(f"{len(active_hosts)} active hosts discovered")

    devices_dict = []

    for host in active_hosts:

        logger.info(f"Port sweeping {host}")

        xml_file = run_port_sweep(host)
        devices = parse_scan(xml_file)

        if not devices:
            continue

        device = devices[0]

        ports_data = [
            {
                "number": p.number,
                "protocol": p.protocol,
                "state": p.state,
                "service": p.service,
                "product": p.product,
                "version": p.version
            }
            for p in device.ports
        ]

        devices_dict.append({
            "ip": device.ip,
            "hostname": device.hostname,
            "mac": device.mac,
            "vendor": device.vendor,
            "status": device.status,
            "os": device.os,
            "ports": ports_data
        })

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    total_open_ports = sum(
        len(device["ports"])
        for device in devices_dict
    )

    metadata = {
        "engine": "Cybersecurity Audit Engine",
        "engine_version": "1.0.0",
        "rules_version": "2026.1",
        "scan_type": "Port Sweep",
        "nmap_command": "nmap -sV --open -T4 <host>",
        "generated_at": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_duration": f"{duration:.2f} seconds",
        "scanner": "Nmap 7.99",
        "parser": "Internal XML Parser",
        "target": target,
        "status": "Completed",
        "total_devices": len(devices_dict),
        "open_ports": total_open_ports
    }

    cleanup()

    return {
        "scan_mode": "ports",
        "devices": devices_dict,
        "metadata": metadata,
        "scan_date": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "engine_version": "1.0.0"
    }

def run_full_audit(target, start_time):

    logger.info("Mode: Full Audit (nmap -A)")

    hosts = discover_hosts(target)

    logger.info(f"{len(hosts)} active hosts discovered")

    lab_report = LaboratoryReport(
        target=target,
        scan_date=datetime.now()
    )

    for host in hosts:

        logger.info(f"Full scan on {host}")

        xml_file = run_detailed_scan(host)
        devices = parse_scan(xml_file)

        if not devices:
            continue

        device = devices[0]

        # Analyze the device
        analysis = analyzer(device)

        # Convert analyzer result into ScanResult
        result = ScanResult(
            device=device,
            scan_date=datetime.now(),
            findings=analysis["findings"],
            security_score=analysis["security_score"],
            risk_score=analysis["risk_score"],
            risk_level=analysis["risk_level"],
            risk_categories=analysis["risk_categories"],
            score_breakdown=analysis["score_breakdown"]
        )

        logger.info(
            f"{device.ip} -> "
            f"Risk={result.risk_level} "
            f"Score={result.security_score}"
        )

        lab_report.results.append(result)

    stats = {
        "devices": len(lab_report.results),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    recommendations = set()

    security_total = 0
    total_open_ports = 0
    total_findings = 0
    highest_risk_host = None

    for result in lab_report.results:

        security_total += result.security_score

        total_open_ports += len(
            result.device.ports
        )

        total_findings += len(
            result.findings
        )

        if (
            highest_risk_host is None
            or result.risk_score > highest_risk_host.risk_score
        ):
            highest_risk_host = result

        for finding in result.findings:

            if finding.recommendation:
                recommendations.add(
                    finding.recommendation
                )

            severity = finding.severity.lower()

            if severity in stats:
                stats[severity] += 1

    lab_report.statistics = stats
    lab_report.recommendations = sorted(list(recommendations))

    # ========================================================
    # Laboratory security score & risk level
    # ========================================================

    if lab_report.results:
        lab_report.laboratory_security_score = int(
            security_total / len(lab_report.results)
        )
    else:
        lab_report.laboratory_security_score = 100

    score = lab_report.laboratory_security_score
    if score >= 90:
        lab_report.laboratory_risk_level = "Low"
    elif score >= 70:
        lab_report.laboratory_risk_level = "Medium"
    elif score >= 50:
        lab_report.laboratory_risk_level = "High"
    else:
        lab_report.laboratory_risk_level = "Critical"

    # ========================================================
    # Metadata
    # ========================================================

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    lab_report.metadata = {
        "engine": "Cybersecurity Audit Engine",
        "engine_version": "1.0.0",
        "rules_version": "2026.1",
        "scan_type": "Laboratory Network Audit",
        "nmap_command": "nmap -A <host>",
        "generated_at": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_duration": f"{duration:.2f} seconds",
        "scanner": "Nmap 7.99",
        "parser": "Internal XML Parser",
        "python_version": platform.python_version(),
        "platform": platform.system(),
        "hostname": socket.gethostname(),
        "target": target,
        "status": "Completed",
        "total_devices": len(lab_report.results),
        "open_ports": total_open_ports,
        "total_findings": total_findings,
        "highest_risk_host": (
            highest_risk_host.device.ip
            if highest_risk_host
            else None
        ),
        "risk_distribution": {
            "Critical": stats["critical"],
            "High": stats["high"],
            "Medium": stats["medium"],
            "Low": stats["low"]
        }
    }

    # ========================================================
    # Export and inventory
    # ========================================================

    report = report_to_dict(lab_report)

    update_inventory(lab_report)

    logger.info("Inventory updated")

    cleanup()

    report["scan_mode"] = "full"

    return report


# ============================================================
# Main dispatcher
# ============================================================

def run_audit(
    target,
    mode="full",
    previous_report=None
):

    start_time = datetime.now()

    logger.info(
        f"Audit Engine Started - Mode: {mode}"
    )

    logger.info(
        f"Target: {target}"
    )

    if mode == "discovery":

        return run_discovery_audit(
            target,
            start_time
        )

    elif mode == "ports":

        return run_port_sweep_audit(
            target,
            start_time
        )

    else:

        report = run_full_audit(
            target,
            start_time
        )

        # Historical comparison
        if previous_report:

            try:

                report["comparison"] = compare_audits(
                    report,
                    previous_report
                )

                logger.info(
                    "Historical comparison generated"
                )

            except Exception as e:

                logger.warning(
                    f"Comparison failed: {e}"
                )

                report["comparison"] = None

        else:

            report["comparison"] = None

        return report
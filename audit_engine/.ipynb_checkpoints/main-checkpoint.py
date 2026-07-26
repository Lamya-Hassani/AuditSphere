import argparse
import platform
import shutil
import socket

from datetime import datetime
from pathlib import Path

from scanner.discovery import discover_hosts
from scanner.detailed_scan import run_detailed_scan
from scanner.parser import parse_scan

from analyzer.analyzer import analyze

from exporter.json_exporter import export_json

from inventory.inventory_manager import update_inventory

from logger.logger import logger

from models.laboratory_report import LaboratoryReport

from config.config_loader import load_config


# --------------------------------------------------
# Cleanup temporary files
# --------------------------------------------------

def cleanup():

    config = load_config()

    if config["engine"]["keep_scan_files"]:
        return

    temp_folder = Path(
        config["engine"]["scan_directory"]
    )

    if temp_folder.exists():
        shutil.rmtree(temp_folder)


# --------------------------------------------------
# Arguments
# --------------------------------------------------

def get_arguments():

    parser = argparse.ArgumentParser(
        description="Cybersecurity Audit Engine"
    )

    parser.add_argument(
        "target",
        help="Target IP or Network"
    )

    return parser.parse_args()


# --------------------------------------------------
# Main
# --------------------------------------------------

start_time = datetime.now()

args = get_arguments()

target = args.target

logger.info("Audit Engine Started")
logger.info(f"Target: {target}")

print("\n==========================================")
print("      CYBERSECURITY AUDIT ENGINE")
print("==========================================")


# --------------------------------------------------
# Discover hosts
# --------------------------------------------------

hosts = discover_hosts(target)

logger.info(f"{len(hosts)} active hosts discovered")

print(f"\nDiscovered {len(hosts)} active host(s).\n")


# --------------------------------------------------
# Laboratory report
# --------------------------------------------------

lab_report = LaboratoryReport(

    target=target,

    scan_date=datetime.now()

)


# --------------------------------------------------
# Scan every host
# --------------------------------------------------

for host in hosts:

    print("=" * 60)
    print(f"Scanning {host}")
    print("=" * 60)

    logger.info(f"Scanning {host}")

    xml_file = run_detailed_scan(host)

    devices = parse_scan(xml_file)

    if not devices:
        continue

    device = devices[0]

    result = analyze(device)

    logger.info(

        f"{device.ip} -> Risk={result.risk_level} "

        f"Score={result.security_score}"

    )

    lab_report.results.append(result)

    print()
    print(f"Target      : {device.ip}")

    if device.hostname:
        print(f"Hostname    : {device.hostname}")

    print(f"OS          : {device.os}")
    print(f"Risk Score  : {result.risk_score}")
    print(f"Risk Level  : {result.risk_level}")

    print("\nRisk Categories")

    for category in result.risk_categories:
        print(f"• {category}")

    print("\nRisk Score Breakdown")

    for category, points in result.score_breakdown.items():
        print(f"{category:<20} {points} points")

    print("\nDetected Vulnerabilities")

    if not result.findings:

        print("No vulnerabilities detected.")

    else:

        for finding in result.findings:

            print("-" * 50)
            print(f"Service        : {finding.service}")
            print(f"Port           : {finding.port}")
            print(f"Severity       : {finding.severity}")
            print(f"Issue          : {finding.description}")
            print(f"Recommendation : {finding.recommendation}")

    print("-" * 50)


# --------------------------------------------------
# Statistics
# --------------------------------------------------

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

    total_open_ports += len(result.device.ports)

    total_findings += len(result.findings)

    if highest_risk_host is None:

        highest_risk_host = result

    elif result.risk_score > highest_risk_host.risk_score:

        highest_risk_host = result

    for finding in result.findings:

        recommendations.add(finding.recommendation)

        severity = finding.severity.lower()

        if severity in stats:

            stats[severity] += 1


lab_report.statistics = stats

lab_report.recommendations = sorted(recommendations)


if lab_report.results:

    lab_report.laboratory_security_score = int(

        security_total / len(lab_report.results)

    )

else:

    lab_report.laboratory_security_score = 100


# --------------------------------------------------
# Audit Metadata
# --------------------------------------------------

end_time = datetime.now()

duration = (end_time - start_time).total_seconds()

lab_report.metadata = {

    "engine": "Cybersecurity Audit Engine",

    "engine_version": "1.0.0",

    "rules_version": "2026.1",

    "scan_type": "Laboratory Network Audit",

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


# --------------------------------------------------
# Export
# --------------------------------------------------

report_path = export_json(lab_report)

logger.info(f"Report exported to {report_path}")


# --------------------------------------------------
# Inventory
# --------------------------------------------------

update_inventory(lab_report)

logger.info("Inventory updated")


# --------------------------------------------------
# Cleanup
# --------------------------------------------------

#cleanup()


# --------------------------------------------------
# Summary
# --------------------------------------------------

print("\n==========================================")
print("LABORATORY SUMMARY")
print("==========================================")

print(f"Devices Scanned           : {stats['devices']}")
print(f"Critical Findings         : {stats['critical']}")
print(f"High Findings             : {stats['high']}")
print(f"Medium Findings           : {stats['medium']}")
print(f"Low Findings              : {stats['low']}")

print(f"\nLaboratory Security Score : {lab_report.laboratory_security_score}/100")

print("\nGlobal Recommendations")

for recommendation in lab_report.recommendations:

    print(f"• {recommendation}")

print("\nJSON Report Saved To:")

print(report_path)

logger.info("Audit completed")
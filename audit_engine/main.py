import argparse
from datetime import datetime

from scanner.scanner import run_scan
from scanner.parser import parse_scan
from analyzer.analyzer import analyze
from exporter.json_exporter import export_json
from models.laboratory_report import LaboratoryReport


# ---------------------------------
# Command-line arguments
# ---------------------------------

def get_arguments():

    parser = argparse.ArgumentParser(
        description="Cybersecurity Audit Engine"
    )

    parser.add_argument(
        "target",
        help="Target IP or Network (Example: 192.168.56.20 or 192.168.56.0/24)"
    )

    return parser.parse_args()


# ---------------------------------
# Main
# ---------------------------------

args = get_arguments()
target = args.target

# Run Nmap scan
xml_file = run_scan(target)

# Parse XML into Device objects
devices = parse_scan(xml_file)

# Create Laboratory Report
lab_report = LaboratoryReport(
    target=target,
    scan_date=datetime.now()
)

print("\n==========================================")
print("      CYBERSECURITY AUDIT ENGINE")
print("==========================================")

# ---------------------------------
# Analyze every discovered device
# ---------------------------------

for device in devices:

    result = analyze(device)

    lab_report.results.append(result)

    print(f"\nTarget : {device.ip}")

    if device.hostname:
        print(f"Hostname : {device.hostname}")

    print(f"OS : {device.os}")

    print(f"Risk Score : {result.risk_score}")
    print(f"Risk Level : {result.risk_level}")

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

# ---------------------------------
# Laboratory Statistics
# ---------------------------------

stats = {
    "devices": len(lab_report.results),
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
}

recommendations = set()

security_total = 0

for result in lab_report.results:

    security_total += result.security_score

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

# ---------------------------------
# Export JSON
# ---------------------------------

report_path = export_json(lab_report)

# ---------------------------------
# Final Summary
# ---------------------------------

print("\n==========================================")
print("LABORATORY SUMMARY")
print("==========================================")

print(f"Devices Scanned     : {stats['devices']}")
print(f"Critical Findings   : {stats['critical']}")
print(f"High Findings       : {stats['high']}")
print(f"Medium Findings     : {stats['medium']}")
print(f"Low Findings        : {stats['low']}")

print(f"\nLaboratory Security Score : {lab_report.laboratory_security_score}/100")

print(f"\nJSON Report Saved To:")
print(report_path)

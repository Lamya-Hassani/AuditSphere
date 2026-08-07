from datetime import datetime

from analyzer.rules_loader import load_rules
from analyzer.risk import calculate_risk_level, calculate_security_score
from analyzer.version_checker import check_versions
from analyzer.port_checker import check_ports
from analyzer.cve_checker import check_cves
from analyzer.nse_analyzer import analyze_nse
from models.finding import Finding
from models.scan_result import ScanResult
from analyzer.risk_categories import calculate_categories


def analyze(device):
    rules = load_rules()
    result = ScanResult(
        device=device,
        scan_date=datetime.now()
    )
    findings = []

    # -----------------------------------
    # 1. Service-based rule checks
    # -----------------------------------
    for port in device.ports:
        service = port.service.lower()
        if service not in rules:
            continue
        rule = rules[service]
        findings.append(
            Finding(
                service=service,
                port=port.number,
                product=port.product,
                version=port.version,
                severity=rule["severity"],
                description=rule["description"],
                recommendation=rule["recommendation"],
                points=rule["points"],
                source="rule",
            )
        )

    # -----------------------------------
    # 2. Port-based checks
    # -----------------------------------
    findings.extend(check_ports(device))

    # -----------------------------------
    # 3. Version-based checks
    # -----------------------------------
    findings.extend(check_versions(device))

    # -----------------------------------
    # 4. CVE detection (local database)
    # -----------------------------------
    findings.extend(check_cves(device))

    # -----------------------------------
    # 5. NSE script analysis
    # -----------------------------------
    findings.extend(analyze_nse(device))

    # -----------------------------------
    # Deduplicate: same port + description = same finding
    # CVE findings are deduplicated by cve_id instead
    # -----------------------------------
    unique = {}
    for finding in findings:
        if finding.cve_id:
            key = finding.cve_id
        else:
            key = (finding.port, finding.description)
        unique[key] = finding

    result.findings = list(unique.values())

    # -----------------------------------
    # Risk scoring
    # -----------------------------------
    categories, breakdown = calculate_categories(result.findings)
    result.risk_categories = categories
    result.score_breakdown = breakdown

    result.risk_score = calculate_security_score(result.findings, mode="risk")
    result.security_score = calculate_security_score(result.findings, mode="security")
    result.risk_level = calculate_risk_level(result.risk_score)

    return result
from datetime import datetime

from analyzer.rules_loader import load_rules
from analyzer.risk import (
    calculate_risk_level,
    calculate_security_score
)
from analyzer.version_checker import check_versions
from analyzer.port_checker import check_ports
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
    # Service-based checks
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
                points=rule["points"]
            )
        )

    # -----------------------------------
    # Port-based checks
    # -----------------------------------

    findings.extend(check_ports(device))

    # -----------------------------------
    # Version checks
    # -----------------------------------

    findings.extend(check_versions(device))

    # -----------------------------------
    # Remove duplicates
    # -----------------------------------

    unique = {}

    for finding in findings:
        key = (
            finding.port,
            finding.description
        )
        unique[key] = finding

    result.findings = list(unique.values())
    
    # -----------------------------------
    # Calculate score
    # -----------------------------------

    categories, breakdown = calculate_categories(
        result.findings
    )
    
    result.risk_categories = categories
    
    result.score_breakdown = breakdown
    
    total_score = sum(
        finding.points
        for finding in result.findings
    )

    result.risk_score = total_score

    result.security_score = calculate_security_score(
        total_score
    )

    result.risk_level = calculate_risk_level(
        total_score
    )

    return result
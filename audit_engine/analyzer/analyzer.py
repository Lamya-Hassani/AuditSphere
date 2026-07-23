from datetime import datetime

from analyzer.rules_loader import load_rules
from analyzer.risk import calculate_risk_level, calculate_security_score
from models.finding import Finding
from models.scan_result import ScanResult


def analyze(device):

    rules = load_rules()
    result = ScanResult(
        device=device,
        scan_date=datetime.now()
    )

    total_score = 0

    for port in device.ports:

        service = port.service.lower()

        if service not in rules:
            continue

        rule = rules[service]

        finding = Finding(
            service=service,
            port=port.number,
            severity=rule["severity"],
            description=rule["description"],
            recommendation=rule["recommendation"],
            points=rule["points"]
        )

        result.findings.append(finding)

        total_score += rule["points"]

    result.risk_score = total_score
    result.security_score = calculate_security_score(total_score)
    result.risk_level = calculate_risk_level(total_score)

    return result

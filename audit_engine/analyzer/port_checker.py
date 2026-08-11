from analyzer.rules_loader import load_port_rules
from models.finding import Finding


def check_ports(device):
    rules = load_port_rules()
    findings = []

    for port in device.ports:

        rule = rules.get(str(port.number))

        if not rule:
            continue

        findings.append(
            Finding(
                service=port.service,
                port=port.number,
                product=port.product,
                version=port.version,
                severity=rule["severity"],
                description=rule["description"],
                recommendation=rule["recommendation"],
                points=rule["points"],
                source="port",
            )
        )

    return findings
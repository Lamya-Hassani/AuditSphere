from analyzer.rules_loader import load_port_rules
from models.finding import Finding

def check_ports(device):
    rules =  load_port_rules()
    findings = []
    for port in device.ports:
        for service_name, rule in rules.items():
            if port.number not in rule.get("ports", []):
                continue
            finding = Finding(
                service=service_name,
                port=port.number,
                product=port.product,
                version=port.version,
                severity=rule["severity"],
                description=rule["description"],
                recommendation=rule["recommendation"],
                points=rule["points"]
            )
            findings.append(finding)

    return findings
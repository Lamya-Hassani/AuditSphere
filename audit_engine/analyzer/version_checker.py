import re

from analyzer.rules_loader import load_version_rules
from models.finding import Finding


def extract_version(version_string):

    if version_string is None:
        return None

    match = re.search(r"\d+(\.\d+)+", version_string)

    if match:
        return match.group()

    return None


def compare_versions(installed, minimum):

    installed = extract_version(installed)

    if installed is None:
        return False

    installed_parts = [int(x) for x in installed.split(".")]
    minimum_parts = [int(x) for x in minimum.split(".")]

    length = max(len(installed_parts), len(minimum_parts))

    installed_parts += [0] * (length - len(installed_parts))
    minimum_parts += [0] * (length - len(minimum_parts))

    return installed_parts < minimum_parts


def check_versions(device):
    findings = []
    rules = load_version_rules()
    
    for port in device.ports:
        
        if port.product is None:
            continue
            
        product = port.product.lower()
        
        if product not in rules:
            continue

        rule = rules[product]
        
        if compare_versions(
            port.version,
            rule["minimum_version"]
        ):
            findings.append(
                Finding(
                    service=port.service,
                    port=port.number,
                    product=port.product,
                    version=port.version,
                    severity=rule["severity"],
                    description=rule["description"],
                    recommendation=rule["recommendation"],
                    points=rule["points"]
                )
            )

    return findings
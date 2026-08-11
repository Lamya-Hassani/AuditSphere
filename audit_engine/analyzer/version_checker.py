import re

from analyzer.rules_loader import load_version_rules
from models.finding import Finding


def parse_version_parts(version):
    if not version:
        return []

    numbers = re.findall(r"\d+", str(version))

    return [int(number) for number in numbers]


def compare_versions(installed, minimum):
    """
    Returns True when installed version is lower
    than the required minimum version.
    """

    installed_parts = parse_version_parts(installed)
    minimum_parts = parse_version_parts(minimum)

    if not installed_parts or not minimum_parts:
        return False

    length = max(
        len(installed_parts),
        len(minimum_parts)
    )

    installed_parts += [0] * (
        length - len(installed_parts)
    )

    minimum_parts += [0] * (
        length - len(minimum_parts)
    )

    return installed_parts < minimum_parts


def check_versions(device):
    rules = load_version_rules()
    findings = []

    for port in device.ports:

        if not port.product or not port.version:
            continue

        product = port.product.lower().strip()

        rule = rules.get(product)

        if not rule:
            continue

        if not compare_versions(
            port.version,
            rule["minimum_version"]
        ):
            continue

        findings.append(
            Finding(
                service=port.service,
                port=port.number,
                product=port.product,
                version=port.version,
                fixed_version=rule["minimum_version"],
                severity=rule["severity"],
                description=rule["description"],
                recommendation=rule["recommendation"],
                points=rule["points"],
                source="version",
            )
        )

    return findings
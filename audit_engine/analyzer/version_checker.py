import re

from analyzer.rules_loader import load_version_rules
from models.finding import Finding


def extract_version(version_string):
    """
    Extract clean numeric dot-separated version string.
    e.g. 'OpenSSH 9.3p2 Ubuntu' -> '9.3.2'
    """
    if not version_string:
        return None

    # Find the main numbers and dots
    match = re.search(r"\d+(\.\d+)*", str(version_string))
    if match:
        return match.group()

    return None


def parse_version_parts(v_str):
    """
    Convert a version string into a tuple of integers.
    e.g. '9.3p2' -> [9, 3, 2]
    """
    if not v_str:
        return []

    # Extract all digit sequences from the string
    numbers = re.findall(r"\d+", str(v_str))
    return [int(n) for n in numbers]


def compare_versions(installed, minimum):
    """
    Returns True if installed version is strictly LESS than minimum version.
    """
    installed_parts = parse_version_parts(installed)
    minimum_parts = parse_version_parts(minimum)

    if not installed_parts or not minimum_parts:
        return False

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
                    points=rule["points"],
                    source="version",
                )
            )

    return findings
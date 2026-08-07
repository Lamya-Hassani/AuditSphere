"""
cve_checker.py
--------------
Matches detected product+version against the local CVE database.
Returns one Finding per matched CVE entry.

The database key is the lowercase product name (e.g. "apache httpd").
Each entry is a list of CVE objects with:
  id, severity, cvss, affected_below, fixed_version, description, recommendation
"""

from analyzer.rules_loader import load_cve_database
from analyzer.version_checker import compare_versions
from models.finding import Finding

# CVSS score → risk points mapping (added on top of base service points)
CVSS_TO_POINTS = {
    range(0, 4):   1,   # Low
    range(4, 7):   3,   # Medium
    range(7, 9):   5,   # High
    range(9, 11):  8,   # Critical
}


def _cvss_points(cvss: float) -> int:
    for r, pts in CVSS_TO_POINTS.items():
        if int(cvss) in r:
            return pts
    return 3


def check_cves(device) -> list:
    """
    Iterate over device ports and match product+version against the local CVE DB.
    Returns a list of Finding objects, one per matched CVE.
    """
    findings = []
    db = load_cve_database()

    for port in device.ports:
        if not port.product:
            continue

        product_key = port.product.lower().strip()

        if product_key not in db:
            continue

        for cve in db[product_key]:
            affected_below = cve.get("affected_below")

            # If version info is missing, still report the CVE as informational
            if port.version and affected_below:
                if not compare_versions(port.version, affected_below):
                    continue   # installed version is >= fixed → not affected

            findings.append(
                Finding(
                    service=port.service,
                    port=port.number,
                    product=port.product,
                    version=port.version,
                    severity=cve["severity"],
                    description=cve["description"],
                    recommendation=cve["recommendation"],
                    points=_cvss_points(cve["cvss"]),
                    cve_id=cve["id"],
                    cvss=cve["cvss"],
                    cve_data=[cve],
                    source="cve",
                )
            )

    return findings

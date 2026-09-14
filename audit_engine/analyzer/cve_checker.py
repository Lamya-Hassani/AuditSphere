from analyzer.rules_loader import load_cve_database
from analyzer.version_checker import compare_versions
from models.finding import Finding


CVSS_POINTS = {
    "Low": 3,
    "Medium": 7,
    "High": 15,
    "Critical": 25,
}


def cvss_to_points(cvss):
    if cvss < 4:
        return 3

    if cvss < 7:
        return 7

    if cvss < 9:
        return 15

    return 25


def check_cves(device):
    database = load_cve_database()
    findings = []

    for port in device.ports:

        if not port.product and not port.service:
            continue

        prod = (port.product or "").lower().strip()
        serv = (port.service or "").lower().strip()

        cves = database.get(prod) or database.get(serv)
        if not cves:
            for key, cve_list in database.items():
                if (key in prod and prod) or (key in serv and serv):
                    cves = cve_list
                    break

        if not cves:
            continue

        for cve in cves:

            affected_below = cve.get("affected_below")

            if affected_below:

                if not compare_versions(
                    port.version,
                    affected_below
                ):
                    continue

            findings.append(
                Finding(
                    service=port.service,
                    port=port.number,
                    product=port.product,
                    version=port.version,
                    fixed_version=cve.get("fixed_version"),
                    severity=cve["severity"],
                    description=cve["description"],
                    recommendation=cve["recommendation"],
                    points=cvss_to_points(cve["cvss"]),
                    cve_id=cve["id"],
                    cvss=cve["cvss"],
                    cve_data=[cve],
                    source="cve",
                )
            )

    return findings
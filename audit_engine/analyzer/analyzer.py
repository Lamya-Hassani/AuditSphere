from analyzer.port_checker import check_ports
from analyzer.version_checker import check_versions
from analyzer.cve_checker import check_cves
from analyzer.nse_analyzer import analyze_nse

from analyzer.risk import (
    calculate_risk_score,
    calculate_risk_level,
    calculate_security_score,
)

from analyzer.risk_categories import calculate_categories


def analyzer(device):

    # Basic service / port analysis
    port_findings = check_ports(device)

    # Software version analysis
    version_findings = check_versions(device)

    # CVE analysis
    cve_findings = check_cves(device)

    # NSE analysis
    nse_findings = analyze_nse(device)

    # Identify ports with specific CVE findings
    ports_with_cves = {
        getattr(f, 'port', None) for f in cve_findings
        if getattr(f, 'port', None)
    }

    # Filter out generic version findings if specific CVE findings exist for that port
    filtered_version_findings = [
        f for f in version_findings
        if getattr(f, 'port', None) not in ports_with_cves
    ]

    # Identify ports with specific version, CVE, or NSE findings
    ports_with_specific_findings = {
        getattr(f, 'port', None) for f in (filtered_version_findings + cve_findings + nse_findings)
        if getattr(f, 'port', None)
    }

    # Filter generic port exposure findings if specific version/CVE/NSE findings exist for that port
    filtered_port_findings = [
        f for f in port_findings
        if getattr(f, 'port', None) not in ports_with_specific_findings
    ]

    all_findings = filtered_port_findings + filtered_version_findings + cve_findings + nse_findings

    # Sort findings by port number and severity (Critical -> High -> Medium -> Low)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(
        key=lambda f: (
            getattr(f, 'port', 99999) or 99999,
            severity_order.get(str(getattr(f, 'severity', '')).lower(), 5)
        )
    )

    findings = all_findings

    # Risk calculation
    risk_score = calculate_risk_score(
        findings
    )

    security_score = calculate_security_score(
        findings
    )

    risk_level = calculate_risk_level(
        security_score
    )

    categories, breakdown = calculate_categories(
        findings
    )

    return {
        "findings": findings,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "security_score": security_score,
        "risk_categories": categories,
        "score_breakdown": breakdown,
    }
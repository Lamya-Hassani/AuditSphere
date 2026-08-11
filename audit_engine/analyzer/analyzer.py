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

    findings = []

    # Basic service / port analysis
    findings.extend(
        check_ports(device)
    )

    # Software version analysis
    findings.extend(
        check_versions(device)
    )

    # CVE analysis
    findings.extend(
        check_cves(device)
    )

    # NSE analysis
    findings.extend(
        analyze_nse(device)
    )

    # Risk calculation
    risk_score = calculate_risk_score(
        findings
    )

    risk_level = calculate_risk_level(
        risk_score
    )

    security_score = calculate_security_score(
        findings
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
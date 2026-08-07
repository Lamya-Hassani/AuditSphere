"""
risk.py
-------
Calculates risk score and security score from a list of findings.

The risk score combines:
  - Base points from rule/version/NSE findings
  - CVSS-weighted bonus for CVE findings
"""

SEVERITY_POINTS = {
    "Low": 1,
    "Medium": 3,
    "High": 5,
    "Critical": 8
}


def calculate_risk_level(score: int) -> str:
    if score <= 3:
        return "Low"
    elif score <= 8:
        return "Medium"
    elif score <= 15:
        return "High"
    else:
        return "Critical"


def calculate_security_score(findings, mode: str = "security") -> int:
    """
    mode="risk"     → returns raw risk score (sum of points)
    mode="security" → returns security score (100 - risk_score*5, min 0)

    CVE findings contribute their CVSS-derived points directly.
    """
    total = 0
    for finding in findings:
        if finding.source == "cve" and finding.cvss is not None:
            # Use CVSS-derived points (already set in cve_checker)
            total += finding.points
        else:
            total += finding.points

    if mode == "risk":
        return total

    # Security score: penalise harder for higher risk totals
    score = 100 - (total * 4)
    return max(score, 0)

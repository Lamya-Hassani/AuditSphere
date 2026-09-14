def calculate_risk_score(findings):
    return sum(
        finding.points
        for finding in findings
    )


def calculate_risk_level(security_score):

    if security_score >= 100:
        return "Safe"

    if security_score >= 90:
        return "Low"

    if security_score >= 70:
        return "Medium"

    if security_score >= 50:
        return "High"

    return "Critical"


def calculate_security_score(findings):

    risk_score = calculate_risk_score(findings)

    score = 100 - risk_score

    return max(score, 0)
def calculate_risk_score(findings):
    return sum(
        finding.points
        for finding in findings
    )


def calculate_risk_level(score):

    if score <= 3:
        return "Low"

    if score <= 8:
        return "Medium"

    if score <= 15:
        return "High"

    return "Critical"


def calculate_security_score(findings):

    risk_score = calculate_risk_score(findings)

    score = 100 - (risk_score * 4)

    return max(score, 0)
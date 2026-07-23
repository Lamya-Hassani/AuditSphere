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


def calculate_security_score(raw_score: int) -> int:
    score = 100 - (raw_score * 5)
    return max(score, 0)

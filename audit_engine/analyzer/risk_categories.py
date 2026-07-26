from analyzer.rules_loader import load_risk_categories


def calculate_categories(findings):

    rules = load_risk_categories()

    categories = set()

    breakdown = {}

    for category in rules:

        breakdown[category] = 0

    for finding in findings:

        service = finding.service.lower()

        for category, services in rules.items():

            if service in services:

                categories.add(category)

                breakdown[category] += finding.points

    breakdown = {

        k: v

        for k, v in breakdown.items()

        if v > 0

    }

    return list(categories), breakdown

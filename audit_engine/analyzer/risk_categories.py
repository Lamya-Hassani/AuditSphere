from analyzer.rules_loader import load_risk_categories


def calculate_categories(findings):

    rules = load_risk_categories()

    categories = set()
    breakdown = {}

    for finding in findings:

        service = finding.service.lower()

        for category, services in rules.items():

            if service not in services:
                continue

            categories.add(category)

            breakdown[category] = (
                breakdown.get(category, 0)
                + finding.points
            )

    return (
        sorted(categories),
        breakdown
    )
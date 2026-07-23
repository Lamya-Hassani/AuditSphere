def unique_recommendations(findings):
    recommendations = []

    seen = set()

    for finding in findings:

        if finding.recommendation not in seen:

            recommendations.append(finding.recommendation)

            seen.add(finding.recommendation)

    return recommendations

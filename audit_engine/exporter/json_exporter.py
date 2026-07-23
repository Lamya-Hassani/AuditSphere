from dataclasses import asdict
import json
from pathlib import Path

REPORT_FOLDER = Path("reports")

def export_json(report):

    REPORT_FOLDER.mkdir(exist_ok=True)

    filename = REPORT_FOLDER / (
        f"laboratory_{report.scan_date.strftime('%Y%m%d_%H%M%S')}.json"
    )

    output = {

        "scan_date":
        report.scan_date.strftime("%Y-%m-%d %H:%M:%S"),

        "target":
        report.target,

        "engine_version":
        report.engine_version,

        "laboratory_security_score":
        report.laboratory_security_score,

        "statistics":
        report.statistics,

        "recommendations":
        report.recommendations,

        "devices": [

            {
                "device": asdict(result.device),

                 "scan_date": result.scan_date.strftime("%Y-%m-%d %H:%M:%S"),

                "risk_score": result.risk_score,

                "risk_level": result.risk_level,

                "security_score": result.security_score,

                "findings": [
                    asdict(finding)
                    for finding in result.findings
                ]
            }

            for result in report.results
        ]
    }

    with open(filename, "w") as f:

        json.dump(output, f, indent=4)

    return filename

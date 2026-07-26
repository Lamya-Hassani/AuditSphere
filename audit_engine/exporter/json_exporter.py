from dataclasses import asdict
from pathlib import Path
import json
from datetime import datetime

TEMP_FOLDER = Path("temp")
REPORT_FILE = TEMP_FOLDER / "report.json"


def convert(obj):

    if isinstance(obj, datetime):
        return obj.strftime("%Y-%m-%d %H:%M:%S")

    raise TypeError()


def export_json(report):

    TEMP_FOLDER.mkdir(exist_ok=True)

    # -------------------------
    # Serialize devices
    # -------------------------

    devices = []

    for result in report.results:

        devices.append(asdict(result))

    # -------------------------
    # Final JSON
    # -------------------------

    output = {

        "audit_metadata": report.metadata,

        "scan_date": report.scan_date.strftime("%Y-%m-%d %H:%M:%S"),

        "target": report.target,

        "engine_version": report.engine_version,

        "laboratory_security_score": report.laboratory_security_score,

        "statistics": report.statistics,

        "recommendations": report.recommendations,

        "devices": devices

    }

    with open(REPORT_FILE, "w") as file:

        json.dump(
            output,
            file,
            indent=4,
            default=convert
        )

    return REPORT_FILE

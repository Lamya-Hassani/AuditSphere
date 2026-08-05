from dataclasses import asdict
from datetime import datetime


def convert(obj):

    if isinstance(obj, datetime):
        return obj.strftime("%Y-%m-%d %H:%M:%S")

    raise TypeError()


def report_to_dict(report):

    devices = []

    for result in report.results:

        devices.append(asdict(result))

    output = {

        "audit_metadata": report.metadata,

        "scan_date": report.scan_date.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "target": report.target,

        "engine_version": report.engine_version,

        "laboratory_security_score":
            report.laboratory_security_score,

        "statistics": report.statistics,

        "recommendations": report.recommendations,

        "devices": devices

    }

    return output
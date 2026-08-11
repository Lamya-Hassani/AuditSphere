import json
from pathlib import Path


CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


def _load_json(filename):
    path = CONFIG_DIR / filename

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def load_cve_database():
    return _load_json("cve_database.json")


def load_port_rules():
    return _load_json("port_rules.json")


def load_risk_categories():
    return _load_json("risk_categories.json")


def load_version_rules():
    return _load_json("version_rules.json")
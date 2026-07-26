import json
from pathlib import Path

CONFIG_FOLDER = Path("config")

def load_rules():
    with open(CONFIG_FOLDER / "rules.json") as f:
        return json.load(f)

def load_port_rules():
    with open(CONFIG_FOLDER / "port_rules.json") as f:
        return json.load(f)

def load_version_rules():
    with open(CONFIG_FOLDER / "version_rules.json") as f:
        return json.load(f)

def load_risk_categories():
    with open(CONFIG_FOLDER / "risk_categories.json") as f:
        return json.load(f)
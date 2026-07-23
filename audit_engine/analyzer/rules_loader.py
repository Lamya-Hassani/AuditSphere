import json
from pathlib import Path


RULES_FILE = Path("config/rules.json")


def load_rules():

    with open(RULES_FILE, "r") as file:

        rules = json.load(file)

    return rules

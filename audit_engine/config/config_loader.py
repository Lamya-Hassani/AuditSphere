import json
from pathlib import Path

CONFIG_FILE = Path(__file__).parent / "config.json"

def load_config():
    with open(CONFIG_FILE, "r") as file:
        return json.load(file)


# Global configuration
config = load_config()
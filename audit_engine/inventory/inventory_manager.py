import json
from pathlib import Path
from datetime import datetime

INVENTORY_FILE = Path("inventory/inventory.json")


def load_inventory():

    if not INVENTORY_FILE.exists():

        return {"devices": []}

    with open(INVENTORY_FILE, "r") as f:

        return json.load(f)


def save_inventory(inventory):

    with open(INVENTORY_FILE, "w") as f:

        json.dump(inventory, f, indent=4)


def update_inventory(lab_report):

    inventory = load_inventory()

    devices = inventory["devices"]

    today = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    scanned_ips = []

    for result in lab_report.results:

        device = result.device

        scanned_ips.append(device.ip)

        existing = None

        for item in devices:

            if item["ip"] == device.ip:

                existing = item
                break

        if existing:

            existing["hostname"] = device.hostname
            existing["mac"] = device.mac
            existing["vendor"] = device.vendor
            existing["os"] = device.os

            existing["last_seen"] = today
            existing["times_scanned"] += 1
            existing["risk_level"] = result.risk_level
            existing["security_score"] = result.security_score
            existing["status"] = "Online"

        else:

            print(f"[+] New device discovered: {device.ip}")

            devices.append({

                "ip": device.ip,

                "hostname": device.hostname,

                "mac": device.mac,

                "vendor": device.vendor,

                "os": device.os,

                "first_seen": today,

                "last_seen": today,

                "times_scanned": 1,

                "risk_level": result.risk_level,

                "security_score": result.security_score,

                "status": "Online"

            })

    for item in devices:

        if item["ip"] not in scanned_ips:

            item["status"] = "Offline"

    save_inventory(inventory)

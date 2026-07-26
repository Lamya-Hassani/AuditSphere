from scanner.scanner import run_scan
from scanner.parser import parse_scan


def run_detailed_scan(ip):

    xml_file = run_scan(ip)
    devices = parse_scan(xml_file)
    if devices:
        return devices[0]

    return None
import requests


class ScanEngineError(Exception):
    """Exception raised when the Kali audit engine returns an error or is unreachable."""
    pass


KALI_API = "http://192.168.56.101:8000"


def run_scan(target):
    """
    Triggers a network scan on the Kali Linux API for the given target.
    Returns the report dictionary on success or raises ScanEngineError.
    """
    try:
        response = requests.post(
            f"{KALI_API}/scan",
            params={"target": target},
            timeout=900
        )
        if not response.ok:
            raise ScanEngineError(
                f"Scan engine returned HTTP {response.status_code}: {response.text}"
            )
        result = response.json()
        if "report" not in result:
            raise ScanEngineError("Scan engine response missing 'report' payload.")
        return result["report"]
    except requests.RequestException as exc:
        raise ScanEngineError(f"Failed to communicate with scan engine: {str(exc)}") from exc
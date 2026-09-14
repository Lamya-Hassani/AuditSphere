"""
compare.py
----------
Compares the current full audit report against the previous one for the same target.
Both reports are plain Python dicts (already serialised by the engine).

Returns a comparison dict that is appended to the report under the key "comparison".
No ML, no external dependencies — simple rule-based diffing.
"""


def _get_hosts(report: dict) -> dict:
    """Return {ip: device_dict} from a report's devices list."""
    return {
        d.get("device", {}).get("ip") or d.get("ip"): d
        for d in report.get("devices", [])
        if d.get("device", {}).get("ip") or d.get("ip")
    }


def _get_open_ports(device_dict: dict) -> set:
    """Return a set of (port_number, protocol) tuples from a device dict."""
    ports = (
        device_dict.get("device", {}).get("ports", [])
        or device_dict.get("ports", [])
    )
    return {(p.get("number"), p.get("protocol", "tcp")) for p in ports}


def _get_finding_keys(device_dict: dict) -> set:
    """Return a set of (port, description) for all findings on a device."""
    findings = device_dict.get("findings", [])
    return {(f.get("port"), f.get("description", "")) for f in findings}


def compare_audits(current: dict, previous: dict) -> dict:
    """
    Diff current vs previous audit report.
    Returns a structured comparison dict.
    """

    current_score  = current.get("laboratory_security_score", 0)
    previous_score = previous.get("laboratory_security_score", 0)
    score_delta    = current_score - previous_score

    current_hosts  = _get_hosts(current)
    previous_hosts = _get_hosts(previous)

    new_hosts     = sorted(set(current_hosts) - set(previous_hosts))
    removed_hosts = sorted(set(previous_hosts) - set(current_hosts))

    new_ports     = {}
    closed_ports  = {}
    new_findings  = {}
    resolved_findings = {}

    for ip in set(current_hosts) | set(previous_hosts):
        cur_dev  = current_hosts.get(ip)
        prev_dev = previous_hosts.get(ip)

        cur_ports  = _get_open_ports(cur_dev)  if cur_dev  else set()
        prev_ports = _get_open_ports(prev_dev) if prev_dev else set()

        opened = cur_ports  - prev_ports
        closed = prev_ports - cur_ports

        if opened:
            new_ports[ip]    = [f"{p}/{proto}" for p, proto in sorted(opened)]
        if closed:
            closed_ports[ip] = [f"{p}/{proto}" for p, proto in sorted(closed)]

        cur_findings  = _get_finding_keys(cur_dev)  if cur_dev  else set()
        prev_findings = _get_finding_keys(prev_dev) if prev_dev else set()

        appeared  = cur_findings  - prev_findings
        resolved  = prev_findings - cur_findings

        if appeared:
            new_findings[ip]      = len(appeared)
        if resolved:
            resolved_findings[ip] = len(resolved)

    total_new_findings      = sum(new_findings.values())
    total_resolved_findings = sum(resolved_findings.values())

    # Current and previous global risk — derived from score, not finding counts.
    # Thresholds must match risk.py (backend) and audit-details.js (frontend).
    def _risk_from_score(score: float) -> str:
        if score >= 90: return "Low"
        if score >= 70: return "Medium"
        if score >= 50: return "High"
        return "Critical"

    prev_risk = _risk_from_score(previous_score)
    cur_risk  = _risk_from_score(current_score)

    # Overall summary sentence
    if score_delta > 0:
        summary = "The infrastructure security posture has improved since the previous audit."
    elif score_delta < 0:
        summary = "The security posture has deteriorated since the previous audit."
    elif total_resolved_findings > total_new_findings:
        summary = "The infrastructure security posture has improved since the previous audit."
    elif total_new_findings > total_resolved_findings:
        summary = "The security posture has deteriorated since the previous audit."
    else:
        summary = "The security posture is stable compared to the previous audit."

    return {
        "previous_score": previous_score,
        "current_score": current_score,
        "score_delta": score_delta,
        "new_hosts": new_hosts,
        "removed_hosts": removed_hosts,
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "new_findings_count": total_new_findings,
        "resolved_findings_count": total_resolved_findings,
        "new_findings_by_host": new_findings,
        "resolved_findings_by_host": resolved_findings,
        "risk_evolution": {
            "previous": prev_risk,
            "current": cur_risk,
        },
        "summary": summary,
    }

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import ipaddress

from engine import run_audit


app = FastAPI(
    title="AuditSphere Audit Engine",
    version="1.1.0"
)


class ScanRequest(BaseModel):
    target: str
    mode: str = "full"
    previous_report: Optional[dict] = None


@app.get("/")
def root():
    return {"message": "AuditSphere Audit Engine API Running"}


@app.post("/scan")
def scan(request: ScanRequest):

    if request.mode not in ["full", "discovery", "ports"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid scan mode. Accepted values: full, discovery, ports"
        )

    try:
        if "/" in request.target:
            ipaddress.ip_network(request.target, strict=False)
        else:
            ipaddress.ip_address(request.target)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid IP address or network."
        )

    try:
        report = run_audit(
            request.target,
            mode=request.mode,
            previous_report=request.previous_report
        )

        return {
            "success": True,
            "message": f"Scan completed successfully in {request.mode} mode.",
            "report": report
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
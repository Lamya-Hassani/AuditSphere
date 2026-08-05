from fastapi import FastAPI, HTTPException
import ipaddress

from engine import run_audit
import json


app = FastAPI(
    title="Cybersecurity Audit Engine",
    version="1.0.0"
)


@app.get("/")
def root():

    return {
        "message": "Audit Engine API Running"
    }

@app.post("/scan")
def scan(target: str):

    try:
        if "/" in target:
            ipaddress.ip_network(target, strict=False)
        else:
            ipaddress.ip_address(target)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid IP address or network."
        )

    try:
        report = run_audit(target)

        return {
            "success": True,
            "message": "Audit completed successfully.",
            "report": report
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
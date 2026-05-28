import os
import uuid
import json
import subprocess
import asyncio
from datetime import datetime
from typing import Dict, Any, List

import aioredis
import fastapi
import uvicorn

# Environment variables
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
RECON_STREAM = "recon.events"
ALERT_STREAM = "alerts"
ALLOWED_SUBNETS = [
    "192.168.",
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
]

app = fastapi.FastAPI(title="Recon Engine")

# Simple in‑memory store for scan status
scans: Dict[str, Dict[str, Any]] = {}

def is_target_allowed(target: str) -> bool:
    """Validate that the target belongs to an allowed private subnet."""
    for prefix in ALLOWED_SUBNETS:
        if target.startswith(prefix):
            return True
    return False

async def publish_to_redis(stream: str, data: Dict[str, Any]):
    redis = await aioredis.from_url(REDIS_URL, decode_responses=False)
    await redis.xadd(stream, {"data": json.dumps(data).encode()})
    await redis.close()

def parse_nmap_xml(xml_output: str) -> List[Dict[str, Any]]:
    """Very small XML parser for nmap output (uses xml.etree)."""
    import xml.etree.ElementTree as ET
    hosts = []
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall('host'):
            status = host.find('status').get('state')
            addr = host.find('address').get('addr')
            os_guess = None
            os_elem = host.find('os')
            if os_elem is not None:
                os_match = os_elem.find('osmatch')
                if os_match is not None:
                    os_guess = os_match.get('name')
            ports = []
            ports_elem = host.find('ports')
            if ports_elem is not None:
                for p in ports_elem.findall('port'):
                    portid = int(p.get('portid'))
                    proto = p.get('protocol')
                    service = p.find('service')
                    svc_name = service.get('name') if service is not None else ""
                    ports.append({"port": portid, "protocol": proto, "service": svc_name})
            hosts.append({
                "ip": addr,
                "status": status,
                "os_guess": os_guess,
                "open_ports": ports,
            })
    except ET.ParseError:
        pass
    return hosts

def compute_risk(open_ports: List[Dict[str, Any]]) -> int:
    """Simple risk scoring based on well‑known risky ports and count of ports."""
    risk = 0
    risky_ports = {22, 3389, 445, 23, 5900}
    for p in open_ports:
        if p["port"] in risky_ports:
            risk += 20
    # add risk for many open ports
    if len(open_ports) > 5:
        risk += 10
    return min(risk, 100)

async def run_nmap(target: str, scan_type: str) -> List[Dict[str, Any]]:
    """Execute nmap and return parsed host dictionaries."""
    # Basic command mapping – extend as needed
    cmd_map = {
        "fast": ["nmap", "-F", "-oX", "-", target],
        "full": ["nmap", "-sS", "-sV", "-O", "-oX", "-", target],
        "os": ["nmap", "-O", "-oX", "-", target],
    }
    cmd = cmd_map.get(scan_type, cmd_map["fast"])
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"Nmap error: {stderr.decode()}")
    return parse_nmap_xml(stdout.decode())

@app.post("/recon/scan")
async def trigger_scan(payload: Dict[str, str]):
    target = payload.get("target")
    scan_type = payload.get("scan_type", "fast")
    if not target or not is_target_allowed(target):
        raise fastapi.HTTPException(status_code=400, detail="Invalid or disallowed target")
    scan_id = str(uuid.uuid4())
    scans[scan_id] = {"status": "running", "target": target, "type": scan_type, "started": datetime.utcnow().isoformat()}
    async def do_scan():
        try:
            hosts = await run_nmap(target, scan_type)
            for host in hosts:
                risk = compute_risk(host["open_ports"])
                event = {
                    "event_type": "recon_scan",
                    "timestamp": datetime.utcnow().isoformat(),
                    "target": host["ip"],
                    "open_ports": host["open_ports"],
                    "os_guess": host.get("os_guess"),
                    "host_status": host["status"],
                    "risk_score": risk,
                }
                await publish_to_redis(RECON_STREAM, event)
                if risk >= 70:
                    alert = {"event_type": "alert", "alert_type": "high_risk_recon", "target": host["ip"], "risk": risk}
                    await publish_to_redis(ALERT_STREAM, alert)
            scans[scan_id]["status"] = "completed"
        except Exception as e:
            scans[scan_id]["status"] = "error"
            scans[scan_id]["error"] = str(e)
    asyncio.create_task(do_scan())
    return {"scan_id": scan_id, "status": "started"}

@app.get("/recon/status/{scan_id}")
async def scan_status(scan_id: str):
    info = scans.get(scan_id)
    if not info:
        raise fastapi.HTTPException(status_code=404, detail="Scan ID not found")
    return info

@app.get("/recon/results")
async def list_results(limit: int = 10):
    # Pull last N entries from Redis stream
    redis = await aioredis.from_url(REDIS_URL, decode_responses=False)
    entries = await redis.xrevrange(RECON_STREAM, max="+", min="-", count=limit)
    await redis.close()
    results = []
    for entry_id, fields in entries:
        data = json.loads(fields[b"data"].decode())
        results.append(data)
    return results

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

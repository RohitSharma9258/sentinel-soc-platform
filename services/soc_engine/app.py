# import and constants
import os
import json
import asyncio
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List

import aioredis
import fastapi
import uvicorn
from pydantic import BaseModel

# Environment variables
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
PACKET_STREAM = "packets.parsed"
FLOW_STREAM = "flows"
ALERT_STREAM = "alerts"
ENRICHED_STREAM = "enriched_packets"

app = fastapi.FastAPI(title="SOC Engine Refactored")

# Internal asyncio queues
flow_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
dns_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
tls_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
yara_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
enrich_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()

# Simple in‑memory TTL cache for threat intel
class TTLCache:
    def __init__(self, ttl_seconds: int = 600):  # 10 min default
        self.ttl = ttl_seconds
        self.store: Dict[str, Any] = {}
        self.expiry: Dict[str, datetime] = {}

    def get(self, key: str):
        now = datetime.utcnow()
        if key in self.store and self.expiry.get(key, now) > now:
            return self.store[key]
        self.store.pop(key, None)
        self.expiry.pop(key, None)
        return None

    def set(self, key: str, value: Any):
        self.store[key] = value
        self.expiry[key] = datetime.utcnow() + timedelta(seconds=self.ttl)

threat_cache = TTLCache()

# ---------- Utility ----------
def publish(stream: str, data: Dict[str, Any]):
    async def _pub():
        redis = await aioredis.from_url(REDIS_URL, decode_responses=False)
        await redis.xadd(stream, {"data": json.dumps(data).encode()})
        await redis.close()
    asyncio.create_task(_pub())

# ---------- Workers ----------
async def ingestion_worker():
    """Consume parsed packets, validate, and route to internal queues."""
    redis = await aioredis.from_url(REDIS_URL, decode_responses=False)
    pubsub = redis.pubsub()
    await pubsub.subscribe(PACKET_STREAM)
    async for msg in pubsub.listen():
        if not msg or msg["type"] != "message":
            continue
        raw = msg["data"]
        try:
            packet = json.loads(raw)
        except Exception:
            continue  # drop malformed
        # Very light schema validation – ensure essential fields exist
        required = ["src_ip", "dst_ip", "protocol"]
        if not all(k in packet for k in required):
            continue
        # Route packet to all internal queues
        await flow_queue.put(packet)
        await dns_queue.put(packet)
        await tls_queue.put(packet)
        await yara_queue.put(packet)
        await enrich_queue.put(packet)
    await pubsub.unsubscribe(PACKET_STREAM)
    await redis.close()

# Flow Worker
async def flow_worker():
    flow_table: Dict[str, Dict[str, Any]] = {}
    while True:
        pkt = await flow_queue.get()
        src = pkt.get("src_ip")
        dst = pkt.get("dst_ip")
        proto = pkt.get("protocol")
        sport = pkt.get("src_port")
        dport = pkt.get("dst_port")
        length = pkt.get("length", 0)
        if not all([src, dst, proto, sport, dport]):
            flow_queue.task_done()
            continue
        flow_key = f"{src}:{sport}-{dst}:{dport}-{proto}".lower()
        now = datetime.utcnow().timestamp()
        flow = flow_table.get(flow_key)
        if not flow:
            flow = {
                "src_ip": src,
                "dst_ip": dst,
                "src_port": sport,
                "dst_port": dport,
                "protocol": proto,
                "start_time": now,
                "last_seen": now,
                "packet_count": 0,
                "byte_count": 0,
            }
            flow_table[flow_key] = flow
        flow["last_seen"] = now
        flow["packet_count"] += 1
        flow["byte_count"] += length
        duration = flow["last_seen"] - flow["start_time"]
        pps = flow["packet_count"] / max(duration, 1)
        risk = 0
        if pps > 100:
            risk += 30
        if duration > 300 and flow["packet_count"] < 5:
            risk += 20
        event = {
            "event_type": "flow_event",
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto,
            "duration": duration,
            "packet_count": flow["packet_count"],
            "bytes": flow["byte_count"],
            "risk_score": min(risk, 100),
            "timestamp": datetime.utcnow().isoformat(),
        }
        publish(FLOW_STREAM, event)
        flow_queue.task_done()

# DNS Worker
async def dns_worker_func():
    while True:
        pkt = await dns_queue.get()
        dns_layer = None
        for layer in pkt.get("layers", []):
            if layer.get("layer_name") == "dns":
                dns_layer = layer
                break
        if dns_layer:
            fields = dns_layer.get("fields", {})
            query = fields.get("qry_name")
            response_ip = fields.get("a")
            risk = 0
            if fields.get("flags_responsecode") == "3":
                risk += 30
            if query:
                import math
                freq = {c: query.count(c) / len(query) for c in set(query)}
                entropy = -sum(p * math.log2(p) for p in freq.values())
                if entropy > 4.0:
                    risk += 20
            event = {
                "event_type": "dns_event",
                "query": query,
                "response_ip": response_ip,
                "risk_score": min(risk, 100),
                "timestamp": datetime.utcnow().isoformat(),
            }
            publish(ALERT_STREAM, event)
        dns_queue.task_done()

# TLS (JA3) Worker
async def tls_worker():
    while True:
        pkt = await tls_queue.get()
        tls_layer = None
        for layer in pkt.get("layers", []):
            if layer.get("layer_name") == "tls":
                tls_layer = layer
                break
        if tls_layer:
            client_hello = tls_layer.get("fields", {})
            try:
                from ja3 import Ja3
                ja3_hash = Ja3(client_hello).fingerprint
            except Exception:
                ciphers = client_hello.get("ciphers", "")
                ja3_hash = uuid.uuid5(uuid.NAMESPACE_DNS, str(ciphers)).hex
            blacklist = {"d4c1..."}
            risk = 80 if ja3_hash in blacklist else 0
            event = {
                "event_type": "tls_fingerprint",
                "ja3_hash": ja3_hash,
                "src_ip": pkt.get("src_ip"),
                "risk_score": risk,
                "timestamp": datetime.utcnow().isoformat(),
            }
            publish(ALERT_STREAM, event)
        tls_queue.task_done()

# YARA Worker (batch mode)
async def yara_worker():
    batch: List[Dict[str, Any]] = []
    BATCH_SIZE = 50
    while True:
        pkt = await yara_queue.get()
        batch.append(pkt)
        # If batch is full, process immediately
        if len(batch) >= BATCH_SIZE:
            await process_yara_batch(batch)
            batch.clear()
        yara_queue.task_done()
        # Also process any pending batch after a short timeout to avoid starvation
        if not yara_queue.empty():
            continue
        await asyncio.sleep(0.5)
        if batch:
            await process_yara_batch(batch)
            batch.clear()

async def process_yara_batch(packets: List[Dict[str, Any]]):
    # Load rules once per batch
    rules_path = os.getenv("YARA_RULES_PATH", "/app/rules")
    if not os.path.isdir(rules_path):
        return
    import yara
    rules = yara.compile(filepaths={f: os.path.join(rules_path, f) for f in os.listdir(rules_path) if f.endswith('.yar')})
    for pkt in packets:
        payload = None
        for layer in pkt.get("layers", []):
            fields = layer.get("fields", {})
            if "data" in fields:
                payload = bytes.fromhex(fields["data"]) if isinstance(fields["data"], str) else fields["data"]
                break
        if not payload:
            continue
        matches = rules.match(data=payload)
        for m in matches:
            alert = {
                "event_type": "yara_alert",
                "rule_name": m.rule,
                "severity": "high" if m.meta.get('severity', '').lower() == 'high' else "medium",
                "matched_payload": payload.hex(),
                "timestamp": datetime.utcnow().isoformat(),
                "src_ip": pkt.get("src_ip"),
                "dst_ip": pkt.get("dst_ip"),
            }
            publish(ALERT_STREAM, alert)

# Enrichment Worker with caching
async def enrichment_worker():
    while True:
        pkt = await enrich_queue.get()
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        def lookup(ip: str):
            if not ip:
                return None, None
            cached = threat_cache.get(ip)
            if cached:
                return cached.get("country"), cached.get("isp")
            try:
                import geoip2.database
                reader = geoip2.database.Reader(os.getenv("GEOIP_DB_PATH", "/data/GeoLite2-Country.mmdb"))
                resp = reader.country(ip)
                country = resp.country.name
                isp = None  # placeholder
                threat_cache.set(ip, {"country": country, "isp": isp})
                return country, isp
            except Exception:
                return None, None
        src_country, src_isp = lookup(src_ip)
        dst_country, dst_isp = lookup(dst_ip)
        enriched = pkt.copy()
        enriched.update({
            "src_country": src_country,
            "dst_country": dst_country,
            "src_isp": src_isp,
            "dst_isp": dst_isp,
            "threat_intel_match": False,
            "timestamp": datetime.utcnow().isoformat(),
        })
        publish(ENRICHED_STREAM, enriched)
        enrich_queue.task_done()

# Rule Worker – simple correlation example
async def rule_worker():
    while True:
        pkt = await enrich_queue.get()
        # Example correlation: if enriched packet already flagged high risk by flow or DNS etc.
        risk = pkt.get("risk_score", 0)
        if risk >= 70:
            alert = {
                "event_type": "final_alert",
                "severity": "high",
                "src_ip": pkt.get("src_ip"),
                "dst_ip": pkt.get("dst_ip"),
                "reason": "high risk after enrichment",
                "timestamp": datetime.utcnow().isoformat(),
            }
            publish(ALERT_STREAM, alert)
        enrich_queue.task_done()

# ---------- Startup ----------
@app.on_event("startup")
async def start_workers():
    asyncio.create_task(ingestion_worker())
    asyncio.create_task(flow_worker())
    asyncio.create_task(dns_worker_func())
    asyncio.create_task(tls_worker())
    asyncio.create_task(yara_worker())
    asyncio.create_task(enrichment_worker())
    asyncio.create_task(rule_worker())

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

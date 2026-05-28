import asyncio
import os
from typing import Dict, Any

import aioredis

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
RAW_CHANNEL = "packets.parsed"
FLOW_CHANNEL = "flows"

class FlowState:
    def __init__(self, src_ip: str, dst_ip: str, protocol: str, src_port: str, dst_port: str):
        self.key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}"
        self.start_time = None
        self.last_seen = None
        self.packet_count = 0
        self.byte_count = 0

    def update(self, timestamp: float, size: int):
        if self.start_time is None:
            self.start_time = timestamp
        self.last_seen = timestamp
        self.packet_count += 1
        self.byte_count += size

    def to_event(self) -> Dict[str, Any]:
        duration = (self.last_seen - self.start_time) if self.start_time else 0
        # Very naive risk scoring
        risk = min(100, self.packet_count // 10)
        return {
            "event_type": "flow_event",
            "src_ip": self.key.split(":")[0],
            "dst_ip": self.key.split("->")[1].split(":")[0],
            "duration": duration,
            "packet_count": self.packet_count,
            "bytes": self.byte_count,
            "risk_score": risk,
        }

flows: Dict[str, FlowState] = {}

async def process_parsed(parsed: Dict[str, Any]):
    # Expected structure from packet_analysis
    layers = parsed.get("layers", [])
    ip_layer = next((l for l in layers if l["layer_name"] == "ip"), None)
    if not ip_layer:
        return
    src_ip = ip_layer["fields"].get("src")
    dst_ip = ip_layer["fields"].get("dst")
    protocol = ip_layer["fields"].get("proto")
    transport_layer = next((l for l in layers if l["layer_name"] in ("tcp", "udp")), None)
    src_port = transport_layer["fields"].get("srcport") if transport_layer else "0"
    dst_port = transport_layer["fields"].get("dstport") if transport_layer else "0"
    timestamp = float(parsed.get("timestamp", 0))
    size = len(str(parsed))
    key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}"
    flow = flows.get(key)
    if not flow:
        flow = FlowState(src_ip, dst_ip, protocol, src_port, dst_port)
        flows[key] = flow
    flow.update(timestamp, size)
    event = flow.to_event()
    # publish flow event
    redis = await aioredis.from_url(REDIS_URL, decode_responses=False)
    await redis.publish(FLOW_CHANNEL, str(event))
    await redis.close()

async def consumer():
    redis = await aioredis.from_url(REDIS_URL, decode_responses=False)
    pubsub = redis.pubsub()
    await pubsub.subscribe(RAW_CHANNEL)
    try:
        async for message in pubsub.listen():
            if message is None:
                continue
            if message["type"] != "message":
                continue
            parsed = eval(message["data"])  # simplistic; replace with json.loads in prod
            await process_parsed(parsed)
    finally:
        await pubsub.unsubscribe(RAW_CHANNEL)
        await redis.close()

if __name__ == "__main__":
    asyncio.run(consumer())

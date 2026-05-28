import asyncio
import os
from typing import Dict, Any

import aioredis
import pyshark

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
RAW_CHANNEL = "packets.raw"
PARSED_CHANNEL = "packets.parsed"

async def process_packet(raw_packet: bytes) -> Dict[str, Any]:
    """Parse a raw packet using pyshark and return structured JSON.
    The raw data is assumed to be a PCAP‑NG capture of a single packet.
    """
    # Write raw packet to a temporary pcap file for pyshark to ingest.
    # Using in‑memory file via BytesIO is not supported, so we write to /tmp.
    tmp_path = "/tmp/raw_packet.pcap"
    with open(tmp_path, "wb") as f:
        f.write(raw_packet)
    # pyshark reads the file; use only the first packet.
    cap = pyshark.FileCapture(tmp_path, keep_packets=False)
    packet = next(iter(cap), None)
    result: Dict[str, Any] = {}
    if packet:
        result["timestamp"] = packet.sniff_timestamp
        result["layers"] = []
        for layer in packet.layers:
            layer_info = {"layer_name": layer.layer_name, "fields": {}}
            for field_name in layer.field_names:
                try:
                    layer_info["fields"][field_name] = getattr(layer, field_name)
                except Exception:
                    # ignore fields that raise errors
                    pass
            result["layers"].append(layer_info)
    cap.close()
    # Cleanup temporary file
    try:
        os.remove(tmp_path)
    except OSError:
        pass
    return result

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
            raw = message["data"]
            parsed = await process_packet(raw)
            await redis.publish(PARSED_CHANNEL, str(parsed))
    finally:
        await pubsub.unsubscribe(RAW_CHANNEL)
        await redis.close()

if __name__ == "__main__":
    asyncio.run(consumer())

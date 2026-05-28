import threading
import asyncio
import logging
from scapy.all import AsyncSniffer
from .config import QUEUE_MAXSIZE
from ..common.event import create_event
import json
import time
from datetime import datetime

logger = logging.getLogger("sniffer_service")

# Global asyncio queue shared with processor (will be set by the processor via import)
packet_queue: asyncio.Queue = None

def set_queue(q: asyncio.Queue):
    """Called by the packet processor to inject the shared queue."""
    global packet_queue
    packet_queue = q

def _packet_handler(pkt):
    """Callback executed by Scapy for each captured packet.
    It puts a lightweight dict onto the asyncio queue.
    """
    if packet_queue is None:
        logger.error("Packet queue not set – dropping packet")
        return
    try:
        # Basic extraction – more fields added later in processor
        data = {
            "raw": bytes(pkt),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        # Use non‑blocking put; if full, drop oldest (FIFO) to maintain back‑pressure
        if packet_queue.full():
            try:
                packet_queue.get_nowait()  # discard oldest
                logger.warning("Packet queue full – dropping oldest packet")
            except asyncio.QueueEmpty:
                pass
        packet_queue.put_nowait(data)
    except Exception as e:
        logger.exception(f"Unexpected error in packet handler: {e}")

def start_sniffer(interface: str = "any"):
    """Start the Scapy AsyncSniffer in a separate thread.
    Returns the ``threading.Thread`` object so the caller can join/stop.
    """
    logger.info(f"Starting sniffer on interface {interface}")
    sniffer = AsyncSniffer(iface=interface, prn=_packet_handler, store=False)
    thread = threading.Thread(target=sniffer.start, daemon=True, name="sniffer_thread")
    thread.start()
    return thread

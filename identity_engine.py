"""
Smart WiFi Intruder Detection System - Identity & Trust Engine
Calculates trust scores and handles weighted device heartbeats.
"""

import logging
import time
from datetime import datetime
from database import db
from event_bus import bus

logger = logging.getLogger("identity")

class IdentityEngine:
    """Calculates device trust and manages session-based state."""
    
    def __init__(self):
        # Weights for different discovery sources
        self.SOURCE_WEIGHTS = {
            "arp": 1.0,      # Active ARP is very reliable
            "packet": 0.8,   # Passive sniffing is good but can be delayed
            "ping": 0.6,     # Ping can be blocked by firewalls
            "dhcp": 1.2      # DHCP request is a strong indicator of a new session
        }
        
        # Behavior trust impacts
        self.TRUST_IMPACTS = {
            "new_device": -10,
            "mac_spoofing": -50,
            "port_scan": -30,
            "flood_attack": -40,
            "known_device": +20,
            "frequent_guest": +5
        }

    def start(self):
        """Initialize subscriptions."""
        bus.subscribe("device_seen", self.handle_device_seen)
        bus.subscribe("threat_detected", self.handle_threat)
        logger.info("Identity Engine started")

    # THREAD-FIX: Add stop() method to cleanly unsubscribe from event_bus topics to prevent dangling thread callback references on application shutdown.
    def stop(self):
        """Cleanly shut down the identity engine."""
        try:
            from event_bus import bus
            # Remove subscriptions by clearing this engine's callbacks
            with bus._event_lock:
                bus._subscribers["device_seen"] = [
                    cb for cb in bus._subscribers["device_seen"]
                    if cb != self.handle_device_seen
                ]
                bus._subscribers["threat_detected"] = [
                    cb for cb in bus._subscribers["threat_detected"]
                    if cb != self.handle_threat
                ]
        except Exception as e:
            logger.warning(f"Identity engine cleanup error: {e}")
        logger.info("Identity Engine stopped")

    def handle_device_seen(self, event_type, data):
        """Process a device heartbeat from any source."""
        mac = data.get("mac")
        ip = data.get("ip")
        source = data.get("source", "arp")
        
        if not mac: return
        
        # If IP is unknown (e.g. from passive sniffing without IP yet), 
        # try to find it from existing records
        if not ip or ip == "0.0.0.0":
            existing = db.get_device_by_mac(mac)
            if existing:
                ip = existing["ip"]
            else:
                return # Can't upsert without IP in current schema

        # Consolidate discovery into DB
        db.upsert_device(ip, mac, source=source)
        
        # Calculate trust bonus for stable behavior
        device = db.get_device_by_mac(mac)
        if device:
            if device["trust_score"] < 100:
                self._apply_trust_bonus(mac)

    def handle_threat(self, event_type, data):
        """Reduce trust score based on detected threats."""
        mac = data.get("mac")
        threat_type = data.get("type")
        impact = self.TRUST_IMPACTS.get(threat_type, -10)
        
        if mac:
            db.update_trust_score(mac, impact)
            logger.warning(f"Trust score reduced for {mac} by {impact} due to {threat_type}")
            
            # Emit trust update for UI
            new_score = db.get_device_by_mac(mac).get("trust_score", 0)
            bus.emit("trust_updated", {"mac": mac, "score": new_score})

    def _apply_trust_bonus(self, mac):
        """Periodically reward 'good' devices."""
        # This could be more complex, e.g. check last threat time
        db.update_trust_score(mac, 1)

# Singleton
identity_engine = IdentityEngine()

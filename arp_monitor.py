"""
NetGuard NDR - ARP Spoofing / Gateway Monitor
==============================================
Standalone ARP defense watchdog that:
  - Monitors ARP table via 'arp -a' + scapy passive capture
  - Detects gateway MAC changes (MITM indicator)
  - Detects IP/MAC conflicts (two MACs claiming same IP)
  - Detects gratuitous ARP floods
  - Emits alerts via the event bus
"""

import re
import time
import logging
import threading
import subprocess
import platform
from collections import defaultdict
from datetime import datetime

from event_bus import bus

logger = logging.getLogger("arp_monitor")

# ─── Configuration ────────────────────────────────────────────────────────────
POLL_INTERVAL_SEC          = 30    # ARP table poll every 30s
GRAT_ARP_FLOOD_THRESHOLD   = 5    # gratuitous ARPs per minute = suspicious
CONFLICT_WINDOW_SEC        = 10   # IP seen from 2 MACs within this window = conflict


class ARPMonitor:
    """
    Dedicated ARP table watchdog.
    Cross-references system ARP table with observed ARP traffic
    to detect spoofing, gateway hijacking, and IP conflicts.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._running = False
        self._thread = None

        # ip → last known mac
        self._arp_table: dict[str, str] = {}
        # Gateway protection
        self._gateway_ip: str = ""
        self._gateway_mac: str = ""
        # ip → list of (mac, timestamp) for conflict detection
        self._ip_mac_history: dict[str, list] = defaultdict(list)
        # mac → list of timestamps for gratuitous ARP flood detection
        self._gratuitous_arps: dict[str, list] = defaultdict(list)
        # Emitted alerts (to avoid duplicates)
        self._alerted_conflicts: set = set()

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def start(self, gateway_ip: str = "", gateway_mac: str = ""):
        """Start the ARP monitor watchdog."""
        if self._running:
            return
        self._running = True
        self._gateway_ip  = gateway_ip
        self._gateway_mac = gateway_mac.upper() if gateway_mac else ""

        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="ARPMonitor"
        )
        self._thread.start()
        logger.info(f"ARP Monitor started (gateway={gateway_ip} / {gateway_mac})")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    # ── Public API (called from packet sniffer) ────────────────────────────────

    def observe_arp(self, ip: str, mac: str, is_gratuitous: bool = False):
        """
        Called by packet_sniffer for every ARP packet seen.
        mac should be uppercase with colons.
        """
        if not ip or not mac or ip == "0.0.0.0":
            return
        now = time.time()
        mac = mac.upper()

        with self._lock:
            # Track gratuitous ARPs
            if is_gratuitous:
                self._gratuitous_arps[mac].append(now)
                # Keep only last 60 seconds
                self._gratuitous_arps[mac] = [
                    t for t in self._gratuitous_arps[mac] if now - t < 60
                ]
                if len(self._gratuitous_arps[mac]) >= GRAT_ARP_FLOOD_THRESHOLD:
                    self._emit_alert("arp_flood", ip, mac,
                        f"Gratuitous ARP flood from {mac} ({ip}): "
                        f"{len(self._gratuitous_arps[mac])} replies/min",
                        severity="high")

            # Track IP→MAC history for conflict detection
            self._ip_mac_history[ip].append((mac, now))
            # Keep only recent entries
            self._ip_mac_history[ip] = [
                (m, t) for m, t in self._ip_mac_history[ip]
                if now - t < CONFLICT_WINDOW_SEC
            ]
            recent_macs = {m for m, _ in self._ip_mac_history[ip]}

            if len(recent_macs) > 1:
                conflict_key = (ip, frozenset(recent_macs))
                if conflict_key not in self._alerted_conflicts:
                    self._alerted_conflicts.add(conflict_key)
                    macs_str = " / ".join(recent_macs)
                    self._emit_alert("ip_conflict", ip, mac,
                        f"IP conflict: {ip} claimed by {macs_str}",
                        severity="critical")

            # Check gateway MAC integrity
            if ip == self._gateway_ip and self._gateway_mac:
                if mac != self._gateway_mac:
                    alert_key = f"gw_{ip}_{mac}"
                    if alert_key not in self._alerted_conflicts:
                        self._alerted_conflicts.add(alert_key)
                        self._emit_alert("gateway_spoof", ip, mac,
                            f"CRITICAL: Gateway MAC changed! "
                            f"{ip} was {self._gateway_mac} now {mac} — likely ARP MITM!",
                            severity="critical")

            # Update ARP table
            prev_mac = self._arp_table.get(ip)
            if prev_mac and prev_mac != mac and ip != self._gateway_ip:
                # Regular MAC change (non-gateway) — possible MAC rotation / spoofing
                change_key = f"mac_change_{ip}_{mac}"
                if change_key not in self._alerted_conflicts:
                    self._alerted_conflicts.add(change_key)
                    self._emit_alert("mac_changed", ip, mac,
                        f"MAC change detected: {ip} was {prev_mac} now {mac}",
                        severity="medium")

            self._arp_table[ip] = mac

    def update_gateway(self, gateway_ip: str, gateway_mac: str):
        """Update the protected gateway MAC (called when scanner identifies gateway)."""
        with self._lock:
            self._gateway_ip  = gateway_ip
            self._gateway_mac = gateway_mac.upper()
            # Seed ARP table with authoritative gateway entry
            if gateway_ip and gateway_mac:
                self._arp_table[gateway_ip] = gateway_mac.upper()
        logger.info(f"ARP Monitor: gateway updated → {gateway_ip} ({gateway_mac})")

    # ── Background Poll Loop ───────────────────────────────────────────────────

    def _monitor_loop(self):
        """Periodically read the system ARP table and check for anomalies."""
        while self._running:
            try:
                self._poll_system_arp()
            except Exception as e:
                logger.debug(f"ARP poll error: {e}")
            time.sleep(POLL_INTERVAL_SEC)

    def _poll_system_arp(self):
        """Read system ARP table via 'arp -a' and check for changes."""
        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True, text=True, timeout=5
            )
            entries = self._parse_arp_output(result.stdout)
            for ip, mac in entries.items():
                self.observe_arp(ip, mac, is_gratuitous=False)
        except Exception as e:
            logger.debug(f"arp -a failed: {e}")

    def _parse_arp_output(self, output: str) -> dict:
        """Parse 'arp -a' output into {ip: mac} dict, cross-platform."""
        entries = {}
        # Windows: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"
        # Linux:   "gateway (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
        for line in output.splitlines():
            # Windows pattern
            win_match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})",
                line
            )
            if win_match:
                ip  = win_match.group(1)
                mac = win_match.group(2).upper().replace("-", ":")
                entries[ip] = mac
        return entries

    # ── Alert Emitter ──────────────────────────────────────────────────────────

    def _emit_alert(self, alert_type: str, ip: str, mac: str, description: str, severity: str = "high"):
        """Emit an ARP alert through the event bus."""
        alert = {
            "type":        alert_type,
            "ip":          ip,
            "mac":         mac,
            "severity":    severity,
            "description": description,
            "detected_at": datetime.now().isoformat(),
        }
        logger.warning(f"[ARP ALERT] {alert_type.upper()}: {description}")
        bus.emit("arp_alert", alert)


# ─── Module Singleton ──────────────────────────────────────────────────────────
arp_monitor = ARPMonitor()

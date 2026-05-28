"""
NetGuard NDR - Threat Detector
Analyzes scan results and sniffer alerts to classify and record threats.
Includes: rogue device detection, MITRE ATT&CK mapping, extended alert types.
"""

import logging
from datetime import datetime, timedelta

from config import AUTO_BLOCK_THREAT_LEVEL
from database import db
from models import Threat

try:
    from mitre_mapper import get_mitre_mapping
except ImportError:
    def get_mitre_mapping(t): return {}

logger = logging.getLogger("detector")


class ThreatDetector:
    """Analyzes devices and sniffer alerts to detect and classify threats."""

    def __init__(self):
        self._threat_history = {}  # mac -> list of recent threats

    def _should_skip_threat(self, mac, ip, threat_type):
        """ANTIGRAVITY-aware threat suppression."""
        from config import ANTIGRAVITY_MODE
        from utils import is_critical_infrastructure
        
        # Layer 1: Critical Infrastructure ALWAYS exempt
        if is_critical_infrastructure(ip):
            db.log_antigravity_action("EXEMPTED_CRITICAL", ip, mac, "Critical infrastructure")
            logger.info(f"✅ [ANTIGRAVITY] Threat suppressed: {ip} is critical infrastructure")
            return True
        
        # Layer 2: Known Device protection
        if ANTIGRAVITY_MODE and db.is_known(mac):
            db.log_antigravity_action("EXEMPTED_TRUSTED", ip, mac, f"Known device: {threat_type}")
            logger.info(f"✅ [ANTIGRAVITY] Threat suppressed: {mac} is trusted device")
            return True
        
        # Layer 3: Duplicate suppression (5-min window)
        if self._is_duplicate_threat(mac, threat_type, minutes=5):
            logger.debug(f"✅ [ANTIGRAVITY] Duplicate threat suppressed: {mac}/{threat_type}")
            return True
        
        return False

    def _is_duplicate_threat(self, mac, threat_type, minutes=5):
        """Check if exact threat was recorded recently."""
        cutoff = (datetime.now() - timedelta(minutes=minutes)).isoformat()
        conn = db._get_conn()
        recent = conn.execute("""
            SELECT COUNT(*) as count FROM threats 
            WHERE device_mac = ? AND threat_type = ? AND detected_at > ?
        """, (mac, threat_type, cutoff)).fetchone()
        return recent and recent["count"] > 0

    def analyze_scan_results(self, devices):
        """Analyze scan results, identify critical 'Gravity' services, and detect threats."""
        new_threats = []
        from config import GRAVITY_EXEMPT_PORTS, ANTIGRAVITY_MODE
        from utils import is_critical_infrastructure
        # ARCH: Fetch gateway from NetworkContext
        from network_context import net_ctx
        gateway_ip = net_ctx.gateway_ip
        
        # PERF: Local cache for threat counts within this scan loop to save duplicate SQLite queries
        threat_cache = {}

        def _get_threat_count_cached(mac, window_seconds=300):
            cache_key = (mac, window_seconds)
            if cache_key not in threat_cache:
                threat_cache[cache_key] = db.get_threat_count_by_mac(mac, window_seconds=window_seconds)
            return threat_cache[cache_key]
        
        for dev_dict in devices:
            mac = dev_dict.get("mac", "").upper()
            ip = dev_dict.get("ip", "")

            if not mac or not ip:
                continue

            # Smart Gravity Detection: Gateway protection
            is_critical_service = (ip == gateway_ip)
            if is_critical_service and ANTIGRAVITY_MODE:
                logger.debug(f"Gravity Detection: {ip} protected as Critical Infrastructure")

            # Check 1: Unknown device (skip if filtered)
            if not db.is_known(mac) and not self._should_skip_threat(mac, ip, "unknown_device"):
                # PERF: Use local cached threat count lookup (10 minutes = 600 seconds) to avoid redundant SQL queries
                existing_threats = _get_threat_count_cached(mac, window_seconds=600)
                if existing_threats == 0:
                    threat = Threat(
                        device_mac=mac,
                        device_ip=ip,
                        threat_type="unknown_device",
                        threat_level="low",
                        threat_score=15,
                        description=f"Unknown device detected on network: {ip} ({mac})",
                        details={
                            "hostname": dev_dict.get("hostname", "Unknown"),
                            "vendor": dev_dict.get("vendor", "Unknown"),
                        }
                    )
                    self._record_threat(threat)
                    new_threats.append(threat)

            # Check 2: Device was previously blocked
            if db.is_blocked(ip) and not self._should_skip_threat(mac, ip, "blocked_device_active"):
                if is_critical_infrastructure(ip):
                    continue

                threat = Threat(
                    device_mac=mac,
                    device_ip=ip,
                    threat_type="blocked_device_active",
                    threat_level="critical",
                    threat_score=95,
                    description=f"ENFORCEMENT ALERT: Blocked device {ip} attempted to reconnect to the network.",
                )
                self._record_threat(threat)
                new_threats.append(threat)

            # NDR: Check 3 — Rogue device indicators
            rogue_threats = self.analyze_rogue_indicators(dev_dict)
            new_threats.extend(rogue_threats)

        return new_threats

    def analyze_rogue_indicators(self, dev_dict: dict) -> list:
        """
        NDR: Evaluate a device for rogue/suspicious indicators.
        Returns list of Threat objects if rogue criteria met.
        """
        new_threats = []
        mac = (dev_dict.get("mac") or "").upper()
        ip  = dev_dict.get("ip", "")

        if not mac or not ip:
            return []

        # Skip trusted/known devices and critical infrastructure
        if db.is_known(mac):
            return []
        from utils import is_critical_infrastructure
        if is_critical_infrastructure(ip):
            return []
        if self._should_skip_threat(mac, ip, "rogue_device"):
            return []

        rogue_score = 0
        rogue_reasons = []

        # Indicator 1: Unknown / randomized vendor
        vendor = (dev_dict.get("vendor") or "Unknown").lower()
        if vendor in ("unknown", ""):
            rogue_score += 20
            rogue_reasons.append("Unknown vendor/manufacturer")

        # Indicator 2: Randomized (locally-administered) MAC
        try:
            first_byte = int(mac.split(":")[0], 16)
            if first_byte & 0x02:  # locally-administered bit
                rogue_score += 35
                rogue_reasons.append("Randomized / locally-administered MAC address")
        except Exception:
            pass

        # Indicator 3: Missing hostname
        hostname = (dev_dict.get("hostname") or "Unknown")
        if hostname in ("Unknown", "", None):
            rogue_score += 15
            rogue_reasons.append("No hostname resolved")

        # Indicator 4: Excessive DHCP requests (from sniffer)
        try:
            from packet_sniffer import sniffer
            dhcp_freq = sniffer.get_dhcp_frequency(mac)
            if dhcp_freq >= 5:
                rogue_score += 20
                rogue_reasons.append(f"Excessive DHCP requests ({dhcp_freq}/min)")
        except Exception:
            pass

        # Indicator 5: AI risk score contribution
        try:
            from ai_predictor import predictor
            risk = predictor.get_device_risk(mac)
            ai_score = risk.get("risk_score", 0)
            if ai_score >= 60:
                rogue_score += 10
                rogue_reasons.append(f"High AI risk score ({ai_score})")
        except Exception:
            pass

        # Threshold: only flag as rogue if score ≥ 40
        if rogue_score >= 40:
            threat_level = "critical" if rogue_score >= 70 else "high" if rogue_score >= 55 else "medium"
            threat = Threat(
                device_mac=mac,
                device_ip=ip,
                threat_type="rogue_device",
                threat_level=threat_level,
                threat_score=min(95, rogue_score),
                description=f"Rogue device detected: {ip} ({mac}) — score {rogue_score}",
                details={
                    "reasons": rogue_reasons,
                    "vendor": dev_dict.get("vendor", "Unknown"),
                    "hostname": hostname,
                    "rogue_score": rogue_score,
                }
            )
            self._record_threat(threat)
            new_threats.append(threat)
            logger.warning(f"[ROGUE DEVICE] {ip} ({mac}) score={rogue_score}: {', '.join(rogue_reasons)}")

        return new_threats

    def process_sniffer_alerts(self, alerts):
        """
        Process alerts from the packet sniffer.
        Converts sniffer alerts into recorded threats with blocking logic.
        Supports all NDR alert types including beaconing, threat intel, ARP, rogue.
        """
        new_threats = []

        for alert in alerts:
            alert_type = alert.get("type", "")
            ip = alert.get("ip", "")
            severity = alert.get("severity", "medium")
            mac = ""

            # Get MAC from database if we know the IP
            device = db.get_device_by_ip(ip) if ip else None
            if device:
                mac = device.get("mac", "")

            # ── Validation: Prevent empty source fields ──────────────────
            if not ip and not mac:
                logger.debug(f"Ignoring malformed sniffer alert: {alert_type}")
                continue

            # Fallback IP/MAC resolution
            if not ip and mac:
                dev = db.get_device_by_mac(mac)
                if dev: ip = dev.get("ip", "Unknown")
            
            if not mac and ip:
                dev = db.get_device_by_ip(ip)
                if dev: mac = dev.get("mac", "Unknown")

            if alert_type == "port_scan":
                threat = Threat(
                    device_mac=mac or "Unknown",
                    device_ip=ip or "Unknown",
                    threat_type="port_scan",
                    threat_level="high",
                    threat_score=65,
                    description=f"Port scan detected from {ip}: {alert.get('ports_scanned', 0)} ports scanned",
                    details={
                        "ports_scanned": alert.get("ports_scanned", 0),
                        "sample_ports": alert.get("ports", [])[:20],
                        "mitre": get_mitre_mapping("port_scan"),
                    }
                )
                self._record_threat(threat)
                new_threats.append(threat)

            elif alert_type == "port_scan_horizontal":
                threat = Threat(
                    device_mac=mac or "Unknown",
                    device_ip=ip or "Unknown",
                    threat_type="port_scan_horizontal",
                    threat_level="high",
                    threat_score=70,
                    description=f"Horizontal port scan from {ip}: port {alert.get('dst_port')} on {alert.get('hosts_scanned',0)} hosts",
                    details={
                        "dst_port": alert.get("dst_port"),
                        "hosts_scanned": alert.get("hosts_scanned", 0),
                        "mitre": get_mitre_mapping("port_scan_horizontal"),
                    }
                )
                self._record_threat(threat)
                new_threats.append(threat)

            elif alert_type == "flood_attack":
                threat = Threat(
                    device_mac=mac or "Unknown",
                    device_ip=ip or "Unknown",
                    threat_type="flood_attack",
                    threat_level="critical",
                    threat_score=85,
                    description=f"Flood attack from {ip}: {alert.get('packets_per_second', 0)} packets/sec",
                    details={
                        "packets_per_second": alert.get("packets_per_second", 0),
                        "total_packets": alert.get("total_packets", 0),
                        "mitre": get_mitre_mapping("flood_attack"),
                    }
                )
                self._record_threat(threat)
                new_threats.append(threat)

            elif alert_type == "mac_spoofing":
                target_mac = alert.get("new_mac", mac) or mac or "Unknown"
                threat = Threat(
                    device_mac=target_mac,
                    device_ip=ip or "Unknown",
                    threat_type="mac_spoofing",
                    threat_level="critical",
                    threat_score=90,
                    description=f"MAC spoofing detected: {ip} changed MAC from {alert.get('original_mac', '?')} to {alert.get('new_mac', '?')}",
                    details={
                        "original_mac": alert.get("original_mac", ""),
                        "new_mac": alert.get("new_mac", ""),
                        "associated_ips": alert.get("ips", []),
                        "mitre": get_mitre_mapping("mac_spoofing"),
                    }
                )
                self._record_threat(threat)
                new_threats.append(threat)

            elif alert_type == "multiple_connections":
                threat = Threat(
                    device_mac=mac or "Unknown",
                    device_ip=ip or "Unknown",
                    threat_type="multiple_connections",
                    threat_level="medium",
                    threat_score=40,
                    description=f"Excessive connection attempts from {ip}: {alert.get('connection_attempts', 0)} attempts",
                    details={
                        "connection_attempts": alert.get("connection_attempts", 0),
                        "mitre": get_mitre_mapping("multiple_connections"),
                    }
                )
                self._record_threat(threat)
                new_threats.append(threat)

            # NDR: Beaconing / C2 detection
            elif alert_type == "beaconing":
                threat = Threat(
                    device_mac=mac or "Unknown",
                    device_ip=ip or "Unknown",
                    threat_type="beaconing",
                    threat_level="critical",
                    threat_score=min(95, 55 + alert.get("confidence", 50) // 3),
                    description=alert.get("description", f"C2 beaconing from {ip}"),
                    details={
                        "dst_ip": alert.get("dst_ip"),
                        "dst_port": alert.get("dst_port"),
                        "interval_sec": alert.get("interval_sec"),
                        "cv": alert.get("cv"),
                        "confidence": alert.get("confidence"),
                        "mitre": get_mitre_mapping("beaconing"),
                    }
                )
                self._record_threat(threat)
                new_threats.append(threat)

            # NDR: Threat intelligence IOC match
            elif alert_type == "threat_intel_match":
                threat = Threat(
                    device_mac=mac or "Unknown",
                    device_ip=ip or "Unknown",
                    threat_type="threat_intel_match",
                    threat_level="critical",
                    threat_score=92,
                    description=f"IOC match: {ip} communicated with {alert.get('dst_ip','?')} ({alert.get('category','?')})",
                    details={
                        "dst_ip": alert.get("dst_ip"),
                        "ioc_category": alert.get("category"),
                        "mitre": get_mitre_mapping("threat_intel_match"),
                    }
                )
                self._record_threat(threat)
                new_threats.append(threat)

            # NDR: ARP-based alerts from arp_monitor
            elif alert_type in ("arp_spoof", "gateway_spoof", "ip_conflict", "arp_flood", "mac_changed"):
                scores = {"gateway_spoof": 95, "arp_spoof": 90, "ip_conflict": 80, "arp_flood": 70, "mac_changed": 55}
                levels = {"gateway_spoof": "critical", "arp_spoof": "critical", "ip_conflict": "high", "arp_flood": "high", "mac_changed": "medium"}
                threat = Threat(
                    device_mac=mac or "Unknown",
                    device_ip=ip or "Unknown",
                    threat_type=alert_type,
                    threat_level=levels.get(alert_type, "high"),
                    threat_score=scores.get(alert_type, 70),
                    description=alert.get("description", f"ARP anomaly: {alert_type} from {ip}"),
                    details={"mitre": get_mitre_mapping(alert_type)}
                )
                self._record_threat(threat)
                new_threats.append(threat)

            # NDR: Excessive DHCP
            elif alert_type == "excessive_dhcp":
                threat_mac = alert.get("mac") or mac or "Unknown"
                threat = Threat(
                    device_mac=threat_mac,
                    device_ip=ip or "Unknown",
                    threat_type="rogue_device",
                    threat_level="medium",
                    threat_score=45,
                    description=f"Excessive DHCP requests from {threat_mac} ({alert.get('count',0)}/min)",
                    details={"dhcp_count": alert.get("count", 0), "mitre": get_mitre_mapping("rogue_device")}
                )
                self._record_threat(threat)
                new_threats.append(threat)

        # No manual auto-block call here; each threat gets checked during _record_threat below
        return new_threats

    def _record_threat(self, threat):
        """Record a threat in the database."""
        threat_id = db.add_threat(
            device_mac=threat.device_mac,
            device_ip=threat.device_ip,
            threat_type=threat.threat_type,
            threat_level=threat.threat_level,
            threat_score=threat.threat_score,
            description=threat.description,
            details=threat.details,
        )
        threat.id = threat_id
        logger.warning(
            f"THREAT RECORDED: [{threat.threat_level.upper()}] {threat.threat_type} "
            f"from {threat.device_ip or 'Unknown'} ({threat.device_mac or 'Unknown'}) - {threat.description}"
        )
        # ARCH: Emit threat_detected event for trust score adjustment in IdentityEngine
        try:
            from event_bus import bus
            bus.emit("threat_detected", {
                "mac": threat.device_mac,
                "ip": threat.device_ip,
                "type": threat.threat_type,
                "level": threat.threat_level,
                "score": threat.threat_score
            })
        except Exception as e:
            logger.error(f"Failed to emit threat_detected event: {e}")

        # Real-time Auto-block evaluation for every recorded threat immediately
        self._check_auto_block([threat])

    def _check_auto_block(self, threats):
        """Auto-block ONLY on confirmed multi-signal threats with ANTIGRAVITY awareness."""
        
        # PERF: Local cache for threat counts within this block loop to save duplicate SQLite queries
        threat_cache = {}

        def _get_threat_count_cached(mac, window_seconds=300):
            cache_key = (mac, window_seconds)
            if cache_key not in threat_cache:
                threat_cache[cache_key] = db.get_threat_count_by_mac(mac, window_seconds=window_seconds)
            return threat_cache[cache_key]

        for threat in threats:
            # 0. Safety: Never auto-block Known/Trusted devices
            if threat.device_mac and db.is_known(threat.device_mac):
                logger.info(f"[ANTIGRAVITY] Skipping auto-block for trusted device {threat.device_mac}")
                continue
            
            should_block = False
            reason = ""
            
            # Rule 1: MAC spoofing OR score >= 95 = instant block
            if threat.threat_type == "mac_spoofing" or threat.threat_score >= 95:
                should_block = True
                reason = f"High-confidence: {threat.threat_type}"
            
            # Rule 2: Flood attack = instant block
            elif threat.threat_type == "flood_attack":
                should_block = True
                reason = "Flood attack confirmed"
            
            # Rule 3: Critical threats that repeat = block on 2nd occurrence
            elif threat.threat_level == "critical" and threat.threat_score >= 75:
                # PERF: Use local cached threat count lookup to avoid redundant queries
                recent_count = _get_threat_count_cached(threat.device_mac, window_seconds=600)
                if recent_count >= 2:
                    should_block = True
                    reason = f"Repeated critical threat ({recent_count} in 10 min)"
            
            # Rule 4: Aggregated risk = block on 3+ threats
            elif threat.device_mac:
                # PERF: Use local cached threat count lookup to avoid redundant queries
                threat_count = _get_threat_count_cached(threat.device_mac, window_seconds=300)
                if threat_count >= 3:
                    should_block = True
                    reason = f"Aggregated risk ({threat_count} threats in 5 min)"
            
            # Enforcement with logging
            if should_block and threat.device_ip and not db.is_blocked(threat.device_ip):
                logger.critical(f"[ANTIGRAVITY AUTO-BLOCK] {threat.device_ip} - {reason}")
                # ARCH: Decouple blocker via event bus block_requested event
                from event_bus import bus
                bus.emit("block_requested", {
                    "ip": threat.device_ip,
                    "mac": threat.device_mac,
                    "reason": reason,
                    "threat_type": threat.threat_type,
                    "threat_score": threat.threat_score,
                })
                logger.info(f"Block requested via event bus for {threat.device_ip}")
                db.add_log("CRITICAL", "audit", f"AUTO-BLOCK: {threat.device_ip} - {reason}", is_audit=1)
                threat.auto_blocked = True
                if hasattr(threat, "id") and threat.id:
                    db.update_threat_auto_blocked(threat.id)

    def get_threat_summary(self):
        """Get a summary of current threat landscape."""
        threats = db.get_active_threats()
        summary = {
            "total": len(threats),
            "critical": sum(1 for t in threats if t["threat_level"] == "critical"),
            "high": sum(1 for t in threats if t["threat_level"] == "high"),
            "medium": sum(1 for t in threats if t["threat_level"] == "medium"),
            "low": sum(1 for t in threats if t["threat_level"] == "low"),
            "by_type": {},
        }
        for t in threats:
            ttype = t["threat_type"]
            summary["by_type"][ttype] = summary["by_type"].get(ttype, 0) + 1
        return summary


# Module singleton
detector = ThreatDetector()

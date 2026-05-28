"""
NetGuard NDR - Enhanced Packet Sniffer
Real-time packet capture and analysis engine.
Integrates: fingerprinting, beaconing detection, threat intel, ARP monitoring.
"""

import time
import logging
import threading
from collections import defaultdict, deque
from datetime import datetime

from config import (
    SNIFFER_ENABLED, SNIFFER_IFACE, PACKET_BUFFER_SIZE,
    PORT_SCAN_THRESHOLD, FLOOD_PACKET_THRESHOLD,
    CONNECTION_ATTEMPT_THRESHOLD, DETECTION_WINDOW
)
from models import PacketInfo
from event_bus import bus
from utils import get_local_ip, get_local_mac
# ARCH: Added NetworkContext import
from network_context import net_ctx

# NDR: New detection module imports (lazy to avoid circular imports at module load)
def _get_fingerprinter():
    try:
        from fingerprinter import fingerprinter
        return fingerprinter
    except Exception:
        return None

def _get_beaconing():
    try:
        from beaconing_detector import beaconing_detector
        return beaconing_detector
    except Exception:
        return None

def _get_threat_intel():
    try:
        from threat_intel import threat_intel
        return threat_intel
    except Exception:
        return None

def _get_arp_monitor():
    try:
        from arp_monitor import arp_monitor
        return arp_monitor
    except Exception:
        return None

logger = logging.getLogger("sniffer")

# Shared DHCP hostname cache: MAC/IP -> hostname (populated from DHCP Option 12)
dhcp_hostname_cache = {}  # key: ip or mac (upper) -> hostname string


class PacketSniffer:
    """Real-time packet capture and behavioral analysis engine."""

    def __init__(self):
        self._running = False
        self._thread = None
        # ARCH: Use Reentrant Lock to allow nested locking across sub-handlers safely
        self._lock = threading.RLock()

        # Packet buffer (circular) — use deque for O(1) append/pop
        self._packets = deque(maxlen=PACKET_BUFFER_SIZE)
        self._max_packets = PACKET_BUFFER_SIZE

        # Traffic analysis counters (reset per window)
        self._port_access = defaultdict(set)       # src_ip -> set of dst_ports
        self._packet_counts = defaultdict(int)     # src_ip -> packet count
        self._connection_attempts = defaultdict(int)  # src_ip -> SYN count
        self._arp_table = {}                        # ip -> mac (for spoof detection)
        self._mac_ip_map = defaultdict(set)        # mac -> set of IPs

        # NDR: Horizontal scan tracking: dst_port -> set of dst_ips (per src_ip)
        self._horizontal_scan = defaultdict(lambda: defaultdict(set))  # src_ip -> port -> {dst_ips}

        # NDR: DHCP request frequency tracking: mac -> list of timestamps
        self._dhcp_timestamps = defaultdict(list)  # mac -> [timestamps]

        # Detection results
        self._alerts = []
        self._window_start = time.time()
        self._potential_spoofs = {}                # ip -> (new_mac, count)
        self._packet_timestamps = defaultdict(list)  # ip -> list of timestamps
        self._local_ip = ""
        self._local_mac = ""

        # Stats
        self._total_packets = 0
        self._packets_per_second = 0

    def start(self):
        """Start the packet sniffer in a background thread."""
        if self._running:
            logger.warning("Sniffer already running")
            return

        if not SNIFFER_ENABLED:
            logger.info("Sniffer disabled in config")
            return

        self._running = True
        # ARCH: Use consolidated NetworkContext IP
        self._local_ip = net_ctx.local_ip
        self._local_mac = get_local_mac()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True, name="PacketSniffer")
        self._thread.start()
        logger.info(f"Packet sniffer started (Local: {self._local_ip} / {self._local_mac})")

    def stop(self):
        """Stop the packet sniffer."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Packet sniffer stopped")

    def _sniff_loop(self):
        """Main sniffing loop."""
        try:
            from scapy.all import sniff, conf
            conf.verb = 0
            logger.info("Starting scapy packet capture...")
            # ARCH: Avoid thread hang on stop by sniffing in a loop with 2-second timeout
            while self._running:
                sniff(
                    prn=self._process_packet,
                    store=False,
                    stop_filter=lambda p: not self._running,
                    iface=SNIFFER_IFACE,
                    timeout=2
                )
        except ImportError:
            logger.warning("Scapy not available, sniffer running in passive mode")
            self._passive_mode()
        except Exception as e:
            logger.error(f"Sniffer error: {e}")
            self._passive_mode()

    def _passive_mode(self):
        """Fallback mode using socket-based sniffing."""
        import socket
        import struct

        try:
            if hasattr(socket, "AF_PACKET"):
                # Linux raw socket
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            else:
                # Windows raw socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                # ARCH: Use NetworkContext local_ip for passive socket binding
                sock.bind((net_ctx.local_ip, 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                except Exception:
                    pass

            sock.settimeout(1.0)
            logger.info("Passive socket sniffer started")

            while self._running:
                try:
                    data, addr = sock.recvfrom(65535)
                    self._process_raw_packet(data)
                except socket.timeout:
                    self._check_detection_window()
                    continue
                except Exception as e:
                    if self._running:
                        logger.debug(f"Socket recv error: {e}")
                    continue

            sock.close()

        except Exception as e:
            logger.error(f"Passive sniffer failed: {e}")
            # Final fallback: just monitor at interval
            while self._running:
                self._check_detection_window()
                time.sleep(1)

    def _process_packet(self, packet):
        """Process a scapy packet."""
        try:
            from scapy.all import IP, TCP, UDP, ARP, ICMP, DHCP, BOOTP

            pkt_info = PacketInfo(src_ip="", dst_ip="", timestamp=time.time())

            with self._lock:
                # DHCP / BOOTP detection for new devices
                if packet.haslayer(DHCP):
                    bootp = packet[BOOTP]
                    mac = bootp.chaddr[:6].hex(":")
                    mac_upper = mac.upper()
                    hostname_found = None
                    option55_list = []
                    # Extract DHCP options
                    try:
                        dhcp_opts = packet[DHCP].options
                        for opt in dhcp_opts:
                            if not isinstance(opt, tuple):
                                continue
                            opt_name, opt_val = opt[0], opt[1]
                            # Option 12: Hostname
                            if opt_name == "hostname":
                                if isinstance(opt_val, bytes):
                                    opt_val = opt_val.decode("utf-8", errors="ignore")
                                if opt_val:
                                    hostname_found = opt_val
                                    dhcp_hostname_cache[mac_upper] = opt_val
                                    yiaddr = bootp.yiaddr
                                    if yiaddr and yiaddr != "0.0.0.0":
                                        dhcp_hostname_cache[yiaddr] = opt_val
                                    logger.info(f"DHCP hostname discovered: {opt_val} -> {mac_upper}")
                            # Option 55: Parameter Request List (OS fingerprint)
                            elif opt_name == "param_req_list":
                                if isinstance(opt_val, (bytes, bytearray)):
                                    option55_list = list(opt_val)
                                elif isinstance(opt_val, (list, tuple)):
                                    option55_list = list(opt_val)
                    except Exception as _e:
                        logger.debug(f"DHCP option parse error: {_e}")

                    # NDR: Feed DHCP data into fingerprinter
                    fp = _get_fingerprinter()
                    if fp and (option55_list or hostname_found):
                        fp.observe_dhcp_options(mac_upper, option55_list, hostname_found)

                    # NDR: Track DHCP frequency for rogue detection
                    now_ts = time.time()
                    self._dhcp_timestamps[mac_upper].append(now_ts)
                    # Keep last 60 seconds
                    self._dhcp_timestamps[mac_upper] = [
                        t for t in self._dhcp_timestamps[mac_upper] if now_ts - t < 60
                    ]
                    dhcp_count = len(self._dhcp_timestamps[mac_upper])
                    if dhcp_count >= 5:   # >5 DHCP requests/min = suspicious
                        self._alerts.append({
                            "type": "excessive_dhcp",
                            "ip": bootp.yiaddr or "0.0.0.0",
                            "mac": mac_upper,
                            "count": dhcp_count,
                            "severity": "medium",
                            "timestamp": datetime.now().isoformat(),
                        })

                    bus.emit("device_seen", {"mac": mac_upper, "ip": "0.0.0.0", "source": "dhcp"})
                    logger.info(f"DHCP Request detected from {mac}")

                # ARP packets
                if packet.haslayer(ARP):
                    arp = packet[ARP]
                    pkt_info.src_ip = arp.psrc
                    pkt_info.dst_ip = arp.pdst
                    pkt_info.src_mac = arp.hwsrc.upper()
                    pkt_info.protocol = "ARP"
                    pkt_info.size = len(packet)

                    # Track ARP for spoofing detection (existing)
                    self._check_arp_spoof(arp.psrc, arp.hwsrc.upper())

                    # NDR: Feed into ARP monitor (gratuitous ARP = src/dst same IP)
                    arm = _get_arp_monitor()
                    if arm:
                        is_gratuitous = (arp.psrc == arp.pdst or arp.pdst == "0.0.0.0")
                        arm.observe_arp(arp.psrc, arp.hwsrc.upper(), is_gratuitous=is_gratuitous)

                # IP packets
                elif packet.haslayer(IP):
                    ip = packet[IP]
                    pkt_info.src_ip = ip.src
                    pkt_info.dst_ip = ip.dst
                    pkt_info.size = len(packet)

                    # NDR: TTL fingerprinting
                    fp = _get_fingerprinter()

                    if packet.haslayer(TCP):
                        tcp = packet[TCP]
                        pkt_info.protocol = "TCP"
                        pkt_info.src_port = tcp.sport
                        pkt_info.dst_port = tcp.dport
                        pkt_info.flags = str(tcp.flags)

                        # Track port access
                        self._port_access[ip.src].add(tcp.dport)

                        # NDR: Horizontal scan tracking (same port, multiple dst_ips)
                        self._horizontal_scan[ip.src][tcp.dport].add(ip.dst)

                        # Track SYN packets (connection attempts)
                        if tcp.flags & 0x02:  # SYN flag
                            self._connection_attempts[ip.src] += 1

                        # NDR: TCP window fingerprinting
                        if fp:
                            # Resolve MAC from ARP table
                            src_mac = self._arp_table.get(ip.src, "")
                            if src_mac:
                                fp.observe_tcp_window(src_mac, tcp.window)
                                fp.observe_ttl(src_mac, ip.ttl)

                    elif packet.haslayer(UDP):
                        udp = packet[UDP]
                        pkt_info.protocol = "UDP"
                        pkt_info.src_port = udp.sport
                        pkt_info.dst_port = udp.dport

                    elif packet.haslayer(ICMP):
                        pkt_info.protocol = "ICMP"

                    else:
                        pkt_info.protocol = f"IP/{ip.proto}"

                    # NDR: Beaconing observation (outbound traffic only)
                    if ip.src != self._local_ip:
                        bc = _get_beaconing()
                        if bc:
                            dst_port = pkt_info.dst_port or 0
                            bc.observe(ip.src, ip.dst, dst_port)

                    # NDR: Threat Intelligence check (outbound dst)
                    if ip.src == self._local_ip or (ip.dst and ip.dst not in ("255.255.255.255",)):
                        ti = _get_threat_intel()
                        if ti:
                            ioc = ti.is_malicious(ip.dst)
                            if ioc:
                                alert = {
                                    "type":      "threat_intel_match",
                                    "ip":        ip.src,
                                    "dst_ip":    ip.dst,
                                    "category":  ioc.get("category", "unknown"),
                                    "severity":  ioc.get("severity", "high"),
                                    "timestamp": datetime.now().isoformat(),
                                }
                                self._alerts.append(alert)
                                ti.record_hit(ip.src, ip.dst, pkt_info.dst_port or 0, ioc)
                                bus.emit("threat_intel_alert", alert)
                                logger.warning(
                                    f"[THREAT INTEL] {ip.src} → {ip.dst} "
                                    f"({ioc.get('category','?')} / {ioc.get('severity','?')})"
                                )

                if not pkt_info.src_ip:
                    return

                # 1. Filter self-traffic (Avoid flagging ourselves as an attacker)
                if (hasattr(pkt_info, 'src_mac') and pkt_info.src_mac == self._local_mac) or pkt_info.src_ip == self._local_ip:
                    return

                # 2. Update counters
                self._packet_counts[pkt_info.src_ip] += 1
                self._packet_timestamps[pkt_info.src_ip].append(time.time())
                self._total_packets += 1

                # Publish raw packet for forensic pipeline
                try:
                    import redis, base64
                    if not hasattr(self, "_redis_conn"):
                        self._redis_conn = redis.StrictRedis(host="redis", port=6379, db=0)
                    raw_bytes = bytes(packet)
                    b64_data = base64.b64encode(raw_bytes).decode("utf-8")
                    self._redis_conn.publish("packets.raw", b64_data)
                except Exception as pub_err:
                    logger.debug(f"Failed to publish raw packet to Redis: {pub_err}")

                # 3. Store packet
                self._packets.append(pkt_info)
                if len(self._packets) > self._max_packets:
                    self._packets.pop(0)

                # 4. Check detection window
                self._check_detection_window()
            
            # Emit passive discovery event
            if hasattr(pkt_info, 'src_mac') and pkt_info.src_mac:
                bus.emit("device_seen", {
                    "mac": pkt_info.src_mac, 
                    "ip": pkt_info.src_ip, 
                    "source": "packet"
                })

        except Exception as e:
            logger.debug(f"Packet processing error: {e}")

    def _process_raw_packet(self, data):
        """Process a raw socket packet (passive mode) with Layer 2 header parsing and lock synchronization."""
        import struct
        import platform

        try:
            # ARCH: Handle Ethernet header on Linux/macOS (14 bytes)
            ip_data = data
            if platform.system() != "Windows":
                if len(data) < 34:
                    return
                # Verify EtherType is IPv4 (0x0800)
                eth_type = struct.unpack("!H", data[12:14])[0]
                if eth_type != 0x0800:
                    return
                ip_data = data[14:]

            if len(ip_data) < 20:
                return

            # Parse IP header
            iph = struct.unpack("!BBHHHBBH4s4s", ip_data[0:20])
            version = iph[0] >> 4
            ihl = (iph[0] & 0xF) * 4
            protocol = iph[6]
            src_ip = ".".join(map(str, ip_data[12:16]))
            dst_ip = ".".join(map(str, ip_data[16:20]))

            pkt_info = PacketInfo(
                src_ip=src_ip, dst_ip=dst_ip,
                size=len(data), timestamp=time.time()
            )

            with self._lock:
                if protocol == 6:  # TCP
                    if len(ip_data) >= ihl + 4:
                        tcp_header = struct.unpack("!HH", ip_data[ihl:ihl + 4])
                        pkt_info.protocol = "TCP"
                        pkt_info.src_port = tcp_header[0]
                        pkt_info.dst_port = tcp_header[1]
                        if len(ip_data) >= ihl + 14:
                            flags = ip_data[ihl + 13]
                            if flags & 0x02:  # SYN
                                self._connection_attempts[src_ip] += 1
                        self._port_access[src_ip].add(pkt_info.dst_port)

                elif protocol == 17:  # UDP
                    if len(ip_data) >= ihl + 4:
                        udp_header = struct.unpack("!HH", ip_data[ihl:ihl + 4])
                        pkt_info.protocol = "UDP"
                        pkt_info.src_port = udp_header[0]
                        pkt_info.dst_port = udp_header[1]

                elif protocol == 1:  # ICMP
                    pkt_info.protocol = "ICMP"
                else:
                    pkt_info.protocol = f"PROTO/{protocol}"

                self._packet_counts[src_ip] += 1
                self._total_packets += 1

                self._packets.append(pkt_info)
                if len(self._packets) > self._max_packets:
                    self._packets.pop(0)

                self._check_detection_window()

        except Exception as e:
            logger.debug(f"Raw packet parse error: {e}")

    def _check_arp_spoof(self, ip, mac):
        """Detect ARP spoofing with multi-step verification and self-traffic filtering."""
        mac = mac.upper()
        
        # 1. Ignore broadcast, null, and SELF-GENERATED poison packets
        if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF") or mac == self._local_mac:
            return

        if ip in self._arp_table:
            if self._arp_table[ip] != mac:
                # 2. Verification Step: Must see the change 3 times before alerting
                # This filters out temporary cache fluctuations and single poison packets
                p_mac, count = self._potential_spoofs.get(ip, (None, 0))
                if p_mac == mac:
                    count += 1
                else:
                    count = 1
                
                self._potential_spoofs[ip] = (mac, count)
                
                if count >= 3:
                    alert = {
                        "type": "mac_spoofing",
                        "ip": ip,
                        "original_mac": self._arp_table[ip],
                        "new_mac": mac,
                        "timestamp": datetime.now().isoformat(),
                        "severity": "critical"
                    }
                    self._alerts.append(alert)
                    logger.warning(f"ARP SPOOFING VERIFIED: {ip} changed from {self._arp_table[ip]} to {mac}")
                    self._arp_table[ip] = mac # Update only after verification
                    del self._potential_spoofs[ip]
            else:
                # Reset verification if we see the original MAC again
                if ip in self._potential_spoofs:
                    del self._potential_spoofs[ip]
        else:
            self._arp_table[ip] = mac

        # Track MAC -> IP mapping
        self._mac_ip_map[mac].add(ip)
        if len(self._mac_ip_map[mac]) > 3:
            alert = {
                "type": "mac_spoofing",
                "mac": mac,
                "ips": list(self._mac_ip_map[mac]),
                "timestamp": datetime.now().isoformat(),
                "severity": "high"
            }
            self._alerts.append(alert)

    def _check_detection_window(self):
        """Monitor detection window and emit stats pulses."""
        now = time.time()
        elapsed = now - self._window_start
        
        # Calculate instant PPS for the high-frequency pulse
        total_recent = sum(self._packet_counts.values())
        instant_pps = round(total_recent / elapsed, 2) if elapsed > 0 else 0

        # 1. Emit High-Frequency stats pulse (every 1 second)
        if not hasattr(self, "_last_pulse"): 
            self._last_pulse = 0
            
        if now - self._last_pulse >= 1.0:
            bus.emit("packet_update", {
                "total": self._total_packets,
                "pps": instant_pps
            })
            self._last_pulse = now

        # 2. Check Security Analysis Window
        if elapsed >= DETECTION_WINDOW:
            self._analyze_window()
            self._reset_window()

    def _analyze_window(self):
        """Analyze traffic patterns in the current window."""
        elapsed = time.time() - self._window_start
        if elapsed == 0:
            elapsed = 1

        for ip, ports in self._port_access.items():
            if len(ports) >= PORT_SCAN_THRESHOLD:
                alert = {
                    "type": "port_scan",
                    "ip": ip,
                    "ports_scanned": len(ports),
                    "ports": sorted(list(ports))[:50],
                    "timestamp": datetime.now().isoformat(),
                    "severity": "high"
                }
                self._alerts.append(alert)
                logger.warning(f"PORT SCAN detected from {ip}: {len(ports)} ports")

        # NDR: Horizontal scan detection (same port → many IPs)
        HORIZONTAL_SCAN_THRESHOLD = 10  # same port to >10 hosts
        for ip, port_map in self._horizontal_scan.items():
            for dst_port, dst_ips in port_map.items():
                if len(dst_ips) >= HORIZONTAL_SCAN_THRESHOLD:
                    alert = {
                        "type": "port_scan_horizontal",
                        "ip": ip,
                        "dst_port": dst_port,
                        "hosts_scanned": len(dst_ips),
                        "timestamp": datetime.now().isoformat(),
                        "severity": "high",
                    }
                    self._alerts.append(alert)
                    logger.warning(f"HORIZONTAL SCAN from {ip}: port {dst_port} on {len(dst_ips)} hosts")

        # NDR: Beaconing analysis every detection window
        bc = _get_beaconing()
        if bc:
            beacon_alerts = bc.analyze()
            for ba in beacon_alerts:
                self._alerts.append(ba)
                bus.emit("beacon_alert", ba)

        for ip, timestamps in self._packet_timestamps.items():
            # 1. Prune timestamps older than the window
            now = time.time()
            valid_ts = [ts for ts in timestamps if now - ts <= DETECTION_WINDOW]
            self._packet_timestamps[ip] = valid_ts
            
            # 2. Calculate PPS over the window
            count = len(valid_ts)
            pps = count / DETECTION_WINDOW
            
            if pps >= FLOOD_PACKET_THRESHOLD:
                alert = {
                    "type": "flood_attack",
                    "ip": ip,
                    "packets_per_second": round(pps, 2),
                    "total_packets": count,
                    "timestamp": datetime.now().isoformat(),
                    "severity": "critical"
                }
                # Avoid duplicate flood alerts in the same window
                if not any(a["type"] == "flood_attack" and a["ip"] == ip for a in self._alerts[-5:]):
                    self._alerts.append(alert)
                    logger.warning(f"FLOOD ATTACK verified from {ip}: {pps:.0f} pps (rolling window)")

        for ip, count in self._connection_attempts.items():
            if count >= CONNECTION_ATTEMPT_THRESHOLD:
                alert = {
                    "type": "multiple_connections",
                    "ip": ip,
                    "connection_attempts": count,
                    "timestamp": datetime.now().isoformat(),
                    "severity": "medium",
                    "description": f"Security Alert: High volume of connection attempts ({count}) detected from {ip}."
                }
                self._alerts.append(alert)
                logger.warning(f"Multiple connection attempts from {ip}: {count}")

        # Final cleanup for circular buffer enforcement
        with self._lock:
            if len(self._packets) > self._max_packets:
                self._packets = self._packets[-self._max_packets:]

        # Update PPS stat
        total = sum(self._packet_counts.values())
        self._packets_per_second = round(total / elapsed, 2)

    def _reset_window(self):
        """Reset detection window counters."""
        self._port_access.clear()
        self._packet_counts.clear()
        self._connection_attempts.clear()
        self._horizontal_scan.clear()   # NDR: reset horizontal scan tracking
        self._window_start = time.time()

    # ═══════════════════════════════════════════════════════════════════════
    #  PUBLIC API
    # ═══════════════════════════════════════════════════════════════════════

    def get_alerts(self, clear=True):
        """Get and optionally clear pending alerts."""
        with self._lock:
            alerts = list(self._alerts)
            if clear:
                self._alerts.clear()
        return alerts

    def get_recent_packets(self, count=50):
        """Get recent captured packets."""
        with self._lock:
            packets = list(self._packets)[-count:]
        return [p.to_dict() for p in packets]

    def get_dhcp_frequency(self, mac: str) -> int:
        """Return recent DHCP request count for a MAC (last 60 seconds)."""
        with self._lock:
            return len(self._dhcp_timestamps.get(mac.upper(), []))

    def get_stats(self):
        """Get sniffer statistics."""
        with self._lock:
            # ARCH: Thread-safe read access of packet statistics
            return {
                "running": self._running,
                "total_packets": self._total_packets,
                "packets_per_second": self._packets_per_second,
                "buffer_size": len(self._packets),
                "tracked_hosts": len(self._packet_counts),
                "pending_alerts": len(self._alerts),
                "arp_entries": len(self._arp_table),
            }

    @property
    def is_running(self):
        return self._running


# Module singleton
sniffer = PacketSniffer()

"""
NetGuard NDR - Network Scanner
ARP-based network scanning using scapy + fallback to OS tools.
Now enriches devices with MAC vendor lookup and OS fingerprint.
"""

import time
import socket
import logging
import subprocess
import platform
import re
import threading
from datetime import datetime

from config import SCAN_TIMEOUT, DEFAULT_NETWORK
from database import db
from utils import get_network_cidr, resolve_hostname, get_mac_vendor, normalize_mac, get_local_ip
from models import Device, ScanResult
from event_bus import bus
# ARCH: Added net_ctx import
from network_context import net_ctx

# NDR: MAC vendor engine (lazy import to avoid circular deps)
def _get_mac_vendor_engine():
    try:
        from mac_vendor import mac_vendor
        return mac_vendor
    except Exception:
        return None

def _get_fingerprinter():
    try:
        from fingerprinter import fingerprinter
        return fingerprinter
    except Exception:
        return None

logger = logging.getLogger("scanner")

# Scan state
_last_scan_result = None
_scan_lock = threading.Lock()

def scan_network(network=None):
    """
    Perform a full network scan with real-time sync and status stabilization.
    """
    global _last_scan_result
    
    if network is None:
        # ARCH: Fetch network CIDR from NetworkContext
        network = net_ctx.network_cidr
    
    logger.info(f"Scanning target subnet: {network}")
    start_time = time.time()
    
    try:
        # 1. Cleanup stale devices from OTHER subnets first
        db.cleanup_stale_devices()

        # 2. Perform the scan
        discovered_devices = _scapy_arp_scan(network)
        if not discovered_devices:
            logger.warning("Scapy scan returned 0 devices, falling back to OS")
            discovered_devices = _os_arp_scan()
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        discovered_devices = _os_arp_scan()

    # 3. Process discovered devices
    current_time = datetime.now().isoformat()
    seen_macs = set()
    unique_devices = []

    # Get all currently "Online" devices in DB to detect disconnects
    current_online_in_db = {d["mac"]: d for d in db.get_all_devices(filter_subnet=True) if d["is_online"]}

    for dev in discovered_devices:
        # Normalize and filter
        mac = dev.mac.upper()
        if mac in seen_macs: continue
        seen_macs.add(mac)

        # Subnet safety
        subnet_prefix = ".".join(network.split(".")[:3]) + "."
        if not dev.ip.startswith(subnet_prefix): continue

        # Enrich and update
        hostname = resolve_hostname(dev.ip, mac=mac)

        # NDR: Use MAC vendor engine for richer vendor data + risk classification
        vendor_engine = _get_mac_vendor_engine()
        if vendor_engine:
            vendor_info = vendor_engine.lookup(mac)
            vendor = vendor_info["vendor"]
            # Store vendor risk metadata for AI predictor
            dev._vendor_risk = vendor_info.get("risk", "medium")
            dev._is_randomized_mac = vendor_info.get("is_randomized", False)
        else:
            vendor = get_mac_vendor(dev.mac)
            dev._vendor_risk = "medium"
            dev._is_randomized_mac = False
        
        # UPSERT into database (marks as Online, updates based on MAC)
        db.upsert_device(dev.ip, mac, hostname, vendor)

        # NDR: Feed hostname into fingerprinter for OS classification
        fp = _get_fingerprinter()
        if fp and hostname and hostname != "Unknown":
            fp.observe_hostname(mac, hostname)
        
        # NDR: Update device OS fingerprint in database
        if fp:
            fingerprint = fp.get_fingerprint(mac)
            if fingerprint["os_type"] != "Unknown":
                try:
                    db.update_device_fingerprint(
                        mac,
                        os_type=fingerprint["os_type"],
                        os_confidence=fingerprint["confidence"],
                        device_class=fingerprint["device_class"]
                    )
                except Exception:
                    pass  # Graceful: column might not exist yet
        
        dev.hostname = hostname
        dev.vendor = vendor
        unique_devices.append(dev)

        # Emit real-time update
        bus.emit("device_update", {
            "mac": mac, "ip": dev.ip, "status": "online", "hostname": hostname
        })

    # 4. Detect DISCONNECTED devices
    # Any device that was Online but NOT seen in this scan is now Offline
    for mac, device in current_online_in_db.items():
        if mac not in seen_macs:
            logger.info(f"Device disconnected: {device['ip']} ({mac})")
            db.mark_offline(mac)
            bus.emit("device_update", {
                "mac": mac, "ip": device["ip"], "status": "offline"
            })

    elapsed = time.time() - start_time
    result = ScanResult(devices=unique_devices, scan_time=round(elapsed, 2), network=network)

    with _scan_lock:
        _last_scan_result = result

    # Emit aggregate stats update
    bus.emit("stats_update", db.get_stats())

    return result

def _scapy_arp_scan(network):
    """Perform ARP scan using scapy."""
    try:
        from scapy.all import ARP, Ether, srp, conf
        conf.verb = 0  # Suppress scapy output
    except ImportError:
        raise ImportError("scapy not installed")

    devices = []
    # Send ARP requests to the entire subnet
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    try:
        # Increase timeout slightly for better reliability on slow networks
        answered, _ = srp(packet, timeout=SCAN_TIMEOUT, verbose=False)
    except Exception as e:
        logger.error(f"SRP error: {e}")
        return []

    for _, received in answered:
        mac = normalize_mac(received.hwsrc)
        ip = received.psrc
        
        # Filter invalid/broadcast MACs
        if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            continue
            
        devices.append(Device(ip=ip, mac=mac))

    return devices

def _os_arp_scan():
    """Fallback: parse OS ARP table with rapid subnet population."""
    devices = []
    # ARCH: Use NetworkContext local_ip
    local_ip = net_ctx.local_ip
    base = ".".join(local_ip.split(".")[:3])
    
    # Rapidly populate ARP cache in background (non-blocking)
    def _ping_range(start, end):
        for i in range(start, end):
            target = f"{base}.{i}"
            # ARCH: Parameterized ping command list with shell=False
            if platform.system() == "Windows":
                subprocess.Popen(["ping", "-n", "1", "-w", "100", target], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.Popen(["ping", "-c", "1", "-W", "1", target], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Split into 4 threads for faster execution
    threads = []
    for i in range(1, 255, 64):
        t = threading.Thread(target=_ping_range, args=(i, min(255, i + 64)))
        t.start()
        threads.append(t)
    
    # ARCH: Join the threads to guarantee all ping processes have been spawned
    for t in threads:
        t.join()
    
    # Wait for population
    time.sleep(2.0)

    try:
        if platform.system() == "Windows":
            # ARCH: Parameterized command list with shell=False
            output = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
            # Pattern: 192.168.1.10   00-11-22-33-44-55   dynamic
            pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([\w:-]+)\s+(\w+)"
            for match in re.finditer(pattern, output):
                ip, mac, dtype = match.groups()
                if dtype.lower() == "dynamic":
                    mac = normalize_mac(mac)
                    if mac not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                        devices.append(Device(ip=ip, mac=mac))
        else:
            # ARCH: Parameterized command list with shell=False
            output = subprocess.check_output(["arp", "-n"], text=True, timeout=5)
            pattern = r"(\d+\.\d+\.\d+\.\d+)\s+\w+\s+([\w:]+)"
            for match in re.finditer(pattern, output):
                ip, mac = match.groups()
                mac = normalize_mac(mac)
                if mac not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                    devices.append(Device(ip=ip, mac=mac))
    except Exception as e:
        logger.error(f"OS ARP scan failed: {e}")

    return devices

def get_last_scan_result():
    """Get the most recent scan result."""
    with _scan_lock:
        return _last_scan_result

def quick_ping(ip, timeout=1):
    """Quick ping check to see if host is alive."""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(f"ping -n 1 -w {timeout * 1000} {ip}", 
                                  shell=True, capture_output=True, text=True, timeout=timeout + 2)
        else:
            result = subprocess.run(f"ping -c 1 -W {timeout} {ip}", 
                                  shell=True, capture_output=True, text=True, timeout=timeout + 2)
        return result.returncode == 0
    except Exception:
        return False

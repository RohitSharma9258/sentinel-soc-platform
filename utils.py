"""
Smart WiFi Intruder Detection System - Utilities
Helper functions used across all modules.
"""

import re
import time
import socket
import struct
import logging
import subprocess
import platform
from datetime import datetime

logger = logging.getLogger("utils")

# Hostname resolution cache: ip -> (hostname, timestamp)
_hostname_cache = {}  # type: dict[str, tuple[str, float]]
HOSTNAME_CACHE_TTL = 300  # seconds (5 minutes)

# PERF: Cache default gateway IP to avoid blocking ping overhead every scan
_gateway_cache = {"ip": None, "last_checked": 0}
GATEWAY_CACHE_TTL = 300  # re-validate every 5 minutes


def get_local_ip():
    """Get the local machine's IP address."""
    # INTERFACE-FIX: Check if local IP is manually overridden in config first
    from config import FORCE_LOCAL_IP
    if FORCE_LOCAL_IP:
        logger.info(f"Using forced local IP: {FORCE_LOCAL_IP}")
        return FORCE_LOCAL_IP

    # 1. Try socket detection method first (determines routing interface accurately)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip != "127.0.0.1" and not ip.startswith("169.254."):
            return ip
    except Exception:
        pass

    # 2. Fallback: Parse active interfaces via psutil
    try:
        import psutil
        addrs = psutil.net_if_addrs()
        candidates = []
        for iface_name, iface_addrs in addrs.items():
            for addr in iface_addrs:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    # Skip loopback, APIPA, and invalid addresses
                    if (ip.startswith("127.") or 
                        ip.startswith("169.254.") or
                        ip == "0.0.0.0"):
                        continue
                    # Skip 172.16.x.x - 172.31.x.x range (commonly Docker/VPN virtual adapters)
                    parts = ip.split(".")
                    if len(parts) == 4 and parts[0] == "172" and 16 <= int(parts[1]) <= 31:
                        continue
                    candidates.append(ip)
        
        # Prefer 192.168.x.x (real home/office LAN)
        for ip in candidates:
            if ip.startswith("192.168."):
                return ip
        # Then prefer 10.x.x.x (corporate LAN)
        for ip in candidates:
            if ip.startswith("10."):
                return ip
        # Fallback to first non-excluded address
        if candidates:
            return candidates[0]
    except ImportError:
        pass

    return "127.0.0.1"


def get_local_mac():
    """Get the local machine's MAC address."""
    try:
        from scapy.all import get_if_hwaddr, conf
        return get_if_hwaddr(conf.iface).upper()
    except Exception:
        # Fallback using uuid
        import uuid
        mac = ":".join(re.findall("..", "%012x" % uuid.getnode()))
        return mac.upper()


def get_default_gateway(validate=True):
    """Get the default gateway IP with enhanced detection and validation."""
    # PERF: Use cached default gateway IP if it is still fresh (within TTL window)
    import time
    now = time.time()
    if (_gateway_cache["ip"] and 
            now - _gateway_cache["last_checked"] < GATEWAY_CACHE_TTL):
        return _gateway_cache["ip"]

    try:
        gateway = None
        if platform.system() == "Windows":
            # Try netstat first as it's often more reliable for just the gateway
            try:
                # ARCH: Parameterized command list with shell=False
                output = subprocess.check_output(["netstat", "-rn"], text=True, timeout=5)
                for line in output.split("\n"):
                    if "0.0.0.0" in line and "On-link" not in line:
                        parts = line.split()
                        if len(parts) >= 3 and validate_ip(parts[2]):
                            gateway = parts[2]
                            break
            except Exception:
                pass

            if not gateway:
                # Fallback to ipconfig
                # ARCH: Parameterized command list with shell=False
                output = subprocess.check_output(["ipconfig"], text=True, timeout=10)
                for line in output.split("\n"):
                    if "Default Gateway" in line:
                        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                        if match:
                            gateway = match.group(1)
                            break
        elif platform.system() == "Darwin":  # macOS support
            try:
                # ARCH: Parameterized command list to fetch default route on macOS
                output = subprocess.check_output(["route", "-n", "get", "default"], text=True, timeout=5)
                match = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", output)
                if match:
                    gateway = match.group(1)
            except Exception:
                pass
        else:  # Linux / Unix
            try:
                # ARCH: Parameterized command list to fetch default route on Linux
                output = subprocess.check_output(["ip", "route", "show", "default"], text=True, timeout=10)
                match = re.search(r"via (\d+\.\d+\.\d+\.\d+)", output)
                if match:
                    gateway = match.group(1)
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"Could not detect gateway: {e}")
    
    if not gateway:
        # Final fallback: Check common gateway IPs
        local_ip = get_local_ip()
        if local_ip != "127.0.0.1":
            prefix = ".".join(local_ip.split(".")[:3])
            gateway = f"{prefix}.1"
        else:
            gateway = "192.168.1.1"

    if validate:
        # Verify gateway is reachable via ping
        if not quick_ping(gateway, timeout=1):
            logger.warning(f"Gateway {gateway} unreachable, using fallback")
            gateway = "192.168.1.1"  # Safe fallback
    
    # PERF: Cache the resolved gateway IP and the check timestamp to avoid repeated blocking pings
    _gateway_cache["ip"] = gateway
    _gateway_cache["last_checked"] = now
    return gateway


def invalidate_gateway_cache():
    """Force-refresh the gateway IP cache by clearing it."""
    # PERF: Reset default gateway cache parameters
    _gateway_cache["ip"] = None
    _gateway_cache["last_checked"] = 0


def quick_ping(ip, timeout=1):
    """Perform a fast ping to check if a host is up with proper cross-platform timeouts."""
    try:
        # ARCH: Check OS type and construct args list without invoking shell interpreter
        if platform.system() == "Windows":
            command = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
        elif platform.system() == "Darwin":  # macOS expects timeout in milliseconds for -W
            command = ["ping", "-c", "1", "-W", str(timeout * 1000), ip]
        else:  # Linux expects timeout in seconds for -W
            command = ["ping", "-c", "1", "-W", str(timeout), ip]
            
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except Exception:
        return False


def get_network_cidr():
    """Detect the local network CIDR."""
    # INTERFACE-FIX: Check if network CIDR is manually overridden in config first
    from config import FORCE_NETWORK
    if FORCE_NETWORK:
        logger.debug(f"Using forced network: {FORCE_NETWORK}")
        return FORCE_NETWORK

    local_ip = get_local_ip()
    parts = local_ip.split(".")
    if len(parts) == 4:
        cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        # INTERFACE-FIX: Log the detected CIDR and which IP it was derived from
        logger.info(f"Network CIDR detected: {cidr} (from IP: {local_ip})")
        return cidr
    return "192.168.1.0/24"


def resolve_hostname(ip, mac=None):
    """
    Resolve IP to hostname using multiple strategies:
    1. In-memory cache (5-minute TTL)
    2. DHCP Option-12 cache (populated by packet sniffer)
    3. Standard DNS reverse lookup (gethostbyaddr)
    4. NetBIOS name query via nbtstat (Windows)
    5. mDNS/Bonjour multicast query
    """
    # ── Strategy 0: In-memory cache ───────────────────────────────────────
    now = time.time()
    cached = _hostname_cache.get(ip)
    if cached:
        hostname, ts = cached
        if now - ts < HOSTNAME_CACHE_TTL and hostname != "Unknown":
            return hostname

    # ── Strategy 1: DHCP hostname cache ──────────────────────────────────
    try:
        from packet_sniffer import dhcp_hostname_cache
        if ip in dhcp_hostname_cache:
            _hostname_cache[ip] = (dhcp_hostname_cache[ip], now)
            return dhcp_hostname_cache[ip]
        if mac:
            mac_key = mac.upper()
            if mac_key in dhcp_hostname_cache:
                _hostname_cache[ip] = (dhcp_hostname_cache[mac_key], now)
                return dhcp_hostname_cache[mac_key]
    except Exception:
        pass

    # ── Strategy 2: Standard DNS reverse lookup ───────────────────────────
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            _hostname_cache[ip] = (hostname, now)
            return hostname
    except (socket.herror, socket.gaierror, OSError):
        pass

    # ── Strategy 3: NetBIOS name via nbtstat (Windows only) ──────────────
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["nbtstat", "-A", ip],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                m = re.match(r"^\s+(\S+)\s+<00>\s+UNIQUE", line)
                if m:
                    name = m.group(1).strip()
                    if name and name not in ("__MSBROWSE__",):
                        _hostname_cache[ip] = (name, now)
                        return name
        except Exception:
            pass

    # ── Strategy 4: mDNS (Bonjour / Avahi) multicast query ───────────────
    try:
        mdns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        mdns_sock.settimeout(1.5)
        mdns_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        qname = b"".join(len(p).to_bytes(1, "big") + p.encode() for p in rev.split(".")) + b"\x00"
        query = b"\x00\x00" + b"\x00\x00" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + qname + b"\x00\x0c\x00\x01"
        mdns_sock.sendto(query, ("224.0.0.251", 5353))
        data, _ = mdns_sock.recvfrom(1024)
        decoded = data.decode("latin-1")
        m = re.search(r"([A-Za-z0-9][A-Za-z0-9\-]{1,62}\.local)", decoded)
        if m:
            name = m.group(1).replace(".local", "")
            _hostname_cache[ip] = (name, now)
            return name
        mdns_sock.close()
    except Exception:
        pass

    # Cache negative result too (avoid repeated slow lookups for Unknown devices)
    _hostname_cache[ip] = ("Unknown", now)
    return "Unknown"


def validate_ip(ip):
    """Validate an IP address format."""
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(pattern, ip):
        parts = ip.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    return False


def validate_mac(mac):
    """Validate a MAC address format."""
    pattern = r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$"
    return bool(re.match(pattern, mac))


def normalize_mac(mac):
    """Normalize MAC address to uppercase with colons."""
    mac = mac.upper().replace("-", ":").replace(".", ":")
    # Handle Cisco-style MACs (aaaa.bbbb.cccc)
    if len(mac) == 14 and mac.count(":") == 2:
        mac = mac.replace(":", "")
        mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
    return mac


# PERF: Move OUI database to module level so it is built exactly once at import time
_OUI_DATABASE = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1A:A0": "Dell",
    "00:25:B5": "Dell",
    "3C:D9:2B": "HP",
    "00:1E:68": "Quanta",
    "08:00:27": "VirtualBox",
    "00:16:3E": "Xen",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:1A:11": "Google",
    "F4:F5:D8": "Google",
    "30:FD:38": "Google",
    "AC:67:B2": "Google",
    "54:60:09": "Google",
    "A4:77:33": "Google",
    "18:B4:30": "Nest Labs",
    "64:16:66": "Nest Labs",
    "AA:BB:CC": "Test Device",
    "00:17:88": "Philips",
    "EC:B5:FA": "Philips",
    "00:11:32": "Synology",
    "78:2B:CB": "Dell",
    "14:FE:B5": "Dell",
    "F0:1F:AF": "Dell",
    "00:1C:B3": "Apple",
    "00:1D:4F": "Apple",
    "00:1E:C2": "Apple",
    "00:1F:5B": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:23:DF": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4B": "Apple",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "00:26:B0": "Apple",
    "00:26:BB": "Apple",
    "28:CF:DA": "Apple",
    "3C:15:C2": "Apple",
    "40:6C:8F": "Apple",
    "60:03:08": "Apple",
    "A8:86:DD": "Apple",
    "AC:BC:32": "Apple",
    "B8:17:C2": "Apple",
    "D8:9E:3F": "Apple",
    "F0:B4:79": "Apple",
    "88:66:A5": "Apple",
    "B0:34:95": "Apple",
    "00:0A:95": "Apple",
    "00:14:51": "Apple",
    "00:16:CB": "Apple",
    "D4:F4:6F": "TP-Link",
    "60:32:B1": "TP-Link",
    "C0:25:E9": "TP-Link",
    "50:C7:BF": "TP-Link",
    "30:B5:C2": "TP-Link",
    "14:CC:20": "TP-Link",
    "00:0E:8F": "Samsung",
    "00:12:47": "Samsung",
    "00:12:FB": "Samsung",
    "00:13:77": "Samsung",
    "00:15:99": "Samsung",
    "00:16:32": "Samsung",
    "00:16:6B": "Samsung",
    "00:16:DB": "Samsung",
    "00:17:C9": "Samsung",
    "00:17:D5": "Samsung",
    "00:18:AF": "Samsung",
    "00:1A:8A": "Samsung",
    "00:1B:98": "Samsung",
    "00:1C:43": "Samsung",
    "00:1D:25": "Samsung",
    "00:1D:F6": "Samsung",
    "00:1E:75": "Samsung",
    "00:1F:CC": "Samsung",
    "00:1F:CD": "Samsung",
    "00:21:19": "Samsung",
    "00:21:4C": "Samsung",
    "00:21:D1": "Samsung",
    "00:21:D2": "Samsung",
    "00:24:54": "Samsung",
    "00:24:91": "Samsung",
    "00:24:E9": "Samsung",
    "00:25:66": "Samsung",
    "00:25:67": "Samsung",
    "00:26:37": "Samsung",
    "D8:D4:3C": "Samsung",
    "84:25:DB": "Samsung",
    "8C:77:12": "Samsung",
    "B4:3A:28": "Samsung",
    "CC:07:AB": "Samsung",
    "E4:7C:F9": "Samsung",
    "F4:7B:5E": "Samsung",
    "74:DA:38": "Edimax",
    "00:0E:2E": "Edimax",
    "00:0E:A6": "ASRock",
    "C8:3A:35": "Tenda",
    "00:1F:A4": "Shenzhen Gongjin",
    "00:E0:4C": "Realtek",
    "52:54:00": "QEMU/KVM",
    "B0:BE:76": "TP-Link",
    "6C:5A:B5": "Samsung",
    "C0:97:27": "Samsung",
    "94:01:C2": "Samsung",
    "FC:F8:AE": "Intel",
    "00:1B:21": "Intel",
    "00:1C:BF": "Intel",
    "00:1D:E0": "Intel",
    "00:1E:64": "Intel",
    "00:1E:65": "Intel",
    "00:1F:3B": "Intel",
    "00:1F:3C": "Intel",
    "00:22:FA": "Intel",
    "00:22:FB": "Intel",
    "00:24:D6": "Intel",
    "00:24:D7": "Intel",
    "00:27:10": "Intel",
}

from functools import lru_cache

# PERF: Add an LRU cache for the OUI vendor lookup to save CPU time on repetitive queries
@lru_cache(maxsize=512)
def get_mac_vendor(mac):
    """Look up vendor from MAC OUI prefix."""
    prefix = mac.upper()[:8]
    return _OUI_DATABASE.get(prefix, "Unknown")


def format_timestamp(iso_str):
    """Format ISO timestamp for display."""
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return iso_str


def ip_to_int(ip):
    """Convert IP string to integer."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(num):
    """Convert integer to IP string."""
    return socket.inet_ntoa(struct.pack("!I", num))


def is_private_ip(ip):
    """Check if IP is in a private range."""
    parts = list(map(int, ip.split(".")))
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    return False


def is_critical_infrastructure(ip):
    """
    Check if IP is critical (Gateway or Localhost).
    Used to prevent accidental self-blocking.
    """
    if ip in ("127.0.0.1", "0.0.0.0", "::1"):
        return True
    
    local_ip = get_local_ip()
    if ip == local_ip:
        return True
        
    gateway_ip = get_default_gateway()
    if ip == gateway_ip:
        return True
        
    return False

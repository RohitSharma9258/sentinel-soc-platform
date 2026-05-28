"""
NetGuard NDR - Advanced Device Fingerprinting Engine
=====================================================
Classifies connected devices into OS/device types using:
  - TTL analysis (from IP packets)
  - TCP window size
  - DHCP Option 55 parameter request list
  - Hostname pattern matching

Device classes: Windows | Linux | macOS | Android | iPhone | IoT | Router | Printer | Unknown
Outputs: os_type, confidence (0-100)
"""

import re
import logging
import threading
from collections import defaultdict, Counter

logger = logging.getLogger("fingerprinter")


# ─── Signature Databases ───────────────────────────────────────────────────────

# TTL → OS heuristic (packets often arrive decremented by 1-15 hops)
TTL_SIGNATURES = [
    (120, 128, "Windows",   35),   # Windows default TTL=128
    (56,  64,  "Linux",     30),   # Linux/Android TTL=64
    (56,  64,  "Android",   25),   # overlaps with Linux — resolved by DHCP
    (56,  64,  "macOS",     25),   # macOS TTL=64 same as Linux
    (240, 255, "Router",    40),   # Cisco/network gear TTL=255
    (30,  32,  "IoT",       25),   # Some IoT devices use TTL=32
]

# TCP Window size → OS signatures
TCP_WINDOW_SIGNATURES = {
    8192:  ("Windows",  30),
    65535: ("Windows",  35),   # Modern Windows
    5840:  ("Linux",    35),
    5792:  ("Linux",    30),
    65228: ("Linux",    25),
    65535: ("macOS",    30),   # macOS also uses 65535 — resolved by DHCP
    2048:  ("IoT",      30),
    1024:  ("IoT",      25),
    4096:  ("Printer",  30),
}

# DHCP Option 55 (Parameter Request List) fingerprints
# Sorted tuple of option numbers → device type
DHCP_OPTION55_SIGNATURES = {
    # Windows
    (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252):  ("Windows",    85),
    (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249):        ("Windows",    80),
    (1, 3, 6, 15, 44, 46, 47, 31, 33, 43, 121, 249, 252, 12):    ("Windows",    75),
    # macOS / iOS
    (1, 121, 3, 6, 15, 119, 252, 95, 44, 46):                    ("macOS",      85),
    (1, 121, 3, 6, 15, 119, 252, 95, 44, 46, 47):                ("iPhone",     80),
    (1, 3, 6, 15, 119, 252):                                      ("macOS",      70),
    # Linux / Android
    (1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42):          ("Linux",      85),
    (1, 33, 3, 6, 15, 26, 28, 51, 58, 59, 119):                  ("Android",    80),
    (1, 3, 6, 15, 26, 28, 51, 58, 59):                           ("Android",    70),
    (1, 3, 6, 12, 15, 17, 23, 28, 29, 31, 33, 40, 41, 42):       ("Linux",      75),
}

# Hostname pattern → device type
HOSTNAME_PATTERNS = [
    (r"^android",               "Android",  70),
    (r"iphone|ipad",            "iPhone",   80),
    (r"macbook|imac|mac-",      "macOS",    75),
    (r"printer|print|hp-|epson|canon|brother", "Printer", 80),
    (r"smart-?tv|lg-|samsung-tv|roku|fire-?tv", "Smart TV", 75),
    (r"alexa|echo|nest|philips-?hue|ring-",    "IoT",     75),
    (r"kali|ubuntu|debian|fedora|centos|arch",  "Linux",   80),
    (r"win(dows)?-|desktop-|laptop-|pc-",       "Windows", 65),
    (r"router|gateway|ap-|access-point",        "Router",  80),
    (r"raspberry|rpi",                          "IoT",     75),
]


class DeviceFingerprinter:
    """
    Accumulates packet observations per device MAC and classifies OS/device type.
    Thread-safe; called from packet sniffer.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # mac → dict of observations
        self._observations = defaultdict(lambda: {
            "ttl_samples": [],
            "tcp_window_samples": [],
            "dhcp_options": None,       # frozenset of option numbers
            "hostname": None,
            "votes": Counter(),
            "confidence": 0,
            "os_type": "Unknown",
        })

    # ── Public API ─────────────────────────────────────────────────────────────

    def observe_ttl(self, mac: str, ttl: int):
        """Record an observed TTL value for a device."""
        if not mac or ttl <= 0:
            return
        with self._lock:
            obs = self._observations[mac.upper()]
            obs["ttl_samples"].append(ttl)
            if len(obs["ttl_samples"]) > 20:
                obs["ttl_samples"] = obs["ttl_samples"][-20:]
            self._update_classification(mac.upper())

    def observe_tcp_window(self, mac: str, window: int):
        """Record a TCP window size for a device."""
        if not mac or window <= 0:
            return
        with self._lock:
            obs = self._observations[mac.upper()]
            obs["tcp_window_samples"].append(window)
            if len(obs["tcp_window_samples"]) > 20:
                obs["tcp_window_samples"] = obs["tcp_window_samples"][-20:]
            self._update_classification(mac.upper())

    def observe_dhcp_options(self, mac: str, option_list: list, hostname: str = None):
        """Record DHCP Option 55 parameter list for a device."""
        if not mac:
            return
        with self._lock:
            obs = self._observations[mac.upper()]
            if option_list:
                obs["dhcp_options"] = tuple(sorted(option_list))
            if hostname:
                obs["hostname"] = hostname.lower()
            self._update_classification(mac.upper())

    def observe_hostname(self, mac: str, hostname: str):
        """Record a device hostname (from DHCP option 12 or mDNS)."""
        if not mac or not hostname:
            return
        with self._lock:
            obs = self._observations[mac.upper()]
            obs["hostname"] = hostname.lower()
            self._update_classification(mac.upper())

    def get_fingerprint(self, mac: str) -> dict:
        """
        Return the current fingerprint for a device.
        Returns: {"os_type": str, "confidence": int, "device_class": str}
        """
        with self._lock:
            obs = self._observations.get(mac.upper())
            if not obs:
                return {"os_type": "Unknown", "confidence": 0, "device_class": "unknown"}
            return {
                "os_type": obs["os_type"],
                "confidence": obs["confidence"],
                "device_class": _device_class(obs["os_type"]),
            }

    # ── Classification Engine ──────────────────────────────────────────────────

    def _update_classification(self, mac: str):
        """Recompute OS classification for a MAC (called under lock)."""
        obs = self._observations[mac]
        votes = Counter()
        total_weight = 0

        # 1. Hostname pattern match (highest priority)
        hostname = obs.get("hostname") or ""
        if hostname:
            for pattern, os_type, weight in HOSTNAME_PATTERNS:
                if re.search(pattern, hostname, re.IGNORECASE):
                    votes[os_type] += weight
                    total_weight += weight
                    break

        # 2. DHCP Option 55 fingerprint (high priority)
        dhcp_opts = obs.get("dhcp_options")
        if dhcp_opts:
            for sig_opts, (os_type, weight) in DHCP_OPTION55_SIGNATURES.items():
                # Allow partial match (≥ 70% of signature options present)
                sig_set = set(sig_opts)
                obs_set = set(dhcp_opts)
                overlap = len(sig_set & obs_set) / len(sig_set) if sig_set else 0
                if overlap >= 0.70:
                    votes[os_type] += int(weight * overlap)
                    total_weight += int(weight * overlap)

        # 3. TTL analysis (medium priority)
        if obs["ttl_samples"]:
            avg_ttl = sum(obs["ttl_samples"]) / len(obs["ttl_samples"])
            for ttl_min, ttl_max, os_type, weight in TTL_SIGNATURES:
                if ttl_min <= avg_ttl <= ttl_max:
                    votes[os_type] += weight
                    total_weight += weight
                    break

        # 4. TCP window analysis (lower priority)
        if obs["tcp_window_samples"]:
            most_common_window = Counter(obs["tcp_window_samples"]).most_common(1)[0][0]
            if most_common_window in TCP_WINDOW_SIGNATURES:
                os_type, weight = TCP_WINDOW_SIGNATURES[most_common_window]
                votes[os_type] += weight
                total_weight += weight

        # Resolve final classification
        if votes:
            best_os, best_votes = votes.most_common(1)[0]
            confidence = min(100, int((best_votes / max(total_weight, 1)) * 100 + 10))
            obs["os_type"] = best_os
            obs["confidence"] = confidence
            obs["votes"] = votes
        else:
            obs["os_type"] = "Unknown"
            obs["confidence"] = 0


def _device_class(os_type: str) -> str:
    """Map os_type to a broader device class."""
    mapping = {
        "Windows": "workstation",
        "Linux":   "server",
        "macOS":   "workstation",
        "Android": "mobile",
        "iPhone":  "mobile",
        "Router":  "infrastructure",
        "IoT":     "iot",
        "Printer": "printer",
        "Smart TV": "entertainment",
    }
    return mapping.get(os_type, "unknown")


# ─── Module Singleton ──────────────────────────────────────────────────────────
fingerprinter = DeviceFingerprinter()

"""
Smart WiFi Intruder Detection System - Data Models
Dataclass models for type-safe data handling across modules.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List


@dataclass
class Device:
    """Represents a network device."""
    ip: str
    mac: str
    hostname: str = "Unknown"
    vendor: str = "Unknown"
    is_online: bool = True
    first_seen: str = ""
    last_seen: str = ""
    device_type: str = "unknown"
    threat_level: str = "none"
    threat_score: int = 0
    is_known: bool = False
    notes: str = ""

    def __post_init__(self):
        if not self.first_seen:
            self.first_seen = datetime.now().isoformat()
        if not self.last_seen:
            self.last_seen = datetime.now().isoformat()
        self.mac = self.mac.upper()

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "is_online": self.is_online,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "device_type": self.device_type,
            "threat_level": self.threat_level,
            "threat_score": self.threat_score,
            "is_known": self.is_known,
            "notes": self.notes,
        }


@dataclass
class Threat:
    """Represents a detected threat."""
    device_mac: str
    device_ip: str
    threat_type: str
    threat_level: str
    threat_score: int = 0
    description: str = ""
    details: Optional[dict] = None
    detected_at: str = ""
    resolved: bool = False
    auto_blocked: bool = False

    TYPES = [
        "unknown_device",
        "port_scan",
        "mac_spoofing",
        "flood_attack",
        "multiple_connections",
        "arp_spoofing",
        "ai_predicted",
    ]

    LEVELS = ["low", "medium", "high", "critical"]

    def __post_init__(self):
        if not self.detected_at:
            self.detected_at = datetime.now().isoformat()
        self.device_mac = self.device_mac.upper()

    def to_dict(self):
        return {
            "device_mac": self.device_mac,
            "device_ip": self.device_ip,
            "threat_type": self.threat_type,
            "threat_level": self.threat_level,
            "threat_score": self.threat_score,
            "description": self.description,
            "details": self.details,
            "detected_at": self.detected_at,
            "resolved": self.resolved,
            "auto_blocked": self.auto_blocked,
        }


@dataclass
class BlockedDevice:
    """Represents a blocked device."""
    ip: str
    mac: Optional[str] = None
    reason: str = "Manual block"
    blocked_at: str = ""
    block_method: str = "firewall"
    is_active: bool = True

    def __post_init__(self):
        if not self.blocked_at:
            self.blocked_at = datetime.now().isoformat()

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "reason": self.reason,
            "blocked_at": self.blocked_at,
            "block_method": self.block_method,
            "is_active": self.is_active,
        }


@dataclass
class PacketInfo:
    """Represents a captured packet summary."""
    src_ip: str
    dst_ip: str
    src_mac: str = ""
    dst_mac: str = ""
    protocol: str = "unknown"
    src_port: int = 0
    dst_port: int = 0
    size: int = 0
    timestamp: float = 0.0
    flags: str = ""

    def to_dict(self):
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "size": self.size,
            "timestamp": self.timestamp,
            "flags": self.flags,
        }


@dataclass
class ScanResult:
    """Result of a network scan operation."""
    devices: List[Device] = field(default_factory=list)
    scan_time: float = 0.0
    network: str = ""
    scan_timestamp: str = ""
    
    def __post_init__(self):
        if not self.scan_timestamp:
            self.scan_timestamp = datetime.now().isoformat()
    
    @property
    def timestamp(self):
        """Alias for scan_timestamp."""
        return self.scan_timestamp
    
    def to_dict(self):
        return {
            "devices": [d.to_dict() for d in self.devices],
            "scan_time": self.scan_time,
            "network": self.network,
            "scan_timestamp": self.scan_timestamp,
            "timestamp": self.scan_timestamp,
            "device_count": len(self.devices),
        }

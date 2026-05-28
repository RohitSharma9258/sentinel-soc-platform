"""
NetGuard NDR - MITRE ATT&CK Tactic Mapper
==========================================
Maps detected threat types to MITRE ATT&CK tactics and techniques.
Used in threat display, SOC timeline, and PDF report generation.

Reference: https://attack.mitre.org/
"""

# ─── Threat Type → MITRE ATT&CK Mapping ──────────────────────────────────────
THREAT_MITRE_MAP = {
    # Discovery / Reconnaissance
    "port_scan": {
        "tactic":     "Discovery",
        "tactic_id":  "TA0007",
        "technique":  "Network Service Discovery",
        "tech_id":    "T1046",
        "sub_tech":   None,
        "severity":   "high",
        "color":      "#f97316",
    },
    "port_scan_stealth": {
        "tactic":     "Discovery",
        "tactic_id":  "TA0007",
        "technique":  "Network Service Discovery (Stealth)",
        "tech_id":    "T1046",
        "sub_tech":   None,
        "severity":   "high",
        "color":      "#f97316",
    },
    "port_scan_horizontal": {
        "tactic":     "Reconnaissance",
        "tactic_id":  "TA0043",
        "technique":  "Active Scanning: Scanning IP Blocks",
        "tech_id":    "T1595.001",
        "sub_tech":   ".001",
        "severity":   "high",
        "color":      "#f97316",
    },

    # Credential Access / Lateral Movement
    "flood_attack": {
        "tactic":     "Impact",
        "tactic_id":  "TA0040",
        "technique":  "Network Denial of Service",
        "tech_id":    "T1498",
        "sub_tech":   None,
        "severity":   "critical",
        "color":      "#ef4444",
    },

    # Defense Evasion / Credential Access
    "mac_spoofing": {
        "tactic":     "Defense Evasion",
        "tactic_id":  "TA0005",
        "technique":  "Network Address Translation Traversal",
        "tech_id":    "T1599",
        "sub_tech":   None,
        "severity":   "critical",
        "color":      "#ef4444",
    },

    # Collection / Credential Access
    "arp_spoof": {
        "tactic":     "Credential Access",
        "tactic_id":  "TA0006",
        "technique":  "Adversary-in-the-Middle: ARP Cache Poisoning",
        "tech_id":    "T1557.002",
        "sub_tech":   ".002",
        "severity":   "critical",
        "color":      "#ef4444",
    },
    "gateway_spoof": {
        "tactic":     "Credential Access",
        "tactic_id":  "TA0006",
        "technique":  "Adversary-in-the-Middle: ARP Cache Poisoning",
        "tech_id":    "T1557.002",
        "sub_tech":   ".002",
        "severity":   "critical",
        "color":      "#ef4444",
    },
    "ip_conflict": {
        "tactic":     "Defense Evasion",
        "tactic_id":  "TA0005",
        "technique":  "Network Address Translation Traversal",
        "tech_id":    "T1599",
        "sub_tech":   None,
        "severity":   "high",
        "color":      "#f97316",
    },
    "arp_flood": {
        "tactic":     "Defense Evasion",
        "tactic_id":  "TA0005",
        "technique":  "Indicator Removal on Host",
        "tech_id":    "T1070",
        "sub_tech":   None,
        "severity":   "high",
        "color":      "#f97316",
    },

    # Command and Control
    "beaconing": {
        "tactic":     "Command and Control",
        "tactic_id":  "TA0011",
        "technique":  "Application Layer Protocol",
        "tech_id":    "T1071",
        "sub_tech":   None,
        "severity":   "critical",
        "color":      "#ef4444",
    },
    "threat_intel_match": {
        "tactic":     "Command and Control",
        "tactic_id":  "TA0011",
        "technique":  "Remote Access Software",
        "tech_id":    "T1219",
        "sub_tech":   None,
        "severity":   "critical",
        "color":      "#ef4444",
    },

    # Initial Access
    "unknown_device": {
        "tactic":     "Initial Access",
        "tactic_id":  "TA0001",
        "technique":  "External Remote Services",
        "tech_id":    "T1133",
        "sub_tech":   None,
        "severity":   "low",
        "color":      "#eab308",
    },
    "rogue_device": {
        "tactic":     "Initial Access",
        "tactic_id":  "TA0001",
        "technique":  "Drive-by Compromise",
        "tech_id":    "T1189",
        "sub_tech":   None,
        "severity":   "high",
        "color":      "#f97316",
    },

    # Persistence
    "blocked_device_active": {
        "tactic":     "Persistence",
        "tactic_id":  "TA0003",
        "technique":  "Valid Accounts",
        "tech_id":    "T1078",
        "sub_tech":   None,
        "severity":   "critical",
        "color":      "#ef4444",
    },
    "multiple_connections": {
        "tactic":     "Lateral Movement",
        "tactic_id":  "TA0008",
        "technique":  "Remote Service Session Hijacking",
        "tech_id":    "T1563",
        "sub_tech":   None,
        "severity":   "medium",
        "color":      "#eab308",
    },

    # Exfiltration
    "data_exfiltration": {
        "tactic":     "Exfiltration",
        "tactic_id":  "TA0010",
        "technique":  "Exfiltration Over Alternative Protocol",
        "tech_id":    "T1048",
        "sub_tech":   None,
        "severity":   "critical",
        "color":      "#ef4444",
    },
}

# Default fallback mapping
_DEFAULT_MAPPING = {
    "tactic":     "Unknown",
    "tactic_id":  "—",
    "technique":  "Unknown Technique",
    "tech_id":    "—",
    "sub_tech":   None,
    "severity":   "medium",
    "color":      "#94a3b8",
}


def get_mitre_mapping(threat_type: str) -> dict:
    """
    Return MITRE ATT&CK mapping for a given threat type.
    Always returns a complete dict (fallback if unknown).
    """
    return THREAT_MITRE_MAP.get(threat_type, _DEFAULT_MAPPING).copy()


def format_mitre_badge(threat_type: str) -> str:
    """Return a short formatted string for UI display, e.g. '[TA0007] Discovery / T1046'."""
    m = get_mitre_mapping(threat_type)
    if m["tactic_id"] == "—":
        return ""
    return f"[{m['tactic_id']}] {m['tactic']} / {m['tech_id']}"


def get_all_mappings() -> dict:
    """Return full mapping table (for API endpoint)."""
    return dict(THREAT_MITRE_MAP)

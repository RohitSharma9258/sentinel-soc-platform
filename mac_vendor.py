"""
NetGuard NDR - MAC Vendor Identification Engine
================================================
Identifies device manufacturer from MAC OUI prefix.
Uses a bundled IEEE OUI dataset + SQLite cache for offline operation.
Classifies vendor risk: known-good, unknown, randomized MAC.
"""

import os
import re
import logging
import sqlite3
import threading
import urllib.request
from functools import lru_cache
from datetime import datetime, timedelta

logger = logging.getLogger("mac_vendor")

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
CACHE_DB   = os.path.join(BASE_DIR, "data", "vendor_cache.db")
OUI_FILE   = os.path.join(BASE_DIR, "data", "oui.txt")

# ─── OUI Update URL (IEEE public registry, plain text) ────────────────────────
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

# ─── Risk Classification ──────────────────────────────────────────────────────
# Known reputable vendors → Low risk
LOW_RISK_VENDORS = {
    "apple", "samsung", "google", "amazon", "microsoft", "intel",
    "cisco", "netgear", "tp-link", "asus", "lg", "sony", "dell",
    "hewlett", "hp", "lenovo", "huawei", "xiaomi", "realtek",
    "broadcom", "qualcomm", "raspberry", "espressif", "arduino",
    "philips", "bosch", "siemens", "honeywell", "ubiquiti",
}

# Vendors associated with network testing / pen-testing hardware → High risk
HIGH_RISK_VENDORS = {
    "alfa", "hak5", "proxmark", "ubertooth", "goodfet", "attify",
}


class MACVendorEngine:
    """
    Thread-safe MAC vendor identification engine.
    Lookup order: LRU in-memory cache → SQLite cache → bundled OUI text.
    """

    _lock = threading.Lock()

    def __init__(self):
        self._init_cache_db()
        self._oui_dict = {}          # prefix (first 3 bytes upper) → vendor string
        self._loaded = False
        self._load_oui_data()

    # ── DB Initialisation ──────────────────────────────────────────────────────
    def _init_cache_db(self):
        """Create the vendor cache SQLite database."""
        os.makedirs(os.path.dirname(CACHE_DB), exist_ok=True)
        conn = sqlite3.connect(CACHE_DB, check_same_thread=False)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vendor_cache (
                oui   TEXT PRIMARY KEY,
                vendor TEXT NOT NULL,
                risk   TEXT NOT NULL,
                cached_at TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    # ── OUI Data Loading ───────────────────────────────────────────────────────
    def _load_oui_data(self):
        """Load OUI data from bundled file into memory dict."""
        if not os.path.exists(OUI_FILE):
            logger.info("OUI file not found; using empty vendor DB. Run update_oui() to download.")
            self._loaded = True
            return

        count = 0
        try:
            with open(OUI_FILE, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    # IEEE format: "00-00-0C   (hex)\t\tCisco Systems, Inc"
                    match = re.match(
                        r"^([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$",
                        line.strip()
                    )
                    if match:
                        raw_oui = match.group(1).upper().replace("-", ":").replace(".", ":")
                        vendor  = match.group(2).strip()
                        self._oui_dict[raw_oui] = vendor
                        count += 1
            logger.info(f"MAC Vendor Engine: loaded {count} OUI entries from {OUI_FILE}")
        except Exception as e:
            logger.warning(f"MAC Vendor Engine: failed to load OUI file: {e}")
        self._loaded = True

    def update_oui(self):
        """Download the latest IEEE OUI registry (background-safe)."""
        try:
            logger.info("Downloading IEEE OUI registry...")
            req = urllib.request.Request(OUI_URL, headers={"User-Agent": "NetGuard-NDR/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read().decode("utf-8", errors="ignore")
            with open(OUI_FILE, "w", encoding="utf-8") as f:
                f.write(data)
            self._oui_dict.clear()
            self._load_oui_data()
            logger.info("IEEE OUI registry updated successfully.")
        except Exception as e:
            logger.warning(f"OUI update failed (offline?): {e}")

    # ── Core Lookup ────────────────────────────────────────────────────────────
    def lookup(self, mac: str) -> dict:
        """
        Look up a MAC address and return vendor + risk info.

        Returns:
            {
                "vendor": str,         # e.g. "Apple, Inc."
                "oui": str,            # e.g. "AA:BB:CC"
                "is_randomized": bool, # locally-administered bit set
                "risk": str,           # "low" | "medium" | "high"
                "risk_score": int,     # additive score
            }
        """
        if not mac:
            return self._unknown_result("00:00:00")

        mac_clean = mac.upper().replace("-", ":").replace(".", ":")
        # Normalise to colon-separated
        parts = re.split(r"[:\-.]", mac.upper().replace("-", ":"))
        if len(parts) < 3:
            return self._unknown_result(mac_clean)

        oui = ":".join(parts[:3])

        # ── Check: locally-administered (randomized) MAC ───────────────────────
        # Bit 1 of first octet = locally-administered
        try:
            first_byte = int(parts[0], 16)
            is_randomized = bool(first_byte & 0x02)
        except ValueError:
            is_randomized = False

        if is_randomized:
            return {
                "vendor": "Randomized/Private MAC",
                "oui": oui,
                "is_randomized": True,
                "risk": "high",
                "risk_score": 35,
            }

        # ── Cache check ────────────────────────────────────────────────────────
        cached = self._cache_get(oui)
        if cached:
            return cached

        # ── OUI dict lookup ────────────────────────────────────────────────────
        vendor = self._oui_dict.get(oui, "")
        if not vendor:
            result = self._unknown_result(oui)
        else:
            risk, risk_score = self._classify_vendor(vendor)
            result = {
                "vendor": vendor,
                "oui": oui,
                "is_randomized": False,
                "risk": risk,
                "risk_score": risk_score,
            }

        self._cache_set(oui, result)
        return result

    def _classify_vendor(self, vendor: str) -> tuple:
        """Classify vendor risk. Returns (risk_level, risk_score)."""
        vendor_lower = vendor.lower()

        for kw in HIGH_RISK_VENDORS:
            if kw in vendor_lower:
                return ("high", 30)

        for kw in LOW_RISK_VENDORS:
            if kw in vendor_lower:
                return ("low", 5)

        # Known OUI but unrecognised vendor → medium
        return ("medium", 15)

    def _unknown_result(self, oui: str) -> dict:
        return {
            "vendor": "Unknown",
            "oui": oui,
            "is_randomized": False,
            "risk": "medium",
            "risk_score": 20,
        }

    # ── Cache ──────────────────────────────────────────────────────────────────
    def _cache_get(self, oui: str) -> dict | None:
        try:
            conn = sqlite3.connect(CACHE_DB, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM vendor_cache WHERE oui = ?", (oui,)
            ).fetchone()
            conn.close()
            if row:
                return {
                    "vendor": row["vendor"],
                    "oui": oui,
                    "is_randomized": False,
                    "risk": row["risk"],
                    "risk_score": {"low": 5, "medium": 20, "high": 30}.get(row["risk"], 20),
                }
        except Exception:
            pass
        return None

    def _cache_set(self, oui: str, result: dict):
        try:
            conn = sqlite3.connect(CACHE_DB, check_same_thread=False)
            conn.execute("""
                INSERT OR REPLACE INTO vendor_cache (oui, vendor, risk, cached_at)
                VALUES (?, ?, ?, ?)
            """, (oui, result["vendor"], result["risk"], datetime.now().isoformat()))
            conn.commit()
            conn.close()
        except Exception:
            pass

    def get_vendor_string(self, mac: str) -> str:
        """Convenience wrapper returning just the vendor name."""
        return self.lookup(mac).get("vendor", "Unknown")


# ─── Module Singleton ─────────────────────────────────────────────────────────
mac_vendor = MACVendorEngine()

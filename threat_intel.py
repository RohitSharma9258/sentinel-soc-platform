"""
NetGuard NDR - Threat Intelligence Engine
==========================================
Integrates external IOC (Indicator of Compromise) feeds with local caching.

Sources:
  - Bundled seed IOC list (known bad IPs, TOR exits, C2 addresses)
  - Feodo Tracker (Abuse.ch) — botnet C2 IPs (auto-refreshed)
  - Emerging Threats blocklist (HTTP, offline-safe fallback)

When a device communicates with a known IOC:
  - Generates critical threat alert
  - Emits event bus notification for auto-blocking
  - Logs evidence in threat_intel_hits table
"""

import os
import json
import time
import logging
import sqlite3
import threading
import ipaddress
import urllib.request
from datetime import datetime, timedelta

logger = logging.getLogger("threat_intel")

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
INTEL_DB     = os.path.join(BASE_DIR, "data", "threat_intel.db")
SEED_FILE    = os.path.join(BASE_DIR, "data", "ioc_seed.json")
UPDATE_INTERVAL_HOURS = 6  # refresh feeds every 6 hours

# ─── IOC Feed URLs ────────────────────────────────────────────────────────────
FEODO_TRACKER_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
EMERGING_THREATS_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

# ─── Seed IOC Data (always-available offline baseline) ────────────────────────
SEED_IOCS = [
    # Known botnet C2 and malicious infrastructure (public threat intel)
    # TOR exit node examples (these are well-known public TOR exits)
    {"ip": "185.220.101.1",  "category": "tor_exit",  "severity": "high",     "source": "seed"},
    {"ip": "185.220.101.2",  "category": "tor_exit",  "severity": "high",     "source": "seed"},
    {"ip": "185.220.101.3",  "category": "tor_exit",  "severity": "high",     "source": "seed"},
    {"ip": "185.220.101.4",  "category": "tor_exit",  "severity": "high",     "source": "seed"},
    {"ip": "185.220.101.5",  "category": "tor_exit",  "severity": "high",     "source": "seed"},
    {"ip": "185.220.101.32", "category": "tor_exit",  "severity": "high",     "source": "seed"},
    {"ip": "185.220.101.33", "category": "tor_exit",  "severity": "high",     "source": "seed"},
    {"ip": "185.220.101.34", "category": "tor_exit",  "severity": "high",     "source": "seed"},
    {"ip": "185.220.101.35", "category": "tor_exit",  "severity": "high",     "source": "seed"},
    {"ip": "185.220.101.47", "category": "tor_exit",  "severity": "high",     "source": "seed"},
    # Known C2 botnet addresses (public feodo tracker historical entries)
    {"ip": "80.82.64.91",    "category": "c2_botnet", "severity": "critical", "source": "seed"},
    {"ip": "94.102.61.10",   "category": "c2_botnet", "severity": "critical", "source": "seed"},
    {"ip": "104.244.72.115", "category": "tor_exit",  "severity": "high",     "source": "seed"},
    {"ip": "162.247.74.201", "category": "tor_exit",  "severity": "high",     "source": "seed"},
    # Scanner / enumeration nodes
    {"ip": "198.20.69.74",   "category": "scanner",   "severity": "medium",   "source": "seed"},
    {"ip": "198.20.69.98",   "category": "scanner",   "severity": "medium",   "source": "seed"},
    {"ip": "198.20.70.114",  "category": "scanner",   "severity": "medium",   "source": "seed"},
    {"ip": "198.20.87.98",   "category": "scanner",   "severity": "medium",   "source": "seed"},
]


class ThreatIntelEngine:
    """
    Threat intelligence lookup engine with local SQLite persistence.
    Auto-refreshes public IOC feeds in background.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._ip_set: dict[str, dict] = {}    # ip_str → IOC record (hot cache)
        self._last_update = 0
        self._init_db()
        self._load_into_memory()

    # ── DB Initialisation ──────────────────────────────────────────────────────
    def _init_db(self):
        conn = sqlite3.connect(INTEL_DB, check_same_thread=False)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ip         TEXT NOT NULL UNIQUE,
                category   TEXT NOT NULL,
                severity   TEXT NOT NULL DEFAULT 'medium',
                source     TEXT NOT NULL DEFAULT 'seed',
                added_at   TEXT NOT NULL,
                expires_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS intel_hits (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip      TEXT NOT NULL,
                dst_ip      TEXT NOT NULL,
                dst_port    INTEGER,
                ioc_category TEXT,
                severity    TEXT,
                detected_at TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ti_ip ON threat_intel(ip)")
        conn.commit()
        conn.close()

        # Seed initial IOCs
        self._seed_iocs()

    def _seed_iocs(self):
        """Insert bundled seed IOCs (skips duplicates)."""
        conn = sqlite3.connect(INTEL_DB, check_same_thread=False)
        now = datetime.now().isoformat()
        for ioc in SEED_IOCS:
            try:
                conn.execute("""
                    INSERT OR IGNORE INTO threat_intel (ip, category, severity, source, added_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (ioc["ip"], ioc["category"], ioc["severity"], ioc["source"], now))
            except Exception:
                pass
        conn.commit()
        conn.close()

    def _load_into_memory(self):
        """Load all IPs into the in-memory hot cache."""
        try:
            conn = sqlite3.connect(INTEL_DB, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM threat_intel").fetchall()
            conn.close()
            with self._lock:
                for row in rows:
                    self._ip_set[row["ip"]] = dict(row)
            logger.info(f"Threat Intel: loaded {len(self._ip_set)} IOCs into memory")
        except Exception as e:
            logger.warning(f"Threat Intel: failed to load IOCs: {e}")

    # ── Public API ─────────────────────────────────────────────────────────────

    def is_malicious(self, ip: str) -> dict | None:
        """
        Check if an IP is a known IOC.
        Returns None if clean, or IOC dict if malicious.
        """
        if not ip:
            return None

        # Skip private/reserved addresses
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return None
        except ValueError:
            return None

        with self._lock:
            return self._ip_set.get(ip)

    def record_hit(self, src_ip: str, dst_ip: str, dst_port: int, ioc: dict):
        """Record an IOC match event in the database."""
        try:
            conn = sqlite3.connect(INTEL_DB, check_same_thread=False)
            conn.execute("""
                INSERT INTO intel_hits (src_ip, dst_ip, dst_port, ioc_category, severity, detected_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (src_ip, dst_ip, dst_port,
                  ioc.get("category", "unknown"),
                  ioc.get("severity", "medium"),
                  datetime.now().isoformat()))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug(f"Intel hit record failed: {e}")

    def get_stats(self) -> dict:
        """Return summary statistics."""
        with self._lock:
            by_category = {}
            by_severity  = {}
            for rec in self._ip_set.values():
                cat = rec.get("category", "unknown")
                sev = rec.get("severity", "medium")
                by_category[cat] = by_category.get(cat, 0) + 1
                by_severity[sev]  = by_severity.get(sev, 0) + 1
            return {
                "total_iocs": len(self._ip_set),
                "by_category": by_category,
                "by_severity": by_severity,
                "last_updated": datetime.fromtimestamp(self._last_update).isoformat() if self._last_update else None,
            }

    # ── Feed Refresh ───────────────────────────────────────────────────────────

    def refresh_feeds(self):
        """Download and import external IOC feeds (run in background thread)."""
        logger.info("Threat Intel: refreshing IOC feeds...")
        total_new = 0

        # Feodo Tracker (botnet C2 IPs)
        total_new += self._import_plaintext_feed(
            FEODO_TRACKER_URL, category="c2_botnet", severity="critical", source="feodo_tracker"
        )

        # Emerging Threats compromised IPs
        total_new += self._import_plaintext_feed(
            EMERGING_THREATS_URL, category="compromised", severity="high", source="emerging_threats"
        )

        self._last_update = time.time()
        self._load_into_memory()
        logger.info(f"Threat Intel: feed refresh complete. {total_new} new IOCs added.")

    def start_auto_refresh(self):
        """Start a background thread that refreshes feeds periodically."""
        def _refresh_loop():
            time.sleep(30)  # wait 30s after startup before first refresh
            while True:
                try:
                    self.refresh_feeds()
                except Exception as e:
                    logger.warning(f"Threat Intel refresh error: {e}")
                time.sleep(UPDATE_INTERVAL_HOURS * 3600)

        t = threading.Thread(target=_refresh_loop, daemon=True, name="ThreatIntelRefresh")
        t.start()
        logger.info("Threat Intel: auto-refresh started")

    def _import_plaintext_feed(self, url: str, category: str, severity: str, source: str) -> int:
        """Fetch a plain-text IP list feed and import into DB. Returns count of new entries."""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetGuard-NDR/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
        except Exception as e:
            logger.warning(f"Feed fetch failed [{source}]: {e}")
            return 0

        conn = sqlite3.connect(INTEL_DB, check_same_thread=False)
        now = datetime.now().isoformat()
        count = 0

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Extract IP (handle lines like "1.2.3.4 # comment" or plain IPs)
            ip = line.split()[0].split("#")[0].strip()
            try:
                ipaddress.ip_address(ip)   # validate
                cursor = conn.execute(
                    "INSERT OR IGNORE INTO threat_intel (ip, category, severity, source, added_at) VALUES (?,?,?,?,?)",
                    (ip, category, severity, source, now)
                )
                if cursor.rowcount > 0:
                    count += 1
            except ValueError:
                pass

        conn.commit()
        conn.close()
        logger.info(f"Threat Intel: imported {count} new IOCs from {source}")
        return count


# ─── Module Singleton ──────────────────────────────────────────────────────────
threat_intel = ThreatIntelEngine()

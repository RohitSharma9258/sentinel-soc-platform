"""
Smart WiFi Intruder Detection System - Database Layer
SQLite database manager with robust status tracking and subnet isolation.
"""

import sqlite3
import logging
import threading
import json
import os
from datetime import datetime, timedelta
from config import DB_PATH
from network_context import net_ctx

logger = logging.getLogger("database")

class Database:
    """Thread-safe SQLite database manager."""

    _local = threading.local()

    def __init__(self):
        # Ensure data directory exists
        db_dir = os.path.dirname(DB_PATH)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        self._init_db()

    def _get_conn(self):
        """Get a thread-local database connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    def _init_db(self):
        """Initialize SQLite database with required tables and perform migrations."""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        # 0. Migration: Check if blocked_devices has the old UNIQUE(ip) constraint
        try:
            schema_info = cursor.execute("PRAGMA table_info(blocked_devices)").fetchall()
            if schema_info:
                # If table exists, check if we need to migrate it to remove UNIQUE(ip)
                # SQLite doesn't allow dropping constraints, so we recreate if needed
                create_sql = cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='blocked_devices'").fetchone()[0]
                if "UNIQUE" in create_sql.upper():
                    logger.info("Database Migration: Recreating blocked_devices table to remove restrictive constraints...")
                    cursor.execute("ALTER TABLE blocked_devices RENAME TO blocked_devices_old")
                    cursor.execute("""
                        CREATE TABLE blocked_devices (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ip TEXT NOT NULL,
                            mac TEXT,
                            reason TEXT,
                            blocked_at TEXT NOT NULL,
                            unblocked_at TEXT,
                            is_active INTEGER DEFAULT 1,
                            block_method TEXT DEFAULT 'firewall'
                        )
                    """)
                    cursor.execute("INSERT INTO blocked_devices SELECT * FROM blocked_devices_old")
                    cursor.execute("DROP TABLE blocked_devices_old")
                    logger.info("Database Migration: Complete.")
        except Exception as e:
            logger.debug(f"Migration check skipped: {e}")

        # Devices table - Store device metadata and last seen info
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                mac TEXT NOT NULL,
                hostname TEXT DEFAULT 'Unknown',
                vendor TEXT DEFAULT 'Unknown',
                is_online INTEGER DEFAULT 1,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                device_type TEXT DEFAULT 'unknown',
                threat_level TEXT DEFAULT 'none',
                threat_score INTEGER DEFAULT 0,
                trust_score INTEGER DEFAULT 100,
                is_known INTEGER DEFAULT 0,
                notes TEXT DEFAULT '',
                UNIQUE(mac)
            )
        """)

        # Ensure all columns exist for older databases (Migrations)
        columns = [
            ("device_type", "TEXT DEFAULT 'unknown'"),
            ("threat_level", "TEXT DEFAULT 'none'"),
            ("threat_score", "INTEGER DEFAULT 0"),
            ("trust_score", "INTEGER DEFAULT 100"),
            ("is_known", "INTEGER DEFAULT 0"),
            ("notes", "TEXT DEFAULT ''"),
            ("is_online", "INTEGER DEFAULT 1")
        ]
        
        for col_name, col_def in columns:
            try:
                cursor.execute(f"ALTER TABLE devices ADD COLUMN {col_name} {col_def}")
            except sqlite3.OperationalError:
                pass # Column already exists

        # Migration for logs table
        try:
            cursor.execute("ALTER TABLE logs ADD COLUMN is_audit INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass

        # Migration for blocked_devices table (ensure unblocked_at exists)
        try:
            cursor.execute("ALTER TABLE blocked_devices ADD COLUMN unblocked_at TEXT")
        except sqlite3.OperationalError:
            pass

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                ip TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(mac, ip)
            )
        """)

        # Threats table - Record security events
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_mac TEXT NOT NULL,
                device_ip TEXT,
                threat_type TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                threat_score INTEGER DEFAULT 0,
                description TEXT,
                details TEXT,
                detected_at TEXT NOT NULL,
                resolved INTEGER DEFAULT 0,
                resolved_at TEXT,
                auto_blocked INTEGER DEFAULT 0
            )
        """)

        # Blocked devices table - Optimized for historical audits
        # Removed UNIQUE constraints that cause failures during state transitions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                mac TEXT,
                reason TEXT,
                blocked_at TEXT NOT NULL,
                unblocked_at TEXT,
                is_active INTEGER DEFAULT 1,
                block_method TEXT DEFAULT 'firewall'
            )
        """)
        
        # Ensure correct indices for performance
        try:
            # Deduplicate blocked_devices by IP before applying UNIQUE index
            # We keep the most recent block entry for each IP
            cursor.execute("""
                DELETE FROM blocked_devices 
                WHERE id NOT IN (
                    SELECT MAX(id) FROM blocked_devices GROUP BY ip
                )
            """)
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_blocked_ip_unique ON blocked_devices(ip)")
        except Exception as e:
            logger.warning(f"Could not create unique index on blocked_devices: {e}. Falling back to non-unique index.")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ip_non_unique ON blocked_devices(ip)")
            
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_active ON blocked_devices(is_active)")

        # Logs table - System-wide internal logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                module TEXT,
                message TEXT NOT NULL,
                details TEXT,
                is_audit INTEGER DEFAULT 0
            )
        """)

        # Known devices table - Trusted devices list
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS known_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL UNIQUE,
                name TEXT,
                device_type TEXT,
                added_at TEXT NOT NULL,
                notes TEXT DEFAULT ''
            )
        """)

        # Settings table - Persistent system configuration
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        # NDR: OS Fingerprint columns (Phase 2 migration)
        ndr_columns = [
            ("os_type",          "TEXT DEFAULT 'Unknown'"),
            ("os_confidence",     "INTEGER DEFAULT 0"),
            ("device_class",      "TEXT DEFAULT 'unknown'"),
            ("is_randomized_mac", "INTEGER DEFAULT 0"),
            ("vendor_risk",       "TEXT DEFAULT 'medium'"),
        ]
        for col_name, col_def in ndr_columns:
            try:
                cursor.execute(f"ALTER TABLE devices ADD COLUMN {col_name} {col_def}")
            except sqlite3.OperationalError:
                pass  # Column already exists

        # NDR: Traffic history table (Phase 5)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS traffic_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                src_ip      TEXT,
                dst_ip      TEXT,
                protocol    TEXT,
                packets     INTEGER DEFAULT 1,
                bytes       INTEGER DEFAULT 0,
                hour_bucket TEXT    -- 'YYYY-MM-DD HH:00' for aggregation
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_th_hour ON traffic_history(hour_bucket)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_th_src  ON traffic_history(src_ip)")
        
        conn.commit()
        logger.info("Database initialized successfully (startup cleanup deferred).")

    # ═══════════════════════════════════════════════════════════════════════
    #  DEVICE OPERATIONS
    # ═══════════════════════════════════════════════════════════════════════

    def upsert_device(self, ip, mac, hostname="Unknown", vendor="Unknown", **kwargs):
        """Insert or update a device seen in the network."""
        conn = self._get_conn()
        now = datetime.now().isoformat()
        mac = mac.upper()
        try:
            conn.execute("""
                INSERT INTO devices (ip, mac, hostname, vendor, is_online, first_seen, last_seen)
                VALUES (?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    ip = excluded.ip,
                    hostname = CASE WHEN excluded.hostname != 'Unknown' THEN excluded.hostname ELSE devices.hostname END,
                    vendor = CASE WHEN excluded.vendor != 'Unknown' THEN excluded.vendor ELSE devices.vendor END,
                    is_online = 1,
                    last_seen = excluded.last_seen
            """, (ip, mac, hostname, vendor, now, now))
            
            # Auto-sync 'is_known' status
            is_known = self.is_known(mac)
            if is_known:
                conn.execute("UPDATE devices SET is_known = 1 WHERE mac = ?", (mac,))

            # Record IP history
            conn.execute("""
                INSERT INTO ip_history (mac, ip, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(mac, ip) DO UPDATE SET last_seen = excluded.last_seen
            """, (mac, ip, now, now))
            
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to upsert device {mac}: {e}")
            return False

    def get_all_devices(self, filter_subnet=True):
        """
        ENHANCED: Get all devices with ANTIGRAVITY-aware status calculation.
        
        Status Windows (FIXED for stability & phone offline bug):
        - Online: seen < 2 minutes ago (120s) - Active device
        - Idle: seen < 10 minutes ago (600s) - Connected but silent
        - Offline: seen > 30 minutes (1800s) for known, 10 min for unknown
        
        KEY FIX: Known devices (like your phone) stay IDLE much longer!
        """
        conn = self._get_conn()
        prefix = ".".join(net_ctx.network_cidr.split(".")[:3]) + "." if filter_subnet else ""
        
        query = "SELECT * FROM devices"
        params = []
        if filter_subnet:
            query += " WHERE ip LIKE ?"
            params.append(f"{prefix}%")
        query += " ORDER BY last_seen DESC"
        
        rows = conn.execute(query, params).fetchall()
        devices = []
        now = datetime.now()
        
        from utils import get_default_gateway
        gateway_ip = get_default_gateway()
        
        for r in rows:
            d = dict(r)
            try:
                last_seen = datetime.fromisoformat(d["last_seen"])
                diff = (now - last_seen).total_seconds()
                is_known = d.get("is_known", 0) == 1
                is_gateway = (d["ip"] == gateway_ip)
                
                # 🛡️ ANTIGRAVITY STATUS LOGIC
                if is_gateway:
                    # Gateway ALWAYS shows online
                    d["status"] = "online"
                    d["is_online"] = 1
                    d["threat_level"] = "none"
                    d["threat_score"] = 0
                elif diff <= 120:  # 2 minutes
                    # Recently seen in ARP/Sniffer = ONLINE
                    d["status"] = "online"
                    d["is_online"] = 1
                elif diff <= 600:  # 10 minutes
                    # Within 10 min = IDLE (still online!)
                    d["status"] = "idle"
                    d["is_online"] = 1
                elif is_known and diff <= 1800:  # 30 minutes for known/trusted devices
                    # YOUR PHONE FIX: Known devices stay idle for 30 min!
                    d["status"] = "idle"
                    d["is_online"] = 1
                    logger.debug(f"Device {d['ip']} kept online (known device, {int(diff)}s old)")
                else:
                    # Really gone
                    d["status"] = "offline"
                    d["is_online"] = 0
            except (ValueError, TypeError):
                d["status"] = "unknown"
                d["is_online"] = 0
            
            devices.append(d)
        return devices

    def cleanup_stale_devices(self, threshold_seconds=3600):
        """
        Cleanup database: 
        Step 1: Remove devices from other subnets.
        Step 2: Remove offline unknown devices older than threshold.
        """
        conn = self._get_conn()
        try:
            # Step 1: Detect current subnet and delete foreign devices
            cidr = net_ctx.network_cidr
            prefix = ".".join(cidr.split(".")[:3]) + "."
            
            cursor = conn.execute("DELETE FROM devices WHERE ip NOT LIKE ?", (f"{prefix}%",))
            deleted_subnet = cursor.rowcount
            
            # Step 2: Delete offline unknown devices after threshold
            # We keep known/trusted devices forever unless they are very old (7 days)
            cursor = conn.execute("""
                DELETE FROM devices 
                WHERE is_online = 0 
                AND is_known = 0 
                AND (strftime('%s', 'now') - strftime('%s', last_seen)) > ?
            """, (threshold_seconds,))
            deleted_stale = cursor.rowcount
            
            # Final hygiene: Delete anything not seen for 7 days
            cursor = conn.execute("DELETE FROM devices WHERE last_seen < datetime('now', '-7 days')")
            deleted_old = cursor.rowcount
            
            conn.commit()
            if deleted_subnet > 0 or deleted_stale > 0 or deleted_old > 0:
                logger.info(f"Cleanup: Removed {deleted_subnet} foreign, {deleted_stale} stale, and {deleted_old} old devices.")
            return True
        except Exception as e:
            logger.error(f"Database cleanup failed: {e}")
            return False

    def is_blocked(self, ip):
        """Check if an IP is currently blocked."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT id FROM blocked_devices WHERE ip = ? AND is_active = 1", (ip,)
        ).fetchone()
        return row is not None

    def get_device_by_mac(self, mac):
        """Get a single device by its MAC address."""
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac.upper(),)).fetchone()
        return dict(row) if row else None

    def get_device_by_ip(self, ip):
        """Get a single device by its IP address."""
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM devices WHERE ip = ?", (ip,)).fetchone()
        return dict(row) if row else None

    def get_device_by_mac_or_ip(self, mac_or_ip):
        """Get a device by either its MAC or IP address."""
        if ":" in mac_or_ip:
            return self.get_device_by_mac(mac_or_ip)
        return self.get_device_by_ip(mac_or_ip)

    def mark_offline(self, mac):
        """Explicitly mark a device as offline."""
        conn = self._get_conn()
        conn.execute("UPDATE devices SET is_online = 0 WHERE mac = ?", (mac.upper(),))
        conn.commit()

    def update_device_fingerprint(self, mac: str, os_type: str, os_confidence: int, device_class: str):
        """NDR: Update OS fingerprint data for a device."""
        conn = self._get_conn()
        try:
            conn.execute("""
                UPDATE devices
                SET os_type = ?, os_confidence = ?, device_class = ?
                WHERE mac = ?
            """, (os_type, os_confidence, device_class, mac.upper()))
            conn.commit()
        except Exception as e:
            logger.debug(f"update_device_fingerprint failed: {e}")

    def get_stats(self):
        """Get highly accurate system statistics for the current network session."""
        # 1. Focus only on current subnet devices
        devices = self.get_all_devices(filter_subnet=True)
        
        # 2. Precise state counting
        online_count = sum(1 for d in devices if d["status"] == "online")
        idle_count = sum(1 for d in devices if d["status"] == "idle")
        
        # 3. Security state counting
        blocked = self.get_blocked_devices()
        known = self.get_known_devices()
        
        # Active threats (unresolved in current subnet)
        threats = self.get_active_threats(filter_subnet=True)
        
        return {
            "total_devices": len(devices),
            "online_devices": online_count,
            "idle_devices": idle_count,
            "active_threats": len(threats),
            "blocked_devices": len(blocked),
            "known_devices": len(known),
            "unknown_devices": len(devices) - sum(1 for d in devices if d["is_known"]),
            "critical_threats": sum(1 for t in threats if t["threat_level"] == "critical"),
            "current_subnet": net_ctx.network_cidr
        }

    # ═══════════════════════════════════════════════════════════════════════
    #  THREAT OPERATIONS
    # ═══════════════════════════════════════════════════════════════════════

    def add_threat(self, device_mac, device_ip, threat_type, threat_level,
                   threat_score, description, details=None, auto_blocked=0):
        conn = self._get_conn()
        now = datetime.now().isoformat()
        try:
            cursor = conn.execute("""
                INSERT INTO threats (device_mac, device_ip, threat_type, threat_level,
                                     threat_score, description, details, detected_at, auto_blocked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (device_mac.upper(), device_ip, threat_type, threat_level,
                  threat_score, description, json.dumps(details) if details else None, now, auto_blocked))
            
            # Update device summary
            conn.execute(
                "UPDATE devices SET threat_level = ?, threat_score = ? WHERE mac = ?",
                (threat_level, threat_score, device_mac.upper())
            )
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to add threat: {e}")
            return None

    def update_threat_auto_blocked(self, threat_id):
        """Update threat status to auto-blocked in database."""
        conn = self._get_conn()
        try:
            conn.execute("UPDATE threats SET auto_blocked = 1 WHERE id = ?", (threat_id,))
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to update auto_blocked for threat {threat_id}: {e}")
            return False

    def update_trust_score(self, mac, delta):
        """Update device trust score, keeping it between 0 and 100."""
        conn = self._get_conn()
        mac = mac.upper()
        try:
            row = conn.execute("SELECT trust_score FROM devices WHERE mac = ?", (mac,)).fetchone()
            if row:
                current_score = row["trust_score"]
                new_score = max(0, min(100, current_score + delta))
                conn.execute("UPDATE devices SET trust_score = ? WHERE mac = ?", (new_score, mac))
                conn.commit()
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to update trust score for {mac}: {e}")
            return False

    def get_threat_count_by_mac(self, mac, window_seconds=3600):
        """Get number of threats recorded for a MAC address in a specific window (default: 1 hour)."""
        conn = self._get_conn()
        try:
            row = conn.execute("""
                SELECT COUNT(*) as count FROM threats 
                WHERE device_mac = ? 
                AND detected_at > datetime('now', '-' || ? || ' seconds')
            """, (mac.upper(), window_seconds)).fetchone()
            return row["count"] if row else 0
        except Exception as e:
            logger.error(f"Failed to get threat count: {e}")
            return 0

    def get_all_threats(self, filter_subnet=True):
        conn = self._get_conn()
        query = "SELECT * FROM threats"
        params = []
        if filter_subnet:
            prefix = ".".join(net_ctx.network_cidr.split(".")[:3]) + "."
            query += " WHERE device_ip LIKE ?"
            params.append(f"{prefix}%")
        query += " ORDER BY detected_at DESC"
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_active_threats(self, filter_subnet=True):
        conn = self._get_conn()
        query = "SELECT * FROM threats WHERE resolved = 0"
        params = []
        if filter_subnet:
            prefix = ".".join(net_ctx.network_cidr.split(".")[:3]) + "."
            query += " AND device_ip LIKE ?"
            params.append(f"{prefix}%")
        query += " ORDER BY detected_at DESC"
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def resolve_threat(self, threat_id):
        conn = self._get_conn()
        now = datetime.now().isoformat()
        conn.execute("UPDATE threats SET resolved = 1, resolved_at = ? WHERE id = ?", (now, threat_id))
        conn.commit()

    # ═══════════════════════════════════════════════════════════════════════
    #  BLOCK & LOG OPERATIONS
    # ═══════════════════════════════════════════════════════════════════════

    def add_blocked_device(self, ip, mac=None, reason="Manual block", method="firewall"):
        """
        Record a device block with robust UPSERT logic.
        Ensures only one record per IP exists, toggling is_active and updating history.
        """
        conn = self._get_conn()
        now = datetime.now().isoformat()
        try:
            # 1. Check if an active block already exists to avoid duplicate logs
            existing = conn.execute(
                "SELECT id, is_active FROM blocked_devices WHERE ip = ?", (ip,)
            ).fetchone()
            
            if existing and existing["is_active"] == 1:
                logger.info(f"IP {ip} is already actively blocked. Updating details.")
            
            # 2. Robust UPSERT: If IP exists, update it to active and refresh reason/time.
            # This handles "reactivate if inactive" and "don't insert duplicate if active" automatically.
            conn.execute("""
                INSERT INTO blocked_devices (ip, mac, reason, blocked_at, is_active, block_method, unblocked_at)
                VALUES (?, ?, ?, ?, 1, ?, NULL)
                ON CONFLICT(ip) DO UPDATE SET
                    mac = COALESCE(excluded.mac, blocked_devices.mac),
                    reason = excluded.reason,
                    blocked_at = excluded.blocked_at,
                    is_active = 1,
                    block_method = excluded.block_method,
                    unblocked_at = NULL
            """, (ip, mac.upper() if mac else None, reason, now, method))
            
            conn.commit()
            
            # 3. Only log if it's a NEW block or reactivation of an inactive one
            if not existing or existing["is_active"] == 0:
                self.add_log("CRITICAL", "audit", f"AUDIT: Device BLOCKED - IP: {ip} ({mac}) - Reason: {reason}", is_audit=1)
            
            return True
        except Exception as e:
            logger.error(f"Failed to record block for {ip}: {e}")
            return False

    def remove_blocked_device(self, ip):
        """
        Unblock a device by setting is_active=0.
        FIXED: Uses atomic UPDATE with rollback and cleaned duplicate handling.
        """
        conn = self._get_conn()
        try:
            # 1. Clean any duplicate active rows first (safety)
            conn.execute("UPDATE blocked_devices SET is_active = 0 WHERE ip = ? AND is_active = 1", (ip,))
            
            # 2. Set unblocked timestamp for the record just deactivated
            conn.execute("""
                UPDATE blocked_devices 
                SET unblocked_at = CURRENT_TIMESTAMP 
                WHERE ip = ? AND is_active = 0 AND unblocked_at IS NULL
            """, (ip,))
            
            conn.commit()
            self.add_log("INFO", "audit", f"AUDIT: Device UNBLOCKED - IP: {ip}", is_audit=1)
            return {"success": True, "message": f"Device {ip} unblocked successfully."}
        except Exception as e:
            conn.rollback()
            logger.error(f"Unblock database failure for {ip}: {e}")
            return {"success": False, "error": "db_update_failed", "message": str(e)}

    def startup_cleanup(self):
        """
        Comprehensive cleanup of database on app startup.
        Removes stale devices, invalid MACs, and fixes duplicate blocked records.
        """
        if not net_ctx.is_initialized:
            logger.error("Database startup cleanup aborted: NetworkContext is uninitialized!")
            raise RuntimeError("Cannot execute database startup cleanup when NetworkContext is uninitialized.")

        logger.info("Performing database maintenance and stale device cleanup...")
        conn = self._get_conn()
        try:
            # 1. Remove invalid MAC records
            conn.execute("DELETE FROM devices WHERE mac = '00:00:00:00:00:00' OR mac IS NULL OR mac = ''")
            
            # 2. Deactivate duplicate active blocked records (keep newest only)
            conn.execute("""
                UPDATE blocked_devices 
                SET is_active = 0 
                WHERE id NOT IN (
                    SELECT MAX(id) FROM blocked_devices GROUP BY ip
                ) AND is_active = 1
            """)
            
            # 3. Purge foreign subnet devices (if not in current /24)
            prefix = ".".join(net_ctx.network_cidr.split(".")[:3]) + "."
            conn.execute("DELETE FROM devices WHERE ip NOT LIKE ?", (f"{prefix}%",))
            
            # 4. Mark all as offline on start (let scanner refresh)
            conn.execute("UPDATE devices SET is_online = 0")
            
            # 5. Clean stale logs older than 7 days
            conn.execute("DELETE FROM logs WHERE timestamp < datetime('now', '-7 days')")
            
            conn.commit()
            self.purge_critical_blocks()
            logger.info("Database maintenance complete.")
        except Exception as e:
            conn.rollback()
            logger.error(f"Startup cleanup failed: {e}")

    def purge_critical_blocks(self):
        """Safety: Automatically remove any blocks on Gateway or Localhost using NetworkContext."""
        critical_ips = ["127.0.0.1", "0.0.0.0", net_ctx.local_ip, net_ctx.gateway_ip]
        conn = self._get_conn()
        for ip in critical_ips:
            conn.execute("DELETE FROM blocked_devices WHERE ip = ?", (ip,))
        conn.commit()

    def get_active_blocks(self):
        """Get all currently active blocked devices."""
        conn = self._get_conn()
        rows = conn.execute("SELECT ip, mac, reason FROM blocked_devices WHERE is_active = 1").fetchall()
        return [dict(r) for r in rows]

    def get_blocked_devices(self):
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM blocked_devices WHERE is_active = 1 ORDER BY blocked_at DESC").fetchall()
        return [dict(r) for r in rows]

    def add_log(self, level, module, message, details=None, is_audit=0):
        """Add a system log entry with optional audit flag."""
        conn = self._get_conn()
        now = datetime.now().isoformat()
        try:
            conn.execute(
                "INSERT INTO logs (timestamp, level, module, message, details, is_audit) VALUES (?, ?, ?, ?, ?, ?)",
                (now, level.upper(), module, message, json.dumps(details) if details else None, is_audit)
            )
            conn.commit()
        except Exception as e:
            logger.error(f"Failed to add log: {e}")

    def log_antigravity_action(self, action, target_ip, target_mac, reason):
        """Log all ANTIGRAVITY exemptions and suppressions with audit level."""
        self.add_log(
            "WARNING",
            "antigravity",
            f"[ANTIGRAVITY] {action}: IP={target_ip}, MAC={target_mac}, Reason={reason}",
            is_audit=1
        )

    def get_logs(self, limit=200, level=None, module=None, is_audit=False):
        """Get system logs with optional audit filtering."""
        conn = self._get_conn()
        query = "SELECT * FROM logs WHERE 1=1"
        params = []
        if level: 
            query += " AND level = ?"
            params.append(level)
        if module: 
            query += " AND module = ?"
            params.append(module)
        if is_audit:
            query += " AND is_audit = 1"
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in conn.execute(query, params).fetchall()]

    # ═══════════════════════════════════════════════════════════════════════
    #  KNOWN DEVICES
    # ═══════════════════════════════════════════════════════════════════════

    def add_known_device(self, mac, name="My Device", device_type="personal", notes=""):
        conn = self._get_conn()
        now = datetime.now().isoformat()
        mac = mac.upper()
        try:
            conn.execute("INSERT OR REPLACE INTO known_devices (mac, name, device_type, added_at, notes) VALUES (?, ?, ?, ?, ?)",
                        (mac, name, device_type, now, notes))
            conn.execute("UPDATE devices SET is_known = 1, threat_level = 'none', threat_score = 0 WHERE mac = ?", (mac,))
            conn.commit()
            return True
        except Exception: return False

    def remove_known_device(self, mac):
        conn = self._get_conn()
        conn.execute("DELETE FROM known_devices WHERE mac = ?", (mac.upper(),))
        conn.execute("UPDATE devices SET is_known = 0 WHERE mac = ?", (mac.upper(),))
        conn.commit()

    def get_known_devices(self):
        rows = self._get_conn().execute("SELECT * FROM known_devices ORDER BY added_at DESC").fetchall()
        return [dict(r) for r in rows]

    def is_known(self, mac_or_ip):
        """Check if device is known by MAC OR IP."""
        conn = self._get_conn()
        
        # Check by MAC
        mac_row = conn.execute(
            "SELECT id FROM known_devices WHERE mac = ?", 
            (mac_or_ip.upper() if ':' in mac_or_ip else mac_or_ip,)
        ).fetchone()
        
        if mac_row: return True
        
        # Check by IP (fallback for DHCP scenarios)
        device = self.get_device_by_ip(mac_or_ip)
        if device and device.get("is_known"):
            return True
        
        return False



    def sync_sniffer_devices(self):
        """Sync devices detected by packet sniffer - keeps phone online even if not in ARP."""
        try:
            from packet_sniffer import sniffer
            packets = sniffer._packets
            
            now = datetime.now().isoformat()
            synced = 0
            
            for pkt in packets[-100:]:
                src_ip = pkt.get("src_ip", "")
                src_mac = pkt.get("src_mac", "")
                
                if not src_ip or not src_mac or src_ip == "Unknown":
                    continue
                
                existing = self.get_device_by_mac(src_mac)
                if existing:
                    # Update last_seen - packet detection counts as online!
                    conn = self._get_conn()
                    conn.execute(
                        "UPDATE devices SET last_seen = ?, is_online = 1 WHERE mac = ?",
                        (now, src_mac)
                    )
                    conn.commit()
                    synced += 1
            
            if synced > 0:
                logger.debug(f"✅ Synced {synced} devices from packet sniffer")
        except Exception as e:
            logger.debug(f"Sniffer sync failed: {e}")

    # ═══════════════════════════════════════════════════════════════════════
    #  ANTIGRAVITY PERSISTENCE
    # ═══════════════════════════════════════════════════════════════════════

    def save_antigravity_state(self, enabled):
        """Persist the ANTIGRAVITY protocol state."""
        conn = self._get_conn()
        try:
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('antigravity_mode', ?)", 
                        ("1" if enabled else "0",))
            conn.commit()
        except Exception as e:
            logger.error(f"Failed to save antigravity state: {e}")

    def load_antigravity_state(self):
        """Load the ANTIGRAVITY protocol state."""
        try:
            row = self._get_conn().execute("SELECT value FROM settings WHERE key = 'antigravity_mode'").fetchone()
            if row:
                return row["value"] == "1"
        except Exception: pass
        return True # Default to True

# Module-level singleton
db = Database()

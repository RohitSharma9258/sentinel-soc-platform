"""
Smart WiFi Intruder Detection System - Real Blocking Engine
Performs ACTUAL blocking using OS firewall rules and gateway isolation (ARP poisoning).
"""

import logging
import subprocess
import platform
import ipaddress
import threading
import time
from scapy.all import ARP, Ether, sendp, send, srp, get_if_hwaddr, get_if_addr, conf
# ARCH: Added IS_MACOS and net_ctx imports
from config import IS_WINDOWS, IS_LINUX, IS_MACOS
from database import db
from utils import get_local_ip, validate_ip, get_local_mac, is_critical_infrastructure, get_default_gateway
from network_context import net_ctx

# Configure logging
logger = logging.getLogger("blocker")

class Blocker:
    """
    Real network blocker using OS firewall and ARP poisoning.
    Maintains state for active isolation threads.
    """

    CRITICAL_INFRASTRUCTURE = {
        "127.0.0.1",      # Localhost
        "0.0.0.0",        # Broadcast
        "255.255.255.255" # Broadcast
    }

    def __init__(self):
        self._os = platform.system()
        self._active_isolation = {}  # Map: IP -> threading.Event (stop_event)
        self._lock = threading.Lock()
        self._last_action_time = {}   # Rate limiting: IP -> timestamp
        self._unblock_cooldown = {}   # IP -> timestamp: prevents auto-reblock after manual unblock
        # ARCH: Cache gateway IP from NetworkContext (deferred initialization to avoid import-time resolution)
        self._gateway_ip_cache = None
        self._gateway_last_validated = 0
        self._started = False
        logger.info(f"Blocker initialized for {self._os}")

    def _validate_gateway_periodically(self):
        """Ensure cached gateway is still valid (every 5 minutes)."""
        # ARCH: Check gateway changes using net_ctx
        if self._gateway_ip_cache is None or time.time() - self._gateway_last_validated > 300:
            current_gateway = net_ctx.gateway_ip
            if self._gateway_ip_cache is not None and current_gateway != self._gateway_ip_cache:
                logger.critical(f"ANTIGRAVITY: Gateway changed detected: {self._gateway_ip_cache} → {current_gateway}")
            self._gateway_ip_cache = current_gateway
            self._gateway_last_validated = time.time()

    def is_gravity_exempt(self, ip):
        """Single authoritative check for ANTIGRAVITY exemption."""
        
        # 1. Permanent critical infrastructure
        if ip in self.CRITICAL_INFRASTRUCTURE:
            return True
        
        # 2. Gateway (cached)
        # ARCH: Check using NetworkContext gateway_ip
        if ip == net_ctx.gateway_ip:
            return True
        
        # 3. Local machine
        # ARCH: Check using NetworkContext local_ip
        if ip == net_ctx.local_ip:
            return True
        
        # 4. Known/trusted device
        device = db.get_device_by_mac_or_ip(ip)
        if device and db.is_known(device.get("mac", "")):
            return True
        
        return False

    def is_in_unblock_cooldown(self, ip):
        """Check if an IP is in manual-unblock cooldown (5 min window)."""
        if ip in self._unblock_cooldown:
            elapsed = time.time() - self._unblock_cooldown[ip]
            if elapsed < 300:  # 5 minutes
                return True
            else:
                del self._unblock_cooldown[ip]
        return False

    def block_ip(self, ip, reason="Manual block"):
        """
        Block a device using both firewall rules and gateway isolation.
        """
        if self.is_gravity_exempt(ip):
            logger.warning(f"ANTIGRAVITY BYPASS: Block request for {ip} ignored (Critical Service)")
            db.add_log("WARNING", "blocker", f"ANTIGRAVITY EXEMPTION: Refused to block critical IP {ip}", is_audit=1)
            return {"success": False, "message": "Device is protected by ANTIGRAVITY protocol."}

        if not validate_ip(ip):
            return {"success": False, "message": f"Invalid IP address: {ip}"}

        # 1. Protection: Never block Gateway or Localhost
        if is_critical_infrastructure(ip):
            db.add_log("WARNING", "audit", f"AUDIT: Block REJECTED for critical infrastructure - IP: {ip}", is_audit=1)
            return {"success": False, "message": "Cannot block critical infrastructure (Gateway/Localhost)"}

        # 2. Rate Limiting: Prevent rapid block/unblock cycles (5s cooldown)
        self._validate_gateway_periodically()
        now = time.time()
        if ip in self._last_action_time and now - self._last_action_time[ip] < 5:
            return {"success": False, "message": "Action too frequent. Please wait 5 seconds."}
        self._last_action_time[ip] = now

        logger.info(f"Initiating robust blocking for {ip} - Reason: {reason}")
        
        try:
            # ARCH: Fetch gateway from NetworkContext
            gateway_ip = net_ctx.gateway_ip
            
            # 1. Apply Firewall Rules (First layer of defense)
            fw_success = False
            # ARCH: OS routing with macOS support
            if IS_WINDOWS:
                fw_success = self._block_windows(ip)
            elif IS_LINUX:
                fw_success = self._block_linux(ip)
            elif IS_MACOS:
                fw_success = self._block_macos(ip)
            
            if not fw_success:
                logger.warning(f"Firewall blocking might have failed for {ip}")

            # 2. Start Gateway Isolation (ARP Poisoning - Second layer)
            isolation_success = self.isolate_device(ip, gateway_ip)
            
            # 3. Verify Block Status
            is_blocked = self.verify_block(ip)
            
            # Update database with robust tracking
            device = db.get_device_by_ip(ip)
            mac = device["mac"] if device else None
            db_success = db.add_blocked_device(ip, mac, reason, method="hybrid_enforcement")
            
            if (isolation_success or fw_success) and db_success:
                msg = f"Device {ip} blocked successfully."
                if not fw_success: msg += " (Isolation only)"
                return {"success": True, "message": msg}
            elif not db_success:
                return {"success": False, "message": f"Network rules applied but failed to update database for {ip}"}
            else:
                return {"success": False, "message": f"Failed to apply any blocking method for {ip}"}

        except Exception as e:
            logger.exception(f"Block operation failed for {ip}: {e}")
            return {"success": False, "message": f"Error during blocking: {str(e)}"}

    def unblock_ip(self, ip):
        """
        Unblock a device: stop ARP poisoning, remove firewall rules, and update DB.
        """
        if not validate_ip(ip):
            return {"success": False, "message": f"Invalid IP address: {ip}"}

        logger.info(f"Initiating full unblock for {ip}")
        
        try:
            # 1. Stop ARP Poisoning Isolation
            isolation_stopped = self.stop_isolation(ip)
            
            # 2. Remove Firewall Rules
            fw_removed = False
            # ARCH: Support macOS pf firewall in unblock_ip
            if IS_WINDOWS:
                fw_removed = self._unblock_windows(ip)
            elif IS_LINUX:
                fw_removed = self._unblock_linux(ip)
            elif IS_MACOS:
                fw_removed = self._unblock_macos(ip)

            # 3. Verify Firewall Removal
            time.sleep(0.5) # Give OS a moment to update
            still_blocked = self.verify_block(ip)
            
            if still_blocked:
                logger.error(f"Firewall removal failed for {ip}. Rule still detected.")
                fw_removed = False

            # 4. Update Database State
            # FIX: remove_blocked_device returns a dict, check its 'success' key
            db_result = db.remove_blocked_device(ip)
            db_success = db_result.get("success", False) if isinstance(db_result, dict) else bool(db_result)
            
            # SUCCESS LOGIC: 
            # - DB update must succeed.
            # - Firewall removal is a success even if rule was already gone (still_blocked is false).
            if db_success:
                # 5. Set unblock cooldown to prevent auto-reblock for 5 minutes
                self._unblock_cooldown[ip] = time.time()
                logger.info(f"Unblock cooldown set for {ip} (5 min anti-reblock)")
                
                status_msg = f"Device {ip} unblocked successfully."
                if still_blocked:
                    status_msg += " (Warning: Firewall rule persisted)"
                
                return {
                    "success": True, 
                    "message": status_msg,
                    "details": {
                        "isolation_stopped": isolation_stopped,
                        "firewall_removed": fw_removed or not still_blocked,
                        "db_updated": True,
                        "firewall_status": "Rule still active" if still_blocked else "Clean"
                    }
                }
            else:
                return {
                    "success": False, 
                    "message": f"Database update failed for {ip}. Firewall might have been removed.",
                    "error": "db_update_failed"
                }

        except Exception as e:
            logger.exception(f"Critical error during unblock for {ip}: {e}")
            return {"success": False, "message": f"Error during unblocking: {str(e)}"}

    def startup_recovery(self):
        """
        Recover active blocks from the database on system startup.
        ENHANCED: Filters for current subnet and prevents critical infrastructure blocking.
        """
        if not net_ctx.is_initialized:
            logger.error("Startup recovery aborted: NetworkContext is uninitialized!")
            raise RuntimeError("Cannot run startup recovery when NetworkContext is uninitialized.")

        logger.info("Running startup block recovery watchdog...")
        try:
            active_blocks = db.get_active_blocks()
            if not active_blocks:
                logger.info("No active blocks to recover.")
                return

            # ARCH: Fetch gateway from NetworkContext
            gateway_ip = net_ctx.gateway_ip
            # ARCH: Fetch network CIDR from NetworkContext
            current_cidr = net_ctx.network_cidr
            subnet_prefix = ".".join(current_cidr.split(".")[:3]) + "."

            recovered_count = 0
            skipped_count = 0

            for block in active_blocks:
                ip = block["ip"]
                
                # 1. Safety: Prevent recovery of critical infrastructure
                if is_critical_infrastructure(ip):
                    logger.warning(f"Watchdog: Deactivating accidental block on critical IP: {ip}")
                    db.remove_blocked_device(ip)
                    continue

                # 2. Subnet Filtering: Only restore if in current subnet
                if not ip.startswith(subnet_prefix):
                    logger.info(f"Watchdog: Skipping recovery of foreign subnet block (preserved in DB): {ip}")
                    skipped_count += 1
                    continue
                
                logger.info(f"Recovering active block for {ip}...")
                
                # Apply firewall
                # ARCH: Restore rules for OS with macOS support
                fw_success = False
                if IS_WINDOWS: fw_success = self._block_windows(ip)
                elif IS_LINUX: fw_success = self._block_linux(ip)
                elif IS_MACOS: fw_success = self._block_macos(ip)
                
                # Apply isolation
                iso_success = self.isolate_device(ip, gateway_ip)
                
                if fw_success or iso_success:
                    recovered_count += 1
                else:
                    logger.error(f"Watchdog: Failed to recover block for {ip}")
                
            db.add_log(
                "INFO",
                "system",
                f"Startup recovery complete: recovered={recovered_count}, skipped_foreign={skipped_count}."
            )
        except Exception as e:
            logger.error(f"Startup recovery failed: {e}")
            raise

    # ARCH: Event Bus subscription and handler methods
    def start(self):
        """Subscribe to block/unblock events from event bus."""
        with self._lock:
            if self._started:
                return
            from event_bus import bus
            bus.subscribe("block_requested", self._handle_block_event)
            bus.subscribe("unblock_requested", self._handle_unblock_event)
            self._started = True
            logger.info("Blocker subscribed to event bus")

    def _handle_block_event(self, event_type, data):
        """Handle block_requested events from detector/AI."""
        ip = data.get("ip")
        reason = data.get("reason", "Auto-block via event bus")
        if ip:
            # Respect manual unblock cooldown: skip auto-reblock within 5 min of manual unblock
            if self.is_in_unblock_cooldown(ip):
                logger.info(f"Skipping auto-block for {ip}: within manual unblock cooldown")
                return
            result = self.block_ip(ip, reason)
            from event_bus import bus
            bus.emit("block_result", {
                "ip": ip,
                "success": result.get("success"),
                "message": result.get("message"),
            })

    def _handle_unblock_event(self, event_type, data):
        """Handle unblock_requested events."""
        ip = data.get("ip")
        if ip:
            self.unblock_ip(ip)

    # ARCH: macOS pf firewall methods
    def _block_macos(self, ip) -> bool:
        """Block IP using macOS pf firewall."""
        anchor = "com.ids.block"
        rule = f"block drop from {ip} to any\nblock drop from any to {ip}\n"
        
        try:
            import tempfile, os
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.conf', 
                delete=False, prefix='ids_block_'
            ) as f:
                f.write(rule)
                rule_file = f.name
            
            # ARCH: Safe list command avoiding shell=True injection
            result = subprocess.run(
                ["sudo", "pfctl", "-a", f"{anchor}/{ip}", "-f", rule_file],
                shell=False, capture_output=True, text=True, timeout=10
            )
            try:
                os.unlink(rule_file)
            except Exception as e:
                logger.error(f"Failed to delete temp rule file {rule_file}: {e}")
            
            # ARCH: Enable pfctl using safe list argument
            subprocess.run(
                ["sudo", "pfctl", "-e"],
                shell=False, capture_output=True, timeout=5
            )
            
            if result.returncode != 0:
                logger.error(f"pf block error: {result.stderr}")
                return False
            
            logger.info(f"macOS pf rule added for {ip}")
            return True
            
        except Exception as e:
            logger.error(f"macOS block failed for {ip}: {e}")
            return False

    def _unblock_macos(self, ip) -> bool:
        """Remove macOS pf firewall rule."""
        anchor = "com.ids.block"
        try:
            # ARCH: Safe list command avoiding shell=True injection
            result = subprocess.run(
                ["sudo", "pfctl", "-a", f"{anchor}/{ip}", "-F", "rules"],
                shell=False, capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                logger.error(f"pf unblock error: {result.stderr}")
                return False
            logger.info(f"macOS pf rule removed for {ip}")
            return True
        except Exception as e:
            logger.error(f"macOS unblock failed for {ip}: {e}")
            return False

    def _verify_block_macos(self, ip) -> bool:
        """Check if pf rule exists for IP."""
        try:
            # ARCH: Safe list command avoiding shell=True injection
            result = subprocess.run(
                ["sudo", "pfctl", "-a", f"com.ids.block/{ip}", "-s", "rules"],
                shell=False, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return ip in result.stdout
            
            output = (result.stdout or "") + (result.stderr or "")
            if "Anchor does not exist" in output or "No rules" in output:
                return False
                
            logger.warning(f"macOS pfctl query failed: Exit code: {result.returncode}, Error: {output.strip()}")
            return False
        except Exception as e:
            logger.error(f"macOS block verification failed for {ip}: {e}")
            return False

    # ═══════════════════════════════════════════════════════════════════════
    #  WINDOWS FIREWALL (netsh)
    # ═══════════════════════════════════════════════════════════════════════

    def _block_windows(self, ip):
        """Block IP using Windows Firewall with duplicate prevention."""
        rule_name = f"BLOCK_{ip}"
        
        # Check if already exists to avoid clutter
        if self.verify_block(ip):
            logger.info(f"Firewall rule for {ip} already exists. Skipping.")
            return True

        commands = [
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}_IN", "dir=in", "action=block", f"remoteip={ip}", "protocol=any", "enable=yes"],
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}_OUT", "dir=out", "action=block", f"remoteip={ip}", "protocol=any", "enable=yes"]
        ]

        success = True
        for cmd in commands:
            try:
                # ARCH: Safe list command avoiding shell=True injection
                result = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    logger.error(f"Windows Firewall error: {result.stderr.strip()}")
                    success = False
            except Exception as e:
                logger.error(f"Command execution failed: {e}")
                success = False
        return success

    def _unblock_windows(self, ip):
        """Remove Windows Firewall rules."""
        rule_name = f"BLOCK_{ip}"
        commands = [
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_IN"],
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_OUT"]
        ]
        
        success = True
        for cmd in commands:
            try:
                # ARCH: Safe list command avoiding shell=True injection
                result = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=10)
                # If rule doesn't exist, netsh returns 1 and "No rules match"
                # We treat this as success for unblocking.
                if result.returncode != 0 and "No rules match" not in result.stdout and "No rules match" not in result.stderr:
                    logger.error(f"Windows Firewall unblock error: {result.stderr.strip()}")
                    success = False
            except Exception as e:
                logger.error(f"Unblock command execution failed: {e}")
                success = False
        return success

    # ═══════════════════════════════════════════════════════════════════════
    #  LINUX FIREWALL (iptables)
    # ═══════════════════════════════════════════════════════════════════════

    def _block_linux(self, ip):
        """Block IP using Linux iptables."""
        commands = [
            ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            ["sudo", "iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"]
        ]

        success = True
        for cmd in commands:
            try:
                # ARCH: Safe list command avoiding shell=True injection
                result = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    logger.error(f"iptables error: {result.stderr}")
                    success = False
            except Exception as e:
                logger.error(f"Command execution failed: {e}")
                success = False
        return success

    def _unblock_linux(self, ip):
        """Remove iptables rules."""
        commands = [
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            ["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"]
        ]
        
        success = True
        for cmd in commands:
            try:
                # ARCH: Safe list command avoiding shell=True injection
                subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=10)
            except Exception:
                success = False
        return success

    # ═══════════════════════════════════════════════════════════════════════
    #  UTILITY
    # ═══════════════════════════════════════════════════════════════════════

    def verify_block(self, ip):
        """
        Verify if a firewall block rule exists for the specified IP address.
        
        Performs cross-platform checks using system firewall CLI tools.
        Distinguishes between a normal "rule not found" (returns False)
        and operational failures (logs warnings/errors and returns False).
        """
        if not validate_ip(ip):
            logger.warning(f"Attempted block verification for invalid IP: {ip}")
            return False

        try:
            if IS_WINDOWS:
                rule_name = f"BLOCK_{ip}_IN"
                result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
                    shell=False, capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0:
                    return True
                
                # Check for standard "rule not found" message
                output = (result.stdout or "") + (result.stderr or "")
                if "No rules match the specified criteria" in output:
                    return False
                
                # Any other exit code/output indicates an elevation or command failure
                logger.warning(
                    f"Windows firewall verification command failed for {ip}. "
                    f"Exit code: {result.returncode}, Error: {output.strip()}"
                )
                return False
                
            elif IS_LINUX:
                result = subprocess.run(
                    ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                    shell=False, capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0:
                    return True
                elif result.returncode == 1:
                    # iptables -C returns 1 if the rule is not found (normal case)
                    return False
                
                # Any exit code other than 0 or 1 indicates a real failure (e.g., missing sudo privileges or tool)
                logger.warning(
                    f"iptables verification command failed for {ip}. "
                    f"Exit code: {result.returncode}, Error: {result.stderr.strip()}"
                )
                return False
                
            elif IS_MACOS:
                return self._verify_block_macos(ip)
                
            else:
                logger.warning(
                    f"Firewall verification requested on unsupported operating system: {platform.system()}. "
                    f"Defaulting to unverified status (False)."
                )
                return False
                
        except subprocess.TimeoutExpired as e:
            logger.error(f"Timeout expired while verifying firewall block for {ip}: {e}")
        except FileNotFoundError as e:
            logger.error(
                f"Firewall utility not found during block verification for {ip}. "
                f"Make sure utility is on PATH. Error: {e}"
            )
        except PermissionError as e:
            logger.error(f"Insufficient privileges to verify firewall block for {ip}: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error verifying firewall block for {ip}: {e}")
            
        return False

    # ═══════════════════════════════════════════════════════════════════════
    #  GATEWAY ISOLATION (ARP POISONING)
    # ═══════════════════════════════════════════════════════════════════════

    def isolate_device(self, ip, gateway_ip):
        """Isolate a device from the gateway using ARP poisoning."""
        if not validate_ip(ip) or not validate_ip(gateway_ip):
            return False

        with self._lock:
            if ip in self._active_isolation:
                logger.info(f"Isolation already active for {ip}")
                return True

            logger.warning(f"Starting ARP isolation for {ip} from gateway {gateway_ip}")
            
            stop_event = threading.Event()
            thread = threading.Thread(
                target=self._poison_loop,
                args=(ip, gateway_ip, stop_event),
                daemon=True,
                name=f"Isolation-{ip}"
            )
            thread.start()
            self._active_isolation[ip] = stop_event
        
        return True

    def stop_isolation(self, ip):
        """Stop ARP poisoning and restore connectivity."""
        with self._lock:
            if ip in self._active_isolation:
                logger.info(f"Stopping isolation thread and restoring connectivity for {ip}")
                self._active_isolation[ip].set()
                
                # Send corrective ARP packets to restore victim/gateway connection
                gateway_ip = net_ctx.gateway_ip
                self._restore_connectivity(ip, gateway_ip)
                
                del self._active_isolation[ip]
                return True
        return False

    def _restore_connectivity(self, target_ip, gateway_ip):
        """Send corrective ARP packets to restore proper network state."""
        try:
            # 1. Resolve real MACs
            def get_mac(ip):
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, retry=2, verbose=False)
                for _, rcv in ans: return rcv.hwsrc
                return None

            target_mac = get_mac(target_ip)
            gateway_mac = get_mac(gateway_ip)

            if target_mac and gateway_mac:
                # Corrective packet: Tell target the real gateway MAC
                target_packet = Ether(dst=target_mac, src=gateway_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
                # Corrective packet: Tell gateway the real target MAC
                gateway_packet = Ether(dst=gateway_mac, src=target_mac)/ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
                
                sendp(target_packet, count=5, inter=0.1, verbose=False)
                sendp(gateway_packet, count=5, inter=0.1, verbose=False)
                logger.info(f"Corrective ARP packets sent for {target_ip}")
        except Exception as e:
            logger.error(f"Restoration failed for {target_ip}: {e}")

    def _poison_loop(self, target_ip, gateway_ip, stop_event):
        """Background loop to keep the ARP cache poisoned."""
        try:
            local_mac = get_local_mac()
            
            # 1. Resolve MAC addresses
            def get_mac(ip):
                try:
                    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, retry=2, verbose=False)
                    for _, rcv in ans: return rcv.hwsrc
                except Exception: pass
                return None

            target_mac = get_mac(target_ip)
            gateway_mac = get_mac(gateway_ip)

            if not target_mac or not gateway_mac:
                logger.error(f"ARP Isolation ABORTED: MAC resolution failed for {target_ip}")
                return

            # 2. Build L2 packets (Tell victim we are gateway, tell gateway we are victim)
            target_packet = Ether(dst=target_mac, src=local_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
            gateway_packet = Ether(dst=gateway_mac, src=local_mac)/ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
            
            logger.info(f"ARP Poisoning started for {target_ip} (2s interval)")
            while not stop_event.is_set():
                sendp(target_packet, verbose=False)
                sendp(gateway_packet, verbose=False)
                time.sleep(2.0) # Standard 2s poisoning interval
        except Exception as e:
            logger.error(f"Poisoning loop error for {target_ip}: {e}")
        finally:
            logger.info(f"ARP Poisoning loop terminated for {target_ip}")

    # ═══════════════════════════════════════════════════════════════════════
    #  BACKWARD COMPATIBILITY
    # ═══════════════════════════════════════════════════════════════════════
    def block(self, ip, mac=None, reason="Manual block"):
        return self.block_ip(ip, reason)

    def unblock(self, ip):
        return self.unblock_ip(ip)

# Module singleton
blocker = Blocker()

def block_ip(ip, reason="Manual block"):
    return blocker.block_ip(ip, reason)

def unblock_ip(ip):
    return blocker.unblock_ip(ip)

def block(ip, mac=None, reason="Manual block"):
    return blocker.block_ip(ip, reason)

def unblock(ip):
    return blocker.unblock_ip(ip)

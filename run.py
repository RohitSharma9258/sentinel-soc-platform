"""
Smart WiFi Intruder Detection System - Entry Point
Run this file to start the entire system.

Usage:
    python run.py

Requires: Run as Administrator (Windows) or sudo (Linux) for firewall control.
"""

import sys
import os
import logging
import platform
import subprocess
import importlib.util

# ─── Startup Validation ────────────────────────────────────────────────────────
def check_environment():
    """Ensure the environment is ready for the system."""
    print("  [*] Performing startup validation...")
    
    # 1. Check Python Version
    major, minor = sys.version_info[:2]
    print(f"  [OK] Python {major}.{minor} detected")

    if (major, minor) < (3, 11):
        print(f"  [!] CRITICAL ERROR: Unsupported Python version {major}.{minor}")
        print("      This project requires Python 3.11 or 3.12 for maximum stability.")
        print("      Please upgrade/downgrade Python and try again.")
        sys.exit(1)
    
    if (major, minor) >= (3, 13):
        print(f"  [!] WARNING: Python {major}.{minor} is very new.")
        print("      Some networking libraries (Scapy) may have compatibility issues.")
        print("      Recommended versions: Python 3.11 or 3.12")

    # 2. Check for Administrator/Root (Required for Sniffer/Firewall)
    is_admin = False
    try:
        if platform.system() == "Windows":
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            is_admin = os.getuid() == 0
    except Exception:
        pass
        
    if not is_admin:
        print("  [!] WARNING: Not running as Administrator/Root.")
        print("      - Network sniffing (Scapy) requires administrative privileges.")
        print("      - Firewall blocking (netsh/iptables/pfctl) requires root privileges.")
        print("      - The system will run in PASSIVE/FALLBACK mode (ping + arp -a).")
    else:
        print("  [OK] Elevated privileges (Administrator) detected")

    # 3. Check Dependencies (Robust Import Validation)
    # Map from import name to human-readable name if they differ
    required_modules = {
        "flask": "Flask",
        "flask_socketio": "Flask-SocketIO",
        "scapy": "Scapy"
    }
    
    missing_modules = []
    
    for module_name, display_name in required_modules.items():
        try:
            # Use importlib for robust module checking
            spec = importlib.util.find_spec(module_name)
            if spec is None:
                missing_modules.append(display_name)
            else:
                importlib.import_module(module_name)
        except Exception as e:
            logger.debug(f"Failed to import {module_name}: {e}")
            missing_modules.append(display_name)

    if missing_modules:
        print(f"  [!] ERROR: Missing or broken dependencies: {', '.join(missing_modules)}")
        print("      Please run: pip install -r requirements.txt")
        sys.exit(1)

    
    print("  [OK] All required dependencies verified")

# Configure basic logging for early startup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("startup")

# Ensure the project root is in the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG
except ImportError:
    print("  [!] ERROR: Could not find config.py. Ensure you are in the project root.")
    sys.exit(1)

def main():
    """Start the Smart WiFi Intruder Detection System."""
    print("""
    ==============================================================
    |     SMART WIFI INTRUDER DETECTION SYSTEM                   |
    |                Real-Time Network Defense                   |
    ==============================================================
    """)

    # Run startup checks
    check_environment()

    try:
        from network_context import net_ctx
        from app import app, start_background_services
        from database import db
        from blocker import Blocker
    except ImportError as e:
        logger.error(f"Failed to load application imports: {e}")
        print(f"  [!] ERROR: Failed to load application: {e}")
        sys.exit(1)

    # 1. Initialize Network Context
    logger.info("Initializing NetworkContext...")
    print("  [*] Initializing network context...")
    try:
        net_ctx.initialize(refresh_interval=300)
        logger.info(f"NetworkContext initialized: IP={net_ctx.local_ip}, Gateway={net_ctx.gateway_ip}, CIDR={net_ctx.network_cidr}")
        print(f"  [OK] Network context initialized. Subnet: {net_ctx.network_cidr}")
    except Exception as e:
        logger.critical(f"NetworkContext initialization failed: {e}")
        print(f"  [!] CRITICAL ERROR: Network Context Initialization failed: {e}")
        sys.exit(1)

    # 2. Clean and stabilize database session (requires initialized net_ctx)
    logger.info("Starting database session cleaning and maintenance...")
    print("  [*] Cleaning and stabilizing database session...")
    try:
        db.startup_cleanup()
        logger.info("Database startup cleanup completed successfully.")
        print("  [OK] Database startup cleanup completed.")
    except Exception as e:
        logger.critical(f"Database startup cleanup failed: {e}")
        print(f"  [!] CRITICAL ERROR: Database startup cleanup failed: {e}")
        sys.exit(1)
    
    # 3. Block recovery (after cleanup, requires initialized net_ctx)
    logger.info("Starting active block recovery watchdog...")
    print("  [*] Recovering active blocks...")
    try:
        blocker = Blocker()
        blocker.startup_recovery()
        logger.info("Startup block recovery completed successfully.")
        print("  [OK] Startup block recovery completed.")
    except Exception as e:
        logger.critical(f"Startup block recovery failed: {e}")
        print(f"  [!] CRITICAL ERROR: Startup block recovery failed: {e}")
        sys.exit(1)

    # 4. Start all background services
    logger.info("Starting background services...")
    print("\n  [*] Starting background services...")
    start_background_services()

    print(f"  [*] Dashboard: http://localhost:{FLASK_PORT}")
    print(f"  [*] API Base:  http://localhost:{FLASK_PORT}/")
    print("  [*] Press Ctrl+C to stop\n")

    # Run SOC-grade IDS/IPS with SocketIO
    try:
        from app import socketio
        socketio.run(
            app,
            host=FLASK_HOST,
            port=FLASK_PORT,
            debug=FLASK_DEBUG,
            use_reloader=False,
            log_output=True,
            allow_unsafe_werkzeug=True
        )
    except KeyboardInterrupt:
        print("\n  [!] Shutting down...")
        try:
            from app import stop_background_services
            stop_background_services()
        except Exception:
            pass
        print("  [OK] System stopped.")
    except Exception as e:
        print(f"  [!] Server error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

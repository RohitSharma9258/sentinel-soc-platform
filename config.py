"""
Smart WiFi Intruder Detection System - Configuration
Central configuration for all system modules.
"""

import os
import platform
import secrets
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# ─── Base Paths ──────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "intruder.db")
LOG_DIR = os.path.join(BASE_DIR, "logs")
EXPORT_DIR = os.path.join(BASE_DIR, "exports")

# ─── Ensure directories exist ────────────────────────────────────────────────
for d in [os.path.join(BASE_DIR, "data"), LOG_DIR, EXPORT_DIR]:
    os.makedirs(d, exist_ok=True)

# ─── Network Scanning ────────────────────────────────────────────────────────
SCAN_INTERVAL = 5           # seconds between background scans
SCAN_TIMEOUT = 3            # ARP scan timeout in seconds
DEFAULT_NETWORK = "192.168.1.0/24"   # default subnet to scan

# ─── Packet Sniffer ──────────────────────────────────────────────────────────
SNIFFER_ENABLED = True
SNIFFER_IFACE = None        # None = auto-detect
PACKET_BUFFER_SIZE = 1000   # max packets in analysis buffer

# ─── Detection Thresholds ────────────────────────────────────────────────────
PORT_SCAN_THRESHOLD = 15       # unique ports in window → port scan
FLOOD_PACKET_THRESHOLD = 200   # packets per second → flood
CONNECTION_ATTEMPT_THRESHOLD = 50  # connection attempts in window
DETECTION_WINDOW = 60          # seconds for detection window
AUTO_BLOCK_THREAT_LEVEL = "critical"  # auto-block at this level

# ─── Threat Levels ────────────────────────────────────────────────────────────
THREAT_LEVELS = {
    "low": {"score_min": 1, "score_max": 25, "color": "#f59e0b"},
    "medium": {"score_min": 26, "score_max": 50, "color": "#f97316"},
    "high": {"score_min": 51, "score_max": 75, "color": "#ef4444"},
    "critical": {"score_min": 76, "score_max": 100, "color": "#dc2626"},
}

# ─── AI Predictor ─────────────────────────────────────────────────────────────
AI_MODEL_PATH = os.path.join(BASE_DIR, "data", "threat_model.pkl")
AI_TRAINING_INTERVAL = 300   # retrain every 5 minutes

# ─── Flask Server ─────────────────────────────────────────────────────────────
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
FLASK_DEBUG = False
def _load_or_create_secret_key():
    # a) Check environment variable first
    env_key = os.environ.get("IDS_SECRET_KEY")
    if env_key:
        return env_key

    # Determine path to the secret key file
    secret_file_path = os.path.join(BASE_DIR, "data", ".secret_key")

    # b) Read from file if it exists
    if os.path.exists(secret_file_path):
        try:
            with open(secret_file_path, "r", encoding="utf-8") as f:
                key = f.read().strip()
                if key:
                    return key
        except Exception:
            pass

    # c) Generate and save new key
    new_key = secrets.token_hex(32)
    try:
        with open(secret_file_path, "w", encoding="utf-8") as f:
            f.write(new_key)
        # d) On Linux/macOS: restrict permissions to owner read/write
        if platform.system() != "Windows":
            os.chmod(secret_file_path, 0o600)
    except Exception:
        pass

    return new_key

SECRET_KEY = _load_or_create_secret_key()

# ─── OS Detection ─────────────────────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
# ARCH: Added macOS detection support
IS_MACOS = platform.system() == "Darwin"

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s | %(name)-18s | %(levelname)-8s | %(message)s"
LOG_FILE = os.path.join(LOG_DIR, "intruder_system.log")
# ─── ANTIGRAVITY Protocol ───────────────────────────────────────────────────
ANTIGRAVITY_MODE = True     # If True, critical system services bypass blocking
GRAVITY_EXEMPT_PORTS = [53, 123, 67, 68] # DNS, NTP, DHCP
ANTIGRAVITY_LOG_EXEMPTIONS = True

# ─── API Authentication ──────────────────────────────────────────────────────
API_KEY = os.environ.get("IDS_API_KEY", "").strip() or None

# INTERFACE-FIX: Network Interface Overrides to manually specify local IP/subnet when auto-detection picks virtual adapters (e.g. Docker/VPN).
FORCE_LOCAL_IP = os.environ.get("IDS_LOCAL_IP", None)
FORCE_NETWORK = os.environ.get("IDS_NETWORK", None)


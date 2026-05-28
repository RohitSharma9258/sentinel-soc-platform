# 🛡️ Smart WiFi Intruder Detection System

Real-time WiFi intrusion detection and **actual blocking** system with a professional cybersecurity dashboard.

## 🚀 Requirement Fixes & Updates

This project has been updated with the following critical fixes:
- **Python 3.11+ Compatibility**: Added startup validation for modern Python environments.
- **Robust Blocking**: Fixed "400 Bad Request" issues. Devices can now be blocked if they exist in history or the current subnet, even if missed in the latest scan.
- **Gateway Isolation**: Enhanced `blocker.py` with ARP poisoning thread management and duplicate rule prevention.
- **Subnet Awareness**: Dynamic detection of current IP and subnet to prevent showing stale devices from old networks.
- **Stable Status**: Devices now use a wider window for status transitions (Online 30s, Idle 90s, Offline 180s) to prevent flickering.
- **Encoding**: All files standardized to UTF-8 to fix broken symbols.

## 🛠️ Installation & Setup

### 1. Prerequisites
- **Python 3.11 or higher** is required.
- **Windows**: Run terminal as **Administrator**.
- **Linux**: Run commands with `sudo`.
- **Npcap (Windows)**: Required for packet sniffing. [Download here](https://npcap.com/#download).

### 2. Setup Environment
```bash
# Clone or enter the project directory
cd mini_project

# Create a virtual environment (Recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the System
```bash
# Must be run as Administrator/Root
python run.py
```

## 📋 Usage & Testing

1. **Access Dashboard**: Open `http://localhost:5000` in your browser.
2. **Manual Scan**: Click the **Scan Now** button. The system will detect your current subnet and find all active devices.
3. **Test Blocking**:
   - Find a device (e.g., your phone) in the list.
   - Click **Block**.
   - **Verification**: The device will be added to the "Blocked" list, and its network access will be disrupted via firewall rules and ARP isolation.
   - **Unblock**: Click **Unblock** to restore access.
4. **Subnet Switching**: If you change networks, the system will automatically detect the new subnet and cleanup old records.

## ⚠️ Important Notes
- **Administrator Privileges**: Blocking and Sniffing **WILL FAIL** without elevation.
- **Real Enforcement**: This system creates actual OS firewall rules. Use with caution.
- **Npcap**: Ensure "WinPcap API-compatible mode" is checked during installation on Windows.

## 📁 Project Structure
- `run.py`: Entry point with environment validation.
- `app.py`: Flask API and background service manager.
- `blocker.py`: Hybrid blocking engine (Firewall + ARP Poisoning).
- `scanner.py`: Subnet-aware network discovery.
- `database.py`: Thread-safe SQLite management with stable status logic.
- `main.js`: UI logic with enhanced error handling and toast notifications.

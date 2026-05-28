import sys
import os

# Add parent directory to path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Ensure UTF-8 output
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

from database import db

devices = db.get_all_devices()
print(f"Total devices in DB: {len(devices)}")
for d in devices:
    print(f"IP: {d['ip']} | MAC: {d['mac']} | Hostname: {d['hostname']} | Vendor: {d['vendor']} | Online: {d['is_online']}")

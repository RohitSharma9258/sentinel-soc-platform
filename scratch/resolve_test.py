import os
import sys

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

import socket
from database import db

devices = [d for d in db.get_all_devices() if d['is_online']]
print(f"Testing resolution for {len(devices)} online devices:")

for d in devices:
    ip = d['ip']
    print(f"\n--- IP: {ip} ---")
    
    # 1. gethostbyaddr
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        print(f"socket.gethostbyaddr: {name}")
    except Exception as e:
        print(f"socket.gethostbyaddr failed: {e}")
        
    # 2. getnameinfo
    try:
        name, _ = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)
        print(f"socket.getnameinfo: {name}")
    except Exception as e:
        print(f"socket.getnameinfo failed: {e}")

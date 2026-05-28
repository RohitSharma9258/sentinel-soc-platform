import sys
import socket

# NetBIOS status query packet
query = b'\xac\x1f\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01'

def query_netbios(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.2)
    try:
        sock.sendto(query, (ip, 137))
        data, addr = sock.recvfrom(1024)
        if len(data) > 56:
            # Parse NetBIOS response
            # Number of names starts at byte 56
            num_names = data[56]
            offset = 57
            for i in range(num_names):
                name_bytes = data[offset : offset + 15]
                name_type = data[offset + 15]
                # Type 0x00 is Workstation Service
                name = name_bytes.decode('ascii', errors='ignore').strip()
                if name_type == 0x00 and name:
                    return name
                offset += 18
    except Exception as e:
        pass
    finally:
        sock.close()
    return None

# Test on a few IPs from our list
test_ips = ["192.168.1.7", "192.168.1.8", "192.168.1.31", "192.168.1.47", "192.168.1.42"]
for ip in test_ips:
    name = query_netbios(ip)
    print(f"IP {ip} NetBIOS Hostname: {name}")

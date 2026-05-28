import os
import sys
import time
import threading
import random
from scapy.all import IP, TCP, ARP, Ether

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import db
from packet_sniffer import sniffer
from event_bus import bus

# Flags to control execution
stop_flag = threading.Event()
lock_failures = 0

def database_writer_stress(thread_id):
    """Stress test the SQLite WAL engine with concurrent writes."""
    global lock_failures
    print(f"[*] Thread {thread_id}: DB writer stress started.")
    mac = f"00:11:22:33:44:{thread_id:02X}"
    ips = [f"192.168.56.{100 + i}" for i in range(10)]
    
    count = 0
    while not stop_flag.is_set():
        ip = random.choice(ips)
        try:
            # Re-read and upsert
            db.upsert_device(ip, mac, f"stressed_host_{thread_id}", "Stress Test")
            # Write a log entry
            db.add_log("INFO", "stress_test", f"Thread {thread_id} completed write iteration {count}")
            count += 1
            if count % 50 == 0:
                print(f"[+] Thread {thread_id}: Completed {count} DB writes successfully.")
        except Exception as e:
            lock_failures += 1
            print(f"[!] Thread {thread_id} DB write error: {e}")
        time.sleep(0.01) # fast write frequency

def sniffer_packet_blast(thread_id):
    """Stress test the packet sniffer lock safety by blasting simulated Scapy packets."""
    print(f"[*] Thread {thread_id}: Sniffer blaster started.")
    src_ip = f"10.0.0.{thread_id}"
    
    # Pre-generate scapy packets
    packets = []
    # 1. Port scan blast packets (TCP SYN packets to unique ports)
    for port in range(100, 150):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src=src_ip, dst="192.168.56.1")/TCP(sport=12345, dport=port, flags="S")
        packets.append(pkt)
        
    # 2. Flood attack packets (high rate, same port)
    for _ in range(300):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src=f"200.0.0.{thread_id}", dst="192.168.56.1")/TCP(sport=2222, dport=80, flags="PA")
        packets.append(pkt)
        
    # 3. ARP packets for MAC spoofing
    for _ in range(5):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc="192.168.56.254", hwsrc=f"00:99:88:77:66:{thread_id:02X}")
        packets.append(pkt)

    while not stop_flag.is_set():
        pkt = random.choice(packets)
        try:
            # Blast directly into sniffer processor to benchmark self._lock
            sniffer._process_packet(pkt)
        except Exception as e:
            print(f"[!] Sniffer blast error: {e}")
        time.sleep(0.002) # Extremely high frequency packet ingestion (500 pps)

def main():
    print("[*] Starting WiFi Intruder Detection System Stress Test Engine...")
    print("[*] Database is using WAL mode: checking connection safety.")
    
    # Spawn threads
    threads = []
    
    # 1. Spawn DB writers (stressing write lock contention)
    for i in range(5):
        t = threading.Thread(target=database_writer_stress, args=(i,), name=f"DBStress-{i}")
        threads.append(t)
        
    # 2. Spawn packet blasters (stressing sniffer thread-safety locks)
    for i in range(5):
        t = threading.Thread(target=sniffer_packet_blast, args=(i,), name=f"SniffStress-{i}")
        threads.append(t)

    # Start all threads
    for t in threads:
        t.start()
        
    try:
        # Run stress test for 15 seconds
        time.sleep(15)
    except KeyboardInterrupt:
        pass
    finally:
        print("[*] Stopping stress test threads...")
        stop_flag.set()
        for t in threads:
            t.join()
        
        # Pull stats
        stats = sniffer.get_stats()
        print("\n==================================================")
        print("                 STRESS TEST RESULTS              ")
        print("==================================================")
        print(f"Total Packets Processed: {stats.get('total_packets')}")
        print(f"Packets Per Second:      {stats.get('packets_per_second')}")
        print(f"Tracked Hosts:           {stats.get('tracked_hosts')}")
        print(f"Pending Alerts:          {stats.get('pending_alerts')}")
        print(f"SQLite DB Lock Failures: {lock_failures}")
        print("==================================================")

if __name__ == "__main__":
    main()

import time
import random
import subprocess
import requests
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

TARGET_IP = "10.0.0.10" # ns_server
TARGET_URL = f"http://{TARGET_IP}"

def log(msg):
    print(f"[BENIGN USER] {msg}")

def generate_traffic(duration=0, fast_mode=False):
    print(f"[*] Starting background traffic to {TARGET_IP}... (fast_mode={fast_mode})")
    start_time = time.time()
    
    # Fast mode settings
    if fast_mode:
        sleep_min, sleep_max = 0.01, 0.1  # Much shorter sleep
        workers = 4  # Parallel workers
    else:
        sleep_min, sleep_max = 0.5, 3.0
        workers = 1
    
    def do_action():
        try:
            action = random.choice(['ping', 'web', 'web', 'tcp', 'tcp', 'udp'])
            
            if action == 'ping':
                # Generate ICMP flows
                subprocess.run(["ping", "-c", "1", "-W", "1", TARGET_IP], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
            elif action == 'web':
                # Generate TCP/HTTP flows
                try:
                    requests.get(TARGET_URL, timeout=1)
                except: pass
                
            elif action == 'tcp':
                # Generate raw TCP connection flows
                try:
                    port = random.choice([80, 22, 443, 8080, 8000])
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    sock.connect((TARGET_IP, port))
                    sock.send(b"GET / HTTP/1.0\\r\\n\\r\\n")
                    sock.recv(1024)
                    sock.close()
                except: pass
                
            elif action == 'udp':
                # Generate UDP flows
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(0.5)
                    port = random.choice([53, 123, 161, 514])
                    sock.sendto(b"test", (TARGET_IP, port))
                    sock.close()
                except: pass
                
        except Exception as e:
            pass
    
    if fast_mode and workers > 1:
        # Use thread pool for parallel traffic generation
        with ThreadPoolExecutor(max_workers=workers) as executor:
            while True:
                if duration > 0 and (time.time() - start_time) > duration:
                    print("[*] Traffic generation finished.")
                    break
                
                # Submit batch of actions
                futures = [executor.submit(do_action) for _ in range(workers * 2)]
                for f in futures:
                    try: f.result(timeout=2)
                    except: pass
                
                time.sleep(random.uniform(sleep_min, sleep_max))
    else:
        while True:
            if duration > 0 and (time.time() - start_time) > duration:
                print("[*] Traffic generation finished.")
                break
            
            do_action()
            time.sleep(random.uniform(sleep_min, sleep_max))

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=0, help="Duration in seconds (0=infinite)")
    parser.add_argument("--fast", action="store_true", help="Fast mode for bulk traffic generation")
    args = parser.parse_args()
    
    generate_traffic(duration=args.duration, fast_mode=args.fast)
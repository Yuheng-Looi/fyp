import time
import random
import subprocess
import requests

TARGET_IP = "10.0.0.10" # ns_server
TARGET_URL = f"http://{TARGET_IP}"

def log(msg):
    print(f"[BENIGN USER] {msg}")

def generate_traffic(duration=0):
    print(f"[*] Starting background traffic to {TARGET_IP}...")
    start_time = time.time()
    
    while True:
        if duration > 0 and (time.time() - start_time) > duration:
            print("[*] Traffic generation finished.")
            break

        try:
            action = random.choice(['ping', 'web', 'web', 'sleep'])
            
            if action == 'ping':
                # Generate ICMP flows
                log("Pinging server...")
                subprocess.run(["ping", "-c", "2", "-W", "1", TARGET_IP], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
            elif action == 'web':
                # Generate TCP/HTTP flows
                log(f"Requesting {TARGET_URL}...")
                requests.get(TARGET_URL, timeout=1)
                
            elif action == 'sleep':
                log("Thinking...")
                
            # Random sleep to look human
            time.sleep(random.uniform(0.5, 3.0))
            
        except Exception as e:
            log(f"Error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=0, help="Duration in seconds (0=infinite)")
    args = parser.parse_args()
    
    generate_traffic(duration=args.duration)
import time
import random
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor

TARGET_IP = "10.0.0.10" # ns_server

def log(msg):
    print(f"[BENIGN USER] {msg}")

def generate_traffic(duration=0, fast_mode=False):
    """
    Generate normal traffic using the SAME methods as server.py's generate_normal_traffic_loop().
    This ensures identical flow patterns between live capture and test dataset generation.
    Uses curl and ping via subprocess (same as server.py).
    """
    print(f"[*] Starting background traffic to {TARGET_IP}... (fast_mode={fast_mode})")
    start_time = time.time()
    
    # Fast mode settings - matches server.py traffic generation timing
    # Always use fast mode timing to match server.py
    sleep_min, sleep_max = 0.01, 0.05
    workers = 1
    
    def do_action():
        """
        Execute traffic actions using SAME commands as server.py's generate_normal_traffic_loop().
        server.py uses: ping and curl via subprocess shell commands.
        """
        try:
            # Weight towards web traffic like server.py does
            action = random.choice(['ping', 'web', 'web', 'sleep'])
            if action == 'ping':
                subprocess.run(
                    f"ping -c 1 -W 1 {TARGET_IP}",
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )
            elif action == 'web':
                subprocess.run(
                    f"curl -s -o /dev/null --connect-timeout 2 http://{TARGET_IP}/",
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )
            # 'sleep' action does nothing (simulates idle periods)
            time.sleep(random.uniform(0.01, 0.05))
        except subprocess.TimeoutExpired:
            pass
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
                    try: f.result(timeout=5)
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
import time
import subprocess
import os
import sys
import requests
import json
import topo
import csv

SERVER_URL = "http://10.100.10.15:8000"
DURATION_NORMAL = 300
DURATION_ATTACK = 30

def run_cmd_bg(cmd):
    return subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)

def ns_exec_bg(ns, cmd):
    # Hide output to keep terminal clean for the report
    full_cmd = f"ip netns exec {ns} {cmd} >/dev/null 2>&1"
    return run_cmd_bg(full_cmd)

def get_best_scaler():
    try:
        resp = requests.get(f"{SERVER_URL}/scalers", timeout=5)
        if resp.status_code == 200:
            scalers = resp.json().get('scalers', [])
            if scalers:
                print(f"[*] Available Scalers: {[s['id'] for s in scalers]}")
                # Use the last one as it's likely the newest
                return scalers[-1]['id']
    except Exception as e:
        print(f"[-] Could not fetch scalers: {e}")
    return 'default'

def add_label_and_merge(normal_csv, attack_csv, output_csv):
    # Reads both files, adds Label column, writes combined.
    # Assumes headers are identical.
    
    headers = []
    rows = []
    
    # Process Normal
    if os.path.exists(normal_csv):
        with open(normal_csv, 'r') as f:
            r = csv.reader(f)
            try:
                h = next(r, None)
                if h:
                    headers = h
                    for row in r:
                        if row: rows.append(row + ['BENIGN'])
            except StopIteration: pass
    
    # Process Attack
    if os.path.exists(attack_csv):
        with open(attack_csv, 'r') as f:
            r = csv.reader(f)
            try:
                h = next(r, None)
                if h and not headers: headers = h # If normal was empty
                for row in r:
                    if row: rows.append(row + ['ATTACK']) # Map "ATTACK" implies malicious
            except StopIteration: pass
    
    if not headers:
        print("[-] Error: No CSV data found.")
        return False
        
    final_headers = headers + ['Label']
    
    with open(output_csv, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(final_headers)
        w.writerows(rows)
        
    return True

def main():
    if os.geteuid() != 0:
        print("[-] Run as sudo.")
        sys.exit(1)
        
    cwd = os.getcwd()
    
    # 0. Get Scaler
    print("\n=== 0. Configuration ===")
    scaler_id = get_best_scaler()
    print(f"[+] Selected Scaler: {scaler_id}")
    
    print("\n=== 1. Setting up Topology ===")
    topo.cleanup()
    topo.setup_topology()
    time.sleep(2)
    
    try:
        extractor_script = os.path.join(cwd, "cic_extractor.py")
        
        # --- Normal Traffic ---
        print(f"\n=== 2. Running Normal Traffic ({DURATION_NORMAL}s) ===")
        traffic_script = os.path.join(cwd, "traffic_normal.py")
        
        # Start Capture
        norm_csv = os.path.join(cwd, "test_normal.csv")
        if os.path.exists(norm_csv): os.remove(norm_csv)
        cap_cmd = f"python3 {extractor_script} --iface eth0 --output {norm_csv}"
        cap_proc = ns_exec_bg("ns_monitor", cap_cmd)
        
        # Start Traffic
        gen_proc = ns_exec_bg("ns_user", f"python3 {traffic_script} --duration {DURATION_NORMAL}")
        
        # Wait
        for i in range(DURATION_NORMAL):
            if i % 10 == 0:
                sys.stdout.write(f"\r Progress: {i}/{DURATION_NORMAL}s")
                sys.stdout.flush()
            time.sleep(1)
            
        print("\nStopping Normal Capture...")
        subprocess.run(f"ip netns exec ns_monitor pkill -f cic_extractor.py", shell=True)
        try: cap_proc.wait(timeout=5)
        except: pass
        try: gen_proc.wait(timeout=5)
        except: pass

        # --- Attack Traffic ---
        print(f"\n=== 3. Running Attack Traffic ({DURATION_ATTACK}s) ===")
        attack_script = os.path.join(cwd, "attack_generator.py")
        
        # Start Capture
        att_csv = os.path.join(cwd, "test_attack.csv")
        if os.path.exists(att_csv): os.remove(att_csv)
        cap_cmd = f"python3 {extractor_script} --iface eth0 --output {att_csv}"
        cap_proc = ns_exec_bg("ns_monitor", cap_cmd)
        
        # Start Attack (SYN Flood)
        att_proc = ns_exec_bg("ns_attacker", f"python3 {attack_script} --attack syn --duration {DURATION_ATTACK}")
        
        time.sleep(DURATION_ATTACK + 2)
        
        print("Stopping Attack Capture...")
        subprocess.run(f"ip netns exec ns_monitor pkill -f cic_extractor.py", shell=True)
        try: cap_proc.wait(timeout=5)
        except: pass
        try: att_proc.wait(timeout=5)
        except: pass
        
        # --- Analysis ---
        print("\n=== 4. Merging and analyzing ===")
        combined_csv = os.path.join(cwd, "test_combined.csv")
        if add_label_and_merge(norm_csv, att_csv, combined_csv):
            print(f"[+] Created {combined_csv}")
            
            print(f"[*] Uploading to {SERVER_URL}/analyze_pcap...")
            with open(combined_csv, 'rb') as f:
                files = {'file': f}
                data = {
                    'scaler_id': scaler_id,
                    'label_col': 'Label',
                    'normal_label': 'BENIGN'
                }
                resp = requests.post(f"{SERVER_URL}/analyze_pcap", files=files, data=data)
                
                if resp.status_code == 200:
                    res = resp.json()
                    metrics = res.get('metrics', {})
                    print("\n" + "="*40)
                    print(" PERFORMANCE REPORT")
                    print("="*40)
                    print(f" Accuracy:  {metrics.get('accuracy', 0):.4f}")
                    print(f" Recall:    {metrics.get('recall', 0):.4f}")
                    print(f" F1 Score:  {metrics.get('f1', 0):.4f}")
                    print(f" Confusion Matrix (TN, FP, FN, TP): {metrics.get('cm')}")
                    print("="*40)
                    
                    # Also count flows manually for sanity check
                    flows = res.get('flows', [])
                    print(f" Total Flows Processed: {len(flows)}")
                else:
                    print(f"[-] Analysis Failed: {resp.status_code} {resp.text}")
                    
    finally:
        print("\n=== Cleanup ===")
        topo.cleanup()

if __name__ == "__main__":
    main()

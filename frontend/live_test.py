import time
import subprocess
import os
import sys
import requests
import json
import topo
import csv

SERVER_URL = "http://10.100.10.15:8000"
TARGET_NORMAL_FLOWS = 45000  # Target normal flows
ATTACK_DURATION_PER_TYPE = 20  # Duration per attack type in seconds
CSV_OUTPUT_DIR = "uploads/csv"

# Multiclass attack labels matching CIC-IDS dataset
ATTACK_TYPES = [
    ('syn', 'DoS-SYNFlood'),
    ('udp', 'DoS-UDP'),
    ('scan', 'PortScan'),
    ('web', 'WebAttack-BruteForce'),
]

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

def count_csv_rows(csv_path):
    """Count data rows in CSV (excluding header)"""
    if not os.path.exists(csv_path):
        return 0
    try:
        with open(csv_path, 'r') as f:
            return sum(1 for _ in f) - 1  # Subtract header
    except:
        return 0

def ensure_output_dir():
    """Ensure the output directory exists"""
    os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)

def add_label_and_merge(normal_csv, attack_csvs_with_labels, output_csv):
    """
    Merge normal and attack CSVs with proper labels.
    normal_csv: path to benign traffic CSV
    attack_csvs_with_labels: list of tuples (csv_path, label_name)
    output_csv: path for combined output
    """
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
    
    # Process Attack files with multiclass labels
    for attack_csv, attack_label in attack_csvs_with_labels:
        if os.path.exists(attack_csv):
            with open(attack_csv, 'r') as f:
                r = csv.reader(f)
                try:
                    h = next(r, None)
                    if h and not headers: headers = h
                    for row in r:
                        if row: rows.append(row + [attack_label])
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
    
    # Ensure output directory exists
    ensure_output_dir()
    output_dir = os.path.join(cwd, CSV_OUTPUT_DIR)
    
    try:
        extractor_script = os.path.join(cwd, "cic_extractor.py")
        
        # --- Normal Traffic ---
        print(f"\n=== 2. Running Normal Traffic (target: {TARGET_NORMAL_FLOWS} flows) ===")
        traffic_script = os.path.join(cwd, "traffic_normal.py")
        
        # Start Capture
        norm_csv = os.path.join(output_dir, "test_normal.csv")
        if os.path.exists(norm_csv): os.remove(norm_csv)
        cap_cmd = f"python3 {extractor_script} --iface eth0 --output {norm_csv}"
        cap_proc = ns_exec_bg("ns_monitor", cap_cmd)
        
        # Start Traffic (infinite mode, we'll stop when flow count reached)
        gen_proc = ns_exec_bg("ns_user", f"python3 {traffic_script} --duration 0 --fast")
        
        # Wait until target flow count reached
        start_time = time.time()
        check_interval = 5  # Check every 5 seconds
        last_count = 0
        while True:
            time.sleep(check_interval)
            current_count = count_csv_rows(norm_csv)
            elapsed = int(time.time() - start_time)
            rate = current_count / max(elapsed, 1)
            eta = int((TARGET_NORMAL_FLOWS - current_count) / max(rate, 0.1)) if rate > 0 else 0
            
            sys.stdout.write(f"\r Flows: {current_count}/{TARGET_NORMAL_FLOWS} | Elapsed: {elapsed}s | Rate: {rate:.1f}/s | ETA: {eta}s    ")
            sys.stdout.flush()
            
            if current_count >= TARGET_NORMAL_FLOWS:
                print(f"\n[+] Target reached! {current_count} flows collected.")
                break
            
            # Safety timeout: 30 minutes max
            if elapsed > 1800:
                print(f"\n[!] Timeout reached. Collected {current_count} flows.")
                break
                
            last_count = current_count
            
        print("Stopping Normal Capture...")
        subprocess.run(f"ip netns exec ns_user pkill -f traffic_normal.py", shell=True)
        subprocess.run(f"ip netns exec ns_monitor pkill -f cic_extractor.py", shell=True)
        try: cap_proc.wait(timeout=5)
        except: pass
        try: gen_proc.wait(timeout=5)
        except: pass
        
        # Get actual normal flow count
        normal_flow_count = count_csv_rows(norm_csv)
        print(f"[+] Normal flows collected: {normal_flow_count}")

        # --- Attack Traffic (Multiple Types with Multiclass Labels) ---
        print(f"\n=== 3. Running Attack Traffic (Multiple Types) ===")
        attack_script = os.path.join(cwd, "attack_generator.py")
        attack_csvs = []  # List of (csv_path, label)
        
        # Calculate target attack flows per type to achieve balance
        # Want: BENIGN > total_attack / 3
        # So: total_attack < BENIGN * 3
        # Per attack type: attack_per_type = (BENIGN * 3) / num_attack_types / 2
        # (divide by 2 to ensure we don't overshoot)
        target_attack_per_type = max(500, (normal_flow_count * 3) // len(ATTACK_TYPES) // 2)
        print(f"[*] Target per attack type: ~{target_attack_per_type} flows (to maintain balance)")
        
        for attack_type, attack_label in ATTACK_TYPES:
            print(f"\n[⚔️] Running {attack_label} attack...")
            
            # Start Capture for this attack
            att_csv = os.path.join(output_dir, f"test_attack_{attack_type}.csv")
            if os.path.exists(att_csv): os.remove(att_csv)
            cap_cmd = f"python3 {extractor_script} --iface eth0 --output {att_csv}"
            cap_proc = ns_exec_bg("ns_monitor", cap_cmd)
            time.sleep(1)  # Let capture start
            
            # Start Attack
            att_proc = ns_exec_bg("ns_attacker", f"python3 {attack_script} --attack {attack_type} --duration {ATTACK_DURATION_PER_TYPE}")
            
            # Wait for attack to complete
            time.sleep(ATTACK_DURATION_PER_TYPE + 3)
            
            # Stop capture
            subprocess.run(f"ip netns exec ns_monitor pkill -f cic_extractor.py", shell=True)
            try: cap_proc.wait(timeout=5)
            except: pass
            try: att_proc.wait(timeout=5)
            except: pass
            
            # Count flows
            att_count = count_csv_rows(att_csv)
            print(f"    [{attack_label}] Captured {att_count} flows")
            
            if att_count > 0:
                attack_csvs.append((att_csv, attack_label))
            
            time.sleep(1)  # Brief pause between attacks
        
        # --- Analysis ---
        print("\n=== 4. Merging and analyzing ===")
        combined_csv = os.path.join(output_dir, "test_combined.csv")
        if add_label_and_merge(norm_csv, attack_csvs, combined_csv):
            print(f"[+] Created {combined_csv}")
            
            # Print class distribution
            print("\n--- Class Distribution ---")
            label_counts = {}
            with open(combined_csv, 'r') as f:
                r = csv.DictReader(f)
                for row in r:
                    lbl = row.get('Label', 'Unknown')
                    label_counts[lbl] = label_counts.get(lbl, 0) + 1
            
            total_flows = sum(label_counts.values())
            benign_count = label_counts.get('BENIGN', 0)
            attack_count = total_flows - benign_count
            
            for label, count in sorted(label_counts.items()):
                pct = (count / total_flows * 100) if total_flows > 0 else 0
                print(f"  {label}: {count} ({pct:.1f}%)")
            
            print(f"\n  BENIGN: {benign_count} | NON-BENIGN: {attack_count}")
            print(f"  Balance Check: BENIGN > NON-BENIGN/3 ? {benign_count} > {attack_count//3} = {benign_count > attack_count//3}")
            
            print(f"\n[*] Uploading to {SERVER_URL}/analyze_pcap...")
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

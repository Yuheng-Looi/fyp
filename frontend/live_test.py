import time
import subprocess
import os
import sys
import requests
import json
import topo # topo.py (renamed from live.py)
import csv
import shutil

SERVER_URL = "http://127.0.0.1:5000"

def run_cmd_bg(cmd):
    # Use setsid to create a new session so we can kill the whole group if needed
    return subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)

def run_cmd(cmd):
    subprocess.run(cmd, shell=True, check=True)

def ns_exec_bg(ns, cmd):
    # ip netns exec ...
    full_cmd = f"ip netns exec {ns} {cmd}"
    return run_cmd_bg(full_cmd)

def add_label_to_csv(input_file, output_file, label_value):
    # Reads CSV, appends a 'Label' column with fixed value
    with open(input_file, 'r') as f_in, open(output_file, 'w', newline='') as f_out:
        reader = csv.DictReader(f_in)
        fieldnames = reader.fieldnames + ['Label']
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()
        for row in reader:
            row['Label'] = label_value
            writer.writerow(row)

def wait_for_job(job_id):
    # Polls /offline/next until done
    results = []
    print(f"    Waiting for job {job_id}...", end='', flush=True)
    while True:
        try:
            resp = requests.get(f"{SERVER_URL}/offline/next?job={job_id}", timeout=5)
            if resp.status_code != 200:
                print(" Error!")
                return []
            data = resp.json()
            if data['status'] == 'done':
                # Get any final batch?
                if 'results' in data:
                    results.extend(data['results'])
                print(" Done.")
                return results
            if 'results' in data:
                results.extend(data['results'])
                print(".", end='', flush=True)
            time.sleep(1)
        except Exception as e:
            print(f" Exception {e}")
            break
    return results

def main():
    if os.geteuid() != 0:
        print("[-] Run as root (sudo)!")
        sys.exit(1)

    print("\n=== 1. Setting up Topology ===")
    topo.cleanup()
    topo.setup_topology()
    
    # Wait for things to settle
    time.sleep(2)
    cwd = os.getcwd()

    latest_scaler_id = 'default'
    latest_xgb_model = 'default'

    try:
        print("\n=== 2. Starting Normal Traffic (15s) ===")
        # Run traffic gen in ns_user
        traffic_script = os.path.join(cwd, "traffic_normal.py")
        gen_proc = ns_exec_bg("ns_user", f"python3 {traffic_script} --duration 15")

        print("\n=== 3. Capturing Traffic (ns_monitor) ===")
        # Start extractor in ns_monitor
        csv_file = os.path.join(cwd, "test_normal.csv")
        if os.path.exists(csv_file): os.remove(csv_file)
        
        extractor_script = os.path.join(cwd, "cic_extractor.py")
        # Monitor interface inside ns_monitor is eth0
        cap_cmd = f"python3 {extractor_script} --iface eth0 --output {csv_file}"
        cap_proc = ns_exec_bg("ns_monitor", cap_cmd)
        
        # Wait for traffic gen to finish
        for i in range(15):
            sys.stdout.write(f"\rRecording... {15-i}s")
            sys.stdout.flush()
            time.sleep(1)
        print("\nStopping capture...")
        
        # Kill extractor
        subprocess.run(f"ip netns exec ns_monitor pkill -f cic_extractor.py", shell=True)
        try:
            cap_proc.wait(timeout=5)
        except: pass
        try:
            gen_proc.wait(timeout=5)
        except: pass

        print(f" Capture saved to {csv_file}")
        
        # Verify CSV content
        if not os.path.exists(csv_file) or os.path.getsize(csv_file) < 50:
            print("[-] Warning: CSV empty or too small. Check extractor.")
            return
        
        print("\n=== 4. Analysis Phase ===")
        # Feature keys as defined in cic_extractor output
        feat_keys = [
            'Fwd Header Len', 'Protocol', 'Init Bwd Win Byts', 'Tot Fwd Pkts', 'Pkt Len Max',
            'Pkt Len Mean', 'Tot Bwd Pkts', 'Dst Port', 'Bwd Pkt Len Max', 'Fwd Pkts/s',
            'Flow IAT Max', 'TotLen Bwd Pkts', 'TotLen Fwd Pkts', 'Bwd Pkt Len Std',
            'Bwd Pkt Len Mean'
        ]
        
        # MAPPING CORRECTION:
        # cic_extractor CSV columns: src, dst, sport, dport, proto, timestamp, [15 Features...]
        # Backend expects standard feature names.
        
        mapping = {k: k for k in feat_keys}
        
        # Map metadata columns to the CSV headers
        mapping['src_ip'] = 'src'
        mapping['dst_ip'] = 'dst'
        mapping['src_port'] = 'sport'
        mapping['dst_port'] = 'dport'
        mapping['timestamp'] = 'timestamp'
        
        try:
            with open(csv_file, 'rb') as f:
                files = {'csv': f}
                data = {'mapping': json.dumps(mapping), 'scaler_id': 'default'}
                
                print(f"[*] Sending {csv_file} to {SERVER_URL}/analyze_recalibration...")
                resp = requests.post(f"{SERVER_URL}/analyze_recalibration", files=files, data=data, timeout=30)
                
                if resp.status_code == 200:
                    res = resp.json()
                    print("\n[+] Analysis Results:")
                    rec = res.get('recommendation')
                    print(f"    Recommendation: {rec}")
                    print(f"    Shape Score:    {res.get('shape_score')}")
                    
                    if rec == 'RESCALE':
                        print("\n[!] Triggering RESCALE (Auto)...")
                        f.seek(0)
                        data_rs = {'scaler_name': 'auto_test_scaler', 'mapping': json.dumps(mapping), 'labelled': 'false'}
                        resp2 = requests.post(f"{SERVER_URL}/api/rescale", files={'csv': f}, data=data_rs)
                        if resp2.status_code == 200:
                            latest_scaler_id = resp2.json().get('scaler_id')
                            print(f"    [+] New Scaler ID: {latest_scaler_id}")
                        else:
                            print(f"    [-] Rescale Failed: {resp2.text}")
                    
                    elif rec == 'RETRAIN':
                        print("\n[!] Triggering RETRAIN (Auto)...")
                        # 1. Prepare Labelled CSV
                        csv_labelled = os.path.join(cwd, "test_normal_labelled.csv")
                        add_label_to_csv(csv_file, csv_labelled, "BENIGN")
                        
                        # 2. Upload Retrain Request (XGB)
                        with open(csv_labelled, 'rb') as f2:
                             data_rt = {
                                 'model_type': 'xgb',
                                 'model_name': 'auto_xgb',
                                 'scaler_id': latest_scaler_id,
                                 'label_col': 'Label',
                                 'benign_label': 'BENIGN',
                                 'mapping': json.dumps(mapping)
                             }
                             resp3 = requests.post(f"{SERVER_URL}/api/retrain", files={'csv': f2}, data=data_rt)
                             if resp3.status_code == 200:
                                 print("    [+] XGB Retrain Success")
                             else:
                                 print(f"    [-] XGB Retrain Failed: {resp3.text}")

                else:
                    print(f"[-] Analysis Error: {resp.status_code} {resp.text}")
        except Exception as e:
            print(f"[-] Analysis skipped (Server unreachable?): {e}")

        print("\n=== 6. Prediction Verification (Normal) ===")
        # Expect Benign
        try:
            with open(csv_file, 'rb') as f:
                # Use /process_pcap with source=csv
                # We need to send as 'csv' file field
                files = {'csv': (os.path.basename(csv_file), f, 'text/csv')}
                data = {'scaler_id': latest_scaler_id, 'filetype': 'csv'}
                
                req = requests.post(f"{SERVER_URL}/process_pcap", files=files, data=data)
                if req.status_code == 200:
                    resp_json = req.json()
                    job_id = resp_json.get('job_id')
                    
                    if job_id:
                        results = wait_for_job(job_id)
                        
                        benign_cnt = sum(1 for r in results if r['prediction'] == 'BENIGN')
                        attack_cnt = sum(1 for r in results if r['prediction'] != 'BENIGN')
                        total = len(results)
                        print(f"\n[?] Prediction Summary for Normal Traffic (Scaler={latest_scaler_id}):")
                        print(f"    Total:  {total}")
                        print(f"    BENIGN: {benign_cnt} ({(benign_cnt/total*100) if total else 0:.1f}%)")
                        print(f"    ATTACK: {attack_cnt}")
                    else:
                        print(f"[-] Prediction success but no job_id? Answer: {resp_json}")
                else:
                    print(f"[-] Prediction Request Failed: {req.text}")
        except Exception as e:
            print(f"[-] Error verifying prediction: {e}")

        print("\n=== 7. Attack Generation (SYN Flood) ===")
        attack_script = os.path.join(cwd, "attack_generator.py")
        
        # Start Attack
        print("[*] Launching SYN Flood for 10s...")
        att_proc = ns_exec_bg("ns_attacker", f"python3 {attack_script} --attack syn --duration 10")
        
        # Capture Attack
        att_csv = os.path.join(cwd, "test_attack.csv")
        if os.path.exists(att_csv): os.remove(att_csv)
        
        cap_cmd_att = f"python3 {extractor_script} --iface eth0 --output {att_csv}"
        cap_proc_att = ns_exec_bg("ns_monitor", cap_cmd_att)
        
        time.sleep(12) # Wait for attack duration + buffer
        
        # Kill extractor
        subprocess.run(f"ip netns exec ns_monitor pkill -f cic_extractor.py", shell=True)
        try:
            cap_proc_att.wait(timeout=5)
            att_proc.wait(timeout=5)
        except: pass
        
        print(f"[*] Attack traffic saved to {att_csv}")

        print("\n=== 8. Prediction Verification (Attack) ===")
        # We need a robust retry loop for mapping
        def try_predict_attack():
            if not os.path.exists(att_csv): return
            
            # First attempt
            with open(att_csv, 'rb') as f:
                files = {'csv': (os.path.basename(att_csv), f, 'text/csv')}
                data = {'scaler_id': latest_scaler_id, 'filetype': 'csv'}
                print(f"[*] Uploading {att_csv} for prediction...")
                req = requests.post(f"{SERVER_URL}/process_pcap", files=files, data=data)
            
            if req.status_code != 200:
                print(f"[-] Prediction request failed: {req.text}")
                return

            resp = req.json()
            if resp.get('status') == 'mapping_needed':
                print("[!] Server requested column mapping. Configuring...")
                filename = resp.get('filename')
                needed_keys = resp.get('feature_keys', [])
                csv_header = resp.get('header', [])
                
                # Build mapping
                mapping = {}
                for k in needed_keys:
                    if k in csv_header:
                        mapping[k] = k
                    else:
                        # Fallback heuristics
                        if k == 'Dst Port' and 'dport' in csv_header: mapping[k] = 'dport'
                        elif k == 'Src Port' and 'sport' in csv_header: mapping[k] = 'sport'
                        elif k == 'Protocol' and 'proto' in csv_header: mapping[k] = 'proto'
                        elif k == 'Src IP' and 'src' in csv_header: mapping[k] = 'src'
                        elif k == 'Dst IP' and 'dst' in csv_header: mapping[k] = 'dst'
                
                # Send mapping
                print(f"    Sending mapping: {mapping}")
                requests.post(f"{SERVER_URL}/save_mapping", json={'filename': filename, 'mapping': mapping})
                
                # Retry prediction
                print("[*] Retrying prediction with mapping...")
                with open(att_csv, 'rb') as f:
                    files = {'csv': (os.path.basename(att_csv), f, 'text/csv')}
                    req = requests.post(f"{SERVER_URL}/process_pcap", files=files, data=data)
                    resp = req.json()

            # Process final result
            job_id = resp.get('job_id')
            if job_id:
                print(f"[+] Prediction Job ID: {job_id}. Waiting for results...")
                results = wait_for_job(job_id)
                if not results:
                    print("[-] No results returned from job.")
                    return

                # Log some sample predictions
                print("    Sample Predictions:")
                for r in results[:5]:
                    print(f"    - {r['prediction']} ({r['action']}) Conf: {r.get('confidence')}")

                benign_cnt = sum(1 for r in results if r['prediction'] == 'BENIGN')
                attack_cnt = sum(1 for r in results if r['prediction'] != 'BENIGN')
                total = len(results)
                print(f"\n[?] Prediction Summary for ATTACK Traffic:")
                print(f"    Total:  {total}")
                print(f"    BENIGN: {benign_cnt}")
                print(f"    ATTACK: {attack_cnt} ({(attack_cnt/total*100) if total else 0:.1f}%)")
                
                if attack_cnt > benign_cnt:
                    print("    [MATCH] Successfully detected attack traffic.")
                else:
                    print("    [FAIL] Attack traffic NOT detected properly.")
            else:
                 print(f"[-] Prediction success but no job_id? Answer: {resp}")

        try_predict_attack()

    finally:
        print("\n=== Cleanup ===")
        topo.cleanup()
        print("Done.")

if __name__ == "__main__":
    main()

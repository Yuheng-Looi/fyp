import sys
import os
import csv
import json
import time
import requests
import traceback
from datetime import datetime

# Add current directory to path so we can import server helpers
sys.path.append(os.getcwd())

try:
    from server import FEATURE_KEYS
    print("Successfully imported FEATURE_KEYS")
except ImportError as e:
    print(f"Import failed: {e}")
    # Fallback if server.py fails
    FEATURE_KEYS = [
        'Fwd Header Len', 'Protocol', 'Init Bwd Win Byts', 'Tot Fwd Pkts', 'Pkt Len Max',
        'Pkt Len Mean', 'Tot Bwd Pkts', 'Dst Port', 'Bwd Pkt Len Max', 'Fwd Pkts/s',
        'Flow IAT Max', 'TotLen Bwd Pkts', 'TotLen Fwd Pkts', 'Bwd Pkt Len Std',
        'Bwd Pkt Len Mean'
    ]

csv_filename = "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"
csv_path = f"uploads/csv/{csv_filename}"
abs_path = os.path.abspath(csv_path)
metadata_dir = os.path.join(os.path.dirname(abs_path), "../metadata")
metadata_path = os.path.join(metadata_dir, f"{csv_filename}.json")

GPU_IP_PORT = os.environ.get('GPU_IP_PORT', '10.100.10.15:9000')
PREDICT_URL = os.environ.get('PREDICT_URL', f"http://{GPU_IP_PORT}/predict")

if not os.path.exists(abs_path):
    print(f"File not found: {abs_path}")
    sys.exit(1)

def get_csv_header(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
            return header
        except StopIteration:
            return []

header = get_csv_header(abs_path)
if not header:
    print("Empty CSV or no header.")
    sys.exit(1)

# Available columns with their original indices
available_columns = [{'index': i, 'name': name} for i, name in enumerate(header)]

mappings = {}
feature_mappings = {}

def ask_user(label, required=True):
    print(f"\nSelect column for '{label}':")
    for i, col in enumerate(available_columns):
        print(f"  [{i}] {col['name']} (Original Index {col['index']})")
    
    while True:
        prompt = f"Enter selection index (0-{len(available_columns)-1})"
        if not required:
            prompt += " or 's' to skip"
        prompt += ": "
        
        val = input(prompt)
        if not required and val.lower() == 's':
            return None
        
        try:
            idx = int(val)
            if 0 <= idx < len(available_columns):
                selected = available_columns[idx]
                # Remove from available
                available_columns.pop(idx)
                return selected['index'] # Return original index
            else:
                print("Invalid index.")
        except ValueError:
            print("Invalid input.")

def resolve_mapping_from_metadata(metadata, header):
    """
    Resolve column names from metadata to current CSV indices.
    """
    resolved_map = {}
    resolved_feats = {}
    
    # Helper to find index by name
    def find_index(name):
        if not name: return None
        for i, h in enumerate(header):
            if h == name:
                return i
        return None

    # Resolve basic fields
    for key in ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'label']:
        col_name = metadata.get(key)
        idx = find_index(col_name)
        if idx is None and key not in ['timestamp', 'label']: # Timestamp and label are optional/handled differently
             print(f"Warning: Column '{col_name}' for '{key}' not found in header.")
             return None, None, None
        resolved_map[key] = idx

    # Resolve features
    feats = metadata.get('features', {})
    for f_key, col_name in feats.items():
        idx = find_index(col_name)
        if idx is None:
             print(f"Warning: Feature column '{col_name}' for '{f_key}' not found.")
             return None, None, None
        resolved_feats[f_key] = idx
        
    benign_label = metadata.get('benign_label', 'BENIGN')
    return resolved_map, resolved_feats, benign_label

def save_metadata(path, mappings, feature_mappings, header, benign_label='BENIGN'):
    """
    Save the mapping using column names instead of indices.
    """
    data = {}
    # Basic fields
    for k, idx in mappings.items():
        if idx is not None and 0 <= idx < len(header):
            data[k] = header[idx]
        else:
            data[k] = None
    
    data['benign_label'] = benign_label
            
    # Features
    data['features'] = {}
    for k, idx in feature_mappings.items():
        if idx is not None and 0 <= idx < len(header):
            data['features'][k] = header[idx]
            
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"Metadata saved to {path}")

# Check for existing metadata
loaded = False
benign_label = 'BENIGN'

if os.path.exists(metadata_path):
    print(f"Found existing metadata: {metadata_path}")
    try:
        with open(metadata_path, 'r') as f:
            meta = json.load(f)
        
        r_map, r_feats, r_benign = resolve_mapping_from_metadata(meta, header)
        if r_map and r_feats:
            mappings = r_map
            feature_mappings = r_feats
            benign_label = r_benign
            loaded = True
            print("Successfully loaded mapping from metadata.")
        else:
            print("Metadata validation failed (columns missing). Starting interactive mode.")
    except Exception as e:
        print(f"Error loading metadata: {e}")

if not loaded:
    print("--- Interactive Column Mapping ---")

    # Helper to find column by list of names
    def find_col(candidates):
        for cand in candidates:
            # Case insensitive match attempts
            for col in available_columns:
                if col['name'].strip() == cand:
                    return col
                if col['name'].strip().lower() == cand.lower():
                    return col
        return None

    # 1. Timestamp
    ts_col = find_col(['Timestamp', 'timestamp', 'Flow Start', 'StartTime'])
    if ts_col:
        mappings['timestamp'] = ts_col['index']
        print(f"Auto-mapped timestamp to {ts_col['name']}")
    else:
        mappings['timestamp'] = ask_user("Timestamp (optional)", required=False)

    # 2. 5-tuple
    five_tuple_fields = [
        ('src_ip', ['Src IP', 'Source IP', 'SrcAddr', 'src_ip', 'Source']),
        ('dst_ip', ['Dst IP', 'Destination IP', 'DstAddr', 'dst_ip', 'Destination']),
        ('src_port', ['Src Port', 'Source Port', 'Sport', 'src_port']),
        ('dst_port', ['Dst Port', 'Destination Port', 'Dport', 'dst_port']),
        ('protocol', ['Protocol', 'Proto', 'protocol'])
    ]

    for key, candidates in five_tuple_fields:
        found = find_col(candidates)
        if found:
            mappings[key] = found['index']
            print(f"Auto-mapped {key} to {found['name']}")
        else:
            mappings[key] = ask_user(f"Column for {key}", required=True)
        
    # 3. Label
    lbl_col = find_col(['Label', 'label', 'Class'])
    if lbl_col:
        mappings['label'] = lbl_col['index']
        print(f"Auto-mapped label to {lbl_col['name']}")
    else:
        mappings['label'] = ask_user("Label (optional)", required=False)
    
    # 4. Benign Label
    print("Using default Benign Label: BENIGN")
    benign_label = 'BENIGN'

    # 5. Features
    print("\n--- Mapping Features ---")
    for feature in FEATURE_KEYS:
        # Check if we can auto-map
        if feature == 'Protocol' and 'protocol' in mappings:
            feature_mappings[feature] = mappings['protocol']
            print(f"Automatically mapped feature '{feature}' to column index {mappings['protocol']}")
            continue
        if feature == 'Dst Port' and 'dst_port' in mappings:
            feature_mappings[feature] = mappings['dst_port']
            print(f"Automatically mapped feature '{feature}' to column index {mappings['dst_port']}")
            continue
            
        # Try direct name match
        found = find_col([feature])
        if found:
            feature_mappings[feature] = found['index']
            print(f"Auto-mapped feature '{feature}'")
            continue

        # Ask user
        idx = ask_user(f"Feature: {feature}", required=True)
        feature_mappings[feature] = idx

    print("\n--- Mapping Complete ---")
    save_metadata(metadata_path, mappings, feature_mappings, header, benign_label)

# Now load data
def load_and_predict(path, mappings, feature_mappings, limit=5, benign_label='BENIGN'):
    print(f"\nReading {path}...")
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        next(reader) # skip header
        
        count = 0
        for row_idx, row in enumerate(reader):
            if count >= limit:
                break
            
            # Extract 5-tuple
            try:
                ts_idx = mappings.get('timestamp')
                if ts_idx is not None and ts_idx < len(row) and row[ts_idx]:
                     ts_val = row[ts_idx]
                else:
                     ts_val = str(datetime.now().timestamp())
                
                src_ip = row[mappings['src_ip']]
                dst_ip = row[mappings['dst_ip']]
                src_port = row[mappings['src_port']]
                dst_port = row[mappings['dst_port']]
                proto = row[mappings['protocol']]
                
                label_idx = mappings.get('label')
                original_label = "N/A"
                if label_idx is not None and label_idx < len(row):
                    original_label = row[label_idx]
                
                # Extract features
                features = {}
                for fk, fidx in feature_mappings.items():
                    val = row[fidx] if fidx < len(row) else 0
                    try:
                        features[fk] = float(val)
                    except:
                        features[fk] = 0.0
                
                # Print and Predict
                print(f"\n[{count+1}] {ts_val} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} proto={proto}")

                # DEBUG INSPECTION
                debug_cols = ['TotLen Fwd Pkts', 'Bwd Pkt Len Std', 'Bwd Pkt Len Mean', 
                              'TotLen Bwd Pkts', 'Bwd Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Max']
                print("    --- Debug Parsed Values ---")
                for dc in debug_cols:
                    # Get raw value if possible
                    raw_val = "N/A"
                    if dc in feature_mappings:
                         idx = feature_mappings[dc]
                         if idx < len(row):
                             raw_val = row[idx]
                    print(f"    {dc}: {features.get(dc, 'MISSING')} (Raw: '{raw_val}')")
                
                print(f"    Original Label: {original_label}")
                
                try:
                    start_time = time.time()
                    resp = requests.post(PREDICT_URL, json={'features': features}, timeout=5)
                    total_time = (time.time() - start_time) * 1000  # ms

                    if resp.status_code == 200:
                        res = resp.json()
                        print(f"    Prediction: {res.get('verdict')} (Action: {res.get('action')})")
                        
                        # Model Details
                        iso = res.get('isolation_forest', {})
                        xgb = res.get('xgb', {})
                        gnn = res.get('gnn', {})
                        
                        print(f"    [Isolation Forest] Anomaly: {iso.get('flag')} (Score: {iso.get('confidence')}, Delay: {iso.get('delay')})")
                        print(f"    [XGBoost]          Attack:  {xgb.get('flag')} (Conf: {xgb.get('confidence')}, Delay: {xgb.get('delay')})")
                        print(f"    [GNN]              Class:   {gnn.get('flag')} (Conf: {gnn.get('confidence')}, Delay: {gnn.get('delay')})")
                        
                        print(f"    Total Time: {total_time:.2f} ms")
                    else:
                        print(f"    Failed: {resp.status_code} {resp.text}")
                except Exception as e:
                    print(f"    Error: {e}")
                
                count += 1
                
            except IndexError:
                print(f"Skipping malformed row {row_idx}")
                continue
            except Exception as e:
                print(f"Error processing row {row_idx}: {e}")
                continue

load_and_predict(abs_path, mappings, feature_mappings, limit=5, benign_label=benign_label)

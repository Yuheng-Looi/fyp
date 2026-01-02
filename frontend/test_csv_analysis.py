import sys
import os
import csv
import json
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

csv_filename = "DrDoS_DNS_data_1_per.csv"
csv_path = f"uploads/csv/{csv_filename}"
abs_path = os.path.abspath(csv_path)
metadata_dir = os.path.join(os.path.dirname(abs_path), "../metadata")
metadata_path = os.path.join(metadata_dir, f"{csv_filename}.json")

PREDICT_URL = "http://10.100.10.15:8000/predict"

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

    # 1. Timestamp
    mappings['timestamp'] = ask_user("Timestamp (optional)", required=False)

    # 2. 5-tuple
    five_tuple_fields = [
        ('src_ip', 'Source IP'),
        ('dst_ip', 'Destination IP'),
        ('src_port', 'Source Port'),
        ('dst_port', 'Destination Port'),
        ('protocol', 'Protocol')
    ]

    for key, label in five_tuple_fields:
        mappings[key] = ask_user(label, required=True)
        
    # 3. Label
    mappings['label'] = ask_user("Label (optional)", required=False)
    
    # 4. Benign Label
    b_label = input("Enter Benign Label (default: BENIGN): ").strip()
    if b_label:
        benign_label = b_label

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
                print(f"    Original Label: {original_label}")
                
                try:
                    resp = requests.post(PREDICT_URL, json={'features': features}, timeout=5)
                    if resp.status_code == 200:
                        res = resp.json()
                        print(f"    Prediction: {res.get('verdict')} (conf: {res.get('confidence')})")
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

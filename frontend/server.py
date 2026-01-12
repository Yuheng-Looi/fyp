#!/usr/bin/env python3
import os
import uuid
import threading
import time
from datetime import datetime
from typing import List, Dict, Optional
import subprocess

from flask import Flask, request, jsonify, send_from_directory
import requests

import csv
import json
import numpy as np
import math
import traceback
import io

from cic_extractor import CICExtractor, FEATURE_KEYS

app = Flask(__name__)
# Increase max upload size to 2GB to avoid 413 Errors / Connection Resets on large datasets
app.config['MAX_CONTENT_LENGTH'] = 2048 * 1024 * 1024

if 'PREDICT_URL' in os.environ:
    PREDICT_URL = os.environ['PREDICT_URL']
else:
    # Default to infer_server.py location
    # If PREDICT_URL points to /predict, we strip it for the base methods
    PREDICT_URL = 'http://10.100.10.15:8000/predict'

def get_base_url():
    if '/predict' in PREDICT_URL:
        return PREDICT_URL.rsplit('/predict', 1)[0]
    return PREDICT_URL.rstrip('/')
SCALER_ID = os.environ.get('SCALER_ID', 'default')

# Persistent upload storage
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
PCAP_DIR = os.path.join(UPLOAD_DIR, 'pcaps')
CSV_DIR = os.path.join(UPLOAD_DIR, 'csv')
METADATA_DIR = os.path.join(UPLOAD_DIR, 'metadata')

for d in (UPLOAD_DIR, PCAP_DIR, CSV_DIR, METADATA_DIR):
    os.makedirs(d, exist_ok=True)

def get_metadata_path(filename):
    return os.path.join(METADATA_DIR, f"{filename}.json")

def load_metadata(filename):
    path = get_metadata_path(filename)
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except:
            return None
    return None

def save_metadata_file(filename, data):
    path = get_metadata_path(filename)
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)


class TrimmedDictReader:
    """A CSV DictReader wrapper that trims whitespace from field names."""
    def __init__(self, file_handle):
        self.reader = csv.DictReader(file_handle)
        # Trim the fieldnames
        if self.reader.fieldnames:
            self.reader.fieldnames = [f.strip() if f else f for f in self.reader.fieldnames]
    
    @property
    def fieldnames(self):
        return self.reader.fieldnames
    
    def __iter__(self):
        return self
    
    def __next__(self):
        row = next(self.reader)
        # Return row with trimmed keys
        return {k.strip() if k else k: v for k, v in row.items()}


def trim_metadata_values(metadata):
    """Trim all string values in metadata that represent column names."""
    if not metadata:
        return metadata
    
    trimmed = {}
    for key, value in metadata.items():
        if key == 'features' and isinstance(value, dict):
            trimmed['features'] = {k: v.strip() if isinstance(v, str) else v for k, v in value.items()}
        elif isinstance(value, str):
            trimmed[key] = value.strip()
        else:
            trimmed[key] = value
    return trimmed


def list_network_interfaces() -> List[Dict]:
    interfaces: List[Dict] = []
    try:
        output = subprocess.check_output(['ip', '-json', 'addr', 'show'], text=True)
        data = json.loads(output)
        for entry in data:
            name = entry.get('ifname')
            if not name:
                continue
            ipv4 = [addr.get('local') for addr in entry.get('addr_info', []) if addr.get('family') == 'inet' and addr.get('local')]
            interfaces.append({
                'name': name,
                'state': (entry.get('operstate') or 'UNKNOWN').upper(),
                'mac': entry.get('address'),
                'ipv4': ipv4
            })
    except Exception:
        try:
            for name in os.listdir('/sys/class/net'):
                state_path = os.path.join('/sys/class/net', name, 'operstate')
                state = 'UNKNOWN'
                try:
                    with open(state_path, 'r') as fh:
                        state = fh.read().strip().upper() or 'UNKNOWN'
                except Exception:
                    pass
                interfaces.append({'name': name, 'state': state, 'mac': None, 'ipv4': []})
        except Exception:
            pass

    seen = set()
    unique: List[Dict] = []
    for iface in interfaces:
        name = iface.get('name')
        if not name or name in seen:
            continue
        seen.add(name)
        unique.append(iface)

    def sort_key(item):
        priority = 0 if item['name'] in ('s1-snoop', 's1-eth3') else 1
        return (priority, item['name'])

    unique.sort(key=sort_key)
    return unique


TIMESTAMP_FORMATS = [
    '%m/%d/%Y %H:%M:%S',
    '%m/%d/%Y %H:%M',
    '%Y-%m-%d %H:%M:%S',
    '%Y-%m-%d %H:%M',
    '%d/%m/%Y %H:%M:%S',
    '%d/%m/%Y %H:%M',
    '%m/%d/%Y %I:%M:%S %p',
    '%m/%d/%Y %I:%M %p',
    '%Y-%m-%dT%H:%M:%S',
    '%Y-%m-%dT%H:%M:%S.%f'
]


def parse_timestamp_value(value):
    if value is None or value == '':
        return time.time()
    if isinstance(value, (int, float)):
        return float(value)

    text = str(value).strip()
    if not text:
        return time.time()

    try:
        return float(text)
    except Exception:
        pass

    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(text, fmt).timestamp()
        except Exception:
            continue

    try:
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return time.time()


class OfflineJob:
    def __init__(self, job_id: str, source_kind: str, src_path: str, label_column: Optional[str] = None, benign_label: str = 'BENIGN', metadata: Optional[Dict] = None, scaler_id: str = 'default', xgb_model: str = None, safetynet_model: str = None, gnn_model: str = None):
        self.id = job_id
        self.source_kind = source_kind  # 'pcap' or 'csv'
        self.src_path = src_path
        self.metadata = trim_metadata_values(metadata)
        self.label_column = label_column.strip().upper() if label_column else None
        self.benign_label = (benign_label or 'BENIGN').strip().upper()
        self.has_labels = bool(label_column) or (metadata and 'label' in metadata)
        self.scaler_id = scaler_id
        self.xgb_model = xgb_model
        self.safetynet_model = safetynet_model
        self.gnn_model = gnn_model
        
        self.lock = threading.Lock()
        self.paused = False
        self.done = False
        self.results: List[Dict] = []
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0
        
        # Prediction counts (for unlabelled data)
        self.pred_benign = 0
        self.pred_attack = 0
        
        # For streaming
        self.file_handle = None
        self.csv_reader = None
        self.processed_count = 0
        self.total_estimated = 0
        
        # Initialize file reading
        self._init_reader()

    def _init_reader(self):
        if self.source_kind == 'csv':
            # Estimate total lines (rough)
            try:
                # Quick line count
                # self.total_estimated = sum(1 for _ in open(self.src_path, 'rb')) - 1
                # Just set a placeholder, or count if fast enough. For large files, maybe just use file size?
                self.total_estimated = os.path.getsize(self.src_path) // 100 # Very rough estimate
            except:
                self.total_estimated = 1000

            self.file_handle = open(self.src_path, 'r', encoding='utf-8', errors='ignore')
            self.csv_reader = TrimmedDictReader(self.file_handle)
        else:
            # PCAP: Load all at once for now as scapy streaming is tricky without custom iterator
            # Or we can implement a generator for pcap too.
            # For now, keep PCAP as is (pre-loaded) but wrap in iterator interface
            self.pcap_entries = load_pcap_entries(self.src_path)
            self.total_estimated = len(self.pcap_entries)
            self.pcap_iter = iter(self.pcap_entries)

    def next_batch(self, batch_size=50) -> List[Dict]:
        batch = []
        if self.source_kind == 'csv':
            if not self.csv_reader:
                return []
            
            try:
                for _ in range(batch_size):
                    try:
                        row = next(self.csv_reader)
                        entry = self._parse_csv_row(row)
                        if entry:
                            batch.append(entry)
                    except StopIteration:
                        self.done = True
                        self.close()
                        break
            except Exception as e:
                print(f"Error reading CSV batch: {e}")
                self.done = True
                self.close()
                
        else:
            # PCAP
            for _ in range(batch_size):
                try:
                    entry = next(self.pcap_iter)
                    batch.append(entry)
                except StopIteration:
                    self.done = True
                    break
        
        self.processed_count += len(batch)
        return batch

    def _parse_csv_row(self, row) -> Optional[Dict]:
        feats: Dict[str, float] = {}
        missing = False
        
        if self.metadata:
            # Use metadata mapping
            meta_feats = self.metadata.get('features', {})
            for key in FEATURE_KEYS:
                col = meta_feats.get(key)
                val = row.get(col) if col else None
                if val is None or val == '':
                    val = 0.0
                try:
                    feats[key] = float(val)
                except:
                    feats[key] = 0.0
            
            # 4-tuple from metadata (protocol is now from features)
            src_ip = row.get(self.metadata.get('src_ip'))
            dst_ip = row.get(self.metadata.get('dst_ip'))
            src_port = row.get(self.metadata.get('src_port'))
            dst_port = row.get(self.metadata.get('dst_port'))
            timestamp = row.get(self.metadata.get('timestamp'))
            
            # Protocol comes from the features (it's one of the 15)
            proto = feats.get('Protocol', 0)
            
            label_col = self.metadata.get('label')
            label_val = row.get(label_col) if label_col else None
            
        else:
            # Auto-detection logic (Legacy)
            for key in FEATURE_KEYS:
                val = row.get(key)
                if val is None or val == '':
                    missing = True
                    break
                try:
                    feats[key] = float(val)
                except Exception:
                    feats[key] = 0.0
            if missing:
                return None

            def pick(r, *names):
                for n in names:
                    if not n: continue
                    if n in r and r[n]: return r[n]
                    for k in r.keys():
                        if k.lower() == n.lower() and r[k]: return r[k]
                return None

            src_ip = pick(row, 'src', 'Src IP', 'Source', 'Source IP', 'src_ip', 'IPV4_SRC_ADDR', 'source_ip', 'SrcAddr')
            dst_ip = pick(row, 'dst', 'Dst IP', 'Destination', 'Destination IP', 'dst_ip', 'IPV4_DST_ADDR', 'destination_ip', 'DstAddr')
            src_port = pick(row, 'sport', 'Src Port', 'Source Port', 'src_port', 'L4_SRC_PORT')
            dst_port = pick(row, 'dport', 'Dst Port', 'Destination Port', 'dst_port', 'L4_DST_PORT')
            timestamp = pick(row, 'timestamp', 'Timestamp', 'Flow Start', 'StartTime', 'Start Time', 'flow_start', 'ts')
            
            # Protocol from features
            proto = feats.get('Protocol', 0)
            
            label_val = None
            if self.label_column:
                label_val = row.get(self.label_column)

        def to_int(val) -> Optional[int]:
            if val is None: return None
            try: return int(float(val))
            except: return None

        ts_float = parse_timestamp_value(timestamp)

        # Protocol is already extracted from features as a number
        proto_int = int(proto) if proto else 0

        return {
            'timestamp': ts_float,
            'src_ip': src_ip or '',
            'dst_ip': dst_ip or '',
            'src_port': to_int(src_port) or 0,
            'dst_port': to_int(dst_port) or 0,
            'protocol': proto_int,
            'features': feats,
            'label': str(label_val).strip().upper() if label_val else None
        }

    def close(self):
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None

    def mark_done(self):
        self.done = True
        self.close()


    def metrics_summary(self) -> Optional[Dict]:
        total = self.pred_benign + self.pred_attack
        if not self.has_labels:
            # Return prediction counts for unlabelled data
            return {
                'labelled': False,
                'pred_benign': self.pred_benign,
                'pred_attack': self.pred_attack,
                'total': total
            }
        # Labelled data - return accuracy metrics
        if total == 0:
            return {'labelled': True, 'accuracy': 0.0, 'recall': 0.0, 'f1': 0.0, 'cm': [0, 0, 0, 0]}
        accuracy = (self.tp + self.tn) / total if total else 0.0
        recall = self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0
        precision = self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        return {
            'labelled': True,
            'accuracy': round(accuracy, 4),
            'recall': round(recall, 4),
            'f1': round(f1, 4),
            'cm': [self.tn, self.fp, self.fn, self.tp]
        }

    def update_metrics(self, true_label: str, pred_label: str):
        true_up = true_label.upper()
        pred_up = pred_label.upper()

        # Treat anything that is not the benign label as an attack/positive
        true_pos = (true_up != self.benign_label)

        # Model marks BENIGN explicitly; anything else is treated as attack
        pred_pos = (pred_up != 'BENIGN')

        if true_pos and pred_pos:
            self.tp += 1
        elif not true_pos and pred_pos:
            self.fp += 1
        elif true_pos and not pred_pos:
            self.fn += 1
        else:
            self.tn += 1


offline_jobs: Dict[str, OfflineJob] = {}
offline_jobs_lock = threading.Lock()


def save_upload(file_storage, dest_dir: str) -> Dict:
    name = file_storage.filename or f"upload_{int(time.time()*1000)}"
    safe = os.path.basename(name)
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, safe)
    file_storage.save(path)
    return {'name': safe, 'path': path}


def load_pcap_entries(path: str) -> List[Dict]:
    extractor = CICExtractor(iface=None, timeout=1.0, print_interval=0.2)
    flows = extractor.extract_offline(path, timeout=1.0)
    entries: List[Dict] = []
    for f in flows:
        entries.append({
            'timestamp': f['timestamp'],
            'src_ip': f['src'],
            'dst_ip': f['dst'],
            'src_port': f['sport'],
            'dst_port': f['dport'],
            'protocol': f['proto'],
            'features': f['features'],
            'label': None
        })
    return entries


def load_csv_entries(path: str, label_column: Optional[str] = None, limit: Optional[int] = None, metadata: Optional[Dict] = None, filter_label: Optional[str] = None, target_count: Optional[int] = None) -> List[Dict]:
    entries: List[Dict] = []
    
    # helper for flow id
    def parse_flow_id(flow_id: str):
        try:
            parts = flow_id.split('-')
            if len(parts) >= 5:
                src_ip, dst_ip, sport, dport, proto = parts[:5]
                return src_ip, dst_ip, int(sport), int(dport), int(proto)
        except Exception:
            pass
        return None, None, None, None, None

    # --- OPTIMIZATION: Use grep for sparse labels ---
    file_handle = None
    close_handle = True
    
    try:
        # Only use grep optimization if we are filtering for a specific label (like BENIGN) 
        # and we have a target count (so we know when to stop)
        if filter_label and target_count and os.name == 'posix':
            try:
                # 1. Read Header
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    header_line = f.readline()
                
                # 2. Grep for lines. 
                # Use -m to stop after finding enough matches.
                # We grep for the label string.
                # We ask for 3x target count to be safe against false matches in other columns.
                grep_limit = target_count * 3
                
                cmd = ['grep', '-m', str(grep_limit), filter_label, path]
                print(f"[FastLoad] Executing: {' '.join(cmd)}")
                
                grep_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, errors='ignore')
                stdout, _ = grep_proc.communicate()
                
                if stdout:
                    print(f"[FastLoad] Grep returned {len(stdout)} bytes of data.")
                    from io import StringIO
                    # Combine header + grep output
                    full_content = header_line + stdout
                    file_handle = StringIO(full_content)
                    close_handle = False # StringIO doesn't need explicit OS close like file, but good practice.
                else:
                     print("[FastLoad] Grep found nothing. Falling back to full scan.")
            except Exception as e:
                print(f"[FastLoad] Optimization failed: {e}. Falling back to normal.")
        
        # Fallback or normal open
        if file_handle is None:
            file_handle = open(path, 'r', encoding='utf-8', errors='ignore')

        reader = TrimmedDictReader(file_handle)
        
        # Trim metadata values if provided
        if metadata:
            metadata = trim_metadata_values(metadata)

        def pick(row, *names):
            # Try multiple casing/alias options for the same field
            for n in names:
                if not n:
                    continue
                if n in row and row[n]:
                    return row[n]
                # Case-insensitive fallback
                for key in row.keys():
                    if key.lower() == n.lower() and row[key]:
                        return row[key]
            return None

        for row in reader:
            feats: Dict[str, float] = {}
            missing = False
            
            if metadata:
                # Use metadata mapping
                meta_feats = metadata.get('features', {})
                for key in FEATURE_KEYS:
                    col = meta_feats.get(key)
                    val = row.get(col) if col else None
                    if val is None or val == '':
                        # Try to be lenient? Or strict?
                        # Let's assume 0.0 if missing in mapped column
                        val = 0.0
                    try:
                        feats[key] = float(val)
                    except:
                        feats[key] = 0.0
                
                src_ip = row.get(metadata.get('src_ip'))
                dst_ip = row.get(metadata.get('dst_ip'))
                src_port = row.get(metadata.get('src_port'))
                dst_port = row.get(metadata.get('dst_port'))
                proto = row.get(metadata.get('protocol'))
                timestamp = row.get(metadata.get('timestamp'))
                
                label_col = metadata.get('label')
                label_val = row.get(label_col) if label_col else None
                
            else:
                # Auto-detection logic
                for key in FEATURE_KEYS:
                    val = row.get(key)
                    if val is None or val == '':
                        missing = True
                        break
                    try:
                        feats[key] = float(val)
                    except Exception:
                        feats[key] = 0.0
                if missing:
                    continue

                # Primary picks
                src_ip = pick(row, 'src', 'Src IP', 'Source', 'Source IP', 'src_ip', 'IPV4_SRC_ADDR', 'source_ip', 'SrcAddr')
                dst_ip = pick(row, 'dst', 'Dst IP', 'Destination', 'Destination IP', 'dst_ip', 'IPV4_DST_ADDR', 'destination_ip', 'DstAddr')
                src_port = pick(row, 'sport', 'Src Port', 'Source Port', 'src_port', 'L4_SRC_PORT')
                dst_port = pick(row, 'dport', 'Dst Port', 'Destination Port', 'dst_port', 'L4_DST_PORT')
                proto = pick(row, 'proto', 'Protocol', 'protocol')
                timestamp = pick(row, 'timestamp', 'Timestamp', 'Flow Start', 'StartTime', 'Start Time', 'flow_start', 'ts')

                # Fallback: parse Flow ID for CIC Friday files
                if (not src_ip or not dst_ip) and 'Flow ID' in row:
                    f_src, f_dst, f_sport, f_dport, f_proto = parse_flow_id(row.get('Flow ID', ''))
                    src_ip = src_ip or f_src
                    dst_ip = dst_ip or f_dst
                    src_port = src_port or f_sport
                    dst_port = dst_port or f_dport
                    proto = proto or f_proto

                label_val = None
                if label_column:
                    label_val = row.get(label_column)
                    if label_val is not None:
                        label_val = str(label_val).strip()

            def to_int(val) -> Optional[int]:
                if val is None:
                    return None
                try:
                    return int(val)
                except Exception:
                    return None

            ts_float = parse_timestamp_value(timestamp)
            
            # Label normalization
            final_label = label_val.upper() if label_val else None

            # Filter Logic
            if filter_label:
                # If we are filtering, skip if label doesn't match
                if not final_label or final_label != filter_label.upper():
                    continue
                
            entries.append({
                'timestamp': ts_float,
                'src_ip': src_ip or '',
                'dst_ip': dst_ip or '',
                'src_port': to_int(src_port) or 0,
                'dst_port': to_int(dst_port) or 0,
                'protocol': to_int(proto) or 0,
                'features': feats,
                'label': final_label
            })
            
            # Stop if target count reached
            if target_count is not None and len(entries) >= target_count:
                break
                
            # Stop if total scanned limit reached (if limit provided)
            # Note: limit in this case acts as 'max rows to read', not 'max rows to collect' if filter is on.
            # But usually 'limit' in this legacy code meant 'max collected'.
            # If we want 'limit' to be 'max collected', then use the same check.
            if limit is not None and len(entries) >= limit:
                break
    finally:
        if file_handle and close_handle and hasattr(file_handle, 'close'):
            file_handle.close()
            
    return entries

# Live capture state
live_state = {
    'thread': None,
    'extractor': None,
    'flows': [],  # list of dicts: {timestamp, src, dst, sport, dport, proto, features, prediction}
    'running': False,
}
state_lock = threading.Lock()


def predict_one(features: Dict, src_ip: Optional[str] = None, dst_ip: Optional[str] = None, scaler_id: str = None, xgb_model: str = None, safetynet_model: str = None, gnn_model: str = None) -> Dict:
    payload_features = dict(features or {})
    if src_ip:
        payload_features.setdefault('src', src_ip)
    if dst_ip:
        payload_features.setdefault('dst', dst_ip)

    # Use provided scaler_id or fall back to global
    target_scaler = scaler_id if scaler_id else SCALER_ID
    
    payload = {
        'features': payload_features,
        'scaler_id': target_scaler
    }
    if xgb_model and xgb_model != 'default':
        payload['xgb_model'] = xgb_model.replace('.json', '')
    if safetynet_model and safetynet_model != 'default':
        payload['safetynet_model'] = safetynet_model.replace('.pkl', '')
    if gnn_model and gnn_model != 'default':
        payload['gnn_model'] = gnn_model.replace('.pt', '')
    
    try:
        resp = requests.post(PREDICT_URL, json=payload, timeout=2)
        if resp.status_code == 200:
            return resp.json()
        return {'verdict': 'UNKNOWN', 'confidence': 0.0, 'details': {}}
    except Exception:
        return {'verdict': 'UNAVAILABLE', 'confidence': 0.0, 'details': {}}


@app.route('/process_pcap', methods=['POST'])
def process_pcap():
    # 1. Handle Upload
    source_kind = 'pcap'
    if 'csv' in request.files or request.form.get('filetype') == 'csv':
        source_kind = 'csv'
    
    use_stored = request.form.get('filename') is not None

    if source_kind not in ('pcap', 'csv'):
        return jsonify({'error': 'source must be "pcap" or "csv"'}), 400

    label_column = None
    benign_label = request.form.get('benign_label', 'BENIGN')
    scaler_id = request.form.get('scaler_id', 'default')
    xgb_model = request.form.get('xgb_model', 'default')
    safetynet_model = request.form.get('safetynet_model', 'default')
    gnn_model = request.form.get('gnn_model', 'default')

    if source_kind == 'csv':
        if request.form.get('labelled', 'false').lower() == 'true':
            label_column = request.form.get('label_column')
            if not label_column:
                # If using metadata, label_column might be in metadata, so we can be lenient here if metadata exists
                pass 
            benign_label = request.form.get('benign_label', 'BENIGN')
        else:
            label_column = None
    else:
        # PCAP mode should not accept labels
        label_column = None

    src_path = None
    saved_name = None

    if use_stored:
        fname = request.form.get('filename')
        if not fname:
            return jsonify({'error': 'filename required when use_stored=true'}), 400
        base = PCAP_DIR if source_kind == 'pcap' else CSV_DIR
        candidate = os.path.join(base, os.path.basename(fname))
        if not os.path.exists(candidate):
            return jsonify({'error': f'stored file not found: {fname}'}), 404
        src_path = candidate
        saved_name = os.path.basename(candidate)
    else:
        upload_field = 'pcap' if source_kind == 'pcap' else 'csv'
        if upload_field not in request.files:
            return jsonify({'error': f'{upload_field} file required'}), 400
        saved = save_upload(request.files[upload_field], PCAP_DIR if source_kind == 'pcap' else CSV_DIR)
        src_path = saved['path']
        saved_name = saved['name']

    metadata = None
    if source_kind == 'csv':
        metadata = load_metadata(saved_name)
        if not metadata:
            # Return special status to prompt user for mapping
            # Read header
            header = []
            try:
                with open(src_path, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader(f)
                    header = next(reader)
            except:
                pass
            
            return jsonify({
                'status': 'mapping_needed',
                'filename': saved_name,
                'header': header,
                'feature_keys': FEATURE_KEYS
            })
        
        # If metadata exists, use it
        if 'benign_label' in metadata:
             benign_label = metadata['benign_label']

    try:
        # Don't load entries here anymore for CSV
        if source_kind == 'pcap':
            # PCAP still pre-loads for now (or refactor later)
            # But OfflineJob now expects src_path, not entries list for CSV
            pass
        else:
            # CSV: Just verify file exists
            if not os.path.exists(src_path):
                 return jsonify({'error': 'source file missing'}), 404
    except Exception as exc:
        return jsonify({'error': f'failed to parse source: {exc}'}), 500

    job_id = uuid.uuid4().hex
    # Pass src_path instead of entries
    job = OfflineJob(job_id, source_kind, src_path, label_column, benign_label, metadata, scaler_id, xgb_model, safetynet_model, gnn_model)

    with offline_jobs_lock:
        offline_jobs[job_id] = job

    # Return job ID immediately for async processing
    return jsonify({
        'job_id': job_id,
        'total': job.total_estimated, # Use estimated total
        'status': 'started'
    })

@app.route('/offline/next', methods=['GET'])
def offline_next():
    job_id = request.args.get('job')
    if not job_id:
        return jsonify({'status': 'error', 'error': 'job parameter required'}), 400

    with offline_jobs_lock:
        job = offline_jobs.get(job_id)
    if not job:
        return jsonify({'status': 'error', 'error': 'job not found'}), 404

    with job.lock:
        if job.done:
            metrics = job.metrics_summary()
            # Do not pop immediately if we want to allow fetching final metrics multiple times
            # But for now, let's keep it simple. If done, we return done.
            # The client should stop polling.
            return jsonify({'status': 'done', 'metrics': metrics, 'progress': job.processed_count, 'total': job.total_estimated})
        if job.paused:
            metrics = job.metrics_summary()
            return jsonify({'status': 'paused', 'progress': job.processed_count, 'total': job.total_estimated, 'metrics': metrics})
        
        # Process a batch of entries to speed up
        batch_size = 50  # Larger batch for faster completion
        results = []
        
        # Get next batch from job
        batch_entries = job.next_batch(batch_size)
        
        for entry in batch_entries:
            start_ts = time.time()
            pred = predict_one(entry.get('features'), entry.get('src_ip'), entry.get('dst_ip'), job.scaler_id, job.xgb_model, job.safetynet_model, job.gnn_model)
            latency = time.time() - start_ts
            
            verdict = pred.get('verdict', 'UNKNOWN')
            action = pred.get('action')
            if not action:
                action = 'BLOCK' if verdict not in ['BENIGN', 'UNKNOWN', 'UNAVAILABLE'] else 'ALLOW'

            iso_forest = pred.get('isolation_forest', {})
            xgb_model = pred.get('xgb', {})
            gnn_model = pred.get('gnn', {})

            gnn_verdict = gnn_model.get('flag')
            gnn_conf = gnn_model.get('confidence')

            details = {
                'isolation_forest': iso_forest,
                'xgb': xgb_model,
                'gnn': gnn_model
            }
            
            result = {
                'timestamp': entry.get('timestamp', time.time()),
                'src_ip': entry.get('src_ip', ''),
                'dst_ip': entry.get('dst_ip', ''),
                'src_port': entry.get('src_port', 0),
                'dst_port': entry.get('dst_port', 0),
                'protocol': entry.get('protocol', 0),
                'prediction': verdict,
                'action': action,
                'confidence': xgb_model.get('confidence', 0.0),
                'gnn_verdict': gnn_verdict,
                'gnn_confidence': gnn_conf,
                'details': details,
                'latency_ms': round(latency * 1000.0, 2),
                'features': entry.get('features', {}),  # Include the 15 features as nested object
                'benign_label': job.benign_label
            }
            
            # Track prediction counts
            if verdict == 'BENIGN':
                job.pred_benign += 1
            else:
                job.pred_attack += 1

            label = entry.get('label')
            if label:
                result['label'] = label
                job.update_metrics(label, verdict)
            
            results.append(result)
            job.results.append(result)

        metrics = job.metrics_summary()
        
        if job.done:
            # Job finished in this batch
            pass
            
    if job.done:
        with offline_jobs_lock:
            offline_jobs.pop(job_id, None)

    status = 'done' if job.done else 'ok'
    return jsonify({
        'status': status,
        'results': results, # Return list of results
        'progress': job.processed_count,
        'total': job.total_estimated,
        'metrics': metrics
    })



@app.route('/offline/control', methods=['POST'])
def offline_control():
    data = request.get_json(force=True)
    job_id = data.get('job')
    action = data.get('action')
    if not job_id or action not in ('pause', 'resume', 'stop'):
        return jsonify({'error': 'job and valid action required'}), 400

    with offline_jobs_lock:
        job = offline_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'job not found'}), 404

    with job.lock:
        if action == 'pause':
            job.paused = True
        elif action == 'resume':
            job.paused = False
        elif action == 'stop':
            job.mark_done()
            job.paused = False
    if action == 'stop':
        with offline_jobs_lock:
            offline_jobs.pop(job_id, None)

    metrics = job.metrics_summary()
    return jsonify({
        'status': 'ok',
        'action': action,
        'progress': job.processed_count,
        'total': job.total_estimated,
        'metrics': metrics
    })


def live_loop():
    ext = live_state['extractor']
    if not ext:
        return
    ext.start()


@app.route('/start_iface', methods=['POST'])
def start_iface():
    data = request.get_json(force=True)
    iface = data.get('iface')
    scaler_id = data.get('scaler_id', 'default')
    xgb_model = data.get('xgb_model', 'default')
    safetynet_model = data.get('safetynet_model', 'default')
    gnn_model = data.get('gnn_model', 'default')

    if not iface:
        return jsonify({'error': 'iface required'}), 400

    with state_lock:
        if live_state['running']:
            return jsonify({'status': 'already_running'}), 200
        
        live_state['scaler_id'] = scaler_id
        live_state['xgb_model'] = xgb_model
        live_state['safetynet_model'] = safetynet_model
        live_state['gnn_model'] = gnn_model

        # Create extractor that appends to live_state flows in flush
        class LiveCIC(CICExtractor):
            def flush_flow(self, key):
                flow = self.flows.pop(key, None)
                if not flow:
                    return
                feats = flow.compute_features()
                src, dst, sport, dport, proto = flow.key
                
                sid = live_state.get('scaler_id', 'default')
                mod_xgb = live_state.get('xgb_model', 'default')
                mod_sn = live_state.get('safetynet_model', 'default')
                mod_gnn = live_state.get('gnn_model', 'default')
                
                pred = predict_one({kk: feats[kk] for kk in FEATURE_KEYS}, src, dst, sid, mod_xgb, mod_sn, mod_gnn)
                
                verdict = pred.get('verdict', 'UNKNOWN')
                action = pred.get('action')
                if not action:
                    action = 'BLOCK' if verdict not in ['BENIGN', 'UNKNOWN', 'UNAVAILABLE'] else 'ALLOW'

                iso_forest = pred.get('isolation_forest', {})
                xgb_model = pred.get('xgb', {})
                gnn_model = pred.get('gnn', {})

                gnn_verdict = gnn_model.get('flag')
                gnn_conf = gnn_model.get('confidence')

                details = {
                    'isolation_forest': iso_forest,
                    'xgb': xgb_model,
                    'gnn': gnn_model
                }

                record = {
                    'timestamp': flow.last_time,
                    'src_ip': src,
                    'dst_ip': dst,
                    'src_port': sport,
                    'dst_port': dport,
                    'protocol': proto,
                    'prediction': verdict,
                    'action': action,
                    'confidence': xgb_model.get('confidence', 0.0),
                    'gnn_verdict': gnn_verdict,
                    'gnn_confidence': gnn_conf,
                    'details': details
                }
                live_state['flows'].append(record)
        live_state['extractor'] = LiveCIC(iface=iface, timeout=0.5, print_interval=0.1)
        live_state['flows'] = []
        live_state['running'] = True
        t = threading.Thread(target=live_loop, daemon=True)
        live_state['thread'] = t
        t.start()
    return jsonify({'status': 'started'})


@app.route('/stop_iface', methods=['POST'])
def stop_iface():
    with state_lock:
        ext = live_state.get('extractor')
        if ext:
            ext.stop()
        live_state['running'] = False
    return jsonify({'status': 'stopped'})


@app.route('/flows', methods=['GET'])
def list_flows():
    with state_lock:
        return jsonify({'flows': live_state['flows'], 'running': live_state['running']})


@app.route('/stored_files', methods=['GET'])
def stored_files():
    def describe(dir_path):
        items = []
        try:
            for name in sorted(os.listdir(dir_path)):
                full = os.path.join(dir_path, name)
                if not os.path.isfile(full):
                    continue
                stat = os.stat(full)
                items.append({
                    'name': name,
                    'size': stat.st_size,
                    'mtime': stat.st_mtime
                })
        except Exception:
            pass
        return items
    return jsonify({'pcaps': describe(PCAP_DIR), 'csvs': describe(CSV_DIR)})


@app.route('/interfaces', methods=['GET'])
def list_interfaces_route():
    interfaces = list_network_interfaces()
    return jsonify({'interfaces': interfaces})


@app.route('/csv_headers', methods=['GET'])
def csv_headers():
    """Get the headers of a stored CSV file."""
    filename = request.args.get('filename')
    if not filename:
        return jsonify({'error': 'filename required'}), 400
    
    filepath = os.path.join(CSV_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'file not found'}), 404
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            first_line = f.readline().strip()
            headers = [h.strip().replace('"', '') for h in first_line.split(',')]
            return jsonify({'headers': headers})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/get_mapping', methods=['GET'])
def get_mapping():
    """Get existing column mapping for a CSV file."""
    filename = request.args.get('filename')
    if not filename:
        return jsonify({'error': 'filename required'}), 400
    
    metadata = load_metadata(filename)
    if metadata:
        return jsonify(metadata)
    return jsonify({}), 404


@app.route('/save_mapping', methods=['POST'])
def save_mapping_route():
    """Save column mapping for a CSV file."""
    data = request.get_json(force=True)
    filename = data.get('filename')
    mapping = data.get('mapping')
    
    if not filename or not mapping:
        return jsonify({'error': 'filename and mapping required'}), 400
    
    # Trim all column name values before saving
    trimmed_mapping = trim_metadata_values(mapping)
    save_metadata_file(filename, trimmed_mapping)
    return jsonify({'status': 'ok'})


@app.route('/save_file', methods=['POST'])
def save_file():
    """Save an uploaded file to permanent storage without processing."""
    if 'pcap' in request.files:
        saved = save_upload(request.files['pcap'], PCAP_DIR)
        return jsonify({'status': 'ok', 'name': saved['name'], 'type': 'pcap'})
    elif 'csv' in request.files:
        saved = save_upload(request.files['csv'], CSV_DIR)
        return jsonify({'status': 'ok', 'name': saved['name'], 'type': 'csv'})
    else:
        return jsonify({'error': 'No file provided'}), 400


@app.route('/analyze_recalibration', methods=['POST'])
def analyze_recalibration():
    # 1. Handle File (Upload or Stored)
    scaler_id = request.form.get('scaler_id', 'default')
    use_stored = request.form.get('filename') is not None
    src_path = None
    saved_name = None
    
    if use_stored:
        fname = request.form.get('filename')
        # We only support CSV for this
        if not fname:
            return jsonify({'error': 'filename required'}), 400
        candidate = os.path.join(CSV_DIR, os.path.basename(fname))
        if not os.path.exists(candidate):
            return jsonify({'error': f'stored file not found: {fname}'}), 404
        src_path = candidate
        saved_name = os.path.basename(candidate)
    else:
        if 'csv' not in request.files:
            return jsonify({'error': 'csv file required'}), 400
        saved = save_upload(request.files['csv'], CSV_DIR)
        src_path = saved['path']
        saved_name = saved['name']

    # 2. Handle Mapping
    mapping_str = request.form.get('mapping')
    metadata = None
    if mapping_str:
        try:
            metadata = json.loads(mapping_str)
        except:
            pass
    
    # If no mapping provided, try to load from disk
    if not metadata:
        metadata = load_metadata(saved_name)

    if not metadata:
        return jsonify({'error': 'Column mapping required'}), 400

    # 3. Determine Sample Size & Load CSV
    try:
        # Check if labelled data
        is_labelled = False
        target_benign_label = None
        target_benign_count = 30000
        
        if metadata and metadata.get('label'):
            is_labelled = True
            target_benign_label = metadata.get('benign_label', 'BENIGN')
            
        if is_labelled:
            # 3000 Benign samples logic
            print(f"[Analysis] Labelled data detected. Searching for up to {target_benign_count} '{target_benign_label}' samples...")
            
            # We pass limit=None (or very large) because we need to scan until we find the targets.
            # But maybe safety cap is still good? Let's say max 1M rows scan to find 3000 benigns.
            entries = load_csv_entries(
                src_path, 
                metadata=metadata, 
                filter_label=target_benign_label, 
                target_count=target_benign_count, 
                limit=1000000 # Safety scan limit
            )
            
            if len(entries) < target_benign_count:
                print(f"[Analysis] Warning: Only found {len(entries)} benign samples (Target: {target_benign_count}). Using all available samples.")
            else:
                 print(f"[Analysis] Successfully collected {target_benign_count} benign samples.")
                 
        else:
            # Unlabelled - 20% Logic
            # Fast line count
            total_lines = 0
            try:
                # Use wc -l if available (Linux)
                output = subprocess.check_output(['wc', '-l', src_path], text=True)
                total_lines = int(output.split()[0])
            except:
                # Fallback to python read
                with open(src_path, 'rb') as f:
                    total_lines = sum(1 for _ in f)
            
            # We need 20%
            # total_lines includes header, so rough estimate is fine
            limit = int(total_lines * 0.2)
            
            # Hard cap to prevent timeout on massive files (e.g. max 100k samples)
            # 100k samples is statistically more than enough for IQR/Median
            max_samples = 100000
            if limit > max_samples:
                print(f"[Analysis] Capping sample size at {max_samples} (20% was {limit})")
                limit = max_samples
                
            if limit < 100: limit = 100 # Min samples
            
            print(f"[Analysis] Loading ~{limit} samples from {total_lines} total lines (Unlabelled)...")
            entries = load_csv_entries(src_path, metadata=metadata, limit=limit)
        
    except Exception as e:
         return jsonify({'error': f'Failed to parse CSV: {str(e)}'}), 500

    if not entries:
         return jsonify({'error': 'No entries found in CSV'}), 400

    print(f"[Analysis] Loaded {len(entries)} samples.")

    # 4. Fetch Baseline Stats
    baseline = {}
    try:
        if '/' in PREDICT_URL:
            base_url = PREDICT_URL.rsplit('/', 1)[0]
        else:
            base_url = PREDICT_URL 
        
        url = f"{base_url}/scaler_stats?scaler_id={scaler_id}"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            baseline = resp.json()
        else:
            return jsonify({'error': 'Failed to fetch baseline stats from backend'}), 500
    except Exception as e:
        return jsonify({'error': f'Failed to connect to backend: {str(e)}'}), 500

    # 5. Compute Stats & Compare
    results = []
    consistent_count = 0
    valid_features_count = 0
    shift_magnitudes = []
    missing_features = []

    # Optimize: Single pass aggregation
    print("[Analysis] Aggregating feature values...")
    feature_buckets = {k: [] for k in FEATURE_KEYS}
    
    for e in entries:
        feats = e.get('features', {})
        for k in FEATURE_KEYS:
            v = feats.get(k)
            if v is not None:
                feature_buckets[k].append(v)
    
    print("[Analysis] Computing statistics...")
    for i, key in enumerate(FEATURE_KEYS):
        vals = feature_buckets[key]
        
        # 1. Data Sanitization
        if not vals:
            missing_features.append(key)
            continue
            
        arr = np.array(vals, dtype=float)
        
        # Remove NaN and Inf
        arr = arr[np.isfinite(arr)]
        
        # Check sample count
        if len(arr) < 1000:
            status = "unstable (insufficient clean samples)"
            results.append({
                'feature': key,
                'median_ratio': 1.0,
                'iqr_ratio': 1.0,
                'status': status
            })
            continue # Exclude from decision metrics
        
        valid_features_count += 1
        
        # 2. Statistics (Median & IQR)
        median_new = float(np.median(arr))
        q75, q25 = np.percentile(arr, [75, 25])
        iqr_new = float(q75 - q25)
        if iqr_new <= 1e-9: iqr_new = 1e-6
        
        ref = baseline.get(key)
        if not ref:
             continue
             
        median_ref = float(ref.get('median', 0.0))
        iqr_ref = float(ref.get('iqr', 1e-6))
        if iqr_ref <= 1e-9: iqr_ref = 1e-6

        # 3. Ratio Computation with Noise Dead-Zone
        # Median Ratio
        if abs(median_ref) < 1e-9:
             # If baseline median is 0, we can't divide.
             # If new median is also near 0, ratio is 1. Else large.
             if abs(median_new) < 1e-9:
                 median_ratio = 1.0
             else:
                 median_ratio = 999.0 # Large shift
        else:
             median_ratio = median_new / median_ref

        # Apply dead-zone to median_ratio
        if median_ratio > 1e-9 and abs(math.log(median_ratio)) < 0.05:
            median_ratio = 1.0

        # IQR Ratio
        iqr_ratio = iqr_new / iqr_ref
        
        # Apply dead-zone to iqr_ratio
        if iqr_ratio > 1e-9 and abs(math.log(iqr_ratio)) < 0.05:
            iqr_ratio = 1.0
        
        # 4. Shape Consistency
        if abs(iqr_ratio) < 1e-9:
             ratio_of_ratios = 0
        else:
             ratio_of_ratios = median_ratio / iqr_ratio
            
        status = "shape_changed"
        if 0.5 <= ratio_of_ratios <= 2.0:
            status = "scale_consistent"
            consistent_count += 1
            
        results.append({
            'feature': key,
            'median_ratio': median_ratio,
            'iqr_ratio': iqr_ratio,
            'status': status
        })
        
        # 5. Shift Magnitude
        if median_ratio > 1e-9:
            shift_magnitudes.append(abs(math.log(median_ratio)))
        else:
            shift_magnitudes.append(5.0) # Penalty for non-positive or zero ratio

    print("[Analysis] Calculation finished.")
        
    if missing_features:
        return jsonify({'error': f'Missing features in CSV: {missing_features}'}), 400
        
    # 6. Global Decision Logic
    try:
        shape_score = consistent_count / valid_features_count if valid_features_count > 0 else 0
        avg_shift = float(np.mean(shift_magnitudes)) if shift_magnitudes else 0.0
        
        if shape_score < 0.6:
            recommendation = "RETRAIN"
        elif avg_shift <= 0.1:
            recommendation = "NO ACTION"
        else:
            recommendation = "RESCALE"
            
        # Sanitize results for JSON compliance (no NaN/Inf)
        sanitized_results = []
        for r in results:
            m_rat = r['median_ratio']
            i_rat = r['iqr_ratio']
            
            # Check for NaN/Inf
            if math.isnan(m_rat) or math.isinf(m_rat): m_rat = 0.0
            if math.isnan(i_rat) or math.isinf(i_rat): i_rat = 0.0
            
            sanitized_results.append({
                'feature': r['feature'],
                'median_ratio': m_rat,
                'iqr_ratio': i_rat,
                'status': r['status']
            })
            
        return jsonify({
            'results': sanitized_results,
            'shape_score': float(shape_score),
            'scale_score': float(shape_score), # For frontend compatibility
            'avg_shift': float(avg_shift),
            'recommendation': recommendation,
            'valid_features': valid_features_count
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'Server Error during response generation: {str(e)}'}), 500


@app.route('/')
@app.route('/dashboard.html')
def serve_dashboard():
    return send_from_directory('.', 'dashboard.html')

@app.route('/api/scaler_stats')
def proxy_scaler_stats():
    try:
        base_url = get_base_url()
        scaler_id = request.args.get('scaler_id', SCALER_ID)
        url = f"{base_url}/scaler_stats?scaler_id={scaler_id}"
        print(f"Fetching stats from: {url}")
        resp = requests.get(url, timeout=5)
        return jsonify(resp.json())
    except Exception as e:
        print(f"Error fetching scaler stats: {e}")
        return jsonify({'error': str(e)}), 500

# --- Proxy Endpoints for Retrieve/Rescale ---

@app.route('/api/scalers', methods=['GET'])
def proxy_list_scalers():
    try:
        base = get_base_url()
        print(f"Proxying list_scalers to: {base}/scalers")
        resp = requests.get(f"{base}/scalers", timeout=5)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        print(f"Error in proxy_list_scalers: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/models', methods=['GET'])
def proxy_list_models():
    try:
        base = get_base_url()
        print(f"Proxying list_models to: {base}/models")
        resp = requests.get(f"{base}/models", timeout=5)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        print(f"Error in proxy_list_models: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/rescale', methods=['POST'])
def proxy_rescale():
    if 'csv' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['csv']
    scaler_name = request.form.get('scaler_name')
    
    # Mapping and Label params
    mapping_file = request.form.get('mapping_source_file')
    mapping_str = request.form.get('mapping')
    
    # Strict boolean parsing
    is_labelled = str(request.form.get('labelled', '')).lower() == 'true'
    label_col = request.form.get('label_col')
    benign_label = request.form.get('benign_label', 'BENIGN')
    
    try:
        # 1. Resolve Mapping (Mandatory)
        metadata = None
        if mapping_file:
             metadata = load_metadata(mapping_file)
        elif mapping_str:
             try:
                 parsed = json.loads(mapping_str)
                 if isinstance(parsed, dict):
                    metadata = {'features': parsed} if 'features' not in parsed else parsed
             except:
                 pass
                 
        if not metadata or 'features' not in metadata:
            return jsonify({'error': 'Column mapping is required for rescaling'}), 400

        # 2. Save Upload temporarily for processing
        temp_dir = os.path.join(UPLOAD_DIR, 'temp_rescale')
        os.makedirs(temp_dir, exist_ok=True)
        temp_path = os.path.join(temp_dir, f"rescale_{uuid.uuid4().hex}.csv")
        file.save(temp_path)
        
        try:
            # 3. Load & Filter Data taking 10k Benign
            target_count = 10000
            filter_lbl = benign_label if is_labelled else None
            
            # Construct metadata for loader
            load_meta = metadata.copy()
            if is_labelled and label_col:
                load_meta['label'] = label_col
                
            print(f"[Rescale] Loading samples from {temp_path}. Labelled={is_labelled}, Filter={filter_lbl}")
                
            entries = load_csv_entries(
                temp_path,
                metadata=load_meta,
                filter_label=filter_lbl,
                target_count=target_count,
                 # If unlabelled, just take first 10k by setting limit/target
                limit=target_count if not is_labelled else None 
            )
            
            if not entries:
                 return jsonify({'error': f'No valid samples found (Labelled={is_labelled}, Label={filter_lbl})'}), 400
                 
            # Allow smaller datasets (user request: use all even if < 10000, and ensure we don't error on small valid sets)
            if len(entries) < 10:
                 return jsonify({'error': f'Insufficient samples ({len(entries)}) found for rescaling. Need at least 10.'}), 400

            print(f"[Rescale] Collected {len(entries)} valid samples for rescaling.")

            # 4. Generate Clean CSV for Backend
            # We write ONLY the 15 features, using standard names.
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=FEATURE_KEYS)
            writer.writeheader()
            
            for e in entries:
                writer.writerow(e['features'])
                
            output.seek(0)
            
            # 5. Send to Backend
            base = get_base_url()
            data = {'name': scaler_name} if scaler_name else {}
            # No mapping needed since columns are standardized
            
            # Streaming the StringIO requires encoding? requests handles it usually if file-like
            # But StringIO is text, files usually expect bytes. 
            # Flask/Requests might handle text/csv
            # Safe bet: encode to bytes
            mem_file = io.BytesIO(output.getvalue().encode('utf-8'))
            
            files = {'file': ('rescaled_cleaned.csv', mem_file, 'text/csv')}
            
            resp = requests.post(f"{base}/refit_scaler", files=files, data=data, timeout=120)
            return jsonify(resp.json()), resp.status_code

        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/retrain', methods=['POST'])
def proxy_retrain():
    if 'csv' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['csv']
    model_type = request.form.get('model_type')
    model_name = request.form.get('model_name')
    label_col = request.form.get('label_col', 'Label')
    benign_label = request.form.get('benign_label', 'BENIGN')
    scaler_id = request.form.get('scaler_id', 'default')
    
    mapping_file = request.form.get('mapping_source_file')
    mapping_str = request.form.get('mapping')
    
    if not model_type or not model_name:
         return jsonify({'error': 'model_type and model_name required'}), 400
         
    # Enforce Mapping (Mandatory as per request)
    metadata = None
    if mapping_file:
         metadata = load_metadata(mapping_file)
    elif mapping_str:
         try:
             parsed = json.loads(mapping_str)
             if isinstance(parsed, dict):
                metadata = {'features': parsed} if 'features' not in parsed else parsed
         except: pass
         
    if not metadata or 'features' not in metadata:
         return jsonify({'error': 'Column mapping is required for retraining'}), 400
         
    try:
        base = get_base_url()
            
        files = {'file': (file.filename, file.stream, file.mimetype)}
        data = {
            'model_name': model_name,
            'label_col': label_col,
            'benign_label': benign_label,
            'scaler_id': scaler_id,
            'mapping': json.dumps(metadata['features']) # Pass explicit mapping
        }
        
        # If mapping file provided, load its metadata (Already done above)
        
        # retrain path
        resp = requests.post(f"{base}/retrain/{model_type}", files=files, data=data, timeout=300)
        try:
            return jsonify(resp.json()), resp.status_code
        except:
             return jsonify({'error': 'Invalid JSON from backend', 'text': resp.text}), resp.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

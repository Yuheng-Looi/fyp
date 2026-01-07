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

from cic_extractor import CICExtractor, FEATURE_KEYS

app = Flask(__name__)

PREDICT_URL = os.environ.get('PREDICT_URL', 'http://10.100.10.15:8000/predict')
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
    def __init__(self, job_id: str, source_kind: str, src_path: str, label_column: Optional[str] = None, benign_label: str = 'BENIGN', metadata: Optional[Dict] = None):
        self.id = job_id
        self.source_kind = source_kind  # 'pcap' or 'csv'
        self.src_path = src_path
        self.metadata = trim_metadata_values(metadata)
        self.label_column = label_column.strip().upper() if label_column else None
        self.benign_label = (benign_label or 'BENIGN').strip().upper()
        self.has_labels = bool(label_column) or (metadata and 'label' in metadata)
        
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


def load_csv_entries(path: str, label_column: Optional[str] = None, limit: Optional[int] = None, metadata: Optional[Dict] = None) -> List[Dict]:
    entries: List[Dict] = []

    def parse_flow_id(flow_id: str):
        # Example CIC flow id format: "172.31.69.25-172.31.69.28-54890-80-6"
        try:
            parts = flow_id.split('-')
            if len(parts) >= 5:
                src_ip, dst_ip, sport, dport, proto = parts[:5]
                return src_ip, dst_ip, int(sport), int(dport), int(proto)
        except Exception:
            pass
        return None, None, None, None, None

    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
        reader = TrimmedDictReader(fh)
        
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

            entries.append({
                'timestamp': ts_float,
                'src_ip': src_ip or '',
                'dst_ip': dst_ip or '',
                'src_port': to_int(src_port) or 0,
                'dst_port': to_int(dst_port) or 0,
                'protocol': to_int(proto) or 0,
                'features': feats,
                'label': label_val.upper() if label_val else None
            })
            if limit is not None and len(entries) >= limit:
                break
    return entries

# Live capture state
live_state = {
    'thread': None,
    'extractor': None,
    'flows': [],  # list of dicts: {timestamp, src, dst, sport, dport, proto, features, prediction}
    'running': False,
}
state_lock = threading.Lock()


def predict_one(features: Dict, src_ip: Optional[str] = None, dst_ip: Optional[str] = None) -> Dict:
    payload_features = dict(features or {})
    if src_ip:
        payload_features.setdefault('src', src_ip)
    if dst_ip:
        payload_features.setdefault('dst', dst_ip)

    payload = {
        'features': payload_features,
        'scaler_id': SCALER_ID
    }
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
    job = OfflineJob(job_id, source_kind, src_path, label_column, benign_label, metadata)

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
            pred = predict_one(entry.get('features'), entry.get('src_ip'), entry.get('dst_ip'))
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
    if not iface:
        return jsonify({'error': 'iface required'}), 400

    with state_lock:
        if live_state['running']:
            return jsonify({'status': 'already_running'}), 200
        # Create extractor that appends to live_state flows in flush
        class LiveCIC(CICExtractor):
            def flush_flow(self, key):
                flow = self.flows.pop(key, None)
                if not flow:
                    return
                feats = flow.compute_features()
                src, dst, sport, dport, proto = flow.key
                pred = predict_one({kk: feats[kk] for kk in FEATURE_KEYS}, src, dst)
                
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


@app.route('/')
@app.route('/dashboard.html')
def serve_dashboard():
    return send_from_directory('.', 'dashboard.html')

@app.route('/api/scaler_stats')
def proxy_scaler_stats():
    # PREDICT_URL is like "http://.../predict"
    # We want "http://.../scaler_stats"
    if '/' in PREDICT_URL:
        base_url = PREDICT_URL.rsplit('/', 1)[0]
    else:
        base_url = PREDICT_URL 
        
    try:
        # Pass the SCALER_ID env var if set
        url = f"{base_url}/scaler_stats?scaler_id={SCALER_ID}"
        print(f"Fetching stats from: {url}")
        resp = requests.get(url, timeout=5)
        return jsonify(resp.json())
    except Exception as e:
        print(f"Error fetching scaler stats: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

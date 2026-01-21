import uvicorn
import pandas as pd
import joblib
import numpy as np
import xgboost as xgb
import uuid
import os
import glob
import json
import torch
import pickle
import time
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Any, Union, Optional
from sklearn.metrics import accuracy_score, recall_score, f1_score, confusion_matrix, precision_score, roc_auc_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from torch_geometric.data import Data

from anomaly_utils import SafetyNet
from xgb_utils import XGBDetector
from scaler_utils import TriChannelScaler
import gnn_utils

app = FastAPI(title="IDS Inference Engine")
model_store = {}
scaler_store = {}
encoder_store = {}
training_jobs = {} # {job_id: {status: 'running'|'completed'|'failed', result: {}, error: str}}



# This list must match training features (15 features from cleaned_data15.csv)
EXPECTED_COLUMNS = [
    'Fwd Header Len', 'Protocol', 'Init Bwd Win Byts', 'Tot Fwd Pkts',
    'Pkt Len Max', 'Pkt Len Mean', 'Tot Bwd Pkts', 'Dst Port',
    'Bwd Pkt Len Max', 'Fwd Pkts/s', 'Flow IAT Max', 'TotLen Bwd Pkts',
    'TotLen Fwd Pkts', 'Bwd Pkt Len Std', 'Bwd Pkt Len Mean'
]

# Column mapping for different CICFlowMeter versions
COLUMN_MAPPING = {
    'Fwd Header Length': 'Fwd Header Len',
    'Bwd Init Win Bytes': 'Init Bwd Win Byts',
    'Total Fwd Packet': 'Tot Fwd Pkts',
    'Packet Length Max': 'Pkt Len Max',
    'Packet Length Mean': 'Pkt Len Mean',
    'Total Bwd packets': 'Tot Bwd Pkts',
    'Bwd Packet Length Max': 'Bwd Pkt Len Max',
    'Fwd Packets/s': 'Fwd Pkts/s',
    'Total Length of Bwd Packet': 'TotLen Bwd Pkts',
    'Total Length of Fwd Packet': 'TotLen Fwd Pkts',
    'Bwd Packet Length Std': 'Bwd Pkt Len Std',
    'Bwd Packet Length Mean': 'Bwd Pkt Len Mean'
}

@app.on_event("startup")
def load_artifacts():
    print("[-] Loading artifacts...")
    try:
        # SafetyNet (joblib pickle)
        if os.path.exists('models/safetynet/safety_net_v1.pkl'):
            sn = joblib.load('models/safetynet/safety_net_v1.pkl')
            model_store['safety_net'] = sn
        else:
            print("[!] SafetyNet model not found.")

        # XGBoost (JSON)
        if os.path.exists('models/xgb/xgb_binary_v1.json'):
            xgb_model = xgb.XGBClassifier()
            xgb_model.load_model('models/xgb/xgb_binary_v1.json')
            xgb_det = XGBDetector()
            xgb_det.model = xgb_model
            model_store['xgb'] = xgb_det
        else:
            print("[!] XGBoost model not found.")
        
        # Default Scaler
        if os.path.exists('scalers/trichannel_scaler.pkl'):
            default_scaler = joblib.load('scalers/trichannel_scaler.pkl')
            scaler_store['default'] = default_scaler
        else:
            print("[!] Default TriChannelScaler not found.")

        # GNN Multiclass Model
        gnn_config_path = 'models/gnn/best_multiclass_config.json'
        gnn_model_path = 'models/gnn/best_multiclass_gnn.pt'
        default_encoder_path = 'encoders/label_encoder.pkl'
        
        if os.path.exists(gnn_config_path) and os.path.exists(gnn_model_path):
            print("[-] Loading GNN Multiclass model...")
            with open(gnn_config_path, 'r') as f:
                gnn_config = json.load(f)
            
            # Determine encoder to load
            # Check config for specific encoder path first
            specific_encoder_path = gnn_config.get('info', {}).get('encoder_path')
            le = None
            
            if specific_encoder_path and os.path.exists(specific_encoder_path):
                print(f"[-] Loading specific GNN encoder: {specific_encoder_path}")
                with open(specific_encoder_path, 'rb') as f:
                    le = pickle.load(f)
            elif os.path.exists(default_encoder_path):
                print(f"[-] Loading default encoder: {default_encoder_path}")
                with open(default_encoder_path, 'rb') as f:
                    le = pickle.load(f)
            
            if le is not None:
                encoder_store['label_encoder'] = le
            else:
                print("[!] Error: No label encoder found (neither specific nor default).")

            # Initialize Model
            info = gnn_config['info']
            hyperparams = info['config']
            
            # Load state dict first to determine correct num_classes
            state_dict = torch.load(gnn_model_path, map_location=torch.device('cpu'))
            
            # Infer num_classes from the last layer's weight in state_dict based on num_layers
            last_layer_idx = hyperparams['num_layers'] - 1
            # Try to find the weight key for the last layer to determine output dimension
            detected_classes = None
            
            # Common patterns for PyG layers (SAGEConv, GATConv) end up using linear layers
            # SAGEConv: layers.X.lin_l.weight
            # GATConv: layers.X.lin_src.weight (or similar depending on implementation version)
            
            for key, tensor in state_dict.items():
                if key.startswith(f"layers.{last_layer_idx}") and "weight" in key:
                    # found a weight tensor for the last layer
                    # The output dimension (num_classes) is typically encoded in the shape
                    # For Linear(in, out), PyTorch stores [out, in]
                    if len(tensor.shape) >= 1:
                        detected_classes = tensor.shape[0]
                        break
            
            if detected_classes:
                print(f"[-] Detected num_classes from checkpoint: {detected_classes}")
                if detected_classes != len(le.classes_):
                    print(f"[!] Warning: LabelEncoder has {len(le.classes_)} classes but Model has {detected_classes}. Predictions might be misaligned.")
                num_classes = detected_classes
            else:
                num_classes = len(le.classes_)
            
            gnn_model = gnn_utils.GNNClassifier(
                input_dim=len(EXPECTED_COLUMNS),
                hidden_dim=hyperparams['hidden_dim'],
                num_classes=num_classes,
                num_layers=hyperparams['num_layers'],
                dropout=hyperparams['dropout'],
                arch=info['arch']
            )
            
            gnn_model.load_state_dict(state_dict)
            gnn_model.eval()
            model_store['gnn_multiclass'] = gnn_model
            
            # Load GNN Scaler (StandardScaler). Prefer persisted scaler if present.
            gnn_scaler_path = 'scalers/gnn_scaler.pkl'
            if os.path.exists(gnn_scaler_path):
                print("[-] Loading GNN scaler from disk...")
                scaler_store['gnn_scaler'] = joblib.load(gnn_scaler_path)
            else:
                # Fallback: fit on reference data
                ref_data_path = '01eda/cleaned_data15.csv'
                if os.path.exists(ref_data_path):
                    print("[-] Fitting GNN Scaler on reference data...")
                    df_ref = pd.read_csv(ref_data_path, usecols=EXPECTED_COLUMNS)
                    gnn_scaler = StandardScaler()
                    gnn_scaler.fit(df_ref)
                    scaler_store['gnn_scaler'] = gnn_scaler
                else:
                    print("[!] Reference data for GNN scaler not found. GNN predictions might be inaccurate.")
        else:
            print("[!] GNN Multiclass artifacts not found.")

        print("[+] Artifact loading complete.")
    except Exception as e:
        print(f"[!] Error loading artifacts: {e}")

class NetworkFlow(BaseModel):
    features: Dict[str, Any]
    scaler_id: str = "default"
    xgb_model: Optional[str] = None
    safetynet_model: Optional[str] = None
    gnn_model: Optional[str] = None
    model_trust: str = "NO_ACTION"

@app.post("/refit_scaler")
async def refit_scaler(file: UploadFile = File(...), name: Optional[str] = Form(None), mapping: Optional[str] = Form(None)):
    try:
        # Read CSV file (DrDoS files can be large/mixed types)
        df = pd.read_csv(file.file, low_memory=False)

        # Apply Column Mapping
        if mapping:
            try:
                # Expecting mapping to be the 'features' dict from metadata: { 'Target': 'CSV_Col' }
                # We need { 'CSV_Col': 'Target' } for rename
                map_dict = json.loads(mapping)
                rename_dict = {v: k for k, v in map_dict.items()}
                df.rename(columns=rename_dict, inplace=True)
            except Exception as e:
                print(f"[!] Invalid mapping provided: {e}")
        else:
            # Fallback legacy mapping
            df.rename(columns=COLUMN_MAPPING, inplace=True)
        
        # Validate columns
        missing_cols = [col for col in EXPECTED_COLUMNS if col not in df.columns]
        if missing_cols:
            raise HTTPException(status_code=400, detail=f"Missing columns in CSV: {missing_cols}")
            
        # Use only expected columns
        df_train = df[EXPECTED_COLUMNS].copy()
        
        # Force numeric conversion to handle mixed types (e.g. "Infinity", "NaN", strings)
        for col in df_train.columns:
            df_train[col] = pd.to_numeric(df_train[col], errors='coerce')
            
        # Fill resulting NaNs with 0
        df_train = df_train.fillna(0)
        
        # Create and fit new scaler
        # We assume the uploaded file contains BENIGN traffic for calibration
        # We use a dummy label '0' and tell scaler that benign_label is 0
        scaler = TriChannelScaler(benign_label=0)
        dummy_labels = pd.Series([0] * len(df_train))
        
        scaler.fit(df_train, dummy_labels)
        
        # Generate ID and save
        if name:
            scaler_id = "".join(x for x in name if x.isalnum() or x in ['_', '-']) # Sanitize
        else:
            scaler_id = str(uuid.uuid4())
            
        save_path = f"scalers/scaler_{scaler_id}.pkl"
        
        # Ensure directory exists
        os.makedirs("scalers", exist_ok=True)
        
        joblib.dump(scaler, save_path)
        scaler_store[scaler_id] = scaler
        
        return {
            "message": "Scaler refitted successfully",
            "scaler_id": scaler_id,
            "info": "Use this ID in your prediction requests to use this calibrated scaler."
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error refitting scaler: {str(e)}")

@app.post("/predict")
def predict_traffic(flow: NetworkFlow):
    if 'xgb' not in model_store or 'safety_net' not in model_store:
        raise HTTPException(status_code=500, detail="Models not loaded")

    # 1. Get Scaler
    scaler_id = flow.scaler_id
    if scaler_id not in scaler_store:
        # Try to load from disk if not in memory
        potential_path = f"scalers/scaler_{scaler_id}.pkl"
        if os.path.exists(potential_path):
            try:
                scaler_store[scaler_id] = joblib.load(potential_path)
            except:
                raise HTTPException(status_code=404, detail=f"Scaler ID {scaler_id} not found or corrupted")
        else:
            if scaler_id == 'default':
                 raise HTTPException(status_code=500, detail="Default scaler not available")
            raise HTTPException(status_code=404, detail=f"Scaler ID {scaler_id} not found")
            
    scaler = scaler_store[scaler_id]

    # 2. Convert JSON to DataFrame
    input_data = pd.DataFrame([flow.features])

    # Optional: Extract IPs for logging purposes (if available)
    src_ip = flow.features.get('src', 'Unknown')
    dst_ip = flow.features.get('dst', 'Unknown')
    
    # 3. SAFETY CHECK: Filter Columns
    try:
        model_input_raw = input_data[EXPECTED_COLUMNS]
    except KeyError as e:
        return {"error": f"Missing feature in request: {e}"}

    # 4. Transform to Tri-Channel (15 -> 45 features)
    try:
        model_input_scaled = scaler.transform(model_input_raw)
    except Exception as e:
        return {"error": f"Scaling failed: {str(e)}"}

    # 5. Predictions (on SCALED features)

    # Helper to load specific model from disk if needed
    def get_model(store_key, model_id, base_dir, loader_func, ext):
        # If no specific ID is requested, use the default loaded at startup
        if not model_id or model_id == 'default':
            return model_store.get(store_key)
            
        # Check if already loaded in a cache (we reuse model_store with keys like 'xgb_v2')
        cache_key = f"{store_key}_{model_id}"
        if cache_key in model_store:
            return model_store[cache_key]
            
        # Attempt load
        path = f"{base_dir}/{model_id}{ext}"
        if os.path.exists(path):
            try:
                mod = loader_func(path)
                model_store[cache_key] = mod
                return mod
            except Exception as e:
                print(f"Failed to load {model_id}: {e}")
                return model_store.get(store_key) # Fallback
        return model_store.get(store_key)

    # --- SafetyNet (Isolation Forest) ---
    sn_start = time.time()
    sn_model = get_model('safety_net', flow.safetynet_model, 'models/safetynet', joblib.load, '.pkl')
    
    # SafetyNet expects DataFrame with 45 cols
    is_anomaly = 0
    if sn_model:
        try:
            is_anomaly = int(sn_model.predict(model_input_scaled)[0])
        except: pass

    sn_end = time.time()
    sn_delay = f"{(sn_end - sn_start) * 1000:.2f}ms"

    # --- XGBoost ---
    xgb_start = time.time()
    
    def load_xgb(path):
        x = xgb.XGBClassifier()
        x.load_model(path)
        det = XGBDetector()
        det.model = x
        return det

    # Clean model ID (remove extension if passed)
    xgb_id = flow.xgb_model
    if xgb_id and xgb_id.endswith('.json'): xgb_id = xgb_id[:-5]
    
    xgb_model_obj = get_model('xgb', xgb_id, 'models/xgb', load_xgb, '.json')
    
    # XGB expects DataFrame with 45 cols
    xgb_pred = 0
    xgb_prob = 0.0
    if xgb_model_obj:
        try:
            xgb_pred = int(xgb_model_obj.model.predict(model_input_scaled)[0])
            raw_prob_attack = float(xgb_model_obj.model.predict_proba(model_input_scaled)[0][1])
            # If BENIGN (0), return P(Benign) = 1 - P(Attack). If Attack (1), return P(Attack).
            if xgb_pred == 1:
                xgb_prob = raw_prob_attack          # P(Attack)
            else:
                xgb_prob = 1.0 - raw_prob_attack    # P(Benign) 
        except: pass
        
    xgb_end = time.time()
    xgb_delay = f"{(xgb_end - xgb_start) * 1000:.2f}ms"

    # --- GNN Prediction (Multiclass) ---
    gnn_start = time.time()
    gnn_verdict = "N/A"
    gnn_conf = 0.0
    
    if 'gnn_multiclass' in model_store and 'gnn_scaler' in scaler_store:
        try:
            # Scale 15 features using GNN scaler
            gnn_input_np = scaler_store['gnn_scaler'].transform(model_input_raw)
            x_tensor = torch.tensor(gnn_input_np, dtype=torch.float)
            
            # Create dummy edge_index (self-loop or empty)
            edge_index = torch.tensor([[0], [0]], dtype=torch.long)
            
            with torch.no_grad():
                logits = model_store['gnn_multiclass'](x_tensor, edge_index)
                probs = torch.softmax(logits, dim=1)
                pred_idx = probs.argmax(dim=1).item()
                gnn_conf = probs[0, pred_idx].item()
                
                if 'label_encoder' in encoder_store:
                    gnn_verdict = encoder_store['label_encoder'].inverse_transform([pred_idx])[0]
                else:
                    gnn_verdict = str(pred_idx)
        except Exception as e:
            print(f"[!] GNN Prediction failed: {e}")
    
    gnn_end = time.time()
    gnn_delay = f"{(gnn_end - gnn_start) * 1000:.2f}ms"

    # 6. Action Decision Logic (Binary Only)
    
    # -- Inputs --
    binary_pred = xgb_pred # 0 or 1
    binary_conf = raw_prob_attack # P(Attack)
    model_trust = flow.model_trust
    if_flag = is_anomaly
    
    # -- Thresholds --
    LOG_THRESHOLD = 0.5
    BLOCK_THRESHOLD = 0.75
    
    # Adaptive tuning
    if if_flag == 1:
        LOG_THRESHOLD = max(0.45, LOG_THRESHOLD - 0.05)
        BLOCK_THRESHOLD = max(0.65, BLOCK_THRESHOLD - 0.1)
        
    # -- Decision Logic --
    action = "ALLOW"
    
    if model_trust == "RETRAIN":
        action = "ALERT_ONLY"
    elif binary_pred == 0:
        action = "ALLOW"
    elif binary_conf < LOG_THRESHOLD:
        action = "LOG"
    elif binary_conf < BLOCK_THRESHOLD:
        action = "RATE_LIMIT"
    else:
        action = "BLOCK"
        
    # Determine Final Verdict for display
    final_verdict = "BENIGN"
    if action in ["BLOCK", "RATE_LIMIT"]:
        final_verdict = "KNOWN_ATTACK"
    elif action == "LOG":
        final_verdict = "SUSPICIOUS"
    elif action == "ALERT_ONLY":
        final_verdict = "ALERT"

    # 7. Construct Response
    result = {
        "isolation_forest": {
            "flag": is_anomaly,
            "delay": sn_delay
        },
        "xgb": {
            "flag": xgb_pred,
            "confidence": xgb_prob, 
            "delay": xgb_delay
        },
        "gnn": {
            "flag": gnn_verdict,
            "confidence": gnn_conf,
            "delay": gnn_delay
        },
        "verdict": final_verdict,
        "action": action,
        "model_trust": model_trust,
        "binary_prediction": "ATTACK" if binary_pred == 1 else "BENIGN",
        "binary_confidence": binary_conf,
        "gnn_prediction": gnn_verdict,
        "gnn_confidence": gnn_conf,
        "if_flag": if_flag
    }
    
    return result

@app.get("/scaler_stats")
def get_scaler_stats(scaler_id: str = "default"):
    """
    Returns the training statistics (median, IQR) for the specified scaler.
    Useful for frontend drift visualization.
    """
    if scaler_id not in scaler_store:
        # Try to load if missing
        potential_path = f"scalers/scaler_{scaler_id}.pkl" if scaler_id != 'default' else "scalers/trichannel_scaler.pkl"
        if os.path.exists(potential_path):
             scaler_store[scaler_id] = joblib.load(potential_path)
        else:
             raise HTTPException(status_code=404, detail="Scaler not found")
    
    scaler = scaler_store[scaler_id]
    
    # Check if it has stats_ (TriChannelScaler)
    if not hasattr(scaler, 'stats_'):
        return {"error": "Scaler does not have stats_ attribute (not TriChannelScaler?)"}
        
    return scaler.stats_

@app.post("/analyze_pcap")
async def analyze_pcap(
    file: UploadFile = File(...),
    scaler_id: str = Form("default"),
    label_col: Optional[str] = Form(None),
    normal_label: Optional[str] = Form("Benign")
):
    if 'xgb' not in model_store or 'safety_net' not in model_store:
        raise HTTPException(status_code=500, detail="Models not loaded")

    # 1. Get Scaler
    if scaler_id not in scaler_store:
        potential_path = f"scalers/scaler_{scaler_id}.pkl"
        if os.path.exists(potential_path):
            try:
                scaler_store[scaler_id] = joblib.load(potential_path)
            except:
                raise HTTPException(status_code=404, detail=f"Scaler ID {scaler_id} not found or corrupted")
        else:
            if scaler_id == 'default':
                 raise HTTPException(status_code=500, detail="Default scaler not available")
            raise HTTPException(status_code=404, detail=f"Scaler ID {scaler_id} not found")
    scaler = scaler_store[scaler_id]

    try:
        # 2. Read CSV
        df = pd.read_csv(file.file, low_memory=False)
        
        # Rename columns
        df.rename(columns=COLUMN_MAPPING, inplace=True)
        
        # 3. Extract Metadata (Flow Info)
        # Try to find standard flow identifier columns
        # Common names: Src IP, Dst IP, Src Port, Dst Port, Protocol, Timestamp, Flow ID
        meta_cols = {
            'src_ip': ['Src IP', 'Source IP', 'src_ip'],
            'dst_ip': ['Dst IP', 'Destination IP', 'dst_ip'],
            'src_port': ['Src Port', 'Source Port', 'src_port'],
            'dst_port': ['Dst Port', 'Destination Port', 'dst_port'],
            'protocol': ['Protocol', 'proto'],
            'timestamp': ['Timestamp', 'timestamp']
        }
        
        flow_meta = []
        for idx, row in df.iterrows():
            meta = {}
            for key, candidates in meta_cols.items():
                val = None
                for c in candidates:
                    if c in df.columns:
                        val = row[c]
                        break
                meta[key] = str(val) if val is not None else "N/A"
            flow_meta.append(meta)

        # 4. Prepare Features
        # Clean data similar to test.py
        for col in EXPECTED_COLUMNS:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')
        
        # We can't drop rows easily because we need to match flow_meta indices.
        # Instead, fill NaNs with 0 or handle them. 
        # For simplicity, we'll drop and keep track of valid indices if needed, 
        # but to keep it simple for the API, we'll fillna(0) for missing numeric features 
        # to ensure we return a result for every flow.
        # OR: we filter and only return valid flows.
        
        # Let's filter valid rows
        valid_mask = df[EXPECTED_COLUMNS].notna().all(axis=1)
        df_valid = df[valid_mask].copy()
        
        # Filter flow_meta to match valid rows
        flow_meta_valid = [flow_meta[i] for i in range(len(flow_meta)) if valid_mask.iloc[i]]
        
        if df_valid.empty:
             return {"metrics": {}, "flows": []}

        X_raw = df_valid[EXPECTED_COLUMNS]
        
        # 5. Scale
        X_scaled = scaler.transform(X_raw)
        
        # 6. Predict
        xgb_model = model_store['xgb']
        preds = xgb_model.model.predict(X_scaled)
        # probs = xgb_model.model.predict_proba(X_scaled)[:, 1] # Optional
        
        # Map predictions to labels
        pred_labels = ["DDoS" if p == 1 else "BENIGN" for p in preds]
        actions = ["BLOCK" if p == 1 else "ALLOW" for p in preds]
        
        # 7. Construct Flows Response
        response_flows = []
        for i, meta in enumerate(flow_meta_valid):
            flow_entry = meta.copy()
            flow_entry['prediction'] = pred_labels[i]
            flow_entry['action'] = actions[i]
            
            # Add label if available
            if label_col and label_col in df.columns:
                # Get original label from df_valid
                orig_label = df_valid.iloc[i][label_col]
                flow_entry['label'] = str(orig_label)
            
            response_flows.append(flow_entry)
            
        # 8. Calculate Metrics (if labeled)
        metrics = {}
        if label_col and label_col in df.columns:
            y_true = (df_valid[label_col].astype(str) != str(normal_label)).astype(int)
            y_pred = preds
            
            metrics = {
                "accuracy": float(accuracy_score(y_true, y_pred)),
                "recall": float(recall_score(y_true, y_pred, zero_division=0)),
                "f1": float(f1_score(y_true, y_pred, zero_division=0)),
                "cm": confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel().tolist() # [TN, FP, FN, TP]
            }
            
        return {
            "metrics": metrics,
            "flows": response_flows
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/scalers")
def list_scalers():
    # List all .pkl files in scalers/
    files = glob.glob("scalers/*.pkl")
    results = []
    
    # Add default separately if exists or force it
    if os.path.exists("scalers/trichannel_scaler.pkl"):
        results.append({"id": "default", "name": "Default TriChannel"})
        
    for f in files:
        fname = os.path.basename(f)
        if fname == "trichannel_scaler.pkl": continue
        
        # Parse ID from filename
        # Pattern: scaler_{NAME}.pkl
        sid = fname
        if sid.endswith(".pkl"):
            sid = sid[:-4]
            
        if sid.startswith("scaler_"):
            sid = sid[7:] # Remove prefix scaler_
        
        results.append({"id": sid, "name": sid})

    return {"scalers": results}


@app.get("/models")
def list_models_endpoint():
    return {
        "xgb": [os.path.basename(f) for f in glob.glob("models/xgb/*.json")],
        "gnn": [os.path.basename(f) for f in glob.glob("models/gnn/*.pt")],
        "isolation_forest": [os.path.basename(f) for f in glob.glob("models/safetynet/*.pkl")]
    }

@app.get("/retrain/status/{job_id}")
def get_training_status(job_id: str):
    if job_id not in training_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return training_jobs[job_id]

def run_training_task(job_id, params):
    try:
        training_jobs[job_id] = {"status": "running"}
        # Load CSV from temp path
        file_path = params['file_path']
        df = pd.read_csv(file_path)
        
        # Execute logic using the shared helper
        result = execute_training_logic(df, params)
        training_jobs[job_id] = {"status": "completed", "result": result}
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        training_jobs[job_id] = {"status": "failed", "error": str(e)}
    finally:
        # Cleanup temp file
        if os.path.exists(params['file_path']):
            try:
                os.remove(params['file_path'])
            except: pass

def execute_training_logic(df, params):
    model_type = params['model_type']
    model_name = params['model_name']
    mapping = params.get('mapping')
    scaler_id = params.get('scaler_id', 'default')
    label_col = params.get('label_col', 'Label')
    benign_label = params.get('benign_label', 'BENIGN')
    sanitized_name = "".join(x for x in model_name if x.isalnum() or x in ['_', '-'])
    
    # Helper: Load Scaler
    def load_specific_scaler(sid):
        if sid in scaler_store:
            return scaler_store[sid]
        path = f'scalers/scaler_{sid}.pkl'
        if sid == 'default' or not os.path.exists(path):
             path2 = f'scalers/{sid}.pkl'
             if os.path.exists(path2): path = path2
             else: path = 'scalers/trichannel_scaler.pkl'
        if os.path.exists(path):
            try:
                sc = joblib.load(path)
                scaler_store[sid] = sc
                return sc
            except: raise ValueError(f"Failed to load scaler {sid}")
        else: raise ValueError(f"Scaler {sid} not found")

    # 1. Apply Mapping
    if mapping:
        try:
            map_dict = json.loads(mapping) if isinstance(mapping, str) else mapping
            rename_dict = {v: k for k, v in map_dict.items()}
            df.rename(columns=rename_dict, inplace=True)
        except Exception as e:
            print(f"[!] Invalid mapping: {e}")
    else:
        df.rename(columns=COLUMN_MAPPING, inplace=True)
        
    # 2. Check Labels
    found_label = None
    for c in df.columns:
        if c.strip() == label_col.strip():
            found_label = c
            break
    
    if not found_label:
        raise ValueError(f"Label column '{label_col}' not found in CSV")

    # 3. Clean
    for col in EXPECTED_COLUMNS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
    df.dropna(subset=EXPECTED_COLUMNS, inplace=True)

    # 4. Model Logic
    if model_type == "isolation_forest":
        target_scaler_path = 'scalers/trichannel_scaler.pkl'
        if scaler_id != 'default':
             if os.path.exists(f'scalers/{scaler_id}.pkl'): target_scaler_path = f'scalers/{scaler_id}.pkl'
             elif os.path.exists(f'scalers/scaler_{scaler_id}.pkl'): target_scaler_path = f'scalers/scaler_{scaler_id}.pkl'
        
        sn = SafetyNet(scaler_path=target_scaler_path, label_col=found_label)
        
        df['norm_label'] = df[found_label].astype(str).str.strip().str.upper()
        benign_norm = benign_label.strip().upper()
        df_benign = df[df['norm_label'] == benign_norm]
        
        if len(df_benign) < 100: raise ValueError("Not enough benign samples")
        
        current_scaler = load_specific_scaler(scaler_id)
        sn.scaler = current_scaler
             
        sn.fit(sn.scaler.transform(df_benign[EXPECTED_COLUMNS]))
        
        # Eval
        X_all = sn.scaler.transform(df[EXPECTED_COLUMNS])
        y_true = df['norm_label'].apply(lambda x: 0 if x == benign_norm else 1)
        preds = sn.model.predict(X_all)
        y_pred = (preds == -1).astype(int)
        
        metrics = {
            "accuracy": round(accuracy_score(y_true, y_pred), 4),
            "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
            "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
            "f1": round(f1_score(y_true, y_pred, zero_division=0), 4)
        }
        
        out_path = f"models/safetynet/{sanitized_name}.pkl"
        os.makedirs("models/safetynet", exist_ok=True)
        joblib.dump(sn, out_path)
        model_store['safety_net'] = sn
        
        return {
            "status": "success",
            "model": out_path,
            "metrics": metrics,
            "model_type": "isolation_forest",
            "model_name": sanitized_name
        }

    elif model_type == "xgb":
        xgb_det = XGBDetector()
        X = df[EXPECTED_COLUMNS]
        y = df[found_label].apply(lambda x: 0 if str(x).strip().upper() == benign_label.strip().upper() else 1)
        
        if y.nunique() < 2: raise ValueError("XGB needs mixed labels")
        
        active_scaler = load_specific_scaler(scaler_id)
        X_scaled = active_scaler.transform(X)
        X_train, X_val, X_test, y_train, y_val, y_test = xgb_det.get_golden_split(X_scaled, y)
        xgb_det.train_binary(X_train, y_train, X_val, y_val)
        
        # Eval
        y_pred = xgb_det.model.predict(X_test)
        y_prob = xgb_det.model.predict_proba(X_test)[:, 1]
        
        metrics = {
            "accuracy": round(accuracy_score(y_test, y_pred), 4),
            "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
            "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
            "f1": round(f1_score(y_test, y_pred, zero_division=0), 4),
            "auc": round(roc_auc_score(y_test, y_prob), 4)
        }
        
        out_path = f"models/xgb/{sanitized_name}.json"
        os.makedirs("models/xgb", exist_ok=True)
        xgb_det.model.save_model(out_path)
        
        # Hot swap
        xgb_det2 = XGBDetector()
        xgb_det2.model = xgb_det.model
        model_store['xgb'] = xgb_det2
        
        return {
            "status": "success", 
            "model": out_path, 
            "metrics": metrics,
            "model_type": "xgb", 
            "model_name": sanitized_name,
            "learning_curve": xgb_det.evals_result,
            "split_info": {"train": len(y_train), "val": len(y_val), "test": len(y_test)}
        }

    elif model_type == "gnn":
        df_user = df
        
        # INSDN
        insdn_ratio = float(params.get('insdn_ratio', 0.2))
        insdn_dir = params.get('insdn_dir', 'datasets/insdn')
        df_insdn = pd.DataFrame()
        
        if insdn_ratio > 0:
             if not os.path.isabs(insdn_dir): insdn_dir = os.path.abspath(insdn_dir)
             files = glob.glob(os.path.join(insdn_dir, "*.csv"))
             frames = []
             for f in files:
                 try:
                     t = pd.read_csv(f, low_memory=False)
                     t.rename(columns=COLUMN_MAPPING, inplace=True)
                     if found_label not in t.columns:
                        for c in t.columns:
                            if c.strip() == label_col.strip():
                                t.rename(columns={c: found_label}, inplace=True)
                                break
                     frames.append(t)
                 except: pass
             if frames:
                 df_insdn = pd.concat(frames, ignore_index=True)
                 for c in EXPECTED_COLUMNS:
                      if c in df_insdn.columns: df_insdn[c] = pd.to_numeric(df_insdn[c], errors='coerce')
                 df_insdn.dropna(subset=EXPECTED_COLUMNS, inplace=True)
                 if found_label in df_insdn.columns:
                      df_insdn['norm_label'] = df_insdn[found_label].astype(str).str.strip().str.replace(r"[\u200b\u200c\u200d\ufeff]", "", regex=True)
                      
        # Clean user
        df_user['norm_label'] = df_user[found_label].astype(str).str.strip().str.replace(r"[\u200b\u200c\u200d\ufeff]", "", regex=True)
        
        # Mix
        insdn_added = 0
        if not df_insdn.empty and insdn_ratio > 0:
            target = max(1, int(len(df_user) * insdn_ratio))
            if len(df_insdn) > target: df_insdn = df_insdn.sample(n=target, random_state=int(params.get('random_seed', 42)))
            insdn_added = len(df_insdn)
            df_mix = pd.concat([df_user, df_insdn], ignore_index=True)
        else:
            df_mix = df_user
            
        print(f"[-] Fitting new LabelEncoder on {len(df_mix)} samples with {df_mix['norm_label'].nunique()} unique labels.")
        le = LabelEncoder()
        df_mix['Label_Encoded'] = le.fit_transform(df_mix['norm_label'])
        
        gnn_scaler = StandardScaler()
        gnn_scaler.fit(df_mix[EXPECTED_COLUMNS])
        X = gnn_scaler.transform(df_mix[EXPECTED_COLUMNS])
        
        gnn_df = df_mix[['Label_Encoded']].copy()
        gnn_df[EXPECTED_COLUMNS] = X
        if 'Src IP' not in df_mix.columns: gnn_df['Src IP'] = 0
        else: gnn_df['Src IP'] = df_mix['Src IP']
        if 'Dst IP' not in df_mix.columns: gnn_df['Dst IP'] = 0
        else: gnn_df['Dst IP'] = df_mix['Dst IP']
        if 'Timestamp' not in df_mix.columns: gnn_df['Timestamp'] = time.time()
        else: gnn_df['Timestamp'] = df_mix['Timestamp']
        if 'Protocol' not in gnn_df.columns:
             gnn_df['Protocol'] = df_mix['Protocol'].values if 'Protocol' in df_mix.columns else 0
            
        data = gnn_utils.build_graph(
            gnn_df, EXPECTED_COLUMNS,
            strategy=params.get('gnn_strategy', 'knn_protocol'),
            k=int(params.get('gnn_k', 5)),
            delta_t_seconds=int(params.get('gnn_delta_t', 10))
        )
        
        y_all = data.y.cpu().numpy()
        idx_all = np.arange(len(y_all))
        train_idx, temp_idx = train_test_split(idx_all, test_size=(1.0 - float(params.get('split_train', 0.7))), stratify=y_all, random_state=int(params.get('random_seed', 42)))
        
        val_ratio = float(params.get('split_val', 0.15))
        test_ratio = float(params.get('split_test', 0.15))
        relative_val = val_ratio / (val_ratio + test_ratio)
        
        val_idx, test_idx = train_test_split(temp_idx, test_size=(1.0 - relative_val), stratify=y_all[temp_idx], random_state=int(params.get('random_seed', 42)))
        
        train_mask = torch.zeros(len(y_all), dtype=torch.bool)
        val_mask = torch.zeros(len(y_all), dtype=torch.bool)
        test_mask = torch.zeros(len(y_all), dtype=torch.bool)
        train_mask[train_idx] = True
        val_mask[val_idx] = True
        test_mask[test_idx] = True
        
        num_classes = len(le.classes_)
        model = gnn_utils.GNNClassifier(
            input_dim=len(EXPECTED_COLUMNS),
            hidden_dim=int(params.get('gnn_hidden_dim', 64)),
            num_classes=num_classes,
            num_layers=int(params.get('gnn_num_layers', 2)),
            dropout=float(params.get('gnn_dropout', 0.3)),
            arch=params.get('gnn_arch', 'sage')
        )
        
        cw = compute_class_weight('balanced', classes=np.unique(y_all), y=y_all)
        cw = torch.tensor(cw, dtype=torch.float)
        
        gnn_utils.train_gnn(
            model, data, train_mask, val_mask,
            epochs=int(params.get('gnn_epochs', 60)),
            class_weights=cw
        )
        
        with torch.no_grad():
             logits = model(data.x, data.edge_index)
             preds = logits.argmax(dim=1)
        
        y_t = data.y[test_mask].cpu().numpy()
        y_p = preds[test_mask].cpu().numpy()
        
        metrics = {
            "accuracy": round(accuracy_score(y_t, y_p), 4),
            "f1": round(f1_score(y_t, y_p, average='macro', zero_division=0), 4),
            "recall": round(recall_score(y_t, y_p, average='macro', zero_division=0), 4)
        }
        
        out_path = f"models/gnn/{sanitized_name}.pt"
        os.makedirs("models/gnn", exist_ok=True)
        torch.save(model.state_dict(), out_path)
        joblib.dump(gnn_scaler, f"scalers/gnn_scaler_{sanitized_name}.pkl")
        
        os.makedirs('encoders', exist_ok=True)
        with open(f"encoders/{sanitized_name}_label_encoder.pkl", 'wb') as f:
             pickle.dump(le, f)
        
        # Hot Swap
        model.eval()
        model_store['gnn_multiclass'] = model
        scaler_store['gnn_scaler'] = gnn_scaler
        encoder_store['label_encoder'] = le
        
        config = {
            "info": {
                "arch": params.get('gnn_arch'), 
                "config": params
            },
            "metrics": metrics
        }
        with open(f"models/gnn/{sanitized_name}_config.json", 'w') as f: json.dump(config, f)
        
        return {
            "status": "success",
            "model": out_path,
            "metrics": metrics,
            "model_type": "gnn",
            "model_name": sanitized_name,
            "gnn_config": config,
            "split_info": {"total": len(df_mix), "train": len(train_idx), "val": len(val_idx), "test": len(test_idx), "insdn_added": insdn_added}
        }
    
    raise ValueError("Unknown model type")

@app.post("/retrain/{model_type}")
async def retrain_model_endpoint(
    model_type: str, 
    background_tasks: BackgroundTasks,
    model_name: str = Form(...),
    file: UploadFile = File(...),
    label_col: str = Form("Label"),
    benign_label: str = Form("BENIGN"),
    mapping: Optional[str] = Form(None),
    scaler_id: str = Form("default"),
    insdn_ratio: float = Form(0.2),
    insdn_dir: str = Form("datasets/insdn"),
    gnn_arch: str = Form("sage"),
    gnn_epochs: int = Form(60),
    gnn_hidden_dim: int = Form(64),
    gnn_num_layers: int = Form(2),
    gnn_dropout: float = Form(0.3),
    gnn_strategy: str = Form("knn_protocol"),
    gnn_k: int = Form(5),
    gnn_delta_t: int = Form(10),
    split_train: float = Form(0.7),
    split_val: float = Form(0.15),
    split_test: float = Form(0.15),
    random_seed: int = Form(42)
):
    # Create temp file for the background task to read
    temp_dir = "temp_uploads"
    os.makedirs(temp_dir, exist_ok=True)
    temp_path = os.path.join(temp_dir, f"train_{uuid.uuid4().hex}.csv")
    
    with open(temp_path, "wb") as f:
        content = await file.read()
        f.write(content)
        
    job_id = str(uuid.uuid4())
    training_jobs[job_id] = {"status": "pending"}
    
    params = {
        "model_type": model_type,
        "model_name": model_name,
        "file_path": temp_path,
        "label_col": label_col,
        "benign_label": benign_label,
        "mapping": mapping,
        "scaler_id": scaler_id,
        "insdn_ratio": insdn_ratio,
        "insdn_dir": insdn_dir,
        "gnn_arch": gnn_arch,
        "gnn_epochs": gnn_epochs,
        "gnn_hidden_dim": gnn_hidden_dim,
        "gnn_num_layers": gnn_num_layers,
        "gnn_dropout": gnn_dropout,
        "gnn_strategy": gnn_strategy,
        "gnn_k": gnn_k,
        "gnn_delta_t": gnn_delta_t,
        "split_train": split_train,
        "split_val": split_val,
        "split_test": split_test,
        "random_seed": random_seed
    }
    
    background_tasks.add_task(run_training_task, job_id, params)
    
    return {"status": "pending", "job_id": job_id, "message": "Training started in background"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

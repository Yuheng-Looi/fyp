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
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from typing import List, Dict, Any, Union, Optional
from sklearn.metrics import accuracy_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
from torch_geometric.data import Data

from anomaly_utils import SafetyNet
from xgb_utils import XGBDetector
from scaler_utils import TriChannelScaler
import gnn_utils

app = FastAPI(title="IDS Inference Engine")
model_store = {}
scaler_store = {}
encoder_store = {}


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
        encoder_path = 'encoders/label_encoder.pkl'
        
        if os.path.exists(gnn_config_path) and os.path.exists(gnn_model_path) and os.path.exists(encoder_path):
            print("[-] Loading GNN Multiclass model...")
            with open(gnn_config_path, 'r') as f:
                gnn_config = json.load(f)
            
            with open(encoder_path, 'rb') as f:
                le = pickle.load(f)
            encoder_store['label_encoder'] = le
            
            # Initialize Model
            info = gnn_config['info']
            hyperparams = info['config']
            num_classes = len(le.classes_)
            
            gnn_model = gnn_utils.GNNClassifier(
                input_dim=len(EXPECTED_COLUMNS),
                hidden_dim=hyperparams['hidden_dim'],
                num_classes=num_classes,
                num_layers=hyperparams['num_layers'],
                dropout=hyperparams['dropout'],
                arch=info['arch']
            )
            
            gnn_model.load_state_dict(torch.load(gnn_model_path, map_location=torch.device('cpu')))
            gnn_model.eval()
            model_store['gnn_multiclass'] = gnn_model
            
            # Fit GNN Scaler (StandardScaler) on reference data
            # We need this because GNN was trained on StandardScaler(15 features), not TriChannel
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
            xgb_prob = float(xgb_model_obj.model.predict_proba(model_input_scaled)[0][1])
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

    # 6. Determine Final Verdict and Action
    final_verdict = "BENIGN"
    action = "allow"

    if xgb_pred == 1:
        final_verdict = "KNOWN_ATTACK"
        action = "block"
    elif is_anomaly == 1:
        final_verdict = "ZERO_DAY_SUSPICION"
        action = "block"

    # 7. Construct Response
    result = {
        "isolation_forest": {
            "flag": is_anomaly,
            # "confidence": removed as per request (not available in standard IsolationForest)
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
        "action": action
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
        
        # Format: scaler_{id}.pkl
        sid = fname.replace("scaler_", "").replace(".pkl", "")
        results.append({"id": sid, "name": sid})
        
    return results

@app.get("/models")
def list_models_endpoint():
    return {
        "xgb": [os.path.basename(f) for f in glob.glob("models/xgb/*.json")],
        "gnn": [os.path.basename(f) for f in glob.glob("models/gnn/*.pt")],
        "isolation_forest": [os.path.basename(f) for f in glob.glob("models/safetynet/*.pkl")]
    }

@app.post("/retrain/{model_type}")
async def retrain_model_endpoint(
    model_type: str, 
    model_name: str = Form(...),
    file: UploadFile = File(...),
    label_col: str = Form("Label"),
    benign_label: str = Form("BENIGN"),
    mapping: Optional[str] = Form(None),
    scaler_id: str = Form("default")
):
    valid_types = ["xgb", "isolation_forest", "gnn"]
    if model_type not in valid_types:
        raise HTTPException(400, f"Invalid model type. Must be one of {valid_types}")
        
    sanitized_name = "".join(x for x in model_name if x.isalnum() or x in ['_', '-'])
    if not sanitized_name:
        raise HTTPException(400, "Invalid model name")
        
    # Helper: Load Scaler
    def load_specific_scaler(sid):
        if sid in scaler_store:
            return scaler_store[sid]
        
        # Determine path
        # Try direct or legacy depending on how ID was listed
        # list_scalers returns ID without prefix usually.
        # But file is saved WITH prefix.
        
        path = f'scalers/scaler_{sid}.pkl'
        
        if sid == 'default' or not os.path.exists(path):
             # Try other path if weird setup
             path2 = f'scalers/{sid}.pkl'
             if os.path.exists(path2):
                 path = path2
             else:
                 path = 'scalers/trichannel_scaler.pkl'
             
        if os.path.exists(path):
            try:
                sc = joblib.load(path)
                scaler_store[sid] = sc
                return sc
            except:
                raise HTTPException(500, f"Failed to load scaler {sid}")
        else:
             raise HTTPException(404, f"Scaler {sid} not found")

    try:
        # Load CSV
        df = pd.read_csv(file.file)

        # Apply Column Mapping
        if mapping:
            try:
                map_dict = json.loads(mapping)
                rename_dict = {v: k for k, v in map_dict.items()}
                df.rename(columns=rename_dict, inplace=True)
            except Exception as e:
                print(f"[!] Invalid mapping provided: {e}")
        else:
            df.rename(columns=COLUMN_MAPPING, inplace=True)
        
        # Check Label Col
        # Clean label col name logic? (strip info)
        # Maybe user provides ' Label '
        found_label = None
        for c in df.columns:
            if c.strip() == label_col.strip():
                found_label = c
                break
        
        if not found_label:
            raise HTTPException(400, f"Label column '{label_col}' not found in CSV")
            
        # Check Features
        # We need the 15 features
        missing = [c for c in EXPECTED_COLUMNS if c not in df.columns]
        if missing:
             raise HTTPException(400, f"Missing features: {missing}")

        # --- DATA CLEANING START ---
        # Force numeric conversion for expected feature columns
        # This handles mixed types, "Infinity", "NaN", and repeated headers
        for col in EXPECTED_COLUMNS:
            df[col] = pd.to_numeric(df[col], errors='coerce')
            
        # Drop rows where any feature became NaN (due to coercion)
        df.dropna(subset=EXPECTED_COLUMNS, inplace=True)
        # --- DATA CLEANING END ---

        # Retrain Logic Switch
        if model_type == "isolation_forest":
            # 1. Initialize SafetyNet
            # Use the selected scaler
            # TriChannelScaler logic is assumed if using default or similar structure.
            
            # Determine scaler path for SafetyNet (which might re-load it, or we pass the object if updated)
            # SafetyNet class expects scaler_path string usually to load it internally if not provided with object.
            # Let's check constructor signature from anomaly_utils if we could but assume generic usage:
            # We will pass the scaler object directly if possible or the path.
            
            target_scaler_path = 'scalers/trichannel_scaler.pkl'
            
            if scaler_id != 'default':
                # Try direct
                if os.path.exists(f'scalers/{scaler_id}.pkl'):
                     target_scaler_path = f'scalers/{scaler_id}.pkl'
                elif os.path.exists(f'scalers/scaler_{scaler_id}.pkl'):
                     target_scaler_path = f'scalers/scaler_{scaler_id}.pkl'
                else:
                     # Fallback check
                     pass 
            
            if not os.path.exists(target_scaler_path):
                 raise HTTPException(404, f"Scaler file not found: {target_scaler_path}")
            
            sn = SafetyNet(scaler_path=target_scaler_path, label_col=found_label)
            
            # 2. Get Benign Only
            # Normalize labels?
            df['norm_label'] = df[found_label].astype(str).str.strip().str.upper()
            benign_norm = benign_label.strip().upper()
            
            df_benign = df[df['norm_label'] == benign_norm]
            if len(df_benign) < 100:
                raise HTTPException(400, f"Not enough benign samples ({len(df_benign)}) for SafetyNet training")
                
            # 3. Scale Data (Important: SafetyNet needs Scaled Data)
            # We need to scale df_benign using the scaler
            # Load scaler object to ensure we have it
            current_scaler = load_specific_scaler(scaler_id)
            if not current_scaler:
                 raise HTTPException(500, "Base scaler for SafetyNet training not found")
            
            # Start fresh with this scaler in SafetyNet instance
            sn.scaler = current_scaler
            
            # Transform
            X_benign = df_benign[EXPECTED_COLUMNS]
            X_benign_scaled = sn.scaler.transform(X_benign) 
            
            # SafetyNet expects DataFrame with 45 columns (if TriChannel)
            # transform returns DataFrame usually if input was DataFrame in sklearn wrappers, 
            # but TriChannelScaler returns DataFrame.
            
            # 4. Fit
            sn.fit(X_benign_scaled)
            
            # 5. Save
            out_path = f"models/safetynet/{sanitized_name}.pkl"
            os.makedirs("models/safetynet", exist_ok=True)
            joblib.dump(sn, out_path)
            model_store['safety_net'] = sn # Hot swap? Maybe dangerous but okay for demo.
            
            return {"status": "success", "model": out_path}

        elif model_type == "xgb":
            # 1. Initialize XGBDetector
            xgb_det = XGBDetector()
            
            # 2. Split Data
            X = df[EXPECTED_COLUMNS]
            y = df[found_label]
            
            # Encode Y -> 0 (Benign), 1 (Attack)
            # Need to match benign_label
            y_binary = y.apply(lambda x: 0 if str(x).strip().upper() == benign_label.strip().upper() else 1)
            
            if y_binary.nunique() < 2:
                 raise HTTPException(400, "XGBoost requires both Benign and Attack samples.")

            # Scale X
            # Use selected scaler
            active_scaler = load_specific_scaler(scaler_id)
                 
            X_scaled = active_scaler.transform(X)
            
            # Split
            X_train, X_val, X_test, y_train, y_val, y_test = xgb_det.get_golden_split(X_scaled, y_binary)
            
            # 3. Train
            xgb_det.train_binary(X_train, y_train, X_val, y_val)
            
            # 4. Save
            out_path = f"models/xgb/{sanitized_name}.json"
            os.makedirs("models/xgb", exist_ok=True)
            xgb_det.model.save_model(out_path)
            
            # Store hot swap
            xgb_det2 = XGBDetector()
            xgb_det2.model = xgb_det.model
            model_store['xgb'] = xgb_det2
            
            return {"status": "success", "model": out_path, "metrics": str(xgb_det.evals_result)}

        elif model_type == "gnn":
            raise HTTPException(501, "GNN Retraining not yet implemented via API due to complexity.")
            
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(500, f"Retraining failed: {str(e)}")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

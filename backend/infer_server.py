import uvicorn
import pandas as pd
import joblib
import numpy as np
import xgboost as xgb
import uuid
import os
import json
import torch
import pickle
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
        if os.path.exists('models/safety_net_v1.pkl'):
            sn = joblib.load('models/safety_net_v1.pkl')
            model_store['safety_net'] = sn
        else:
            print("[!] SafetyNet model not found.")

        # XGBoost (JSON)
        if os.path.exists('models/xgb_binary_v1.json'):
            xgb_model = xgb.XGBClassifier()
            xgb_model.load_model('models/xgb_binary_v1.json')
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

@app.post("/refit_scaler")
async def refit_scaler(file: UploadFile = File(...)):
    try:
        # Read CSV file
        df = pd.read_csv(file.file)
        
        # Validate columns
        missing_cols = [col for col in EXPECTED_COLUMNS if col not in df.columns]
        if missing_cols:
            raise HTTPException(status_code=400, detail=f"Missing columns in CSV: {missing_cols}")
            
        # Use only expected columns
        df_train = df[EXPECTED_COLUMNS]
        
        # Create and fit new scaler
        # We assume the uploaded file contains BENIGN traffic for calibration
        # We use a dummy label '0' and tell scaler that benign_label is 0
        scaler = TriChannelScaler(benign_label=0)
        dummy_labels = pd.Series([0] * len(df_train))
        
        scaler.fit(df_train, dummy_labels)
        
        # Generate ID and save
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
    sn_model = model_store['safety_net']
    # SafetyNet expects DataFrame with 45 cols
    is_anomaly = sn_model.predict(model_input_scaled)[0]
    
    xgb_model = model_store['xgb']
    # XGB expects DataFrame with 45 cols
    xgb_pred = xgb_model.model.predict(model_input_scaled)[0]
    xgb_prob = float(xgb_model.model.predict_proba(model_input_scaled)[0][1])

    # GNN Prediction (Multiclass)
    gnn_verdict = "N/A"
    gnn_conf = 0.0
    if 'gnn_multiclass' in model_store and 'gnn_scaler' in scaler_store:
        try:
            # Scale 15 features using GNN scaler
            gnn_input_np = scaler_store['gnn_scaler'].transform(model_input_raw)
            x_tensor = torch.tensor(gnn_input_np, dtype=torch.float)
            
            # Create dummy edge_index (self-loop or empty)
            # For single node, empty edge_index is fine, or self-loop
            # GNNs usually need edges to aggregate. If no edges, it acts like MLP (if self-loops added)
            # GraphSAGE/GAT might fail if no edges?
            # Let's add self-loop: node 0 -> node 0
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

    # 6. Result
    result = {
        "verdict": "BENIGN",
        "confidence": 0.0,
        "source": src_ip,
        "destination": dst_ip,
        "scaler_used": scaler_id,
        "gnn_verdict": gnn_verdict,
        "details": {
            "safety_net_flag": int(is_anomaly),
            "xgb_flag": int(xgb_pred),
            "xgb_probability": xgb_prob,
            "gnn_multiclass": gnn_verdict,
            "gnn_confidence": gnn_conf
        }
    }

    if xgb_pred == 1:
        result["verdict"] = "KNOWN_ATTACK"
        result["confidence"] = xgb_prob
    elif is_anomaly == 1:
        result["verdict"] = "ZERO_DAY_SUSPICION"
        result["confidence"] = 0.5 
    
    return result

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

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
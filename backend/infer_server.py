import uvicorn
import pandas as pd
import joblib
import numpy as np
import xgboost as xgb
import uuid
import os
from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import List, Dict, Any, Union, Optional

from anomaly_utils import SafetyNet
from xgb_utils import XGBDetector
from scaler_utils import TriChannelScaler

app = FastAPI(title="IDS Inference Engine")
model_store = {}
scaler_store = {}

# This list must match training features (15 features from cleaned_data15.csv)
EXPECTED_COLUMNS = [
    'Fwd Header Len', 'Protocol', 'Init Bwd Win Byts', 'Tot Fwd Pkts',
    'Pkt Len Max', 'Pkt Len Mean', 'Tot Bwd Pkts', 'Dst Port',
    'Bwd Pkt Len Max', 'Fwd Pkts/s', 'Flow IAT Max', 'TotLen Bwd Pkts',
    'TotLen Fwd Pkts', 'Bwd Pkt Len Std', 'Bwd Pkt Len Mean'
]

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

    # 6. Result
    result = {
        "verdict": "BENIGN",
        "confidence": 0.0,
        "source": src_ip,
        "destination": dst_ip,
        "scaler_used": scaler_id,
        "details": {
            "safety_net_flag": int(is_anomaly),
            "xgb_flag": int(xgb_pred),
            "xgb_probability": xgb_prob
        }
    }

    if xgb_pred == 1:
        result["verdict"] = "KNOWN_ATTACK"
        result["confidence"] = xgb_prob
    elif is_anomaly == 1:
        result["verdict"] = "ZERO_DAY_SUSPICION"
        result["confidence"] = 0.5 
    
    return result

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
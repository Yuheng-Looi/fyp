import uvicorn
import pandas as pd
import joblib
import numpy as np
import xgboost as xgb
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Union  # NOTE: Added Any

from anomaly_utils import SafetyNet
from xgb_utils import XGBDetector

app = FastAPI(title="IDS Inference Engine")
model_store = {}

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
        sn = joblib.load('models/safety_net_v1.pkl')
        model_store['safety_net'] = sn

        # XGBoost (JSON)
        xgb_model = xgb.XGBClassifier()
        xgb_model.load_model('models/xgb_binary_v1.json')
        xgb_det = XGBDetector()
        xgb_det.model = xgb_model
        model_store['xgb'] = xgb_det
        
        print("[+] All models loaded successfully!")
    except Exception as e:
        print(f"[!] Error loading models: {e}")

# --- FIX IS HERE ---
class NetworkFlow(BaseModel):
    # Change Dict[str, float] to Dict[str, Any]
    # This allows 'src': '10.0.0.1' (str) AND 'flow_duration': 0.5 (float)
    features: Dict[str, Any]

@app.post("/predict")
def predict_traffic(flow: NetworkFlow):
    if 'xgb' not in model_store:
        raise HTTPException(status_code=500, detail="Models not loaded")

    # 1. Convert JSON to DataFrame
    input_data = pd.DataFrame([flow.features])

    # Optional: Extract IPs for logging purposes (if available)
    src_ip = flow.features.get('src', 'Unknown')
    dst_ip = flow.features.get('dst', 'Unknown')
    
    # 2. SAFETY CHECK: Filter Columns
    # We strip out 'src' and 'dst' here so the model only gets the numbers it expects.
    try:
        model_input = input_data[EXPECTED_COLUMNS]
    except KeyError as e:
        return {"error": f"Missing feature in request: {e}"}

    # 3. Predictions (no scaler; models were trained on raw feature values)
    sn_model = model_store['safety_net']
    is_anomaly = sn_model.predict(model_input)[0]
    
    xgb_model = model_store['xgb']
    xgb_pred = xgb_model.model.predict(model_input)[0]
    xgb_prob = float(xgb_model.model.predict_proba(model_input)[0][1])

    # 5. Result
    result = {
        "verdict": "BENIGN",
        "confidence": 0.0,
        "source": src_ip, # We can now return the IP in the logs
        "destination": dst_ip,
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
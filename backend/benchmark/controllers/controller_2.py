from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, Any

import xgboost as xgb
import pandas as pd


SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.append(str(BACKEND_DIR))


EXPECTED_COLUMNS = [
    "Fwd Header Len",
    "Protocol",
    "Init Bwd Win Byts",
    "Tot Fwd Pkts",
    "Pkt Len Max",
    "Pkt Len Mean",
    "Tot Bwd Pkts",
    "Dst Port",
    "Bwd Pkt Len Max",
    "Fwd Pkts/s",
    "Flow IAT Max",
    "TotLen Bwd Pkts",
    "TotLen Fwd Pkts",
    "Bwd Pkt Len Std",
    "Bwd Pkt Len Mean",
]


class LocalSDNController:
    def __init__(self, model_path: str | None = None):
        self.model = None
        self.model_path = model_path or str(BACKEND_DIR / "models" / "xgb" / "xgb_binary_v1.json")
        self.load_local_model()

    def load_local_model(self) -> None:
        if os.path.exists(self.model_path):
            model = xgb.XGBClassifier()
            model.load_model(self.model_path)
            self.model = model

    def _build_feature_frame(self, flow_features: Dict[str, Any]) -> pd.DataFrame:
        row = {col: float(flow_features.get(col, 0.0) or 0.0) for col in EXPECTED_COLUMNS}
        return pd.DataFrame([row], columns=EXPECTED_COLUMNS)

    def evaluate_flow(self, flow_features: dict) -> dict:
        if self.model is None:
            return {"verdict": "BENIGN", "action": "ALLOW"}

        features = self._build_feature_frame(flow_features)
        try:
            pred = int(self.model.predict(features)[0])
        except Exception:
            pred = 0

        action = "BLOCK" if pred == 1 else "ALLOW"
        verdict = "ALERT" if action == "BLOCK" else "BENIGN"
        return {"verdict": verdict, "action": action}

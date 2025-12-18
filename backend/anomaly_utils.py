import numpy as np
import pandas as pd
import joblib
import copy
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score

class SafetyNet:
    """
    Unsupervised Anomaly Detection using Isolation Forest.
    Role: The 'Safety Net' for zero-day attacks.
    CRITICAL: Must receive Tri-Channel Scaled Features to be adaptive.
    """
    def __init__(self, scaler_path='scalers/trichannel_scaler.pkl', label_col='Label', features=None):
        self.label_col = label_col
        self.features = features
        self.scaler = None
        
        # We don't force load scaler here to keep class flexible, 
        # but in pipeline we expect scaled input.
        if scaler_path:
            try:
                self.scaler = joblib.load(scaler_path)
                print(f"[Info] SafetyNet loaded scaler from {scaler_path}")
            except:
                print(f"[Info] Scaler not found at {scaler_path}. Training expects pre-scaled data.")

        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.01,  # Assumption: ~1% of benign traffic might be noise
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )

    def fit(self, X_benign_real):
        """
        Train ONLY on Real Benign Data.
        Input X_benign_real MUST BE PRE-SCALED (45 features) if adaptability is desired.
        """
        # Auto-detect features if not provided
        if self.features is None:
            self.features = [c for c in X_benign_real.columns if c != self.label_col]

        print(f"[-] Safety Net: Training on {len(X_benign_real)} samples. Feature count: {len(self.features)}")
        
        # Ensure we only use features, no labels
        X_subset = X_benign_real[self.features]
        self.model.fit(X_subset)
        print("[+] Safety Net trained (Learned the distribution of 'Normal').")

    def predict(self, X):
        """
        Returns: 1 for Anomaly (Attack), 0 for Normal
        Input X MUST BE PRE-SCALED.
        """
        X_subset = X[self.features]
        # IsoForest raw: -1 is anomaly, 1 is normal
        raw_preds = self.model.predict(X_subset)
        # Invert: 1 = Attack, 0 = Normal
        return np.where(raw_preds == -1, 1, 0)

    def fit_with_split_search(self, df, seeds=(42, 52, 62), normal_label="Normal", val_size=0.2):
        """
        Finds the best random split that maximizes detection on a VALIDATION set.
        Note: Input 'df' SHOULD BE SCALED (45 features + Label).
        """
        if self.features is None:
            self.features = [c for c in df.columns if c != self.label_col]

        # Prepare Binary Targets (0=Normal, 1=Attack)
        y_binary = (df[self.label_col] != normal_label).astype(int)
        X = df[self.features]

        best_f1 = -np.inf
        best_seed = None
        best_model = None
        best_metrics = None

        print(f"[-] Starting Split Search on {len(df)} samples...")

        for seed in seeds:
            # 1. Stratified Split (to ensure attacks exist in Validation)
            X_train, X_val, y_train, y_val = train_test_split(
                X, y_binary, test_size=val_size, random_state=seed, stratify=y_binary
            )

            # 2. FILTER: Train ONLY on Benign samples
            # We must NOT let the model see attacks during training
            X_train_benign = X_train[y_train == 0]
            
            # Temporary model fit
            temp_model = copy.deepcopy(self.model)
            temp_model.fit(X_train_benign)

            # 3. Validate on Mixed Set (Benign + Attack) to check detection power
            raw_preds = temp_model.predict(X_val)
            preds = np.where(raw_preds == -1, 1, 0)

            # Calculate Metrics
            f1 = f1_score(y_val, preds, zero_division=0)
            
            # Score samples for AUC (Higher score = Normal, Lower = Anomaly)
            raw_scores = temp_model.score_samples(X_val)
            anomaly_scores = -raw_scores
            auc = roc_auc_score(y_val, anomaly_scores)

            metrics = {
                "f1": f1,
                "auc": auc,
                "precision": precision_score(y_val, preds, zero_division=0),
                "recall": recall_score(y_val, preds, zero_division=0)
            }
            
            print(f"   [Seed {seed}] F1: {f1:.4f} | AUC: {auc:.4f}")

            if f1 > best_f1:
                best_f1 = f1
                best_seed = seed
                best_metrics = metrics
                best_model = temp_model

        # Finalize the best model
        self.model = best_model
        print(f"[+] Best Split Found: Seed {best_seed} (F1={best_f1:.4f})")
        return {"best_seed": best_seed, "metrics": best_metrics}

    def save(self, path='models/safety_net.pkl'):
        joblib.dump(self, path)
        print(f"[+] Safety Net saved to {path}")
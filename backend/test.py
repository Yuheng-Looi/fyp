import os
import sys
import pandas as pd
import numpy as np
import joblib
import xgboost as xgb
from datetime import datetime
from sklearn.metrics import accuracy_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report

# Add script directory to path to import utils
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR)

from scaler_utils import TriChannelScaler
from anomaly_utils import SafetyNet
from xgb_utils import XGBDetector

# Configuration
DATASET_DIR = os.path.join(BASE_DIR, 'testDataSet')
SCALER_DIR = os.path.join(BASE_DIR, 'scalers')
MODEL_DIR = os.path.join(BASE_DIR, 'models')
OUTPUT_DIR = os.path.join(BASE_DIR, 'output')

# Expected columns (must match training)
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

def list_csv_files(directory):
    files = []
    if not os.path.exists(directory):
        print(f"Directory {directory} does not exist.")
        return []
    
    for f in os.listdir(directory):
        if f.endswith('.csv'):
            path = os.path.join(directory, f)
            if os.path.getsize(path) > 0:
                files.append(f)
    return sorted(files)

def list_scalers(directory):
    files = []
    if not os.path.exists(directory):
        return []
    
    for f in os.listdir(directory):
        if f.endswith('.pkl'):
            files.append(f)
    return sorted(files)

def load_models():
    models = {}
    
    # Load SafetyNet
    sn_path = os.path.join(MODEL_DIR, 'safety_net_v1.pkl')
    if os.path.exists(sn_path):
        try:
            models['safetynet'] = joblib.load(sn_path)
            print(f"[+] Loaded SafetyNet from {sn_path}")
        except Exception as e:
            print(f"[!] Failed to load SafetyNet: {e}")
    
    # Load XGBoost
    xgb_path = os.path.join(MODEL_DIR, 'xgb_binary_v1.json')
    if os.path.exists(xgb_path):
        try:
            bst = xgb.XGBClassifier()
            bst.load_model(xgb_path)
            xgb_det = XGBDetector()
            xgb_det.model = bst
            models['xgboost'] = xgb_det
            print(f"[+] Loaded XGBoost from {xgb_path}")
        except Exception as e:
            print(f"[!] Failed to load XGBoost: {e}")
            
    return models

def get_user_selection(options, prompt_text):
    print(f"\n{prompt_text}")
    for i, opt in enumerate(options):
        print(f"{i+1}. {opt}")
    
    while True:
        try:
            choice = int(input("Enter number: "))
            if 1 <= choice <= len(options):
                return options[choice-1]
            print("Invalid selection. Try again.")
        except ValueError:
            print("Please enter a number.")

def main():
    print("=== IDS Model Testing Tool ===")
    
    # 1. Select Dataset
    csv_files = list_csv_files(DATASET_DIR)
    if not csv_files:
        print("No CSV files found in testDataSet.")
        return
    
    selected_file = get_user_selection(csv_files, "Available Datasets:")
    file_path = os.path.join(DATASET_DIR, selected_file)
    
    print(f"\nLoading {selected_file}...")
    try:
        # Read CSV with low_memory=False to handle mixed types initially
        df = pd.read_csv(file_path, low_memory=False)
        
        # Rename columns if necessary
        df.rename(columns=COLUMN_MAPPING, inplace=True)
        
        # Check if expected columns exist
        missing = [c for c in EXPECTED_COLUMNS if c not in df.columns]
        if missing:
            print(f"[!] Warning: Missing columns: {missing}")
            print("Proceeding might fail if models require these features.")
            
        # CLEANING: Coerce expected columns to numeric and drop bad rows
        print("Cleaning data (removing non-numeric rows)...")
        initial_len = len(df)
        for col in EXPECTED_COLUMNS:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')
        
        # Drop rows where any of the expected columns are NaN
        # (This handles repeated headers or garbage data)
        df.dropna(subset=[c for c in EXPECTED_COLUMNS if c in df.columns], inplace=True)
        
        # Also handle Infinity
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(subset=[c for c in EXPECTED_COLUMNS if c in df.columns], inplace=True)
        
        dropped_count = initial_len - len(df)
        if dropped_count > 0:
            print(f"[!] Dropped {dropped_count} rows containing non-numeric values or Infinity.")

    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # 1.5 Check for Labels
    label_col = input("\nIs this dataset labeled? Enter label column name (or press Enter to skip): ").strip()
    if label_col and label_col not in df.columns:
        print(f"[!] Column '{label_col}' not found. Treating as unlabeled.")
        label_col = None
    
    # 2. Select Scaler
    scaler_files = list_scalers(SCALER_DIR)
    scaler_options = scaler_files + ["Refit new scaler (Calibration)"]
    
    selected_scaler_opt = get_user_selection(scaler_options, "Select Scaler:")
    
    scaler = None
    if selected_scaler_opt == "Refit new scaler (Calibration)":
        # Refit Strategy
        refit_strategy = "random"
        benign_val = None
        
        if label_col:
            print("\nRefit Strategy:")
            print("1. Random sample (Unsupervised/Mixed)")
            print("2. Benign samples only (Supervised Calibration)")
            strat_choice = input("Enter number (1 or 2): ").strip()
            if strat_choice == "2":
                refit_strategy = "benign"
                benign_val = input(f"Enter value for Benign label in '{label_col}' (e.g. 'Benign', 'Normal', 0): ").strip()
        
        while True:
            try:
                pct = float(input("\nEnter percentage of data to use for calibration (1-100): "))
                if 0 < pct <= 100:
                    break
                print("Please enter a value between 1 and 100.")
            except ValueError:
                print("Invalid number.")
        
        print(f"Fitting scaler on first {pct}% of the data...")
        n_samples = int(len(df) * (pct / 100))
        
        if refit_strategy == "benign":
            # Filter for benign only
            # We need to be careful if benign samples are fewer than n_samples
            df_benign = df[df[label_col].astype(str) == benign_val]
            if len(df_benign) == 0:
                print(f"[!] No samples found with label '{benign_val}'. Falling back to random sample.")
                df_calib = df.iloc[:n_samples][EXPECTED_COLUMNS].copy()
            else:
                # Take up to n_samples from benign
                take_n = min(n_samples, len(df_benign))
                print(f"Using {take_n} benign samples for calibration.")
                df_calib = df_benign.iloc[:take_n][EXPECTED_COLUMNS].copy()
        else:
            df_calib = df.iloc[:n_samples][EXPECTED_COLUMNS].copy()
        
        # Create dummy labels (0) and tell scaler benign_label is 0
        dummy_labels = pd.Series([0] * len(df_calib), index=df_calib.index)
        
        scaler = TriChannelScaler(benign_label=0)
        scaler.fit(df_calib, dummy_labels)
        print("[+] Scaler fitted successfully.")
        
    else:
        scaler_path = os.path.join(SCALER_DIR, selected_scaler_opt)
        print(f"Loading scaler from {scaler_path}...")
        scaler = joblib.load(scaler_path)

    # 3. Select Model
    model_options = ["SafetyNet (Isolation Forest)", "XGBoost", "Both"]
    selected_model_opt = get_user_selection(model_options, "Select Model to Label:")
    
    models = load_models()
    if not models:
        print("No models available. Exiting.")
        return

    # 4. Process
    print("\nProcessing...")
    
    # Transform features
    try:
        X_raw = df[EXPECTED_COLUMNS]
        print("Transforming features to Tri-Channel (15 -> 45)...")
        X_scaled = scaler.transform(X_raw)
    except KeyError as e:
        print(f"Error: Dataset missing required columns: {e}")
        return
    except Exception as e:
        print(f"Error during scaling: {e}")
        return

    # Prepare output dataframe
    df_out = df.copy()
    
    # Run Predictions
    y_true = None
    normal_label_val = None
    
    if label_col:
        normal_label_val = input(f"\nEnter value for Normal label in '{label_col}' to calculate metrics (e.g. 'Benign'): ").strip()
        # Create binary y_true: 0 for Normal, 1 for Attack
        y_true = (df[label_col].astype(str) != normal_label_val).astype(int)

    if selected_model_opt in ["SafetyNet (Isolation Forest)", "Both"]:
        if 'safetynet' in models:
            print("\n--- SafetyNet Results ---")
            # SafetyNet predict returns 1 for anomaly, 0 for normal
            preds = models['safetynet'].predict(X_scaled)
            df_out['SafetyNet_Pred'] = preds
            # Map to string
            df_out['SafetyNet_Label'] = df_out['SafetyNet_Pred'].map({1: 'Anomaly', 0: 'Normal'})
            
            if y_true is not None:
                print(f"Accuracy: {accuracy_score(y_true, preds):.4f}")
                print(f"Recall:   {recall_score(y_true, preds):.4f}")
                print(f"F1 Score: {f1_score(y_true, preds):.4f}")
                print(f"AUC:      {roc_auc_score(y_true, preds):.4f}")
                print("Confusion Matrix:")
                print(confusion_matrix(y_true, preds))
        else:
            print("[!] SafetyNet model not loaded.")

    if selected_model_opt in ["XGBoost", "Both"]:
        if 'xgboost' in models:
            print("\n--- XGBoost Results ---")
            # XGBoost predict
            preds = models['xgboost'].model.predict(X_scaled)
            probs = models['xgboost'].model.predict_proba(X_scaled)[:, 1]
            df_out['XGB_Pred'] = preds
            df_out['XGB_Prob'] = probs
            df_out['XGB_Label'] = df_out['XGB_Pred'].map({1: 'Attack', 0: 'Normal'})
            
            if y_true is not None:
                print(f"Accuracy: {accuracy_score(y_true, preds):.4f}")
                print(f"Recall:   {recall_score(y_true, preds):.4f}")
                print(f"F1 Score: {f1_score(y_true, preds):.4f}")
                print(f"AUC:      {roc_auc_score(y_true, probs):.4f}")
                print("Confusion Matrix:")
                print(confusion_matrix(y_true, preds))
        else:
            print("[!] XGBoost model not loaded.")

    # 5. Output
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        
    output_filename = f"{os.path.splitext(selected_file)[0]}_predicted.csv"
    output_path = os.path.join(OUTPUT_DIR, output_filename)
    
    print(f"\nSaving results to {output_path}...")
    df_out.to_csv(output_path, index=False)
    print("Done!")

if __name__ == "__main__":
    main()

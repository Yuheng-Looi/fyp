import os
import sys
import json
import torch
import joblib
import argparse
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# Ensure backend directory is in python path
sys.path.append("/home/fyp2025/fyp/backend")
import gnn_utils
from scaler_utils import TriChannelScaler

# Column mapping from raw columns to normalized names
COL_MAP = {
    'Source IP': 'Src IP',
    'Source Port': 'Src Port',
    'Destination IP': 'Dst IP',
    'Destination Port': 'Dst Port',
    'Protocol': 'Protocol',
    'Timestamp': 'Timestamp',
    'Flow Duration': 'Flow Duration',
    'Total Fwd Packets': 'Tot Fwd Pkts',
    'Total Backward Packets': 'Tot Bwd Pkts',
    'Total Length of Fwd Packets': 'TotLen Fwd Pkts',
    'Total Length of Bwd Packets': 'TotLen Bwd Pkts',
    'Fwd Packet Length Max': 'Fwd Pkt Len Max',
    'Fwd Packet Length Min': 'Fwd Pkt Len Min',
    'Fwd Packet Length Mean': 'Fwd Pkt Len Mean',
    'Fwd Packet Length Std': 'Fwd Pkt Len Std',
    'Bwd Packet Length Max': 'Bwd Pkt Len Max',
    'Bwd Packet Length Min': 'Bwd Pkt Len Min',
    'Bwd Packet Length Mean': 'Bwd Pkt Len Mean',
    'Bwd Packet Length Std': 'Bwd Pkt Len Std',
    'Flow Bytes/s': 'Flow Byts/s',
    'Flow Packets/s': 'Flow Pkts/s',
    'Flow IAT Mean': 'Flow IAT Mean',
    'Flow IAT Std': 'Flow IAT Std',
    'Flow IAT Max': 'Flow IAT Max',
    'Flow IAT Min': 'Flow IAT Min',
    'Fwd IAT Total': 'Fwd IAT Tot',
    'Fwd IAT Mean': 'Fwd IAT Mean',
    'Fwd IAT Std': 'Fwd IAT Std',
    'Fwd IAT Max': 'Fwd IAT Max',
    'Fwd IAT Min': 'Fwd IAT Min',
    'Bwd IAT Total': 'Bwd IAT Tot',
    'Bwd IAT Mean': 'Bwd IAT Mean',
    'Bwd IAT Std': 'Bwd IAT Std',
    'Bwd IAT Max': 'Bwd IAT Max',
    'Bwd IAT Min': 'Bwd IAT Min',
    'Bwd PSH Flags': 'Bwd PSH Flags',
    'Bwd URG Flags': 'Bwd URG Flags',
    'Fwd Header Length': 'Fwd Header Len',
    'Bwd Header Length': 'Bwd Header Len',
    'Fwd Packets/s': 'Fwd Pkts/s',
    'Bwd Packets/s': 'Bwd Pkts/s',
    'Min Packet Length': 'Pkt Len Min',
    'Max Packet Length': 'Pkt Len Max',
    'Packet Length Mean': 'Pkt Len Mean',
    'Packet Length Std': 'Pkt Len Std',
    'Packet Length Variance': 'Pkt Len Var',
    'FIN Flag Count': 'FIN Flag Cnt',
    'SYN Flag Count': 'SYN Flag Cnt',
    'RST Flag Count': 'RST Flag Cnt',
    'PSH Flag Count': 'PSH Flag Cnt',
    'ACK Flag Count': 'ACK Flag Cnt',
    'URG Flag Count': 'URG Flag Cnt',
    'ECE Flag Count': 'ECE Flag Cnt',
    'Down/Up Ratio': 'Down/Up Ratio',
    'Average Packet Size': 'Pkt Size Avg',
    'Avg Fwd Segment Size': 'Fwd Seg Size Avg',
    'Avg Bwd Segment Size': 'Bwd Seg Size Avg',
    'Fwd Avg Bytes/Bulk': 'Fwd Byts/b Avg',
    'Fwd Avg Packets/Bulk': 'Fwd Pkts/b Avg',
    'Fwd Avg Bulk Rate': 'Fwd Blk Rate Avg',
    'Bwd Avg Bytes/Bulk': 'Bwd Byts/b Avg',
    'Bwd Avg Packets/Bulk': 'Bwd Pkts/b Avg',
    'Bwd Avg Bulk Rate': 'Bwd Blk Rate Avg',
    'Subflow Fwd Packets': 'Subflow Fwd Pkts',
    'Subflow Fwd Bytes': 'Subflow Fwd Byts',
    'Subflow Bwd Packets': 'Subflow Bwd Pkts',
    'Subflow Bwd Bytes': 'Subflow Bwd Byts',
    'Init_Win_bytes_forward': 'Init Fwd Win Byts',
    'Init_Win_bytes_backward': 'Init Bwd Win Byts',
    'act_data_pkt_fwd': 'Fwd Act Data Pkts',
    'min_seg_size_forward': 'Fwd Seg Size Min',
    'Active Mean': 'Active Mean',
    'Active Std': 'Active Std',
    'Active Max': 'Active Max',
    'Active Min': 'Active Min',
    'Idle Mean': 'Idle Mean',
    'Idle Std': 'Idle Std',
    'Idle Max': 'Idle Max',
    'Idle Min': 'Idle Min',
    'Label': 'Label'
}

LABEL_MAP_DNS = {
    'BENIGN': 'Normal',
    'DrDoS_DNS': 'DDoS'
}

LABEL_MAP_FRIDAY = {
    'Benign': 'Normal',
    'DoS attacks-Hulk': 'DoS',
    'DoS attacks-SlowHTTPTest': 'DoS'
}

def format_markdown_table(headers, rows):
    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(x) for x in row) + " |")
    return "\n".join(lines)

def load_and_preprocess_raw(csv_path, dataset_type, feature_cols, nrows):
    print(f"Loading {nrows} rows from {csv_path} ({dataset_type})...")
    df = pd.read_csv(csv_path, nrows=nrows, low_memory=False)
    df.columns = df.columns.str.strip()
    
    if 'Label' in df.columns:
        df = df[df['Label'] != 'Label']
    elif ' Label' in df.columns:
        df = df[df[' Label'] != 'Label']
        
    df.rename(columns=COL_MAP, inplace=True)
    
    if dataset_type == 'dns':
        df['Label'] = df['Label'].map(LABEL_MAP_DNS).fillna('Normal')
    elif dataset_type == 'friday':
        df['Label'] = df['Label'].map(LABEL_MAP_FRIDAY).fillna('Normal')
        
    if 'Src IP' not in df.columns:
        df['Src IP'] = '10.0.0.1'
    if 'Dst IP' not in df.columns:
        df['Dst IP'] = '10.0.0.2'
        
    for col in feature_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
            
    df.dropna(subset=feature_cols, inplace=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=feature_cols, inplace=True)
    
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    df = df.sort_values('Timestamp').reset_index(drop=True)
    
    return df

def select_best_strategy(results):
    # Heuristic: choose strategy with Normal ratio between 20% and 80%, maximizing Pseudo confidence.
    valid = [r for r in results if 0.20 <= r['Normal ratio'] <= 0.80]
    if not valid:
        # Fallback to closest normal ratio to 50%
        valid = sorted(results, key=lambda x: abs(x['Normal ratio'] - 0.5))
        return valid[0]['key']
    
    # Sort by pseudo confidence descending
    valid = sorted(valid, key=lambda x: x['Pseudo confidence'], reverse=True)
    return valid[0]['key']

def evaluate_gnn_model(df_test, feature_cols, model_name, task, results_dir, label_encoder, device, scaler, is_adaptive):
    if task == 'binary':
        strategy = 'hybrid'
        arch = 'gat'
        config = {'hidden_dim': 64, 'num_layers': 2, 'dropout': 0.3}
        num_classes = 2
        is_binary = True
    else:
        strategy = 'src_ip_temporal'
        arch = 'sage'
        config = {'hidden_dim': 128, 'num_layers': 3, 'dropout': 0.5}
        num_classes = len(label_encoder.classes_)
        is_binary = False

    config_path = os.path.join(results_dir, f"{model_name}_{task}_config.json")
    model_path = os.path.join(results_dir, f"{model_name}_{task}_model.pt")
    
    if not os.path.exists(config_path) or not os.path.exists(model_path):
        return None

    # Scale feature columns
    df = df_test.copy()
    if model_name == 'model1':
        # TriChannelScaler transformation
        # Note: Tri-channel scaler was trained on the base 15 features
        raw_15_features = scaler.feature_names_
        df_scaled_feats = scaler.transform(df[raw_15_features])
        meta_cols = ['Src IP', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', 'Label']
        df = pd.concat([df_scaled_feats, df[meta_cols]], axis=1)
        
        # Load the feature list expected by the model
        with open(config_path, 'r') as f:
            model_features = json.load(f)['features']
    else:
        # StandardScaler transformation
        df[feature_cols] = scaler.transform(df[feature_cols])
        model_features = feature_cols

    # Encode label
    df['Label_Encoded'] = label_encoder.transform(df['Label'])

    # Build Graph topology
    original_data = gnn_utils.build_graph(df, model_features, strategy=strategy)
    data = original_data.clone()

    if is_binary:
        normal_idx = label_encoder.transform(['Normal'])[0]
        data.y = (original_data.y != normal_idx).long()

    data = data.to(device)

    # Initialize GNN Classifier
    model = gnn_utils.GNNClassifier(
        input_dim=len(model_features),
        hidden_dim=config['hidden_dim'],
        num_classes=num_classes,
        num_layers=config['num_layers'],
        dropout=config['dropout'],
        arch=arch
    ).to(device)

    # Load weights
    model.load_state_dict(torch.load(model_path, map_location=device))
    model.eval()

    # Predict
    with torch.no_grad():
        logits = model(data.x, data.edge_index)
        preds = logits.argmax(dim=1)
        
    y_true = data.y.cpu().numpy()
    y_pred = preds.cpu().numpy()

    # Calculate metrics
    accuracy = accuracy_score(y_true, y_pred)
    
    if is_binary:
        y_true_bin = y_true
        y_pred_bin = y_pred
        f1 = f1_score(y_true, y_pred, zero_division=0)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
    else:
        normal_idx = label_encoder.transform(['Normal'])[0]
        y_true_bin = (y_true != normal_idx).astype(int)
        y_pred_bin = (y_pred != normal_idx).astype(int)
        f1 = f1_score(y_true, y_pred, average='macro', zero_division=0)
        precision = precision_score(y_true_bin, y_pred_bin, zero_division=0)
        recall = recall_score(y_true_bin, y_pred_bin, zero_division=0)
        
    tn, fp, fn, tp = confusion_matrix(y_true_bin, y_pred_bin, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        'Accuracy': accuracy,
        'Test F1': f1,
        'Attack Recall': recall if is_binary else recall_score(y_true_bin, y_pred_bin, zero_division=0),
        'FPR': fpr,
        'Precision': precision
    }

def main():
    parser = argparse.ArgumentParser(description="Adaptive Calibration Experiment for GNN IDS.")
    parser.add_argument("--dataset", type=str, default="both", choices=["dns", "friday", "both"], help="Which dataset to test.")
    args = parser.parse_args()

    results_dir = "/home/fyp2025/fyp/backend/gnn_compare"
    dns_csv = "/home/fyp2025/fyp/backend/testDataSet/DrDoS_DNS_data_1_per.csv"
    friday_csv = "/home/fyp2025/fyp/backend/testDataSet/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"
    encoder_path = "/home/fyp2025/fyp/backend/encoders/label_encoder.pkl"
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    print(f"Using Device: {device}")

    # Load artifacts
    with open(encoder_path, 'rb') as f:
        label_encoder = joblib.load(f)

    pre_trained_scaler = joblib.load("/home/fyp2025/fyp/backend/scalers/trichannel_scaler.pkl")
    raw_15_features = pre_trained_scaler.feature_names_

    with open(os.path.join(results_dir, "model2_binary_config.json"), 'r') as f:
        raw_51_features = json.load(f)['features']

    all_features = list(set(raw_15_features + raw_51_features))

    datasets_to_run = []
    if args.dataset in ["dns", "both"]:
        datasets_to_run.append(("dns", dns_csv))
    if args.dataset in ["friday", "both"]:
        datasets_to_run.append(("friday", friday_csv))

    overall_report = "# Adaptive GNN IDS Calibration Experiment Report\n\n"

    for ds_name, csv_path in datasets_to_run:
        print(f"\n==================================================")
        print(f"RUNNING ADAPTIVE EXPERIMENT ON: {ds_name.upper()}")
        print(f"==================================================")

        # Load first 60,000 flows total (20k calibration, 40k test)
        df_all = load_and_preprocess_raw(csv_path, ds_name, all_features, nrows=60000)
        
        if len(df_all) < 30000:
            print(f"[!] Dataset {ds_name} too small ({len(df_all)} rows). Skipping.")
            continue

        # Split into calibration (first 20k) and test (next 40k)
        df_calib = df_all.iloc[:20000].copy().reset_index(drop=True)
        df_test = df_all.iloc[20000:60000].copy().reset_index(drop=True)

        print(f"Calibration size: {len(df_calib)}, Test size: {len(df_test)}")

        # ----------------------------------------------------
        # PHASE 1: Initial environment calibration & pseudo-labeling
        # ----------------------------------------------------
        print("\n[Phase 1] Calibrating Environment & Pseudo-labeling...")
        
        # Load calibration models
        xgb_model = xgb.XGBClassifier()
        xgb_model.load_model('/home/fyp2025/fyp/backend/models/xgb/xgb_binary_v1.json')
        sn = joblib.load('/home/fyp2025/fyp/backend/models/safetynet/safety_net_v1.pkl')

        # Generate 45 features on 20k calibration flows using the pre-trained scaler
        calib_scaled_feats = pre_trained_scaler.transform(df_calib[raw_15_features])

        # Run predictions
        xgb_probs = xgb_model.predict_proba(calib_scaled_feats)[:, 1]
        if_scores = -sn.model.score_samples(calib_scaled_feats) # higher = more anomalous

        # Define evaluation options
        strategy_options = [
            # Option A: AND logic
            {'opt': 'Option A', 'xgb_t': 0.7, 'if_t': 0.55, 'op': 'AND'},
            {'opt': 'Option A', 'xgb_t': 0.7, 'if_t': 0.60, 'op': 'AND'},
            {'opt': 'Option A', 'xgb_t': 0.7, 'if_t': 0.65, 'op': 'AND'},
            # Option B: OR logic
            {'opt': 'Option B', 'xgb_t': 0.7, 'if_t': 0.55, 'op': 'OR'},
            {'opt': 'Option B', 'xgb_t': 0.7, 'if_t': 0.60, 'op': 'OR'},
            {'opt': 'Option B', 'xgb_t': 0.7, 'if_t': 0.65, 'op': 'OR'},
            # Option C: high threshold AND
            {'opt': 'Option C', 'xgb_t': 0.8, 'if_t': 0.55, 'op': 'AND'},
            {'opt': 'Option C', 'xgb_t': 0.8, 'if_t': 0.60, 'op': 'AND'},
            {'opt': 'Option C', 'xgb_t': 0.8, 'if_t': 0.65, 'op': 'AND'},
            # Option D: low threshold OR
            {'opt': 'Option D', 'xgb_t': 0.6, 'if_t': 0.55, 'op': 'OR'},
            {'opt': 'Option D', 'xgb_t': 0.6, 'if_t': 0.60, 'op': 'OR'},
            {'opt': 'Option D', 'xgb_t': 0.6, 'if_t': 0.65, 'op': 'OR'},
        ]

        strategy_results = []
        strategy_pseudo_labels = {}

        for i, s in enumerate(strategy_options):
            xgb_t = s['xgb_t']
            if_t = s['if_t']
            
            if s['op'] == 'AND':
                pseudo_labels = ((xgb_probs >= xgb_t) & (if_scores >= if_t)).astype(int)
            else:
                pseudo_labels = ((xgb_probs >= xgb_t) | (if_scores >= if_t)).astype(int)

            attack_ratio = np.mean(pseudo_labels)
            normal_ratio = 1.0 - attack_ratio

            # Calculate confidence: probability of the pseudo-labeled class
            confidence = np.where(pseudo_labels == 1, xgb_probs, 1.0 - xgb_probs)
            mean_conf = np.mean(confidence)

            key = f"{s['opt']}_xgb{xgb_t}_if{if_t}_{s['op']}"
            
            strategy_results.append({
                'key': key,
                'Strategy': s['opt'],
                'XGB threshold': xgb_t,
                'IF threshold': if_t,
                'op': s['op'],
                'Attack ratio': attack_ratio,
                'Normal ratio': normal_ratio,
                'Pseudo confidence': mean_conf
            })
            strategy_pseudo_labels[key] = pseudo_labels

        # Select the best strategy based on the heuristic
        selected_key = select_best_strategy(strategy_results)
        print(f"Selected strategy for calibration: {selected_key}")

        # Table X output rows
        table_x_rows = []
        for r in strategy_results:
            is_selected = "Yes" if r['key'] == selected_key else "No"
            table_x_rows.append([
                f"{r['Strategy']} ({r['op']})",
                f"{r['XGB threshold']:.2f}",
                f"{r['IF threshold']:.2f}",
                f"{r['Attack ratio']:.4f}",
                f"{r['Normal ratio']:.4f}",
                f"{r['Pseudo confidence']:.4f}",
                is_selected
            ])

        # ----------------------------------------------------
        # PHASE 2: Adaptive calibration (fitting scalers)
        # ----------------------------------------------------
        print("\n[Phase 2] Calibrating Scalers with Pseudo-labels...")
        selected_labels = strategy_pseudo_labels[selected_key]

        # 1. Model 1: Calibrate TriChannelScaler on pseudo Normal flows only
        normal_mask = (selected_labels == 0)
        df_calib_normal = df_calib[normal_mask].copy()

        if len(df_calib_normal) < 100:
            print("[!] Warning: Too few normal samples in pseudo labeling! Calibration might be unstable.")
            df_calib_normal = df_calib.copy() # fallback
            
        df_calib_normal.reset_index(drop=True, inplace=True)
        adaptive_trichannel = TriChannelScaler(benign_label=0)
        adaptive_trichannel.fit(df_calib_normal[raw_15_features], pd.Series([0]*len(df_calib_normal), index=df_calib_normal.index))
        print(f"  Adapted TriChannelScaler parameters successfully on {len(df_calib_normal)} pseudo-normal flows.")

        # 2. Model 2: Calibrate StandardScaler on all 20k calibration flows
        adaptive_scaler_51 = StandardScaler()
        adaptive_scaler_51.fit(df_calib[raw_51_features])

        # 3. Model 3: Calibrate StandardScaler on all 20k calibration flows
        adaptive_scaler_15 = StandardScaler()
        adaptive_scaler_15.fit(df_calib[raw_15_features])

        # ----------------------------------------------------
        # PHASE 3: Testing & Evaluation on next 40,000 flows
        # ----------------------------------------------------
        print("\n[Phase 3] Evaluating GNN models on next 40,000 test flows...")
        
        # Prepare "Original" scalers for evaluation
        # original standard scalers are fitted on the test set directly, as standard practice
        original_scaler_51 = StandardScaler().fit(df_test[raw_51_features])
        original_scaler_15 = StandardScaler().fit(df_test[raw_15_features])

        # We will collect evaluation results
        eval_results = []
        models = ["model1", "model2", "model3"]
        tasks = ["binary", "multiclass"]

        for model_name in models:
            for task in tasks:
                # Select scalers
                if model_name == "model1":
                    scaler_orig = pre_trained_scaler
                    scaler_adap = adaptive_trichannel
                    feat_cols = raw_15_features
                elif model_name == "model2":
                    scaler_orig = original_scaler_51
                    scaler_adap = adaptive_scaler_51
                    feat_cols = raw_51_features
                else: # model3
                    scaler_orig = original_scaler_15
                    scaler_adap = adaptive_scaler_15
                    feat_cols = raw_15_features

                # Run Original
                orig_metrics = evaluate_gnn_model(
                    df_test, feat_cols, model_name, task, results_dir, label_encoder, device, scaler_orig, is_adaptive=False
                )
                
                # Run Adaptive
                adap_metrics = evaluate_gnn_model(
                    df_test, feat_cols, model_name, task, results_dir, label_encoder, device, scaler_adap, is_adaptive=True
                )

                if orig_metrics:
                    eval_results.append({
                        "Model": model_name.upper(), "Task": task.upper(), "Calibration": "Original",
                        **orig_metrics
                    })
                if adap_metrics:
                    eval_results.append({
                        "Model": model_name.upper(), "Task": task.upper(), "Calibration": "Adaptive",
                        **adap_metrics
                    })

        # Table Y output rows
        table_y_rows = []
        for r in eval_results:
            table_y_rows.append([
                r["Model"],
                r["Task"],
                f"{r['Accuracy']:.6f}",
                f"{r['Test F1']:.6f}",
                f"{r['Attack Recall']:.6f}",
                f"{r['FPR']:.6f}",
                r["Calibration"]
            ])

        # Save results to CSV files
        os.makedirs(results_dir, exist_ok=True)
        
        df_table_x = pd.DataFrame(strategy_results)
        df_table_x['Selected'] = df_table_x['key'].apply(lambda x: "Yes" if x == selected_key else "No")
        df_table_x.drop(columns=['key', 'op'], inplace=True)
        csv_x_path = os.path.join(results_dir, f"adaptive_strategies_{ds_name}.csv")
        df_table_x.to_csv(csv_x_path, index=False)
        
        df_table_y = pd.DataFrame(eval_results)
        csv_y_path = os.path.join(results_dir, f"adaptive_eval_{ds_name}.csv")
        df_table_y.to_csv(csv_y_path, index=False)

        print(f"Results saved to {csv_x_path} and {csv_y_path}")

        # Construct Markdown report for this dataset
        table_x_headers = ["Strategy", "XGB threshold", "IF threshold", "Attack ratio", "Normal ratio", "Pseudo confidence", "Selected?"]
        table_y_headers = ["Model", "Task", "Accuracy", "Test F1", "Attack Recall", "FPR", "Calibration Method"]

        overall_report += f"""## Dataset: {ds_name.upper()}

### Table X: Pseudo-label calibration strategy comparison
*Tested on the first 20,000 flows. Strategy selected based on high confidence and viable Normal ratio.*

{format_markdown_table(table_x_headers, table_x_rows)}

### Table Y: Adaptive external dataset evaluation
*Evaluated on the next 40,000 test flows. Normal labels mapped: BENIGN &rarr; Normal, DrDoS_DNS / DoS attacks &rarr; Attack.*

{format_markdown_table(table_y_headers, table_y_rows)}

---
"""

    # Save overall markdown report
    report_md_path = os.path.join(results_dir, "adaptive_comparison_report.md")
    with open(report_md_path, 'w') as f:
        f.write(overall_report)

    print(f"\n[+] Adaptive IDS Calibration Experiment Complete!")
    print(f"Comprehensive report saved to {report_md_path}")

if __name__ == "__main__":
    main()

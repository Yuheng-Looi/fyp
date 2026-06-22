import os
import sys
import json
import torch
import joblib
import argparse
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, recall_score, f1_score, confusion_matrix

# Ensure backend directory is in python path
sys.path.append("/home/fyp2025/fyp/backend")
import gnn_utils

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

# Label mappings to align with training classes
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

def load_and_preprocess_test_data(csv_path, dataset_type, feature_cols, nrows):
    print(f"\n[+] Loading {nrows} rows from {csv_path} ({dataset_type})...")
    df = pd.read_csv(csv_path, nrows=nrows, low_memory=False)
    
    # 1. Clean column names
    df.columns = df.columns.str.strip()
    
    # Drop rows that are duplicate header rows (common in merged datasets)
    if 'Label' in df.columns:
        df = df[df['Label'] != 'Label']
    elif ' Label' in df.columns:
        df = df[df[' Label'] != 'Label']
        
    df.rename(columns=COL_MAP, inplace=True)
    
    # 2. Map labels
    if dataset_type == 'dns':
        df['Label'] = df['Label'].map(LABEL_MAP_DNS).fillna('Normal')
    elif dataset_type == 'friday':
        df['Label'] = df['Label'].map(LABEL_MAP_FRIDAY).fillna('Normal')
        
    # Inject dummy IPs if missing (enables temporal/hybrid graph construction)
    if 'Src IP' not in df.columns:
        df['Src IP'] = '10.0.0.1'
    if 'Dst IP' not in df.columns:
        df['Dst IP'] = '10.0.0.2'
    
    # 3. Clean numeric features
    for col in feature_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
            
    # Drop rows where required features are NaN or Inf
    df.dropna(subset=feature_cols, inplace=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=feature_cols, inplace=True)
    
    # 4. Parse Timestamps and Sort for Graph topology
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    df = df.sort_values('Timestamp').reset_index(drop=True)
    
    return df

def get_original_results(results_dir):
    models = ["model1", "model2", "model3"]
    tasks = ["binary", "multiclass"]
    
    rows = []
    for model_name in models:
        for task in tasks:
            config_path = os.path.join(results_dir, f"{model_name}_{task}_config.json")
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    data = json.load(f)
                info = data.get('info', {})
                
                rows.append([
                    model_name.upper(),
                    task.upper(),
                    info.get("arch", "").upper(),
                    info.get("strategy", ""),
                    f"{info.get('test_f1', 0.0):.6f}",
                    f"{info.get('attack_recall', 0.0):.6f}",
                    f"{info.get('fpr', 0.0):.6f}",
                    f"{info.get('training_time', 0.0):.2f}"
                ])
            else:
                rows.append([model_name.upper(), task.upper(), "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"])
    return rows

def evaluate_model_on_test_data(df_raw, model_name, task, results_dir, label_encoder, device):
    # Determine configuration based on task
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

    # Get feature list and load model
    config_path = os.path.join(results_dir, f"{model_name}_{task}_config.json")
    model_path = os.path.join(results_dir, f"{model_name}_{task}_model.pt")
    
    if not os.path.exists(config_path) or not os.path.exists(model_path):
        print(f"  [!] Checkpoint for {model_name} {task} not found. Skipping.")
        return None

    with open(config_path, 'r') as f:
        config_data = json.load(f)
    feature_cols = config_data['features']

    # Preprocess & Scale
    df = df_raw.copy()
    
    if model_name == 'model1':
        # Tri-channel scaling
        scaler_path = "/home/fyp2025/fyp/backend/scalers/trichannel_scaler.pkl"
        scaler = joblib.load(scaler_path)
        raw_15_features = scaler.feature_names_
        df_scaled_feats = scaler.transform(df[raw_15_features])
        meta_cols = ['Src IP', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', 'Label']
        df = pd.concat([df_scaled_feats, df[meta_cols]], axis=1)
    else:
        # Standard scaling (Model 2 and Model 3)
        scaler = StandardScaler()
        df[feature_cols] = scaler.fit_transform(df[feature_cols])

    # Encode label using loaded encoder
    df['Label_Encoded'] = label_encoder.transform(df['Label'])

    # Build Graph Topology
    print(f"  Building test graph for {model_name} {task}...")
    original_data = gnn_utils.build_graph(df, feature_cols, strategy=strategy)
    data = original_data.clone()

    if is_binary:
        normal_idx = label_encoder.transform(['Normal'])[0]
        data.y = (original_data.y != normal_idx).long()

    data = data.to(device)

    # Initialize GNN Classifier
    model = gnn_utils.GNNClassifier(
        input_dim=len(feature_cols),
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

    # Metrics
    accuracy = accuracy_score(y_true, y_pred)
    
    if is_binary:
        y_true_bin = y_true
        y_pred_bin = y_pred
        f1 = f1_score(y_true, y_pred)
    else:
        normal_idx = label_encoder.transform(['Normal'])[0]
        y_true_bin = (y_true != normal_idx).astype(int)
        y_pred_bin = (y_pred != normal_idx).astype(int)
        f1 = f1_score(y_true, y_pred, average='macro')
        
    recall_attack = recall_score(y_true_bin, y_pred_bin, pos_label=1, zero_division=0)
    
    tn, fp, fn, tp = confusion_matrix(y_true_bin, y_pred_bin, labels=[0, 1]).ravel()
    fpr_normal = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        'accuracy': accuracy,
        'recall_attack': recall_attack,
        'fpr_normal': fpr_normal,
        'f1_score': f1
    }

def run_evaluation_on_dataset(csv_path, dataset_type, raw_15_features, raw_51_features, nrows, results_dir, label_encoder, device):
    all_raw_features = list(set(raw_15_features + raw_51_features))
    
    # Load and clean dataset
    df_raw = load_and_preprocess_test_data(csv_path, dataset_type, all_raw_features, nrows)
    print(f"  Test dataset loaded. Preprocessed shape: {df_raw.shape}")
    
    test_rows = []
    models = ["model1", "model2", "model3"]
    tasks = ["binary", "multiclass"]

    for model_name in models:
        for task in tasks:
            metrics = evaluate_model_on_test_data(df_raw, model_name, task, results_dir, label_encoder, device)
            if metrics:
                test_rows.append([
                    model_name.upper(),
                    task.upper(),
                    f"{metrics['accuracy']:.6f}",
                    f"{metrics['f1_score']:.6f}",
                    f"{metrics['recall_attack']:.6f}",
                    f"{metrics['fpr_normal']:.6f}"
                ])
            else:
                test_rows.append([model_name.upper(), task.upper(), "N/A", "N/A", "N/A", "N/A"])
                
    test_headers = ["Model", "Task", "Accuracy", "Test F1", "Attack Recall", "FPR"]
    return format_markdown_table(test_headers, test_rows)

def main():
    parser = argparse.ArgumentParser(description="Evaluate GNN models on external test sets.")
    parser.add_argument("--dataset", type=str, default="both", choices=["dns", "friday", "both"], help="Which dataset to test on.")
    parser.add_argument("--nrows", type=int, default=100000, help="Number of rows to load per dataset.")
    args = parser.parse_args()

    results_dir = "/home/fyp2025/fyp/backend/gnn_compare"
    dns_csv = "/home/fyp2025/fyp/backend/testDataSet/DrDoS_DNS_data_1_per.csv"
    friday_csv = "/home/fyp2025/fyp/backend/testDataSet/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"
    encoder_path = "/home/fyp2025/fyp/backend/encoders/label_encoder.pkl"
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    print(f"Device: {device}")
    
    # Load Label Encoder
    with open(encoder_path, 'rb') as f:
        label_encoder = joblib.load(f)

    # 1. Fetch Original Results (Table 1)
    print("\n[+] Compiling Original Val/Test Results...")
    original_headers = ["Model", "Task", "Architecture", "Strategy", "Test F1", "Attack Recall", "FPR", "Train Time (s)"]
    original_rows = get_original_results(results_dir)
    original_table_md = format_markdown_table(original_headers, original_rows)

    # Extract raw 15 and 51 features lists from configs to prepare the datasets properly
    with open(os.path.join(results_dir, "model3_binary_config.json"), 'r') as f:
        raw_15_features = json.load(f)['features']

    with open(os.path.join(results_dir, "model2_binary_config.json"), 'r') as f:
        raw_51_features = json.load(f)['features']

    dns_table_md = ""
    friday_table_md = ""

    # Evaluate on DNS
    if args.dataset in ["dns", "both"]:
        print("\n[+] Running evaluation on DrDoS_DNS Dataset...")
        dns_table_md = run_evaluation_on_dataset(dns_csv, 'dns', raw_15_features, raw_51_features, args.nrows, results_dir, label_encoder, device)

    # Evaluate on Friday DoS
    if args.dataset in ["friday", "both"]:
        print("\n[+] Running evaluation on Friday DoS Dataset...")
        friday_table_md = run_evaluation_on_dataset(friday_csv, 'friday', raw_15_features, raw_51_features, args.nrows, results_dir, label_encoder, device)

    # Compile report text
    report_content = f"""# GNN Models Evaluation & Comparison Report

This report compares the performance of three GNN models trained differently:
- **MODEL 1**: 15 features scaled via pre-trained **TriChannelScaler** (45 total features).
- **MODEL 2**: 51 raw features scaled via **StandardScaler**.
- **MODEL 3**: 15 raw features scaled via **StandardScaler**.

---

## Table 1: Original Validation/Test Results (Training Environment)
The metrics below are from the original GNN training runs on the validation/test sets.

{original_table_md}
"""

    if args.dataset in ["dns", "both"]:
        report_content += f"""
---

## Table 2: Performance on External DNS Attack Dataset (`DrDoS_DNS_data_1_per.csv`)
Evaluated on a contiguous sample of **{args.nrows}** flows. 
Labels mapped: `BENIGN` &rarr; `Normal`, `DrDoS_DNS` &rarr; `DDoS`.

{dns_table_md}
"""

    if args.dataset in ["friday", "both"]:
        report_content += f"""
---

## Table 3: Performance on External Friday DoS Dataset (`Friday-16-02-2018_TrafficForML_CICFlowMeter.csv`)
Evaluated on a contiguous sample of **{args.nrows}** flows.
Labels mapped: `Benign` &rarr; `Normal`, `DoS attacks-Hulk` &rarr; `DoS`, `DoS attacks-SlowHTTPTest` &rarr; `DoS`.

{friday_table_md}
"""

    report_content += "\n*Note: For Binary tasks, Test F1 represents Binary F1 score; for Multiclass tasks, it represents Macro F1 score.*\n"

    report_path = os.path.join(results_dir, "comparison_report.md")
    with open(report_path, 'w') as f:
        f.write(report_content)

    print(f"\n[+] Evaluation finished! Report saved to {report_path}")
    
    print("\n=== Table 1: Original Results ===")
    print(original_table_md)
    if dns_table_md:
        print("\n=== Table 2: DrDoS_DNS Test Results ===")
        print(dns_table_md)
    if friday_table_md:
        print("\n=== Table 3: Friday DoS Test Results ===")
        print(friday_table_md)

if __name__ == "__main__":
    main()

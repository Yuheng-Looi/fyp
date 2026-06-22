import os
import sys
import json
import torch
import joblib
import argparse
import time
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# Ensure backend directory is in python path
sys.path.append("/home/fyp2025/fyp/backend")
import gnn_utils
from scaler_utils import TriChannelScaler
from gnn_compare.evaluate_adaptive import COL_MAP, LABEL_MAP_DNS, LABEL_MAP_FRIDAY, format_markdown_table, load_and_preprocess_raw, select_best_strategy

def evaluate_gnn_model_weights(df_test, feature_cols, model, config_path, label_encoder, device, scaler, task):
    if task == 'binary':
        strategy = 'hybrid'
        is_binary = True
    else:
        strategy = 'src_ip_temporal'
        is_binary = False

    # Scale feature columns
    df = df_test.copy()
    if hasattr(scaler, 'stats_'): # TriChannelScaler
        raw_15_features = scaler.feature_names_
        df_scaled_feats = scaler.transform(df[raw_15_features])
        meta_cols = ['Src IP', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', 'Label']
        df = pd.concat([df_scaled_feats, df[meta_cols]], axis=1)
        model_features = list(df_scaled_feats.columns)
    else: # StandardScaler
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

def retrain_gnn(df_calib, feature_cols, label_encoder, task, pseudo_labels, scaler, device):
    df = df_calib.copy()
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

    # Apply scaling
    if hasattr(scaler, 'stats_'): # TriChannelScaler
        raw_15_features = scaler.feature_names_
        df_scaled_feats = scaler.transform(df[raw_15_features])
        meta_cols = ['Src IP', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp']
        df_gnn = pd.concat([df_scaled_feats, df[meta_cols]], axis=1)
        model_features = list(df_scaled_feats.columns)
    else: # StandardScaler
        df[feature_cols] = scaler.transform(df[feature_cols])
        df_gnn = df
        model_features = feature_cols

    # Inject labels and build graph
    df_gnn['Label_Encoded'] = pseudo_labels
    original_data = gnn_utils.build_graph(df_gnn, model_features, strategy=strategy)
    data = original_data.clone()

    if is_binary:
        data.y = torch.tensor(pseudo_labels, dtype=torch.long)
    else:
        data.y = torch.tensor(pseudo_labels, dtype=torch.long)

    data = data.to(device)

    # Stratified split for training
    num_nodes = data.num_nodes
    indices = np.arange(num_nodes)
    
    from sklearn.model_selection import train_test_split
    try:
        train_idx, val_idx = train_test_split(
            indices, train_size=0.8, stratify=pseudo_labels, random_state=42
        )
    except Exception:
        train_idx, val_idx = train_test_split(
            indices, train_size=0.8, random_state=42
        )

    train_mask = torch.zeros(num_nodes, dtype=torch.bool)
    val_mask = torch.zeros(num_nodes, dtype=torch.bool)
    train_mask[train_idx] = True
    val_mask[val_idx] = True

    # Class weights
    y_train = pseudo_labels[train_idx]
    classes_in_train = np.unique(y_train)
    class_weights = torch.tensor(
        [len(y_train) / (len(classes_in_train) * np.sum(y_train == c)) if np.sum(y_train == c) > 0 else 1.0 for c in range(num_classes)],
        dtype=torch.float
    ).to(device)

    # Initialize GNN Classifier
    model = gnn_utils.GNNClassifier(
        input_dim=len(model_features),
        hidden_dim=config['hidden_dim'],
        num_classes=num_classes,
        num_layers=config['num_layers'],
        dropout=config['dropout'],
        arch=arch
    ).to(device)

    # Train GNN
    start_time = time.time()
    _ = gnn_utils.train_gnn(
        model, data, train_mask.to(device), val_mask.to(device),
        epochs=30, patience=5, class_weights=class_weights
    )
    train_time = time.time() - start_time
    
    return model, train_time, model_features

def main():
    parser = argparse.ArgumentParser(description="Adaptive IDS Rescale vs Retrain Ablation Study.")
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

    overall_report = "# Adaptive IDS — Rescale vs Retrain Ablation Study Report\n\n"
    all_ablation_results = []
    all_strategy_selection = []

    for ds_name, csv_path in datasets_to_run:
        print(f"\n==================================================")
        print(f"RUNNING ABLATION STUDY ON: {ds_name.upper()}")
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
        # PHASE 1: Pseudo-labeling (First 20k flows)
        # ----------------------------------------------------
        print("\n[Phase 1] Evaluating Pseudo-label Calibration Strategies...")
        xgb_model = xgb.XGBClassifier()
        xgb_model.load_model('/home/fyp2025/fyp/backend/models/xgb/xgb_binary_v1.json')
        sn = joblib.load('/home/fyp2025/fyp/backend/models/safetynet/safety_net_v1.pkl')

        calib_scaled_feats = pre_trained_scaler.transform(df_calib[raw_15_features])
        xgb_probs = xgb_model.predict_proba(calib_scaled_feats)[:, 1]
        if_scores = -sn.model.score_samples(calib_scaled_feats)

        strategy_options = [
            {'name': 'Strategy A', 'xgb_t': 0.70, 'if_t': 0.60, 'op': 'AND'},
            {'name': 'Strategy B', 'xgb_t': 0.70, 'if_t': 0.60, 'op': 'OR'},
            {'name': 'Strategy C', 'xgb_t': 0.80, 'if_t': 0.65, 'op': 'AND'},
            {'name': 'Strategy D', 'xgb_t': 0.60, 'if_t': 0.65, 'op': 'OR'},
        ]

        strategy_results = []
        strategy_pseudo_labels = {}

        for s in strategy_options:
            xgb_t = s['xgb_t']
            if_t = s['if_t']
            
            if s['op'] == 'AND':
                pseudo_labels = ((xgb_probs >= xgb_t) & (if_scores >= if_t)).astype(int)
            else:
                pseudo_labels = ((xgb_probs >= xgb_t) | (if_scores >= if_t)).astype(int)

            attack_ratio = np.mean(pseudo_labels)
            normal_ratio = 1.0 - attack_ratio

            # Confidence score: mean of maximum predicted probability of target class
            confidence = np.where(pseudo_labels == 1, xgb_probs, 1.0 - xgb_probs)
            mean_conf = np.mean(confidence)

            key = f"{s['name']}_xgb{xgb_t}_if{if_t}_{s['op']}"
            
            strategy_results.append({
                'key': key,
                'Strategy': f"{s['name']} ({s['op']})",
                'XGB threshold': xgb_t,
                'IF threshold': if_t,
                'Attack ratio': attack_ratio,
                'Normal ratio': normal_ratio,
                'Pseudo confidence': mean_conf,
                'dataset': ds_name
            })
            strategy_pseudo_labels[key] = pseudo_labels

        # Select strategy
        selected_key = select_best_strategy(strategy_results)
        print(f"Selected Strategy: {selected_key}")

        table_a_rows = []
        for r in strategy_results:
            is_selected = "Yes" if r['key'] == selected_key else "No"
            table_a_rows.append([
                r['Strategy'],
                f"{r['XGB threshold']:.2f}",
                f"{r['IF threshold']:.2f}",
                f"{r['Attack ratio']:.4f}",
                f"{r['Pseudo confidence']:.4f}",
                is_selected
            ])
            all_strategy_selection.append({
                'dataset': ds_name,
                'Strategy': r['Strategy'],
                'XGB threshold': r['XGB threshold'],
                'IF threshold': r['IF threshold'],
                'Attack ratio': r['Attack ratio'],
                'Confidence': r['Pseudo confidence'],
                'Selected': is_selected
            })

        selected_labels = strategy_pseudo_labels[selected_key]
        normal_mask = (selected_labels == 0)
        df_calib_normal = df_calib[normal_mask].copy()
        if len(df_calib_normal) < 100:
            df_calib_normal = df_calib.copy()
        df_calib_normal.reset_index(drop=True, inplace=True)

        # ----------------------------------------------------
        # PHASE 2 & 3: Mode Execution (Baseline, Rescale, Retrain)
        # ----------------------------------------------------
        print("\n[Phase 2 & 3] Running Ablation Modes...")
        
        # 1. Prepare Scalers
        # Mode 2 & 3 adapted scalers
        adapted_trichannel = TriChannelScaler(benign_label=0)
        adapted_trichannel.fit(df_calib_normal[raw_15_features], pd.Series([0]*len(df_calib_normal), index=df_calib_normal.index))
        
        adapted_scaler_51 = StandardScaler().fit(df_calib_normal[raw_51_features])
        adapted_scaler_15 = StandardScaler().fit(df_calib_normal[raw_15_features])

        # Mode 1 baseline standard scalers (fitted on test set directly)
        original_scaler_51 = StandardScaler().fit(df_test[raw_51_features])
        original_scaler_15 = StandardScaler().fit(df_test[raw_15_features])

        # Prepare Pseudo-labels for multiclass GNN retraining
        # Map Normal -> Normal class index
        # Map Attack -> DDoS (for DNS) / DoS (for Friday) class index
        normal_multiclass_idx = label_encoder.transform(['Normal'])[0]
        if ds_name == 'dns':
            attack_multiclass_idx = label_encoder.transform(['DDoS'])[0]
        else:
            attack_multiclass_idx = label_encoder.transform(['DoS'])[0]
        
        pseudo_labels_multiclass = np.where(selected_labels == 0, normal_multiclass_idx, attack_multiclass_idx)

        # We will collect metrics for all runs
        dataset_results = []
        models = ["model1", "model2", "model3"]
        tasks = ["binary", "multiclass"]

        for model_name in models:
            for task in tasks:
                config_path = os.path.join(results_dir, f"{model_name}_{task}_config.json")
                model_path = os.path.join(results_dir, f"{model_name}_{task}_model.pt")
                
                if not os.path.exists(config_path) or not os.path.exists(model_path):
                    continue

                # Load original model weights
                if task == 'binary':
                    config = {'hidden_dim': 64, 'num_layers': 2, 'dropout': 0.3, 'arch': 'gat', 'num_classes': 2}
                else:
                    config = {'hidden_dim': 128, 'num_layers': 3, 'dropout': 0.5, 'arch': 'sage', 'num_classes': len(label_encoder.classes_)}

                # Helper to initialize original GNN model
                with open(config_path, 'r') as f:
                    config_data = json.load(f)
                feat_list = config_data['features']
                
                original_model = gnn_utils.GNNClassifier(
                    input_dim=len(feat_list),
                    hidden_dim=config['hidden_dim'],
                    num_classes=config['num_classes'],
                    num_layers=config['num_layers'],
                    dropout=config['dropout'],
                    arch=config['arch']
                ).to(device)
                original_model.load_state_dict(torch.load(model_path, map_location=device)) # Load weights

                # Scaler selection
                if model_name == "model1":
                    scaler_orig = pre_trained_scaler
                    scaler_adap = adapted_trichannel
                    feature_cols = raw_15_features
                elif model_name == "model2":
                    scaler_orig = original_scaler_51
                    scaler_adap = adapted_scaler_51
                    feature_cols = raw_51_features
                else:
                    scaler_orig = original_scaler_15
                    scaler_adap = adapted_scaler_15
                    feature_cols = raw_15_features

                # -----------------
                # MODE 1: Baseline
                # -----------------
                print(f"  Evaluating {model_name} {task} Mode 1 (Baseline)...")
                metrics_baseline = evaluate_gnn_model_weights(
                    df_test, feature_cols, original_model, config_path, label_encoder, device, scaler_orig, task
                )
                
                # -----------------
                # MODE 2: Rescale-only
                # -----------------
                print(f"  Evaluating {model_name} {task} Mode 2 (Rescale-only)...")
                metrics_rescale = evaluate_gnn_model_weights(
                    df_test, feature_cols, original_model, config_path, label_encoder, device, scaler_adap, task
                )

                # -----------------
                # MODE 3: Full Retrain
                # -----------------
                print(f"  Retraining and Evaluating {model_name} {task} Mode 3 (Full Retrain)...")
                target_labels = selected_labels if task == 'binary' else pseudo_labels_multiclass
                retrained_model, train_time, model_features = retrain_gnn(
                    df_calib, feature_cols, label_encoder, task, target_labels, scaler_adap, device
                )
                metrics_retrain = evaluate_gnn_model_weights(
                    df_test, feature_cols, retrained_model, config_path, label_encoder, device, scaler_adap, task
                )

                # Append results
                dataset_results.append({
                    "dataset": ds_name, "Model": model_name.upper(), "Task": task.upper(), "Mode": "Baseline",
                    "Accuracy": metrics_baseline["Accuracy"], "F1": metrics_baseline["Test F1"],
                    "Recall": metrics_baseline["Attack Recall"], "FPR": metrics_baseline["FPR"],
                    "Cost": 0.0
                })
                
                # Calculate improvement for Rescale
                imp_rescale = metrics_rescale["Test F1"] - metrics_baseline["Test F1"]
                dataset_results.append({
                    "dataset": ds_name, "Model": model_name.upper(), "Task": task.upper(), "Mode": "Rescale",
                    "Accuracy": metrics_rescale["Accuracy"], "F1": metrics_rescale["Test F1"],
                    "Recall": metrics_rescale["Attack Recall"], "FPR": metrics_rescale["FPR"],
                    "Cost": 0.0, "Improvement": imp_rescale
                })

                # Calculate improvement for Retrain
                imp_retrain = metrics_retrain["Test F1"] - metrics_baseline["Test F1"]
                dataset_results.append({
                    "dataset": ds_name, "Model": model_name.upper(), "Task": task.upper(), "Mode": "Retrain",
                    "Accuracy": metrics_retrain["Accuracy"], "F1": metrics_retrain["Test F1"],
                    "Recall": metrics_retrain["Attack Recall"], "FPR": metrics_retrain["FPR"],
                    "Cost": train_time, "Improvement": imp_retrain
                })

        all_ablation_results.extend(dataset_results)

        # Table B Rows
        table_b_rows = []
        for r in dataset_results:
            imp_val = r.get("Improvement", 0.0)
            imp_str = f"{imp_val:+.4f}" if r["Mode"] != "Baseline" else "-"
            table_b_rows.append([
                f"{r['Model']} ({r['Task']})",
                r["Mode"],
                f"{r['Accuracy']:.6f}",
                f"{r['F1']:.6f}",
                f"{r['Recall']:.6f}",
                f"{r['FPR']:.6f}",
                imp_str,
                f"{r['Cost']:.2f}s"
            ])

        table_a_headers = ["Strategy", "XGB threshold", "IF threshold", "Attack ratio", "Confidence score", "Selected strategy"]
        table_b_headers = ["Model (Task)", "Mode", "Accuracy", "F1", "Recall", "FPR", "Absolute F1 Improvement", "Training cost"]

        overall_report += f"""## Dataset: {ds_name.upper()}

### Table A: Calibration Strategy Selection ({ds_name.upper()})
*Evaluated on the first 20,000 flows. Objective: avoid extreme ratio collapse.*

{format_markdown_table(table_a_headers, table_a_rows)}

### Table B: Rescale vs Retrain Comparison ({ds_name.upper()})
*Evaluated on the next 40,000 test flows.*

{format_markdown_table(table_b_headers, table_b_rows)}

---
"""

    # ----------------------------------------------------
    # PHASE 4: Key Insight Summary (Table C) - COMPUTED
    # ----------------------------------------------------
    print("\n[Phase 4] Computing Key Insights (Table C)...")
    df_results = pd.DataFrame(all_ablation_results)

    # 1. Which dataset benefits more from rescale?
    # Compare average absolute improvement of Model 1 under Rescale-only on DNS vs Friday
    m1_dns_rescale_imp = df_results[(df_results['dataset'] == 'dns') & (df_results['Model'] == 'MODEL1') & (df_results['Mode'] == 'Rescale')]['Improvement'].mean()
    m1_friday_rescale_imp = df_results[(df_results['dataset'] == 'friday') & (df_results['Model'] == 'MODEL1') & (df_results['Mode'] == 'Rescale')]['Improvement'].mean()
    
    if m1_dns_rescale_imp > m1_friday_rescale_imp:
        better_rescale_ds = f"DNS (average Model 1 F1 improvement: +{m1_dns_rescale_imp:.4f} vs Friday: {m1_friday_rescale_imp:+.4f})"
    else:
        better_rescale_ds = f"Friday (average Model 1 F1 improvement: +{m1_friday_rescale_imp:.4f} vs DNS: {m1_dns_rescale_imp:+.4f})"

    # 2. Which model collapses without adaptation?
    # Find model with lowest average F1 in baseline Mode 1
    m_baseline = df_results[df_results['Mode'] == 'Baseline'].groupby(['Model', 'dataset'])['F1'].mean().reset_index()
    lowest_row = m_baseline.loc[m_baseline['F1'].idxmin()]
    collapsing_model = f"{lowest_row['Model']} on {lowest_row['dataset'].upper()} (F1 score: {lowest_row['F1']:.4f})"

    # 3. Does retraining consistently outperform rescale?
    # Compare retrain F1 vs rescale F1 across all models/tasks/datasets
    df_res = df_results[df_results['Mode'] == 'Rescale'].set_index(['dataset', 'Model', 'Task'])
    df_ret = df_results[df_results['Mode'] == 'Retrain'].set_index(['dataset', 'Model', 'Task'])
    better_count = np.sum(df_ret['F1'] > df_res['F1'])
    total_count = len(df_res)
    does_outperform = "Yes" if better_count > (total_count / 2) else "No"
    outperform_str = f"{does_outperform} (Retraining was better in {better_count}/{total_count} model configurations)"

    # 4. When is rescale sufficient?
    # Rescale is sufficient when the F1 difference between Retrain and Rescale is very small (<0.05) or negative
    close_configs = []
    for idx, row in df_res.iterrows():
        ret_f1 = df_ret.loc[idx, 'F1']
        res_f1 = row['F1']
        diff = ret_f1 - res_f1
        if diff <= 0.05:
            close_configs.append(f"{idx[1]} {idx[2]} on {idx[0].upper()}")
    
    if close_configs:
        rescale_sufficient = f"Rescale is sufficient in {len(close_configs)}/{total_count} configurations (F1 diff <= 0.05): {', '.join(close_configs)}"
    else:
        rescale_sufficient = "Rescale is rarely sufficient; retraining is needed to recover discriminative power."

    # Table C construction
    table_c_rows = [
        ["Which dataset benefits more from rescale?", better_rescale_ds],
        ["Which model collapses without adaptation?", collapsing_model],
        ["Does retraining consistently outperform rescale?", outperform_str],
        ["When is rescale sufficient?", rescale_sufficient]
    ]
    table_c_headers = ["Question", "Computed Insight"]
    table_c_md = format_markdown_table(table_c_headers, table_c_rows)

    overall_report += f"""## Table C: Key Insight Summary (Computed from Data)

{table_c_md}
"""

    # Save to CSV files
    df_results.to_csv(os.path.join(results_dir, "ablation_study_results.csv"), index=False)
    pd.DataFrame(all_strategy_selection).to_csv(os.path.join(results_dir, "ablation_strategies.csv"), index=False)
    
    report_md_path = os.path.join(results_dir, "ablation_report.md")
    with open(report_md_path, 'w') as f:
        f.write(overall_report)

    print(f"\n[+] Ablation Study Experiment Complete!")
    print(f"Results saved to {results_dir} and report generated at {report_md_path}")

if __name__ == "__main__":
    main()

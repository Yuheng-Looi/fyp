import os
import sys
import pickle
import numpy as np
import pandas as pd
import torch
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import copy
import time
import json

sys.path.append("/home/fyp2025/fyp/backend")
import eda_utils
import gnn_utils

def load_gnn_data_raw(cleaned_ref_path='01eda/cleaned_data15.csv', raw_folder='datasets', encoder_path='encoders/label_encoder.pkl'):
    print(f"Loading raw data to recover topology using reference: {cleaned_ref_path}...")
    filenames = ['metasploitable-2.csv', 'OVS.csv', 'Normal_data.csv']
    
    # Load raw data
    raw_folder_full = os.path.join("/home/fyp2025/fyp/backend", raw_folder)
    df_raw = eda_utils.load_and_concatenate_datasets(raw_folder_full, filenames)
    
    # Normalize labels
    df_raw['Label'] = (
        df_raw['Label']
        .astype(str)
        .str.replace(r"[\u200b\u200c\u200d\ufeff]", "", regex=True)
        .str.strip()
        .str.replace(r"\s+", " ", regex=True)
    )
    
    # Load reference cleaned data to get the features list
    cleaned_ref_path_full = os.path.join("/home/fyp2025/fyp/backend", cleaned_ref_path)
    if not os.path.exists(cleaned_ref_path_full):
        raise FileNotFoundError(f"Reference file {cleaned_ref_path_full} not found.")
    
    df_ref = pd.read_csv(cleaned_ref_path_full, nrows=1)
    feature_cols = [c for c in df_ref.columns if c != 'Label']
    print(f"Selected features ({len(feature_cols)}): {feature_cols}")
    
    # Check if raw data has these features + meta
    meta_cols = ['Src IP', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp']
    required_cols = feature_cols + meta_cols + ['Label']
    
    cols_to_use = list(set(required_cols))
    
    # Filter columns
    df = df_raw[cols_to_use].copy()
    
    # Parse Timestamp
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    df = df.sort_values('Timestamp').reset_index(drop=True)
    
    # Handle NaNs
    df = df.dropna(subset=feature_cols)
    
    # Encode Label
    encoder_path_full = os.path.join("/home/fyp2025/fyp/backend", encoder_path)
    if os.path.exists(encoder_path_full):
        with open(encoder_path_full, 'rb') as f:
            le = pickle.load(f)
        df = df[df['Label'].isin(le.classes_)]
        df['Label_Encoded'] = le.transform(df['Label'])
    else:
        print("Encoder not found, creating new one")
        le = LabelEncoder()
        df['Label_Encoded'] = le.fit_transform(df['Label'])
        
    return df, feature_cols, le

def run_experiment(df, feature_cols, label_encoder, task, strategy, arch, config, split, output_prefix):
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"\n==================================================")
    print(f"Starting GNN Experiment: {task.upper()} | Strategy: {strategy} | Arch: {arch}")
    print(f"==================================================")
    
    # 1. Build Graph
    print(f"Building graph for strategy: {strategy}...")
    original_data = gnn_utils.build_graph(df, feature_cols, strategy=strategy)
    data = original_data.clone()
    
    if task == 'binary':
        # Map Normal -> 0, Attack -> 1
        normal_idx = label_encoder.transform(['Normal'])[0]
        data.y = (original_data.y != normal_idx).long()
        num_classes = 2
        is_binary = True
    else:
        num_classes = len(label_encoder.classes_)
        is_binary = False
        
    data = data.to(device)
    
    train_ratio, val_ratio, test_ratio = split
    num_nodes = data.num_nodes
    indices = np.arange(num_nodes)
    y_cpu = data.y.cpu().numpy()
    
    # 2. Stratified train/val/test split
    try:
        train_idx, temp_idx = train_test_split(
            indices, train_size=train_ratio, stratify=y_cpu, random_state=42
        )
        val_ratio_adj = val_ratio / (val_ratio + test_ratio)
        val_idx, test_idx = train_test_split(
            temp_idx, train_size=val_ratio_adj, stratify=y_cpu[temp_idx], random_state=42
        )
    except ValueError as e:
        print(f"[!] Stratification split failed: {e}")
        return None
        
    train_mask = torch.zeros(num_nodes, dtype=torch.bool)
    val_mask = torch.zeros(num_nodes, dtype=torch.bool)
    test_mask = torch.zeros(num_nodes, dtype=torch.bool)
    
    train_mask[train_idx] = True
    val_mask[val_idx] = True
    test_mask[test_idx] = True
    
    # 3. Class Weights (for loss function)
    y_train = y_cpu[train_idx]
    classes_in_train = np.unique(y_train)
    class_weights = torch.tensor(
        [len(y_train) / (len(classes_in_train) * np.sum(y_train == c)) for c in range(num_classes)],
        dtype=torch.float
    ).to(device)
    
    # 4. Instantiate model
    model = gnn_utils.GNNClassifier(
        input_dim=len(feature_cols),
        hidden_dim=config['hidden_dim'],
        num_classes=num_classes,
        num_layers=config['num_layers'],
        dropout=config['dropout'],
        arch=arch
    ).to(device)
    
    # 5. Train
    print("Training GNN model...")
    start_time = time.time()
    history = gnn_utils.train_gnn(
        model, data, train_mask.to(device), val_mask.to(device),
        epochs=50,
        patience=5,
        class_weights=class_weights
    )
    training_time = time.time() - start_time
    
    # 6. Evaluate
    print("Evaluating GNN model on test set...")
    metrics = gnn_utils.evaluate_gnn(model, data, test_mask.to(device), label_encoder, is_binary_task=is_binary)
    
    res = {
        'task': task,
        'strategy': strategy,
        'arch': arch,
        'split': f"{int(train_ratio*100)}/{int(val_ratio*100)}/{int(test_ratio*100)}",
        'hidden_dim': config['hidden_dim'],
        'num_layers': config['num_layers'],
        'dropout': config['dropout'],
        'test_f1': metrics['f1_binary'] if is_binary else metrics['macro_f1'],
        'attack_recall': metrics['recall_attack'],
        'fpr': metrics['fpr_normal'],
        'macro_f1': metrics['macro_f1'],
        'training_time': training_time
    }
    
    print("\n---------------- GNN EVALUATION REPORT ----------------")
    print(f"Task:              {task.upper()}")
    print(f"Architecture:      {arch.upper()}")
    print(f"Strategy:          {strategy}")
    print(f"Attack Recall:     {metrics['recall_attack']:.4f}")
    print(f"FPR (Normal):      {metrics['fpr_normal']:.4f}")
    print(f"Test F1 (Macro):   {metrics['macro_f1']:.4f}")
    print(f"Training Time:     {training_time:.2f}s")
    print("-------------------------------------------------------")
    
    # Save model state and info
    os.makedirs("/home/fyp2025/fyp/backend/gnn_compare", exist_ok=True)
    torch.save(model.state_dict(), f"/home/fyp2025/fyp/backend/gnn_compare/{output_prefix}_model.pt")
    with open(f"/home/fyp2025/fyp/backend/gnn_compare/{output_prefix}_config.json", 'w') as f:
        json.dump({
            'info': res,
            'features': feature_cols
        }, f, indent=4)
        
    return res

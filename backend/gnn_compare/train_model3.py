import os
import sys
import pandas as pd
import torch
from sklearn.preprocessing import StandardScaler

# Ensure backend directory is in python path
sys.path.append("/home/fyp2025/fyp/backend")

from gnn_compare.compare_utils import load_gnn_data_raw, run_experiment

def main():
    # 1. Load raw 15-feature GNN dataset
    df, feature_cols, label_encoder = load_gnn_data_raw(
        cleaned_ref_path='01eda/cleaned_data15.csv',
        raw_folder='datasets',
        encoder_path='encoders/label_encoder.pkl'
    )
    
    # 2. Scale continuous features using StandardScaler
    print("Scaling continuous features using StandardScaler...")
    scaler = StandardScaler()
    df[feature_cols] = scaler.fit_transform(df[feature_cols])
    
    print(f"Dataset prepared for GNN training. Shape: {df.shape}")
    print(f"Number of node features: {len(feature_cols)}")
    
    # 3. Run Binary Classification Experiment
    # Best Binary Config: gat arch, hybrid strategy, hidden_dim=64, num_layers=2, dropout=0.3, split 80/10/10
    print("\n--- Running Model 3: Binary Classification ---")
    binary_config = {
        'hidden_dim': 64,
        'num_layers': 2,
        'dropout': 0.3
    }
    run_experiment(
        df=df,
        feature_cols=feature_cols,
        label_encoder=label_encoder,
        task='binary',
        strategy='hybrid',
        arch='gat',
        config=binary_config,
        split=(0.8, 0.1, 0.1),
        output_prefix='model3_binary'
    )
    
    # 4. Run Multiclass Classification Experiment
    # Best Multiclass Config: sage arch, src_ip_temporal strategy, hidden_dim=128, num_layers=3, dropout=0.5, split 70/15/15
    print("\n--- Running Model 3: Multiclass Classification ---")
    multiclass_config = {
        'hidden_dim': 128,
        'num_layers': 3,
        'dropout': 0.5
    }
    run_experiment(
        df=df,
        feature_cols=feature_cols,
        label_encoder=label_encoder,
        task='multiclass',
        strategy='src_ip_temporal',
        arch='sage',
        config=multiclass_config,
        split=(0.7, 0.15, 0.15),
        output_prefix='model3_multiclass'
    )
    
    print("\nModel 3 Experiments Finished!")

if __name__ == "__main__":
    main()

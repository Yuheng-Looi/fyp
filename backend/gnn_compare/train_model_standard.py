#!/usr/bin/env python3
"""
train_model_standard.py — Train Binary GNN with StandardScaler (15 features)

Trains a GAT-based binary GNN classifier using sklearn StandardScaler
on the same 15 raw features as Model 3.  This enables a fair comparison
with the TriChannelScaler (Model 1, 45 features) in the Rescale-vs-Retrain
ablation study.

Output:
    model_standard_binary_model.pt
    model_standard_binary_config.json
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

# Ensure backend directory is in python path
sys.path.append("/home/fyp2025/fyp/backend")

from gnn_compare.compare_utils import load_gnn_data_raw, run_experiment


def main():
    # 1. Load raw 15-feature GNN dataset (same features as Model 3)
    df, feature_cols, label_encoder = load_gnn_data_raw(
        cleaned_ref_path='01eda/cleaned_data15.csv',
        raw_folder='datasets',
        encoder_path='encoders/label_encoder.pkl'
    )

    print(f"Feature columns ({len(feature_cols)}): {feature_cols}")

    # 2. Fit StandardScaler on the 15 features using benign traffic only
    benign_mask = df['Label_Encoded'] == 4  # benign label
    X_benign = df.loc[benign_mask, feature_cols].astype(float)

    scaler = StandardScaler()
    scaler.fit(X_benign)

    # Save scaler for later use in rescale experiments
    scaler_dir = "/home/fyp2025/fyp/backend/scalers"
    os.makedirs(scaler_dir, exist_ok=True)
    scaler_path = os.path.join(scaler_dir, "standard_scaler_15feat.pkl")
    joblib.dump(scaler, scaler_path)
    print(f"StandardScaler saved to {scaler_path}")

    # 3. Transform continuous features in-place
    print("Transforming continuous features using StandardScaler...")
    df[feature_cols] = scaler.transform(df[feature_cols].astype(float))

    print(f"Dataset prepared for GNN training. Shape: {df.shape}")
    print(f"Number of node features: {len(feature_cols)}")

    # 5. Run Binary Classification Experiment
    # Same architecture as Model 1/3: GAT, hybrid strategy, hidden_dim=64, num_layers=2, dropout=0.3
    print("\n--- Running StandardScaler Model: Binary Classification ---")
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
        output_prefix='model_standard_binary'
    )

    print("\nStandardScaler Model Training Finished!")


if __name__ == "__main__":
    main()

import os
import sys
import joblib
import pandas as pd
import torch

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
    
    # 2. Load the pre-trained Tri-Channel Scaler
    scaler_path = "/home/fyp2025/fyp/backend/scalers/trichannel_scaler.pkl"
    if not os.path.exists(scaler_path):
        raise FileNotFoundError(f"TriChannelScaler not found at {scaler_path}. Please fit it first.")
        
    print(f"Loading TriChannelScaler from {scaler_path}...")
    scaler = joblib.load(scaler_path)
    
    # 3. Transform features (15 -> 45 features)
    print("Transforming continuous features using TriChannelScaler...")
    df_scaled_feats = scaler.transform(df[feature_cols])
    new_feature_cols = list(df_scaled_feats.columns)
    
    # 4. Combine scaled features and original metadata + label columns
    meta_and_label_cols = ['Src IP', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', 'Label', 'Label_Encoded']
    df_gnn = pd.concat([df_scaled_feats, df[meta_and_label_cols]], axis=1)
    
    print(f"Dataset prepared for GNN training. Shape: {df_gnn.shape}")
    print(f"Number of node features: {len(new_feature_cols)}")
    
    # 5. Run Binary Classification Experiment
    # Best Binary Config: gat arch, hybrid strategy, hidden_dim=64, num_layers=2, dropout=0.3, split 80/10/10
    print("\n--- Running Model 1: Binary Classification ---")
    binary_config = {
        'hidden_dim': 64,
        'num_layers': 2,
        'dropout': 0.3
    }
    run_experiment(
        df=df_gnn,
        feature_cols=new_feature_cols,
        label_encoder=label_encoder,
        task='binary',
        strategy='hybrid',
        arch='gat',
        config=binary_config,
        split=(0.8, 0.1, 0.1),
        output_prefix='model1_binary'
    )
    
    # 6. Run Multiclass Classification Experiment
    # Best Multiclass Config: sage arch, src_ip_temporal strategy, hidden_dim=128, num_layers=3, dropout=0.5, split 70/15/15
    print("\n--- Running Model 1: Multiclass Classification ---")
    multiclass_config = {
        'hidden_dim': 128,
        'num_layers': 3,
        'dropout': 0.5
    }
    run_experiment(
        df=df_gnn,
        feature_cols=new_feature_cols,
        label_encoder=label_encoder,
        task='multiclass',
        strategy='src_ip_temporal',
        arch='sage',
        config=multiclass_config,
        split=(0.7, 0.15, 0.15),
        output_prefix='model1_multiclass'
    )
    
    print("\nModel 1 Experiments Finished!")

if __name__ == "__main__":
    main()

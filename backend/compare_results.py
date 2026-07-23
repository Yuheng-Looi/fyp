import pandas as pd
import os

gnn_csv = 'models/gnn/gnn_model_comparison.csv'
gnn_robust_csv = 'models/gnn_robust/gnn_model_comparison_robust.csv'

if os.path.exists(gnn_csv):
    df = pd.read_csv(gnn_csv)
    print("=== GNN Standard Scaler (Top Multiclass) ===")
    print(df[df['task']=='multiclass'].sort_values('test_f1', ascending=False).head(3))
    print("=== GNN Standard Scaler (Top Binary) ===")
    print(df[df['task']=='binary'].sort_values('test_f1', ascending=False).head(3))

if os.path.exists(gnn_robust_csv):
    df_robust = pd.read_csv(gnn_robust_csv)
    print("\n=== GNN Robust Scaler (Top Multiclass) ===")
    print(df_robust[df_robust['task']=='multiclass'].sort_values('test_f1', ascending=False).head(3))
    print("=== GNN Robust Scaler (Top Binary) ===")
    print(df_robust[df_robust['task']=='binary'].sort_values('test_f1', ascending=False).head(3))

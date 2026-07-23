#!/usr/bin/env python3
"""
fig1_rescale_retrain.py — Figure 1: Rescale vs Retrain Comparison

Trains GNN models using 3 scaler configurations on the SAME 15 raw features:
  - StandardScaler
  - RobustScaler
  - Tri-Channel Scaler

Evaluates each under 3 modes (Original, Rescale, Retrain) on DNS and FRIDAY datasets.
Records F1 scores and generates fig1_rescale_vs_retrain.png.

All models use identical:
  - 15 raw input features
  - GNN architecture (GraphSAGE, 2 layers, 64 hidden)
  - Training procedure, splits, seeds
  - InSDN source dataset
"""

import os
import sys
import time
import json
import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
import joblib

from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score
from sklearn.neighbors import NearestNeighbors

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Add backend to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, BACKEND_DIR)

from scaler_utils import TriChannelScaler

# ── Column mapping (raw CICFlowMeter → normalized) ──────────────────────
COL_MAP = {
    'Source IP': 'Src IP', 'Source Port': 'Src Port',
    'Destination IP': 'Dst IP', 'Destination Port': 'Dst Port',
    'Protocol': 'Protocol', 'Timestamp': 'Timestamp',
    'Flow Duration': 'Flow Duration', 'Total Fwd Packets': 'Tot Fwd Pkts',
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
    'Flow Bytes/s': 'Flow Byts/s', 'Flow Packets/s': 'Flow Pkts/s',
    'Flow IAT Mean': 'Flow IAT Mean', 'Flow IAT Std': 'Flow IAT Std',
    'Flow IAT Max': 'Flow IAT Max', 'Flow IAT Min': 'Flow IAT Min',
    'Fwd IAT Total': 'Fwd IAT Tot', 'Fwd IAT Mean': 'Fwd IAT Mean',
    'Fwd IAT Std': 'Fwd IAT Std', 'Fwd IAT Max': 'Fwd IAT Max',
    'Fwd IAT Min': 'Fwd IAT Min',
    'Bwd IAT Total': 'Bwd IAT Tot', 'Bwd IAT Mean': 'Bwd IAT Mean',
    'Bwd IAT Std': 'Bwd IAT Std', 'Bwd IAT Max': 'Bwd IAT Max',
    'Bwd IAT Min': 'Bwd IAT Min',
    'Fwd Header Length': 'Fwd Header Len', 'Bwd Header Length': 'Bwd Header Len',
    'Fwd Packets/s': 'Fwd Pkts/s', 'Bwd Packets/s': 'Bwd Pkts/s',
    'Min Packet Length': 'Pkt Len Min', 'Max Packet Length': 'Pkt Len Max',
    'Packet Length Mean': 'Pkt Len Mean', 'Packet Length Std': 'Pkt Len Std',
    'Packet Length Variance': 'Pkt Len Var',
    'Init_Win_bytes_forward': 'Init Fwd Win Byts',
    'Init_Win_bytes_backward': 'Init Bwd Win Byts',
    'act_data_pkt_fwd': 'Fwd Act Data Pkts',
    'min_seg_size_forward': 'Fwd Seg Size Min',
    'Label': 'Label',
}

LABEL_MAP_DNS = {'BENIGN': 'Normal', 'DrDoS_DNS': 'DDoS'}
LABEL_MAP_FRIDAY = {'Benign': 'Normal', 'DoS attacks-Hulk': 'DoS', 'DoS attacks-SlowHTTPTest': 'DoS'}

# ── The 15 raw features (must match across all scalers) ──────────────────
RAW_15_FEATURES = [
    'Fwd Header Len', 'Protocol', 'Init Bwd Win Byts', 'Tot Fwd Pkts',
    'Pkt Len Max', 'Pkt Len Mean', 'Tot Bwd Pkts', 'Dst Port',
    'Bwd Pkt Len Max', 'Fwd Pkts/s', 'Flow IAT Max', 'TotLen Bwd Pkts',
    'TotLen Fwd Pkts', 'Bwd Pkt Len Std', 'Bwd Pkt Len Mean',
]

# ── Paths ────────────────────────────────────────────────────────────────
DNS_CSV = os.path.join(BACKEND_DIR, "testDataSet", "DrDoS_DNS_data_1_per.csv")
FRIDAY_CSV = os.path.join(BACKEND_DIR, "testDataSet", "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv")
ENCODER_PATH = os.path.join(BACKEND_DIR, "encoders", "label_encoder.pkl")
SOURCE_DATA_DIR = os.path.join(BACKEND_DIR, "datasets")

# ── GNN Architecture (identical for all scalers) ─────────────────────────
GNN_CONFIG = {
    'hidden_dim': 64,
    'num_layers': 2,
    'dropout': 0.3,
    'lr': 0.01,
    'epochs': 30,
    'graph_strategy': 'hybrid',
    'k_neighbors': 5,
}

SEEDS = [42, 52, 62]
NROWS_TARGET = 60000  # 20k calibration + 40k test

# ═══════════════════════════════════════════════════════════════════════════
# GNN Model
# ═══════════════════════════════════════════════════════════════════════════
from torch_geometric.nn import SAGEConv
from torch_geometric.data import Data


class GNNBinaryClassifier(torch.nn.Module):
    def __init__(self, input_dim, hidden_dim, num_classes=2, num_layers=2, dropout=0.3):
        super().__init__()
        self.dropout = dropout
        self.layers = torch.nn.ModuleList()
        self.layers.append(SAGEConv(input_dim, hidden_dim))
        for _ in range(num_layers - 2):
            self.layers.append(SAGEConv(hidden_dim, hidden_dim))
        if num_layers > 1:
            self.layers.append(SAGEConv(hidden_dim, num_classes))

    def forward(self, x, edge_index):
        for i, layer in enumerate(self.layers):
            x = layer(x, edge_index)
            if i < len(self.layers) - 1:
                x = F.relu(x)
                x = F.dropout(x, p=self.dropout, training=self.training)
        return x


# ═══════════════════════════════════════════════════════════════════════════
# Graph Construction
# ═══════════════════════════════════════════════════════════════════════════
def build_graph(df, feature_cols, k=5):
    """Build a KNN graph from features."""
    df = df.reset_index(drop=True)
    x = torch.tensor(df[feature_cols].values, dtype=torch.float)
    y = torch.tensor(df['Label_Binary'].values, dtype=torch.long)

    src_list, dst_list = [], []

    # KNN within protocol groups
    if 'Protocol' in df.columns:
        for p in df['Protocol'].unique():
            idx = df.index[df['Protocol'] == p].values
            if len(idx) < k + 1:
                continue
            subset = df.iloc[idx][feature_cols].values
            nbrs = NearestNeighbors(n_neighbors=min(k + 1, len(idx)),
                                     algorithm='ball_tree', n_jobs=-1).fit(subset)
            _, knn_idx = nbrs.kneighbors(subset)
            neighbors_global = idx[knn_idx[:, 1:]]
            srcs = np.repeat(idx, knn_idx.shape[1] - 1)
            dsts = neighbors_global.flatten()
            src_list.extend(srcs)
            dst_list.extend(dsts)

    # Temporal edges
    if 'Timestamp' in df.columns and df['Timestamp'].notna().any():
        valid = df[df['Timestamp'].notna()]
        if 'Src IP' in valid.columns:
            for _, grp in valid.groupby('Src IP'):
                if len(grp) < 2:
                    continue
                indices = grp.index.values
                times = grp['Timestamp'].values
                diffs = (times[1:] - times[:-1]) / np.timedelta64(1, 's')
                mask = diffs <= 10
                src_list.extend(indices[:-1][mask])
                dst_list.extend(indices[1:][mask])

    if not src_list:
        edge_index = torch.empty((2, 0), dtype=torch.long)
    else:
        edge_index = torch.tensor([src_list, dst_list], dtype=torch.long)
        edge_index = torch.unique(edge_index, dim=1)

    return Data(x=x, y=y, edge_index=edge_index)


# ═══════════════════════════════════════════════════════════════════════════
# Data Loading
# ═══════════════════════════════════════════════════════════════════════════
def load_source_dataset():
    """Load InSDN source dataset for training."""
    import eda_utils
    filenames = ['metasploitable-2.csv', 'OVS.csv', 'Normal_data.csv']
    df = eda_utils.load_and_concatenate_datasets(SOURCE_DATA_DIR, filenames)
    df['Label'] = (df['Label'].astype(str)
                   .str.replace(r"[\u200b\u200c\u200d\ufeff]", "", regex=True)
                   .str.strip()
                   .str.replace(r"\s+", " ", regex=True))
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    df = df.sort_values('Timestamp').reset_index(drop=True)

    le = joblib.load(ENCODER_PATH)
    df = df[df['Label'].isin(le.classes_)].reset_index(drop=True)
    normal_idx = le.transform(['Normal'])[0]

    # Binary label: 0=Normal, 1=Attack
    df['Label_Binary'] = (le.transform(df['Label']) != normal_idx).astype(int)

    # Subsample for speed (every 11th row)
    df = df.iloc[::11].copy().reset_index(drop=True)
    print(f"[source] Loaded {len(df)} rows (subsampled)")

    # Ensure all 15 features exist and are numeric
    for col in RAW_15_FEATURES:
        if col not in df.columns:
            raise ValueError(f"Feature '{col}' not found in source dataset")
        df[col] = pd.to_numeric(df[col], errors='coerce')

    df.dropna(subset=RAW_15_FEATURES, inplace=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=RAW_15_FEATURES, inplace=True)
    df = df.reset_index(drop=True)
    print(f"[source] After cleaning: {len(df)} rows, normal ratio: {(df['Label_Binary']==0).mean():.3f}")

    return df, le, normal_idx


def load_target_dataset(csv_path, ds_type, nrows=60000):
    """Load and preprocess a target dataset (DNS or FRIDAY)."""
    print(f"[target] Loading {nrows} rows from {os.path.basename(csv_path)} ({ds_type})...")
    df = pd.read_csv(csv_path, nrows=nrows, low_memory=False)
    df.columns = df.columns.str.strip()

    # Drop header rows that got into data
    if 'Label' in df.columns:
        df = df[df['Label'] != 'Label']
    elif ' Label' in df.columns:
        df = df[df[' Label'] != 'Label']

    df.rename(columns=COL_MAP, inplace=True)

    if ds_type == 'dns':
        df['Label'] = df['Label'].map(LABEL_MAP_DNS).fillna('Normal')
    elif ds_type == 'friday':
        df['Label'] = df['Label'].map(LABEL_MAP_FRIDAY).fillna('Normal')

    # Fill missing IP columns
    if 'Src IP' not in df.columns:
        df['Src IP'] = '10.0.0.1'
    if 'Dst IP' not in df.columns:
        df['Dst IP'] = '10.0.0.2'

    # Ensure features are numeric
    for col in RAW_15_FEATURES:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')

    df.dropna(subset=RAW_15_FEATURES, inplace=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=RAW_15_FEATURES, inplace=True)

    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    df = df.sort_values('Timestamp').reset_index(drop=True)

    # Binary label
    df['Label_Binary'] = (df['Label'] != 'Normal').astype(int)

    print(f"[target] {ds_type}: {len(df)} rows, attack ratio: {df['Label_Binary'].mean():.3f}")
    return df


# ═══════════════════════════════════════════════════════════════════════════
# Training & Evaluation
# ═══════════════════════════════════════════════════════════════════════════
def apply_scaler(df, feature_cols, scaler, scaler_type=""):
    """Apply scaler and return scaled feature columns + transformed df."""
    df_out = df.copy()
    is_trichannel = isinstance(scaler, TriChannelScaler) or 'tri' in str(scaler_type).lower()
    if is_trichannel:
        df_scaled = scaler.transform(df_out[feature_cols])
        out_feats = df_scaled.columns.tolist()
        meta_cols = [c for c in df_out.columns if c not in feature_cols]
        df_out = pd.concat([df_scaled, df_out[meta_cols].reset_index(drop=True)], axis=1)
    else:
        df_out[feature_cols] = scaler.transform(df_out[feature_cols])
        out_feats = feature_cols
    return df_out, out_feats


def train_gnn(df_train, feature_cols, device, seed, epochs=30):
    """Train a GNN model on the training data."""
    torch.manual_seed(seed)
    np.random.seed(seed)

    graph = build_graph(df_train, feature_cols)
    graph = graph.to(device)

    n = graph.num_nodes
    indices = np.arange(n)
    y_cpu = graph.y.cpu().numpy()

    try:
        train_idx, test_idx = train_test_split(
            indices, train_size=0.7, stratify=y_cpu, random_state=seed
        )
    except ValueError:
        train_idx, test_idx = train_test_split(
            indices, train_size=0.7, random_state=seed
        )

    train_mask = torch.zeros(n, dtype=torch.bool, device=device)
    train_mask[train_idx] = True

    # Class weights
    n_classes = 2
    y_tr = y_cpu[train_idx]
    classes_present = np.unique(y_tr)
    weights = np.ones(n_classes)
    for c in classes_present:
        weights[c] = len(y_tr) / (len(classes_present) * np.sum(y_tr == c))
    class_weights = torch.tensor(weights, dtype=torch.float, device=device)

    model = GNNBinaryClassifier(
        input_dim=len(feature_cols),
        hidden_dim=GNN_CONFIG['hidden_dim'],
        num_classes=n_classes,
        num_layers=GNN_CONFIG['num_layers'],
        dropout=GNN_CONFIG['dropout'],
    ).to(device)

    optimizer = torch.optim.Adam(model.parameters(), lr=GNN_CONFIG['lr'])
    criterion = torch.nn.CrossEntropyLoss(weight=class_weights)

    model.train()
    for epoch in range(epochs):
        optimizer.zero_grad()
        out = model(graph.x, graph.edge_index)
        loss = criterion(out[train_mask], graph.y[train_mask])
        loss.backward()
        optimizer.step()

    return model


def evaluate_f1(model, df_eval, feature_cols, device):
    """Evaluate the model on evaluation data, return F1 score."""
    graph = build_graph(df_eval, feature_cols)
    graph = graph.to(device)

    model.eval()
    with torch.no_grad():
        logits = model(graph.x, graph.edge_index)
        preds = logits.argmax(dim=1).cpu().numpy()

    y_true = graph.y.cpu().numpy()
    return f1_score(y_true, preds, zero_division=0)


# ═══════════════════════════════════════════════════════════════════════════
# Main Experiment
# ═══════════════════════════════════════════════════════════════════════════
def run_experiment():
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Device: {device}")

    # Load source dataset
    df_source, le, normal_idx = load_source_dataset()

    # Load target datasets
    targets = {}
    if os.path.exists(DNS_CSV):
        targets['DNS'] = load_target_dataset(DNS_CSV, 'dns', nrows=NROWS_TARGET)
    else:
        print(f"[WARN] DNS dataset not found: {DNS_CSV}")
    if os.path.exists(FRIDAY_CSV):
        targets['FRIDAY'] = load_target_dataset(FRIDAY_CSV, 'friday', nrows=NROWS_TARGET)
    else:
        print(f"[WARN] FRIDAY dataset not found: {FRIDAY_CSV}")

    if not targets:
        print("[ERROR] No target datasets found. Exiting.")
        sys.exit(1)

    scaler_configs = {
        'StandardScaler': lambda: StandardScaler(),
        'RobustScaler': lambda: RobustScaler(),
        'Tri-Channel': lambda: TriChannelScaler(benign_label=0),  # label=0 for binary Normal
    }

    all_results = []

    for scaler_name, scaler_factory in scaler_configs.items():
        print(f"\n{'='*60}")
        print(f"  SCALER: {scaler_name}")
        print(f"{'='*60}")

        for seed in SEEDS:
            print(f"\n  --- Seed {seed} ---")
            torch.manual_seed(seed)
            np.random.seed(seed)

            # Step 1: Fit scaler on source data
            source_scaler = scaler_factory()
            if scaler_name == 'Tri-Channel':
                source_scaler.fit(df_source[RAW_15_FEATURES],
                                  df_source['Label_Binary'])  # benign_label=0
            else:
                source_scaler.fit(df_source[RAW_15_FEATURES])

            # Step 2: Scale source data and train GNN
            df_src_scaled, src_feats = apply_scaler(df_source, RAW_15_FEATURES,
                                                     source_scaler, scaler_name.lower().replace('-', ''))

            scaler_type_key = scaler_name.lower().replace('-', '')
            if 'tri' in scaler_type_key:
                scaler_type_key = 'tri-channel'

            model = train_gnn(df_src_scaled, src_feats, device, seed,
                              epochs=GNN_CONFIG['epochs'])

            # Step 3: Evaluate on each target dataset
            for ds_name, df_target_full in targets.items():
                # Split target: 20k calibration, rest for test
                if len(df_target_full) > 20000:
                    df_calib = df_target_full.iloc[:20000].copy().reset_index(drop=True)
                    df_test = df_target_full.iloc[20000:].copy().reset_index(drop=True)
                else:
                    df_calib = df_target_full.iloc[:len(df_target_full)//3].copy().reset_index(drop=True)
                    df_test = df_target_full.iloc[len(df_target_full)//3:].copy().reset_index(drop=True)

                # ── Mode 1: Original ──
                # Apply source scaler to test data, evaluate with source model
                df_test_orig, feats_orig = apply_scaler(df_test, RAW_15_FEATURES,
                                                         source_scaler, scaler_type_key)
                f1_orig = evaluate_f1(model, df_test_orig, feats_orig, device)
                all_results.append({
                    'dataset': ds_name, 'scaler': scaler_name,
                    'mode': 'Original', 'seed': seed, 'f1': f1_orig,
                })
                print(f"    {ds_name} Original  F1={f1_orig:.4f}")

                # ── Mode 2: Rescale ──
                # Fit new scaler on calibration data, apply to test, use same model
                rescale_scaler = scaler_factory()
                if scaler_name == 'Tri-Channel':
                    rescale_scaler.fit(df_calib[RAW_15_FEATURES],
                                       df_calib['Label_Binary'])
                else:
                    rescale_scaler.fit(df_calib[RAW_15_FEATURES])

                df_test_rescale, feats_rescale = apply_scaler(df_test, RAW_15_FEATURES,
                                                               rescale_scaler, scaler_type_key)
                f1_rescale = evaluate_f1(model, df_test_rescale, feats_rescale, device)
                all_results.append({
                    'dataset': ds_name, 'scaler': scaler_name,
                    'mode': 'Rescale', 'seed': seed, 'f1': f1_rescale,
                })
                print(f"    {ds_name} Rescale   F1={f1_rescale:.4f}")

                # ── Mode 3: Retrain ──
                # Fit new scaler on calibration, retrain model on calibration, evaluate on test
                df_calib_retrain, feats_retrain = apply_scaler(df_calib, RAW_15_FEATURES,
                                                                rescale_scaler, scaler_type_key)
                retrained_model = train_gnn(df_calib_retrain, feats_retrain, device, seed,
                                            epochs=GNN_CONFIG['epochs'])

                df_test_retrain, feats_retrain2 = apply_scaler(df_test, RAW_15_FEATURES,
                                                                rescale_scaler, scaler_type_key)
                f1_retrain = evaluate_f1(retrained_model, df_test_retrain, feats_retrain2, device)
                all_results.append({
                    'dataset': ds_name, 'scaler': scaler_name,
                    'mode': 'Retrain', 'seed': seed, 'f1': f1_retrain,
                })
                print(f"    {ds_name} Retrain   F1={f1_retrain:.4f}")

    return all_results


def save_results_csv(results, output_path):
    """Save raw results to CSV."""
    df = pd.DataFrame(results)
    df.to_csv(output_path, index=False)
    print(f"[saved] Raw F1 results → {output_path}")
    return df


def generate_figure(results_df, output_path):
    """Generate Figure 1: grouped bar chart of F1 scores."""
    # Aggregate: mean and std across seeds
    agg = results_df.groupby(['dataset', 'scaler', 'mode']).agg(
        mean_f1=('f1', 'mean'),
        std_f1=('f1', 'std'),
        count=('f1', 'count')
    ).reset_index()
    agg['std_f1'] = agg['std_f1'].fillna(0)

    datasets = sorted(results_df['dataset'].unique())
    scalers = ['StandardScaler', 'RobustScaler', 'Tri-Channel']
    modes = ['Original', 'Rescale', 'Retrain']

    # Colors for modes
    mode_colors = {
        'Original': '#4C72B0',
        'Rescale': '#55A868',
        'Retrain': '#C44E52',
    }

    fig, axes = plt.subplots(1, len(datasets), figsize=(7 * len(datasets), 6), sharey=True)
    if len(datasets) == 1:
        axes = [axes]

    plt.rcParams.update({
        'font.family': 'sans-serif',
        'font.sans-serif': ['DejaVu Sans', 'Arial'],
        'font.size': 11,
        'axes.grid': True,
        'grid.alpha': 0.3,
        'axes.spines.top': False,
        'axes.spines.right': False,
    })

    for ax_idx, ds_name in enumerate(datasets):
        ax = axes[ax_idx]
        ds_data = agg[agg['dataset'] == ds_name]

        x = np.arange(len(scalers))
        width = 0.25

        for m_idx, mode in enumerate(modes):
            mode_data = ds_data[ds_data['mode'] == mode]
            means = []
            errs = []
            for scaler in scalers:
                row = mode_data[mode_data['scaler'] == scaler]
                if not row.empty:
                    means.append(row['mean_f1'].values[0])
                    errs.append(row['std_f1'].values[0])
                else:
                    means.append(0)
                    errs.append(0)

            bars = ax.bar(x + m_idx * width, means, width, yerr=errs,
                         label=mode, color=mode_colors[mode],
                         edgecolor='white', linewidth=0.8, capsize=3)

            # Value labels
            for bar, val in zip(bars, means):
                if val > 0.01:
                    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                            f'{val:.3f}', ha='center', va='bottom', fontsize=7,
                            fontweight='bold')

        ax.set_xlabel('Scaler Configuration')
        ax.set_ylabel('F1 Score' if ax_idx == 0 else '')
        ax.set_title(f'{ds_name} Dataset')
        ax.set_xticks(x + width)
        ax.set_xticklabels(scalers, rotation=15, ha='right')
        ax.set_ylim(0, 1.15)
        ax.legend(loc='upper right', fontsize=9)

    fig.suptitle('Figure 1: Rescale vs Retrain — F1 Score Comparison', fontsize=14, fontweight='bold', y=1.02)
    fig.tight_layout()
    fig.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close(fig)
    print(f"[saved] Figure 1 → {output_path}")


def validate_results(results):
    """Validate that no required result is all-zero."""
    df = pd.DataFrame(results)
    issues = []

    for ds in df['dataset'].unique():
        for scaler in df['scaler'].unique():
            for mode in df['mode'].unique():
                subset = df[(df['dataset'] == ds) & (df['scaler'] == scaler) & (df['mode'] == mode)]
                if subset.empty:
                    issues.append(f"MISSING: {ds}/{scaler}/{mode}")
                elif subset['f1'].max() == 0.0:
                    issues.append(f"ALL-ZERO F1: {ds}/{scaler}/{mode}")

    if issues:
        print("\n[VALIDATION WARNINGS]")
        for issue in issues:
            print(f"  ⚠ {issue}")
    else:
        print("\n[VALIDATION] All F1 scores are non-zero ✓")

    return issues


def main():
    print("=" * 60)
    print("  FIGURE 1: Rescale vs Retrain Experiment")
    print("=" * 60)
    t_start = time.time()

    results = run_experiment()

    # Save CSV
    csv_path = os.path.join(SCRIPT_DIR, "fig1_f1_raw.csv")
    results_df = save_results_csv(results, csv_path)

    # Validate
    issues = validate_results(results)

    # Generate figure
    fig_path = os.path.join(SCRIPT_DIR, "fig1_rescale_vs_retrain.png")
    generate_figure(results_df, fig_path)

    elapsed = time.time() - t_start
    print(f"\n[done] Completed in {elapsed:.1f}s")
    print(f"  CSV: {csv_path}")
    print(f"  Figure: {fig_path}")

    if issues:
        print(f"\n[WARNING] {len(issues)} validation issues detected.")
        for issue in issues:
            print(f"  - {issue}")

    return results


if __name__ == "__main__":
    main()

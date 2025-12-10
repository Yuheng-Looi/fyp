"""
GNN Training Utilities for Network Intrusion Detection.

This module contains:
- Fixed label mapping (multiclass and binary)
- Protocol-aware kNN graph construction
- GNN models (GraphSAGE, GAT)
- Training functions with early stopping
- Explainability utilities (GNNExplainer, feature attribution)
- CTGAN synthetic data generation helpers

UPDATED: Protocol-aware graph, fixed label maps, explainability support.
"""

import os
import json
import copy
import warnings
from datetime import datetime
from collections import Counter

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
import joblib

from sklearn.preprocessing import RobustScaler, MinMaxScaler
from sklearn.neighbors import NearestNeighbors
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, mean_squared_error, mean_absolute_error
)
from scipy.spatial.distance import jensenshannon
import matplotlib.pyplot as plt
import seaborn as sns

from torch_geometric.data import Data
from torch_geometric.nn import SAGEConv, GATConv
from torch_geometric.explain import Explainer, GNNExplainer

warnings.filterwarnings('ignore')

# ============================================================================
# LABEL MAPPING (FIXED - DO NOT USE LabelEncoder)
# ============================================================================

LABEL_MAP = {
    0: 'BFA',
    1: 'BOTNET',
    2: 'DDoS',
    3: 'DoS',
    4: 'Normal',
    5: 'Probe',
    6: 'U2R',
    7: 'Web-Attack'
}

REVERSE_LABEL_MAP = {v: k for k, v in LABEL_MAP.items()}

BINARY_LABEL_MAP = {
    0: 'Benign',
    1: 'Attack'
}

REVERSE_BINARY_LABEL_MAP = {v: k for k, v in BINARY_LABEL_MAP.items()}


def get_label_map(binary=False):
    """Return label mapping dictionary."""
    return BINARY_LABEL_MAP if binary else LABEL_MAP


def get_reverse_label_map(binary=False):
    """Return reverse label mapping dictionary."""
    return REVERSE_BINARY_LABEL_MAP if binary else REVERSE_LABEL_MAP


def encode_labels(labels, binary=False):
    """
    Encode string labels to integers using the fixed label map.
    
    Args:
        labels: array-like of string labels
        binary: if True, use binary encoding (Normal->0, others->1)
    
    Returns:
        numpy array of encoded labels
    """
    labels = np.array([str(l).strip() for l in labels])
    
    if binary:
        # Binary: Normal -> 0 (Benign), everything else -> 1 (Attack)
        encoded = np.where(labels == 'Normal', 0, 1)
    else:
        # Multiclass: use fixed reverse label map
        encoded = np.zeros(len(labels), dtype=np.int64)
        for i, label in enumerate(labels):
            if label in REVERSE_LABEL_MAP:
                encoded[i] = REVERSE_LABEL_MAP[label]
            else:
                # Try to find partial match or default
                matched = False
                for key in REVERSE_LABEL_MAP:
                    if key.lower() in label.lower() or label.lower() in key.lower():
                        encoded[i] = REVERSE_LABEL_MAP[key]
                        matched = True
                        break
                if not matched:
                    print(f"  Warning: Unknown label '{label}', defaulting to Normal (4)")
                    encoded[i] = 4  # Default to Normal
    
    return encoded


def decode_labels(encoded, binary=False):
    """
    Decode integer labels back to string names.
    
    Args:
        encoded: array-like of integer labels
        binary: if True, use binary decoding
    
    Returns:
        list of string labels
    """
    label_map = get_label_map(binary)
    return [label_map.get(int(e), 'Unknown') for e in encoded]


# ============================================================================
# PROTOCOL-AWARE kNN GRAPH CONSTRUCTION
# ============================================================================

def get_protocol_group(protocol_value):
    """
    Map protocol values to groups: TCP, UDP, ICMP, or Other.
    
    Protocol numbers: 6=TCP, 17=UDP, 1=ICMP
    """
    try:
        p = int(protocol_value)
        if p == 6:
            return 'TCP'
        elif p == 17:
            return 'UDP'
        elif p == 1:
            return 'ICMP'
        else:
            return 'Other'
    except (ValueError, TypeError):
        # Handle string protocols
        p_str = str(protocol_value).upper()
        if 'TCP' in p_str:
            return 'TCP'
        elif 'UDP' in p_str:
            return 'UDP'
        elif 'ICMP' in p_str:
            return 'ICMP'
        else:
            return 'Other'


def build_protocol_aware_knn_graph(X, protocols, k=5, metric='euclidean'):
    """
    Build k-NN graph with protocol awareness.
    
    Edges are only created between nodes with the same protocol.
    This prevents mixing TCP/UDP/ICMP flows in the graph structure.
    
    Args:
        X: Feature matrix (n_samples, n_features)
        protocols: Array of protocol values for each sample
        k: Number of neighbors (default 5)
        metric: Distance metric (default 'euclidean')
    
    Returns:
        edge_index: torch.Tensor of shape (2, num_edges)
    """
    print(f"\nBuilding Protocol-Aware k-NN graph (k={k})...")
    
    n_samples = X.shape[0]
    protocols = np.array(protocols)
    
    # Map protocols to groups
    protocol_groups = np.array([get_protocol_group(p) for p in protocols])
    unique_groups = np.unique(protocol_groups)
    
    print(f"  Protocol groups found: {dict(Counter(protocol_groups))}")
    
    all_edges = []
    
    for group in unique_groups:
        # Get indices for this protocol group
        group_mask = protocol_groups == group
        group_indices = np.where(group_mask)[0]
        n_group = len(group_indices)
        
        if n_group < 2:
            print(f"  Skipping {group}: only {n_group} samples")
            continue
        
        # Extract features for this group
        X_group = X[group_indices]
        
        # Build k-NN within group (use min of k and group size - 1)
        k_actual = min(k, n_group - 1)
        if k_actual < 1:
            continue
            
        knn = NearestNeighbors(n_neighbors=k_actual + 1, metric=metric, n_jobs=-1)
        knn.fit(X_group)
        distances, indices = knn.kneighbors(X_group)
        
        # Build edges (skip self-loops)
        for local_i in range(n_group):
            global_i = group_indices[local_i]
            for j in range(1, k_actual + 1):  # Skip index 0 (self)
                local_j = indices[local_i, j]
                global_j = group_indices[local_j]
                all_edges.append([global_i, global_j])
        
        print(f"  {group}: {n_group} nodes, {n_group * k_actual} edges")
    
    if len(all_edges) == 0:
        print("  Warning: No edges created! Creating fallback edges...")
        # Fallback: create at least some edges
        for i in range(min(100, n_samples)):
            j = (i + 1) % n_samples
            all_edges.append([i, j])
    
    edge_index = torch.tensor(all_edges, dtype=torch.long).t().contiguous()
    
    print(f"  ✓ Total graph: {n_samples} nodes, {edge_index.shape[1]} edges")
    print(f"  Average degree: {edge_index.shape[1] / n_samples:.2f}")
    
    return edge_index


# Legacy function name for compatibility
def build_knn_graph(X, k=5, metric='euclidean', protocols=None):
    """
    Build k-NN graph. If protocols provided, uses protocol-aware construction.
    """
    if protocols is not None:
        return build_protocol_aware_knn_graph(X, protocols, k, metric)
    
    # Fallback to simple k-NN if no protocol info
    print(f"\nBuilding simple k-NN graph (k={k}, metric={metric})...")
    
    knn = NearestNeighbors(n_neighbors=k+1, metric=metric, n_jobs=-1)
    knn.fit(X)
    distances, indices = knn.kneighbors(X)
    
    edges = []
    for i in range(len(X)):
        for j in indices[i][1:]:
            edges.append([i, j])
    
    edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
    
    print(f"  ✓ Created graph: {len(X)} nodes, {edge_index.shape[1]} edges")
    return edge_index


# ============================================================================
# DATA LOADING AND PREPROCESSING
# ============================================================================

def load_and_preprocess_gnn_data(csv_paths, scaler_path='scalers/gnn_scaler.pkl', 
                                  fit_scaler=True, binary_labels=False):
    """
    Load and preprocess CSV files for GNN training.
    
    Uses FIXED label mapping (not LabelEncoder).
    Extracts Protocol column for graph construction.
    
    Args:
        csv_paths: Single path or list of paths to CSV files
        scaler_path: Path to save/load the scaler
        fit_scaler: If True, fit new scaler; if False, load existing
        binary_labels: If True, convert to binary (Normal vs Attack)
    
    Returns:
        tuple: (X_scaled, y_encoded, scaler, protocols, feature_names, label_map)
    """
    print("Loading and preprocessing data for GNN...")
    
    if isinstance(csv_paths, str):
        csv_paths = [csv_paths]
    
    dfs = []
    for path in csv_paths:
        df = pd.read_csv(path)
        print(f"  Loaded {path}: {df.shape}")
        dfs.append(df)
    
    data = pd.concat(dfs, ignore_index=True)
    print(f"  Combined shape: {data.shape}")
    
    # Extract labels
    y_raw = data['Label'].astype(str).values
    
    # Extract Protocol before dropping
    if 'Protocol' in data.columns:
        protocols = data['Protocol'].values.copy()
    else:
        print("  Warning: No 'Protocol' column found, using default (TCP)")
        protocols = np.full(len(data), 6)  # Default to TCP
    
    # Prepare features (drop Label column only, keep Protocol for features)
    X = data.drop(columns=['Label'])
    
    feature_names = X.columns.tolist()
    
    # Handle NaN/inf
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(X.median())
    X = X.values
    
    # Encode labels using fixed mapping
    y_encoded = encode_labels(y_raw, binary=binary_labels)
    
    label_map = get_label_map(binary_labels)
    
    print(f"\n  Features: {len(feature_names)}")
    print(f"  Label mapping: {label_map}")
    print(f"  Class distribution: {dict(Counter(y_encoded))}")
    
    # Scale features
    scaler_dir = os.path.dirname(scaler_path)
    if scaler_dir:
        os.makedirs(scaler_dir, exist_ok=True)
    
    if fit_scaler:
        print(f"\n  Fitting RobustScaler...")
        scaler = RobustScaler()
        X_scaled = scaler.fit_transform(X)
        
        joblib.dump(scaler, scaler_path)
        print(f"  ✓ Scaler saved to: {scaler_path}")
    else:
        print(f"\n  Loading existing scaler from: {scaler_path}")
        scaler = joblib.load(scaler_path)
        X_scaled = scaler.transform(X)
    
    return X_scaled, y_encoded, scaler, protocols, feature_names, label_map


def create_train_val_test_masks(n_samples, y, train_ratio=0.7, val_ratio=0.15, random_state=42):
    """
    Create train/val/test masks with stratification.
    
    Args:
        n_samples: Total number of samples
        y: Labels for stratification
        train_ratio: Training set ratio
        val_ratio: Validation set ratio
        random_state: Random seed
    
    Returns:
        tuple: (train_mask, val_mask, test_mask) as boolean numpy arrays
    """
    test_ratio = 1.0 - train_ratio - val_ratio
    
    idx = np.arange(n_samples)
    
    # First split: train vs (val+test)
    train_idx, temp_idx = train_test_split(
        idx, test_size=(val_ratio + test_ratio), 
        random_state=random_state, stratify=y
    )
    
    # Second split: val vs test
    val_relative = val_ratio / (val_ratio + test_ratio)
    val_idx, test_idx = train_test_split(
        temp_idx, test_size=(1 - val_relative),
        random_state=random_state, stratify=y[temp_idx]
    )
    
    train_mask = np.zeros(n_samples, dtype=bool)
    val_mask = np.zeros(n_samples, dtype=bool)
    test_mask = np.zeros(n_samples, dtype=bool)
    
    train_mask[train_idx] = True
    val_mask[val_idx] = True
    test_mask[test_idx] = True
    
    print(f"  Split: Train={train_mask.sum()}, Val={val_mask.sum()}, Test={test_mask.sum()}")
    
    return train_mask, val_mask, test_mask


def create_pyg_data(X, y, edge_index, train_mask, val_mask, test_mask):
    """
    Create PyTorch Geometric Data object for GNN training.
    """
    data = Data(
        x=torch.FloatTensor(X),
        edge_index=edge_index,
        y=torch.LongTensor(y),
        train_mask=torch.BoolTensor(train_mask),
        val_mask=torch.BoolTensor(val_mask),
        test_mask=torch.BoolTensor(test_mask)
    )
    return data


# ============================================================================
# GNN MODELS
# ============================================================================

class GraphSAGEModel(nn.Module):
    """GraphSAGE model for node classification."""
    
    def __init__(self, num_features, hidden_dim=128, num_classes=8, dropout=0.3, num_layers=2, device=None):
        super(GraphSAGEModel, self).__init__()
        self.num_layers = num_layers
        self.dropout = dropout
        self.device = device
        
        self.convs = nn.ModuleList()
        self.convs.append(SAGEConv(num_features, hidden_dim))
        
        for _ in range(num_layers - 1):
            self.convs.append(SAGEConv(hidden_dim, hidden_dim))
        
        self.lin = nn.Linear(hidden_dim, num_classes)
        
        if self.device is not None:
            self.to(self.device)
    
    def forward(self, x, edge_index):
        for conv in self.convs:
            x = conv(x, edge_index)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)
        
        x = self.lin(x)
        return x


class GATModel(nn.Module):
    """Graph Attention Network model for node classification."""
    
    def __init__(self, num_features, hidden_dim=128, num_classes=8, dropout=0.3, num_layers=2, heads=4, device=None):
        super(GATModel, self).__init__()
        self.num_layers = num_layers
        self.dropout = dropout
        self.device = device
        
        self.convs = nn.ModuleList()
        self.convs.append(GATConv(num_features, hidden_dim, heads=heads, dropout=dropout))
        
        for _ in range(num_layers - 2):
            self.convs.append(GATConv(hidden_dim * heads, hidden_dim, heads=heads, dropout=dropout))
        
        if num_layers > 1:
            self.convs.append(GATConv(hidden_dim * heads, hidden_dim, heads=1, dropout=dropout))
        
        self.lin = nn.Linear(hidden_dim, num_classes)
        
        if self.device is not None:
            self.to(self.device)
    
    def forward(self, x, edge_index):
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index)
            x = F.elu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)
        
        x = self.lin(x)
        return x


# ============================================================================
# TRAINING FUNCTIONS
# ============================================================================

def calculate_class_weights(y_train):
    """Calculate inverse frequency class weights for loss function."""
    class_counts = Counter(y_train)
    total = len(y_train)
    num_classes = max(class_counts.keys()) + 1
    
    weights = torch.zeros(num_classes)
    for cls, count in class_counts.items():
        weights[cls] = total / (num_classes * count)
    
    print(f"\nClass weights (inverse frequency):")
    for cls in sorted(class_counts.keys()):
        print(f"  Class {cls}: {weights[cls]:.4f}")
    
    return weights


def train_gnn_epoch(model, data, optimizer, criterion, device):
    """Train GNN for one epoch."""
    model.train()
    data = data.to(device)
    
    optimizer.zero_grad()
    out = model(data.x, data.edge_index)
    loss = criterion(out[data.train_mask], data.y[data.train_mask])
    loss.backward()
    optimizer.step()
    
    return loss.item()


def evaluate_gnn(model, data, mask, device):
    """Evaluate GNN on a specific split."""
    model.eval()
    data = data.to(device)
    
    with torch.no_grad():
        out = model(data.x, data.edge_index)
        pred = out.argmax(dim=1)
        
        y_pred = pred[mask].cpu().numpy()
        y_true = data.y[mask].cpu().numpy()
        
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, average='macro', zero_division=0)
        recall = recall_score(y_true, y_pred, average='macro', zero_division=0)
        f1 = f1_score(y_true, y_pred, average='macro', zero_division=0)
        
        criterion = nn.CrossEntropyLoss()
        loss = criterion(out[mask], data.y[mask]).item()
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'loss': loss,
        'predictions': y_pred,
        'true_labels': y_true
    }


def train_gnn_with_early_stopping(model, data, optimizer, criterion, device,
                                   num_epochs=200, patience=20, verbose=True):
    """
    Train GNN with early stopping based on validation loss.
    
    Returns:
        tuple: (best_model, history)
    """
    history = {
        'train_loss': [],
        'val_loss': [],
        'val_accuracy': [],
        'val_f1': []
    }
    
    best_val_loss = float('inf')
    best_model = None
    patience_counter = 0
    
    print(f"\nTraining GNN (max {num_epochs} epochs, patience {patience})...")
    
    for epoch in range(num_epochs):
        train_loss = train_gnn_epoch(model, data, optimizer, criterion, device)
        val_metrics = evaluate_gnn(model, data, data.val_mask, device)
        
        history['train_loss'].append(train_loss)
        history['val_loss'].append(val_metrics['loss'])
        history['val_accuracy'].append(val_metrics['accuracy'])
        history['val_f1'].append(val_metrics['f1'])
        
        if val_metrics['loss'] < best_val_loss:
            best_val_loss = val_metrics['loss']
            best_model = copy.deepcopy(model)
            patience_counter = 0
        else:
            patience_counter += 1
        
        if verbose and (epoch % 10 == 0 or patience_counter == 0):
            print(f"  Epoch {epoch:3d}: Train Loss={train_loss:.4f}, "
                  f"Val Loss={val_metrics['loss']:.4f}, "
                  f"Val Acc={val_metrics['accuracy']:.4f}, "
                  f"Val F1={val_metrics['f1']:.4f}")
        
        if patience_counter >= patience:
            print(f"\n  ✓ Early stopping at epoch {epoch} (no improvement for {patience} epochs)")
            break
    
    print(f"  ✓ Training complete. Best val loss: {best_val_loss:.4f}")
    
    return best_model, history


def print_detailed_metrics(metrics, label_map, split_name="Test"):
    """Print detailed classification metrics."""
    print(f"\n{'='*80}")
    print(f"{split_name.upper()} SET METRICS")
    print(f"{'='*80}")
    
    print(f"\nOverall Metrics:")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1 Score:  {metrics['f1']:.4f}")
    
    y_true = metrics['true_labels']
    y_pred = metrics['predictions']
    
    # Get class names for report
    unique_labels = sorted(set(y_true) | set(y_pred))
    target_names = [label_map.get(l, str(l)) for l in unique_labels]
    
    print(f"\nPer-Class Metrics:")
    report = classification_report(y_true, y_pred, 
                                   labels=unique_labels,
                                   target_names=target_names,
                                   zero_division=0,
                                   digits=4)
    print(report)
    
    cm = confusion_matrix(y_true, y_pred, labels=unique_labels)
    print(f"\nConfusion Matrix:")
    print(f"  Classes: {[label_map.get(l, str(l)) for l in unique_labels]}")
    print(cm)
    
    return cm


def save_gnn_model(model, path, metadata=None, label_map=None):
    """Save trained GNN model with metadata and label mapping."""
    model_dir = os.path.dirname(path)
    if model_dir:
        os.makedirs(model_dir, exist_ok=True)
    
    checkpoint = {
        'model_state_dict': model.state_dict(),
        'model_class': model.__class__.__name__,
        'metadata': metadata or {},
        'label_map': label_map or LABEL_MAP
    }
    
    torch.save(checkpoint, path)
    print(f"  ✓ Model saved to: {path}")


# ============================================================================
# COMPLETE TRAINING PIPELINE
# ============================================================================

def train_gnn_multiclass(csv_path, split_name, train_ratio, val_ratio, 
                         model_type='GAT', save_dir='models', device=None):
    """
    Complete multiclass GNN training pipeline.
    
    Args:
        csv_path: Path to training CSV
        split_name: Name for saving (e.g., '70_15_15')
        train_ratio: Training set ratio
        val_ratio: Validation set ratio
        model_type: 'GAT' or 'GraphSAGE'
        save_dir: Directory to save model
        device: torch device
    
    Returns:
        tuple: (best_model, test_metrics, label_map, data, feature_names)
    """
    print(f"\n{'='*80}")
    print(f"TRAINING MULTICLASS {model_type} - Split {split_name}")
    print(f"{'='*80}")
    
    if device is None:
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")
    
    # Load data
    scaler_path = f'scalers/gnn_scaler_multiclass_{split_name}.pkl'
    X, y, scaler, protocols, feature_names, label_map = load_and_preprocess_gnn_data(
        csv_path, scaler_path=scaler_path, fit_scaler=True, binary_labels=False
    )
    
    n_samples = X.shape[0]
    num_features = X.shape[1]
    num_classes = len(set(y))
    
    # Check if dataset is too large for GPU
    MAX_GPU_NODES = int(os.environ.get('GNN_MAX_GPU_NODES', 50000))
    if device.type == 'cuda' and n_samples > MAX_GPU_NODES:
        print(f"  Dataset ({n_samples} nodes) > GPU limit ({MAX_GPU_NODES}). Using CPU.")
        device = torch.device('cpu')
    
    # Build protocol-aware graph
    edge_index = build_protocol_aware_knn_graph(X, protocols, k=5)
    
    # Create masks
    train_mask, val_mask, test_mask = create_train_val_test_masks(
        n_samples, y, train_ratio=train_ratio, val_ratio=val_ratio
    )
    
    # Create PyG data
    data = create_pyg_data(X, y, edge_index, train_mask, val_mask, test_mask)
    
    # Create model
    if model_type.upper() == 'GAT':
        model = GATModel(num_features=num_features, hidden_dim=64, 
                        num_classes=num_classes, heads=2, device=device)
    else:
        model = GraphSAGEModel(num_features=num_features, hidden_dim=64,
                               num_classes=num_classes, device=device)
    
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-5)
    
    # Calculate class weights
    y_train = y[train_mask]
    weights = calculate_class_weights(y_train)
    criterion = nn.CrossEntropyLoss(weight=weights.to(device))
    
    # Train
    best_model, history = train_gnn_with_early_stopping(
        model, data, optimizer, criterion, device,
        num_epochs=200, patience=20, verbose=True
    )
    
    # Evaluate on test set
    test_metrics = evaluate_gnn(best_model, data, data.test_mask, device)
    print_detailed_metrics(test_metrics, label_map, "Test")
    
    # Check for low accuracy
    if test_metrics['accuracy'] < 0.5:
        print("\n⚠️  WARNING: Low accuracy (<50%). Diagnostics:")
        print(f"  - Train samples: {train_mask.sum()}")
        print(f"  - Unique classes in train: {len(set(y[train_mask]))}")
        print(f"  - Class distribution: {dict(Counter(y[train_mask]))}")
    
    # Save model
    os.makedirs(save_dir, exist_ok=True)
    model_name = f"gnn_{model_type.lower()}_{split_name}.pt"
    model_path = os.path.join(save_dir, model_name)
    save_gnn_model(best_model, model_path, 
                   metadata={'split': split_name, 'test_f1': test_metrics['f1'],
                            'num_features': num_features, 'num_classes': num_classes},
                   label_map=label_map)
    
    return best_model, test_metrics, label_map, data, feature_names


def train_gnn_binary(csv_path, model_type='GAT', save_dir='models', device=None):
    """
    Complete binary GNN training pipeline.
    
    Binary labels: 0=Benign (Normal), 1=Attack (all others)
    """
    print(f"\n{'='*80}")
    print(f"TRAINING BINARY {model_type}")
    print(f"{'='*80}")
    
    if device is None:
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")
    
    # Load data with binary labels
    scaler_path = 'scalers/gnn_scaler_binary.pkl'
    X, y, scaler, protocols, feature_names, label_map = load_and_preprocess_gnn_data(
        csv_path, scaler_path=scaler_path, fit_scaler=True, binary_labels=True
    )
    
    n_samples = X.shape[0]
    num_features = X.shape[1]
    num_classes = 2
    
    # Check GPU limit
    MAX_GPU_NODES = int(os.environ.get('GNN_MAX_GPU_NODES', 50000))
    if device.type == 'cuda' and n_samples > MAX_GPU_NODES:
        print(f"  Dataset ({n_samples} nodes) > GPU limit ({MAX_GPU_NODES}). Using CPU.")
        device = torch.device('cpu')
    
    # Build protocol-aware graph
    edge_index = build_protocol_aware_knn_graph(X, protocols, k=5)
    
    # Create masks (70/15/15 split for binary)
    train_mask, val_mask, test_mask = create_train_val_test_masks(
        n_samples, y, train_ratio=0.7, val_ratio=0.15
    )
    
    # Create PyG data
    data = create_pyg_data(X, y, edge_index, train_mask, val_mask, test_mask)
    
    # Create model
    if model_type.upper() == 'GAT':
        model = GATModel(num_features=num_features, hidden_dim=64,
                        num_classes=num_classes, heads=2, device=device)
    else:
        model = GraphSAGEModel(num_features=num_features, hidden_dim=64,
                               num_classes=num_classes, device=device)
    
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-5)
    
    # Calculate class weights
    y_train = y[train_mask]
    weights = calculate_class_weights(y_train)
    criterion = nn.CrossEntropyLoss(weight=weights.to(device))
    
    # Train
    best_model, history = train_gnn_with_early_stopping(
        model, data, optimizer, criterion, device,
        num_epochs=200, patience=20, verbose=True
    )
    
    # Evaluate
    test_metrics = evaluate_gnn(best_model, data, data.test_mask, device)
    print_detailed_metrics(test_metrics, label_map, "Test")
    
    # Check for low accuracy
    if test_metrics['accuracy'] < 0.5:
        print("\n⚠️  WARNING: Low accuracy (<50%). Diagnostics:")
        print(f"  - Class distribution: {dict(Counter(y[train_mask]))}")
    
    # Save model
    os.makedirs(save_dir, exist_ok=True)
    model_name = f"gnn_{model_type.lower()}_binary.pt"
    model_path = os.path.join(save_dir, model_name)
    save_gnn_model(best_model, model_path,
                   metadata={'binary': True, 'test_f1': test_metrics['f1'],
                            'num_features': num_features},
                   label_map=label_map)
    
    return best_model, test_metrics, label_map, data, feature_names


# ============================================================================
# EXPLAINABILITY UTILITIES
# ============================================================================

def explain_node(model, data, node_idx, device, feature_names=None):
    """
    Explain a single node's prediction using GNNExplainer.
    
    Returns:
        dict: Explanation with top features, neighbors, edges
    """
    model.eval()
    data = data.to(device)
    
    try:
        explainer = Explainer(
            model=model,
            algorithm=GNNExplainer(epochs=100),
            explanation_type='model',
            node_mask_type='attributes',
            edge_mask_type='object',
            model_config=dict(
                mode='multiclass_classification',
                task_level='node',
                return_type='log_probs',
            ),
        )
        
        explanation = explainer(data.x, data.edge_index, index=node_idx)
        
        # Extract feature importance
        node_mask = explanation.node_mask
        if node_mask is not None:
            node_mask = node_mask.cpu().numpy()
            if len(node_mask.shape) > 1:
                feature_importance = node_mask[node_idx] if node_idx < len(node_mask) else node_mask.mean(axis=0)
            else:
                feature_importance = node_mask
        else:
            feature_importance = np.zeros(data.x.shape[1])
        
        # Get top features
        top_k = min(10, len(feature_importance))
        top_feature_idx = np.argsort(feature_importance)[-top_k:][::-1]
        
        if feature_names is not None:
            top_features = [(feature_names[i], float(feature_importance[i])) for i in top_feature_idx]
        else:
            top_features = [(f"Feature_{i}", float(feature_importance[i])) for i in top_feature_idx]
        
        # Extract edge importance
        edge_mask = explanation.edge_mask
        if edge_mask is not None:
            edge_mask = edge_mask.cpu().numpy()
            important_edges = np.where(edge_mask > 0.5)[0]
        else:
            important_edges = []
        
        # Find neighbors
        edge_index = data.edge_index.cpu().numpy()
        neighbors = []
        for i in range(edge_index.shape[1]):
            if edge_index[0, i] == node_idx:
                neighbors.append(int(edge_index[1, i]))
            elif edge_index[1, i] == node_idx:
                neighbors.append(int(edge_index[0, i]))
        neighbors = list(set(neighbors))[:10]  # Limit to 10 neighbors
        
        # Get prediction
        with torch.no_grad():
            out = model(data.x, data.edge_index)
            pred = out[node_idx].argmax().item()
            true_label = data.y[node_idx].item()
        
        return {
            'node_idx': node_idx,
            'predicted_class': pred,
            'true_class': true_label,
            'top_features': top_features,
            'num_important_edges': len(important_edges),
            'neighbors': neighbors
        }
        
    except Exception as e:
        print(f"  Warning: GNNExplainer failed for node {node_idx}: {e}")
        # Return basic info without explanation
        with torch.no_grad():
            out = model(data.x, data.edge_index)
            pred = out[node_idx].argmax().item()
            true_label = data.y[node_idx].item()
        
        return {
            'node_idx': node_idx,
            'predicted_class': pred,
            'true_class': true_label,
            'top_features': [],
            'num_important_edges': 0,
            'neighbors': [],
            'error': str(e)
        }


def explain_nodes_by_class(model, data, device, label_map, feature_names=None, n_per_class=3):
    """
    Explain N random nodes per class.
    
    Args:
        model: Trained GNN model
        data: PyG Data object
        device: torch device
        label_map: Label mapping dict
        feature_names: List of feature names
        n_per_class: Number of nodes to explain per class
    
    Returns:
        dict: Explanations grouped by class
    """
    print(f"\nExplaining {n_per_class} nodes per class...")
    
    y = data.y.cpu().numpy()
    unique_classes = sorted(set(y))
    
    explanations = {}
    
    for cls in unique_classes:
        class_name = label_map.get(cls, str(cls))
        class_indices = np.where(y == cls)[0]
        
        if len(class_indices) == 0:
            continue
        
        # Sample random nodes
        n_sample = min(n_per_class, len(class_indices))
        sampled_indices = np.random.choice(class_indices, n_sample, replace=False)
        
        explanations[class_name] = []
        
        for node_idx in sampled_indices:
            exp = explain_node(model, data, int(node_idx), device, feature_names)
            explanations[class_name].append(exp)
        
        print(f"  {class_name}: explained {n_sample} nodes")
    
    return explanations


def summarize_explanations(explanations, label_map, save_path=None):
    """
    Summarize explanations across all classes.
    
    Args:
        explanations: Dict of explanations from explain_nodes_by_class
        label_map: Label mapping dict
        save_path: Optional path to save summary (JSON)
    
    Returns:
        dict: Summary with top features per class
    """
    print("\n" + "="*80)
    print("EXPLANATION SUMMARY")
    print("="*80)
    
    summary = {}
    
    for class_name, class_explanations in explanations.items():
        print(f"\n{class_name}:")
        
        # Aggregate feature importance
        feature_scores = {}
        total_edges = 0
        total_neighbors = 0
        correct_predictions = 0
        
        for exp in class_explanations:
            for feat_name, score in exp.get('top_features', []):
                if feat_name not in feature_scores:
                    feature_scores[feat_name] = []
                feature_scores[feat_name].append(score)
            
            total_edges += exp.get('num_important_edges', 0)
            total_neighbors += len(exp.get('neighbors', []))
            
            if exp['predicted_class'] == exp['true_class']:
                correct_predictions += 1
        
        # Average scores
        avg_feature_scores = {k: np.mean(v) for k, v in feature_scores.items()}
        top_features = sorted(avg_feature_scores.items(), key=lambda x: x[1], reverse=True)[:5]
        
        print(f"  Top influential features:")
        for feat, score in top_features:
            print(f"    - {feat}: {score:.4f}")
        
        n_explanations = len(class_explanations) if class_explanations else 1
        print(f"  Avg important edges: {total_edges / n_explanations:.1f}")
        print(f"  Avg neighbors: {total_neighbors / n_explanations:.1f}")
        print(f"  Prediction accuracy: {correct_predictions}/{len(class_explanations)}")
        
        summary[class_name] = {
            'top_features': top_features,
            'avg_important_edges': total_edges / n_explanations,
            'avg_neighbors': total_neighbors / n_explanations,
            'prediction_accuracy': correct_predictions / n_explanations if n_explanations > 0 else 0
        }
    
    # Save if path provided
    if save_path:
        save_dir = os.path.dirname(save_path)
        if save_dir:
            os.makedirs(save_dir, exist_ok=True)
        
        # Convert to JSON-serializable format
        json_summary = {}
        for cls, data in summary.items():
            json_summary[cls] = {
                'top_features': [(str(f), float(s)) for f, s in data['top_features']],
                'avg_important_edges': float(data['avg_important_edges']),
                'avg_neighbors': float(data['avg_neighbors']),
                'prediction_accuracy': float(data['prediction_accuracy'])
            }
        
        with open(save_path, 'w') as f:
            json.dump(json_summary, f, indent=2)
        print(f"\n✓ Summary saved to: {save_path}")
    
    return summary


def run_explainability(model, data, device, label_map, feature_names, 
                       save_dir='explanations', n_per_class=3):
    """
    Run complete explainability pipeline.
    
    Args:
        model: Trained GNN model
        data: PyG Data object
        device: torch device
        label_map: Label mapping dict
        feature_names: List of feature names
        save_dir: Directory to save explanations
        n_per_class: Nodes to explain per class
    
    Returns:
        dict: Summary of explanations
    """
    os.makedirs(save_dir, exist_ok=True)
    
    print(f"\n{'='*80}")
    print("RUNNING EXPLAINABILITY ANALYSIS")
    print(f"{'='*80}")
    
    # Explain nodes by class
    explanations = explain_nodes_by_class(
        model, data, device, label_map, feature_names, n_per_class
    )
    
    # Save raw explanations
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    exp_path = os.path.join(save_dir, f"explanations_{timestamp}.json")
    
    # Convert to JSON-serializable
    json_explanations = {}
    for cls, exps in explanations.items():
        json_explanations[cls] = []
        for exp in exps:
            json_exp = {
                'node_idx': int(exp['node_idx']),
                'predicted_class': int(exp['predicted_class']),
                'true_class': int(exp['true_class']),
                'top_features': [(str(f), float(s)) for f, s in exp.get('top_features', [])],
                'num_important_edges': int(exp.get('num_important_edges', 0)),
                'neighbors': [int(n) for n in exp.get('neighbors', [])]
            }
            json_explanations[cls].append(json_exp)
    
    with open(exp_path, 'w') as f:
        json.dump(json_explanations, f, indent=2)
    print(f"✓ Raw explanations saved to: {exp_path}")
    
    # Summarize
    summary_path = os.path.join(save_dir, f"summary_{timestamp}.json")
    summary = summarize_explanations(explanations, label_map, summary_path)
    
    return summary


# ============================================================================
# CTGAN UTILITIES (PRESERVED FROM ORIGINAL)
# ============================================================================

def calculate_target_samples(data, balance_strategy='moderate'):
    """Calculate target sample sizes for each class based on balance strategy."""
    label_counts = data['Label'].value_counts()
    median_count = label_counts.median()
    max_count = label_counts.max()
    
    target_samples = {}
    
    if balance_strategy == 'aggressive':
        target_size = int(median_count)
        target_samples = {label: target_size for label in label_counts.index}
        
    elif balance_strategy == 'moderate':
        majority_target = int(max_count * 0.75)
        minority_target = int(majority_target * 0.5)
        
        for label in label_counts.index:
            if label_counts[label] > majority_target:
                target_samples[label] = majority_target
            elif label_counts[label] < minority_target:
                target_samples[label] = minority_target
            else:
                target_samples[label] = label_counts[label]
                
    else:  # conservative
        minority_target = int(max_count * 0.25)
        
        for label in label_counts.index:
            if label_counts[label] < minority_target:
                target_samples[label] = minority_target
            else:
                target_samples[label] = label_counts[label]
    
    return target_samples


def calculate_synthetic_quality_metrics(original_data, synthetic_data, numerical_columns):
    """Calculate quality metrics comparing original and synthetic data."""
    metrics = {}
    
    orig_means = original_data[numerical_columns].mean()
    synth_means = synthetic_data[numerical_columns].mean()
    
    metrics['mae_mean'] = mean_absolute_error(orig_means, synth_means)
    metrics['mse_mean'] = mean_squared_error(orig_means, synth_means)
    
    js_scores = []
    for col in numerical_columns:
        orig_hist, bins = np.histogram(original_data[col], bins=50, density=True)
        synth_hist, _ = np.histogram(synthetic_data[col], bins=bins, density=True)
        
        orig_hist = orig_hist + 1e-10
        synth_hist = synth_hist + 1e-10
        
        orig_hist = orig_hist / orig_hist.sum()
        synth_hist = synth_hist / synth_hist.sum()
        
        js_score = jensenshannon(orig_hist, synth_hist)
        js_scores.append(js_score)
    
    metrics['js_divergence'] = np.mean(js_scores)
    
    orig_corr = original_data[numerical_columns].corr()
    synth_corr = synthetic_data[numerical_columns].corr()
    metrics['feature_correlation_diff'] = np.abs(orig_corr - synth_corr).mean().mean()
    
    return metrics


def print_quality_report(original_data, synthetic_data, label_value, numerical_columns):
    """Print quality report comparing original and synthetic data."""
    print(f"\n{'='*80}")
    print(f"QUALITY REPORT FOR LABEL {label_value}")
    print(f"{'='*80}")
    
    print(f"\nSample Counts:")
    print(f"  Original samples: {len(original_data):,}")
    print(f"  Synthetic samples: {len(synthetic_data):,}")
    print(f"  Total samples: {len(original_data) + len(synthetic_data):,}")
    
    metrics = calculate_synthetic_quality_metrics(original_data, synthetic_data, numerical_columns)
    
    print(f"\nQuality Metrics:")
    print(f"  Mean Absolute Error (MAE):        {metrics['mae_mean']:.6f}")
    print(f"  Mean Squared Error (MSE):         {metrics['mse_mean']:.6f}")
    print(f"  Jensen-Shannon Divergence:        {metrics['js_divergence']:.6f}")
    print(f"  Feature Correlation Difference:   {metrics['feature_correlation_diff']:.6f}")
    
    js_div = metrics['js_divergence']
    if js_div < 0.1:
        quality = "EXCELLENT"
    elif js_div < 0.2:
        quality = "GOOD"
    elif js_div < 0.3:
        quality = "ACCEPTABLE"
    else:
        quality = "POOR"
    
    print(f"\n  Overall Quality Assessment: {quality}")


def print_dataset_summary(data, dataset_name="Dataset"):
    """Print comprehensive dataset summary."""
    print(f"\n{'='*80}")
    print(f"{dataset_name.upper()} SUMMARY")
    print(f"{'='*80}")
    
    print(f"\nTotal samples: {len(data):,}")
    print(f"Total features: {len(data.columns) - 1}")
    
    label_counts = data['Label'].value_counts().sort_index()
    max_count = label_counts.max()
    min_count = label_counts.min()
    
    print(f"\nLabel Distribution:")
    print(f"{'Label':<15} {'Count':<12} {'Percentage':<12} {'Imbalance Ratio':<15}")
    print(f"{'-'*55}")
    
    for label, count in label_counts.items():
        percentage = (count / len(data)) * 100
        ratio = max_count / count if count > 0 else float('inf')
        print(f"{label:<15} {count:<12,} {percentage:<11.2f}% {ratio:<14.2f}x")
    
    print(f"\nImbalance Statistics:")
    print(f"  Majority class size: {max_count:,}")
    print(f"  Minority class size: {min_count:,}")
    print(f"  Imbalance ratio: {max_count/min_count:.2f}:1")

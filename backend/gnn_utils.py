import os
import pickle
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Data
from torch_geometric.nn import SAGEConv, GATConv
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.neighbors import NearestNeighbors
from sklearn.metrics import recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
import eda_utils

# --- Data Loading & Graph Construction ---

def load_gnn_data(raw_folder='datasets', cleaned_ref_path='01eda/cleaned_data15.csv', encoder_path='encoders/label_encoder.pkl'):
    """
    Loads raw data to recover IPs/Time, aligns with cleaned features, and prepares for GNN.
    """
    print("Loading raw data to recover topology...")
    filenames = ['metasploitable-2.csv', 'OVS.csv', 'Normal_data.csv']
    
    # Load raw data (using eda_utils logic but keeping meta columns)
    # We can't use eda_utils.load_and_concatenate_datasets directly if we want to be sure about indices
    # unless we trust it just concats. It does.
    df_raw = eda_utils.load_and_concatenate_datasets(raw_folder, filenames)
    
    # Normalize labels (same as Part 1)
    df_raw['Label'] = (
        df_raw['Label']
        .astype(str)
        .str.replace(r"[\u200b\u200c\u200d\ufeff]", "", regex=True)
        .str.strip()
        .str.replace(r"\s+", " ", regex=True)
    )
    
    # Load reference cleaned data to get the 15 features list
    if not os.path.exists(cleaned_ref_path):
        raise FileNotFoundError(f"Reference file {cleaned_ref_path} not found.")
    
    df_ref = pd.read_csv(cleaned_ref_path, nrows=1)
    feature_cols = [c for c in df_ref.columns if c != 'Label']
    print(f"Selected 15 features: {feature_cols}")
    
    # Check if raw data has these features + meta
    meta_cols = ['Src IP', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp']
    required_cols = feature_cols + meta_cols + ['Label']
    
    # Note: 'Dst Port' and 'Protocol' are likely in feature_cols too. Handle duplicates.
    cols_to_use = list(set(required_cols))
    
    # Filter columns
    df = df_raw[cols_to_use].copy()
    
    # Parse Timestamp
    print("Parsing timestamps...")
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    df = df.sort_values('Timestamp').reset_index(drop=True) # Sort by time for temporal graphs
    
    # Handle NaNs (drop rows with NaNs in features)
    df = df.dropna(subset=feature_cols)
    
    # Encode Label
    if os.path.exists(encoder_path):
        with open(encoder_path, 'rb') as f:
            le = pickle.load(f)
        # Handle unseen labels if any (shouldn't be if raw data is same)
        # But raw data might have labels that were dropped in Part 1? 
        # Part 1 dropped constant columns and high corr, but didn't filter rows by label.
        # However, let's fit_transform or transform safely.
        # The user said "Use existing encoded labels".
        # We'll try transform, if fails, we might need to re-fit or filter.
        # Let's assume consistency.
        # Actually, let's filter to keep only labels in encoder
        df = df[df['Label'].isin(le.classes_)]
        df['Label_Encoded'] = le.transform(df['Label'])
    else:
        print("Encoder not found, creating new one (warning: might differ from Part 1)")
        le = LabelEncoder()
        df['Label_Encoded'] = le.fit_transform(df['Label'])
        
    # Scale Features (Physics-normalization)
    print("Scaling features...")
    scaler = StandardScaler()
    df[feature_cols] = scaler.fit_transform(df[feature_cols])
    
    return df, feature_cols, le

def build_graph(df, feature_cols, strategy='hybrid', k=5, delta_t_seconds=10):
    """
    Constructs a PyG Data object based on the strategy.
    Strategies: 'knn_protocol', 'src_ip_temporal', 'dst_ip_temporal', 'hybrid'
    """
    print(f"Building graph with strategy: {strategy}")
    
    # Node features
    x = torch.tensor(df[feature_cols].values, dtype=torch.float)
    y = torch.tensor(df['Label_Encoded'].values, dtype=torch.long)
    
    edge_index_list = []
    
    # Helper to add edges
    def add_edges(sources, targets):
        edge_index_list.append(torch.tensor([sources, targets], dtype=torch.long))
        
    # 1. Protocol-aware KNN
    if 'knn' in strategy or 'hybrid' in strategy:
        print("  Constructing Protocol-aware KNN edges...")
        # Group by Protocol
        if 'Protocol' in df.columns:
            protocols = df['Protocol'].unique()
            for p in protocols:
                indices = df.index[df['Protocol'] == p].tolist()
                if len(indices) < k + 1:
                    continue
                
                subset = df.iloc[indices][feature_cols].values
                nbrs = NearestNeighbors(n_neighbors=k+1, algorithm='ball_tree').fit(subset)
                distances, knn_indices = nbrs.kneighbors(subset)
                
                # knn_indices contains indices within 'subset'. Need to map back to global df indices.
                # Also remove self-loop (first neighbor is self)
                for i, neighbors in enumerate(knn_indices):
                    src_node = indices[i]
                    for neighbor_local_idx in neighbors[1:]: # Skip self
                        dst_node = indices[neighbor_local_idx]
                        # Add undirected edge? Or directed? KNN is usually directed.
                        # Let's add directed for now.
                        edge_index_list.append(torch.tensor([[src_node], [dst_node]], dtype=torch.long))
        else:
            print("  Warning: Protocol column not found, skipping Protocol-aware KNN")

    # 2. SrcIP Temporal
    if 'src_ip' in strategy or 'hybrid' in strategy:
        print("  Constructing SrcIP Temporal edges...")
        # Group by Src IP, sort by time (already sorted globally, but need per-group)
        # Since df is sorted by time, groupby preserves order? Not guaranteed.
        # Let's iterate.
        # Faster: use shift
        # We want to connect row i to row j if same SrcIP and time diff < delta
        # Just connecting consecutive flows from same IP is a good approximation
        
        # Create a mapping of SrcIP -> list of indices
        # This might be slow in pure python. Use pandas.
        
        # Filter valid timestamps
        valid_time = df['Timestamp'].notna()
        
        # Group by SrcIP
        # We only connect t to t-1.
        grouped = df[valid_time].groupby('Src IP')
        
        src_nodes = []
        dst_nodes = []
        
        for ip, group in grouped:
            if len(group) < 2:
                continue
            
            # Get indices and timestamps
            indices = group.index.values
            times = group['Timestamp'].values
            
            # Vectorized check for time diff
            # diff in seconds
            time_diffs = (times[1:] - times[:-1]) / np.timedelta64(1, 's')
            
            # Find where diff < delta_t
            valid_links = time_diffs <= delta_t_seconds
            
            # Connect i+1 to i (flow of information from past to future? or bidirectional?)
            # Usually temporal graphs are directed: past -> future.
            # But GNNs propagate info.
            # Let's add edges: previous -> current
            
            from_idx = indices[:-1][valid_links]
            to_idx = indices[1:][valid_links]
            
            src_nodes.extend(from_idx)
            dst_nodes.extend(to_idx)
            
        if src_nodes:
            edge_index_list.append(torch.tensor([src_nodes, dst_nodes], dtype=torch.long))

    # 3. DstIP / DstPort (Shared Destination)
    if 'dst' in strategy or 'hybrid' in strategy:
        print("  Constructing DstIP/Port edges...")
        # Similar to SrcIP but for DstIP or DstPort
        # Connecting flows that share destination within time window
        # This can be dense. Let's restrict to "consecutive flows to same DstIP"
        
        grouped = df.groupby('Dst IP') # or Dst Port
        
        src_nodes = []
        dst_nodes = []
        
        for ip, group in grouped:
            if len(group) < 2:
                continue
            indices = group.index.values
            times = group['Timestamp'].values
            time_diffs = (times[1:] - times[:-1]) / np.timedelta64(1, 's')
            valid_links = time_diffs <= delta_t_seconds
            
            from_idx = indices[:-1][valid_links]
            to_idx = indices[1:][valid_links]
            
            src_nodes.extend(from_idx)
            dst_nodes.extend(to_idx)
            
        if src_nodes:
            edge_index_list.append(torch.tensor([src_nodes, dst_nodes], dtype=torch.long))

    # Combine edges
    if not edge_index_list:
        print("  Warning: No edges created! Returning empty edge_index.")
        edge_index = torch.empty((2, 0), dtype=torch.long)
    else:
        edge_index = torch.cat(edge_index_list, dim=1)
        # Remove duplicates
        edge_index = torch.unique(edge_index, dim=1)
        
    print(f"  Graph created: {x.shape[0]} nodes, {edge_index.shape[1]} edges")
    
    return Data(x=x, y=y, edge_index=edge_index)

# --- Model Definitions ---

class GNNClassifier(torch.nn.Module):
    def __init__(self, input_dim, hidden_dim, num_classes, num_layers=2, dropout=0.3, arch='sage'):
        super().__init__()
        self.dropout = dropout
        self.arch = arch
        self.layers = torch.nn.ModuleList()
        
        # Input layer
        if arch == 'sage':
            self.layers.append(SAGEConv(input_dim, hidden_dim))
        elif arch == 'gat':
            self.layers.append(GATConv(input_dim, hidden_dim, heads=1)) # Keep simple for now
            
        # Hidden layers
        for _ in range(num_layers - 2):
            if arch == 'sage':
                self.layers.append(SAGEConv(hidden_dim, hidden_dim))
            elif arch == 'gat':
                self.layers.append(GATConv(hidden_dim, hidden_dim, heads=1))
                
        # Output layer
        if num_layers > 1:
            if arch == 'sage':
                self.layers.append(SAGEConv(hidden_dim, num_classes))
            elif arch == 'gat':
                self.layers.append(GATConv(hidden_dim, num_classes, heads=1))
        else:
            # If 1 layer, we need to adjust (not handled here for simplicity, assuming >=2)
            pass

    def forward(self, x, edge_index):
        for i, layer in enumerate(self.layers):
            x = layer(x, edge_index)
            if i < len(self.layers) - 1:
                x = F.relu(x)
                x = F.dropout(x, p=self.dropout, training=self.training)
        return x # Logits

# --- Training & Evaluation ---

def train_gnn(model, data, train_mask, val_mask, epochs=100, lr=0.01, patience=10, class_weights=None):
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = torch.nn.CrossEntropyLoss(weight=class_weights)
    
    best_val_loss = float('inf')
    patience_counter = 0
    best_model_state = None
    
    history = {'train_loss': [], 'val_loss': []}
    
    for epoch in range(epochs):
        model.train()
        optimizer.zero_grad()
        out = model(data.x, data.edge_index)
        loss = criterion(out[train_mask], data.y[train_mask])
        loss.backward()
        optimizer.step()
        
        # Validation
        model.eval()
        with torch.no_grad():
            out_val = model(data.x, data.edge_index)
            val_loss = criterion(out_val[val_mask], data.y[val_mask])
            
        history['train_loss'].append(loss.item())
        history['val_loss'].append(val_loss.item())
        
        if epoch % 10 == 0:
            print(f"Epoch {epoch:03d}: Train Loss: {loss.item():.4f}, Val Loss: {val_loss.item():.4f}")
            
        # Early Stopping
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_model_state = model.state_dict()
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print(f"Early stopping at epoch {epoch}")
                break
                
    # Load best model
    if best_model_state:
        model.load_state_dict(best_model_state)
        
    return history

def evaluate_gnn(model, data, mask, label_encoder, is_binary_task=False):
    model.eval()
    with torch.no_grad():
        logits = model(data.x, data.edge_index)
        preds = logits.argmax(dim=1)
        
    y_true = data.y[mask].cpu().numpy()
    y_pred = preds[mask].cpu().numpy()
    
    # Metrics
    if is_binary_task:
        # Assuming 0=Normal, 1=Attack for binary task
        y_true_bin = y_true
        y_pred_bin = y_pred
    else:
        # Assuming 'Normal' is one of the classes.
        normal_idx = label_encoder.transform(['Normal'])[0]
        y_true_bin = (y_true != normal_idx).astype(int)
        y_pred_bin = (y_pred != normal_idx).astype(int)
    
    recall_attack = recall_score(y_true_bin, y_pred_bin, pos_label=1)
    
    # FPR (Normal) = FP / (FP + TN)
    # FP: True is Normal (0), Pred is Attack (1)
    tn, fp, fn, tp = confusion_matrix(y_true_bin, y_pred_bin, labels=[0, 1]).ravel()
    fpr_normal = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    f1 = f1_score(y_true_bin, y_pred_bin)
    
    # Multiclass Macro F1
    macro_f1 = f1_score(y_true, y_pred, average='macro')
    
    return {
        'recall_attack': recall_attack,
        'fpr_normal': fpr_normal,
        'f1_binary': f1,
        'macro_f1': macro_f1
    }

def plot_gnn_learning_curve(history, title, filename):
    """
    Plots training and validation loss curves.
    """
    plt.figure(figsize=(10, 6))
    plt.plot(history['train_loss'], label='Train Loss')
    plt.plot(history['val_loss'], label='Val Loss')
    plt.title(title)
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    plt.legend()
    plt.grid(True)
    plt.savefig(filename)
    plt.close()
    print(f"Saved plot to {filename}")


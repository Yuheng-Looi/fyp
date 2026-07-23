import sys
import time
import pandas as pd
import numpy as np
import torch
import threading
from torch_geometric.data import Data
from sklearn.neighbors import NearestNeighbors

sys.path.append('backend')
import gnn_utils

class KeepAlivePrinter:
    def __init__(self, interval=2):
        self.interval = interval
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._run)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.running = False

    def _run(self):
        while self.running:
            print("[Keep-Alive] Processing graph construction...", flush=True)
            time.sleep(self.interval)

def build_graph_fast(df, feature_cols, strategy='hybrid', k=5, delta_t_seconds=10):
    df = df.reset_index(drop=True)
    x = torch.tensor(df[feature_cols].values, dtype=torch.float)
    y = torch.tensor(df['Label_Encoded'].values, dtype=torch.long)
    
    src_nodes_list = []
    dst_nodes_list = []
    
    if 'knn' in strategy or 'hybrid' in strategy:
        if 'Protocol' in df.columns:
            protocols = df['Protocol'].unique()
            for p in protocols:
                indices = df.index[df['Protocol'] == p].values
                if len(indices) < k + 1:
                    continue
                subset = df.iloc[indices][feature_cols].values
                print(f"  Protocol {p}: fitting NearestNeighbors on {len(subset)} rows...", flush=True)
                
                # Start keep-alive printer
                printer = KeepAlivePrinter(interval=2)
                printer.start()
                
                nbrs = NearestNeighbors(n_neighbors=k+1, algorithm='ball_tree', n_jobs=-1).fit(subset)
                distances, knn_indices = nbrs.kneighbors(subset)
                
                printer.stop()
                
                neighbors_global = indices[knn_indices[:, 1:]]
                srcs = np.repeat(indices, k)
                dsts = neighbors_global.flatten()
                src_nodes_list.extend(srcs)
                dst_nodes_list.extend(dsts)
                
    if 'src_ip' in strategy or 'hybrid' in strategy:
        valid_time = df['Timestamp'].notna()
        grouped = df[valid_time].groupby('Src IP')
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
        src_nodes_list.extend(src_nodes)
        dst_nodes_list.extend(dst_nodes)
        
    if not src_nodes_list:
        edge_index = torch.empty((2, 0), dtype=torch.long)
    else:
        edge_index = torch.tensor([src_nodes_list, dst_nodes_list], dtype=torch.long)
        edge_index = torch.unique(edge_index, dim=1)
    return Data(x=x, y=y, edge_index=edge_index)

print("Loading data...", flush=True)
df, feats, le = gnn_utils.load_gnn_data(
    raw_folder='backend/datasets',
    cleaned_ref_path='backend/01eda/cleaned_data15.csv',
    encoder_path='backend/encoders/label_encoder.pkl'
)
t0 = time.time()
print("Building graph...", flush=True)
graph = build_graph_fast(df, feats, strategy='knn_protocol')
print('Graph building time:', time.time() - t0, flush=True)
print('Nodes:', graph.num_nodes, 'Edges:', graph.num_edges, flush=True)

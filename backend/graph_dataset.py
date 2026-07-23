import math
import json
import os
import torch
import numpy as np
from sklearn.preprocessing import StandardScaler
from torch.utils.data import Dataset
from torch_geometric.data import Data

class TopologyDataset(Dataset):
    def __init__(self, filepath, feature_dropout_prob=0.15):
        self.filepath = filepath
        self.feature_dropout_prob = feature_dropout_prob
        self.data_list = []
        self.load_and_process()

    def load_and_process(self):
        # Read JSONL file
        snapshots = []
        if not os.path.exists(self.filepath):
            print(f"[!] Warning: File {self.filepath} not found.")
            return

        with open(self.filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    snapshots.append(json.loads(line))
                except Exception as e:
                    print(f"Error loading JSON line: {e}")

        # Sort snapshots by timestamp to ensure chronological sequencing
        snapshots.sort(key=lambda s: s.get("timestamp", ""))

        # Group snapshots by iteration to track temporal features correctly
        iterations = {}
        for snap in snapshots:
            it = snap.get("iteration", 1)
            iterations.setdefault(it, []).append(snap)

        raw_graphs = []

        for it, snaps in sorted(iterations.items()):
            previous_neighbors = {} # Resets for each iteration to avoid temporal leakage

            for snap_idx, snap in enumerate(snaps):
                if snap_idx % 500 == 0:
                    print(f"      [loader] Parsing snapshot {snap_idx}/{len(snaps)} in iteration {it}...")
                
                # 1. Parse and collect all unique IP addresses in the snapshot
                node_set = set(n["id"] for n in snap.get("nodes", []))
                edges = snap.get("edges", [])
                for e in edges:
                    node_set.add(e["source"])
                    node_set.add(e["target"])
                
                nodes = sorted(list(node_set))
                num_nodes = len(nodes)
                if num_nodes == 0:
                    continue

                ip_to_idx = {ip: idx for idx, ip in enumerate(nodes)}

                # 2. Build continuous feature and discrete role matrices
                snap_continuous = np.zeros((num_nodes, 6), dtype=np.float32)
                snap_role = np.zeros((num_nodes, 3), dtype=np.float32)

                for idx, ip in enumerate(nodes):
                    # Filter incoming and outgoing edges for the current node IP
                    in_edges = [e for e in edges if e["target"] == ip]
                    out_edges = [e for e in edges if e["source"] == ip]
                    
                    in_deg = len(in_edges)
                    out_deg = len(out_edges)
                    
                    total_pkts = sum(e.get("weight_packets", 0.0) for e in in_edges + out_edges)
                    total_byts = sum(e.get("weight_bytes", 0.0) for e in in_edges + out_edges)
                    
                    log_pkts = np.log1p(total_pkts)
                    log_byts = np.log1p(total_byts)
                    
                    # Communication neighbors & weights
                    neighbor_weights = {}
                    for e in out_edges:
                        target_ip = e["target"]
                        neighbor_weights[target_ip] = neighbor_weights.get(target_ip, 0.0) + e.get("weight_packets", 0.0)
                    for e in in_edges:
                        source_ip = e["source"]
                        neighbor_weights[source_ip] = neighbor_weights.get(source_ip, 0.0) + e.get("weight_packets", 0.0)
                    
                    current_neigh = set(neighbor_weights.keys())
                    
                    # Compute communication entropy
                    entropy = 0.0
                    if total_pkts > 0.0:
                        for u_ip, w_u in neighbor_weights.items():
                            p_u = w_u / total_pkts
                            if p_u > 0.0:
                                entropy -= p_u * math.log(p_u)
                                
                    # Compute temporal feature (new neighbor count compared to previous snapshot)
                    if ip in previous_neighbors:
                        prev_neigh = previous_neighbors[ip]
                        new_neigh_cnt = len(current_neigh - prev_neigh)
                    else:
                        new_neigh_cnt = len(current_neigh)
                    
                    previous_neighbors[ip] = current_neigh
                    
                    # Assign computed continuous feature values
                    snap_continuous[idx] = [
                        float(in_deg),
                        float(out_deg),
                        float(log_pkts),
                        float(log_byts),
                        float(entropy),
                        float(new_neigh_cnt)
                    ]

                    # Node Role Embedding flags (IP-based role detection)
                    role = None
                    for n in snap.get("nodes", []):
                        if n.get("id") == ip:
                            role = n.get("role")
                            break

                    if role is not None:
                        is_web_port_80 = 1.0 if role == "web" else 0.0
                        is_db_port_3306 = 1.0 if role == "db" else 0.0
                    else:
                        is_web_port_80 = 1.0 if ip == "10.0.0.100" else 0.0
                        is_db_port_3306 = 1.0 if ip == "10.0.0.200" else 0.0

                    is_client = 1.0 if (is_web_port_80 == 0.0 and is_db_port_3306 == 0.0) else 0.0
                    
                    snap_role[idx] = [is_web_port_80, is_db_port_3306, is_client]

                # 3. Build edge index matrix
                edge_index_list = []
                for e in edges:
                    src_ip = e["source"]
                    dst_ip = e["target"]
                    if src_ip in ip_to_idx and dst_ip in ip_to_idx:
                        edge_index_list.append([ip_to_idx[src_ip], ip_to_idx[dst_ip]])
                
                # 4. Get label and iteration
                label = snap.get("label")
                if label is None:
                    continue # Skip unlabeled snapshots
                
                raw_graphs.append({
                    "continuous": snap_continuous,
                    "role": snap_role,
                    "edge_index_list": edge_index_list,
                    "y": int(label),
                    "iteration": it
                })

        print(f"[loader] Completed parsing. Loaded {len(raw_graphs)} graphs. Scaling features...")

        # 5. Fit StandardScaler strictly on the training partition and scale features globally
        if len(raw_graphs) > 0:
            # Extract training iteration continuous features to prevent test set leakage
            train_continuous_list = [g["continuous"] for g in raw_graphs if g["iteration"] == 1]
            if len(train_continuous_list) > 0:
                train_continuous = np.concatenate(train_continuous_list, axis=0)
            else:
                train_continuous = np.concatenate([g["continuous"] for g in raw_graphs], axis=0)
                
            scaler = StandardScaler()
            scaler.fit(train_continuous)
            
            # Scale continuous features and construct final node features X before converting to tensors
            for g in raw_graphs:
                scaled_continuous = scaler.transform(g["continuous"])
                
                # Concatenate scaled features and role embeddings along feature dimension (resulting in 9 inputs)
                X_np = np.concatenate([scaled_continuous, g["role"]], axis=1)
                
                # Convert to tensors
                X_tensor = torch.tensor(X_np, dtype=torch.float)
                
                if g["edge_index_list"]:
                    edge_index = torch.tensor(g["edge_index_list"], dtype=torch.long).t().contiguous()
                else:
                    edge_index = torch.empty((2, 0), dtype=torch.long)
                    
                y = torch.tensor([g["y"]], dtype=torch.long)
                
                # Construct PyG Data object
                pyg_data = Data(x=X_tensor, edge_index=edge_index, y=y)
                pyg_data.iteration = g["iteration"]
                
                self.data_list.append(pyg_data)

    def __len__(self):
        return len(self.data_list)

    def __getitem__(self, idx):
        data = self.data_list[idx].clone()
        # Apply feature dropout: randomly zero out role embeddings (is_web, is_db, is_client)
        # with 15% probability per node during training step (runs 1-20 / iteration <= 20)
        if self.feature_dropout_prob > 0.0 and getattr(data, "iteration", 1) <= 20:
            num_nodes = data.x.size(0)
            for i in range(num_nodes):
                if torch.rand(1).item() < self.feature_dropout_prob:
                    data.x[i, 6] = 0.0
                    data.x[i, 7] = 0.0
                    data.x[i, 8] = 0.0
        return data

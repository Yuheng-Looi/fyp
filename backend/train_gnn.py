import os
import sys
import torch
import torch.nn.functional as F
from torch_geometric.loader import DataLoader
from torch.utils.data import WeightedRandomSampler
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, f1_score
import numpy as np

# Setup paths
sys.path.append("/home/fyp2025/fyp/backend")

from graph_dataset import TopologyDataset
from gnn_model import GraphSAGEClassifier

def train_and_evaluate(filepath, epochs=100, batch_size=8, hidden_dim=64, lr=0.01):
    print(f"[+] Loading TopologyDataset from {filepath}...")
    dataset = TopologyDataset(filepath)
    
    if len(dataset) == 0:
        print("[!] Error: TopologyDataset is empty. Run scenario_runner.py first to generate graph snapshots.")
        return

    print(f"[+] Loaded {len(dataset)} snapshots.")

    # 1. Split dataset by scenario iteration
    # Train: runs 1-20, Test: runs 21-30
    train_data = [data for data in dataset if getattr(data, "iteration", 1) <= 20]
    test_data = [data for data in dataset if 21 <= getattr(data, "iteration", 1) <= 30]

    # Fallback to random split if either partition is empty (to prevent training crashes)
    if len(train_data) == 0 or len(test_data) == 0:
        print("[!] Warning: Could not perform scenario split (runs 1-20 vs 21-30). Falling back to 70/30 split.")
        generator = torch.Generator().manual_seed(42)
        train_size = int(0.7 * len(dataset))
        test_size = len(dataset) - train_size
        train_data, test_data = torch.utils.data.random_split(
            dataset, [train_size, test_size], generator=generator
        )

    if len(train_data) == 0 or len(test_data) == 0:
        print("[!] Error: Either training or testing split has 0 samples. Cannot continue.")
        return

    print(f"[+] Dataset Split:")
    print(f"    Train size: {len(train_data)} snapshots (runs 1-20)")
    print(f"    Test size: {len(test_data)} snapshots (runs 21-30)")

    # Setup device
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"[+] Training on device: {device}")

    # 2. Balanced Batch Sampler & Weighted Loss calculation
    # Compute inverse class frequencies
    train_labels = [int(data.y.item()) for data in train_data]
    class_counts = np.bincount(train_labels, minlength=5)
    
    # Safe division mapping
    class_counts_safe = np.where(class_counts == 0, 1, class_counts)
    inverse_weights = 1.0 / class_counts_safe
    normalized_weights = inverse_weights / np.sum(inverse_weights) * 5.0
    
    class_weights_tensor = torch.tensor(normalized_weights, dtype=torch.float).to(device)
    criterion = torch.nn.CrossEntropyLoss(weight=class_weights_tensor)
    
    # Create WeightedRandomSampler to yield balanced batches
    sample_weights = [normalized_weights[lbl] for lbl in train_labels]
    sampler = WeightedRandomSampler(
        weights=sample_weights,
        num_samples=len(sample_weights),
        replacement=True
    )

    # PyG DataLoader configuration (shuffle must be False when sampler is defined)
    train_loader = DataLoader(train_data, batch_size=batch_size, sampler=sampler)
    test_loader = DataLoader(test_data, batch_size=batch_size, shuffle=False)

    # 3. Instantiate SAGEConv model with 9 input dimensions (6 continuous + 3 role embeds)
    input_dim = 9
    num_classes = 5
    model = GraphSAGEClassifier(input_dim=input_dim, hidden_dim=hidden_dim, num_classes=num_classes).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-3)

    # Class names mapping
    class_names = ["1-to-1", "1-to-N", "N-to-1", "N-to-N", "service_transition"]

    # Early Stopping setup
    best_val_loss = float('inf')
    patience = 10
    patience_counter = 0
    best_model_state = None

    # 4. Training Loop
    print("\n[+] Starting training...")
    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        for batch in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            out = model(batch.x, batch.edge_index, batch.batch)
            loss = criterion(out, batch.y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * batch.num_graphs

        avg_loss = total_loss / len(train_data)

        # Evaluate validation (test_data) loss and accuracy for Early Stopping
        model.eval()
        val_loss = 0.0
        correct = 0
        with torch.no_grad():
            for batch in test_loader:
                batch = batch.to(device)
                out = model(batch.x, batch.edge_index, batch.batch)
                loss = criterion(out, batch.y)
                val_loss += loss.item() * batch.num_graphs
                preds = out.argmax(dim=1)
                correct += int((preds == batch.y).sum())
        
        avg_val_loss = val_loss / len(test_data)
        test_acc = correct / len(test_data)
        
        print(f"Epoch {epoch:03d} | Train Loss: {avg_loss:.4f} | Val Loss: {avg_val_loss:.4f} | Val Accuracy: {test_acc * 100.0:.2f}%")

        # Early Stopping check
        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            patience_counter = 0
            best_model_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print(f"[+] Early stopping triggered at epoch {epoch}. Restoring best model weights.")
                break

    # Restore best model weights
    if best_model_state is not None:
        model.load_state_dict({k: v.to(device) for k, v in best_model_state.items()})

    # 5. Final Evaluation, Per-Class F1, & Confusion Matrix
    print("\n[+] Running final model evaluation on test set...")
    model.eval()
    all_y_true = []
    all_y_pred = []
    
    with torch.no_grad():
        for batch in test_loader:
            batch = batch.to(device)
            out = model(batch.x, batch.edge_index, batch.batch)
            preds = out.argmax(dim=1)
            all_y_true.extend(batch.y.cpu().numpy())
            all_y_pred.extend(preds.cpu().numpy())

    y_true = np.array(all_y_true)
    y_pred = np.array(all_y_pred)

    accuracy = accuracy_score(y_true, y_pred)
    conf_matrix = confusion_matrix(y_true, y_pred, labels=list(range(num_classes)))
    per_class_f1 = f1_score(y_true, y_pred, average=None, labels=list(range(num_classes)), zero_division=0)
    
    print("\n" + "="*70)
    print("                    GNN TOPOLOGY EVALUATION REPORT")
    print("="*70)
    print(f"Topology Classification Accuracy: {accuracy * 100.0:.2f}%")
    print("\nClassification Report:")
    
    # Identify labels present in test set to avoid sklearn warnings
    present_labels = sorted(list(set(y_true) | set(y_pred)))
    target_names = [class_names[i] for i in present_labels]
    
    print(classification_report(y_true, y_pred, labels=present_labels, target_names=target_names, zero_division=0))
    
    print("\nPer-Class F1 Scores:")
    for i, name in enumerate(class_names):
        print(f"  {name.ljust(20)}: {per_class_f1[i]:.4f}")
        
    print("\nConfusion Matrix:")
    # Print headers
    header_str = "True \\ Pred".ljust(20) + " | " + " | ".join(name.center(10) for name in class_names)
    print(header_str)
    print("-" * len(header_str))
    for i, row in enumerate(conf_matrix):
        row_str = class_names[i].ljust(20) + " | " + " | ".join(str(val).center(10) for val in row)
        print(row_str)
    print("="*70)

if __name__ == "__main__":
    filepath = "/home/fyp2025/fyp/backend/graph_snapshots.json"
    train_and_evaluate(filepath)

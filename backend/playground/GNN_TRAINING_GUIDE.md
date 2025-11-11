# GNN Training Guide

## Overview
This guide explains the Graph Neural Network (GNN) training pipeline implemented in `gnn_train.ipynb` and `gnn_utils.py`.

## Quick Start

### 1. Run the Training Pipeline
Open `gnn_train.ipynb` and run all cells in the GNN Training Pipeline section. The pipeline will:
- Load balanced CTGAN data
- Preprocess with RobustScaler
- Build k-NN graph (k=5)
- Train 6 models (2 architectures × 3 splits)
- Save all models and visualizations

### 2. Expected Runtime
- **With GPU**: ~15-30 minutes for all 6 models
- **Without GPU**: ~45-90 minutes (depends on CPU)

### 3. Output Files
After training completes, you'll have:
```
playground/
├── models/
│   ├── gnn_graphsage_70_15_15.pt
│   ├── gnn_graphsage_50_25_25.pt
│   ├── gnn_graphsage_20_40_40.pt
│   ├── gnn_gat_70_15_15.pt
│   ├── gnn_gat_50_25_25.pt
│   ├── gnn_gat_20_40_40.pt
│   ├── gnn_training_curves.png
│   ├── gnn_model_comparison.png
│   └── gnn_f1_heatmap.png
└── scalers/
    └── gnn_scaler.pkl
```

## Architecture Details

### GraphSAGE Model
- **Aggregation**: Mean pooling
- **Layers**: 2 SAGEConv layers
- **Hidden dim**: 128
- **Dropout**: 0.3
- **Best for**: General graph learning, stable training

### GAT Model
- **Attention**: Multi-head (4 heads)
- **Layers**: 2 GATConv layers
- **Hidden dim**: 128
- **Dropout**: 0.3
- **Best for**: Learning complex neighbor relationships

## Training Configuration

### Data Splits Tested
1. **70/15/15**: Maximum training data, standard split
2. **50/25/25**: Balanced val/test for robust evaluation
3. **20/40/40**: Small train set, tests generalization

### Hyperparameters
- **Optimizer**: Adam (lr=1e-3, weight_decay=5e-4)
- **Loss**: Weighted CrossEntropy (inverse class frequency)
- **Batch**: Full batch (all nodes)
- **Max epochs**: 200
- **Early stopping**: Patience 20 (validation loss)
- **k-NN**: k=5 neighbors

### Graph Construction
- **Nodes**: Each network flow
- **Edges**: k-NN connections in feature space
- **Metric**: Euclidean distance
- **Average degree**: ~5 (bidirectional: ~10)

## Functions in gnn_utils.py

### Data Processing
```python
load_and_preprocess_gnn_data(csv_paths, scaler_path, fit_scaler=True)
# Load CSVs, encode labels, scale features, save/load scaler
```

### Graph Building
```python
build_knn_graph(X, k=5, metric='euclidean')
# Create k-NN graph from feature matrix
```

### Training
```python
train_gnn_with_early_stopping(model, data, optimizer, criterion, device, 
                               num_epochs=200, patience=20)
# Train with early stopping, returns best model and history
```

### Evaluation
```python
evaluate_gnn(model, data, mask, device)
# Compute accuracy, precision, recall, F1, predictions
```

```python
print_detailed_metrics(metrics, label_encoder, split_name)
# Print per-class metrics and confusion matrix
```

### Model Classes
```python
GraphSAGEModel(num_features, hidden_dim=128, num_classes, dropout=0.3)
GATModel(num_features, hidden_dim=128, num_classes, dropout=0.3, heads=4)
```

## How to Use Trained Models

### Loading a Model
```python
import torch
import joblib
from gnn_utils import GraphSAGEModel, GATModel

# Load scaler
scaler = joblib.load('scalers/gnn_scaler.pkl')

# Load model checkpoint
checkpoint = torch.load('models/gnn_graphsage_70_15_15.pt')
metadata = checkpoint['metadata']

# Initialize model with same architecture
model = GraphSAGEModel(
    num_features=metadata['num_features'],
    hidden_dim=metadata['hidden_dim'],
    num_classes=metadata['num_classes'],
    dropout=metadata['dropout']
)

# Load weights
model.load_state_dict(checkpoint['model_state_dict'])
model.eval()
```

### Inference on New Data
```python
import numpy as np
from gnn_utils import build_knn_graph, create_pyg_data

# 1. Load and preprocess new data
X_new = pd.read_csv('new_traffic.csv').drop(columns=['Label'])
X_new_scaled = scaler.transform(X_new.values)

# 2. Build graph
edge_index = build_knn_graph(X_new_scaled, k=5)

# 3. Create data object (dummy labels and masks for inference)
data = create_pyg_data(
    X_new_scaled, 
    np.zeros(len(X_new)),  # dummy labels
    edge_index,
    np.ones(len(X_new), dtype=bool),  # all nodes for inference
    np.zeros(len(X_new), dtype=bool),
    np.zeros(len(X_new), dtype=bool)
)

# 4. Run inference
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
data = data.to(device)
model = model.to(device)

with torch.no_grad():
    out = model(data.x, data.edge_index)
    predictions = out.argmax(dim=1).cpu().numpy()

# predictions[i] = predicted class for flow i
```

## Interpreting Results

### Metrics Explained
- **Accuracy**: Overall correct predictions (good for balanced data)
- **Precision**: Of predicted attacks, how many are real? (low FP)
- **Recall**: Of real attacks, how many are detected? (low FN)
- **F1 Score**: Harmonic mean of precision and recall (balanced metric)

### Which Model to Choose?
1. **Highest F1**: Best overall performance
2. **Highest Recall**: Minimize missed attacks (security critical)
3. **Highest Precision**: Minimize false alarms (operational)

### Confusion Matrix Reading
```
              Predicted
            0    1    2   ...
True    0 [TN] [FP] [FP]
        1 [FN] [TP] [FP]
        2 [FN] [FP] [TP]
        ...
```
- Diagonal = correct predictions
- Off-diagonal = errors

## Troubleshooting

### CUDA Out of Memory
Reduce batch size or use CPU:
```python
device = torch.device('cpu')
```

### Poor Performance
1. Check CTGAN quality (run quality checks first)
2. Try different k values (k=3, k=7, k=10)
3. Increase hidden_dim (256, 512)
4. More epochs or adjust learning rate
5. Different graph construction (weighted edges, mutual k-NN)

### Training Too Slow
1. Reduce dataset size (sample)
2. Reduce k (fewer edges)
3. Reduce hidden_dim
4. Use GraphSAGE (faster than GAT)

## Advanced Usage

### Custom Model Configuration
```python
# Deeper model
model = GraphSAGEModel(
    num_features=20,
    hidden_dim=256,
    num_classes=5,
    dropout=0.4,
    num_layers=3  # add more layers
)

# More attention heads
model = GATModel(
    num_features=20,
    hidden_dim=128,
    num_classes=5,
    dropout=0.3,
    heads=8  # more heads
)
```

### Different Data Splits
```python
# Custom split (80/10/10)
train_ratio, val_ratio, test_ratio = 0.8, 0.1, 0.1
# ... create masks accordingly
```

### Weighted Loss Customization
```python
# Manual class weights
class_weights = torch.tensor([0.5, 2.0, 3.0, 1.5, 1.0])  # custom weights
criterion = nn.CrossEntropyLoss(weight=class_weights.to(device))
```

## References
- GraphSAGE: Hamilton et al., "Inductive Representation Learning on Large Graphs" (2017)
- GAT: Veličković et al., "Graph Attention Networks" (2018)
- PyTorch Geometric: https://pytorch-geometric.readthedocs.io/

## Next Steps
1. Integrate best model into production pipeline
2. Set up continuous monitoring
3. Implement online learning for drift adaptation
4. Deploy with FastAPI or Flask for real-time inference

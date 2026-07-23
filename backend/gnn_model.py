import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv, global_mean_pool

class GraphSAGEClassifier(torch.nn.Module):
    """
    GraphSAGE model for graph-level classification.
    Architecture: Node Features -> SAGEConv -> ReLU -> SAGEConv -> global_mean_pool -> Linear (MLP) -> Softmax (5 classes)
    """
    def __init__(self, input_dim, hidden_dim, num_classes, dropout_prob=0.25):
        super(GraphSAGEClassifier, self).__init__()
        self.conv1 = SAGEConv(input_dim, hidden_dim)
        self.conv2 = SAGEConv(hidden_dim, hidden_dim)
        self.dropout = nn.Dropout(dropout_prob)
        self.fc = nn.Linear(hidden_dim, num_classes)

    def forward(self, x, edge_index, batch):
        # 1. First SAGEConv layer
        x = self.conv1(x, edge_index)
        
        # 2. ReLU activation followed by Dropout
        x = F.relu(x)
        x = self.dropout(x)
        
        # 3. Second SAGEConv layer
        x = self.conv2(x, edge_index)
        
        # 4. Global mean pooling (aggregates node features to graph-level features)
        x = global_mean_pool(x, batch)
        
        # 5. Output linear layer (MLP logits)
        logits = self.fc(x)
        
        # Note: PyTorch CrossEntropyLoss expects raw logits, so we return logits.
        # During evaluation we can apply F.softmax.
        return logits

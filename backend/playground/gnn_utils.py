"""
Utility functions for GNN training and CTGAN synthetic data generation.
This module contains helper functions for data preprocessing, synthetic data generation,
and quality assessment for network intrusion detection datasets.
"""

import pandas as pd
import numpy as np
import os
import gc
from datetime import datetime
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import mean_squared_error, mean_absolute_error
from scipy.spatial.distance import jensenshannon
import matplotlib.pyplot as plt
import seaborn as sns


def calculate_target_samples(data, balance_strategy='moderate'):
    """
    Calculate target sample sizes for each class based on the balance strategy.
    
    This function determines how many samples each class should have to create
    a balanced dataset. Three strategies are available:
    - 'aggressive': All classes equal to median size
    - 'moderate': Reduce majority by 25%, increase minority to 50% of reduced majority
    - 'conservative': Only increase minority to 25% of majority class
    
    Args:
        data (pd.DataFrame): DataFrame containing the data with 'Label' column
        balance_strategy (str): Strategy for balancing - 'aggressive', 'moderate', or 'conservative'
    
    Returns:
        dict: Dictionary mapping label to target sample size
    
    Example:
        >>> target_samples = calculate_target_samples(df, balance_strategy='moderate')
        >>> print(target_samples)
        {0: 50000, 1: 25000, 2: 25000}
    """
    label_counts = data['Label'].value_counts()
    median_count = label_counts.median()
    max_count = label_counts.max()
    
    target_samples = {}
    
    if balance_strategy == 'aggressive':
        # Make all classes equal to median size
        target_size = int(median_count)
        target_samples = {label: target_size for label in label_counts.index}
        
    elif balance_strategy == 'moderate':
        # Reduce majority classes to 75% of original, increase minority to 50% of that
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
        # Only increase minority classes to 25% of majority class
        minority_target = int(max_count * 0.25)
        
        for label in label_counts.index:
            if label_counts[label] < minority_target:
                target_samples[label] = minority_target
            else:
                target_samples[label] = label_counts[label]
    
    return target_samples


def calculate_synthetic_quality_metrics(original_data, synthetic_data, numerical_columns):
    """
    Calculate quality metrics comparing original and synthetic data distributions.
    
    This function computes various statistical metrics to assess how well the synthetic
    data matches the original data distribution. Lower values indicate better quality.
    
    Metrics calculated:
    - Mean Absolute Error (MAE): Average absolute difference in feature means
    - Mean Squared Error (MSE): Average squared difference in feature means
    - Jensen-Shannon Divergence: Distribution similarity (0 = identical, 1 = completely different)
    
    Args:
        original_data (pd.DataFrame): Original real data
        synthetic_data (pd.DataFrame): Generated synthetic data
        numerical_columns (list): List of numerical column names to compare
    
    Returns:
        dict: Dictionary containing quality metrics:
            - 'mae_mean': Mean Absolute Error of feature means
            - 'mse_mean': Mean Squared Error of feature means
            - 'js_divergence': Average Jensen-Shannon divergence across features
            - 'feature_correlation_diff': Difference in correlation matrices
    
    Example:
        >>> metrics = calculate_synthetic_quality_metrics(orig_df, synth_df, num_cols)
        >>> print(f"Quality Score (JS): {metrics['js_divergence']:.4f}")
    """
    metrics = {}
    
    # Calculate mean and std for each numerical feature
    orig_means = original_data[numerical_columns].mean()
    synth_means = synthetic_data[numerical_columns].mean()
    
    orig_stds = original_data[numerical_columns].std()
    synth_stds = synthetic_data[numerical_columns].std()
    
    # Mean Absolute Error for means
    metrics['mae_mean'] = mean_absolute_error(orig_means, synth_means)
    
    # Mean Squared Error for means
    metrics['mse_mean'] = mean_squared_error(orig_means, synth_means)
    
    # Jensen-Shannon divergence for distributions
    js_scores = []
    for col in numerical_columns:
        # Create histograms with same bins
        orig_hist, bins = np.histogram(original_data[col], bins=50, density=True)
        synth_hist, _ = np.histogram(synthetic_data[col], bins=bins, density=True)
        
        # Add small epsilon to avoid division by zero
        orig_hist = orig_hist + 1e-10
        synth_hist = synth_hist + 1e-10
        
        # Normalize to probability distributions
        orig_hist = orig_hist / orig_hist.sum()
        synth_hist = synth_hist / synth_hist.sum()
        
        # Calculate JS divergence
        js_score = jensenshannon(orig_hist, synth_hist)
        js_scores.append(js_score)
    
    metrics['js_divergence'] = np.mean(js_scores)
    
    # Correlation difference
    orig_corr = original_data[numerical_columns].corr()
    synth_corr = synthetic_data[numerical_columns].corr()
    metrics['feature_correlation_diff'] = np.abs(orig_corr - synth_corr).mean().mean()
    
    return metrics


def print_quality_report(original_data, synthetic_data, label_value, numerical_columns):
    """
    Print a comprehensive quality report comparing original and synthetic data.
    
    This function generates a detailed report showing:
    - Sample counts comparison
    - Statistical quality metrics
    - Feature-level statistics comparison
    - Data quality assessment
    
    Args:
        original_data (pd.DataFrame): Original real data for specific label
        synthetic_data (pd.DataFrame): Generated synthetic data for specific label
        label_value: Label value being analyzed
        numerical_columns (list): List of numerical column names
    
    Returns:
        None: Prints report to console
    
    Example:
        >>> print_quality_report(orig_subset, synth_subset, label=1, num_cols=features)
    """
    print(f"\n{'='*80}")
    print(f"QUALITY REPORT FOR LABEL {label_value}")
    print(f"{'='*80}")
    
    print(f"\nSample Counts:")
    print(f"  Original samples: {len(original_data):,}")
    print(f"  Synthetic samples: {len(synthetic_data):,}")
    print(f"  Total samples: {len(original_data) + len(synthetic_data):,}")
    
    # Calculate quality metrics
    metrics = calculate_synthetic_quality_metrics(original_data, synthetic_data, numerical_columns)
    
    print(f"\nQuality Metrics:")
    print(f"  Mean Absolute Error (MAE):        {metrics['mae_mean']:.6f}")
    print(f"  Mean Squared Error (MSE):         {metrics['mse_mean']:.6f}")
    print(f"  Jensen-Shannon Divergence:        {metrics['js_divergence']:.6f}")
    print(f"  Feature Correlation Difference:   {metrics['feature_correlation_diff']:.6f}")
    
    # Quality assessment
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
    print(f"  (JS Divergence < 0.1 = Excellent, < 0.2 = Good, < 0.3 = Acceptable)")
    
    # Show sample statistics for a few key features
    print(f"\nFeature Statistics Comparison (first 5 features):")
    print(f"{'Feature':<30} {'Orig Mean':<12} {'Synth Mean':<12} {'Diff %':<10}")
    print(f"{'-'*70}")
    
    for col in numerical_columns[:5]:
        orig_mean = original_data[col].mean()
        synth_mean = synthetic_data[col].mean()
        diff_pct = ((synth_mean - orig_mean) / orig_mean * 100) if orig_mean != 0 else 0
        print(f"{col:<30} {orig_mean:<12.4f} {synth_mean:<12.4f} {diff_pct:>+9.2f}%")


def train_and_generate_ctgan(data, feature_count, subset_label=None, target_size=None, epochs=300):
    """
    Train a CTGAN model and generate synthetic data for balancing datasets.
    
    This function trains a Conditional Tabular GAN on network flow data to generate
    synthetic samples for minority classes or undersample majority classes. It includes:
    - Data scaling and preprocessing
    - CTGAN model training with optimized hyperparameters
    - Synthetic data generation
    - Quality assessment and reporting
    - Model checkpointing
    
    The function handles both oversampling (generating new samples) and undersampling
    (reducing samples) based on the target_size parameter.
    
    Args:
        data (pd.DataFrame): DataFrame containing the training data
        feature_count (int): Number of features in the dataset (52 or 20)
        subset_label (int, optional): Specific label to generate data for. If None, uses all data
        target_size (int, optional): Target number of samples for the class
        epochs (int, optional): Number of training epochs. Default is 300
    
    Returns:
        pd.DataFrame or None: Combined original and synthetic data, or None if error occurs
    
    Example:
        >>> balanced_data = train_and_generate_ctgan(
        ...     df, 
        ...     feature_count=20, 
        ...     subset_label=1, 
        ...     target_size=50000,
        ...     epochs=300
        ... )
    
    Note:
        - For undersampling (target_size < current size), returns random sample without training
        - Saves trained model to 'checkpoints/ctgan/ctgan_{feature_count}_label_{label}.pkl'
        - Prints quality metrics comparing synthetic to original data
    """
    from ctgan import CTGAN
    
    # Filter data if subset_label is provided
    if subset_label is not None:
        data_subset = data[data['Label'] == subset_label].copy()
    else:
        data_subset = data.copy()
        
    if len(data_subset) == 0:
        print(f"❌ No samples found for label {subset_label}")
        return None
    
    print(f"\n{'='*80}")
    print(f"TRAINING CTGAN - {feature_count} features, Label {subset_label}")
    print(f"{'='*80}")
    print(f"Original samples: {len(data_subset):,}")
    print(f"Target samples: {target_size:,}")
    
    # Check if we need to undersample
    if target_size is not None and target_size < len(data_subset):
        print(f"\n⚠️  Undersampling from {len(data_subset):,} to {target_size:,} samples")
        sampled_data = data_subset.sample(n=target_size, random_state=42)
        print(f"✓ Undersampling complete")
        return sampled_data
    
    # Identify column types
    columns = data_subset.columns.tolist()
    categorical_columns = ['Protocol', 'Label'] if 'Protocol' in columns else ['Label']
    numerical_columns = [col for col in columns if col not in categorical_columns]
    
    print(f"\nFeature types:")
    print(f"  Numerical features: {len(numerical_columns)}")
    print(f"  Categorical features: {len(categorical_columns)}")
    
    # Scale numerical columns to [0, 1] range for better CTGAN performance
    scaler = MinMaxScaler()
    data_scaled = data_subset.copy()
    data_scaled[numerical_columns] = scaler.fit_transform(data_subset[numerical_columns])
    
    # Initialize CTGAN with optimized parameters
    print(f"\n🔧 Initializing CTGAN model...")
    ctgan = CTGAN(
        epochs=epochs,
        batch_size=500,
        generator_dim=(256, 256),
        discriminator_dim=(256, 256),
        generator_lr=2e-4,
        discriminator_lr=2e-4,
        verbose=True
    )
    
    # Train the model
    print(f"\n🚀 Training CTGAN for {epochs} epochs...")
    try:
        ctgan.fit(data_scaled, discrete_columns=categorical_columns)
        print(f"✓ Training complete")
        
    except Exception as e:
        print(f"❌ Error during training: {str(e)}")
        import traceback
        traceback.print_exc()
        return None
    
    # Calculate number of samples to generate
    sample_size = target_size - len(data_subset) if target_size else len(data_subset)
    
    if sample_size <= 0:
        print(f"\n⚠️  No synthetic samples needed (target already met)")
        return data_subset
    
    print(f"\n🎲 Generating {sample_size:,} synthetic samples...")
    try:
        synthetic_data = ctgan.sample(sample_size)
        print(f"✓ Generation complete")
        
    except Exception as e:
        print(f"❌ Error during generation: {str(e)}")
        import traceback
        traceback.print_exc()
        return None
    
    # Inverse transform the scaled features
    synthetic_data_unscaled = synthetic_data.copy()
    synthetic_data_unscaled[numerical_columns] = scaler.inverse_transform(synthetic_data[numerical_columns])
    
    # Ensure label column matches if generating for specific label
    if subset_label is not None:
        synthetic_data_unscaled['Label'] = subset_label
    
    # Print quality report
    print_quality_report(data_subset, synthetic_data_unscaled, subset_label, numerical_columns)
    
    # Combine original and synthetic data
    final_data = pd.concat([data_subset, synthetic_data_unscaled], ignore_index=True)
    print(f"\n✓ Final dataset size: {len(final_data):,} samples")
    
    # Save the model
    model_path = f'checkpoints/ctgan/ctgan_{feature_count}'
    model_path += f'_label_{subset_label}' if subset_label is not None else ''
    model_path += '.pkl'
    
    try:
        ctgan.save(model_path)
        print(f"💾 Model saved to: {model_path}")
    except Exception as e:
        print(f"⚠️  Warning: Could not save model: {str(e)}")
    
    return final_data


def plot_label_distribution_comparison(original_data, balanced_data, title="Label Distribution"):
    """
    Plot comparison of label distributions before and after balancing.
    
    Creates a bar chart showing the number of samples per label in both
    original and balanced datasets for visual comparison.
    
    Args:
        original_data (pd.DataFrame): Original unbalanced data
        balanced_data (pd.DataFrame): Balanced data after CTGAN processing
        title (str, optional): Plot title. Default is "Label Distribution"
    
    Returns:
        None: Displays matplotlib plot
    
    Example:
        >>> plot_label_distribution_comparison(df_original, df_balanced)
    """
    plt.figure(figsize=(12, 6))
    
    # Get label counts
    orig_counts = original_data['Label'].value_counts().sort_index()
    balanced_counts = balanced_data['Label'].value_counts().sort_index()
    
    # Get all unique labels
    all_labels = sorted(set(orig_counts.index) | set(balanced_counts.index))
    
    # Set up bar positions
    x = np.arange(len(all_labels))
    width = 0.35
    
    # Plot bars
    plt.bar(x - width/2, [orig_counts.get(label, 0) for label in all_labels], 
            width, label='Original', color='skyblue', alpha=0.8)
    plt.bar(x + width/2, [balanced_counts.get(label, 0) for label in all_labels], 
            width, label='Balanced', color='lightgreen', alpha=0.8)
    
    # Customize plot
    plt.title(title, fontsize=14, fontweight='bold', pad=20)
    plt.xlabel('Label', fontsize=12)
    plt.ylabel('Number of Samples', fontsize=12)
    plt.xticks(x, all_labels, rotation=45, ha='right')
    plt.legend(fontsize=11)
    plt.grid(True, alpha=0.3, axis='y')
    
    # Add value labels on bars
    for i, label in enumerate(all_labels):
        orig_val = orig_counts.get(label, 0)
        balanced_val = balanced_counts.get(label, 0)
        
        plt.text(i - width/2, orig_val, f'{orig_val:,}', 
                ha='center', va='bottom', fontsize=9)
        plt.text(i + width/2, balanced_val, f'{balanced_val:,}', 
                ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    plt.show()


def print_dataset_summary(data, dataset_name="Dataset"):
    """
    Print a comprehensive summary of dataset statistics.
    
    Displays label distribution, class imbalance ratios, and basic statistics
    for understanding the dataset composition.
    
    Args:
        data (pd.DataFrame): Dataset to analyze
        dataset_name (str, optional): Name to display in report. Default is "Dataset"
    
    Returns:
        None: Prints summary to console
    
    Example:
        >>> print_dataset_summary(df, dataset_name="Training Data (52 features)")
    """
    print(f"\n{'='*80}")
    print(f"{dataset_name.upper()} SUMMARY")
    print(f"{'='*80}")
    
    print(f"\nTotal samples: {len(data):,}")
    print(f"Total features: {len(data.columns) - 1}")  # -1 for Label column
    
    label_counts = data['Label'].value_counts().sort_index()
    max_count = label_counts.max()
    min_count = label_counts.min()
    
    print(f"\nLabel Distribution:")
    print(f"{'Label':<10} {'Count':<12} {'Percentage':<12} {'Imbalance Ratio':<15}")
    print(f"{'-'*55}")
    
    for label, count in label_counts.items():
        percentage = (count / len(data)) * 100
        ratio = max_count / count if count > 0 else float('inf')
        print(f"{label:<10} {count:<12,} {percentage:<11.2f}% {ratio:<14.2f}x")
    
    print(f"\nImbalance Statistics:")
    print(f"  Majority class size: {max_count:,}")
    print(f"  Minority class size: {min_count:,}")
    print(f"  Imbalance ratio: {max_count/min_count:.2f}:1")


# ======================== GNN Training Utilities ========================

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Data
from torch_geometric.nn import SAGEConv, GATConv, global_mean_pool
from sklearn.preprocessing import RobustScaler, LabelEncoder
from sklearn.neighbors import NearestNeighbors
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import joblib
from collections import Counter
import copy


def load_and_preprocess_gnn_data(csv_paths, scaler_path='scalers/gnn_scaler.pkl', fit_scaler=True):
    """
    Load and preprocess CSV files for GNN training.
    
    This function loads one or more CSV files, encodes labels, applies RobustScaler
    to numerical features, and saves/loads the scaler for consistent preprocessing.
    
    Args:
        csv_paths (str or list): Single path or list of paths to CSV files
        scaler_path (str): Path to save/load the scaler. Default: 'scalers/gnn_scaler.pkl'
        fit_scaler (bool): If True, fit new scaler. If False, load existing. Default: True
    
    Returns:
        tuple: (X_scaled, y_encoded, scaler, label_encoder, feature_names)
            - X_scaled: numpy array of scaled features
            - y_encoded: numpy array of encoded labels (0, 1, 2, ...)
            - scaler: fitted RobustScaler object
            - label_encoder: fitted LabelEncoder object
            - feature_names: list of feature column names
    
    Example:
        >>> X, y, scaler, le, features = load_and_preprocess_gnn_data(
        ...     'checkpoints/ctgan/balanced_20.csv'
        ... )
    """
    print("Loading and preprocessing data for GNN...")
    
    # Load CSV(s)
    if isinstance(csv_paths, str):
        csv_paths = [csv_paths]
    
    dfs = []
    for path in csv_paths:
        df = pd.read_csv(path)
        print(f"  Loaded {path}: {df.shape}")
        dfs.append(df)
    
    data = pd.concat(dfs, ignore_index=True)
    print(f"  Combined shape: {data.shape}")
    
    # Separate features and labels
    y = data['Label'].values
    X = data.drop(columns=['Label'])
    
    # Handle any remaining NaN/inf
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(X.median())
    
    feature_names = X.columns.tolist()
    X = X.values
    
    # Encode labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    print(f"\n  Features: {len(feature_names)}")
    print(f"  Classes: {len(label_encoder.classes_)} -> {label_encoder.classes_}")
    print(f"  Class distribution: {dict(zip(*np.unique(y_encoded, return_counts=True)))}")
    
    # Scale features
    if fit_scaler:
        print(f"\n  Fitting RobustScaler...")
        scaler = RobustScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Save scaler
        os.makedirs(os.path.dirname(scaler_path), exist_ok=True)
        joblib.dump(scaler, scaler_path)
        print(f"  ✓ Scaler saved to: {scaler_path}")
    else:
        print(f"\n  Loading existing scaler from: {scaler_path}")
        scaler = joblib.load(scaler_path)
        X_scaled = scaler.transform(X)
    
    return X_scaled, y_encoded, scaler, label_encoder, feature_names


def build_knn_graph(X, k=5, metric='euclidean'):
    """
    Build k-nearest neighbors graph from feature matrix.
    
    Creates a graph where each node is connected to its k nearest neighbors
    in feature space. Returns edge indices in PyTorch Geometric format.
    
    Args:
        X (numpy.ndarray): Feature matrix (n_samples, n_features)
        k (int): Number of nearest neighbors. Default: 5
        metric (str): Distance metric for k-NN. Default: 'euclidean'
    
    Returns:
        torch.Tensor: Edge index tensor of shape (2, num_edges)
    
    Example:
        >>> edge_index = build_knn_graph(X_scaled, k=5)
        >>> print(f"Created {edge_index.shape[1]} edges")
    """
    print(f"\nBuilding k-NN graph (k={k}, metric={metric})...")
    
    # Fit k-NN
    knn = NearestNeighbors(n_neighbors=k+1, metric=metric, n_jobs=-1)
    knn.fit(X)
    
    # Get neighbors (exclude self)
    distances, indices = knn.kneighbors(X)
    
    # Build edge list
    edges = []
    for i in range(len(X)):
        for j in indices[i][1:]:  # Skip first (self)
            edges.append([i, j])
    
    edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
    
    print(f"  ✓ Created graph: {len(X)} nodes, {edge_index.shape[1]} edges")
    print(f"  Average degree: {edge_index.shape[1] / len(X):.2f}")
    
    return edge_index


def create_pyg_data(X, y, edge_index, train_mask, val_mask, test_mask):
    """
    Create PyTorch Geometric Data object for GNN training.
    
    Wraps features, labels, edges, and train/val/test masks into a single
    Data object compatible with PyTorch Geometric models.
    
    Args:
        X (numpy.ndarray): Feature matrix
        y (numpy.ndarray): Label array
        edge_index (torch.Tensor): Edge connectivity
        train_mask (numpy.ndarray): Boolean mask for training nodes
        val_mask (numpy.ndarray): Boolean mask for validation nodes
        test_mask (numpy.ndarray): Boolean mask for test nodes
    
    Returns:
        Data: PyTorch Geometric Data object
    
    Example:
        >>> data = create_pyg_data(X, y, edge_index, train_m, val_m, test_m)
        >>> print(f"Data: {data.num_nodes} nodes, {data.num_edges} edges")
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


def calculate_class_weights(y_train):
    """
    Calculate class weights for weighted cross-entropy loss.
    
    Computes inverse class frequency weights to handle class imbalance.
    More weight is given to minority classes.
    
    Args:
        y_train (numpy.ndarray): Training labels
    
    Returns:
        torch.Tensor: Class weights tensor
    
    Example:
        >>> weights = calculate_class_weights(y_train)
        >>> criterion = nn.CrossEntropyLoss(weight=weights)
    """
    class_counts = Counter(y_train)
    total = len(y_train)
    num_classes = len(class_counts)
    
    weights = torch.zeros(num_classes)
    for cls, count in class_counts.items():
        weights[cls] = total / (num_classes * count)
    
    print(f"\nClass weights (inverse frequency):")
    for cls in range(num_classes):
        print(f"  Class {cls}: {weights[cls]:.4f}")
    
    return weights


class GraphSAGEModel(nn.Module):
    """
    GraphSAGE model for node classification.
    
    Implements a Graph Sample and Aggregate neural network with configurable
    hidden dimensions, number of layers, and dropout. Uses mean aggregation.
    
    Architecture:
    - Input -> SAGEConv -> ReLU -> Dropout -> SAGEConv -> ReLU -> Dropout -> Linear -> Output
    
    Args:
        num_features (int): Number of input features
        hidden_dim (int): Hidden layer dimension. Default: 128
        num_classes (int): Number of output classes
        dropout (float): Dropout probability. Default: 0.3
        num_layers (int): Number of SAGE layers. Default: 2
    
    Example:
        >>> model = GraphSAGEModel(num_features=20, hidden_dim=128, num_classes=5)
        >>> out = model(data.x, data.edge_index)
    """
    def __init__(self, num_features, hidden_dim=128, num_classes=2, dropout=0.3, num_layers=2):
        super(GraphSAGEModel, self).__init__()
        self.num_layers = num_layers
        self.dropout = dropout
        
        # First layer
        self.convs = nn.ModuleList()
        self.convs.append(SAGEConv(num_features, hidden_dim))
        
        # Hidden layers
        for _ in range(num_layers - 1):
            self.convs.append(SAGEConv(hidden_dim, hidden_dim))
        
        # Output layer
        self.lin = nn.Linear(hidden_dim, num_classes)
        
    def forward(self, x, edge_index):
        # Apply SAGE layers
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)
        
        # Final linear layer
        x = self.lin(x)
        return x


class GATModel(nn.Module):
    """
    Graph Attention Network (GAT) model for node classification.
    
    Implements a GAT with multi-head attention, configurable hidden dimensions,
    number of layers, and dropout. Attention allows the model to weigh neighbor
    importance dynamically.
    
    Architecture:
    - Input -> GATConv (multi-head) -> ELU -> Dropout -> GATConv -> ELU -> Dropout -> Linear -> Output
    
    Args:
        num_features (int): Number of input features
        hidden_dim (int): Hidden layer dimension. Default: 128
        num_classes (int): Number of output classes
        dropout (float): Dropout probability. Default: 0.3
        num_layers (int): Number of GAT layers. Default: 2
        heads (int): Number of attention heads in first layer. Default: 4
    
    Example:
        >>> model = GATModel(num_features=20, hidden_dim=128, num_classes=5, heads=4)
        >>> out = model(data.x, data.edge_index)
    """
    def __init__(self, num_features, hidden_dim=128, num_classes=2, dropout=0.3, num_layers=2, heads=4):
        super(GATModel, self).__init__()
        self.num_layers = num_layers
        self.dropout = dropout
        
        # First layer with multi-head attention
        self.convs = nn.ModuleList()
        self.convs.append(GATConv(num_features, hidden_dim, heads=heads, dropout=dropout))
        
        # Hidden layers
        for _ in range(num_layers - 2):
            self.convs.append(GATConv(hidden_dim * heads, hidden_dim, heads=heads, dropout=dropout))
        
        # Last GAT layer with single head
        if num_layers > 1:
            self.convs.append(GATConv(hidden_dim * heads, hidden_dim, heads=1, dropout=dropout))
        
        # Output layer
        self.lin = nn.Linear(hidden_dim, num_classes)
        
    def forward(self, x, edge_index):
        # Apply GAT layers
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index)
            x = F.elu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)
        
        # Final linear layer
        x = self.lin(x)
        return x


def train_gnn_epoch(model, data, optimizer, criterion, device):
    """
    Train GNN for one epoch.
    
    Performs one forward pass, computes loss on training nodes, backpropagates,
    and updates model weights.
    
    Args:
        model: GNN model
        data: PyTorch Geometric Data object
        optimizer: PyTorch optimizer
        criterion: Loss function
        device: torch device (cpu or cuda)
    
    Returns:
        float: Training loss for the epoch
    
    Example:
        >>> loss = train_gnn_epoch(model, data, optimizer, criterion, device)
    """
    model.train()
    data = data.to(device)
    
    optimizer.zero_grad()
    out = model(data.x, data.edge_index)
    loss = criterion(out[data.train_mask], data.y[data.train_mask])
    loss.backward()
    optimizer.step()
    
    return loss.item()


def evaluate_gnn(model, data, mask, device):
    """
    Evaluate GNN on a specific split (train/val/test).
    
    Computes accuracy, precision, recall, F1 score, and predictions
    for nodes in the specified mask.
    
    Args:
        model: GNN model
        data: PyTorch Geometric Data object
        mask: Boolean mask for evaluation nodes
        device: torch device
    
    Returns:
        dict: Dictionary containing:
            - 'accuracy': Overall accuracy
            - 'precision': Macro-averaged precision
            - 'recall': Macro-averaged recall
            - 'f1': Macro-averaged F1 score
            - 'loss': Cross-entropy loss
            - 'predictions': Predicted labels
            - 'true_labels': True labels
    
    Example:
        >>> metrics = evaluate_gnn(model, data, data.val_mask, device)
        >>> print(f"Val Acc: {metrics['accuracy']:.4f}")
    """
    model.eval()
    data = data.to(device)
    
    with torch.no_grad():
        out = model(data.x, data.edge_index)
        pred = out.argmax(dim=1)
        
        # Get masked predictions and labels
        mask_indices = mask.cpu().numpy()
        y_pred = pred[mask].cpu().numpy()
        y_true = data.y[mask].cpu().numpy()
        
        # Compute metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, average='macro', zero_division=0)
        recall = recall_score(y_true, y_pred, average='macro', zero_division=0)
        f1 = f1_score(y_true, y_pred, average='macro', zero_division=0)
        
        # Compute loss
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
    
    Trains the model for multiple epochs, tracks validation loss, and stops
    early if validation loss doesn't improve for 'patience' epochs. Returns
    the best model and training history.
    
    Args:
        model: GNN model
        data: PyTorch Geometric Data object
        optimizer: PyTorch optimizer
        criterion: Loss function with class weights
        device: torch device
        num_epochs (int): Maximum number of epochs. Default: 200
        patience (int): Early stopping patience. Default: 20
        verbose (bool): Print progress every 10 epochs. Default: True
    
    Returns:
        tuple: (best_model, history)
            - best_model: Model with best validation loss
            - history: Dictionary with training/validation metrics per epoch
    
    Example:
        >>> best_model, history = train_gnn_with_early_stopping(
        ...     model, data, optimizer, criterion, device, num_epochs=200
        ... )
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
        # Train
        train_loss = train_gnn_epoch(model, data, optimizer, criterion, device)
        
        # Evaluate on validation
        val_metrics = evaluate_gnn(model, data, data.val_mask, device)
        
        # Record history
        history['train_loss'].append(train_loss)
        history['val_loss'].append(val_metrics['loss'])
        history['val_accuracy'].append(val_metrics['accuracy'])
        history['val_f1'].append(val_metrics['f1'])
        
        # Early stopping check
        if val_metrics['loss'] < best_val_loss:
            best_val_loss = val_metrics['loss']
            best_model = copy.deepcopy(model)
            patience_counter = 0
        else:
            patience_counter += 1
        
        # Print progress
        if verbose and (epoch % 10 == 0 or patience_counter == 0):
            print(f"  Epoch {epoch:3d}: Train Loss={train_loss:.4f}, "
                  f"Val Loss={val_metrics['loss']:.4f}, "
                  f"Val Acc={val_metrics['accuracy']:.4f}, "
                  f"Val F1={val_metrics['f1']:.4f}")
        
        # Early stopping
        if patience_counter >= patience:
            print(f"\n  ✓ Early stopping at epoch {epoch} (no improvement for {patience} epochs)")
            break
    
    print(f"  ✓ Training complete. Best val loss: {best_val_loss:.4f}")
    
    return best_model, history


def print_detailed_metrics(metrics, label_encoder, split_name="Test"):
    """
    Print detailed classification metrics including per-class performance.
    
    Displays overall metrics, per-class accuracy/recall/F1, and confusion matrix.
    
    Args:
        metrics (dict): Metrics dictionary from evaluate_gnn()
        label_encoder: LabelEncoder with class names
        split_name (str): Name of split (e.g., "Test", "Val"). Default: "Test"
    
    Returns:
        None: Prints to console
    
    Example:
        >>> print_detailed_metrics(test_metrics, label_encoder, "Test")
    """
    print(f"\n{'='*80}")
    print(f"{split_name.upper()} SET METRICS")
    print(f"{'='*80}")
    
    print(f"\nOverall Metrics:")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1 Score:  {metrics['f1']:.4f}")
    
    # Per-class metrics
    print(f"\nPer-Class Metrics:")
    y_true = metrics['true_labels']
    y_pred = metrics['predictions']
    
    report = classification_report(y_true, y_pred, 
                                   target_names=[str(c) for c in label_encoder.classes_],
                                   zero_division=0,
                                   digits=4)
    print(report)
    
    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    print(f"\nConfusion Matrix:")
    print(f"  Rows = True labels, Columns = Predicted labels")
    print(f"  Classes: {label_encoder.classes_}")
    print(cm)


def save_gnn_model(model, path, metadata=None):
    """
    Save trained GNN model and metadata.
    
    Saves model state dict and optional metadata (hyperparameters, metrics, etc.)
    to a .pt file for later reuse.
    
    Args:
        model: Trained GNN model
        path (str): Save path (e.g., 'models/gnn_sage_70_15_15.pt')
        metadata (dict, optional): Additional info to save (metrics, config, etc.)
    
    Returns:
        None
    
    Example:
        >>> save_gnn_model(best_model, 'models/gnn_sage.pt', 
        ...                metadata={'split': '70/15/15', 'val_f1': 0.85})
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    
    checkpoint = {
        'model_state_dict': model.state_dict(),
        'model_class': model.__class__.__name__,
        'metadata': metadata or {}
    }
    
    torch.save(checkpoint, path)
    print(f"  ✓ Model saved to: {path}")

import pandas as pd
import numpy as np
import os
import subprocess
import time
import joblib
import xgboost as xgb

def inspect_missing_and_constant(df):
    """
    Inspects NaNs, infs, and constant columns in the DataFrame.
    Args:
        df (pd.DataFrame): DataFrame to inspect.
    Returns:
        dict: Dictionary with summary.
    """
    summary = {}
    summary['total_rows'] = df.shape[0]
    summary['total_columns'] = df.shape[1]
    summary['nan_count'] = df.isna().sum().sort_values(ascending=False)
    summary['inf_count'] = np.isinf(df.select_dtypes(include=[np.number])).sum().sort_values(ascending=False)
    summary['constant_columns'] = [col for col in df.columns if df[col].nunique() == 1]
    return summary

def load_and_concatenate_datasets(folder_path):
    """
    Loads and concatenates multiple CSV files from a folder.
    Args:
        folder_path (str): Path to the folder containing the CSVs.
    Returns:
        pd.DataFrame: Combined DataFrame.
    """
    dfs = []
    for name in os.listdir(folder_path):
        if name.endswith('.csv'):
            file_path = os.path.join(folder_path, name)
            try:
                df = pd.read_csv(file_path)
                print(f"Loaded {name} with shape {df.shape}")
                dfs.append(df)
            except Exception as e:
                print(f"Failed to load {name}: {e}")
    return pd.concat(dfs, ignore_index=True)

def export_day_attack_and_label_count(filepath, chunksize, filename):
    """
    Processes a large CSV file in chunks to tabulate the number of attacks per day
    """
    # Define columns we need to read to save memory
    use_cols = ['FLOW_START_MILLISECONDS', 'Label', 'Attack']

    # Initialize counters
    day_attack_count = {}
    attack_type_count = {}

    print(filepath + " is loading...")

    for chunk in pd.read_csv(filepath, usecols=use_cols, chunksize=chunksize):
        # Convert timestamp to date
        chunk['Date'] = pd.to_datetime(chunk['FLOW_START_MILLISECONDS'], unit='ms').dt.date
        
        # Tabulate per day per attack type
        day_grouped = chunk.groupby(['Date', 'Attack']).size()
        for (day, attack), count in day_grouped.items():
            day_attack_count[(day, attack)] = day_attack_count.get((day, attack), 0) + count

        # Class imbalance overall
        label_counts = chunk['Label'].value_counts()
        for label, count in label_counts.items():
            attack_type_count[label] = attack_type_count.get(label, 0) + count

    # Convert result to DataFrame for clean viewing
    df_day_attack = pd.DataFrame(
        [(day, attack, count) for (day, attack), count in day_attack_count.items()],
        columns=['Date', 'Attack', 'Count']
    )

    df_label = pd.DataFrame(
        list(attack_type_count.items()), columns=['Label', 'Total Count']
    )

    export_day_attack_name = filename + '_day_attack.csv'
    export_label_name = filename + '_label.csv'

    # Save or display
    df_day_attack.to_csv(export_day_attack_name, index=False)
    df_label.to_csv(export_label_name, index=False)

    print(f" ✓ Done — result saved as '{export_day_attack_name}' and '{export_label_name}'")


def get_feature_mappings():
    """Define feature mappings between CSV columns and model features"""
    # Features for each model (20 features version)
    features_20 = [
        'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts',
        'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Flow Pkts/s',
        'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
        'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Max',
        'Bwd IAT Mean', 'Bwd IAT Min', 'Fwd Header Len',
        'Fwd Pkts/s', 'Pkt Len Max', 'Pkt Len Mean',
        'Init Bwd Win Byts'
    ]
    
    # CSV to model feature name mapping
    csv_to_model = {
        'Total Fwd Packet': 'Tot Fwd Pkts',
        'Bwd Packet Length Max': 'Bwd Pkt Len Max',
        'Bwd Packet Length Min': 'Bwd Pkt Len Min',
        'Flow Packets/s': 'Flow Pkts/s',
        'Fwd IAT Total': 'Fwd IAT Tot',
        'Fwd Header Length': 'Fwd Header Len',
        'Fwd Packets/s': 'Fwd Pkts/s',
        'Packet Length Max': 'Pkt Len Max',
        'Packet Length Mean': 'Pkt Len Mean',
        'Bwd Init Win Bytes': 'Init Bwd Win Byts'
    }
    
    return features_20, csv_to_model

"""Check if CSV has required columns for prediction"""
def columnCheck(csv_path):
    try:
        # Read CSV headers
        df = pd.read_csv(csv_path, nrows=0)
        csv_columns = set(df.columns)
        
        # Get feature mappings
        features_20, csv_to_model = get_feature_mappings()
        
        # For each required feature, check if either the original or mapped name exists
        missing_features = []
        for feature in features_20:
            # Get the CSV column name if it exists in the mapping
            csv_name = next((k for k, v in csv_to_model.items() if v == feature), feature)
            if feature not in csv_columns and csv_name not in csv_columns:
                missing_features.append(f"{feature} (or {csv_name})")
        
        if missing_features:
            print(f"columnCheck(): Missing required columns: {missing_features}")
            return False
            
        print("columnCheck(): All required columns are present!")
        return True
        
    except Exception as e:
        print(f"columnCheck(): Error checking columns: {str(e)}")
        return False

"""Clean features by handling infinity and extreme values"""
def clean_features(df, columns):
    df_clean = df.copy()
    
    for col in columns:
        if col != 'Protocol':  # Skip categorical columns
            # Replace infinity with NaN
            df_clean[col] = df_clean[col].replace([np.inf, -np.inf], np.nan)
            
            # For each column, calculate reasonable bounds (e.g., 99th percentile)
            q99 = df_clean[col].quantile(0.99)
            q01 = df_clean[col].quantile(0.01)
            
            # Cap values at the bounds
            df_clean[col] = df_clean[col].clip(lower=q01, upper=q99)
            
            # Fill remaining NaN with median
            median_val = df_clean[col].median()
            df_clean[col] = df_clean[col].fillna(median_val)
    
    return df_clean


# ============================================================================
# LABEL MAPPINGS FOR DECODING PREDICTIONS
# ============================================================================

MULTICLASS_LABEL_MAP = {
    0: 'BFA',
    1: 'BOTNET',
    2: 'DDoS',
    3: 'DoS',
    4: 'Normal',
    5: 'Probe',
    6: 'U2R',
    7: 'Web-Attack'
}

BINARY_LABEL_MAP = {
    0: 'Benign',
    1: 'Attack'
}


def get_model_registry():
    """
    Returns the model registry organized by categories.
    
    Model Categories:
    - XGB: XGBoost models (20 features)
    - GNN20_binary: GNN models with 20 features for binary classification
    - GNN20_multiclass: GNN models with 20 features for multiclass classification
    - GNN52_binary: GNN models with 52 features for binary classification
    - GNN52_multiclass: GNN models with 52 features for multiclass classification
    """
    return {
        # XGBoost models (20 features, binary classification)
        'XGB': {
            'models/best_xgb_20.json': {'name': 'xgb_20', 'task': 'binary', 'features': 20},
            'models/best_xgb_50.json': {'name': 'xgb_50', 'task': 'binary', 'features': 20},
            'models/best_xgb_80.json': {'name': 'xgb_80', 'task': 'binary', 'features': 20},
        },
        # GNN 20-feature Binary models
        'GNN20_binary': {
            'models/binary/gnn_gat_70_15_15.pt': {'name': 'gnn20_bin_gat_70', 'task': 'binary', 'features': 20},
            'models/binary/gnn_gat_50_25_25.pt': {'name': 'gnn20_bin_gat_50', 'task': 'binary', 'features': 20},
            'models/binary/gnn_gat_20_40_40.pt': {'name': 'gnn20_bin_gat_20', 'task': 'binary', 'features': 20},
            'models/binary/gnn_graphsage_70_15_15.pt': {'name': 'gnn20_bin_sage_70', 'task': 'binary', 'features': 20},
            'models/binary/gnn_graphsage_50_25_25.pt': {'name': 'gnn20_bin_sage_50', 'task': 'binary', 'features': 20},
            'models/binary/gnn_graphsage_20_40_40.pt': {'name': 'gnn20_bin_sage_20', 'task': 'binary', 'features': 20},
        },
        # GNN 20-feature Multiclass models
        'GNN20_multiclass': {
            'models/multiclass/gnn_gat_70_15_15.pt': {'name': 'gnn20_multi_gat_70', 'task': 'multiclass', 'features': 20},
            'models/multiclass/gnn_gat_50_25_25.pt': {'name': 'gnn20_multi_gat_50', 'task': 'multiclass', 'features': 20},
            'models/multiclass/gnn_gat_20_40_40.pt': {'name': 'gnn20_multi_gat_20', 'task': 'multiclass', 'features': 20},
            'models/multiclass/gnn_graphsage_70_15_15.pt': {'name': 'gnn20_multi_sage_70', 'task': 'multiclass', 'features': 20},
            'models/multiclass/gnn_graphsage_50_25_25.pt': {'name': 'gnn20_multi_sage_50', 'task': 'multiclass', 'features': 20},
            'models/multiclass/gnn_graphsage_20_40_40.pt': {'name': 'gnn20_multi_sage_20', 'task': 'multiclass', 'features': 20},
        },
        # GNN 52-feature Binary models
        'GNN52_binary': {
            'models/binary_52/gnn_gat_70_15_15.pt': {'name': 'gnn52_bin_gat_70', 'task': 'binary', 'features': 52},
            'models/binary_52/gnn_gat_50_25_25.pt': {'name': 'gnn52_bin_gat_50', 'task': 'binary', 'features': 52},
            'models/binary_52/gnn_gat_20_40_40.pt': {'name': 'gnn52_bin_gat_20', 'task': 'binary', 'features': 52},
            'models/binary_52/gnn_graphsage_70_15_15.pt': {'name': 'gnn52_bin_sage_70', 'task': 'binary', 'features': 52},
            'models/binary_52/gnn_graphsage_50_25_25.pt': {'name': 'gnn52_bin_sage_50', 'task': 'binary', 'features': 52},
            'models/binary_52/gnn_graphsage_20_40_40.pt': {'name': 'gnn52_bin_sage_20', 'task': 'binary', 'features': 52},
        },
        # GNN 52-feature Multiclass models
        'GNN52_multiclass': {
            'models/multiclass_52/gnn_gat_70_15_15.pt': {'name': 'gnn52_multi_gat_70', 'task': 'multiclass', 'features': 52},
            'models/multiclass_52/gnn_gat_50_25_25.pt': {'name': 'gnn52_multi_gat_50', 'task': 'multiclass', 'features': 52},
            'models/multiclass_52/gnn_gat_20_40_40.pt': {'name': 'gnn52_multi_gat_20', 'task': 'multiclass', 'features': 52},
            'models/multiclass_52/gnn_graphsage_70_15_15.pt': {'name': 'gnn52_multi_sage_70', 'task': 'multiclass', 'features': 52},
            'models/multiclass_52/gnn_graphsage_50_25_25.pt': {'name': 'gnn52_multi_sage_50', 'task': 'multiclass', 'features': 52},
            'models/multiclass_52/gnn_graphsage_20_40_40.pt': {'name': 'gnn52_multi_sage_20', 'task': 'multiclass', 'features': 52},
        },
    }


def get_models_by_selection(selection="all"):
    """
    Get models based on selection type.
    
    Args:
        selection: One of:
            - "all": All models (XGB + GNN20 + GNN52, binary + multiclass)
            - "all_20_features": XGB + GNN20 (binary + multiclass)
            - "gnn_52_features": GNN52 only (binary + multiclass)
            - "binary": All binary models (XGB + GNN20_binary + GNN52_binary)
            - "multiclass": All multiclass models (GNN20_multiclass + GNN52_multiclass)
    
    Returns:
        dict: {model_path: model_info} for selected models
    """
    registry = get_model_registry()
    selected = {}
    
    selection_lower = selection.lower().replace(" ", "_").replace("-", "_")
    
    if selection_lower in ["all", "all_models"]:
        # All models
        for category in registry.values():
            selected.update(category)
            
    elif selection_lower in ["all_20_features", "all_20", "20_features", "20features"]:
        # XGB + GNN20 (both binary and multiclass)
        selected.update(registry['XGB'])
        selected.update(registry['GNN20_binary'])
        selected.update(registry['GNN20_multiclass'])
        
    elif selection_lower in ["gnn_52_features", "gnn52_features", "52_features", "52features", "gnn52"]:
        # GNN52 only (both binary and multiclass)
        selected.update(registry['GNN52_binary'])
        selected.update(registry['GNN52_multiclass'])
        
    elif selection_lower in ["binary", "binary_only"]:
        # All binary models
        selected.update(registry['XGB'])
        selected.update(registry['GNN20_binary'])
        selected.update(registry['GNN52_binary'])
        
    elif selection_lower in ["multiclass", "multiclass_only", "multi"]:
        # All multiclass models
        selected.update(registry['GNN20_multiclass'])
        selected.update(registry['GNN52_multiclass'])
        
    else:
        print(f"Warning: Unknown selection '{selection}'. Using 'all' instead.")
        print("Valid options: 'all', 'all_20_features', 'gnn_52_features', 'binary', 'multiclass'")
        for category in registry.values():
            selected.update(category)
    
    return selected


def decode_prediction(value, task='binary'):
    """
    Decode numeric prediction to human-readable label.
    
    Args:
        value: Numeric prediction (0, 1, 2, etc.)
        task: 'binary' or 'multiclass'
    
    Returns:
        str: Human-readable label
    """
    try:
        v = int(value)
        if task == 'multiclass':
            return MULTICLASS_LABEL_MAP.get(v, f'Unknown({v})')
        else:
            return BINARY_LABEL_MAP.get(v, f'Unknown({v})')
    except:
        return str(value)


"""
Make predictions using selected models and save results.

Args:
    csv_path: Path to CSV file with flow data
    model_selection: Model selection type:
        - "all": All models (default)
        - "all_20_features": XGB + GNN 20-feature models
        - "gnn_52_features": GNN 52-feature models only
        - "binary": All binary classification models
        - "multiclass": All multiclass classification models

Returns:
    Path to the output CSV file with predictions
"""
def predict(csv_path, model_selection="all"):
    try:
        import torch
        import importlib.util
        
        # Base directory for module-local resources (models, scalers, output)
        module_dir = os.path.dirname(__file__)

        # Create output directory if it doesn't exist
        output_dir = os.path.join(module_dir, '..', 'output')
        output_dir = os.path.abspath(output_dir)
        os.makedirs(output_dir, exist_ok=True)
        
        # Get feature mappings
        features_20, csv_to_model = get_feature_mappings()
        
        # Load full data to preserve all columns
        df_full = pd.read_csv(csv_path)
        print(f"Loaded {len(df_full)} rows from {csv_path}")
        
        # Get selected models based on model_selection parameter
        selected_models = get_models_by_selection(model_selection)
        print(f"\nModel selection: '{model_selection}'")
        print(f"Running {len(selected_models)} models...")
        
        # Process features for prediction (always need 20-feature set for now)
        df_features = df_full.copy()
        
        # Ensure we have all features in the correct format
        for feature in features_20:
            csv_name = next((k for k, v in csv_to_model.items() if v == feature), feature)
            if csv_name in df_features.columns:
                df_features = df_features.rename(columns={csv_name: feature})
        
        # Clean features before scaling
        print("Cleaning features...")
        df_features = clean_features(df_features, features_20)
        
        # Load and apply scaler for 20-feature models
        scaler_path_20 = os.path.join(module_dir, 'scalers', 'benign_robust_scaler.pkl')
        if os.path.exists(scaler_path_20):
            scaler_20 = joblib.load(scaler_path_20)
            scaled_cols = [col for col in features_20 if col != 'Protocol']
            print("Scaling 20-feature set...")
            df_features_20 = df_features.copy()
            df_features_20[scaled_cols] = scaler_20.transform(df_features_20[scaled_cols])
        else:
            print(f"Warning: Scaler not found at {scaler_path_20}")
            df_features_20 = df_features.copy()
        
        # Load gnn_utils for GNN inference
        gnn_utils_path = os.path.join(module_dir, 'gnn_utils.py')
        spec = importlib.util.spec_from_file_location('gnn_utils', gnn_utils_path)
        gnn_utils = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gnn_utils)
        GraphSAGEModel = gnn_utils.GraphSAGEModel
        GATModel = gnn_utils.GATModel
        build_knn_graph = gnn_utils.build_knn_graph
        
        # Setup GPU device with memory optimization
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        print(f"\nMaking predictions on device: {device}")
        if device.type == 'cuda':
            # Print GPU info
            gpu_name = torch.cuda.get_device_name(0)
            gpu_mem_total = torch.cuda.get_device_properties(0).total_memory / 1e9
            gpu_mem_free = (torch.cuda.get_device_properties(0).total_memory - torch.cuda.memory_allocated()) / 1e9
            print(f"GPU: {gpu_name} ({gpu_mem_total:.1f} GB total, {gpu_mem_free:.1f} GB free)")
            
            # Enable memory-efficient settings
            torch.backends.cudnn.benchmark = True
            torch.cuda.empty_cache()
        print("="*60)
        
        # Track results for summary
        results_summary = {}
        
        for model_rel_path, model_info in selected_models.items():
            model_path = os.path.join(module_dir, model_rel_path)
            column_name = model_info['name']
            task = model_info['task']
            num_features = model_info['features']
            
            # Check if model file exists
            if not os.path.exists(model_path):
                print(f"⚠ Skipping {column_name}: Model not found at {model_path}")
                continue
                
            ext = os.path.splitext(model_path)[1].lower()
            print(f"\n→ {column_name} ({task}, {num_features} features)")

            # XGBoost models (JSON/Model/BST)
            if ext in ('.json', '.model', '.bst'):
                try:
                    model = xgb.XGBClassifier()
                    model.load_model(model_path)

                    # Get predictions using 20-feature set
                    X = df_features_20[features_20].copy()
                    if X.isna().any().any():
                        X = X.fillna(0)

                    preds = model.predict(X)
                    df_full[column_name] = preds

                    # Decode predictions to labels
                    label_col = f"{column_name}_label"
                    df_full[label_col] = df_full[column_name].apply(
                        lambda v: decode_prediction(v, task)
                    )
                    
                    # Store summary
                    results_summary[column_name] = df_full[label_col].value_counts().to_dict()
                    print(f"  ✓ Complete: {results_summary[column_name]}")
                    
                except Exception as e:
                    print(f"  ✗ Failed: {e}")
                    df_full[column_name] = -1

            # PyTorch GNN checkpoints (.pt)
            elif ext == '.pt':
                try:
                    # Load checkpoint directly to GPU
                    checkpoint = torch.load(model_path, map_location=device, weights_only=False)
                    metadata = checkpoint.get('metadata', {}) or {}
                    
                    # Get model parameters
                    model_num_features = metadata.get('num_features', 20)
                    num_classes = metadata.get('num_classes', 8 if task == 'multiclass' else 2)
                    hidden_dim = metadata.get('hidden_dim', 64)
                    dropout = metadata.get('dropout', 0.4)
                    heads = metadata.get('heads', 2)
                    num_layers = metadata.get('num_layers', 2)
                    
                    # Select appropriate feature set - keep as tensor on GPU
                    X_infer = df_features_20[features_20].copy()
                    if X_infer.isna().any().any():
                        X_infer = X_infer.fillna(0)
                    
                    # Convert to GPU tensor immediately (RTX 3080 Ti 12GB can handle this)
                    X_gpu = torch.tensor(X_infer.values, dtype=torch.float32, device=device)
                    
                    # Create model based on architecture
                    model_file = os.path.basename(model_path)
                    if 'sage' in model_file.lower() or 'graphsage' in model_file.lower():
                        model = GraphSAGEModel(
                            num_features=model_num_features,
                            hidden_dim=hidden_dim,
                            num_classes=num_classes,
                            dropout=dropout,
                            num_layers=num_layers,
                            device=device
                        )
                    else:
                        model = GATModel(
                            num_features=model_num_features,
                            hidden_dim=hidden_dim,
                            num_classes=num_classes,
                            dropout=dropout,
                            heads=heads,
                            device=device
                        )
                    
                    # Load weights
                    state = checkpoint.get('model_state_dict', checkpoint)
                    if isinstance(state, dict):
                        model.load_state_dict(state)
                    
                    # Free checkpoint memory
                    del checkpoint, state
                    torch.cuda.empty_cache()
                    
                    model.to(device)
                    model.eval()
                    
                    n_nodes = X_gpu.shape[0]
                    
                    # RTX 3080 Ti 12GB settings - can handle ~200k nodes comfortably
                    # For larger datasets, use batching
                    MAX_FULL_INFERENCE = 200000
                    
                    if n_nodes > MAX_FULL_INFERENCE:
                        # Batch processing for very large datasets
                        BATCH_SIZE = 100000  # 100k per batch is fine for 12GB
                        print(f"    Processing {n_nodes:,} nodes in batches of {BATCH_SIZE:,}")
                        all_preds = torch.zeros(n_nodes, dtype=torch.long, device=device)
                        
                        for batch_start in range(0, n_nodes, BATCH_SIZE):
                            batch_end = min(batch_start + BATCH_SIZE, n_nodes)
                            X_batch = X_gpu[batch_start:batch_end]
                            
                            # Build kNN graph - uses CPU sklearn but that's fine
                            edge_index_batch = build_knn_graph(
                                X_batch.cpu().numpy(), k=5, metric='euclidean'
                            ).to(device)
                            
                            with torch.no_grad():
                                out = model(X_batch, edge_index_batch)
                                all_preds[batch_start:batch_end] = out.argmax(dim=1)
                            
                            del edge_index_batch, out
                        
                        preds = all_preds.cpu().numpy()
                        del all_preds
                    else:
                        # Full inference on GPU - most datasets will fit here
                        # Build kNN graph
                        edge_index = build_knn_graph(
                            X_gpu.cpu().numpy(), k=5, metric='euclidean'
                        ).to(device)
                        
                        with torch.no_grad():
                            out = model(X_gpu, edge_index)
                            preds = out.argmax(dim=1).cpu().numpy()
                        
                        del edge_index, out
                    
                    # Clean up GPU tensors
                    del X_gpu, model
                    torch.cuda.empty_cache()
                    
                    df_full[column_name] = preds
                    
                    # Decode predictions to labels
                    label_col = f"{column_name}_label"
                    df_full[label_col] = df_full[column_name].apply(
                        lambda v: decode_prediction(v, task)
                    )
                    
                    # Store summary
                    results_summary[column_name] = df_full[label_col].value_counts().to_dict()
                    print(f"  ✓ Complete: {results_summary[column_name]}")
                    
                    del preds
                    
                except Exception as e:
                    print(f"  ✗ Failed: {e}")
                    import traceback
                    traceback.print_exc()
                    df_full[column_name] = -1
                    torch.cuda.empty_cache()
            else:
                print(f"  ⚠ Unsupported model format: {ext}")
        
        # Save results
        output_filename = f"{os.path.splitext(os.path.basename(csv_path))[0]}_predicted.csv"
        output_path = os.path.join(output_dir, output_filename)
        df_full.to_csv(output_path, index=False)
        
        # Print summary
        print("\n" + "="*60)
        print(f"PREDICTION SUMMARY for {os.path.basename(csv_path)}")
        print("="*60)
        print(f"Total flows: {len(df_full):,}")
        print(f"Models run: {len(results_summary)}")
        print("\nResults by model:")
        for model_name, counts in results_summary.items():
            print(f"\n  {model_name}:")
            for label, count in sorted(counts.items(), key=lambda x: -x[1]):
                pct = count / len(df_full) * 100
                print(f"    {label}: {count:,} ({pct:.1f}%)")
        
        print(f"\n✓ Results saved to: {output_path}")
        return output_path
        
    except Exception as e:
        print(f"Error during prediction: {str(e)}")
        print("Stack trace:")
        import traceback
        traceback.print_exc()
        return None


"""
    Convert pcap file to CSV using CICFlowMeter
    Args:
        pcap_path: Path to pcap file or directory containing pcap files
        output_dir: Directory where CSV files will be saved (default: ../testDataSet)
        replace: Optional to replace existing CSV files (default: False -> skip convertion if CSV exists)
    Returns:
        Path to the generated CSV file
"""
def convert_pcap_to_csv(pcap_path, output_dir="../testDataSet", replace=False):
    
    try:
        # Normalize paths
        pcap_path = os.path.abspath(pcap_path)
        output_dir = os.path.abspath(output_dir)
        
        # Verify input file exists
        if not os.path.exists(pcap_path):
            print(f"Error: PCAP file not found at {pcap_path}")
            return None
            
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        print(f"Output directory: {output_dir}")
        
        # Check if CSV already exists (skip conversion if replace=False)
        pcap_basename = os.path.basename(pcap_path)
        pcap_name_no_ext = os.path.splitext(pcap_basename)[0]
        
        # Expected final CSV name
        final_csv_name = f"{pcap_name_no_ext}.csv"
        final_csv_path = os.path.join(output_dir, final_csv_name)
        
        if not replace:
            # Check if the file exists and is not empty
            if os.path.exists(final_csv_path):
                file_size = os.path.getsize(final_csv_path)
                if file_size > 0:
                    print(f"\n✓ CSV file already exists: {final_csv_path}")
                    print(f"File size: {file_size:,} bytes")
                    print("Skipping conversion (use replace=True to force reconversion)")
                    return final_csv_path
                else:
                    print(f"Warning: Existing CSV file is empty, will reconvert")
                    os.remove(final_csv_path)
        
        # Set jnetpcap path and verify it exists
        jnetpcap_path = os.path.abspath("../CICFlowMeter/jnetpcap/win/jnetpcap-1.4.r1425")
        if not os.path.exists(jnetpcap_path):
            print(f"Error: jnetpcap directory not found at {jnetpcap_path}")
            return None
        
        # Set and verify CICFlowMeter jar exists
        cicflowmeter_jar = os.path.abspath("../CICFlowMeter/target/CICFlowMeterV3-0.0.4-SNAPSHOT.jar")
        if not os.path.exists(cicflowmeter_jar):
            print(f"Error: CICFlowMeter JAR not found at {cicflowmeter_jar}")
            return None
            
        # Update PATH environment
        env = os.environ.copy()
        env["PATH"] = f"{jnetpcap_path};{env['PATH']}"
        
        # Build CICFlowMeter command
        cmd = [
            "java",
            "-cp",
            cicflowmeter_jar,
            "cic.cs.unb.ca.ifm.Cmd",
            pcap_path,
            output_dir
        ]
        
        print(f"\nConverting PCAP to CSV...")
        print(f"Input: {pcap_path}")
        print(f"Command: {' '.join(cmd)}")
        
        process = subprocess.run(cmd, env=env, capture_output=True, text=True)
        
        if process.returncode != 0:
            print("\nError during conversion:")
            print(f"Return code: {process.returncode}")
            print("\nStandard error output:")
            print(process.stderr)
            print("\nStandard output:")
            print(process.stdout)
            return None
        
        print("\nConversion command executed successfully!")
        if process.stdout:
            print(f"Output: {process.stdout}")
            
        # Wait for file system to catch up
        time.sleep(2)
        
        # Check if the expected CSV file was created
        if not os.path.exists(final_csv_path):
            print(f"\nCSV file not found at expected location: {final_csv_path}")
            print("Checking output directory for generated files...")
            print("Files in output directory:")
            for f in os.listdir(output_dir):
                print(f"  {f}")
            return None
            
        # Verify the CSV is not empty
        if os.path.getsize(final_csv_path) == 0:
            print("Error: Generated CSV file is empty")
            return None
        
        print(f"\n✓ Successfully converted to: {final_csv_path}")
        print(f"File size: {os.path.getsize(final_csv_path):,} bytes")
        
        return final_csv_path
            
    except Exception as e:
        print(f"Error in convert_pcap_to_csv: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

"""
    Analyze prediction results with focus on ports and IP addresses
    Args:
        csv_path: Path to the predicted CSV file
        pred_column: Which prediction column to analyze (predict20/50/80)
"""
def analyze_predictions(csv_path, pred_column='predict20'):
    # Load predictions
    df = pd.read_csv(csv_path)
    
    # Filter attacks
    attack_df = df[df[pred_column] == 1]
    
    print(f"\n=== Analysis for {pred_column} ===")
    print("\nDetailed Attack Records (showing first 10):")
    for _, row in attack_df.head(10).iterrows():
        print(f"Source: {row['Src IP']}:{row['Src Port']} -> Destination: {row['Dst IP']}:{row['Dst Port']}")
    
    print("\n=== Top 10 Source IPs and Ports in Attacks ===")
    src_counts = attack_df.groupby(['Src IP', 'Src Port']).size().sort_values(ascending=False).head(10)
    for (ip, port), count in src_counts.items():
        print(f"{ip}:{port} - {count} attacks")
    
    print("\n=== Top 10 Destination IPs and Ports in Attacks ===")
    dst_counts = attack_df.groupby(['Dst IP', 'Dst Port']).size().sort_values(ascending=False).head(10)
    for (ip, port), count in dst_counts.items():
        print(f"{ip}:{port} - {count} attacks")
    
    print("\n=== Most Common Attack Destination Ports ===")
    port_counts = attack_df['Dst Port'].value_counts().head(10)
    for port, count in port_counts.items():
        print(f"Port {port}: {count} attacks")
    
    print("\n=== Summary Statistics ===")
    total_flows = len(df)
    total_attacks = len(attack_df)
    print(f"Total flows analyzed: {total_flows}")
    print(f"Total attacks detected: {total_attacks}")
    print(f"Attack percentage: {(total_attacks/total_flows)*100:.2f}%")

"""
    Complete streamlined process from pcap to predictions
    Args:
        pcap_path: Path to pcap file to analyze
        output_dir: Directory for output files
    Returns:
        Path to the final prediction CSV file
"""
def streamline_process(pcap_path, output_dir="../output"):
    try:
        # Normalize paths
        pcap_path = os.path.abspath(pcap_path)
        output_dir = os.path.abspath(output_dir)
        
        print(f"Starting streamline process...")
        print(f"PCAP file: {pcap_path}")
        print(f"Output directory: {output_dir}")
        
        # Step 1: Convert PCAP to CSV
        print(f"\n{'='*60}")
        print(f"Step 1: Converting PCAP to CSV")
        print(f"{'='*60}")
        csv_path = convert_pcap_to_csv(pcap_path, "../testDataSet")
        if not csv_path:
            raise Exception("PCAP to CSV conversion failed")
            
        # Step 2: Verify columns
        print(f"\n{'='*60}")
        print(f"Step 2: Verifying CSV format")
        print(f"{'='*60}")
        if not columnCheck(csv_path):
            raise Exception("CSV format verification failed")
            
        # Step 3: Make predictions
        print(f"\n{'='*60}")
        print(f"Step 3: Making predictions")
        print(f"{'='*60}")
        prediction_path = predict(csv_path)
        if not prediction_path:
            raise Exception("Prediction failed")
            
        print(f"\n{'='*60}")
        print(f"✓ Process completed successfully!")
        print(f"{'='*60}")
        print(f"Results saved to: {prediction_path}")
        return prediction_path
        
    except Exception as e:
        print(f"\n{'='*60}")
        print(f"✗ Error in streamline_process: {str(e)}")
        print(f"{'='*60}")
        import traceback
        traceback.print_exc()
        return None

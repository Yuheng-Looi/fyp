"""
CTGAN Augmentation Utilities for Network Intrusion Detection

This module provides:
1. CTGAN training and generation (can generate more samples than real data)
2. Quality-based filtering to keep high-quality synthetic samples
3. Undersampling for majority classes
4. Visualization utilities for data balance
"""

import pandas as pd
import numpy as np
import warnings
from typing import Tuple, List, Dict, Optional
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import NearestNeighbors
from sklearn.ensemble import RandomForestClassifier
from sklearn.cluster import MiniBatchKMeans
from collections import Counter

warnings.filterwarnings('ignore')

# Lazy load SDV to avoid import overhead
_sdv_loaded = False
CTGANSynthesizer = None
evaluate_quality = None
SingleTableMetadata = None


def _load_sdv():
    """Lazy load SDV modules."""
    global _sdv_loaded, CTGANSynthesizer, evaluate_quality, SingleTableMetadata
    if not _sdv_loaded:
        from sdv.single_table import CTGANSynthesizer as _CTGAN
        from sdv.evaluation.single_table import evaluate_quality as _eval
        from sdv.metadata import SingleTableMetadata as _Meta
        CTGANSynthesizer = _CTGAN
        evaluate_quality = _eval
        SingleTableMetadata = _Meta
        _sdv_loaded = True


def train_and_generate_ctgan(
    df: pd.DataFrame,
    label_value: str,
    generate_samples: int = 5000,
    epochs: int = 300,
    batch_size: int = 500,
    cuda: bool = True
) -> Tuple[pd.DataFrame, float]:
    """
    Train CTGAN on a specific class and generate synthetic samples.
    
    CTGAN can generate MORE samples than the original data size.
    The quality of generated samples depends on the real data distribution.
    
    Args:
        df: Full DataFrame with all classes
        label_value: The class label (string) to generate for
        generate_samples: Number of synthetic samples to generate
        epochs: CTGAN training epochs
        batch_size: CTGAN batch size
        cuda: Use GPU acceleration
        
    Returns:
        Tuple of (synthetic DataFrame with Label column, quality score)
    """
    _load_sdv()
    
    # Filter data for the target class
    real_data = df[df["Label"] == label_value].copy()
    
    if real_data.empty:
        print(f"⚠ No data found for label '{label_value}'")
        print(f"   Available labels: {df['Label'].unique().tolist()}")
        return pd.DataFrame(), 0.0
    
    print(f"  Real data size for '{label_value}': {len(real_data)} samples")
    print(f"  Generating {generate_samples} synthetic samples...")
    
    # Drop Label column for CTGAN training
    real_data_no_label = real_data.drop(columns=["Label"])
    
    # Create metadata
    metadata = SingleTableMetadata()
    metadata.detect_from_dataframe(real_data_no_label)
    
    # Mark categorical columns
    if "Protocol" in real_data_no_label.columns:
        metadata.update_column(column_name="Protocol", sdtype="categorical")
    if "Dst Port" in real_data_no_label.columns:
        metadata.update_column(column_name="Dst Port", sdtype="categorical")
    
    try:
        # Train CTGAN
        synthesizer = CTGANSynthesizer(
            metadata,
            epochs=epochs,
            batch_size=batch_size,
            cuda=cuda,
            verbose=False
        )
        synthesizer.fit(real_data_no_label)
        
        # Generate synthetic samples
        synthetic = synthesizer.sample(generate_samples)
        
        # Evaluate quality
        quality_report = evaluate_quality(real_data_no_label, synthetic, metadata)
        quality_score = quality_report.get_score()
        
        # Add Label column back
        synthetic["Label"] = label_value
        
        print(f"  ✅ Generated {len(synthetic)} samples with quality: {quality_score:.4f}")
        return synthetic, quality_score
        
    except Exception as e:
        print(f"  ⚠ Error generating for {label_value}: {e}")
        return pd.DataFrame(), 0.0


def filter_synthetic_samples(
    synthetic_df: pd.DataFrame,
    real_df: pd.DataFrame,
    label_col: str = "Label",
    quality_threshold: float = 0.5,
    max_samples_per_class: Optional[int] = None
) -> Tuple[pd.DataFrame, Dict]:
    """
    Filter synthetic samples to keep only high-quality ones.
    
    Filtering methods:
    1. Nearest-neighbor distance: Remove outliers far from real data
    2. Feature bounds: Remove samples outside realistic ranges
    3. Optional: Cap maximum samples per class
    
    Args:
        synthetic_df: Generated synthetic samples
        real_df: Real training data for reference
        label_col: Label column name
        quality_threshold: Percentile threshold for NN distance (lower = stricter)
        max_samples_per_class: Maximum samples to keep per class
        
    Returns:
        Tuple of (filtered DataFrame, filter statistics)
    """
    if synthetic_df.empty:
        return synthetic_df, {}
    
    print(f"\n{'='*50}")
    print("Filtering Synthetic Samples")
    print(f"{'='*50}")
    print(f"  Input: {len(synthetic_df)} samples")
    
    feature_cols = [c for c in synthetic_df.columns if c != label_col]
    numeric_cols = synthetic_df[feature_cols].select_dtypes(include=[np.number]).columns.tolist()
    
    if not numeric_cols:
        return synthetic_df, {'input': len(synthetic_df), 'output': len(synthetic_df)}
    
    stats = {'input': len(synthetic_df), 'per_class': {}}
    filtered_dfs = []
    
    for label in synthetic_df[label_col].unique():
        syn_class = synthetic_df[synthetic_df[label_col] == label].copy()
        real_class = real_df[real_df[label_col] == label]
        
        initial = len(syn_class)
        print(f"\n  Class '{label}': {initial} synthetic samples")
        
        if len(real_class) < 5:
            # Not enough real data to filter, keep all
            filtered_dfs.append(syn_class)
            stats['per_class'][label] = {'input': initial, 'output': initial}
            continue
        
        # Filter 1: Nearest-neighbor distance (keep top 80% closest to real data)
        try:
            scaler = StandardScaler()
            X_real = scaler.fit_transform(real_class[numeric_cols].fillna(0))
            X_syn = scaler.transform(syn_class[numeric_cols].fillna(0))
            
            nn = NearestNeighbors(n_neighbors=1, metric='euclidean')
            nn.fit(X_real)
            distances, _ = nn.kneighbors(X_syn)
            distances = distances.flatten()
            
            # Keep top 80% of synthetic samples (closest to real data)
            # This is more robust than using real data internal distances
            threshold = np.percentile(distances, 80)
            
            mask = distances <= threshold
            syn_class = syn_class[mask].copy()
            print(f"    After NN filter: {len(syn_class)} ({len(syn_class)/initial*100:.1f}%)")
        except Exception as e:
            print(f"    NN filter skipped: {e}")
        
        # Filter 2: Feature bounds (remove extreme outliers - very lenient)
        try:
            cols_to_check = numeric_cols[:5]  # Only check top 5 features
            for col in cols_to_check:
                if col not in real_class.columns or len(syn_class) == 0:
                    continue
                q_low = real_class[col].quantile(0.001)  # Very lenient: 0.1th percentile
                q_high = real_class[col].quantile(0.999)  # Very lenient: 99.9th percentile
                margin = (q_high - q_low) * 0.5  # 50% margin
                syn_class = syn_class[
                    (syn_class[col] >= q_low - margin) & 
                    (syn_class[col] <= q_high + margin)
                ]
            print(f"    After bounds filter: {len(syn_class)} ({len(syn_class)/initial*100:.1f}%)")
        except Exception as e:
            print(f"    Bounds filter skipped: {e}")
        
        # Cap samples if specified
        if max_samples_per_class and len(syn_class) > max_samples_per_class:
            syn_class = syn_class.sample(n=max_samples_per_class, random_state=42)
            print(f"    After capping: {len(syn_class)}")
        
        if len(syn_class) > 0:
            filtered_dfs.append(syn_class)
        
        stats['per_class'][label] = {'input': initial, 'output': len(syn_class)}
    
    if filtered_dfs:
        result = pd.concat(filtered_dfs, ignore_index=True)
        stats['output'] = len(result)
        print(f"\n  ✅ Total filtered: {len(result)} samples ({len(result)/stats['input']*100:.1f}% retained)")
        return result, stats
    
    return pd.DataFrame(), stats


def _compute_flow_signature(row: pd.Series, signature_cols: List[str], precision: int = 3) -> str:
    """
    Compute a lightweight hash signature for a flow based on key features.
    Uses rounding to group near-duplicate flows together.
    Higher precision = more conservative (fewer duplicates detected).
    """
    values = []
    for col in signature_cols:
        if col in row.index:
            val = row[col]
            if pd.isna(val):
                values.append("nan")
            elif isinstance(val, (int, float)):
                # Round to specified precision
                values.append(str(round(val, precision)))
            else:
                values.append(str(val))
    return "|".join(values)


def _remove_duplicate_signatures_conservative(
    class_df: pd.DataFrame,
    label_col: str,
    min_final_size: int,
    near_duplicate_precision: int = 3,
    signature_cols: Optional[List[str]] = None
) -> Tuple[pd.DataFrame, int]:
    """
    Remove TRUE duplicate flows based on flow signature.
    Very conservative - uses high precision to only catch exact/near-exact duplicates.
    
    NEVER reduces below min_final_size.
    Expected reduction: 5-20% max.
    
    Returns:
        Tuple of (deduplicated DataFrame, number removed)
    """
    if len(class_df) == 0:
        return class_df, 0
    
    original_count = len(class_df)
    
    # If already at or below minimum, don't remove anything
    if original_count <= min_final_size:
        return class_df, 0
    
    feature_cols = [c for c in class_df.columns if c != label_col]
    numeric_cols = class_df[feature_cols].select_dtypes(include=[np.number]).columns.tolist()
    
    # Use core flow features for signature (fewer = more conservative)
    if signature_cols is None:
        signature_cols = []
        priority_features = [
            'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
            'Flow Duration', 'Dst Port', 'Protocol'
        ]
        for feat in priority_features:
            if feat in numeric_cols or feat in class_df.columns:
                signature_cols.append(feat)
    
    if not signature_cols:
        return class_df, 0
    
    # Compute signatures with specified precision
    signatures = class_df.apply(
        lambda row: _compute_flow_signature(row, signature_cols, precision=near_duplicate_precision), 
        axis=1
    )
    
    # Identify duplicates
    seen = {}
    duplicate_indices = []
    for i, sig in enumerate(signatures):
        if sig in seen:
            duplicate_indices.append(i)
        else:
            seen[sig] = i
    
    # Calculate how many we can remove while respecting minimum
    max_removable = original_count - min_final_size
    n_duplicates = len(duplicate_indices)
    
    # Only remove up to max_removable duplicates
    n_to_remove = min(n_duplicates, max_removable)
    
    if n_to_remove == 0:
        return class_df, 0
    
    # Remove only the first n_to_remove duplicates
    remove_set = set(duplicate_indices[:n_to_remove])
    keep_mask = [i not in remove_set for i in range(len(class_df))]
    
    deduplicated = class_df[keep_mask].copy()
    removed = original_count - len(deduplicated)
    
    return deduplicated, removed


def _density_based_reduction_conservative(
    class_df: pd.DataFrame,
    label_col: str,
    min_final_size: int,
    density_prune_fraction: float = 0.10
) -> Tuple[pd.DataFrame, int]:
    """
    Remove ONLY highly redundant samples from dense regions.
    Very conservative - removes at most density_prune_fraction (10% default).
    
    NEVER reduces below min_final_size.
    Always preserves outliers and edge samples.
    
    Returns:
        Tuple of (reduced DataFrame, number removed)
    """
    original_count = len(class_df)
    
    # If already at or below minimum, don't remove anything
    if original_count <= min_final_size:
        return class_df, 0
    
    feature_cols = [c for c in class_df.columns if c != label_col]
    numeric_cols = class_df[feature_cols].select_dtypes(include=[np.number]).columns.tolist()
    
    if not numeric_cols or len(class_df) < 1000:
        return class_df, 0
    
    try:
        # Standardize features
        scaler = StandardScaler()
        X = scaler.fit_transform(class_df[numeric_cols].fillna(0))
        
        # Compute local density using kNN
        k = min(15, max(5, len(X) // 500))
        
        nn = NearestNeighbors(n_neighbors=k, metric='euclidean')
        nn.fit(X)
        distances, _ = nn.kneighbors(X)
        
        # Local density = inverse of mean distance to k neighbors
        mean_distances = distances.mean(axis=1)
        mean_distances = np.maximum(mean_distances, 1e-10)
        local_density = 1.0 / mean_distances
        
        # Only target the TOP 10% densest samples (most redundant)
        density_threshold = np.percentile(local_density, 90)
        very_high_density_mask = local_density >= density_threshold
        very_high_density_indices = np.where(very_high_density_mask)[0]
        
        if len(very_high_density_indices) == 0:
            return class_df, 0
        
        # Sort by density (highest first = most redundant)
        sorted_indices = very_high_density_indices[
            np.argsort(local_density[very_high_density_indices])[::-1]
        ]
        
        # Calculate how many we can remove:
        # 1. Never exceed density_prune_fraction of original
        # 2. Never go below min_final_size
        max_by_fraction = int(original_count * density_prune_fraction)
        max_by_threshold = original_count - min_final_size
        max_remove = min(max_by_fraction, max_by_threshold)
        
        # Also limit to half of the very high density samples
        max_remove = min(max_remove, len(sorted_indices) // 2)
        
        if max_remove <= 0:
            return class_df, 0
        
        # Remove the most redundant samples
        remove_indices = set(sorted_indices[:max_remove])
        keep_mask = [i not in remove_indices for i in range(len(class_df))]
        
        reduced = class_df.iloc[keep_mask].copy()
        removed = original_count - len(reduced)
        
        return reduced, removed
        
    except Exception as e:
        print(f"    Density reduction skipped: {e}")
        return class_df, 0


def undersample_majority_classes(
    df: pd.DataFrame,
    label_col: str = "Label",
    target_per_class: int = 5000,  # IGNORED - kept for API compatibility only
    method: str = "hybrid"  # Only hybrid is used
) -> pd.DataFrame:
    """
    Conservative hybrid undersampling that ONLY removes true redundancy.
    
    This method:
    1. NEVER cuts classes to a fixed target size
    2. Enforces strict minimum retention (70% or 40,000 samples)
    3. Only removes true duplicates and highly redundant dense samples
    4. Preserves natural class distributions and all attack patterns
    
    Configuration:
        minimum_keep_ratio = 0.70     # Keep at least 70% of each class
        minimum_keep_absolute = 40000 # Never reduce below 40,000 samples
        near_duplicate_precision = 3  # High precision = conservative dedup
        density_prune_fraction = 0.10 # Remove at most 10% via density
    
    Args:
        df: DataFrame to undersample
        label_col: Label column name
        target_per_class: IGNORED (kept for backward compatibility)
        method: IGNORED (always uses hybrid)
        
    Returns:
        DataFrame with redundancy removed (structure unchanged)
    """
    # ═══════════════════════════════════════════════════════════════
    # CONFIGURATION - Strict minimum retention rules
    # ═══════════════════════════════════════════════════════════════
    minimum_keep_ratio = 0.70       # Keep at least 70% of a class
    minimum_keep_absolute = 40000   # Never reduce below this
    near_duplicate_precision = 3    # Rounding precision for signatures
    density_prune_fraction = 0.10   # Prune at most 10% via density
    
    print(f"\n{'='*70}")
    print("CONSERVATIVE HYBRID UNDERSAMPLING (Redundancy Removal Only)")
    print(f"{'='*70}")
    print(f"\n⚙️  Configuration:")
    print(f"    minimum_keep_ratio = {minimum_keep_ratio} (keep ≥70%)")
    print(f"    minimum_keep_absolute = {minimum_keep_absolute:,} (never below this)")
    print(f"    near_duplicate_precision = {near_duplicate_precision}")
    print(f"    density_prune_fraction = {density_prune_fraction} (≤10% density removal)")
    
    class_counts = df[label_col].value_counts()
    
    print(f"\n📊 Original Distribution:")
    total_original = 0
    for cls in sorted(class_counts.index, key=lambda x: class_counts[x], reverse=True):
        cnt = class_counts[cls]
        # Calculate minimum threshold for this class
        if cnt > minimum_keep_absolute:
            min_keep = max(int(cnt * minimum_keep_ratio), minimum_keep_absolute)
        else:
            min_keep = cnt  # Keep all if below absolute minimum
        print(f"    {cls}: {cnt:,} (min retain: {min_keep:,})")
        total_original += cnt
    print(f"    {'─'*40}")
    print(f"    Total: {total_original:,}")
    
    result_dfs = []
    total_duplicates_removed = 0
    total_density_removed = 0
    
    for label in df[label_col].unique():
        class_df = df[df[label_col] == label].copy()
        original_count = len(class_df)
        
        # ═══════════════════════════════════════════════════════════
        # Calculate minimum final size for this class
        # ═══════════════════════════════════════════════════════════
        if original_count > minimum_keep_absolute:
            min_final_size = max(
                int(original_count * minimum_keep_ratio),
                minimum_keep_absolute
            )
        else:
            # Class is small - keep ALL samples
            min_final_size = original_count
        
        # Check if class is protected (below absolute minimum)
        is_protected = original_count <= minimum_keep_absolute
        
        if is_protected:
            result_dfs.append(class_df)
            print(f"\n  🔒 {label}: {original_count:,} -> {original_count:,} (protected - below {minimum_keep_absolute:,})")
            continue
        
        print(f"\n  📉 {label}: Processing {original_count:,} samples (min: {min_final_size:,})...")
        
        dup_removed = 0
        density_removed = 0
        threshold_applied = False
        
        # ═══════════════════════════════════════════════════════════
        # Step A: Remove TRUE duplicates (conservative)
        # ═══════════════════════════════════════════════════════════
        class_df, dup_removed = _remove_duplicate_signatures_conservative(
            class_df, label_col,
            min_final_size=min_final_size,
            near_duplicate_precision=near_duplicate_precision
        )
        total_duplicates_removed += dup_removed
        
        # Check if we hit the minimum threshold
        if len(class_df) <= min_final_size:
            threshold_applied = True
        
        # ═══════════════════════════════════════════════════════════
        # Step B: Light density reduction (only if still above minimum)
        # ═══════════════════════════════════════════════════════════
        if len(class_df) > min_final_size:
            class_df, density_removed = _density_based_reduction_conservative(
                class_df, label_col,
                min_final_size=min_final_size,
                density_prune_fraction=density_prune_fraction
            )
            total_density_removed += density_removed
            
            if len(class_df) <= min_final_size:
                threshold_applied = True
        
        final_count = len(class_df)
        reduction_pct = (1 - final_count / original_count) * 100
        
        # Logging
        print(f"      Duplicates removed: {dup_removed:,}")
        print(f"      Dense redundant removed: {density_removed:,}")
        print(f"      Final: {original_count:,} -> {final_count:,} ({reduction_pct:.1f}% reduced)")
        if threshold_applied:
            print(f"      ⚠️  Minimum threshold applied (kept ≥{min_final_size:,})")
        
        result_dfs.append(class_df)
    
    result = pd.concat(result_dfs, ignore_index=True)
    result = result.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle
    
    # ═══════════════════════════════════════════════════════════════
    # Final Summary
    # ═══════════════════════════════════════════════════════════════
    print(f"\n{'─'*70}")
    print("📋 REDUCTION SUMMARY:")
    print(f"    Total duplicates removed: {total_duplicates_removed:,}")
    print(f"    Total dense redundant removed: {total_density_removed:,}")
    print(f"    Total removed: {total_duplicates_removed + total_density_removed:,}")
    total_reduction = (1 - len(result) / total_original) * 100
    print(f"    Overall reduction: {total_reduction:.1f}%")
    
    print(f"\n📊 Final Distribution:")
    final_counts = result[label_col].value_counts()
    for cls in sorted(final_counts.index, key=lambda x: final_counts[x], reverse=True):
        orig = class_counts[cls]
        final = final_counts[cls]
        change_pct = (1 - final / orig) * 100
        print(f"    {cls}: {final:,} (was {orig:,}, -{change_pct:.1f}%)")
    print(f"    {'─'*40}")
    print(f"    Total: {len(result):,}")
    
    # Calculate imbalance ratio
    imbalance = final_counts.max() / final_counts.min()
    print(f"\n  ✅ Final dataset: {len(result):,} samples (imbalance ratio: {imbalance:.1f}x)")
    
    return result


def create_balanced_dataset(
    original_df: pd.DataFrame,
    synthetic_df: pd.DataFrame,
    label_col: str = "Label",
    target_per_class: int = 5000  # Kept for API compatibility
) -> pd.DataFrame:
    """
    Combine original and synthetic data to create an augmented dataset.
    
    This updated version:
    - Augments minority classes with synthetic data to boost their counts
    - Does NOT cut majority classes to a fixed target
    - Preserves the natural (but improved) class distribution
    
    Args:
        original_df: Original real data (after hybrid undersampling)
        synthetic_df: Filtered synthetic data for minority classes
        label_col: Label column name
        target_per_class: Reference target (used to determine how much synthetic to add)
        
    Returns:
        Augmented DataFrame
    """
    print(f"\n{'='*60}")
    print("CREATING AUGMENTED DATASET")
    print(f"{'='*60}")
    
    result_dfs = []
    all_labels = set(original_df[label_col].unique())
    if not synthetic_df.empty:
        all_labels |= set(synthetic_df[label_col].unique())
    
    # Get class counts from original
    original_counts = original_df[label_col].value_counts()
    median_count = original_counts.median()
    
    print(f"\n  Reference target: {target_per_class:,}")
    print(f"  Median class size: {median_count:,.0f}")
    
    for label in sorted(all_labels):
        real_class = original_df[original_df[label_col] == label].copy()
        syn_class = synthetic_df[synthetic_df[label_col] == label] if not synthetic_df.empty else pd.DataFrame()
        
        real_count = len(real_class)
        syn_available = len(syn_class) if not syn_class.empty else 0
        
        # Determine if this class needs augmentation
        # Augment if below the reference target
        if real_count < target_per_class and syn_available > 0:
            # Add synthetic data to boost minority classes
            syn_needed = min(target_per_class - real_count, syn_available)
            syn_to_add = syn_class.sample(n=syn_needed, random_state=42) if syn_needed < syn_available else syn_class
            combined = pd.concat([real_class, syn_to_add], ignore_index=True)
            syn_used = len(syn_to_add)
        else:
            # Keep all real data as-is (majority classes not cut)
            combined = real_class
            syn_used = 0
        
        result_dfs.append(combined)
        
        if syn_used > 0:
            print(f"  {label}: {real_count:,} real + {syn_used:,} synthetic = {len(combined):,} ⬆️")
        else:
            print(f"  {label}: {real_count:,} (unchanged)")
    
    result = pd.concat(result_dfs, ignore_index=True)
    result = result.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Final stats
    final_counts = result[label_col].value_counts()
    imbalance = final_counts.max() / final_counts.min()
    
    print(f"\n  ✅ Total: {len(result):,} samples")
    print(f"  📊 Imbalance ratio: {imbalance:.1f}x")
    
    return result


def plot_data_balance(
    original_df: pd.DataFrame,
    balanced_df: pd.DataFrame,
    label_col: str = "Label",
    save_path: Optional[str] = None
):
    """
    Plot before/after class distribution comparison.
    """
    import matplotlib.pyplot as plt
    
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    
    # Original distribution
    orig_counts = original_df[label_col].value_counts().sort_index()
    axes[0].bar(range(len(orig_counts)), orig_counts.values, color='steelblue', alpha=0.8)
    axes[0].set_xticks(range(len(orig_counts)))
    axes[0].set_xticklabels(orig_counts.index, rotation=45, ha='right')
    axes[0].set_title('Original Dataset', fontsize=14, fontweight='bold')
    axes[0].set_xlabel('Class')
    axes[0].set_ylabel('Sample Count')
    axes[0].set_yscale('log')
    for i, v in enumerate(orig_counts.values):
        axes[0].text(i, v * 1.1, str(v), ha='center', va='bottom', fontsize=9)
    
    # Balanced distribution
    bal_counts = balanced_df[label_col].value_counts().sort_index()
    axes[1].bar(range(len(bal_counts)), bal_counts.values, color='forestgreen', alpha=0.8)
    axes[1].set_xticks(range(len(bal_counts)))
    axes[1].set_xticklabels(bal_counts.index, rotation=45, ha='right')
    axes[1].set_title('Balanced Dataset (After CTGAN + Filtering)', fontsize=14, fontweight='bold')
    axes[1].set_xlabel('Class')
    axes[1].set_ylabel('Sample Count')
    for i, v in enumerate(bal_counts.values):
        axes[1].text(i, v * 1.02, str(v), ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    
    if save_path:
        plt.savefig(save_path, dpi=150, bbox_inches='tight')
        print(f"  Saved plot to {save_path}")
    
    plt.show()
    return fig


def plot_synthetic_quality(
    quality_scores: Dict[str, float],
    save_path: Optional[str] = None
):
    """
    Plot synthetic data quality scores per class.
    """
    import matplotlib.pyplot as plt
    
    labels = list(quality_scores.keys())
    scores = list(quality_scores.values())
    
    fig, ax = plt.subplots(figsize=(10, 5))
    
    colors = ['green' if s >= 0.7 else 'orange' if s >= 0.5 else 'red' for s in scores]
    bars = ax.bar(labels, scores, color=colors, alpha=0.8, edgecolor='black')
    
    ax.axhline(y=0.7, color='green', linestyle='--', linewidth=2, label='High Quality (≥0.7)')
    ax.axhline(y=0.5, color='orange', linestyle='--', linewidth=2, label='Acceptable (≥0.5)')
    
    ax.set_xlabel('Class', fontsize=12)
    ax.set_ylabel('Quality Score', fontsize=12)
    ax.set_title('CTGAN Synthetic Data Quality by Class', fontsize=14, fontweight='bold')
    ax.set_ylim(0, 1)
    ax.legend(loc='lower right')
    
    for bar, score in zip(bars, scores):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02, 
                f'{score:.3f}', ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    if save_path:
        plt.savefig(save_path, dpi=150, bbox_inches='tight')
        print(f"  Saved plot to {save_path}")
    
    plt.show()
    return fig


def plot_feature_distributions(
    real_df: pd.DataFrame,
    synthetic_df: pd.DataFrame,
    label_col: str = "Label",
    n_features: int = 6,
    save_path: Optional[str] = None
):
    """
    Compare feature distributions between real and synthetic data.
    """
    import matplotlib.pyplot as plt
    
    feature_cols = [c for c in real_df.columns if c != label_col]
    numeric_cols = real_df[feature_cols].select_dtypes(include=[np.number]).columns.tolist()
    
    # Select top features by variance
    variances = real_df[numeric_cols].var().sort_values(ascending=False)
    top_features = variances.head(n_features).index.tolist()
    
    fig, axes = plt.subplots(2, 3, figsize=(15, 10))
    axes = axes.flatten()
    
    for idx, feature in enumerate(top_features):
        ax = axes[idx]
        
        real_vals = real_df[feature].dropna()
        syn_vals = synthetic_df[feature].dropna() if feature in synthetic_df.columns else []
        
        ax.hist(real_vals, bins=50, alpha=0.6, label='Real', color='steelblue', density=True)
        if len(syn_vals) > 0:
            ax.hist(syn_vals, bins=50, alpha=0.6, label='Synthetic', color='coral', density=True)
        
        ax.set_title(feature, fontsize=11, fontweight='bold')
        ax.legend(fontsize=9)
        ax.set_xlabel('Value')
        ax.set_ylabel('Density')
    
    plt.suptitle('Feature Distribution Comparison: Real vs Synthetic', fontsize=14, fontweight='bold')
    plt.tight_layout()
    
    if save_path:
        plt.savefig(save_path, dpi=150, bbox_inches='tight')
        print(f"  Saved plot to {save_path}")
    
    plt.show()
    return fig


# Legacy function for backward compatibility
def train_and_sample_ctgan(df, label_value, 
                           sample_sizes=[1000, 800, 500, 300, 200, 100],
                           runs=5, quality_threshold=0.7):
    """Legacy wrapper - use train_and_generate_ctgan instead."""
    synthetic, quality = train_and_generate_ctgan(
        df, label_value, 
        generate_samples=sample_sizes[0] if sample_sizes else 1000
    )
    summary = pd.DataFrame([{
        'Label': label_value,
        'Size': len(synthetic),
        'Quality': quality
    }])
    return synthetic, summary

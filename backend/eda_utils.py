import os
import pickle
import warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from IPython.display import display
from sklearn.feature_selection import mutual_info_classif
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, recall_score, roc_auc_score
import xgboost as xgb

"""
Loads and concatenates multiple CSV files from a folder.
Args:
    folder_path (str): Path to the folder containing the CSVs.
    filenames (list): List of CSV filenames.
Returns:
    pd.DataFrame: Combined DataFrame.
"""
def load_and_concatenate_datasets(folder_path, filenames):
    dfs = []
    for name in filenames:
        file_path = os.path.join(folder_path, name)
        try:
            df = pd.read_csv(file_path)
            print(f"Loaded {name} with shape {df.shape}")
            dfs.append(df)
        except Exception as e:
            print(f"Failed to load {name}: {e}")
    return pd.concat(dfs, ignore_index=True)

"""
Inspects NaNs, infs, and constant columns in the DataFrame.
Args:
    df (pd.DataFrame): DataFrame to inspect.
Returns:
    dict: Dictionary with summary.
"""
def inspect_missing_and_constant(df):
    summary = {}
    summary['total_rows'] = df.shape[0]
    summary['total_columns'] = df.shape[1]
    summary['nan_count'] = df.isna().sum().sort_values(ascending=False)
    summary['inf_count'] = np.isinf(df.select_dtypes(include=[np.number])).sum().sort_values(ascending=False)
    summary['constant_columns'] = [col for col in df.columns if df[col].nunique() == 1]
    return summary

"""
Prints the value counts and percentage of each class.
"""
def check_class_distribution(df, label_col='Label'):
    class_counts = df[label_col].value_counts()
    total = class_counts.sum()
    print("Class Distribution:")
    print(class_counts)
    print("\nPercentage:")
    print((class_counts / total * 100).round(2))

"""
Gets pairs of highly correlated features above a threshold.
"""
def get_highly_correlated_pairs(df, threshold=0.9):
    # Keep only numeric columns
    numeric_df = df.select_dtypes(include=[np.number])
    
    # Compute absolute correlation
    corr_matrix = numeric_df.corr().abs()
    
    # Upper triangle of the correlation matrix
    upper_tri = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
    
    # Stack and filter by threshold
    high_corr = upper_tri.stack().reset_index()
    high_corr.columns = ['Feature 1', 'Feature 2', 'Correlation']
    high_corr_sorted = high_corr[high_corr['Correlation'] >= threshold].sort_values(by='Correlation', ascending=False)
    
    return high_corr_sorted, corr_matrix

import seaborn as sns
import matplotlib.pyplot as plt

"""
Plots a heatmap of the correlation matrix.
"""
def plot_correlation_heatmap(corr_matrix, figsize=(15,12)):
    plt.figure(figsize=figsize)
    sns.heatmap(corr_matrix, cmap='coolwarm', vmin=-1, vmax=1)
    plt.title('Correlation Heatmap of Numeric Features')
    plt.tight_layout()
    plt.show()

"""
Drops highly correlated features above a threshold.
"""
def drop_highly_correlated(df, corr_matrix, threshold=0.99):
    # Keep only numeric columns
    numeric_df = df.select_dtypes(include=[np.number])
    
    # Compute upper triangle
    upper_tri = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))

    # Identify columns to drop
    to_drop = [column for column in upper_tri.columns if any(upper_tri[column] > threshold)]

    # Drop columns
    reduced_df = df.drop(columns=to_drop)
    return reduced_df, to_drop

"""
Inspects non-numeric columns in the DataFrame.
"""
def inspect_non_numeric_columns(df):
    non_numeric = df.select_dtypes(exclude=['number'])
    print(f"Non-numeric columns found: {non_numeric.shape[1]}")
    if not non_numeric.empty:
        print("Columns:")
        print(non_numeric.columns.tolist())
        display(non_numeric.head())
    else:
        print("No non-numeric columns remaining.")



"""
Creates or loads a permanent LabelEncoder for y.
Ensures consistent mapping across entire FYP pipeline.
"""
def prepare_label_encoder(df, label_col="Label", save_path="encoders/label_encoder.pkl"):
    """
    Creates or loads a permanent LabelEncoder for y.
    Ensures consistent mapping across entire FYP pipeline.
    """

    os.makedirs(os.path.dirname(save_path), exist_ok=True)

    # If encoder already exists → load it (consistent mapping)
    if os.path.exists(save_path):
        with open(save_path, "rb") as f:
            le = pickle.load(f)
        print("Loaded existing label encoder from:", save_path)

        # Check if dataframe contains unseen labels (shouldn't happen)
        unique_df_labels = set(df[label_col].unique())
        unknown = unique_df_labels - set(le.classes_)
        if unknown:
            print("⚠ Warning: New/unseen labels detected:", unknown)
        y = le.transform(df[label_col])
        return y, le

    # Else create new encoder
    from sklearn.preprocessing import LabelEncoder
    le = LabelEncoder()
    y = le.fit_transform(df[label_col])

    # Save encoder forever
    with open(save_path, "wb") as f:
        pickle.dump(le, f)

    print("Saved NEW label encoder to:", save_path)
    print("\n🧭 Label mapping:")
    for cls, idx in zip(le.classes_, le.transform(le.classes_)):
        print(f"{cls} → {idx}")

    return y, le


# ========================================================================================
#  Feature Selection Functions
# ========================================================================================

"""
Hybrid Dst Port bucketing: 
- critical security services manually (SSH, DNS, HTTP, HTTPS)
- everything else automatically by IANA range
"""
def bucket_dst_port(port):
    try:
        p = int(port)
    except:
        return "other"

    # Semantic buckets (important services)
    if p == 22: return "ssh"
    if p in [80, 443, 8080]: return "web"
    if p == 53: return "dns"

    # IANA automatic fallback
    if 0 <= p <= 1023: return "well_known"
    if 1024 <= p <= 49151: return "registered"
    if 49152 <= p <= 65535: return "ephemeral"

    return "other"

"""
Main Feature Selection Function
"""
def feature_selection_pipeline(
    df,
    label_col="Label",
    dst_port_col="Dst Port",
    n_list=[5,10,15,20,25,30,'all'],
    RANDOM_SEED = 42,
    label_encoder_path="encoders/label_encoder.pkl"
):
    warnings.filterwarnings('ignore')
    sns.set(style='whitegrid')

    df = df.copy()

    # ------------------------------------------
    # APPLY DST PORT BUCKETING (Hybrid)
    # ------------------------------------------
    if dst_port_col in df.columns:
        df[dst_port_col] = df[dst_port_col].apply(bucket_dst_port)

    # ------------------------------------------
    # LABEL ENCODE CATEGORICAL FEATURES
    # Protocol + flags + bucketted ports
    # ------------------------------------------
    categorical_cols = [
        dst_port_col,
        "Protocol",
        "FIN Flag Cnt",
        "SYN Flag Cnt",
        "RST Flag Cnt",
        "ACK Flag Cnt",
        "Bwd PSH Flags",
        "Bwd URG Flags",
    ]
    categorical_cols = [c for c in categorical_cols if c in df.columns]

    encoders = {}
    for col in categorical_cols:
        df[col] = df[col].astype(str)
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        encoders[col] = le

    # ------------------------------------------
    # ENCODE LABEL COLUMN (use saved encoder)
    # ------------------------------------------
    os.makedirs(os.path.dirname(label_encoder_path), exist_ok=True)
    if os.path.exists(label_encoder_path):
        with open(label_encoder_path, "rb") as f:
            label_le = pickle.load(f)
        print(f"Using existing label encoder from: {label_encoder_path}")
    else:
        label_le = LabelEncoder()
        label_le.fit(df[label_col])
        with open(label_encoder_path, "wb") as f:
            pickle.dump(label_le, f)
        print(f"Created new label encoder: {label_encoder_path}")
    
    # Encode labels
    y = label_le.transform(df[label_col])
    
    # ------------------------------------------
    # SEPARATE X
    # ------------------------------------------
    X = df.drop(columns=[label_col])

    feature_names = X.columns.tolist()
    print(f"Total features available: {len(feature_names)}")

    # ------------------------------------------
    # STANDARDIZE NUMERIC FEATURES (for MI only)
    # ------------------------------------------
    numeric_cols = X.select_dtypes(include=[np.number]).columns
    scaler = StandardScaler()
    X_scaled = X.copy()
    X_scaled[numeric_cols] = scaler.fit_transform(X[numeric_cols])

    # ================================================================
    # 3) MUTUAL INFORMATION RANKING
    # ================================================================
    print("Computing Mutual Information (MI)...")
    mi = mutual_info_classif(X_scaled, y, random_state=RANDOM_SEED, n_neighbors=3)
    mi_series = pd.Series(mi, index=feature_names).sort_values(ascending=False)

    # ================================================================
    # 4) XGBOOST GPU FEATURE IMPORTANCE
    # ================================================================
    print("Training quick GPU XGBoost for feature importance...")

    num_classes = len(np.unique(y))
    is_multiclass = num_classes > 2

    xgb_params = {
        "objective": "multi:softprob" if is_multiclass else "binary:logistic",
        "tree_method": "hist",
        "device": "cuda",
        "verbosity": 0,
        "n_estimators": 300,
        "max_depth": 6,
        "learning_rate": 0.1,
        "random_state": RANDOM_SEED,
    }

    X_train_tmp, X_val_tmp, y_train_tmp, y_val_tmp = train_test_split(X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y)

    model_full = xgb.XGBClassifier(**xgb_params)
    model_full.fit(X_train_tmp, y_train_tmp)

    # Extract booster importance (gain)
    booster = model_full.get_booster()
    fscore = booster.get_score(importance_type='gain')

    # Handle both feature name formats (actual names or f0, f1, etc.)
    gain_dict = {}
    for k, v in fscore.items():
        if k in feature_names:
            gain_dict[k] = v
        elif k.startswith('f') and k[1:].isdigit():
            idx = int(k[1:])
            if idx < len(feature_names):
                gain_dict[feature_names[idx]] = v
    
    gain_series = pd.Series(gain_dict).reindex(feature_names).fillna(0).sort_values(ascending=False)

    # ================================================================
    # 5) COMBINE MI + XGB RANKS
    # ================================================================
    print("Combining MI and XGB ranks...")
    mi_rank = mi_series.rank(ascending=False)
    xgb_rank = gain_series.rank(ascending=False)
    combined_rank = (mi_rank + xgb_rank) / 2

    rank_df = pd.DataFrame({
        "MI": mi_series,
        "XGB_gain": gain_series,
        "MI_rank": mi_rank,
        "XGB_rank": xgb_rank,
        "combined_rank": combined_rank
    }).sort_values("combined_rank")

    print("\nTop 20 features:")
    display(rank_df.head(20))

    ordered_features = rank_df.index.tolist()

    # ================================================================
    # 6) TRAIN XGB USING TOP N FEATURES
    # ================================================================
    eval_params = xgb_params.copy()
    eval_params["n_estimators"] = 600  # Override for evaluation
    
    def evaluate_n_features(selected_features):
        X_tr, X_te, y_tr, y_te = train_test_split(X[selected_features], y, test_size=0.2,
                             random_state=RANDOM_SEED, stratify=y)

        model = xgb.XGBClassifier(**eval_params)
        model.fit(X_tr, y_tr)

        y_pred = model.predict(X_te)
        y_prob = model.predict_proba(X_te)

        acc = accuracy_score(y_te, y_pred)
        rec = recall_score(
            y_te, y_pred,
            average="macro" if is_multiclass else "binary",
            zero_division=0
        )
        auc = roc_auc_score(
            y_te, y_prob,
            multi_class="ovr" if is_multiclass else "raise"
        )

        return acc, rec, auc

    results = []
    for n in n_list:
        if n == "all":
            selected = ordered_features
            n_real = len(ordered_features)
        else:
            selected = ordered_features[:n]
            n_real = n

        print(f"Training with top {n_real} features...")
        acc, rec, auc = evaluate_n_features(selected)

        results.append({
            "n_features": n_real,
            "accuracy": acc,
            "recall": rec,
            "auc": auc
        })

    results_df = pd.DataFrame(results).set_index("n_features")
    print("\nPerformance table:")
    display(results_df)

    # ================================================================
    # 7) PLOTS
    # ================================================================
    plt.figure(figsize=(10,6))
    plt.plot(results_df.index, results_df["accuracy"], marker="o", label="Accuracy")
    plt.plot(results_df.index, results_df["recall"], marker="o", label="Recall")
    plt.plot(results_df.index, results_df["auc"], marker="o", label="AUC")
    plt.xlabel("Number of Features")
    plt.ylabel("Score")
    plt.title("Performance vs Number of Features (XGBoost GPU)")
    plt.legend()
    plt.grid(True)
    plt.show()

    # ================================================================
    # 8) RECOMMEND BEST N BY <1% GAIN RULE
    # ================================================================
    print("\nDetermining optimal N using <1% improvement rule...")

    guidance = {}
    rows = results_df.sort_index()

    for idx, row in rows.iterrows():
        next_n = idx + 5
        if next_n in rows.index:
            acc_gain = rows.loc[next_n, "accuracy"] - row["accuracy"]
            rec_gain = rows.loc[next_n, "recall"] - row["recall"]
            guidance[idx] = {"acc_gain": acc_gain, "rec_gain": rec_gain}

    guidance_df = pd.DataFrame(guidance).T
    print("\n+5 feature improvement table:")
    display(guidance_df)

    # Rule: choose smallest N where acc_gain < 0.01 AND rec_gain < 0.01
    candidates = [n for n, g in guidance.items()
                  if g["acc_gain"] < 0.01 and g["rec_gain"] < 0.01]

    if candidates:
        recommended_n = min(candidates)
        print(f"\n📌 Recommended N: {recommended_n} features")
    else:
        recommended_n = None
        print("\n⚠ No clear best N; check plots for elbow point.")

    return {
        "rank_df": rank_df,
        "results_df": results_df,
        "guided_df": guidance_df,
        "recommended_n": recommended_n,
        "ordered_features": ordered_features
    }
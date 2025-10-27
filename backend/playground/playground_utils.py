import pandas as pd
import numpy as np
import os

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

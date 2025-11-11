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

"""Make predictions using all three models and save results"""
def predict(csv_path):
    try:
        # Create output directory if it doesn't exist
        output_dir = "../output"
        os.makedirs(output_dir, exist_ok=True)
        
        # Get feature mappings
        features_20, csv_to_model = get_feature_mappings()
        
        # Load full data to preserve all columns
        df_full = pd.read_csv(csv_path)
        
        # Load scaler
        scaler = joblib.load("scalers/benign_robust_scaler.pkl")
        
        # Process features for prediction
        df_features = df_full.copy()
        
        # Ensure we have all features in the correct format
        for feature in features_20:
            csv_name = next((k for k, v in csv_to_model.items() if v == feature), feature)
            if csv_name in df_features.columns:
                df_features = df_features.rename(columns={csv_name: feature})
        
        # Clean features before scaling
        print("Cleaning features...")
        df_features = clean_features(df_features, features_20)
        
        # Scale features (excluding 'Protocol')
        scaled_cols = [col for col in features_20 if col != 'Protocol']
        print("Scaling features...")
        df_features[scaled_cols] = scaler.transform(df_features[scaled_cols])
        
        # Model to column name mapping - easy to add more models here
        model_mapping = {
            'best_xgb_20.json': 'model20',
            'best_xgb_50.json': 'model50',
            'best_xgb_80.json': 'model80'
            # Add more models here, e.g.:
            # 'best_xgb_custom.json': 'modelCustom',
            # 'rf_model.json': 'modelRF'
        }
        
        print("Making predictions...")
        for model_file, column_name in model_mapping.items():
            print(f"Using model: {model_file} -> column: {column_name}")
            model = xgb.XGBClassifier()
            model.load_model(f"models/{model_file}")
            
            # Get predictions
            X = df_features[features_20]
            
            # Additional safety check
            if X.isna().any().any():
                print(f"Warning: NaN values found in features. Filling with 0...")
                X = X.fillna(0)
            
            preds = model.predict(X)
            
            # Add predictions to full dataframe
            df_full[column_name] = preds
        
        # Save results
        output_path = os.path.join(output_dir, f"{os.path.splitext(os.path.basename(csv_path))[0]}_predicted.csv")
        df_full.to_csv(output_path, index=False)
        
        # Print summary
        print(f"\nPrediction Summary for {os.path.basename(csv_path)}:")
        for column_name in model_mapping.values():
            attacks = sum(df_full[column_name] == 1)
            total = len(df_full)
            print(f"{column_name}: {attacks} attacks detected ({attacks/total*100:.2f}%)")
        
        print(f"\nResults saved to: {output_path}")
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

import os
import json
import pandas as pd

def main():
    results_dir = "/home/fyp2025/fyp/backend/gnn_compare"
    models = ["model1", "model2", "model3"]
    tasks = ["binary", "multiclass"]
    
    rows = []
    
    for model_name in models:
        for task in tasks:
            config_filename = f"{model_name}_{task}_config.json"
            config_path = os.path.join(results_dir, config_filename)
            
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r') as f:
                        data = json.load(f)
                    info = data.get('info', {})
                    
                    rows.append({
                        "Model": model_name.upper(),
                        "Task": task.upper(),
                        "Architecture": info.get("arch", "").upper(),
                        "Strategy": info.get("strategy", ""),
                        "Split": info.get("split", ""),
                        "Hidden Dim": info.get("hidden_dim", ""),
                        "Layers": info.get("num_layers", ""),
                        "Test F1": f"{info.get('test_f1', 0.0):.6f}",
                        "Attack Recall": f"{info.get('attack_recall', 0.0):.6f}",
                        "FPR": f"{info.get('fpr', 0.0):.6f}",
                        "Train Time (s)": f"{info.get('training_time', 0.0):.2f}"
                    })
                except Exception as e:
                    print(f"Error reading {config_path}: {e}")
            else:
                rows.append({
                    "Model": model_name.upper(),
                    "Task": task.upper(),
                    "Architecture": "N/A",
                    "Strategy": "N/A",
                    "Split": "N/A",
                    "Hidden Dim": "N/A",
                    "Layers": "N/A",
                    "Test F1": "N/A",
                    "Attack Recall": "N/A",
                    "FPR": "N/A",
                    "Train Time (s)": "N/A"
                })
                
    df = pd.DataFrame(rows)
    
    print("\n================== GNN COMPARE MODELS REPORT ==================")
    print(df.to_string(index=False))
    print("===============================================================")
    
    # Save as Markdown file
    md_path = os.path.join(results_dir, "comparison_report.md")
    with open(md_path, 'w') as f:
        f.write("# GNN Models Comparison Report\n\n")
        f.write(df.to_markdown(index=False))
        f.write("\n\n*Note: N/A indicates the model training outputs are not yet available.*")
        
    print(f"\nSaved markdown report to {md_path}")

if __name__ == "__main__":
    main()

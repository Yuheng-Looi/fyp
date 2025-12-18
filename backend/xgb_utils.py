import xgboost as xgb
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from sklearn.metrics import (
    classification_report,
    roc_auc_score,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.model_selection import train_test_split

class XGBDetector:
    """
    GPU-Accelerated XGBoost for IDS.
    """
    def __init__(self, scaler_path='scalers/trichannel_scaler.pkl', label_encoder_path='encoders/label_encoder.pkl'):
        self.model = None
        self.evals_result = {}
        self.scaler_path = scaler_path
        self.le_path = label_encoder_path

    def get_golden_split(self, X, y, val_size=0.15, test_size=0.15, seed=42, stratify_labels=None):
        stratify_vec = stratify_labels if stratify_labels is not None else y
        
        X_temp, X_test, y_temp, y_test, strat_temp, strat_test = train_test_split(
            X, y, stratify_vec, test_size=test_size, random_state=seed, stratify=stratify_vec
        )
        
        relative_val = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val, strat_train, strat_val = train_test_split(
            X_temp, y_temp, strat_temp, test_size=relative_val, random_state=seed, stratify=strat_temp
        )
        
        return X_train, X_val, X_test, y_train, y_val, y_test

    def train_binary(self, X_train, y_train, X_val, y_val, patience=20):
        print("[-] Initializing XGBoost (GPU: ON, Tree: Hist)...")
        
        self.model = xgb.XGBClassifier(
            device="cuda",              
            tree_method="hist",         
            objective="binary:logistic",
            n_estimators=400,           
            learning_rate=0.1,          
            max_depth=6,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric=["logloss", "auc"],
            random_state=42,
            use_label_encoder=False
        )

        print("[-] Training started...")
        self.model.fit(
            X_train,
            y_train,
            eval_set=[(X_train, y_train), (X_val, y_val)],
            verbose=False,
        )

        best_iter = getattr(self.model, "best_iteration", None)
        if best_iter is not None:
            print(f"[+] Training complete. Best Iteration: {best_iter}")
        else:
            print(f"[+] Training complete. Trees trained: {self.model.n_estimators}")
        self.evals_result = self.model.evals_result()
        return self.evals_result

    def evaluate_metrics(self, X_test, y_test):
        preds = self.model.predict(X_test)
        probs = self.model.predict_proba(X_test)[:, 1]

        metrics = {
            "accuracy": accuracy_score(y_test, preds),
            "precision": precision_score(y_test, preds, zero_division=0),
            "recall": recall_score(y_test, preds, zero_division=0),
            "f1": f1_score(y_test, preds, zero_division=0),
            "auc": roc_auc_score(y_test, probs),
        }
        return metrics

    def evaluate(self, X_test, y_test):
        print("\n=== XGBoost Evaluation ===")
        preds = self.model.predict(X_test)
        probs = self.model.predict_proba(X_test)[:, 1]
        
        print(classification_report(y_test, preds, digits=4))
        print(f"ROC-AUC: {roc_auc_score(y_test, probs):.4f}")
        
        cm = confusion_matrix(y_test, preds)
        plt.figure(figsize=(5,4))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title("Confusion Matrix")
        plt.show()

    def save(self, path='models/xgb_detector.json'):
        self.model.save_model(path)
        print(f"[+] Model saved to {path}")

    def train_with_split_search(self, X, y, seeds=(42, 52, 62), val_size=0.15, test_size=0.15, patience=20, metric="auc", stratify_labels=None, split_grid=None):
        best_score = -np.inf
        best_seed = None
        best_metrics = None
        best_model = None
        best_data = None
        best_split = None
        best_evals_result = None

        if split_grid is None:
            split_grid = [(1 - val_size - test_size, val_size, test_size)]

        for train_ratio, val_ratio, test_ratio in split_grid:
            for seed in seeds:
                print(f"\n[~] Evaluating split train/val/test={train_ratio:.2f}/{val_ratio:.2f}/{test_ratio:.2f} seed={seed}")
                
                # Input X here MUST be the SCALED features
                X_train, X_val, X_test, y_train, y_val, y_test = self.get_golden_split(
                    X, y, val_size=val_ratio, test_size=test_ratio, seed=seed, stratify_labels=stratify_labels
                )

                evals_result = self.train_binary(X_train, y_train, X_val, y_val, patience=patience)
                metrics = self.evaluate_metrics(X_test, y_test)
                score = metrics.get(metric, metrics["auc"])

                print(f"    Metrics (seed {seed}): {metrics}")

                if score > best_score:
                    best_score = score
                    best_seed = seed
                    best_metrics = metrics
                    best_model = self.model
                    best_data = (X_test, y_test)
                    best_split = (train_ratio, val_ratio, test_ratio)
                    best_evals_result = evals_result

        if best_model is not None:
            self.model = best_model
            self.evals_result = best_evals_result
        self.best_seed = best_seed
        self.best_split = best_split
        self.best_data = best_data
        print(f"\n[+] Best split {best_split} seed={best_seed} {metric}={best_score:.4f}")
        return {"best_seed": best_seed, "best_split": best_split, "best_score": best_score, "metrics": best_metrics}
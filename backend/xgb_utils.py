from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import xgboost as xgb
import cupy as cp
import joblib  # for saving model
import numpy as np
import matplotlib.pyplot as plt


def train_xgboost_binary_gpu(X, y, feature_set_name='All Features', test_size=0.25, random_state=42,
                             early_stopping_rounds=20, model_save_path=None):
    # Split on CPU
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    # Convert to GPU arrays (cupy)
    X_train_cp = cp.array(X_train.values)
    y_train_cp = cp.array(y_train.values)
    X_test_cp = cp.array(X_test.values)
    y_test_cp = cp.array(y_test.values)

    # Train on GPU
    clf = xgb.XGBClassifier(
        device="cuda",
        tree_method="hist",
        n_estimators=300,
        eval_metric="logloss",
        early_stopping_rounds=early_stopping_rounds
    )

    clf.fit(
        X_train_cp, y_train_cp,
        eval_set=[(X_train_cp, y_train_cp), (X_test_cp, y_test_cp)],
        verbose=False,
    )

    # Save model if path is given
    if model_save_path:
        joblib.dump(clf, model_save_path)
        print(f"Best model saved to: {model_save_path}")

    # Predict
    y_pred = clf.predict(X_test_cp)
    y_proba = clf.predict_proba(X_test_cp)[:, 1]

    report = classification_report(cp.asnumpy(y_test_cp), cp.asnumpy(y_pred), output_dict=True)
    auc = roc_auc_score(cp.asnumpy(y_test_cp), cp.asnumpy(y_proba))

    return {
        "model": clf,
        "feature_set": feature_set_name,
        "classification_report": report,
        "roc_auc": auc,
        "evals_result": clf.evals_result(),
        "best_iteration": clf.best_iteration
    }



def plot_learning_curve(evals_result, feature_set, metric='logloss'):
    """
    Enhanced learning curve plot with better visualization of overlapping curves.
    """
    train_metric = evals_result['validation_0'][metric]
    val_metric = evals_result['validation_1'][metric]
    epochs = range(1, len(train_metric) + 1)

    # Calculate statistics for better y-axis limits
    min_val = min(min(train_metric), min(val_metric))
    max_val = max(max(train_metric), max(val_metric))
    range_val = max_val - min_val
    
    # Create figure with larger size
    plt.figure(figsize=(10, 6))
    
    # Plot with enhanced styling
    plt.plot(epochs, train_metric, 
             label='Train Loss',
             color='forestgreen',
             linestyle='-',
             linewidth=2,
             alpha=0.7)
    
    plt.plot(epochs, val_metric, 
             label='Validation Loss',
             color='crimson',
             linestyle='--',
             linewidth=2,
             alpha=0.7)
    
    # Add fill between curves to highlight differences
    plt.fill_between(epochs, train_metric, val_metric,
                     alpha=0.15,
                     color='gray',
                     label='Difference')
    
    # Set y-axis limits to zoom in on the differences
    padding = range_val * 0.1  # 10% padding
    plt.ylim(min_val - padding, max_val + padding)
    
    # Add difference statistics
    mean_diff = np.mean(np.array(val_metric) - np.array(train_metric))
    max_diff = max(np.array(val_metric) - np.array(train_metric))
    plt.text(0.02, 0.98, 
             f'Mean Diff: {mean_diff:.6f}\nMax Diff: {max_diff:.6f}',
             transform=plt.gca().transAxes,
             verticalalignment='top',
             bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))
    
    # Enhance grid and styling
    plt.grid(True, linestyle='--', alpha=0.3)
    plt.xlabel('Iteration', fontsize=12)
    plt.ylabel(metric.title(), fontsize=12)
    plt.title(f'{feature_set} - Learning Curve\n({metric})', fontsize=13, pad=10)
    
    # Enhance legend
    plt.legend(loc='center right', framealpha=0.8, fancybox=True, shadow=True)
    
    plt.tight_layout()
    plt.show()
    
    # Print numeric summary
    print(f"\nMetric Statistics for {feature_set}:")
    print(f"Final Train Loss: {train_metric[-1]:.6f}")
    print(f"Final Valid Loss: {val_metric[-1]:.6f}")
    print(f"Final Difference: {val_metric[-1] - train_metric[-1]:.6f}")
#!/usr/bin/env python3
"""
paper_figures.py — APAN 62 & Conference Paper Figure Generator
================================================================

Master script that reads benchmark outputs and regenerates every
publication-quality figure.

Data Sources:
    - backend/benchmark/results/summary.csv
    - backend/gnn_compare/ablation_study_results.csv

Output:
    All PNGs are saved into backend/benchmark/images/

Figures:
    1. Rescale vs Retrain — Grouped bar chart comparing scaler strategies
    2. Latency Comparison — Grouped bar chart across topologies & controllers
    3. Security Preservation — Grouped bar chart (WS, DB) per attack type
    4. Service Availability — Grouped bar chart (SCS) showing resilience

Usage:
    python3 paper_figures.py
"""

import csv
import os
import sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

# =====================================================================
# Paths
# =====================================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BENCHMARK_DIR = os.path.dirname(SCRIPT_DIR)         # backend/benchmark/
BACKEND_DIR = os.path.dirname(BENCHMARK_DIR)         # backend/
SUMMARY_CSV = os.path.join(BENCHMARK_DIR, "results", "summary.csv")
ABLATION_CSV = os.path.join(BACKEND_DIR, "gnn_compare", "ablation_study_results.csv")
IMAGES_DIR = SCRIPT_DIR                               # output here

# =====================================================================
# Publication Style Configuration
# =====================================================================
# Caption: Publication-quality matplotlib configuration for APAN 62
# paper and conference presentations. 300 DPI, white background,
# large readable fonts, colorblind-friendly palette.

STYLE = {
    "font.family": "sans-serif",
    "font.sans-serif": ["DejaVu Sans", "Arial", "Helvetica"],
    "font.size": 12,
    "axes.titlesize": 14,
    "axes.titleweight": "bold",
    "axes.labelsize": 13,
    "axes.labelweight": "bold",
    "xtick.labelsize": 11,
    "ytick.labelsize": 11,
    "legend.fontsize": 10,
    "legend.framealpha": 0.9,
    "legend.edgecolor": "#cccccc",
    "figure.dpi": 150,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
    "savefig.facecolor": "white",
    "savefig.edgecolor": "white",
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.grid": True,
    "grid.alpha": 0.25,
    "grid.linewidth": 0.5,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.linewidth": 1.2,
}

# Colorblind-friendly palette (Wong 2011)
PALETTE = {
    "blue":    "#0072B2",
    "orange":  "#E69F00",
    "green":   "#009E73",
    "red":     "#D55E00",
    "purple":  "#CC79A7",
    "cyan":    "#56B4E9",
    "yellow":  "#F0E442",
    "grey":    "#999999",
}

# Controller display names
CTRL_LABELS = {
    "simple_13":    "Simple L2",
    "controller_1": "C1 (XGBoost)",
    "controller_2": "C2 (XGB+IF)",
    "controller_3": "C3 (XGB+IF+GNN)",
    "controller_4": "C4 (Full Pipeline)",
}

# Scenario display names
SCENARIO_LABELS = {
    "probe":              "Probe",
    "dos":                "DoS",
    "ddos":               "DDoS",
    "sqli_web":           "SQLi",
    "credential_attack":  "Credential",
    "exfiltration":       "Exfiltration",
}


# =====================================================================
# Data Loaders
# =====================================================================

def load_summary_csv():
    """Load benchmark summary.csv into a list of dicts with float-converted numerics."""
    rows = []
    if not os.path.exists(SUMMARY_CSV):
        print(f"[ERROR] summary.csv not found at {SUMMARY_CSV}")
        print("        Run statistics.py first to generate it.")
        return rows

    with open(SUMMARY_CSV, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            for key in ("n", "mean", "median", "std", "min", "max", "ci_95"):
                try:
                    row[key] = float(row[key])
                except (ValueError, KeyError):
                    row[key] = 0.0
            rows.append(row)

    print(f"[data] Loaded {len(rows)} rows from summary.csv")
    return rows


def load_ablation_csv():
    """Load gnn_compare/ablation_study_results.csv into a list of dicts."""
    rows = []
    if not os.path.exists(ABLATION_CSV):
        print(f"[WARN] ablation_study_results.csv not found at {ABLATION_CSV}")
        print("       Figure 1 will use placeholder annotations.")
        return rows

    with open(ABLATION_CSV, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            for key in ("Accuracy", "F1", "Recall", "FPR", "Cost", "Improvement"):
                try:
                    row[key] = float(row[key]) if row.get(key, "") != "" else 0.0
                except (ValueError, KeyError):
                    row[key] = 0.0
            rows.append(row)

    print(f"[data] Loaded {len(rows)} rows from ablation_study_results.csv")
    return rows


def get_metric(rows, metric, controller=None, topology=None, scenario=None):
    """Extract mean and ci_95 for a specific metric from summary.csv rows."""
    vals = []
    cis = []
    for row in rows:
        if row["metric"] != metric:
            continue
        if controller and row["controller"] != controller:
            continue
        if topology and row["topology"] != topology:
            continue
        if scenario and row["scenario"] != scenario:
            continue
        vals.append(row["mean"])
        cis.append(row["ci_95"])

    if not vals:
        return 0.0, 0.0
    return sum(vals) / len(vals), sum(cis) / len(cis)


# =====================================================================
# Figure 1: Rescale vs Retrain
# =====================================================================
# Caption: Comparison of detection performance (F1 Score) after
# feature rescaling versus full model retraining on two unseen
# environments (DNS and FRIDAY datasets). Tri-Channel Scaler maintains
# near-retraining performance through rescaling alone, avoiding the
# cost of full retraining.

def figure_1_rescale_vs_retrain(ablation_rows):
    """
    Figure 1 — Rescale vs Retrain comparison.

    Plots F1 scores for binary GNN models using three scaler strategies
    (StandardScaler, RobustScaler, Tri-Channel) in Rescale and Retrain
    modes across DNS and FRIDAY datasets.

    If StandardScaler/RobustScaler data is missing, only plots TriChannel
    (MODEL1) and annotates the missing bars as TODO.
    """
    if not ablation_rows:
        print("[SKIP] Figure 1: No ablation data available")
        return

    datasets = ["dns", "friday"]
    dataset_labels = {"dns": "DNS Dataset", "friday": "FRIDAY Dataset"}

    # Map model names to scaler types
    # MODEL1 = TriChannelScaler (45 features), MODEL3 = Raw 15-feature
    # model_standard = StandardScaler 15-feature, model_robust = RobustScaler 15-feature
    scaler_models = [
        ("StandardScaler",  "MODEL_STANDARD"),
        ("RobustScaler",    "MODEL_ROBUST"),
        ("Tri-Channel",     "MODEL1"),
    ]

    # Check which models actually exist in the ablation data
    available_models = set(row["Model"] for row in ablation_rows)

    # Build data structure: {dataset: {scaler_label: {mode: f1}}}
    data = {}
    for ds in datasets:
        data[ds] = {}
        for scaler_label, model_key in scaler_models:
            data[ds][scaler_label] = {}
            for mode in ["Rescale", "Retrain"]:
                matching = [
                    row for row in ablation_rows
                    if row["dataset"] == ds
                    and row["Model"] == model_key
                    and row["Task"] == "BINARY"
                    and row["Mode"] == mode
                ]
                if matching:
                    data[ds][scaler_label][mode] = matching[0]["F1"]
                else:
                    data[ds][scaler_label][mode] = None  # Missing

    # Also extract Retrain reference (best retrain F1 per dataset)
    retrain_ref = {}
    for ds in datasets:
        retrain_vals = [
            row["F1"] for row in ablation_rows
            if row["dataset"] == ds and row["Task"] == "BINARY" and row["Mode"] == "Retrain"
            and row["F1"] > 0.5  # Filter out collapsed models
        ]
        retrain_ref[ds] = max(retrain_vals) if retrain_vals else None

    # --- Plot ---
    fig, axes = plt.subplots(1, 2, figsize=(14, 6), sharey=True)

    colors_rescale = PALETTE["blue"]
    colors_retrain = PALETTE["orange"]

    for ax_idx, ds in enumerate(datasets):
        ax = axes[ax_idx]
        scaler_labels = [s[0] for s in scaler_models]
        x = np.arange(len(scaler_labels))
        width = 0.35

        rescale_vals = []
        retrain_vals = []
        rescale_available = []
        retrain_available = []

        for scaler_label, _ in scaler_models:
            r_val = data[ds][scaler_label].get("Rescale")
            t_val = data[ds][scaler_label].get("Retrain")
            rescale_vals.append(r_val if r_val is not None else 0)
            retrain_vals.append(t_val if t_val is not None else 0)
            rescale_available.append(r_val is not None)
            retrain_available.append(t_val is not None)

        # Draw bars
        bars_r = ax.bar(
            x - width / 2, rescale_vals, width,
            label="Rescale", color=colors_rescale,
            edgecolor="white", linewidth=0.8, alpha=0.9
        )
        bars_t = ax.bar(
            x + width / 2, retrain_vals, width,
            label="Retrain", color=colors_retrain,
            edgecolor="white", linewidth=0.8, alpha=0.9
        )

        # Value labels and TODO annotations
        for i, (bar, avail, val) in enumerate(zip(bars_r, rescale_available, rescale_vals)):
            if avail:
                ax.text(
                    bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f"{val:.3f}", ha="center", va="bottom", fontsize=8, fontweight="bold"
                )
            else:
                ax.text(
                    bar.get_x() + bar.get_width() / 2, 0.02,
                    "TODO", ha="center", va="bottom", fontsize=8,
                    fontweight="bold", color=PALETTE["red"], fontstyle="italic"
                )

        for i, (bar, avail, val) in enumerate(zip(bars_t, retrain_available, retrain_vals)):
            if avail:
                ax.text(
                    bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f"{val:.3f}", ha="center", va="bottom", fontsize=8, fontweight="bold"
                )
            else:
                ax.text(
                    bar.get_x() + bar.get_width() / 2, 0.02,
                    "TODO", ha="center", va="bottom", fontsize=8,
                    fontweight="bold", color=PALETTE["red"], fontstyle="italic"
                )

        # Full Retraining reference line
        if retrain_ref[ds] is not None:
            ax.axhline(
                y=retrain_ref[ds], color=PALETTE["grey"],
                linestyle="--", linewidth=1.5, alpha=0.7,
                label=f"Best Retrain F1 ({retrain_ref[ds]:.3f})"
            )

        ax.set_xlabel("Scaler Strategy")
        ax.set_title(dataset_labels[ds], fontsize=13, fontweight="bold")
        ax.set_xticks(x)
        ax.set_xticklabels(scaler_labels, fontsize=10)
        ax.set_ylim(0, 1.15)
        ax.legend(loc="upper left", fontsize=8)

    axes[0].set_ylabel("F1 Score (Binary Detection)")

    fig.suptitle(
        "Figure 1: Rescale vs Retrain — Binary GNN Detection Performance",
        fontsize=15, fontweight="bold", y=1.02
    )

    path = os.path.join(IMAGES_DIR, "fig1_rescale_vs_retrain.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"[saved] {path}")


# =====================================================================
# =====================================================================
# Timeline History Loader Helper
# =====================================================================

def load_timeline_history(controller, topology, metric_type="latency"):
    import json
    from collections import defaultdict
    scenarios = ["probe", "dos", "ddos", "sqli_web", "credential_attack", "exfiltration"]
    concatenated_time = []
    concatenated_val = []
    
    current_time_offset = 0.0
    runs_dir = os.path.join(BENCHMARK_DIR, "results", "benchmark_runs")
    
    for scen in scenarios:
        path = os.path.join(runs_dir, controller, topology, scen, "seed_1.json")
        if not os.path.exists(path):
            scen_dir = os.path.join(runs_dir, controller, topology, scen)
            if os.path.exists(scen_dir):
                seeds = [f for f in os.listdir(scen_dir) if f.endswith(".json")]
                if seeds:
                    path = os.path.join(scen_dir, seeds[0])
                    
        if not os.path.exists(path):
            # Fill with 0s if data is missing
            for t in range(65):
                concatenated_time.append(current_time_offset + t)
                concatenated_val.append(0.0)
            current_time_offset += 65.0
            continue
            
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[warn] Failed to read {path}: {e}")
            for t in range(65):
                concatenated_time.append(current_time_offset + t)
                concatenated_val.append(0.0)
            current_time_offset += 65.0
            continue
            
        results = data.get("results", {})
        scores_dict = None
        for ctrl_key, topo_dict in results.items():
            if isinstance(topo_dict, dict) and topology in topo_dict:
                scores_dict = topo_dict[topology]
                break
                
        if not scores_dict:
            for t in range(65):
                concatenated_time.append(current_time_offset + t)
                concatenated_val.append(0.0)
            current_time_offset += 65.0
            continue
            
        if metric_type == "latency":
            probe_hist = scores_dict.get("probe_history", [])
            probes = [p for p in probe_hist if p.get("probe_type") == "http"]
            if not probes:
                probes = [p for p in probe_hist if p.get("probe_type") == "icmp"]
            
            if not probes:
                for t in range(65):
                    concatenated_time.append(current_time_offset + t)
                    concatenated_val.append(0.0)
                current_time_offset += 65.0
                continue
                
            probes = sorted(probes, key=lambda x: x["timestamp"])
            first_ts = probes[0]["timestamp"]
            
            sec_dict = defaultdict(list)
            for p in probes:
                elapsed_sec = int(round(p["timestamp"] - first_ts))
                elapsed_sec = max(0, min(64, elapsed_sec))
                sec_dict[elapsed_sec].append(p["latency_ms"])
                
            for t in range(65):
                lats = sec_dict.get(t, [])
                avg_lat = sum(lats) / len(lats) if lats else 0.0
                concatenated_time.append(current_time_offset + t)
                concatenated_val.append(avg_lat)
                
        elif metric_type == "bandwidth":
            qos_hist = scores_dict.get("qos_history", [])
            if not qos_hist:
                for t in range(65):
                    concatenated_time.append(current_time_offset + t)
                    concatenated_val.append(0.0)
                current_time_offset += 65.0
                continue
                
            qos_hist = sorted(qos_hist, key=lambda x: x["elapsed"])
            sec_dict = {}
            for q in qos_hist:
                elapsed_sec = int(round(q["elapsed"]))
                elapsed_sec = max(0, min(64, elapsed_sec))
                throughput_dict = q.get("throughput", {})
                total_bytes_sec = sum(throughput_dict.values())
                sec_dict[elapsed_sec] = total_bytes_sec / 1024.0 # in KB/s
                
            for t in range(65):
                val = sec_dict.get(t, 0.0)
                concatenated_time.append(current_time_offset + t)
                concatenated_val.append(val)
                
        elif metric_type == "throughput":
            flow_hist = scores_dict.get("flow_history", [])
            if not flow_hist:
                for t in range(65):
                    concatenated_time.append(current_time_offset + t)
                    concatenated_val.append(0.0)
                current_time_offset += 65.0
                continue
                
            flow_hist = sorted(flow_hist, key=lambda x: x["elapsed"])
            sec_dict = {}
            if topology == "small":
                normal_hosts = ["h1", "h4", "h5"]
            else:
                normal_hosts = ["h1"] + [f"h{i}" for i in range(4, 17)]
                
            for q in flow_hist:
                elapsed_sec = int(round(q["elapsed"]))
                elapsed_sec = max(0, min(64, elapsed_sec))
                throughput_dict = q.get("throughput", {})
                normal_bytes_sec = sum(throughput_dict.get(h, 0.0) for h in normal_hosts)
                sec_dict[elapsed_sec] = normal_bytes_sec / 1024.0 # in KB/s
                
            for t in range(65):
                val = sec_dict.get(t, 0.0)
                concatenated_time.append(current_time_offset + t)
                concatenated_val.append(val)
                
        current_time_offset += 65.0
        
    return concatenated_time, concatenated_val


def smooth_values(values, window_size=3):
    """Apply a simple moving average to smooth the timeline values."""
    if not values:
        return []
    smoothed = []
    for i in range(len(values)):
        start_idx = max(0, i - window_size + 1)
        window = values[start_idx : i + 1]
        smoothed.append(sum(window) / len(window))
    return smoothed


# =====================================================================
# Figure 2: Latency Timeline (Line Chart)
# =====================================================================
# Caption: Average user-perceived latency (ms) during attacks, plotted
# over the benchmark timeline. The 6 scenarios of 65s each are concatenated 
# to form a 6.5-minute timeline. Shaded red regions mark attack active phases.
# The figure is split into two subplots (Small and Large topologies) with 
# y-axis scales customized dynamically to fit their respective maximum peak values.
# Under both topologies, Controller 4 actively mitigates congestion and keeps 
# latency stable, whereas Simple Switch experiences high latency spikes during attacks.

def figure_2_latency(summary_rows):
    """
    Figure 2 — Latency timeline across concatenated scenarios.
    Plots user-perceived latency (ms) as a line graph across time.
    Splits Small and Large topologies into separate subplots with optimized y-axes.
    """
    print("[figures] Generating Figure 2: Latency Timeline...")
    
    # 2 rows, 1 col subplot layout, sharing the x-axis for timeline continuity
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 10), sharex=True)
    
    # Load small topology datasets
    times_small_simple, vals_small_simple = load_timeline_history("simple_13", "small", "latency")
    times_small_c4, vals_small_c4 = load_timeline_history("controller_4", "small", "latency")
    
    # Load large topology datasets
    times_large_simple, vals_large_simple = load_timeline_history("simple_13", "large", "latency")
    times_large_c4, vals_large_c4 = load_timeline_history("controller_4", "large", "latency")
    
    # Compute max values for y-limit customization
    max_small = max(max(vals_small_simple or [0]), max(vals_small_c4 or [0]))
    max_large = max(max(vals_large_simple or [0]), max(vals_large_c4 or [0]))
    
    # Plot on Small Topology (ax1)
    ax1.plot(times_small_simple, vals_small_simple, label="Small — Simple Switch", color=PALETTE["blue"], linewidth=1.5, alpha=0.8)
    ax1.plot(times_small_c4, vals_small_c4, label="Small — Controller 4", color=PALETTE["orange"], linewidth=1.5, alpha=0.8)
    
    # Plot on Large Topology (ax2)
    ax2.plot(times_large_simple, vals_large_simple, label="Large — Simple Switch", color=PALETTE["green"], linewidth=1.5, alpha=0.8)
    ax2.plot(times_large_c4, vals_large_c4, label="Large — Controller 4", color=PALETTE["red"], linewidth=1.5, alpha=0.8)
    
    scenarios = ["probe", "dos", "ddos", "sqli_web", "credential_attack", "exfiltration"]
    
    # Configure each axis
    for ax, ymax, title_text in [(ax1, max_small, "Small Network Topology"), (ax2, max_large, "Large Network Topology")]:
        # Draw attack phases and boundaries
        for i, scen in enumerate(scenarios):
            ax.axvspan(i * 65 + 20, i * 65 + 50, color="#ffcccc", alpha=0.2, 
                       label="Attack Active" if i == 0 else "")
            if i > 0:
                ax.axvline(x=i * 65, color="#888888", linestyle=":", alpha=0.5)
                
        # Set dynamic y limit based on maximum value
        ax.set_ylim(bottom=-10, top=ymax * 1.30 if ymax > 0 else 100)
        curr_ymax = ax.get_ylim()[1]
        
        # Place labels dynamically
        for i, scen in enumerate(scenarios):
            center_x = i * 65 + 32.5
            ax.text(center_x, curr_ymax * 0.85, SCENARIO_LABELS[scen], ha="center", va="center",
                    fontsize=8.5, fontweight="bold", 
                    bbox=dict(boxstyle="round,pad=0.2", facecolor="white", edgecolor="#cccccc", alpha=0.8))
            
        ax.set_ylabel("Average Latency (ms)")
        ax.set_title(title_text, fontsize=12, fontweight="bold")
        ax.legend(loc="upper left", framealpha=0.9)
        
    # Configure common X-axis on bottom plot (ax2)
    ax2.set_xlabel("Timeline (minutes)")
    ticks = np.arange(0, 391, 60)
    ax2.set_xticks(ticks)
    ax2.set_xticklabels([f"{t//60}m {t%60}s" if t > 0 else "0s" for t in ticks])
    
    # Title and layout adjustment
    fig.suptitle("Figure 2: User-Perceived Latency Timeline across Scenarios", fontsize=15, fontweight="bold", y=0.98)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    
    path = os.path.join(IMAGES_DIR, "fig2_latency_timeline.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"[saved] {path}")


# =====================================================================
# Figure 5: Bandwidth Utilization (Line Chart)
# =====================================================================
# Caption: Bandwidth utilization (KB/s) across scenarios, plotted
# over the benchmark timeline. The 6 scenarios of 65s each are concatenated.
# Shaded red regions mark attack active phases. Shows total throughput peaks
# during DDoS and exfiltration attacks, comparing Simple Switch against Controller 4.

def figure_5_bandwidth_util(summary_rows):
    """
    Figure 5 — Bandwidth utilization timeline.
    Plots total throughput (KB/s) to/from h2 and h3 across the timeline.
    Splits Small and Large topologies into separate subplots with optimized y-axes.
    Smooths values with a rolling average window to improve readability.
    """
    print("[figures] Generating Figure 5: Bandwidth Utilization...")
    
    # 2 rows, 1 col subplot layout, sharing x-axis
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 10), sharex=True)
    
    # Load small topology datasets, convert to % of 20 Mbps limit, and smooth
    times_small_simple, vals_small_simple = load_timeline_history("simple_13", "small", "bandwidth")
    vals_small_simple = [(v / 2560.0) * 100.0 for v in vals_small_simple]
    vals_small_simple_smooth = smooth_values(vals_small_simple, window_size=3)
    
    times_small_c4, vals_small_c4 = load_timeline_history("controller_4", "small", "bandwidth")
    vals_small_c4 = [(v / 2560.0) * 100.0 for v in vals_small_c4]
    vals_small_c4_smooth = smooth_values(vals_small_c4, window_size=3)
    
    # Load large topology datasets, convert to % of 20 Mbps limit, and smooth
    times_large_simple, vals_large_simple = load_timeline_history("simple_13", "large", "bandwidth")
    vals_large_simple = [(v / 2560.0) * 100.0 for v in vals_large_simple]
    vals_large_simple_smooth = smooth_values(vals_large_simple, window_size=3)
    
    times_large_c4, vals_large_c4 = load_timeline_history("controller_4", "large", "bandwidth")
    vals_large_c4 = [(v / 2560.0) * 100.0 for v in vals_large_c4]
    vals_large_c4_smooth = smooth_values(vals_large_c4, window_size=3)
    
    # Plot on Small Topology (ax1)
    ax1.plot(times_small_simple, vals_small_simple_smooth, label="Small — Simple Switch", color=PALETTE["blue"], linewidth=1.5, alpha=0.8)
    ax1.plot(times_small_c4, vals_small_c4_smooth, label="Small — Controller 4", color=PALETTE["orange"], linewidth=1.5, alpha=0.8)
    
    # Plot on Large Topology (ax2)
    ax2.plot(times_large_simple, vals_large_simple_smooth, label="Large — Simple Switch", color=PALETTE["green"], linewidth=1.5, alpha=0.8)
    ax2.plot(times_large_c4, vals_large_c4_smooth, label="Large — Controller 4", color=PALETTE["red"], linewidth=1.5, alpha=0.8)
    
    scenarios = ["probe", "dos", "ddos", "sqli_web", "credential_attack", "exfiltration"]
    
    # Configure each axis
    for ax, title_text in [(ax1, "Small Network Topology"), (ax2, "Large Network Topology")]:
        # Draw attack phases and boundaries
        for i, scen in enumerate(scenarios):
            ax.axvspan(i * 65 + 20, i * 65 + 50, color="#ffcccc", alpha=0.2, 
                       label="Attack Active" if i == 0 else "")
            if i > 0:
                ax.axvline(x=i * 65, color="#888888", linestyle=":", alpha=0.5)
                
        # Set y limits for percentage (0 to 110%)
        ax.set_ylim(bottom=-5, top=110)
        ax.set_yticks([0, 20, 40, 60, 80, 100])
        ax.axhline(y=100.0, color="#666666", linestyle="--", linewidth=1.2, alpha=0.8, label="Link Capacity (100%)")
        curr_ymax = 110.0
        
        # Place labels dynamically
        for i, scen in enumerate(scenarios):
            center_x = i * 65 + 32.5
            ax.text(center_x, curr_ymax * 0.85, SCENARIO_LABELS[scen], ha="center", va="center",
                    fontsize=8.5, fontweight="bold", 
                    bbox=dict(boxstyle="round,pad=0.2", facecolor="white", edgecolor="#cccccc", alpha=0.8))
            
        ax.set_ylabel("Bandwidth Utilization (%)")
        ax.set_title(title_text, fontsize=12, fontweight="bold")
        ax.legend(loc="upper left", framealpha=0.9)
        
    # Configure common X-axis on bottom plot (ax2)
    ax2.set_xlabel("Timeline (minutes)")
    ticks = np.arange(0, 391, 60)
    ax2.set_xticks(ticks)
    ax2.set_xticklabels([f"{t//60}m {t%60}s" if t > 0 else "0s" for t in ticks])
    
    # Title and layout adjustment
    fig.suptitle("Figure 5: Bandwidth Utilization Timeline across Scenarios", fontsize=15, fontweight="bold", y=0.98)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    
    path = os.path.join(IMAGES_DIR, "fig5_bandwidth_util.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"[saved] {path}")


# =====================================================================
# Figure 6: Benign User Throughput Timeline
# =====================================================================

def figure_6_throughput_timeline(summary_rows):
    """
    Figure 6 — Benign User Throughput Timeline.
    Plots sum of throughput (KB/s) for normal clients across the timeline.
    Splits Small and Large topologies into separate subplots with dynamic y-axes.
    Smooths values with a moving average.
    """
    print("[figures] Generating Figure 6: Benign User Throughput Timeline...")
    
    # 2 rows, 1 col subplot layout, sharing x-axis
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 10), sharex=True)
    
    # Load small topology datasets and smooth
    times_small_simple, vals_small_simple = load_timeline_history("simple_13", "small", "throughput")
    vals_small_simple_smooth = smooth_values(vals_small_simple, window_size=3)
    
    times_small_c4, vals_small_c4 = load_timeline_history("controller_4", "small", "throughput")
    vals_small_c4_smooth = smooth_values(vals_small_c4, window_size=3)
    
    # Load large topology datasets and smooth
    times_large_simple, vals_large_simple = load_timeline_history("simple_13", "large", "throughput")
    vals_large_simple_smooth = smooth_values(vals_large_simple, window_size=3)
    
    times_large_c4, vals_large_c4 = load_timeline_history("controller_4", "large", "throughput")
    vals_large_c4_smooth = smooth_values(vals_large_c4, window_size=3)
    
    # Compute max values for y-limit customization, factoring in baseline lines
    max_small = max(max(vals_small_simple_smooth or [0]), max(vals_small_c4_smooth or [0]), 158.57)
    max_large = max(max(vals_large_simple_smooth or [0]), max(vals_large_c4_smooth or [0]), 1077.69)
    
    # Plot on Small Topology (ax1)
    ax1.plot(times_small_simple, vals_small_simple_smooth, label="Small — Simple Switch", color=PALETTE["blue"], linewidth=1.5, alpha=0.8)
    ax1.plot(times_small_c4, vals_small_c4_smooth, label="Small — Controller 4", color=PALETTE["orange"], linewidth=1.5, alpha=0.8)
    ax1.axhline(y=158.57, color="#888888", linestyle=":", linewidth=1.5, alpha=0.9, label="Benign Baseline (158.6 KB/s)")
    
    # Plot on Large Topology (ax2)
    ax2.plot(times_large_simple, vals_large_simple_smooth, label="Large — Simple Switch", color=PALETTE["green"], linewidth=1.5, alpha=0.8)
    ax2.plot(times_large_c4, vals_large_c4_smooth, label="Large — Controller 4", color=PALETTE["red"], linewidth=1.5, alpha=0.8)
    ax2.axhline(y=1077.69, color="#888888", linestyle=":", linewidth=1.5, alpha=0.9, label="Benign Baseline (1077.7 KB/s)")
    
    scenarios = ["probe", "dos", "ddos", "sqli_web", "credential_attack", "exfiltration"]
    
    # Configure each axis
    for ax, ymax, title_text in [(ax1, max_small, "Small Network Topology"), (ax2, max_large, "Large Network Topology")]:
        # Draw attack phases and boundaries
        for i, scen in enumerate(scenarios):
            ax.axvspan(i * 65 + 20, i * 65 + 50, color="#ffcccc", alpha=0.2, 
                       label="Attack Active" if i == 0 else "")
            if i > 0:
                ax.axvline(x=i * 65, color="#888888", linestyle=":", alpha=0.5)
                
        # Set dynamic y limit based on maximum value
        ax.set_ylim(bottom=-10, top=ymax * 1.30 if ymax > 0 else 100)
        curr_ymax = ax.get_ylim()[1]
        
        # Place labels dynamically
        for i, scen in enumerate(scenarios):
            center_x = i * 65 + 32.5
            ax.text(center_x, curr_ymax * 0.85, SCENARIO_LABELS[scen], ha="center", va="center",
                    fontsize=8.5, fontweight="bold", 
                    bbox=dict(boxstyle="round,pad=0.2", facecolor="white", edgecolor="#cccccc", alpha=0.8))
            
        ax.set_ylabel("Benign User Throughput (KB/s)")
        ax.set_title(title_text, fontsize=12, fontweight="bold")
        ax.legend(loc="upper left", framealpha=0.9)
        
    # Configure common X-axis on bottom plot (ax2)
    ax2.set_xlabel("Timeline (minutes)")
    ticks = np.arange(0, 391, 60)
    ax2.set_xticks(ticks)
    ax2.set_xticklabels([f"{t//60}m {t%60}s" if t > 0 else "0s" for t in ticks])
    
    # Title and layout adjustment
    fig.suptitle("Figure 6: Benign User Throughput Timeline across Scenarios", fontsize=15, fontweight="bold", y=0.98)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    
    path = os.path.join(IMAGES_DIR, "fig6_throughput_timeline.png")
    fig.savefig(path)
    # Save a copy as fig6_throughput_util.png to cover both names
    path_util = os.path.join(IMAGES_DIR, "fig6_throughput_util.png")
    fig.savefig(path_util)
    plt.close(fig)
    print(f"[saved] {path}")
    print(f"[saved] {path_util}")


# =====================================================================
# Figure 3: Security Preservation
# =====================================================================
# Caption: Security preservation scores showing Web Server (WS)
# survival and Database (DB) preservation rates under security-relevant
# attack scenarios. WS measures resistance to SQL injection and
# credential attacks; DB measures resistance to data exfiltration.
# Simple Switch provides no application-layer security, while
# Controller 4's ML pipeline detects and mitigates threats.

def figure_3_security(summary_rows):
    """
    Figure 3 — Security Preservation grouped bar chart.

    Compares WS and DB scores for Simple Switch vs Controller 4
    across security-relevant attack scenarios (sqli_web, credential_attack,
    exfiltration) in both Small and Large topologies.
    """
    if not summary_rows:
        print("[SKIP] Figure 3: No summary data available")
        return

    controllers = ["simple_13", "controller_4"]
    security_scenarios = ["sqli_web", "credential_attack", "exfiltration"]
    metrics = ["WS", "DB"]
    metric_labels = {"WS": "Web Server Survival", "DB": "Database Preservation"}
    topologies = ["small", "large"]

    fig, axes = plt.subplots(1, 2, figsize=(15, 6.5), sharey=True)
    topo_titles = {"small": "Small Topology", "large": "Large Topology"}

    for ax_idx, topo in enumerate(topologies):
        ax = axes[ax_idx]

        # Each x-position = one scenario
        # Within each, grouped bars for: simple_WS, ctrl4_WS, simple_DB, ctrl4_DB
        x = np.arange(len(security_scenarios))
        n_bars = len(controllers) * len(metrics)
        total_width = 0.75
        width = total_width / n_bars

        bar_colors = [
            PALETTE["blue"],    # simple_13 WS
            PALETTE["orange"],  # controller_4 WS
            PALETTE["green"],   # simple_13 DB
            PALETTE["red"],     # controller_4 DB
        ]
        bar_labels = [
            "Simple Switch — WS",
            "Controller 4 — WS",
            "Simple Switch — DB",
            "Controller 4 — DB",
        ]

        bar_idx = 0
        for m_idx, metric in enumerate(metrics):
            for c_idx, ctrl in enumerate(controllers):
                vals = []
                cis = []
                for scen in security_scenarios:
                    mean, ci = get_metric(summary_rows, metric, controller=ctrl, topology=topo, scenario=scen)
                    vals.append(mean)
                    cis.append(ci)

                offset = (bar_idx - n_bars / 2 + 0.5) * width
                bars = ax.bar(
                    x + offset, vals, width, yerr=cis, capsize=2,
                    label=bar_labels[bar_idx], color=bar_colors[bar_idx],
                    edgecolor="white", linewidth=0.8, alpha=0.9
                )

                # Value labels
                for bar, val in zip(bars, vals):
                    ax.text(
                        bar.get_x() + bar.get_width() / 2,
                        bar.get_height() + 0.02,
                        f"{val:.2f}", ha="center", va="bottom", fontsize=7, fontweight="bold"
                    )
                bar_idx += 1

        ax.set_xlabel("Attack Scenario")
        ax.set_title(topo_titles[topo], fontsize=13, fontweight="bold")
        ax.set_xticks(x)
        ax.set_xticklabels([SCENARIO_LABELS[s] for s in security_scenarios], fontsize=10)
        ax.set_ylim(0, 1.2)
        ax.legend(loc="lower right", fontsize=8, ncol=2)

    axes[0].set_ylabel("Security Score (0–1)")

    fig.suptitle(
        "Figure 3: Security Preservation — Web Server & Database Protection",
        fontsize=15, fontweight="bold", y=1.02
    )

    path = os.path.join(IMAGES_DIR, "fig3_security_preservation.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"[saved] {path}")


# =====================================================================
# Figure 4: Service Availability / Resilience
# =====================================================================
# Caption: Service Continuity Score (SCS) measuring weighted uptime of
# critical network services (web server, database) under attack.
# Grouped by topology size and controller type across all 6 attack
# scenarios. Dashed reference lines indicate maximum achievable SCS
# (1.0). Simple Switch maintains higher SCS because it forwards all
# traffic without inspection (no blocking), while ML-enabled controllers
# trade some availability for security.

def figure_4_service_availability(summary_rows):
    """
    Figure 4 — Service Availability grouped bar chart.

    Shows SCS scores for Simple Switch vs Controller 4 in Small and
    Large topologies across all 6 attack scenarios.
    """
    if not summary_rows:
        print("[SKIP] Figure 4: No summary data available")
        return

    controllers = ["simple_13", "controller_4"]
    scenarios = list(SCENARIO_LABELS.keys())
    topologies = ["small", "large"]

    fig, axes = plt.subplots(1, 2, figsize=(14, 6.5), sharey=True)
    topo_titles = {"small": "Small Topology", "large": "Large Topology"}

    for ax_idx, topo in enumerate(topologies):
        ax = axes[ax_idx]
        x = np.arange(len(scenarios))
        width = 0.35

        for c_idx, ctrl in enumerate(controllers):
            vals = []
            cis = []
            for scen in scenarios:
                mean, ci = get_metric(summary_rows, "SCS", controller=ctrl, topology=topo, scenario=scen)
                vals.append(mean)
                cis.append(ci)

            offset = (c_idx - 0.5) * width
            color = PALETTE["blue"] if ctrl == "simple_13" else PALETTE["orange"]
            label = CTRL_LABELS.get(ctrl, ctrl)

            bars = ax.bar(
                x + offset, vals, width, yerr=cis, capsize=3,
                label=label, color=color,
                edgecolor="white", linewidth=0.8, alpha=0.9
            )

            # Value labels
            for bar, val in zip(bars, vals):
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.02,
                    f"{val:.2f}", ha="center", va="bottom", fontsize=7, fontweight="bold"
                )

        # Maximum reference line
        ax.axhline(
            y=1.0, color=PALETTE["grey"], linestyle="--", linewidth=1.5,
            alpha=0.6, label="Maximum SCS (1.0)"
        )

        ax.set_xlabel("Attack Scenario")
        ax.set_title(topo_titles[topo], fontsize=13, fontweight="bold")
        ax.set_xticks(x)
        ax.set_xticklabels([SCENARIO_LABELS[s] for s in scenarios], fontsize=10, rotation=20, ha="right")
        ax.set_ylim(0, 1.2)
        ax.legend(loc="upper right", fontsize=9)

    axes[0].set_ylabel("Service Continuity Score (SCS)")

    fig.suptitle(
        "Figure 4: Service Availability — Resilience Under Attack",
        fontsize=15, fontweight="bold", y=1.02
    )

    path = os.path.join(IMAGES_DIR, "fig4_service_availability.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"[saved] {path}")


# =====================================================================
# Main
# =====================================================================

def main():
    print("=" * 65)
    print("  PAPER FIGURES GENERATOR — APAN 62 & Conference Paper")
    print("=" * 65)

    # Apply publication style
    plt.rcParams.update(STYLE)

    # Load data
    summary_rows = load_summary_csv()
    ablation_rows = load_ablation_csv()

    # Generate all figures
    figure_1_rescale_vs_retrain(ablation_rows)
    figure_2_latency(summary_rows)
    figure_3_security(summary_rows)
    figure_4_service_availability(summary_rows)
    figure_5_bandwidth_util(summary_rows)
    figure_6_throughput_timeline(summary_rows)

    print(f"\n[done] All figures saved to {IMAGES_DIR}/")
    print("[done] Paper figures generation complete.")


if __name__ == "__main__":
    main()

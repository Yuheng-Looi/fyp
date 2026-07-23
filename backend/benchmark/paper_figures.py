#!/usr/bin/env python3
"""
paper_figures.py — Phase 4.9 Graph Generator

Reads ONLY from results/summary.csv (produced by statistics.py).
Generates publication-quality PNG figures for the APAN paper.

Figures:
  1. OFS Rankings — Bar chart comparing all 5 controllers
  2. Scalability / Resilience — Grouped bar chart showing NRS by topology
  3. Security vs Resilience — Scatter plot of NRS vs SPS trade-offs
"""

import os
import sys

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for headless servers

import matplotlib.pyplot as plt
import numpy as np

BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
SUMMARY_CSV = os.path.join(BENCHMARK_DIR, "results", "summary.csv")
FIGURES_DIR = os.path.join(BENCHMARK_DIR, "figures")

# Display-friendly controller labels
CONTROLLER_LABELS = {
    "simple_13": "Simple L2",
    "controller_1": "C1 (XGBoost)",
    "controller_2": "C2 (XGB+IF)",
    "controller_3": "C3 (XGB+IF+GNN)",
    "controller_4": "C4 (Hybrid+FB)",
}

CONTROLLER_ORDER = ["simple_13", "controller_1", "controller_2", "controller_3", "controller_4"]

# Academic color palette (colorblind-friendly)
COLORS = ["#4C72B0", "#55A868", "#C44E52", "#8172B2", "#CCB974"]


def load_summary():
    """Load summary.csv using only stdlib csv (no pandas dependency for loading)."""
    import csv

    rows = []
    if not os.path.exists(SUMMARY_CSV):
        print(f"[error] summary.csv not found at {SUMMARY_CSV}")
        print("        Run statistics.py first to generate it.")
        sys.exit(1)

    with open(SUMMARY_CSV, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Convert numeric fields
            for key in ("n", "mean", "median", "std", "min", "max", "ci_95"):
                try:
                    row[key] = float(row[key])
                except (ValueError, KeyError):
                    row[key] = 0.0
            rows.append(row)

    print(f"[figures] Loaded {len(rows)} rows from summary.csv")
    return rows


def get_metric_by_controller(rows, metric, topology=None, scenario=None):
    """Extract mean and ci_95 for a metric, aggregated across scenarios/topologies."""
    from collections import defaultdict

    vals = defaultdict(list)
    cis = defaultdict(list)

    for row in rows:
        if row["metric"] != metric:
            continue
        if topology and row["topology"] != topology:
            continue
        if scenario and row["scenario"] != scenario:
            continue

        ctrl = row["controller"]
        vals[ctrl].append(row["mean"])
        cis[ctrl].append(row["ci_95"])

    # Average across the filtered combinations
    result = {}
    for ctrl in CONTROLLER_ORDER:
        if ctrl in vals and vals[ctrl]:
            result[ctrl] = {
                "mean": sum(vals[ctrl]) / len(vals[ctrl]),
                "ci_95": sum(cis[ctrl]) / len(cis[ctrl]),
            }
        else:
            result[ctrl] = {"mean": 0.0, "ci_95": 0.0}

    return result


def setup_style():
    """Configure matplotlib for academic publication quality."""
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.sans-serif": ["DejaVu Sans", "Arial", "Helvetica"],
        "font.size": 11,
        "axes.titlesize": 13,
        "axes.labelsize": 12,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "legend.fontsize": 9,
        "figure.dpi": 150,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
        "axes.grid": True,
        "grid.alpha": 0.3,
        "axes.spines.top": False,
        "axes.spines.right": False,
    })


def figure_1_ofs_rankings(rows):
    """Figure 1: Bar chart comparing OFS across all 5 controllers."""
    data = get_metric_by_controller(rows, "OFS")

    labels = [CONTROLLER_LABELS.get(c, c) for c in CONTROLLER_ORDER]
    means = [data[c]["mean"] for c in CONTROLLER_ORDER]
    errors = [data[c]["ci_95"] for c in CONTROLLER_ORDER]

    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(labels))
    bars = ax.bar(x, means, yerr=errors, capsize=4, color=COLORS,
                  edgecolor="white", linewidth=0.8, width=0.6)

    # Add value labels on bars
    for bar, val in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                f"{val:.3f}", ha="center", va="bottom", fontsize=9, fontweight="bold")

    ax.set_xlabel("Controller")
    ax.set_ylabel("Overall Framework Score (OFS)")
    ax.set_title("Figure 1: Overall Framework Score (OFS) Ranking")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha="right")
    ax.set_ylim(0, 1.05)
    ax.axhline(y=0.5, color="gray", linestyle="--", alpha=0.4, label="Baseline (0.5)")
    ax.legend(loc="upper left")

    path = os.path.join(FIGURES_DIR, "fig1_ofs_rankings.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"[figures] Saved: {path}")


def figure_2_scalability(rows):
    """Figure 2: Grouped bar chart showing NRS for Small vs Large topologies."""
    data_small = get_metric_by_controller(rows, "NRS", topology="small")
    data_large = get_metric_by_controller(rows, "NRS", topology="large")

    labels = [CONTROLLER_LABELS.get(c, c) for c in CONTROLLER_ORDER]
    means_small = [data_small[c]["mean"] for c in CONTROLLER_ORDER]
    means_large = [data_large[c]["mean"] for c in CONTROLLER_ORDER]
    ci_small = [data_small[c]["ci_95"] for c in CONTROLLER_ORDER]
    ci_large = [data_large[c]["ci_95"] for c in CONTROLLER_ORDER]

    fig, ax = plt.subplots(figsize=(9, 5.5))
    x = np.arange(len(labels))
    width = 0.35

    bars1 = ax.bar(x - width / 2, means_small, width, yerr=ci_small, capsize=3,
                   label="Small Topology", color="#4C72B0", edgecolor="white", linewidth=0.8)
    bars2 = ax.bar(x + width / 2, means_large, width, yerr=ci_large, capsize=3,
                   label="Large Topology", color="#C44E52", edgecolor="white", linewidth=0.8)

    # Add value labels
    for bar, val in zip(bars1, means_small):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                f"{val:.2f}", ha="center", va="bottom", fontsize=8)
    for bar, val in zip(bars2, means_large):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                f"{val:.2f}", ha="center", va="bottom", fontsize=8)

    ax.set_xlabel("Controller")
    ax.set_ylabel("Network Resilience Score (NRS)")
    ax.set_title("Figure 2: Scalability — NRS Across Topologies")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha="right")
    ax.set_ylim(0, 1.05)
    ax.legend(loc="upper right")

    path = os.path.join(FIGURES_DIR, "fig2_scalability_nrs.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"[figures] Saved: {path}")


def figure_3_security_vs_resilience(rows):
    """Figure 3: Scatter plot of NRS (x) vs SPS (y) per controller."""
    fig, ax = plt.subplots(figsize=(7, 6))

    for idx, ctrl in enumerate(CONTROLLER_ORDER):
        nrs_data = get_metric_by_controller(rows, "NRS")
        sps_data = get_metric_by_controller(rows, "SPS")

        nrs_val = nrs_data[ctrl]["mean"]
        sps_val = sps_data[ctrl]["mean"]
        nrs_ci = nrs_data[ctrl]["ci_95"]
        sps_ci = sps_data[ctrl]["ci_95"]

        label = CONTROLLER_LABELS.get(ctrl, ctrl)
        ax.errorbar(nrs_val, sps_val, xerr=nrs_ci, yerr=sps_ci,
                     fmt="o", markersize=10, color=COLORS[idx], label=label,
                     capsize=4, capthick=1.5, elinewidth=1.2,
                     markeredgecolor="white", markeredgewidth=1.0)

        # Annotate with controller label
        ax.annotate(label, (nrs_val, sps_val),
                    textcoords="offset points", xytext=(8, 8),
                    fontsize=8, alpha=0.8)

    ax.set_xlabel("Network Resilience Score (NRS)")
    ax.set_ylabel("Security Preservation Score (SPS)")
    ax.set_title("Figure 3: Security vs. Resilience Trade-off")
    ax.set_xlim(-0.05, 1.05)
    ax.set_ylim(-0.05, 1.05)

    # Add quadrant lines at 0.5
    ax.axvline(x=0.5, color="gray", linestyle="--", alpha=0.3)
    ax.axhline(y=0.5, color="gray", linestyle="--", alpha=0.3)

    # Quadrant labels
    ax.text(0.75, 0.05, "High Resilience\nLow Security", ha="center", fontsize=8,
            alpha=0.4, style="italic")
    ax.text(0.05, 0.95, "Low Resilience\nHigh Security", ha="left", fontsize=8,
            alpha=0.4, style="italic")
    ax.text(0.75, 0.95, "Ideal", ha="center", fontsize=9,
            alpha=0.5, fontweight="bold", color="green")

    ax.legend(loc="lower right", framealpha=0.9)

    path = os.path.join(FIGURES_DIR, "fig3_security_vs_resilience.png")
    fig.savefig(path)
    plt.close(fig)
    print(f"[figures] Saved: {path}")


def main():
    print("=" * 60)
    print("  PAPER FIGURES GENERATOR — Phase 4.9")
    print("=" * 60)

    setup_style()
    os.makedirs(FIGURES_DIR, exist_ok=True)

    rows = load_summary()

    figure_1_ofs_rankings(rows)
    figure_2_scalability(rows)
    figure_3_security_vs_resilience(rows)

    print(f"\n[figures] All figures saved to {FIGURES_DIR}/")
    print("[figures] Done.")


if __name__ == "__main__":
    main()

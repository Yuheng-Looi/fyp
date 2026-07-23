#!/usr/bin/env python3
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# Import helpers and styling from the master figure script
from paper_figures import load_timeline_history, smooth_values, PALETTE, IMAGES_DIR

def generate_figure():
    print("[data] Loading timeline history for Simple Switch (simple_13)...")
    
    # 1. Load Small topology data
    times_small_lat, vals_small_lat = load_timeline_history("simple_13", "small", "latency")
    times_small_bw, vals_small_bw = load_timeline_history("simple_13", "small", "bandwidth")
    vals_small_bw = [(v / 2560.0) * 100.0 for v in vals_small_bw]
    vals_small_bw = smooth_values(vals_small_bw, 3)

    # 2. Load Large topology data
    times_large_lat, vals_large_lat = load_timeline_history("simple_13", "large", "latency")
    times_large_bw, vals_large_bw = load_timeline_history("simple_13", "large", "bandwidth")
    vals_large_bw = [(v / 2560.0) * 100.0 for v in vals_large_bw]
    vals_large_bw = smooth_values(vals_large_bw, 3)

    # Subplots: 2 rows, 1 column
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10), sharex=True)

    # 6.5 minutes concatenated timeline (6 scenarios of 65s each)
    scenarios = [
        ("Probe", 0.0),
        ("DoS", 65.0),
        ("DDoS", 130.0),
        ("SQLi", 195.0),
        ("Credential", 260.0),
        ("Exfiltration", 325.0),
    ]

    def plot_dual_axis(ax, times_lat, vals_lat, times_bw, vals_bw, title):
        # Configure title and grid
        ax.set_title(title, fontsize=13, fontweight="bold")
        ax.grid(True, which="both", linestyle=":", alpha=0.5)

        # Plot Latency on the left axis (Blue)
        ax_left = ax
        color_lat = PALETTE["blue"]
        line_lat, = ax_left.plot(
            times_lat, vals_lat,
            label="User Latency (ms)",
            color=color_lat, linewidth=1.5, alpha=0.85
        )
        ax_left.set_ylabel("Average Latency (ms)", color=color_lat, fontweight="bold")
        ax_left.tick_params(axis="y", labelcolor=color_lat)

        # Plot Bandwidth on the right axis (Orange)
        ax_right = ax_left.twinx()
        color_bw = PALETTE["orange"]
        line_bw, = ax_right.plot(
            times_bw, vals_bw,
            label="Bandwidth Utilization (%)",
            color=color_bw, linewidth=1.5, alpha=0.85
        )
        ax_right.set_ylabel("Bandwidth Utilization (%)", color=color_bw, fontweight="bold")
        ax_right.tick_params(axis="y", labelcolor=color_bw)
        ax_right.set_ylim(bottom=-5, top=110)
        ax_right.set_yticks([0, 20, 40, 60, 80, 100])
        ax_right.axhline(y=100.0, color="#666666", linestyle="--", linewidth=1.2, alpha=0.8, label="Link Capacity (100%)")

        # Draw shaded regions for active attack phases & scenario text labels
        for idx, (scen_name, start_t) in enumerate(scenarios):
            # Attack active window: t=20s to t=50s of each 65s run
            ax_left.axvspan(start_t + 20.0, start_t + 50.0, color="#FF0000", alpha=0.04)
            # Mixed transform: X in data coordinates (seconds), Y in axis fraction coordinates (0.85)
            ax_left.text(
                start_t + 35.0, 0.85, scen_name,
                transform=ax_left.get_xaxis_transform(),
                ha="center", va="center", fontsize=9, color="#555555",
                bbox=dict(boxstyle="square,pad=0.2", fc="#fbfbfb", ec="#dddddd", alpha=0.9)
            )
            # Dotted separator lines between scenario runs
            if idx > 0:
                ax_left.axvline(start_t, color=PALETTE["grey"], linestyle=":", linewidth=1.2, alpha=0.7)

        # Combine legends from both axes
        lines = [line_lat, line_bw]
        labels = [l.get_label() for l in lines]
        ax_left.legend(lines, labels, loc="upper left", fontsize=9)

    # Plot Small and Large topology subplots
    plot_dual_axis(ax1, times_small_lat, vals_small_lat, times_small_bw, vals_small_bw, "Small Network Topology (Simple Switch)")
    plot_dual_axis(ax2, times_large_lat, vals_large_lat, times_large_bw, vals_large_bw, "Large Network Topology (Simple Switch)")

    # Set X-axis timeline tick markers and labels (6.5 minutes total)
    ax2.set_xlabel("Timeline (minutes)", fontsize=11, fontweight="bold")
    tick_positions = [0.0, 60.0, 120.0, 180.0, 240.0, 300.0, 360.0]
    tick_labels = ["0s", "1m 0s", "2m 0s", "3m 0s", "4m 0s", "5m 0s", "6m 0s"]
    ax2.set_xticks(tick_positions)
    ax2.set_xticklabels(tick_labels)

    # Main title
    fig.suptitle(
        "Figure: Impact of Bandwidth Utilization on User-Perceived Latency (Simple Switch)",
        fontsize=15, fontweight="bold", y=0.98
    )

    plt.tight_layout()
    path = os.path.join(IMAGES_DIR, "fig_latency_vs_bandwidth.png")
    fig.savefig(path, dpi=300)
    plt.close(fig)
    print(f"[saved] {path}")

if __name__ == "__main__":
    generate_figure()

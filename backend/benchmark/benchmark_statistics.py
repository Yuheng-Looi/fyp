#!/usr/bin/env python3
"""
statistics.py — Phase 4.9 Math Engine

Walks results/benchmark_runs/ and reads all seed JSON files.
For every (Controller × Topology × Scenario) combination, calculates:
  Mean, Median, Std Dev, Min, Max, and 95% Confidence Interval

Exports to results/summary.csv
"""

import csv
import json
import math
import os
import sys
from collections import defaultdict

BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
RUNS_DIR = os.path.join(BENCHMARK_DIR, "results", "benchmark_runs")
OUTPUT_CSV = os.path.join(BENCHMARK_DIR, "results", "summary.csv")

METRICS = [
    "SCS", "QPS", "UIS", "RES", "NRS",
    "WS", "DB", "SPS", "OFS",
    "avg_latency",
]

# We alias avg_latency -> latency_avg in the CSV for paper-friendliness
METRIC_CSV_NAMES = {
    "SCS": "SCS",
    "QPS": "QPS",
    "UIS": "UIS",
    "RES": "RES",
    "NRS": "NRS",
    "WS": "WS",
    "DB": "DB",
    "SPS": "SPS",
    "OFS": "OFS",
    "avg_latency": "latency_avg",
}


def mean(values):
    return sum(values) / len(values) if values else 0.0


def median(values):
    s = sorted(values)
    n = len(s)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2 == 0:
        return (s[mid - 1] + s[mid]) / 2.0
    return s[mid]


def stdev(values):
    if len(values) < 2:
        return 0.0
    m = mean(values)
    variance = sum((x - m) ** 2 for x in values) / (len(values) - 1)
    return math.sqrt(variance)


def ci_95(values):
    """Return the 95% CI half-width (t-distribution approximation for small n)."""
    n = len(values)
    if n < 2:
        return 0.0
    sd = stdev(values)
    # t-value for 95% CI with n-1 degrees of freedom (approximation for small n)
    t_values = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
                6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228}
    t = t_values.get(n - 1, 1.96)  # fallback to z=1.96 for large n
    return t * sd / math.sqrt(n)


def collect_data():
    """Walk the benchmark_runs directory and collect metric values per combo."""
    # Key: (controller, topology, scenario) -> {metric: [values]}
    data = defaultdict(lambda: defaultdict(list))

    if not os.path.isdir(RUNS_DIR):
        print(f"[error] Runs directory not found: {RUNS_DIR}")
        sys.exit(1)

    file_count = 0
    for controller in sorted(os.listdir(RUNS_DIR)):
        ctrl_dir = os.path.join(RUNS_DIR, controller)
        if not os.path.isdir(ctrl_dir):
            continue
        for topology in sorted(os.listdir(ctrl_dir)):
            topo_dir = os.path.join(ctrl_dir, topology)
            if not os.path.isdir(topo_dir):
                continue
            for scenario in sorted(os.listdir(topo_dir)):
                scen_dir = os.path.join(topo_dir, scenario)
                if not os.path.isdir(scen_dir):
                    continue
                for seed_file in sorted(os.listdir(scen_dir)):
                    if not seed_file.endswith(".json"):
                        continue
                    filepath = os.path.join(scen_dir, seed_file)
                    try:
                        with open(filepath, "r") as f:
                            run_data = json.load(f)
                    except Exception as e:
                        print(f"[warn] Skipping {filepath}: {e}")
                        continue

                    # Extract scores from the results dict
                    results = run_data.get("results", {})
                    # The results dict has controller_name -> topology -> scores
                    # We need to find the scores regardless of key naming
                    scores = None
                    for ctrl_key, topo_dict in results.items():
                        if isinstance(topo_dict, dict):
                            for topo_key, score_dict in topo_dict.items():
                                if isinstance(score_dict, dict) and "NRS" in score_dict:
                                    scores = score_dict
                                    break
                        if scores:
                            break

                    if not scores:
                        print(f"[warn] No scores found in {filepath}")
                        continue

                    key = (controller, topology, scenario)
                    for metric in METRICS:
                        val = scores.get(metric)
                        if val is not None:
                            data[key][metric].append(float(val))

                    file_count += 1

    print(f"[stats] Loaded {file_count} run files across {len(data)} combinations")
    return data


def compute_and_export(data):
    """Compute statistics and write to CSV."""
    rows = []

    for (controller, topology, scenario), metrics_dict in sorted(data.items()):
        for metric in METRICS:
            csv_name = METRIC_CSV_NAMES.get(metric, metric)
            values = metrics_dict.get(metric, [])
            n = len(values)

            if n == 0:
                continue

            row = {
                "controller": controller,
                "topology": topology,
                "scenario": scenario,
                "metric": csv_name,
                "n": n,
                "mean": round(mean(values), 6),
                "median": round(median(values), 6),
                "std": round(stdev(values), 6),
                "min": round(min(values), 6),
                "max": round(max(values), 6),
                "ci_95": round(ci_95(values), 6),
            }
            rows.append(row)

    # Write CSV
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    fieldnames = ["controller", "topology", "scenario", "metric",
                  "n", "mean", "median", "std", "min", "max", "ci_95"]

    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[stats] Exported {len(rows)} rows to {OUTPUT_CSV}")


def main():
    print("=" * 60)
    print("  STATISTICS ENGINE — Phase 4.9")
    print("=" * 60)

    data = collect_data()
    compute_and_export(data)

    print("[stats] Done.")


if __name__ == "__main__":
    main()

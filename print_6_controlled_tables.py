#!/usr/bin/env python3
"""
print_6_controlled_tables.py — Format per-second raw telemetry for the 6 controlled conditions.
"""

import glob
import json
import os

RESULTS_DIR = "/home/fyp2025/fyp/backend/benchmark/results/controlled_6_runs"


def main():
    files = sorted(glob.glob(os.path.join(RESULTS_DIR, "*.json")))

    for fpath in files:
        with open(fpath) as f:
            data = json.load(f)

        meta = data["run_metadata"]
        scores = data["scores"]
        logs = data["per_second_logs"]
        lat_stats = scores.get("latency_stats", {})

        print("\n" + "=" * 115)
        print(f"  PER-SECOND RAW TELEMETRY: {meta['controller'].upper()} | Scenario: {meta['scenario'].upper()}")
        print(f"  Mean Latency: {lat_stats.get('mean_ms', 0):.3f} ms | P95: {lat_stats.get('p95_ms', 0):.3f} ms | Max: {lat_stats.get('max_ms', 0):.3f} ms | SCS: {scores.get('SCS', 1.0):.4f} | QPS: {scores.get('QPS', 1.0):.4f}")
        print("=" * 115)

        header = f"{'Elapsed':<8} | {'Phase':<9} | {'Benign Off (KB/s)':<17} | {'Benign Del (KB/s)':<17} | {'Att Off (KB/s)':<14} | {'Att Del (KB/s)':<14} | {'Util (%)':<9} | {'Reason Code'}"
        print(header)
        print("-" * len(header))

        for log in logs:
            print(f"{log['elapsed']:<8.1f} | {log['phase']:<9} | {log['benign_offered_throughput_kbps']:>17.2f} | {log['benign_delivered_throughput_kbps']:>17.2f} | {log['attack_offered_throughput_kbps']:>14.2f} | {log['attack_delivered_throughput_kbps']:>14.2f} | {log['bottleneck_utilization_pct']:>9.2f} | {log.get('reason_code', 'NORMAL')}")


if __name__ == "__main__":
    main()

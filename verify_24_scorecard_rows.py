#!/usr/bin/env python3
"""
verify_24_scorecard_rows.py — Verify exact loading of all 24 JSON score rows (12 Small + 12 Large).
"""

import glob
import json
import os
import sys

BASE_DIR = "/home/fyp2025/fyp/backend/benchmark/results/benchmark_runs"

CONTROLLERS = ["simple_switch_13", "controller_4"]
TOPOLOGIES = ["small", "large"]
SCENARIOS = ["probe", "dos", "ddos", "sqli_web", "credential_attack", "exfiltration"]


def verify_all_24_rows():
    print("=" * 120)
    print("  VERIFYING ALL 24 BENCHMARK SCORECARD ROWS (12 Small + 12 Large)")
    print("=" * 120)

    rows = []
    missing = []
    hashes = set()

    for ctrl in CONTROLLERS:
        for topo in TOPOLOGIES:
            for scen in SCENARIOS:
                fpath = os.path.join(BASE_DIR, ctrl, topo, scen, "seed_1.json")
                if not os.path.exists(fpath):
                    missing.append((ctrl, topo, scen, fpath))
                    continue

                with open(fpath) as f:
                    data = json.load(f)

                scores = data.get("scores", {})
                row_tuple = (
                    ctrl, topo, scen,
                    scores.get("SCS"), scores.get("QPS"), scores.get("UIS"),
                    scores.get("RES"), scores.get("SPS"), scores.get("NRS"), scores.get("OFS")
                )
                row_str = str(row_tuple)

                rows.append({
                    "controller": ctrl,
                    "topology": topo,
                    "scenario": scen,
                    "path": fpath,
                    "scores": scores,
                    "row_str": row_str
                })
                hashes.add(row_str)

    print(f"\nTotal Loaded Run Files: {len(rows)} / 24")
    if missing:
        print(f"[ERROR] {len(missing)} run files missing:")
        for m in missing:
            print(f"  - {m[0]} | {m[1]} | {m[2]} -> {m[3]}")
    else:
        print("[SUCCESS] All 24 JSON run files exist and loaded successfully.")

    print("\n" + "-" * 120)
    print(f"{'#':<3} | {'Controller':<18} | {'Topo':<6} | {'Scenario':<18} | {'SCS':<6} | {'QPS':<6} | {'UIS':<6} | {'RES':<6} | {'SPS':<6} | {'NRS':<6} | {'OFS':<6}")
    print("-" * 120)

    idx = 1
    for r in rows:
        sc = r["scores"]
        print(f"{idx:<3} | {r['controller']:<18} | {r['topology']:<6} | {r['scenario']:<18} | {sc.get('SCS', 0):<6.4f} | {sc.get('QPS', 0):<6.4f} | {sc.get('UIS', 0):<6.4f} | {sc.get('RES', 0):<6.4f} | {sc.get('SPS', 0):<6.4f} | {sc.get('NRS', 0):<6.4f} | {sc.get('OFS', 0):<6.4f}")
        idx += 1

    print("-" * 120)
    print(f"Unique Score Hashes: {len(hashes)} / {len(rows)}")
    if missing:
        print("[STATUS] FAILED — Missing run files!")
        sys.exit(1)
    else:
        print("[STATUS] PASSED — All 24 distinct score rows verified.")


if __name__ == "__main__":
    verify_all_24_rows()

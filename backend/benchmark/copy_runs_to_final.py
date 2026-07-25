#!/usr/bin/env python3
"""
copy_runs_to_final.py
Copies all run files from results/benchmark_runs/ to results/final_atdm_runs/
with standardized names: <ctrl>_<topo>_<scen>_seed_<N>.json
"""
import os
import glob
import shutil

BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
RUNS_DIR = os.path.join(BENCHMARK_DIR, "results", "benchmark_runs")
FINAL_DIR = os.path.join(BENCHMARK_DIR, "results", "final_atdm_runs")

os.makedirs(FINAL_DIR, exist_ok=True)

copied = 0
for root, dirs, files in os.walk(RUNS_DIR):
    for f in files:
        if f.endswith(".json") and f.startswith("seed_"):
            parts = root.split(os.sep)
            # root format: .../results/benchmark_runs/<controller>/<topology>/<scenario>
            scen = parts[-1]
            topo = parts[-2]
            ctrl = parts[-3]
            
            ctrl_name = "simple_switch_13" if ctrl == "simple_13" else ctrl
            target_name = f"{ctrl_name}_{topo}_{scen}_{f}"
            
            src = os.path.join(root, f)
            dst = os.path.join(FINAL_DIR, target_name)
            shutil.copy2(src, dst)
            copied += 1

print(f"[sync] Copied {copied} run files into {FINAL_DIR}")

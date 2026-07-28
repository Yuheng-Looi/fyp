#!/usr/bin/env python3
"""
test_single_atdm_run.py — Live Empirical Execution of ATDM (Controller 4) + Infer Server

Executes 1 live Mininet experiment (Small Topology, DDoS Scenario, 65s) with:
  1. Backend Inference Server (infer_server.py on port 8000)
  2. ATDM Ryu Controller (controller_4.py on port 6653)
  3. Real Mininet traffic (Benign + DDoS Attack)

Saves raw empirical telemetry to:
  backend/benchmark/results/controlled_4_runs/controller_4_small_ddos.json
"""

import json
import os
import subprocess
import sys
import time

SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
BENCHMARK_DIR = os.path.join(SCRIPT_DIR, "backend", "benchmark")
BACKEND_DIR = os.path.join(SCRIPT_DIR, "backend")

if BENCHMARK_DIR not in sys.path:
    sys.path.insert(0, BENCHMARK_DIR)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from core.experiment_runner import ExperimentRunner

RESULTS_DIR = os.path.join(BENCHMARK_DIR, "results")
OUT_DIR = os.path.join(RESULTS_DIR, "controlled_4_runs")
OUT_FILE = os.path.join(OUT_DIR, "controller_4_small_ddos.json")

PYTHON_BIN = "/home/fyp2025/fyp/backend/benchmark/benchmarkenv/bin/python"


def clean_environment():
    """Reset Mininet and clean up background processes."""
    subprocess.run(["mn", "-c"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "hping3"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "iperf3"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "curl"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "ryu-manager"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "infer_server"], capture_output=True)
    subprocess.run(["fuser", "-k", "-9", "6653/tcp"], capture_output=True)
    subprocess.run(["fuser", "-k", "-9", "8000/tcp"], capture_output=True)
    time.sleep(2)


def start_infer_server():
    """Start backend inference server on port 8000."""
    cmd = [PYTHON_BIN, "-m", "uvicorn", "infer_server:app", "--host", "0.0.0.0", "--port", "8000"]
    proc = subprocess.Popen(cmd, cwd=BACKEND_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3.5)
    return proc


def run_single_atdm_live_experiment():
    print("=" * 80)
    print("  RUNNING LIVE EMPIRICAL ATDM EXPERIMENT (Controller 4 + Infer Server)")
    print("=" * 80)

    clean_environment()
    os.makedirs(OUT_DIR, exist_ok=True)

    print("[1/3] Starting backend infer_server on port 8000...")
    infer_proc = start_infer_server()

    try:
        config_path = os.path.join(BENCHMARK_DIR, "config", "experiment.yaml")
        scenario_path = os.path.join(BENCHMARK_DIR, "config", "scenarios", "ddos.yaml")
        controller_path = os.path.join(BENCHMARK_DIR, "controllers", "controller_4.py")

        print("[2/3] Initializing ExperimentRunner for Small topology, DDoS scenario...")
        runner = ExperimentRunner(
            config_path=config_path,
            scenario_path=scenario_path,
            controller_path=controller_path,
            topology_name="small",
            real_time=True
        )

        print("[3/3] Executing 65-second live experiment on Mininet...")
        scores = runner.run()

        # Save empirical results
        run_data = {
            "metadata": {
                "controller": "controller_4",
                "topology": "small",
                "scenario": "ddos",
                "mode": "empirical_live_test"
            },
            "scores": scores,
        }

        with open(OUT_FILE, "w") as f:
            json.dump(run_data, f, indent=2)

        print(f"\n[saved] Live empirical ATDM telemetry saved to: {OUT_FILE}")
        print("=" * 80)

    finally:
        clean_environment()


if __name__ == "__main__":
    run_single_atdm_live_experiment()

#!/usr/bin/env python3
"""
run_http_workload_isolation.py — Empirical HTTP Workload Isolation & Validation Suite
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


def clean_env():
    subprocess.run(["mn", "-c"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "hping3"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "iperf3"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "curl"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "while true"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "ryu-manager"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "infer_server"], capture_output=True)
    subprocess.run(["fuser", "-k", "-9", "6653/tcp"], capture_output=True)
    subprocess.run(["fuser", "-k", "-9", "8000/tcp"], capture_output=True)
    time.sleep(2)


def run_isolation_test(test_name, enable_bg_http=True, enable_attack=True, ctrl_path="controllers/controller_4.py"):
    print("\n" + "=" * 75)
    print(f"  EXECUTING WORKLOAD ISOLATION TEST: {test_name}")
    print("=" * 75)

    clean_env()

    config_path = os.path.join(BENCHMARK_DIR, "config", "experiment.yaml")
    scen_path = os.path.join(BENCHMARK_DIR, "config", "scenarios", "ddos.yaml")
    ctrl_abs = os.path.join(BENCHMARK_DIR, ctrl_path)

    runner = ExperimentRunner(
        config_path,
        scen_path,
        controller_path=ctrl_abs,
        topology_name="small",
        real_time=True,
    )

    if not enable_attack:
        # Override attack to do nothing
        runner._attack.start_attack = lambda scen, net=None: print("[attack] Attack DISABLED for this test")

    if not enable_bg_http:
        # Override normal traffic HTTP loop to do nothing
        orig_start = runner._normal_traffic.start
        def start_no_http(net=None):
            orig_start(net)
            # Stop curl loops
            for rec in list(runner._normal_traffic._client_procs):
                if rec.get("role") == "http":
                    p = rec.get("proc")
                    if p:
                        p.terminate()
            print("[traffic] Background HTTP loop DISABLED for this test")
        runner._normal_traffic.start = start_no_http

    scores = runner.run()

    # Collect telemetry details from runner
    probes = runner._asset_monitor.probe_history
    t0 = probes[0]["timestamp"] if probes else 0.0

    p_base = [p for p in probes if 5.0 <= (p["timestamp"] - t0 + 5.0) < 20.0]
    p_att = [p for p in probes if 20.0 <= (p["timestamp"] - t0 + 5.0) <= 50.0]

    lat_base = [p["latency_ms"] for p in p_base if p.get("latency_ms") is not None]
    lat_att = [p["latency_ms"] for p in p_att if p.get("latency_ms") is not None]

    base_mean = sum(lat_base) / len(lat_base) if lat_base else 0.0
    att_mean = sum(lat_att) / len(lat_att) if lat_att else 0.0
    att_sorted = sorted(lat_att) if lat_att else [0.0]
    att_median = att_sorted[len(att_sorted) // 2]
    att_p95 = att_sorted[int(len(att_sorted) * 0.95)]
    att_max = max(att_sorted)

    print(f"\n--- RESULTS: {test_name} ---")
    print(f"Baseline Probe Latency Mean: {base_mean:.3f} ms (count={len(p_base)})")
    print(f"Attack-Phase Probe Latency Mean: {att_mean:.3f} ms (count={len(p_att)})")
    print(f"Attack-Phase Median: {att_median:.3f} ms | P95: {att_p95:.3f} ms | Max: {att_max:.3f} ms")

    return {
        "test_name": test_name,
        "base_mean_ms": round(base_mean, 3),
        "att_mean_ms": round(att_mean, 3),
        "att_median_ms": round(att_median, 3),
        "att_p95_ms": round(att_p95, 3),
        "att_max_ms": round(att_max, 3),
        "scores": scores,
        "probe_history": probes
    }


if __name__ == "__main__":
    results = {}
    
    # 1. Test A: HTTP Latency Probes ONLY (No bg HTTP loop, No attack)
    results["test_a_probes_only"] = run_isolation_test("Test A: Probes ONLY", enable_bg_http=False, enable_attack=False)

    # 2. Test B: Fixed-Rate Background HTTP Traffic + Probes (No attack)
    results["test_b_bg_http_no_attack"] = run_isolation_test("Test B: BG HTTP + Probes (No Attack)", enable_bg_http=True, enable_attack=False)

    # 3. Test C1: Fixed-Rate BG HTTP + Probes + DDoS (ATDM)
    results["test_c1_atdm_ddos"] = run_isolation_test("Test C1: ATDM DDoS", enable_bg_http=True, enable_attack=True, ctrl_path="controllers/controller_4.py")

    # 4. Test C2: Fixed-Rate BG HTTP + Probes + DDoS (Simple Switch 13)
    results["test_c2_ss13_ddos"] = run_isolation_test("Test C2: Simple Switch 13 DDoS", enable_bg_http=True, enable_attack=True, ctrl_path="controllers/simple_13.py")

    out_file = "/home/fyp2025/fyp/backend/benchmark/results/http_isolation_results.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[success] All isolation tests completed! Results saved to {out_file}")

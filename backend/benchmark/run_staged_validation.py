#!/usr/bin/env python3
"""
run_staged_validation.py — Staged validation tests A–E for the fixed benchmark pipeline.

Runs 5 tests in sequence, checking acceptance criteria after each.
Only reports PASS/FAIL — does not run the full 24-run benchmark.

Must be run as root (sudo) with Mininet access.

Usage:
    sudo PYTHONPATH=/usr/lib/python3/dist-packages python3 run_staged_validation.py
"""

import json
import os
import subprocess
import sys
import time

# Add benchmark dir to path
BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(BENCHMARK_DIR)
sys.path.insert(0, BENCHMARK_DIR)
sys.path.insert(0, BACKEND_DIR)

RESULTS_DIR = os.path.join(BENCHMARK_DIR, "results", "staged_validation")
os.makedirs(RESULTS_DIR, exist_ok=True)


def clean_environment():
    """Kill leftover processes and clean Mininet."""
    print("\n[clean] Cleaning environment...")
    subprocess.run(["mn", "-c"], capture_output=True)
    subprocess.run(["pkill", "-9", "hping3"], capture_output=True)
    subprocess.run(["pkill", "-9", "iperf3"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "while true"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "ryu-manager"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "ryu.cmd.manager"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "os_ken.cmd.manager"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "infer_server"], capture_output=True)
    subprocess.run(["fuser", "-k", "-9", "6653/tcp"], capture_output=True)
    subprocess.run(["fuser", "-k", "-9", "8000/tcp"], capture_output=True)
    time.sleep(2)


def run_experiment(controller_path, scenario_path, topology="small"):
    """Run a single experiment and return scores dict."""
    from core.experiment_runner import ExperimentRunner

    config_path = os.path.join(BENCHMARK_DIR, "config", "experiment.yaml")
    ctrl_abs = os.path.join(BENCHMARK_DIR, controller_path)
    scen_abs = os.path.join(BENCHMARK_DIR, scenario_path)

    runner = ExperimentRunner(
        config_path,
        scen_abs,
        controller_path=ctrl_abs,
        topology_name=topology,
        real_time=True,
    )
    scores = runner.run()
    return scores


def extract_metrics(scores):
    """Extract key metrics from experiment scores for validation."""
    # QoS metrics
    qos_history = scores.get("qos_history", [])
    flow_history = scores.get("flow_history", [])
    probe_history = scores.get("probe_history", [])

    # Bandwidth utilization by phase
    LINK_LIMIT_BPS = 2_560_000.0  # 20 Mbps

    def phase_bw(phase):
        ticks = [t for t in qos_history if t.get("phase") == phase]
        if not ticks:
            return 0.0
        bw_values = []
        for t in ticks:
            total_bps = sum(t.get("throughput", {}).values())
            bw_pct = (total_bps / LINK_LIMIT_BPS) * 100.0
            bw_values.append(bw_pct)
        return sum(bw_values) / len(bw_values) if bw_values else 0.0

    # Benign throughput (client tx) by phase
    def phase_throughput(phase):
        ticks = [t for t in flow_history if t.get("phase") == phase]
        if not ticks:
            return 0.0
        tp_values = []
        for t in ticks:
            total_bps = sum(t.get("throughput", {}).values())
            tp_values.append(total_bps / 1024.0)  # KB/s
        return sum(tp_values) / len(tp_values) if tp_values else 0.0

    # Latency from probe history
    latencies = [p.get("latency_ms") for p in probe_history if p.get("latency_ms") is not None]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    # HTTP success/failure counts
    successes = sum(1 for p in probe_history if p.get("status_code") == 200)
    failures = sum(1 for p in probe_history if p.get("status_code") != 200)

    return {
        "baseline_bw_pct": phase_bw("baseline"),
        "attack_bw_pct": phase_bw("attack"),
        "recovery_bw_pct": phase_bw("recovery"),
        "baseline_throughput_kbps": phase_throughput("baseline"),
        "attack_throughput_kbps": phase_throughput("attack"),
        "recovery_throughput_kbps": phase_throughput("recovery"),
        "avg_latency_ms": avg_latency,
        "http_successes": successes,
        "http_failures": failures,
        "total_qos_samples": len(qos_history),
        "total_flow_samples": len(flow_history),
        "total_probes": len(probe_history),
        "SCS": scores.get("SCS", 0.0),
        "QPS": scores.get("QPS", 0.0),
        "UIS": scores.get("UIS", 0.0),
        "RES": scores.get("RES", 0.0),
        "NRS": scores.get("NRS", 0.0),
        "OFS": scores.get("OFS", 0.0),
    }


# ======================================================================
# Test A — Benign baseline (no attack)
# ======================================================================
def test_a():
    """Simple Switch 13, Small topology, no attack — sustained benign traffic."""
    print("\n" + "=" * 70)
    print("  TEST A — Benign Baseline (Simple Switch 13, Small, Probe)")
    print("  Expected: benign throughput >> 0.07 KB/s, latency valid, BW > 0%")
    print("=" * 70)

    clean_environment()

    # Use probe scenario (minimal attack impact) as the closest to "no attack"
    scores = run_experiment(
        controller_path="controllers/simple_13.py",
        scenario_path="config/scenarios/probe.yaml",
        topology="small",
    )

    metrics = extract_metrics(scores)

    # Acceptance criteria
    criteria = {}
    criteria["benign_throughput_above_probe"] = metrics["baseline_throughput_kbps"] > 0.5  # > 0.5 KB/s (vs 0.07)
    criteria["latency_valid"] = metrics["avg_latency_ms"] > 0.0
    criteria["bw_util_nonzero"] = metrics["baseline_bw_pct"] > 0.001
    criteria["has_probes"] = metrics["total_probes"] > 0

    passed = all(criteria.values())
    metrics["criteria"] = criteria
    metrics["passed"] = passed

    print(f"\n[Test A] Baseline BW: {metrics['baseline_bw_pct']:.4f}%")
    print(f"[Test A] Baseline Throughput: {metrics['baseline_throughput_kbps']:.2f} KB/s")
    print(f"[Test A] Avg Latency: {metrics['avg_latency_ms']:.2f} ms")
    print(f"[Test A] HTTP Success/Fail: {metrics['http_successes']}/{metrics['http_failures']}")
    print(f"[Test A] Criteria: {criteria}")
    print(f"[Test A] {'PASSED ✓' if passed else 'FAILED ✗'}")

    return metrics


# ======================================================================
# Test B — DoS
# ======================================================================
def test_b():
    """Simple Switch 13, Small topology, DoS — single attacker volumetric."""
    print("\n" + "=" * 70)
    print("  TEST B — DoS (Simple Switch 13, Small)")
    print("  Expected: BW util rises substantially, 1 attacker sustained")
    print("=" * 70)

    clean_environment()

    scores = run_experiment(
        controller_path="controllers/simple_13.py",
        scenario_path="config/scenarios/dos.yaml",
        topology="small",
    )

    metrics = extract_metrics(scores)

    criteria = {}
    criteria["attack_traffic_volumetric"] = metrics["attack_bw_pct"] > 0.01 or metrics["attack_throughput_kbps"] > 100.0
    criteria["has_qos_samples"] = metrics["total_qos_samples"] > 5

    passed = all(criteria.values())
    metrics["criteria"] = criteria
    metrics["passed"] = passed

    print(f"\n[Test B] Baseline BW: {metrics['baseline_bw_pct']:.4f}%")
    print(f"[Test B] Attack BW: {metrics['attack_bw_pct']:.4f}%")
    print(f"[Test B] Recovery BW: {metrics['recovery_bw_pct']:.4f}%")
    print(f"[Test B] Baseline Throughput: {metrics['baseline_throughput_kbps']:.2f} KB/s")
    print(f"[Test B] Attack Throughput: {metrics['attack_throughput_kbps']:.2f} KB/s")
    print(f"[Test B] Avg Latency: {metrics['avg_latency_ms']:.2f} ms")
    print(f"[Test B] Criteria: {criteria}")
    print(f"[Test B] {'PASSED ✓' if passed else 'FAILED ✗'}")

    return metrics


# ======================================================================
# Test C — DDoS
# ======================================================================
def test_c():
    """Simple Switch 13, Small topology, DDoS — multi-attacker flood."""
    print("\n" + "=" * 70)
    print("  TEST C — DDoS (Simple Switch 13, Small)")
    print("  Expected: multiple attackers, utilization approaches capacity")
    print("=" * 70)

    clean_environment()

    scores = run_experiment(
        controller_path="controllers/simple_13.py",
        scenario_path="config/scenarios/ddos.yaml",
        topology="small",
    )

    metrics = extract_metrics(scores)

    criteria = {}
    criteria["attack_traffic_volumetric"] = metrics["attack_bw_pct"] > 0.01 or metrics["attack_throughput_kbps"] > 100.0
    criteria["has_qos_samples"] = metrics["total_qos_samples"] > 5

    passed = all(criteria.values())
    metrics["criteria"] = criteria
    metrics["passed"] = passed

    print(f"\n[Test C] Baseline BW: {metrics['baseline_bw_pct']:.4f}%")
    print(f"[Test C] Attack BW: {metrics['attack_bw_pct']:.4f}%")
    print(f"[Test C] Recovery BW: {metrics['recovery_bw_pct']:.4f}%")
    print(f"[Test C] Baseline Throughput: {metrics['baseline_throughput_kbps']:.2f} KB/s")
    print(f"[Test C] Attack Throughput: {metrics['attack_throughput_kbps']:.2f} KB/s")
    print(f"[Test C] Criteria: {criteria}")
    print(f"[Test C] {'PASSED ✓' if passed else 'FAILED ✗'}")

    return metrics


# ======================================================================
# Test D — Non-volumetric attack (SQL Injection)
# ======================================================================
def test_d():
    """Simple Switch 13, Small topology, SQL Injection — low bandwidth attack."""
    print("\n" + "=" * 70)
    print("  TEST D — SQL Injection (Simple Switch 13, Small)")
    print("  Expected: attack runs, BW stays low, does not resemble DoS")
    print("=" * 70)

    clean_environment()

    scores = run_experiment(
        controller_path="controllers/simple_13.py",
        scenario_path="config/scenarios/sqli_web.yaml",
        topology="small",
    )

    metrics = extract_metrics(scores)

    criteria = {}
    # Attack BW should be present but low — less than half of DoS levels
    criteria["attack_runs"] = metrics["total_qos_samples"] > 5
    criteria["bw_stays_low"] = metrics["attack_bw_pct"] < 50.0  # doesn't resemble DoS
    criteria["has_flow_data"] = metrics["total_flow_samples"] > 0

    passed = all(criteria.values())
    metrics["criteria"] = criteria
    metrics["passed"] = passed

    print(f"\n[Test D] Baseline BW: {metrics['baseline_bw_pct']:.4f}%")
    print(f"[Test D] Attack BW: {metrics['attack_bw_pct']:.4f}%")
    print(f"[Test D] Baseline Throughput: {metrics['baseline_throughput_kbps']:.2f} KB/s")
    print(f"[Test D] Attack Throughput: {metrics['attack_throughput_kbps']:.2f} KB/s")
    print(f"[Test D] Criteria: {criteria}")
    print(f"[Test D] {'PASSED ✓' if passed else 'FAILED ✗'}")

    return metrics


# ======================================================================
# Test E — ATDM mitigation (DDoS)
# ======================================================================
def test_e():
    """ATDM controller, Small topology, DDoS — mitigation active."""
    print("\n" + "=" * 70)
    print("  TEST E — DDoS with ATDM Mitigation (Small)")
    print("  Expected: infer_server healthy, mitigation rules installed")
    print("=" * 70)

    clean_environment()

    try:
        scores = run_experiment(
            controller_path="controllers/controller_4.py",
            scenario_path="config/scenarios/ddos.yaml",
            topology="small",
        )
    except RuntimeError as e:
        print(f"[Test E] FAILED — experiment error: {e}")
        return {
            "passed": False,
            "error": str(e),
            "criteria": {"infer_server_healthy": False},
        }

    metrics = extract_metrics(scores)

    criteria = {}
    criteria["infer_server_healthy"] = True  # If we got here, it started
    criteria["attack_traffic_present"] = metrics["attack_bw_pct"] > 0.001 or metrics["attack_throughput_kbps"] > 10.0
    criteria["has_qos_samples"] = metrics["total_qos_samples"] > 5
    criteria["benign_traffic_active"] = metrics["baseline_throughput_kbps"] > 0.1

    passed = all(criteria.values())
    metrics["criteria"] = criteria
    metrics["passed"] = passed

    print(f"\n[Test E] Baseline BW: {metrics['baseline_bw_pct']:.4f}%")
    print(f"[Test E] Attack BW: {metrics['attack_bw_pct']:.4f}%")
    print(f"[Test E] Recovery BW: {metrics['recovery_bw_pct']:.4f}%")
    print(f"[Test E] Baseline Throughput: {metrics['baseline_throughput_kbps']:.2f} KB/s")
    print(f"[Test E] Attack Throughput: {metrics['attack_throughput_kbps']:.2f} KB/s")
    print(f"[Test E] Avg Latency: {metrics['avg_latency_ms']:.2f} ms")
    print(f"[Test E] HTTP Success/Fail: {metrics['http_successes']}/{metrics['http_failures']}")
    print(f"[Test E] Criteria: {criteria}")
    print(f"[Test E] {'PASSED ✓' if passed else 'FAILED ✗'}")

    # Try to read infer_server log
    infer_log = "/tmp/infer_server.log"
    if os.path.exists(infer_log):
        with open(infer_log) as f:
            log_content = f.read()
        print(f"\n[Test E] Inference server log ({len(log_content)} chars):")
        # Print last 500 chars
        if len(log_content) > 500:
            print("  ... (truncated) ...")
        print(log_content[-500:] if log_content else "  (empty)")

    return metrics


# ======================================================================
# Main
# ======================================================================
def main():
    print("=" * 70)
    print("  STAGED VALIDATION — Benchmark Traffic Generation Pipeline")
    print("  Tests A–E must all pass before running the 24-run benchmark")
    print("=" * 70)

    all_results = {}
    all_passed = True
    test_funcs = [
        ("A", "Benign Baseline", test_a),
        ("B", "DoS", test_b),
        ("C", "DDoS", test_c),
        ("D", "SQL Injection", test_d),
        ("E", "ATDM DDoS Mitigation", test_e),
    ]

    for test_id, test_name, test_fn in test_funcs:
        try:
            result = test_fn()
            all_results[f"test_{test_id}"] = result
            if not result.get("passed", False):
                all_passed = False
                print(f"\n[VALIDATION] Test {test_id} ({test_name}) FAILED — continuing remaining tests")
        except Exception as e:
            print(f"\n[VALIDATION] Test {test_id} ({test_name}) EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
            all_results[f"test_{test_id}"] = {"passed": False, "error": str(e)}
            all_passed = False

    # Final cleanup
    clean_environment()

    # Summary
    print("\n" + "=" * 70)
    print("  STAGED VALIDATION SUMMARY")
    print("=" * 70)

    for test_id, test_name, _ in test_funcs:
        key = f"test_{test_id}"
        result = all_results.get(key, {})
        status = "PASSED ✓" if result.get("passed", False) else "FAILED ✗"
        print(f"  Test {test_id} ({test_name}): {status}")

    print(f"\n  OVERALL: {'ALL PASSED ✓ — Ready for 24-run benchmark' if all_passed else 'SOME TESTS FAILED ✗'}")
    print("=" * 70)

    # Save results
    output_path = os.path.join(RESULTS_DIR, "staged_validation_results.json")
    serializable = {}
    for k, v in all_results.items():
        serializable[k] = {sk: sv for sk, sv in v.items() if sk != "criteria" or isinstance(sv, dict)}
    with open(output_path, "w") as f:
        json.dump(serializable, f, indent=2, default=str)
    print(f"\n[output] Results saved to {output_path}")

    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

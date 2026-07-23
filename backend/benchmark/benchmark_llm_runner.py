#!/usr/bin/env python3
"""
benchmark_llm_runner.py — Phase 4.9 LLM Ablation Study Master Orchestrator

Systematically executes benchmark runs for the LLM-driven controllers:
  4 LLM Controllers × 2 Topologies × 6 Scenarios × 5 Seeds

Saves raw JSON outputs to:
  results/benchmark_runs/<controller>/<topology>/<scenario>/seed_<N>.json
"""

import json
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime
from itertools import product

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON_BIN = os.path.join(BENCHMARK_DIR, "benchmarkenv", "bin", "python")
BENCHMARK_SCRIPT = os.path.join(BENCHMARK_DIR, "benchmark.py")
RESULTS_DIR = os.path.join(BENCHMARK_DIR, "results")
RUNS_DIR = os.path.join(RESULTS_DIR, "benchmark_runs")

CONTROLLERS = [
    ("controller_4a", "controllers/controller_4a.py"),
    ("controller_4b", "controllers/controller_4b.py"),
    ("controller_4c", "controllers/controller_4c.py"),
    ("controller_4d", "controllers/controller_4d.py"),
]

TOPOLOGIES = ["small", "large"]

SCENARIOS = [
    ("probe",            "config/scenarios/probe.yaml"),
    ("dos",              "config/scenarios/dos.yaml"),
    ("ddos",             "config/scenarios/ddos.yaml"),
    ("sqli_web",         "config/scenarios/sqli_web.yaml"),
    ("credential_attack","config/scenarios/credential_attack.yaml"),
    ("exfiltration",     "config/scenarios/exfiltration.yaml"),
]

NUM_SEEDS = 5

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_version(cmd):
    """Run a command and return its stdout, or 'unknown'."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout.strip().split("\n")[0]
    except Exception:
        return "unknown"


def generate_manifest():
    """Write a manifest_llm.json documenting the environment."""
    ryu_bin = os.path.join(BENCHMARK_DIR, "benchmarkenv", "bin", "ryu-manager")
    ryu_version = get_version([ryu_bin, "--version"]) if os.path.exists(ryu_bin) else "unknown"
    mn_version = get_version(["mn", "--version"])
    python_version = get_version([PYTHON_BIN, "--version"])

    manifest = {
        "generated_at": datetime.now().isoformat(),
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "python_version": python_version,
        "ryu_version": ryu_version,
        "mininet_version": mn_version,
        "controllers": [c[0] for c in CONTROLLERS],
        "topologies": TOPOLOGIES,
        "scenarios": [s[0] for s in SCENARIOS],
        "seeds_per_combo": NUM_SEEDS,
        "total_runs": len(CONTROLLERS) * len(TOPOLOGIES) * len(SCENARIOS) * NUM_SEEDS,
    }

    manifest_path = os.path.join(RESULTS_DIR, "manifest_llm.json")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[manifest] Written to {manifest_path}")
    print(f"[manifest] Total planned runs: {manifest['total_runs']}")
    return manifest


def run_single_benchmark(controller_name, controller_path, topology, scenario_name, scenario_path, seed):
    """Execute a single benchmark run and save its JSON output."""

    # Prepare output directory
    out_dir = os.path.join(RUNS_DIR, controller_name, topology, scenario_name)
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, f"seed_{seed}.json")

    # Skip if already completed
    if os.path.exists(out_file):
        try:
            with open(out_file, "r") as f:
                data = json.load(f)
            if "results" in data:
                print(f"  [skip] Already exists: {out_file}")
                return True
        except Exception:
            pass  # Corrupted file, re-run

    # Build command
    cmd = [
        "sudo", PYTHON_BIN, BENCHMARK_SCRIPT,
        "--topology", topology,
        "--controller", controller_path,
        "--scenario", scenario_path,
        "--nobase",
    ]

    # Run benchmark
    try:
        result = subprocess.run(
            cmd,
            cwd=BENCHMARK_DIR,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout per run
        )
    except subprocess.TimeoutExpired:
        print(f"  [TIMEOUT] Run timed out after 300s")
        return False
    except Exception as e:
        print(f"  [ERROR] Subprocess failed: {e}")
        return False

    # Read the latest_benchmark.json that was produced
    latest_path = os.path.join(RESULTS_DIR, "latest_benchmark.json")
    if not os.path.exists(latest_path):
        print(f"  [ERROR] No latest_benchmark.json produced")
        return False

    try:
        with open(latest_path, "r") as f:
            benchmark_data = json.load(f)
    except Exception as e:
        print(f"  [ERROR] Failed to read latest_benchmark.json: {e}")
        return False

    # Enrich with run metadata
    benchmark_data["run_metadata"] = {
        "controller": controller_name,
        "topology": topology,
        "scenario": scenario_name,
        "seed": seed,
        "timestamp": datetime.now().isoformat(),
    }

    # Save to the organized location
    with open(out_file, "w") as f:
        json.dump(benchmark_data, f, indent=2)

    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("  LLM BENCHMARK RUNNER — Phase 4.9 Ablation Study Run")
    print("=" * 70)

    manifest = generate_manifest()
    total = manifest["total_runs"]
    completed = 0
    failed = 0
    start_time = time.time()

    combos = list(product(CONTROLLERS, TOPOLOGIES, SCENARIOS, range(1, NUM_SEEDS + 1)))

    for idx, ((ctrl_name, ctrl_path), topo, (scen_name, scen_path), seed) in enumerate(combos, 1):
        elapsed = time.time() - start_time
        eta = (elapsed / max(idx - 1, 1)) * (total - idx + 1) if idx > 1 else 0

        print(f"\n[{idx}/{total}] {ctrl_name} | {topo} | {scen_name} | seed={seed}  "
              f"(elapsed={elapsed/60:.1f}m, ETA={eta/60:.1f}m)")

        success = run_single_benchmark(ctrl_name, ctrl_path, topo, scen_name, scen_path, seed)

        if success:
            completed += 1
        else:
            failed += 1

    # Final summary
    total_time = time.time() - start_time
    print("\n" + "=" * 70)
    print(f"  LLM BENCHMARK RUNNER COMPLETE")
    print(f"  Completed: {completed}/{total}  |  Failed: {failed}  |  Time: {total_time/60:.1f} min")
    print("=" * 70)

    # Save completion summary
    summary = {
        "completed_at": datetime.now().isoformat(),
        "total_runs": total,
        "completed": completed,
        "failed": failed,
        "total_time_seconds": round(total_time, 2),
    }
    with open(os.path.join(RESULTS_DIR, "runner_llm_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)


if __name__ == "__main__":
    main()

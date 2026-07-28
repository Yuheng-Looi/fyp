import subprocess
import time
import os
import sys

BENCHMARK_DIR = "/home/fyp2025/fyp/backend/benchmark"
sys.path.insert(0, BENCHMARK_DIR)
sys.path.insert(0, "/home/fyp2025/fyp/backend")

from core.experiment_runner import ExperimentRunner

def clean():
    subprocess.run(["mn", "-c"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "hping3"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "iperf3"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "curl"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "ryu-manager"], capture_output=True)
    subprocess.run(["pkill", "-9", "-f", "infer_server"], capture_output=True)
    time.sleep(2)

clean()

runner = ExperimentRunner(
    os.path.join(BENCHMARK_DIR, "config", "experiment.yaml"),
    os.path.join(BENCHMARK_DIR, "config", "scenarios", "ddos.yaml"),
    controller_path=os.path.join(BENCHMARK_DIR, "controllers", "controller_4.py"),
    topology_name="small",
    real_time=True
)

def on_tick(elapsed):
    if 25.0 <= elapsed <= 45.0:
        res = subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"], capture_output=True, text=True)
        print(f"\n--- [{elapsed:.1f}s RAW OVS FLOW DUMP] ---")
        print(res.stdout)

runner._timeline.register("on_tick", on_tick)
scores = runner.run()

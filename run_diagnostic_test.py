#!/usr/bin/env python3
"""
run_diagnostic_test.py

Minimal controlled diagnostic test for Bandwidth Utilization and Benign Throughput data paths.
Runs minimal test for Simple Switch 13 and ATDM controllers under Small topology.
"""

import os
import sys
import time
import json
import socket
import subprocess

REPO_ROOT = "/home/fyp2025/fyp"
BENCHMARK_DIR = os.path.join(REPO_ROOT, "backend", "benchmark")
sys.path.insert(0, BENCHMARK_DIR)
sys.path.insert(0, os.path.join(REPO_ROOT, "backend"))

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink

def clean_mininet():
    print("[clean] Cleaning mininet and background processes...")
    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-9", "-f", "ryu-manager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-9", "-f", "infer_server.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-9", "-f", "http.server"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-9", "-f", "curl"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-9", "-f", "hping3"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-9", "-f", "iperf"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

def check_infer_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    result = sock.connect_ex(('127.0.0.1', 5001))
    sock.close()
    return result == 0

def start_infer_server():
    print("[infer_server] Starting backend/infer_server.py...")
    env = os.environ.copy()
    py_bin = os.path.join(REPO_ROOT, "backend", "fypenv", "bin", "python")
    p = subprocess.Popen([py_bin, "/home/fyp2025/fyp/backend/infer_server.py"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    for _ in range(15):
        if check_infer_server():
            print("[infer_server] infer_server.py is HEALTHY and listening on port 5001")
            return p
        time.sleep(1)
    print("[infer_server] WARNING: infer_server.py did not respond on port 5001")
    return p

def start_ryu_controller(controller_script):
    print(f"[ryu] Starting Ryu controller: {controller_script}")
    ryu_bin = os.path.join(BENCHMARK_DIR, "benchmarkenv", "bin", "ryu-manager")
    if not os.path.exists(ryu_bin):
        ryu_bin = "ryu-manager"
    
    env = os.environ.copy()
    compat_dir = os.path.join(BENCHMARK_DIR, "compat")
    backend_dir = os.path.join(REPO_ROOT, "backend")
    env["PYTHONPATH"] = f"{compat_dir}:{backend_dir}:{BENCHMARK_DIR}:" + env.get("PYTHONPATH", "")

    p = subprocess.Popen([ryu_bin, "--ofp-tcp-listen-port", "6653", controller_script],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    
    # Wait for port 6653
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if p.poll() is not None:
            stdout, _ = p.communicate()
            raise RuntimeError(f"Ryu process exited early: {stdout}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex(('127.0.0.1', 6653)) == 0:
                print("[ryu] Ryu controller listening on port 6653")
                return p
        time.sleep(0.5)
    raise RuntimeError("Ryu controller failed to listen on port 6653")

def run_minimal_controlled_test(controller_name, controller_script):
    print(f"\n=======================================================")
    print(f"RUNNING MINIMAL CONTROLLED TEST: {controller_name}")
    print(f"=======================================================")

    clean_mininet()

    infer_proc = None
    infer_healthy = False
    if controller_name == "ATDM":
        infer_proc = start_infer_server()
        infer_healthy = check_infer_server()

    ryu_proc = start_ryu_controller(controller_script)

    # Build Small Topology
    print("[topology] Building Mininet Small topology (s1, h1, h2, h3)...")
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24") # Web Server Asset
    h3 = net.addHost("h3", ip="10.0.0.3/24")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.start()
    net.staticArp()

    # Start HTTP server on h2:8080
    print("[service] Starting HTTP server on h2:8080...")
    h2.cmd("python3 -m http.server 8080 >/tmp/h2_http.log 2>&1 &")
    time.sleep(2)

    # Force ARP / flow resolution by pinging h2 from h1
    print("[network] Pre-warming flow table via ping...")
    h1.cmd("ping -c 2 -W 1 10.0.0.2 >/dev/null 2>&1")

    # Verify initial service health from h1 with strict timeout
    health_out = h1.cmd("curl --connect-timeout 2 --max-time 2 -s -o /dev/null -w '%{http_code}' http://10.0.0.2:8080/").strip()
    print(f"[service health] Initial HTTP probe from h1 -> h2:8080 HTTP status code: '{health_out}'")
    service_healthy = (health_out == "200")

    # Start continuous benign request loop on h1
    print("[traffic] Starting continuous HTTP request loop from h1 -> h2:8080...")
    h1.cmd("while true; do curl --connect-timeout 2 --max-time 2 -s http://10.0.0.2:8080/ >/dev/null; sleep 0.05; done &")

    # Sample counters over 5 seconds
    samples = []
    success_requests = 0
    
    last_h1_tx = int(h1.cmd("cat /sys/class/net/h1-eth0/statistics/tx_bytes").strip() or 0)
    last_h2_rx = int(h2.cmd("cat /sys/class/net/h2-eth0/statistics/rx_bytes").strip() or 0)
    last_time = time.monotonic()

    LINK_CAPACITY_BPS = 2560000.0 # 20 Mbps limit in B/s

    for sample_idx in range(1, 6):
        time.sleep(1.0)
        now = time.monotonic()
        dt = now - last_time
        
        curr_h1_tx = int(h1.cmd("cat /sys/class/net/h1-eth0/statistics/tx_bytes").strip() or 0)
        curr_h2_rx = int(h2.cmd("cat /sys/class/net/h2-eth0/statistics/rx_bytes").strip() or 0)

        # Check HTTP health
        res_code = h1.cmd("curl --connect-timeout 1 --max-time 1 -s -o /dev/null -w '%{http_code}' http://10.0.0.2:8080/").strip()
        if res_code == "200":
            success_requests += 1

        tx_diff = max(0, curr_h1_tx - last_h1_tx)
        rx_diff = max(0, curr_h2_rx - last_h2_rx)

        h1_tx_rate = tx_diff / dt # B/s
        h2_rx_rate = rx_diff / dt # B/s

        calc_bw_util_pct = (h2_rx_rate / LINK_CAPACITY_BPS) * 100.0
        calc_tp_kbps = (h1_tx_rate) / 1024.0

        sample_data = {
            "second": sample_idx,
            "dt": round(dt, 4),
            "h1_tx_bytes_raw": curr_h1_tx,
            "h1_tx_delta": tx_diff,
            "h2_rx_bytes_raw": curr_h2_rx,
            "h2_rx_delta": rx_diff,
            "h1_tx_rate_Bps": round(h1_tx_rate, 2),
            "h2_rx_rate_Bps": round(h2_rx_rate, 2),
            "calc_bw_util_pct": round(calc_bw_util_pct, 4),
            "calc_benign_tp_kbps": round(calc_tp_kbps, 4),
            "http_status": res_code
        }
        samples.append(sample_data)
        print(f"  [sec {sample_idx:2d}] dt={dt:.2f}s | h1_tx_delta={tx_diff:6d} B | h2_rx_delta={rx_diff:6d} B | "
              f"calc_BW={calc_bw_util_pct:6.4f}% | calc_TP={calc_tp_kbps:6.2f} KB/s | HTTP={res_code}")

        last_h1_tx = curr_h1_tx
        last_h2_rx = curr_h2_rx
        last_time = now

    h1.cmd("pkill -9 -f curl")
    h2.cmd("pkill -9 -f http.server")

    net.stop()
    ryu_proc.terminate()
    if infer_proc:
        infer_proc.terminate()

    avg_bw = sum(s["calc_bw_util_pct"] for s in samples) / len(samples)
    avg_tp = sum(s["calc_benign_tp_kbps"] for s in samples) / len(samples)

    res = {
        "controller": controller_name,
        "service_healthy": service_healthy,
        "infer_healthy": infer_healthy,
        "success_requests": success_requests,
        "sample_count": len(samples),
        "avg_calc_bw_util_pct": round(avg_bw, 4),
        "avg_calc_benign_tp_kbps": round(avg_tp, 4),
        "samples": samples
    }
    return res

def main():
    base_ctrl = os.path.join(BENCHMARK_DIR, "controllers", "simple_13.py")
    if not os.path.exists(base_ctrl):
        base_ctrl = os.path.join(BENCHMARK_DIR, "controllers", "base_controller.py")

    atdm_ctrl = os.path.join(BENCHMARK_DIR, "controllers", "controller_4.py")

    ss13_res = run_minimal_controlled_test("Simple Switch 13", base_ctrl)
    atdm_res = run_minimal_controlled_test("ATDM", atdm_ctrl)

    out_json = "/home/fyp2025/fyp/diagnostic_test_results.json"
    with open(out_json, "w") as f:
        json.dump({"simple_switch_13": ss13_res, "atdm": atdm_res}, f, indent=2)

    print("\n=======================================================")
    print(f"DIAGNOSTIC CONTROLLED TEST COMPLETED")
    print(f"Results saved to: {out_json}")
    print("=======================================================")

if __name__ == '__main__':
    main()

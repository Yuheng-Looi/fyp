import os
import sys
import time
import subprocess
import socket
import datetime
import json
import argparse
import random
from functools import partial

# Setup paths
sys.path.append("/home/fyp2025/fyp/backend")
sys.path.append("/home/fyp2025/fyp/backend/attack")

def wait_for_port(host, port, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.5)
    return False

def clean_up():
    print("[-] Cleaning up Mininet, Ryu, and background traffic...")
    subprocess.run(["sudo", "mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "ryu-manager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "-f", "app.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "hping3"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "nmap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "curl"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "ping"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "nc"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "-f", "traffic_loop"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def stop_traffic_processes():
    print("  [-] Stopping background traffic processes...")
    subprocess.run(["sudo", "pkill", "-9", "hping3"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "nmap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "curl"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "ping"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "nc"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-9", "-f", "traffic_loop"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_phase_0(net, run_config):
    print("  -> Phase 0: 1-to-1 traffic (Normal single-host request loop)")
    h_web = net.get(run_config["web_host"])
    user_name = random.choice(run_config["benign_hosts"])
    h_user = net.get(user_name)
    h_user.cmd(f"while true; do curl -s http://{h_web.IP()}/ >/dev/null; sleep 1; done &")

def run_phase_1(net, run_config):
    print("  -> Phase 1: 1-to-N traffic (Scanning target subnets)")
    att_name = random.choice(run_config["attacker_hosts"])
    h_key = net.get(att_name)
    
    # Attacker pings multiple subnet IPs sequentially
    target_ips = [run_config["web_ip"], run_config["db_ip"]] + run_config["benign_ips"][:3]
    ips_str = " ".join(target_ips)
    h_key.cmd(f"while true; do for ip in {ips_str}; do ping -c 1 -W 0.2 $ip >/dev/null; done; sleep 1; done &")
    
    # Attacker runs nmap ping scan on the subnet range
    subnet_base = ".".join(run_config["web_ip"].split(".")[:3]) + ".1-15"
    h_key.cmd(f"while true; do nmap -sP {subnet_base} >/dev/null; sleep 2; done &")

def run_phase_2(net, run_config):
    print("  -> Phase 2: N-to-1 traffic (Botnet / DDoS targeting the Web Server)")
    h_web = net.get(run_config["web_host"])
    
    # 2 attackers flooding the web server
    for att_name in run_config["attacker_hosts"][:2]:
        h_att = net.get(att_name)
        h_att.cmd(f"hping3 -S --flood -p 80 {h_web.IP()} >/dev/null 2>&1 &")
        
    # An attacker performing credential/DB queries mimicking compromised bot
    if len(run_config["attacker_hosts"]) > 0:
        h_att = net.get(random.choice(run_config["attacker_hosts"]))
        h_att.cmd(f"while true; do curl -s http://{h_web.IP()}/credentials >/dev/null; done &")
        
    if len(run_config["benign_hosts"]) > 0:
        h_user = net.get(random.choice(run_config["benign_hosts"]))
        h_user.cmd(f"while true; do curl -s http://{h_web.IP()}/query?q=admin >/dev/null; done &")

def run_phase_3(net, run_config):
    print("  -> Phase 3: N-to-N traffic (Normal distributed background traffic)")
    h_web = net.get(run_config["web_host"])
    
    # Benign hosts curl the web server and ping each other
    for idx, usr_name in enumerate(run_config["benign_hosts"]):
        h_user = net.get(usr_name)
        h_user.cmd(f"while true; do curl -s http://{h_web.IP()}/ >/dev/null; sleep {random.uniform(1.0, 2.5)}; done &")
        if idx < len(run_config["benign_hosts"]) - 1:
            next_usr_ip = run_config["benign_ips"][idx + 1]
            h_user.cmd(f"while true; do ping -c 1 {next_usr_ip} >/dev/null; sleep {random.uniform(1.5, 3.0)}; done &")

def run_phase_4(net, run_config):
    print("  -> Phase 4: service_transition traffic (User directly connecting to DB Server)")
    h_db = net.get(run_config["db_host"])
    
    for usr_name in run_config["benign_hosts"][:2]:
        h_user = net.get(usr_name)
        h_user.cmd(f"while true; do nc -zv {h_db.IP()} 3306 >/dev/null; sleep 1.5; done &")
        h_user.cmd(f"while true; do ping -c 1 {h_db.IP()} >/dev/null; sleep 1; done &")

def build_random_topology(run_config):
    try:
        from mininet.link import TCLink
        from mininet.topo import Topo
        from mininet.node import OVSSwitch
    except Exception as exc:
        raise RuntimeError("Mininet is required to run the benchmark") from exc

    class DynamicTopo(Topo):
        def build(self) -> None:
            switch = self.addSwitch("s1")
            
            # Add web server
            self.addHost(run_config["web_host"], ip=f"{run_config['web_ip']}/24")
            # Add DB server
            self.addHost(run_config["db_host"], ip=f"{run_config['db_ip']}/24")
            
            # Add benign hosts
            for host, ip in zip(run_config["benign_hosts"], run_config["benign_ips"]):
                self.addHost(host, ip=f"{ip}/24")
                
            # Add attacker hosts
            for host, ip in zip(run_config["attacker_hosts"], run_config["attacker_ips"]):
                self.addHost(host, ip=f"{ip}/24")

            # Add links
            self.addLink(run_config["web_host"], switch, bw=100)
            self.addLink(run_config["db_host"], switch, bw=1000)
            for host in run_config["benign_hosts"] + run_config["attacker_hosts"]:
                self.addLink(host, switch)

    return DynamicTopo(), partial(OVSSwitch, protocols="OpenFlow13"), TCLink

def create_random_network(run_config, controller_ip="127.0.0.1", controller_port=6653):
    try:
        from mininet.net import Mininet
        from mininet.node import RemoteController
        from functools import partial
    except Exception as exc:
        raise RuntimeError("Mininet is required to run the benchmark") from exc

    topo, switch_cls, link_cls = build_random_topology(run_config)
    controller = partial(RemoteController, ip=controller_ip, port=controller_port)
    switch_cls = partial(switch_cls, failMode="secure")

    net = Mininet(
        topo=topo,
        controller=controller,
        switch=switch_cls,
        link=link_cls,
        autoSetMacs=True,
        autoStaticArp=True,
        waitConnected=True,
    )

    # Custom start to launch the Flask app on the randomized web host
    orig_start = net.start
    def custom_start():
        orig_start()
        web_host = net.get(run_config["web_host"])
        web_host.cmd("PYTHONPATH=/home/fyp2025/.local/lib/python3.11/site-packages /home/fyp2025/fyp/backend/benchmark/benchmarkenv/bin/python /home/fyp2025/fyp/backend/app.py --port 80 > /tmp/flask_victim.log 2>&1 &")
        print(f"[topology] Spin up Flask app on Victim Server {run_config['web_host']} (IP {web_host.IP()})")
    net.start = custom_start

    return net

def run_scenarios(phase_duration, num_iterations):
    clean_up()

    snap_path = "/home/fyp2025/fyp/backend/graph_snapshots.json"
    labeled_snap_path = "/home/fyp2025/fyp/backend/graph_snapshots_labeled.json"
    
    if os.path.exists(snap_path):
        os.remove(snap_path)
    if os.path.exists(labeled_snap_path):
        os.remove(labeled_snap_path)
    
    ryu_path = "/home/fyp2025/fyp/backend/benchmark/benchmarkenv/bin/ryu-manager"
    controller_path = "/home/fyp2025/fyp/backend/benchmark/controllers/controller_1.py"
    compat_path = "/home/fyp2025/fyp/backend/benchmark/compat"
    backend_dir = "/home/fyp2025/fyp/backend"
    frontend_dir = "/home/fyp2025/fyp/frontend"
    system_packages_dir = "/usr/lib/python3/dist-packages"

    env = os.environ.copy()
    pythonpath = [compat_path, backend_dir, frontend_dir, system_packages_dir]
    env["PYTHONPATH"] = os.pathsep.join(pythonpath)
    env["PYTHONUNBUFFERED"] = "1"

    total_labeled_count = 0

    for run_idx in range(1, num_iterations + 1):
        print(f"\n==========================================")
        print(f"   STARTING INDEPENDENT RUN {run_idx} / {num_iterations}")
        print(f"==========================================")
        
        # 1. Randomize topology parameters
        num_hosts = random.randint(8, 18)
        host_indices = list(range(1, num_hosts + 1))
        random.shuffle(host_indices)
        
        # Roles assignment
        web_idx = host_indices[0]
        db_idx = host_indices[1]
        
        # 1 to 3 attackers
        num_attackers = random.randint(1, 3)
        attacker_indices = host_indices[2 : 2 + num_attackers]
        benign_indices = host_indices[2 + num_attackers :]
        
        # Subnet randomization
        subnet_x = random.randint(1, 254)
        subnet_y = random.randint(1, 254)
        subnet_prefix = f"10.{subnet_x}.{subnet_y}."
        
        # Host IPs randomization
        host_ips_pool = random.sample(range(2, 254), num_hosts)
        
        web_ip = f"{subnet_prefix}{host_ips_pool[0]}"
        db_ip = f"{subnet_prefix}{host_ips_pool[1]}"
        
        attacker_ips = [f"{subnet_prefix}{ip}" for ip in host_ips_pool[2 : 2 + num_attackers]]
        benign_ips = [f"{subnet_prefix}{ip}" for ip in host_ips_pool[2 + num_attackers :]]
        
        # Build run configuration dict
        run_config = {
            "web_host": f"h{web_idx}",
            "db_host": f"h{db_idx}",
            "attacker_hosts": [f"h{idx}" for idx in attacker_indices],
            "benign_hosts": [f"h{idx}" for idx in benign_indices],
            "web_ip": web_ip,
            "db_ip": db_ip,
            "attacker_ips": attacker_ips,
            "benign_ips": benign_ips,
            "subnet": f"{subnet_prefix}0/24"
        }
        
        # Map IP to role for Ryu controller
        ip_to_role = {
            web_ip: "web",
            db_ip: "db"
        }
        for ip in attacker_ips:
            ip_to_role[ip] = "attacker"
        for ip in benign_ips:
            ip_to_role[ip] = "client"
            
        # Write config to /tmp
        with open("/tmp/current_run_config.json", "w") as f:
            json.dump(ip_to_role, f)
            
        print(f"[+] Random Topology Configured:")
        print(f"    Hosts: {num_hosts} | Subnet: {run_config['subnet']}")
        print(f"    Web Server: {run_config['web_host']} ({web_ip})")
        print(f"    DB Server: {run_config['db_host']} ({db_ip})")
        print(f"    Attackers: {', '.join(run_config['attacker_hosts'])} ({', '.join(attacker_ips)})")
        print(f"    Benign: {len(run_config['benign_hosts'])} hosts")

        # Make sure no old controller output remains
        if os.path.exists(snap_path):
            os.remove(snap_path)

        # 2. Start Ryu controller
        print("[+] Starting Ryu Controller...")
        ryu_proc = subprocess.Popen(
            [ryu_path, "--verbose", "--ofp-tcp-listen-port", "6653", controller_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            cwd=backend_dir
        )

        if not wait_for_port("127.0.0.1", 6653, timeout=15):
            print("[!] Failed to start Ryu controller")
            ryu_proc.terminate()
            continue

        # 3. Create and Start Mininet network
        print("[+] Initializing randomized Mininet topology...")
        net = create_random_network(run_config, controller_ip="127.0.0.1", controller_port=6653)
        
        print("[+] Starting Mininet network (starts Flask in background)...")
        net.start()
        
        print("[+] Waiting for OpenFlow handshake and Flask server startup...")
        time.sleep(5)

        timeline = []
        phases = [
            (0, "1-to-1", run_phase_0),
            (1, "1-to-N", run_phase_1),
            (2, "N-to-1", run_phase_2),
            (3, "N-to-N", run_phase_3),
            (4, "service_transition", run_phase_4)
        ]
        
        # Shuffle phase sequence to randomize attack start times
        random.shuffle(phases)

        try:
            for label, name, run_func in phases:
                print(f"\n[+] Starting Phase {label} ({name}) - Run {run_idx}")
                
                # Clear Ryu controller flow states before starting a new phase
                try:
                    with open("/tmp/clear_controller_state", "w") as f:
                        f.write("clear")
                    time.sleep(1)
                except Exception as e:
                    print(f"[!] Warning: failed to write clear signal: {e}")

                start_dt = datetime.datetime.now()
                
                # Randomize start delay before starting the phase traffic commands
                start_delay = random.uniform(0.0, 8.0)
                print(f"  [time] Delaying phase start by {start_delay:.2f} seconds...")
                time.sleep(start_delay)

                # Execute traffic generator
                run_func(net, run_config)
                
                # Sleep a randomized duration to collect data
                p_duration = random.randint(15, 35) if phase_duration is None else phase_duration
                print(f"  [time] Running for {p_duration} seconds...")
                time.sleep(p_duration)
                
                end_dt = datetime.datetime.now()
                timeline.append({
                    "label": label,
                    "start": start_dt,
                    "end": end_dt
                })
                
                # Clean up traffic processes before moving to next phase
                stop_traffic_processes()
                time.sleep(2)
                
        finally:
            print("\n[+] Stopping Mininet...")
            net.stop()

            print("[+] Terminating Ryu...")
            ryu_proc.terminate()
            try:
                ryu_proc.communicate(timeout=3)
            except Exception:
                ryu_proc.kill()

            clean_up()

        # 4. Process and Label Snapshots generated in this run
        print(f"[+] Labeling graph snapshots for Run {run_idx}...")
        if not os.path.exists(snap_path):
            print(f"[!] Warning: no snapshots exported in Run {run_idx}.")
            continue

        run_snapshots = []
        with open(snap_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    snapshot = json.loads(line)
                    ts_str = snapshot.get("timestamp")
                    if not ts_str:
                        continue
                    snapshot_dt = datetime.datetime.fromisoformat(ts_str)
                    
                    # Match timeline
                    for entry in timeline:
                        start_pad = entry["start"] - datetime.timedelta(seconds=2)
                        end_pad = entry["end"] + datetime.timedelta(seconds=2)
                        if start_pad <= snapshot_dt <= end_pad:
                            snapshot["label"] = entry["label"]
                            snapshot["iteration"] = run_idx
                            run_snapshots.append(snapshot)
                            break
                except Exception as e:
                    print(f"Error parsing snapshot: {e}")

        print(f"    Labeled {len(run_snapshots)} snapshots from Run {run_idx}.")
        total_labeled_count += len(run_snapshots)

        # Append labeled snapshots to the labeled snapshots file
        with open(labeled_snap_path, "a") as f:
            for snap in run_snapshots:
                f.write(json.dumps(snap) + "\n")

        # Cleanup raw file from this run
        if os.path.exists(snap_path):
            os.remove(snap_path)

    # 5. Finalize dataset: rename labeled snapshots file to main snapshots file
    if os.path.exists(labeled_snap_path):
        os.rename(labeled_snap_path, snap_path)
        print(f"\n[+] Independent runs completed. Final dataset saved to {snap_path}")
        print(f"    Total snapshots collected: {total_labeled_count}")
        
        # Print label distribution
        distribution = {}
        with open(snap_path, "r") as f:
            for line in f:
                snap = json.loads(line)
                lbl = snap["label"]
                distribution[lbl] = distribution.get(lbl, 0) + 1
        print("    Label distribution:")
        for lbl in sorted(distribution.keys()):
            print(f"      Label {lbl}: {distribution[lbl]} snapshots")
    else:
        print("[!] Error: No labeled snapshots were generated across all runs.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Script must be run as root (sudo)")
        sys.exit(1)
        
    parser = argparse.ArgumentParser(description="Scenario Generator & Auto-Labeler for GNN Training")
    parser.add_argument("--phase-duration", type=int, default=None, help="Duration of each traffic phase in seconds (randomized if not specified)")
    parser.add_argument("--iterations", type=int, default=30, help="Number of complete scenario iterations to run")
    args = parser.parse_args()
    
    run_scenarios(phase_duration=args.phase_duration, num_iterations=args.iterations)

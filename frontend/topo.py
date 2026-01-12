import os
import subprocess
import time
import sys

# Configuration
BRIDGE_NAME = "ovs-br0"
NAMESPACES = {
    "ns_server":   {"ip": "10.0.0.10/24", "veth": "veth_serv"},
    "ns_user":     {"ip": "10.0.0.1/24",  "veth": "veth_user"},
    "ns_attacker": {"ip": "10.0.0.66/24", "veth": "veth_hack"},
    "ns_monitor":  {"ip": "0.0.0.0",      "veth": "veth_mon"} 
}

def run(cmd):
    """Run shell command"""
    print(f"[CMD] {cmd}")
    subprocess.run(cmd, shell=True, check=False)

def check_root():
    if os.geteuid() != 0:
        print("[-] This script must be run as root (sudo).")
        sys.exit(1)

def cleanup():
    print("\n[!] Cleaning up existing topology...")
    # Delete namespaces
    for ns in NAMESPACES:
        run(f"ip netns del {ns} 2>/dev/null")
    # Delete OVS bridge
    run(f"ovs-vsctl del-br {BRIDGE_NAME} 2>/dev/null")
    # Clean leftover veths just in case
    for ns_data in NAMESPACES.values():
        run(f"ip link delete {ns_data['veth']} 2>/dev/null")

def setup_topology():
    print("\n[+] Creating OVS Bridge...")
    run(f"ovs-vsctl add-br {BRIDGE_NAME}")
    # Set bridge to secure mode (requires controller or manual flows)
    # For this simple setup, we use standalone (learning switch behavior)
    run(f"ovs-vsctl set-fail-mode {BRIDGE_NAME} standalone")

    print("[+] Creating Namespaces and Connections...")
    for ns, data in NAMESPACES.items():
        veth_host = data['veth']
        veth_ns = f"{veth_host}_ns"
        
        # 1. Create NetNS
        run(f"ip netns add {ns}")
        
        # 2. Create Veth Pair
        run(f"ip link add {veth_host} type veth peer name {veth_ns}")
        
        # 3. Attach Host side to OVS
        run(f"ovs-vsctl add-port {BRIDGE_NAME} {veth_host}")
        run(f"ip link set {veth_host} up")
        
        # 4. Move Peer to NetNS
        run(f"ip link set {veth_ns} netns {ns}")
        
        # 5. Configure interface inside NetNS
        # Rename for simplicity inside NS (e.g., eth0)
        run(f"ip netns exec {ns} ip link set dev {veth_ns} name eth0")
        run(f"ip netns exec {ns} ip link set dev lo up")
        run(f"ip netns exec {ns} ip link set dev eth0 up")
        
        # 6. Assign IP (except monitor)
        if data['ip'] != "0.0.0.0":
            run(f"ip netns exec {ns} ip addr add {data['ip']} dev eth0")

    print("[+] Setting up Port Mirroring (SPAN)...")
    # Mirror ALL traffic on bridge to the monitor interface
    # We need the UUID of the monitor port
    port_uuid = subprocess.check_output(f"ovs-vsctl get port {NAMESPACES['ns_monitor']['veth']} _uuid", shell=True).decode().strip()
    
    cmd = (f"ovs-vsctl -- --id=@m create mirror name=m0 select-all=true "
           f"output-port={port_uuid} "
           f"-- set bridge {BRIDGE_NAME} mirrors=@m")
    run(cmd)

    print("[+] Starting Victim Web Server...")
    # Simple Python HTTP server in background
    run(f"ip netns exec ns_server nohup python3 -m http.server 80 > /dev/null 2>&1 &")

    print("\n✅ TOPOLOGY READY!")
    print("---------------------------------------------------")
    print("1. Monitor (IDS):  sudo ip netns exec ns_monitor python3 listener.py")
    print("2. Benign Traffic: sudo ip netns exec ns_user python3 traffic_normal.py")
    print("3. Attacker:       sudo ip netns exec ns_attacker python3 attack_generator.py")
    print("---------------------------------------------------")
    print("Press Ctrl+C to stop and cleanup.")

if __name__ == "__main__":
    check_root()
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--cleanup", action="store_true", help="Only clean up")
    args = parser.parse_args()

    if args.cleanup:
        cleanup()
    else:
        cleanup()
        try:
            setup_topology()
            print("[*] Topology running. Press Ctrl+C to stop.")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            cleanup()
import os
import subprocess
import time
import sys

# Configuration - MUST MATCH server.py exactly
BRIDGE_NAME = "ovs-br0"
NAMESPACES = {
    "ns_server":    {"ip": "10.0.0.10/24", "veth": "veth_serv"},
    "ns_user":      {"ip": "10.0.0.1/24",  "veth": "veth_user"},
    "ns_attacker":  {"ip": "10.0.0.66/24", "veth": "veth_hack"},
    "ns_attacker2": {"ip": "10.0.0.67/24", "veth": "veth_hack2"},
    "ns_attacker3": {"ip": "10.0.0.68/24", "veth": "veth_hack3"},
    "ns_monitor":   {"ip": "0.0.0.0",      "veth": "veth_mon"} 
}

# Monitor capture interface name (host side) - SAME as server.py
MONITOR_CAPTURE_IFACE = "mon-cap"

def run(cmd):
    """Run shell command"""
    print(f"[CMD] {cmd}")
    subprocess.run(cmd, shell=True, check=False)

def check_root():
    if os.geteuid() != 0:
        print("[-] This script must be run as root (sudo).")
        sys.exit(1)

def cleanup():
    """Clean up existing topology - SAME as server.py cleanup_topology()"""
    print("\n[!] Cleaning up existing topology...")
    # Delete namespaces (skip monitor as it's not a namespace anymore)
    for ns in NAMESPACES:
        if ns != "ns_monitor":
            run(f"ip netns del {ns} 2>/dev/null")
    # Delete OVS bridge
    run(f"ovs-vsctl del-br {BRIDGE_NAME} 2>/dev/null")
    # Clean leftover veths
    for ns_data in NAMESPACES.values():
        run(f"ip link delete {ns_data['veth']} 2>/dev/null")
    # Clean monitor capture interface
    run(f"ip link delete {MONITOR_CAPTURE_IFACE} 2>/dev/null")

def setup_topology():
    """
    Set up the OVS-based network topology.
    This function MUST match server.py's setup_topology() exactly
    to ensure identical network behavior between live and test.
    """
    print("\n[+] Creating OVS Bridge...")
    run(f"ovs-vsctl add-br {BRIDGE_NAME}")
    run(f"ovs-vsctl set-fail-mode {BRIDGE_NAME} standalone")

    print("[+] Creating Namespaces and Connections...")
    for ns, data in NAMESPACES.items():
        veth_host = data['veth']
        veth_ns = f"{veth_host}_ns"
        
        # Skip monitor - we'll handle it separately (like server.py)
        if ns == "ns_monitor":
            continue
        
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
        run(f"ip netns exec {ns} ip link set dev {veth_ns} name eth0")
        run(f"ip netns exec {ns} ip link set dev lo up")
        run(f"ip netns exec {ns} ip link set dev eth0 up")
        
        # 6. Assign IP (except monitor)
        if data['ip'] != "0.0.0.0":
            run(f"ip netns exec {ns} ip addr add {data['ip']} dev eth0")

    # Create monitor interface for port mirroring - SAME as server.py
    print("[+] Creating Monitor Interface...")
    mon_veth = NAMESPACES['ns_monitor']['veth']  # veth_mon
    # Create veth pair: veth_mon <-> mon-cap
    run(f"ip link add {mon_veth} type veth peer name {MONITOR_CAPTURE_IFACE}")
    # Add veth_mon to OVS bridge - this will receive mirrored traffic
    run(f"ovs-vsctl add-port {BRIDGE_NAME} {mon_veth}")
    run(f"ip link set {mon_veth} up")
    run(f"ip link set {mon_veth} promisc on")
    
    # Bring up the capture interface on host
    run(f"ip link set {MONITOR_CAPTURE_IFACE} up")
    run(f"ip link set {MONITOR_CAPTURE_IFACE} promisc on")

    print("[+] Setting up Port Mirroring (SPAN)...")
    port_uuid = subprocess.check_output(
        f"ovs-vsctl get port {NAMESPACES['ns_monitor']['veth']} _uuid", 
        shell=True
    ).decode().strip()
    
    cmd = (f"ovs-vsctl -- --id=@m create mirror name=m0 select-all=true "
           f"output-port={port_uuid} "
           f"-- set bridge {BRIDGE_NAME} mirrors=@m")
    run(cmd)

    print("[+] Starting Victim Web Server...")
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
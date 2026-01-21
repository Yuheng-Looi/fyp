
import subprocess
import time
import os
import sys

# Add current directory to path so we can import server/topo modules if needed
sys.path.append(os.getcwd())

def run_cmd(cmd, sudo=False):
    if sudo:
        cmd = "sudo " + cmd
    print(f"Running: {cmd}")
    subprocess.run(cmd, shell=True, check=False)

def check_interface(iface):
    print(f"Checking {iface}...")
    if os.path.exists(f"/sys/class/net/{iface}"):
        print(f"  {iface} exists in /sys/class/net")
        # Check index
        with open(f"/sys/class/net/{iface}/ifindex", "r") as f:
            print(f"  Index: {f.read().strip()}")
    else:
        print(f"  {iface} DOES NOT EXIST")

def recreate_topo():
    print("\n--- TEARING DOWN ---")
    run_cmd("ip link delete mon-cap 2>/dev/null", sudo=True)
    run_cmd("ip link delete veth_mon 2>/dev/null", sudo=True)
    run_cmd("ovs-vsctl del-br ovs-br0 2>/dev/null", sudo=True)
    
    print("\n--- SETTING UP ---")
    bridge = "ovs-br0"
    mon_capture = "mon-cap"
    mon_veth = "veth_mon"
    
    run_cmd(f"ovs-vsctl add-br {bridge}", sudo=True)
    
    # Create veth pair
    print(f"Creating pair {mon_veth} <-> {mon_capture}")
    run_cmd(f"ip link add {mon_veth} type veth peer name {mon_capture}", sudo=True)
    
    # Add to OVS
    run_cmd(f"ovs-vsctl add-port {bridge} {mon_veth}", sudo=True)
    
    # Bring UP
    run_cmd(f"ip link set {mon_veth} up", sudo=True)
    run_cmd(f"ip link set {mon_veth} promisc on", sudo=True)
    run_cmd(f"ip link set {mon_capture} up", sudo=True)
    run_cmd(f"ip link set {mon_capture} promisc on", sudo=True)

    check_interface(mon_capture)
    check_interface(mon_veth)

def try_capture(iface):
    print(f"\n--- CAPTURING on {iface} ---")
    from scapy.all import sniff, IP
    
    # Force refresh interface list in Scapy
    from scapy.config import conf
    print("Reloading Scapy interface cache...")
    conf.ifaces.reload()
    
    # Verify index if possible
    try:
        scapy_iface = conf.ifaces.dev_from_name(iface)
        print(f"Scapy sees {iface} at index: {scapy_iface.index}")
    except Exception as e:
        print(f"Could not get index from Scapy: {e}")

    try:
        print(f"Calling sniff on {iface}...")
        sniff(iface=iface, count=1, timeout=2, store=False)
        print("Sniff returned successfully")
    except Exception as e:
        print(f"Sniff FAILED: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    recreate_topo()
    try_capture("mon-cap")
    
    print("\n--- RECREATING TOPO AGAIN (simulate restart) ---")
    recreate_topo()
    try_capture("mon-cap")

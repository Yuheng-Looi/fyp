
import subprocess
import time
import os
import sys

# IP Configuration
TARGET_IP = "10.0.0.10"
NS_LIST = ["ns_attacker", "ns_attacker2", "ns_attacker3"]
ATTACK_TYPES = ["syn", "udp", "scan", "web", "botnet"]

def run_cmd(cmd):
    """Run shell command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return "TIMEOUT", "TIMEOUT"

def verify_traffic(ns):
    """Check if traffic is being generated on the interface"""
    veth_map = {
        "ns_attacker": "veth_hack",
        "ns_attacker2": "veth_hack2",
        "ns_attacker3": "veth_hack3"
    }
    iface = veth_map.get(ns)
    if not iface: return 0
    
    # Simple packet count check using ip -s link
    cmd = f"ip -s link show {iface} | grep RX: -A 1 | tail -n 1 | awk '{{print $2}}'"
    out, _ = run_cmd(cmd)
    try:
        return int(out) if out else 0
    except:
        return 0

def test_attack(ns, attack_type):
    print(f"\n[Test] Testing {attack_type.upper()} from {ns}...")
    
    # 1. Define command (Same as server.py optimization)
    if attack_type == 'syn':
        cmd = f"sudo ip netns exec {ns} hping3 -S -p 80 -i u1000 -c 50 {TARGET_IP}"
    elif attack_type == 'udp':
        cmd = f"sudo ip netns exec {ns} hping3 --udp -p 80 -i u1000 -c 50 {TARGET_IP}"
    elif attack_type == 'scan':
        cmd = f"sudo ip netns exec {ns} nmap -sS -T4 -p 80 --open {TARGET_IP}"
    elif attack_type == 'web':
        cmd = f"sudo ip netns exec {ns} wget -q -O /dev/null http://{TARGET_IP}/"
    elif attack_type == 'botnet':
        cmd = f"sudo ip netns exec {ns} nc -z -v -w 1 {TARGET_IP} 80"
    
    # 2. Measure baseline traffic
    pkts_before = verify_traffic(ns)
    
    # 3. specific timeout handling for nmap which can be slow
    try:
        print(f"  Running: {cmd}")
        subprocess.run(cmd, shell=True, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        print("  (Command timed out - which is fine for flood tests)")
    except Exception as e:
        print(f"  Error: {e}")
        
    # 4. Measure traffic after
    pkts_after = verify_traffic(ns)
    delta = pkts_after - pkts_before
    
    print(f"  Packets generated: {delta}")
    if delta > 0:
        print(f"  ✅ {attack_type} working")
    else:
        print(f"  ❌ {attack_type} NOT generating traffic")

def main():
    print("=== ATTACK FUNCTIONALITY TEST ===")
    
    # Ensure topo is up partially (we need OVS)
    # This script assumes server.py or topo is already running, or at least interfaces exist.
    # If not, we can't test.
    
    # Check if namespaces exist
    out, _ = run_cmd("ip netns list")
    if "ns_attacker" not in out:
        print("❌ Namespaces not found. Is Topology running?")
        sys.exit(1)
        
    for ns in NS_LIST:
        print(f"\n--- Testing Namespace: {ns} ---")
        for attack in ATTACK_TYPES:
            test_attack(ns, attack)
            time.sleep(1)

if __name__ == "__main__":
    main()

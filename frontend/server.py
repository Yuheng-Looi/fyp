#!/usr/bin/env python3
import os
import uuid
import threading
import time
import signal
from datetime import datetime
from typing import List, Dict, Optional
import subprocess

from flask import Flask, request, jsonify, send_from_directory
import requests

import csv
import json
import numpy as np
import math
import traceback
import io

from cic_extractor import CICExtractor, FEATURE_KEYS
import uuid  # Ensure imported here if not already present

# Global locks and state must be defined early if used in multiple places
# (Added for clarity, actual definitions typically follow)
# =============================================================================

# Configuration for network topology
BRIDGE_NAME = "ovs-br0"
NAMESPACES = {
    "ns_server":    {"ip": "10.0.0.10/24", "veth": "veth_serv"},
    "ns_user":      {"ip": "10.0.0.1/24",  "veth": "veth_user"},
    "ns_attacker":  {"ip": "10.0.0.66/24", "veth": "veth_hack"},
    "ns_attacker2": {"ip": "10.0.0.67/24", "veth": "veth_hack2"},
    "ns_attacker3": {"ip": "10.0.0.68/24", "veth": "veth_hack3"},
    "ns_monitor":   {"ip": "0.0.0.0",      "veth": "veth_mon"} 
}
TARGET_IP = "10.0.0.10"  # ns_server

# Action thresholds (should match backend)
LOG_THRESHOLD = 0.5
RATE_LIMIT_THRESHOLD = 0.7
BLOCK_THRESHOLD = 0.85

# Track injected rules per IP for deduplication
injected_rules = {}  # {src_ip: {'action': action, 'priority': priority}}
injected_rules_lock = threading.Lock()

# Global state for topology and processes
topo_state = {
    'running': False,
    'http_server_proc': None,
}
traffic_state = {
    'running': False,
    'process': None,
    'thread': None,
}
attack_state = {
    'running': False,
    'attack_type': None,
    'process': None,
    'thread': None,
}
topo_lock = threading.Lock()


def run_cmd(cmd, check=False, sudo=False):
    """Run shell command and return result"""
    if sudo:
        cmd = f"sudo {cmd}"
    print(f"[CMD] {cmd}")
    result = subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)
    return result


def cleanup_topology():
    """Clean up existing topology"""
    print("\n[!] Cleaning up existing topology...")
    # Delete namespaces (skip monitor as it's not a namespace anymore)
    for ns in NAMESPACES:
        if ns != "ns_monitor":
            run_cmd(f"ip netns del {ns} 2>/dev/null", sudo=True)
    # Delete OVS bridge
    run_cmd(f"ovs-vsctl del-br {BRIDGE_NAME} 2>/dev/null", sudo=True)
    # Clean leftover veths
    for ns_data in NAMESPACES.values():
        run_cmd(f"ip link delete {ns_data['veth']} 2>/dev/null", sudo=True)
    # Clean monitor capture interface
    run_cmd(f"ip link delete {MONITOR_CAPTURE_IFACE} 2>/dev/null", sudo=True)
    # Clear injected rules tracking
    with injected_rules_lock:
        injected_rules.clear()

# =============================================================================
# OVS OPENFLOW RULE INJECTION FOR ACTIONS
# =============================================================================

def inject_ovs_rule(src_ip=None, action='BLOCK', dst_ip=None, dst_port=None, protocol=None, priority=None):
    """
    Inject OpenFlow rules into OVS bridge based on action type.
    Supports granular 5-tuple injection (Src Port removed as it's random).
    """
    src_ip_clean = src_ip.split('/')[0] if src_ip and '/' in src_ip else src_ip
    
    # Construct match parts
    match_parts = []
    
    # Protocol Logic
    # If using L4 ports, we NEED to specify protocol
    proto_map = {6: 'tcp', 17: 'udp', 1: 'icmp'}
    proto_name = 'ip' # default to IP generic
    
    if protocol:
        try:
            p_int = int(protocol)
            if p_int in proto_map:
                proto_name = proto_map[p_int]
            else:
                 # If user typed 'tcp' or 'udp'
                 if str(protocol).lower() in ['tcp','udp','icmp']:
                     proto_name = str(protocol).lower()
        except:
             pass
    
    # If ports are present, enforce L4 proto
    if (dst_port) and proto_name == 'ip':
         # Default to TCP if not specified but ports are present? 
         # Or just fail? Let's default to tcp to be safe, or user must specify.
         # Actually OVS requires protocol to use tp_src/tp_dst
         # If mixed, we might need multiple rules? For now, assume TCP if unspecified.
         proto_name = 'tcp'
         
    match_parts.append(proto_name)
    
    if src_ip_clean:
        match_parts.append(f"nw_src={src_ip_clean}")
    
    if dst_ip:
        match_parts.append(f"nw_dst={dst_ip}")
        
    if dst_port and int(dst_port) > 0:
        match_parts.append(f"tp_dst={dst_port}")
        
    match_str = ",".join(match_parts)
    
    # Determine Priority
    # User specified > Auto high (ALLOW) > Auto low (BLOCK)
    if priority:
        prio = int(priority)
    else:
        if action in ['ALLOW', 'SAFE', 'PERMIT']:
            prio = 2000
        elif action == 'BLOCK':
            prio = 1000
        else:
            prio = 500
            
    # Check for duplicates using match string as key
    with injected_rules_lock:
        if match_str in injected_rules:
             # Just update action/time
              injected_rules[match_str]['action'] = action
              injected_rules[match_str]['priority'] = prio
              injected_rules[match_str]['time'] = time.time()
              return {'status': 'updated', 'match': match_str}
    
    result = {'status': 'ok', 'action': action, 'match': match_str, 'rules_added': []}
    
    try:
        final_rule = f"priority={prio},{match_str}"
        
        if action == 'BLOCK':
            cmd = f"ovs-ofctl add-flow {BRIDGE_NAME} \"{final_rule},actions=drop\""
            run_cmd(cmd, sudo=True)
            result['rules_added'].append(cmd)
            print(f"[🛡️ OVS] BLOCKED flow: {match_str} (Prio={prio})")
            
        elif action == 'RATE_LIMIT':
            # Mark with normal actions (dummy implementation)
            cmd = f"ovs-ofctl add-flow {BRIDGE_NAME} \"{final_rule},actions=normal\""
            run_cmd(cmd, sudo=True)
            result['rules_added'].append(cmd)
            result['note'] = 'Rate limiting tag'
            print(f"[⚠️ OVS] RATE_LIMIT flow: {match_str}")

        elif action in ['ALLOW', 'SAFE', 'PERMIT']:
             cmd = f"ovs-ofctl add-flow {BRIDGE_NAME} \"{final_rule},actions=normal\""
             run_cmd(cmd, sudo=True)
             result['rules_added'].append(cmd)
             print(f"[✅ OVS] ALLOW flow: {match_str} (Prio={prio})")
            
        elif action in ['LOG', 'ALERT_ONLY']:
            result['rules_added'] = []
            
        # Track by match string
        with injected_rules_lock:
            injected_rules[match_str] = {
                'action': action, 
                'time': time.time(),
                'priority': prio,
                'match_parts': match_parts # store for verification?
            }
            
    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)
        print(f"[❌ OVS] Failed to inject rule: {e}")
    
    return result


def remove_ovs_rule(match_str):
    """Remove OVS rule by match string"""
    try:
        # Delete using match string without --strict since we don't include priority
        # This will delete all flows matching the given criteria
        run_cmd(f"ovs-ofctl del-flows {BRIDGE_NAME} \"{match_str}\"", sudo=True)
        
        with injected_rules_lock:
            injected_rules.pop(match_str, None)
        
        print(f"[🔓 OVS] Removed rule: {match_str}")
        return {'status': 'ok', 'match': match_str}
    except Exception as e:
        print(f"[❌ OVS] Failed to remove rule: {e}")
        return {'status': 'error', 'error': str(e)}



def get_ovs_flows():
    """Get current OVS flow table dump"""
    try:
        result = subprocess.run(
            f"sudo ovs-ofctl dump-flows {BRIDGE_NAME}",
            shell=True, capture_output=True, text=True
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            flows = []
            for line in lines:
                if line.startswith(' cookie=') or 'cookie=' in line:
                    flows.append(line.strip())
            return {'status': 'ok', 'flows': flows, 'raw': result.stdout}
        else:
            return {'status': 'error', 'error': result.stderr}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def get_ovs_ports():
    """Get OVS bridge port information"""
    try:
        result = subprocess.run(
            f"sudo ovs-ofctl show {BRIDGE_NAME}",
            shell=True, capture_output=True, text=True
        )
        if result.returncode == 0:
            return {'status': 'ok', 'info': result.stdout}
        else:
            return {'status': 'error', 'error': result.stderr}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


def clear_all_ovs_rules():
    """Clear all manually added OVS rules (keep default)"""
    try:
        # Delete all flows with priority > 0 (keep table-miss rule)
        run_cmd(f"ovs-ofctl del-flows {BRIDGE_NAME}", sudo=True)
        # Re-add default normal action
        run_cmd(f"ovs-ofctl add-flow {BRIDGE_NAME} \"priority=0,actions=normal\"", sudo=True)
        
        with injected_rules_lock:
            injected_rules.clear()
        
        print("[🧹 OVS] Cleared all custom rules")
        return {'status': 'ok'}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}

# Monitor capture interface name (host side)
MONITOR_CAPTURE_IFACE = "mon-cap"
# IPs that are always considered BENIGN (e.g. Server IP)
BENIGN_IPS = ['10.0.0.10']

def setup_topology():
    """Set up the OVS-based network topology"""
    print("\n[+] Creating OVS Bridge...")
    run_cmd(f"ovs-vsctl add-br {BRIDGE_NAME}", sudo=True)
    run_cmd(f"ovs-vsctl set-fail-mode {BRIDGE_NAME} standalone", sudo=True)

    print("[+] Creating Namespaces and Connections...")
    for ns, data in NAMESPACES.items():
        veth_host = data['veth']
        veth_ns = f"{veth_host}_ns"
        
        # Skip monitor - we'll handle it separately
        if ns == "ns_monitor":
            continue
        
        # 1. Create NetNS
        run_cmd(f"ip netns add {ns}", sudo=True)
        
        # 2. Create Veth Pair
        run_cmd(f"ip link add {veth_host} type veth peer name {veth_ns}", sudo=True)
        
        # 3. Attach Host side to OVS
        run_cmd(f"ovs-vsctl add-port {BRIDGE_NAME} {veth_host}", sudo=True)
        run_cmd(f"ip link set {veth_host} up", sudo=True)
        
        # 4. Move Peer to NetNS
        run_cmd(f"ip link set {veth_ns} netns {ns}", sudo=True)
        
        # 5. Configure interface inside NetNS
        run_cmd(f"ip netns exec {ns} ip link set dev {veth_ns} name eth0", sudo=True)
        run_cmd(f"ip netns exec {ns} ip link set dev lo up", sudo=True)
        run_cmd(f"ip netns exec {ns} ip link set dev eth0 up", sudo=True)
        
        # 6. Assign IP (except monitor)
        if data['ip'] != "0.0.0.0":
            run_cmd(f"ip netns exec {ns} ip addr add {data['ip']} dev eth0", sudo=True)

    # Create monitor interface for port mirroring
    print("[+] Creating Monitor Interface...")
    mon_veth = NAMESPACES['ns_monitor']['veth']  # veth_mon
    # Create veth pair: veth_mon <-> mon-cap
    run_cmd(f"ip link add {mon_veth} type veth peer name {MONITOR_CAPTURE_IFACE}", sudo=True)
    # Add veth_mon to OVS bridge - this will receive mirrored traffic
    run_cmd(f"ovs-vsctl add-port {BRIDGE_NAME} {mon_veth}", sudo=True)
    run_cmd(f"ip link set {mon_veth} up", sudo=True)
    run_cmd(f"ip link set {mon_veth} promisc on", sudo=True)
    
    # Bring up the capture interface on host
    run_cmd(f"ip link set {MONITOR_CAPTURE_IFACE} up", sudo=True)
    run_cmd(f"ip link set {MONITOR_CAPTURE_IFACE} promisc on", sudo=True)

    print("[+] Setting up Port Mirroring (SPAN)...")
    port_result = subprocess.check_output(
        f"sudo ovs-vsctl get port {NAMESPACES['ns_monitor']['veth']} _uuid",
        shell=True
    ).decode().strip()
    
    mirror_cmd = (f"ovs-vsctl -- --id=@m create mirror name=m0 select-all=true "
                  f"output-port={port_result} "
                  f"-- set bridge {BRIDGE_NAME} mirrors=@m")
    run_cmd(mirror_cmd, sudo=True)

    print("[+] Starting Victim Web Server...")
    proc = subprocess.Popen(
        f"sudo ip netns exec ns_server python3 -m http.server 80",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid
    )
    return proc


def generate_normal_traffic_loop(duration=0):
    """Generate normal traffic in a loop"""
    import random
    start_time = time.time()
    
    while traffic_state['running']:
        if duration > 0 and (time.time() - start_time) > duration:
            break
        
        try:
            action = random.choice(['ping', 'web', 'web', 'sleep'])
            
            if action == 'ping':
                subprocess.run(
                    f"sudo ip netns exec ns_user ping -c 1 -W 1 {TARGET_IP}",
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )
            elif action == 'web':
                subprocess.run(
                    f"sudo ip netns exec ns_user curl -s -o /dev/null --connect-timeout 2 http://{TARGET_IP}/",
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )
            
            # Much faster traffic: sleep 0.01s to 0.05s
            time.sleep(random.uniform(0.01, 0.05))
            
        except Exception as e:
            print(f"[Traffic] Error: {e}")
            time.sleep(1)
    
    traffic_state['running'] = False
    print("[Traffic] Normal traffic generation stopped.")

# =============================================================================
# CSV PLAYBACK LOOP (HYBRID MODE)
# =============================================================================

def run_attack_playback_loop(csv_path, attacker_ip, duration=0, attack_type='unknown'):
    """
    Replays attack traffic from a CSV file, injecting it into the live monitoring state.
    Mimics the behavior of live_loop but uses pre-calculated features.
    """
    import itertools
    import random

    print(f"[Playback] Loading attack pattern from {csv_path}...")
    
    # 1. Load all rows into memory (files are small ~3-4MB)
    rows = []
    try:
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = TrimmedDictReader(f)
            rows = list(reader)
    except Exception as e:
        print(f"[Playback] Error reading CSV: {e}")
        attack_state['running'] = False
        return

    if not rows:
        print("[Playback] CSV is empty.")
        attack_state['running'] = False
        return

    print(f"[Playback] Starting playback loop as {attacker_ip} (Duration: {duration}s)")
    
    start_time = time.time()
    row_cycle = itertools.cycle(rows) # Loop the CSV infinitely

    # 2. Playback Loop
    while attack_state['running']:
        if duration > 0 and (time.time() - start_time) > duration:
            break

        try:
            row = next(row_cycle)
            
            # --- A. Construct Flow Key (5-tuple) ---
            # Overwrite Source IP with the selected attacker
            src = attacker_ip
            # Keep destination from CSV (usually 10.0.0.10) or default
            dst = row.get('dst_ip') or row.get('Destination IP') or TARGET_IP
            
            # Try to get ports/proto from CSV, default to sensible values if missing
            try:
                sport = int(row.get('src_port') or row.get('Source Port') or random.randint(1024, 65535))
                dport = int(row.get('dst_port') or row.get('Destination Port') or 80)
                proto = int(row.get('protocol') or row.get('Protocol') or 6)
            except:
                sport, dport, proto = 0, 80, 6

            # --- B. Extract Features ---
            # The CSV contains the features. specific feature mapping logic
            features_dict = {}
            for k in FEATURE_KEYS:
                # Try exact match or flexible lookup
                val = row.get(k)
                if val is None:
                    # Fallback for some CSV variations
                    val = 0.0
                features_dict[k] = float(val)

            # --- C. Predict & Process (Same logic as live_loop) ---
            # Initialize vars
            final_verdict = None
            final_action = None
            rule_source = None
            rule_injected = None
            
            # 1. Check Existing OVS Rules (Simulated)
            existing_rule = is_flow_covered(src, dst, dport, proto)
            if existing_rule:
                final_action = existing_rule.get('action', 'ALLOW').upper()
                final_verdict = 'SKIP'
                rule_source = f"OVS Dumpflow ({existing_rule.get('match', '')})"
                xgb_model_res = {'confidence': 1.0, 'note': 'Skipped due to active rule'}
                gnn_model_res = {}
                iso_forest = {}
            else:
                # 2. ML Prediction
                sid = live_state.get('scaler_id', 'default')
                mod_xgb = live_state.get('xgb_model', 'default')
                mod_sn = live_state.get('safetynet_model', 'default')
                mod_gnn = live_state.get('gnn_model', 'default')

                pred = predict_one(features_dict, src, dst, sid, mod_xgb, mod_sn, mod_gnn)
                
                final_verdict = pred.get('verdict', 'UNKNOWN')
                raw_action = pred.get('action', '').upper()
                iso_forest = pred.get('isolation_forest', {})
                xgb_model_res = pred.get('xgb', {})
                gnn_model_res = pred.get('gnn', {})

                # Action Logic
                if not raw_action or raw_action.lower() in ['allow', 'block']:
                    if raw_action == 'BLOCK':
                        final_action = 'BLOCK'
                    elif final_verdict not in ['BENIGN', 'UNKNOWN', 'UNAVAILABLE']:
                        xgb_conf = xgb_model_res.get('confidence', 0)
                        if xgb_conf >= BLOCK_THRESHOLD:
                            final_action = 'BLOCK'
                        elif xgb_conf >= RATE_LIMIT_THRESHOLD:
                            final_action = 'RATE_LIMIT'
                        elif xgb_conf >= LOG_THRESHOLD:
                            final_action = 'LOG'
                        else:
                            final_action = 'ALLOW'
                    else:
                        final_action = 'ALLOW'
                else:
                    final_action = raw_action
                
                # 3. Inject Rule (Real injection, even in playback mode, to stop "traffic")
                if topo_state.get('running') and final_action in ['BLOCK', 'RATE_LIMIT']:
                     # We only block. We don't allow purely because there is no real traffic to allow.
                     rule_injected = inject_ovs_rule(src, final_action, dst_ip=dst, dst_port=dport, protocol=proto)

            # --- D. Append to Live State ---
            record = {
                'timestamp': time.time(), # Set to NOW
                'src_ip': src,
                'dst_ip': dst,
                'src_port': sport,
                'dst_port': dport,
                'protocol': proto,
                'features': features_dict,
                'prediction': final_verdict,
                'action': final_action,
                'confidence': xgb_model_res.get('confidence', 0.0) if xgb_model_res else 1.0,
                'gnn_verdict': gnn_model_res.get('flag'),
                'gnn_confidence': gnn_model_res.get('confidence'),
                'details': {
                    'isolation_forest': iso_forest,
                    'xgb': xgb_model_res,
                    'gnn': gnn_model_res,
                    'rule_source': rule_source
                },
                'latency_ms': 0.1, # Simulated latency
                'rule_injected': rule_injected
            }

            with state_lock:
                live_state['flows'].append(record)

            # --- E. Rate Control ---
            # Sleep to simulate traffic rate. 
            # Randomize slightly to look natural.
            time.sleep(random.uniform(0.02, 0.1))

        except Exception as e:
            print(f"[Playback] Error in loop: {e}")
            time.sleep(1)

    attack_state['running'] = False
    print(f"[Playback] Stopped playback of {attack_type}")

def run_attack_loop(attack_type, duration=0, attacker_ns='ns_attacker'):
    """Run attack in a loop until stopped from specified attacker namespace"""
    start_time = time.time()
    
    # Build commands with dynamic namespace
    # Optimized commands to ensure traffic generation
    attack_commands = {
        # SYN Flood: Increased rate, faster interval
        'syn': f"sudo ip netns exec {attacker_ns} hping3 -S -p 80 -i u100 {TARGET_IP}",
        # UDP Flood: Use hping3 UDP mode as it's more reliable for DoS than iperf3
        'udp': f"sudo ip netns exec {attacker_ns} hping3 --udp -p 80 -i u1000 --rand-source {TARGET_IP}",
        # Port Scan: Faster scan, more common ports
        'scan': f"sudo ip netns exec {attacker_ns} nmap -sS -T4 -p 21,22,23,25,53,80,110,443,3306,8080 --open {TARGET_IP}",
        # Web Attack: Continuous curl requests (now same as normal traffic)
        'web': f"sudo ip netns exec {attacker_ns} curl -s -o /dev/null --connect-timeout 2 http://{TARGET_IP}/",
        # Botnet: Repeated connection attempts to varied ports
        'botnet': f"sudo ip netns exec {attacker_ns} nc -z -v -w 1 {TARGET_IP} 80"
    }
    
    attacker_ip = NAMESPACES.get(attacker_ns, {}).get('ip', 'unknown').split('/')[0]
    print(f"[Attack] Starting {attack_type} from {attacker_ns} ({attacker_ip})")
    
    import random
    while attack_state['running']:
        if duration > 0 and (time.time() - start_time) > duration:
            break
        try:
            if attack_type == 'botnet':
                subprocess.run(
                    attack_commands['botnet'],
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5
                )
                time.sleep(2)
            elif attack_type == 'web':
                # Loop curl for web attack (align with live_test.py/attack_generator.py)
                subprocess.run(
                    attack_commands['web'],
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3
                )
                time.sleep(random.uniform(0.01, 0.05))
            else:
                cmd = attack_commands.get(attack_type)
                if cmd:
                    proc = subprocess.Popen(
                        cmd,
                        shell=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        preexec_fn=os.setsid
                    )
                    attack_state['process'] = proc
                    while proc.poll() is None and attack_state['running']:
                        time.sleep(0.5)
                    
                    if not attack_state['running'] and proc.poll() is None:
                        # Kill the process group
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                        except:
                            pass
                    
                    attack_state['process'] = None
                    
        except Exception as e:
            print(f"[Attack] Error: {e}")
            time.sleep(1)
    
    attack_state['running'] = False
    attack_state['attack_type'] = None
    attack_state['attacker_ns'] = None
    print(f"[Attack] Attack '{attack_type}' from {attacker_ns} stopped.")

app = Flask(__name__)
# Increase max upload size to 2GB to avoid 413 Errors / Connection Resets on large datasets
app.config['MAX_CONTENT_LENGTH'] = 2048 * 1024 * 1024

if 'PREDICT_URL' in os.environ:
    PREDICT_URL = os.environ['PREDICT_URL']
else:
    # Default to infer_server.py location
    # If PREDICT_URL points to /predict, we strip it for the base methods
    PREDICT_URL = 'http://10.100.10.15:8000/predict'

def get_base_url():
    if '/predict' in PREDICT_URL:
        return PREDICT_URL.rsplit('/predict', 1)[0]
    return PREDICT_URL.rstrip('/')
SCALER_ID = os.environ.get('SCALER_ID', 'default')

# Persistent upload storage
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
PCAP_DIR = os.path.join(UPLOAD_DIR, 'pcaps')
CSV_DIR = os.path.join(UPLOAD_DIR, 'csv')
METADATA_DIR = os.path.join(UPLOAD_DIR, 'metadata')
GLOBAL_MAPPING_PATH = os.path.join(METADATA_DIR, 'global_mapping.json')

for d in (UPLOAD_DIR, PCAP_DIR, CSV_DIR, METADATA_DIR):
    os.makedirs(d, exist_ok=True)

def load_global_mapping():
    if os.path.exists(GLOBAL_MAPPING_PATH):
        try:
            with open(GLOBAL_MAPPING_PATH, 'r') as f:
                return json.load(f)
        except:
            pass
    return {}

def save_global_mapping(mapping):
    with open(GLOBAL_MAPPING_PATH, 'w') as f:
        json.dump(mapping, f, indent=4)

def get_suggested_mapping(headers):
    """
    Given a list of CSV headers, suggest a mapping based on the global dictionary.
    Returns a dict with 'src_ip', ..., and 'features': {...}
    """
    global_map = load_global_mapping()
    if not global_map:
        return {}
    
    mapping = {'features': {}}
    headers_lower = [h.lower().strip() for h in headers]
    header_map = {h.lower().strip(): h for h in headers} # lower -> original

    def find_match(candidates):
        if not candidates: return None
        for c in candidates:
            c_clean = c.lower().strip()
            if c_clean in headers_lower:
                return header_map[c_clean]
        return None

    # Basic fields
    for field in ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'label']:
        candidates = global_map.get(field, [])
        match = find_match(candidates)
        if match:
            mapping[field] = match

    # Features
    g_features = global_map.get('features', {})
    for feat_key, candidates in g_features.items():
        match = find_match(candidates)
        if match:
            mapping['features'][feat_key] = match
            
    return mapping

def update_global_from_mapping(new_mapping):
    """
    Update the global mapping dictionary with new aliases from a user-provided mapping.
    """
    global_map = load_global_mapping()
    if not global_map:
        # Should initiate with defaults if missing, but assuming it exists or we handle empty
        global_map = {
             "timestamp": [], "src_ip": [], "dst_ip": [], 
             "src_port": [], "dst_port": [], "protocol": [], "label": [],
             "features": {}
        }

    def add_alias(field, alias):
        clean_alias = str(alias).strip()
        if not clean_alias:
            return
            
        if clean_alias not in global_map.setdefault(field, []):
            # Check if alias exists case-insensitively to avoid dupes like "Src" vs "src"
            current = [x.lower() for x in global_map[field]]
            if clean_alias.lower() not in current:
                global_map[field].append(clean_alias)

    # Basic fields
    for field in ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'label']:
        val = new_mapping.get(field)
        if val:
            add_alias(field, val)
            
    # Features
    mapped_features = new_mapping.get('features', {})
    if 'features' not in global_map:
        global_map['features'] = {}
        
    for key, val in mapped_features.items():
        if val:
            if key not in global_map['features']:
                global_map['features'][key] = []
            
            clean_val = str(val).strip()
            if not clean_val:
                continue
                
            # Add alias
            current = [x.lower() for x in global_map['features'][key]]
            if clean_val.lower() not in current:
                global_map['features'][key].append(clean_val)

    save_global_mapping(global_map)


def get_metadata_path(filename):
    return os.path.join(METADATA_DIR, f"{filename}.json")

# Deprecated but kept for compatibility during migration if needed
def load_metadata(filename):
    path = get_metadata_path(filename)
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except:
            return None
    return None


def save_metadata_file(filename, data):
    path = get_metadata_path(filename)
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)


class TrimmedDictReader:
    """A CSV DictReader wrapper that trims whitespace from field names."""
    def __init__(self, file_handle):
        self.reader = csv.DictReader(file_handle)
        # Trim the fieldnames
        if self.reader.fieldnames:
            self.reader.fieldnames = [f.strip() if f else f for f in self.reader.fieldnames]
    
    @property
    def fieldnames(self):
        return self.reader.fieldnames
    
    def __iter__(self):
        return self
    
    def __next__(self):
        row = next(self.reader)
        # Return row with trimmed keys
        return {k.strip() if k else k: v for k, v in row.items()}


def trim_metadata_values(metadata):
    """Trim all string values in metadata that represent column names."""
    if not metadata:
        return metadata
    
    trimmed = {}
    for key, value in metadata.items():
        if key == 'features' and isinstance(value, dict):
            trimmed['features'] = {k: v.strip() if isinstance(v, str) else v for k, v in value.items()}
        elif isinstance(value, str):
            trimmed[key] = value.strip()
        else:
            trimmed[key] = value
    return trimmed


def list_network_interfaces() -> List[Dict]:
    interfaces: List[Dict] = []
    try:
        output = subprocess.check_output(['ip', '-json', 'addr', 'show'], text=True)
        data = json.loads(output)
        for entry in data:
            name = entry.get('ifname')
            if not name:
                continue
            ipv4 = [addr.get('local') for addr in entry.get('addr_info', []) if addr.get('family') == 'inet' and addr.get('local')]
            interfaces.append({
                'name': name,
                'state': (entry.get('operstate') or 'UNKNOWN').upper(),
                'mac': entry.get('address'),
                'ipv4': ipv4
            })
    except Exception:
        try:
            for name in os.listdir('/sys/class/net'):
                state_path = os.path.join('/sys/class/net', name, 'operstate')
                state = 'UNKNOWN'
                try:
                    with open(state_path, 'r') as fh:
                        state = fh.read().strip().upper() or 'UNKNOWN'
                except Exception:
                    pass
                interfaces.append({'name': name, 'state': state, 'mac': None, 'ipv4': []})
        except Exception:
            pass

    seen = set()
    unique: List[Dict] = []
    for iface in interfaces:
        name = iface.get('name')
        if not name or name in seen:
            continue
        seen.add(name)
        unique.append(iface)

    def sort_key(item):
        priority = 0 if item['name'] in ('s1-snoop', 's1-eth3') else 1
        return (priority, item['name'])

    unique.sort(key=sort_key)
    return unique


TIMESTAMP_FORMATS = [
    '%m/%d/%Y %H:%M:%S',
    '%m/%d/%Y %H:%M',
    '%Y-%m-%d %H:%M:%S',
    '%Y-%m-%d %H:%M',
    '%d/%m/%Y %H:%M:%S',
    '%d/%m/%Y %H:%M',
    '%m/%d/%Y %I:%M:%S %p',
    '%m/%d/%Y %I:%M %p',
    '%Y-%m-%dT%H:%M:%S',
    '%Y-%m-%dT%H:%M:%S.%f'
]


def parse_timestamp_value(value):
    if value is None or value == '':
        return time.time()
    if isinstance(value, (int, float)):
        return float(value)

    text = str(value).strip()
    if not text:
        return time.time()

    try:
        return float(text)
    except Exception:
        pass

    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(text, fmt).timestamp()
        except Exception:
            continue

    try:
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return time.time()


class OfflineJob:
    def __init__(self, job_id: str, source_kind: str, src_path: str, label_column: Optional[str] = None, benign_label: str = 'BENIGN', metadata: Optional[Dict] = None, scaler_id: str = 'default', xgb_model: str = None, safetynet_model: str = None, gnn_model: str = None):
        self.id = job_id
        self.source_kind = source_kind  # 'pcap' or 'csv'
        self.src_path = src_path
        self.metadata = trim_metadata_values(metadata)
        self.label_column = label_column.strip().upper() if label_column else None
        self.benign_label = (benign_label or 'BENIGN').strip().upper()
        self.has_labels = bool(label_column) or (metadata and 'label' in metadata)
        self.scaler_id = scaler_id
        self.xgb_model = xgb_model
        self.safetynet_model = safetynet_model
        self.gnn_model = gnn_model
        
        self.lock = threading.Lock()
        self.paused = False
        self.done = False
        self.results: List[Dict] = []
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0
        
        # Prediction counts (for unlabelled data)
        self.pred_benign = 0
        self.pred_attack = 0
        
        # For streaming
        self.file_handle = None
        self.csv_reader = None
        self.processed_count = 0
        self.total_estimated = 0
        
        # Initialize file reading
        self._init_reader()

    def _init_reader(self):
        if self.source_kind == 'csv':
            # Estimate total lines (rough)
            try:
                # Quick line count
                # self.total_estimated = sum(1 for _ in open(self.src_path, 'rb')) - 1
                # Just set a placeholder, or count if fast enough. For large files, maybe just use file size?
                self.total_estimated = os.path.getsize(self.src_path) // 100 # Very rough estimate
            except:
                self.total_estimated = 1000

            self.file_handle = open(self.src_path, 'r', encoding='utf-8', errors='ignore')
            self.csv_reader = TrimmedDictReader(self.file_handle)
        else:
            # PCAP: Load all at once for now as scapy streaming is tricky without custom iterator
            # Or we can implement a generator for pcap too.
            # For now, keep PCAP as is (pre-loaded) but wrap in iterator interface
            self.pcap_entries = load_pcap_entries(self.src_path)
            self.total_estimated = len(self.pcap_entries)
            self.pcap_iter = iter(self.pcap_entries)

    def next_batch(self, batch_size=50) -> List[Dict]:
        batch = []
        if self.source_kind == 'csv':
            if not self.csv_reader:
                return []
            
            try:
                for _ in range(batch_size):
                    try:
                        row = next(self.csv_reader)
                        entry = self._parse_csv_row(row)
                        if entry:
                            batch.append(entry)
                    except StopIteration:
                        self.done = True
                        self.close()
                        break
            except Exception as e:
                print(f"Error reading CSV batch: {e}")
                self.done = True
                self.close()
                
        else:
            # PCAP
            for _ in range(batch_size):
                try:
                    entry = next(self.pcap_iter)
                    batch.append(entry)
                except StopIteration:
                    self.done = True
                    break
        
        self.processed_count += len(batch)
        return batch

    def _parse_csv_row(self, row) -> Optional[Dict]:
        feats: Dict[str, float] = {}
        missing = False
        
        if self.metadata:
            # Use metadata mapping
            meta_feats = self.metadata.get('features', {})
            for key in FEATURE_KEYS:
                col = meta_feats.get(key)
                val = row.get(col) if col else None
                if val is None or val == '':
                    val = 0.0
                try:
                    feats[key] = float(val)
                except:
                    feats[key] = 0.0
            
            # 4-tuple from metadata (protocol is now from features)
            src_ip = row.get(self.metadata.get('src_ip'))
            dst_ip = row.get(self.metadata.get('dst_ip'))
            src_port = row.get(self.metadata.get('src_port'))
            dst_port = row.get(self.metadata.get('dst_port'))
            timestamp = row.get(self.metadata.get('timestamp'))
            
            # Protocol comes from the features (it's one of the 15)
            proto = feats.get('Protocol', 0)
            
            label_col = self.metadata.get('label')
            label_val = row.get(label_col) if label_col else None
            
        else:
            # Auto-detection logic (Legacy)
            for key in FEATURE_KEYS:
                val = row.get(key)
                if val is None or val == '':
                    missing = True
                    break
                try:
                    feats[key] = float(val)
                except Exception:
                    feats[key] = 0.0
            if missing:
                return None

            def pick(r, *names):
                for n in names:
                    if not n: continue
                    if n in r and r[n]: return r[n]
                    for k in r.keys():
                        if k.lower() == n.lower() and r[k]: return r[k]
                return None

            src_ip = pick(row, 'src', 'Src IP', 'Source', 'Source IP', 'src_ip', 'IPV4_SRC_ADDR', 'source_ip', 'SrcAddr')
            dst_ip = pick(row, 'dst', 'Dst IP', 'Destination', 'Destination IP', 'dst_ip', 'IPV4_DST_ADDR', 'destination_ip', 'DstAddr')
            src_port = pick(row, 'sport', 'Src Port', 'Source Port', 'src_port', 'L4_SRC_PORT')
            dst_port = pick(row, 'dport', 'Dst Port', 'Destination Port', 'dst_port', 'L4_DST_PORT')
            timestamp = pick(row, 'timestamp', 'Timestamp', 'Flow Start', 'StartTime', 'Start Time', 'flow_start', 'ts')
            
            # Protocol from features
            proto = feats.get('Protocol', 0)
            
            label_val = None
            if self.label_column:
                label_val = row.get(self.label_column)

        def to_int(val) -> Optional[int]:
            if val is None: return None
            try: return int(float(val))
            except: return None

        ts_float = parse_timestamp_value(timestamp)

        # Protocol is already extracted from features as a number
        proto_int = int(proto) if proto else 0

        return {
            'timestamp': ts_float,
            'src_ip': src_ip or '',
            'dst_ip': dst_ip or '',
            'src_port': to_int(src_port) or 0,
            'dst_port': to_int(dst_port) or 0,
            'protocol': proto_int,
            'features': feats,
            'label': str(label_val).strip().upper() if label_val else None
        }

    def close(self):
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None

    def mark_done(self):
        self.done = True
        self.close()


    def metrics_summary(self) -> Optional[Dict]:
        total = self.pred_benign + self.pred_attack
        if not self.has_labels:
            # Return prediction counts for unlabelled data
            return {
                'labelled': False,
                'pred_benign': self.pred_benign,
                'pred_attack': self.pred_attack,
                'total': total
            }
        # Labelled data - return accuracy metrics
        if total == 0:
            return {'labelled': True, 'accuracy': 0.0, 'recall': 0.0, 'f1': 0.0, 'cm': [0, 0, 0, 0]}
        accuracy = (self.tp + self.tn) / total if total else 0.0
        recall = self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0
        precision = self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        return {
            'labelled': True,
            'accuracy': round(accuracy, 4),
            'recall': round(recall, 4),
            'f1': round(f1, 4),
            'cm': [self.tn, self.fp, self.fn, self.tp]
        }

    def update_metrics(self, true_label: str, pred_label: str):
        true_up = true_label.upper()
        pred_up = pred_label.upper()

        # Treat anything that is not the benign label as an attack/positive
        true_pos = (true_up != self.benign_label)

        # Model marks BENIGN explicitly; anything else is treated as attack
        pred_pos = (pred_up != 'BENIGN')

        if true_pos and pred_pos:
            self.tp += 1
        elif not true_pos and pred_pos:
            self.fp += 1
        elif true_pos and not pred_pos:
            self.fn += 1
        else:
            self.tn += 1


offline_jobs: Dict[str, OfflineJob] = {}
offline_jobs_lock = threading.Lock()


def save_upload(file_storage, dest_dir: str) -> Dict:
    name = file_storage.filename or f"upload_{int(time.time()*1000)}"
    safe = os.path.basename(name)
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, safe)
    file_storage.save(path)
    return {'name': safe, 'path': path}


def load_pcap_entries(path: str) -> List[Dict]:
    extractor = CICExtractor(iface=None, timeout=1.0, print_interval=0.2)
    flows = extractor.extract_offline(path, timeout=1.0)
    entries: List[Dict] = []
    for f in flows:
        entries.append({
            'timestamp': f['timestamp'],
            'src_ip': f['src'],
            'dst_ip': f['dst'],
            'src_port': f['sport'],
            'dst_port': f['dport'],
            'protocol': f['proto'],
            'features': f['features'],
            'label': None
        })
    return entries


def load_csv_entries(path: str, label_column: Optional[str] = None, limit: Optional[int] = None, metadata: Optional[Dict] = None, filter_label: Optional[str] = None, target_count: Optional[int] = None) -> List[Dict]:
    entries: List[Dict] = []
    
    # helper for flow id
    def parse_flow_id(flow_id: str):
        try:
            parts = flow_id.split('-')
            if len(parts) >= 5:
                src_ip, dst_ip, sport, dport, proto = parts[:5]
                return src_ip, dst_ip, int(sport), int(dport), int(proto)
        except Exception:
            pass
        return None, None, None, None, None

    # --- OPTIMIZATION: Use grep for sparse labels ---
    file_handle = None
    close_handle = True
    
    try:
        # Only use grep optimization if we are filtering for a specific label (like BENIGN) 
        # and we have a target count (so we know when to stop)
        if filter_label and target_count and os.name == 'posix':
            try:
                # 1. Read Header
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    header_line = f.readline()
                
                # 2. Grep for lines. 
                # Use -m to stop after finding enough matches.
                # We grep for the label string.
                # We ask for 3x target count to be safe against false matches in other columns.
                grep_limit = target_count * 3
                
                cmd = ['grep', '-m', str(grep_limit), filter_label, path]
                print(f"[FastLoad] Executing: {' '.join(cmd)}")
                
                grep_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, errors='ignore')
                stdout, _ = grep_proc.communicate()
                
                if stdout:
                    print(f"[FastLoad] Grep returned {len(stdout)} bytes of data.")
                    from io import StringIO
                    # Combine header + grep output
                    full_content = header_line + stdout
                    file_handle = StringIO(full_content)
                    close_handle = False # StringIO doesn't need explicit OS close like file, but good practice.
                else:
                     print("[FastLoad] Grep found nothing. Falling back to full scan.")
            except Exception as e:
                print(f"[FastLoad] Optimization failed: {e}. Falling back to normal.")
        
        # Fallback or normal open
        if file_handle is None:
            file_handle = open(path, 'r', encoding='utf-8', errors='ignore')

        reader = TrimmedDictReader(file_handle)
        
        # Trim metadata values if provided
        if metadata:
            metadata = trim_metadata_values(metadata)

        def pick(row, *names):
            # Try multiple casing/alias options for the same field
            for n in names:
                if not n:
                    continue
                if n in row and row[n]:
                    return row[n]
                # Case-insensitive fallback
                for key in row.keys():
                    if key.lower() == n.lower() and row[key]:
                        return row[key]
            return None

        for row in reader:
            feats: Dict[str, float] = {}
            missing = False
            
            if metadata:
                # Use metadata mapping
                meta_feats = metadata.get('features', {})
                for key in FEATURE_KEYS:
                    col = meta_feats.get(key)
                    val = row.get(col) if col else None
                    if val is None or val == '':
                        # Try to be lenient? Or strict?
                        # Let's assume 0.0 if missing in mapped column
                        val = 0.0
                    try:
                        feats[key] = float(val)
                    except:
                        feats[key] = 0.0
                
                src_ip = row.get(metadata.get('src_ip'))
                dst_ip = row.get(metadata.get('dst_ip'))
                src_port = row.get(metadata.get('src_port'))
                dst_port = row.get(metadata.get('dst_port'))
                proto = row.get(metadata.get('protocol'))
                timestamp = row.get(metadata.get('timestamp'))
                
                label_col = metadata.get('label')
                label_val = row.get(label_col) if label_col else None
                
            else:
                # Auto-detection logic
                for key in FEATURE_KEYS:
                    val = row.get(key)
                    if val is None or val == '':
                        missing = True
                        break
                    try:
                        feats[key] = float(val)
                    except Exception:
                        feats[key] = 0.0
                if missing:
                    continue

                # Primary picks
                src_ip = pick(row, 'src', 'Src IP', 'Source', 'Source IP', 'src_ip', 'IPV4_SRC_ADDR', 'source_ip', 'SrcAddr')
                dst_ip = pick(row, 'dst', 'Dst IP', 'Destination', 'Destination IP', 'dst_ip', 'IPV4_DST_ADDR', 'destination_ip', 'DstAddr')
                src_port = pick(row, 'sport', 'Src Port', 'Source Port', 'src_port', 'L4_SRC_PORT')
                dst_port = pick(row, 'dport', 'Dst Port', 'Destination Port', 'dst_port', 'L4_DST_PORT')
                proto = pick(row, 'proto', 'Protocol', 'protocol')
                timestamp = pick(row, 'timestamp', 'Timestamp', 'Flow Start', 'StartTime', 'Start Time', 'flow_start', 'ts')

                # Fallback: parse Flow ID for CIC Friday files
                if (not src_ip or not dst_ip) and 'Flow ID' in row:
                    f_src, f_dst, f_sport, f_dport, f_proto = parse_flow_id(row.get('Flow ID', ''))
                    src_ip = src_ip or f_src
                    dst_ip = dst_ip or f_dst
                    src_port = src_port or f_sport
                    dst_port = dst_port or f_dport
                    proto = proto or f_proto

                label_val = None
                if label_column:
                    label_val = row.get(label_column)
                    if label_val is not None:
                        label_val = str(label_val).strip()

            def to_int(val) -> Optional[int]:
                if val is None:
                    return None
                try:
                    return int(val)
                except Exception:
                    return None

            ts_float = parse_timestamp_value(timestamp)
            
            # Label normalization
            final_label = label_val.upper() if label_val else None

            # Filter Logic
            if filter_label:
                # If we are filtering, skip if label doesn't match
                if not final_label or final_label != filter_label.upper():
                    continue
                
            entries.append({
                'timestamp': ts_float,
                'src_ip': src_ip or '',
                'dst_ip': dst_ip or '',
                'src_port': to_int(src_port) or 0,
                'dst_port': to_int(dst_port) or 0,
                'protocol': to_int(proto) or 0,
                'features': feats,
                'label': final_label
            })
            
            # Stop if target count reached
            if target_count is not None and len(entries) >= target_count:
                break
                
            # Stop if total scanned limit reached (if limit provided)
            # Note: limit in this case acts as 'max rows to read', not 'max rows to collect' if filter is on.
            # But usually 'limit' in this legacy code meant 'max collected'.
            # If we want 'limit' to be 'max collected', then use the same check.
            if limit is not None and len(entries) >= limit:
                break
    finally:
        if file_handle and close_handle and hasattr(file_handle, 'close'):
            file_handle.close()
            
    return entries

# Live capture state
live_state = {
    'thread': None,
    'extractor': None,
    'flows': [],  # list of dicts: {timestamp, src, dst, sport, dport, proto, features, prediction}
    'running': False,
}
state_lock = threading.Lock()


def predict_one(features: Dict, src_ip: Optional[str] = None, dst_ip: Optional[str] = None, scaler_id: str = None, xgb_model: str = None, safetynet_model: str = None, gnn_model: str = None) -> Dict:
    payload_features = dict(features or {})
    if src_ip:
        payload_features.setdefault('src', src_ip)
    if dst_ip:
        payload_features.setdefault('dst', dst_ip)

    # Use provided scaler_id or fall back to global
    target_scaler = scaler_id if scaler_id else SCALER_ID
    
    payload = {
        'features': payload_features,
        'scaler_id': target_scaler
    }
    if xgb_model and xgb_model != 'default':
        payload['xgb_model'] = xgb_model.replace('.json', '')
    if safetynet_model and safetynet_model != 'default':
        payload['safetynet_model'] = safetynet_model.replace('.pkl', '')
    if gnn_model and gnn_model != 'default':
        payload['gnn_model'] = gnn_model.replace('.pt', '')
    
    try:
        resp = requests.post(PREDICT_URL, json=payload, timeout=2)
        if resp.status_code == 200:
            return resp.json()
        return {'verdict': 'UNKNOWN', 'confidence': 0.0, 'details': {}}
    except Exception:
        return {'verdict': 'UNAVAILABLE', 'confidence': 0.0, 'details': {}}


@app.route('/process_pcap', methods=['POST'])
def process_pcap():
    # 1. Handle Upload
    source_kind = 'pcap'
    if 'csv' in request.files or request.form.get('filetype') == 'csv':
        source_kind = 'csv'
    
    use_stored = request.form.get('filename') is not None

    if source_kind not in ('pcap', 'csv'):
        return jsonify({'error': 'source must be "pcap" or "csv"'}), 400

    label_column = None
    benign_label = request.form.get('benign_label', 'BENIGN')
    scaler_id = request.form.get('scaler_id', 'default')
    xgb_model = request.form.get('xgb_model', 'default')
    safetynet_model = request.form.get('safetynet_model', 'default')
    gnn_model = request.form.get('gnn_model', 'default')

    if source_kind == 'csv':
        if request.form.get('labelled', 'false').lower() == 'true':
            label_column = request.form.get('label_column')
            if not label_column:
                # If using metadata, label_column might be in metadata, so we can be lenient here if metadata exists
                pass 
            benign_label = request.form.get('benign_label', 'BENIGN')
        else:
            label_column = None
    else:
        # PCAP mode should not accept labels
        label_column = None

    src_path = None
    saved_name = None

    if use_stored:
        fname = request.form.get('filename')
        if not fname:
            return jsonify({'error': 'filename required when use_stored=true'}), 400
        base = PCAP_DIR if source_kind == 'pcap' else CSV_DIR
        candidate = os.path.join(base, os.path.basename(fname))
        if not os.path.exists(candidate):
            return jsonify({'error': f'stored file not found: {fname}'}), 404
        src_path = candidate
        saved_name = os.path.basename(candidate)
    else:
        upload_field = 'pcap' if source_kind == 'pcap' else 'csv'
        if upload_field not in request.files:
            return jsonify({'error': f'{upload_field} file required'}), 400
        saved = save_upload(request.files[upload_field], PCAP_DIR if source_kind == 'pcap' else CSV_DIR)
        src_path = saved['path']
        saved_name = saved['name']

    metadata = None
    if source_kind == 'csv':
        # Retrieve mapping passed from frontend, OR try to deduce it
        # The frontend should ideally send 'mapping' in the form data if it was just confirmed
        mapping_json = request.form.get('mapping')
        
        if mapping_json:
            try:
                metadata = json.loads(mapping_json)
                # If we got a mapping, update global dict
                update_global_from_mapping(metadata)
            except:
                print("Failed to parse provided mapping")
                metadata = None
        
        if not metadata:
            # If no mapping provided (e.g. quick re-run), try to auto-map
            # Read header
            header = []
            try:
                with open(src_path, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader(f)
                    header = next(reader)
            except:
                pass
            
            # Get suggestion
            metadata = get_suggested_mapping(header)
            
            # Check if mapping is sufficient? 
            # For now, we assume if it's not provided, we try our best.
            # But if critical features are missing, job might fail or produce zeros.
    
    # Create and start the job
    job_id = str(uuid.uuid4())
    job = OfflineJob(
        job_id=job_id,
        source_kind=source_kind,
        src_path=src_path,
        label_column=label_column,
        benign_label=benign_label,
        metadata=metadata,
        scaler_id=scaler_id,
        xgb_model=xgb_model,
        safetynet_model=safetynet_model,
        gnn_model=gnn_model
    )
    
    with offline_jobs_lock:
        offline_jobs[job_id] = job
    
    return jsonify({
        'job_id': job_id,
        'filename': saved_name,
        'source_kind': source_kind,
        'total': job.total_estimated,
        'status': 'started'
    })

# =============================================================================
# SAFE ZONE RULES APIs
# =============================================================================

# =============================================================================
# (Removed Safe Zone endpoints in favor of generic /switch/inject)
# =============================================================================


# =============================================================================
# JOB MANAGEMENT
# =============================================================================

@app.route('/jobs/start', methods=['POST'])
def start_job():
    """Start an offline processing job (CSV or PCAP)"""
    data = request.get_json(force=True)
    job_type = data.get('type')  # 'csv' or 'pcap'
    filename = data.get('filename')  
    model_name = data.get('model', 'default')
    scaler_id = data.get('scaler_id', 'default')

    if not filename:
         return jsonify({'error': 'filename required'}), 400
         
    try:
        source_kind, src_path = None, None
        if job_type == 'pcap':
            source_kind = 'pcap'
            src_path = os.path.join(PCAP_DIR, filename)
        else:
            source_kind = 'csv'
            src_path = os.path.join(CSV_DIR, filename)

        if source_kind == 'pcap':
            # PCAP check
            if not os.path.exists(src_path):
                 return jsonify({'error': 'source file missing'}), 404
        else:
            # CSV: Just verify file exists
            if not os.path.exists(src_path):
                 return jsonify({'error': 'source file missing'}), 404
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500

    job_id = str(uuid.uuid4())
    job = OfflineJob(job_id, source_kind, src_path, scaler_id=scaler_id)
    
    with offline_jobs_lock:
        offline_jobs[job_id] = job
    
    return jsonify({
        'job_id': job_id,
        'total': job.total_estimated,
        'status': 'started'
    })

@app.route('/offline/next', methods=['GET'])
def offline_next():
    job_id = request.args.get('job')
    if not job_id:
        return jsonify({'status': 'error', 'error': 'job parameter required'}), 400

    with offline_jobs_lock:
        job = offline_jobs.get(job_id)
    if not job:
        return jsonify({'status': 'error', 'error': 'job not found'}), 404

    with job.lock:
        if job.done:
            metrics = job.metrics_summary()
            # Do not pop immediately if we want to allow fetching final metrics multiple times
            # But for now, let's keep it simple. If done, we return done.
            # The client should stop polling.
            return jsonify({'status': 'done', 'metrics': metrics, 'progress': job.processed_count, 'total': job.total_estimated})
        if job.paused:
            metrics = job.metrics_summary()
            return jsonify({'status': 'paused', 'progress': job.processed_count, 'total': job.total_estimated, 'metrics': metrics})
        
        # Process a batch of entries to speed up
        batch_size = 50  # Larger batch for faster completion
        results = []
        
        # Get next batch from job
        batch_entries = job.next_batch(batch_size)
        
        for entry in batch_entries:
            start_ts = time.time()
            pred = predict_one(entry.get('features'), entry.get('src_ip'), entry.get('dst_ip'), job.scaler_id, job.xgb_model, job.safetynet_model, job.gnn_model)
            latency = time.time() - start_ts
            
            verdict = pred.get('verdict', 'UNKNOWN')
            action = pred.get('action')
            if not action:
                action = 'BLOCK' if verdict not in ['BENIGN', 'UNKNOWN', 'UNAVAILABLE'] else 'ALLOW'

            iso_forest = pred.get('isolation_forest', {})
            xgb_model = pred.get('xgb', {})
            gnn_model = pred.get('gnn', {})

            gnn_verdict = gnn_model.get('flag')
            gnn_conf = gnn_model.get('confidence')

            details = {
                'isolation_forest': iso_forest,
                'xgb': xgb_model,
                'gnn': gnn_model
            }
            
            result = {
                'timestamp': entry.get('timestamp', time.time()),
                'src_ip': entry.get('src_ip', ''),
                'dst_ip': entry.get('dst_ip', ''),
                'src_port': entry.get('src_port', 0),
                'dst_port': entry.get('dst_port', 0),
                'protocol': entry.get('protocol', 0),
                'prediction': verdict,
                'action': action,
                'confidence': xgb_model.get('confidence', 0.0),
                'gnn_verdict': gnn_verdict,
                'gnn_confidence': gnn_conf,
                'details': details,
                'latency_ms': round(latency * 1000.0, 2),
                'features': entry.get('features', {}),  # Include the 15 features as nested object
                'benign_label': job.benign_label
            }
            
            # Track prediction counts
            if verdict == 'BENIGN':
                job.pred_benign += 1
            else:
                job.pred_attack += 1

            label = entry.get('label')
            if label:
                result['label'] = label
                job.update_metrics(label, verdict)
            
            results.append(result)
            job.results.append(result)

        metrics = job.metrics_summary()
        
        if job.done:
            # Job finished in this batch
            pass
            
    if job.done:
        with offline_jobs_lock:
            offline_jobs.pop(job_id, None)

    status = 'done' if job.done else 'ok'
    return jsonify({
        'status': status,
        'results': results, # Return list of results
        'progress': job.processed_count,
        'total': job.total_estimated,
        'metrics': metrics
    })



@app.route('/offline/control', methods=['POST'])
def offline_control():
    data = request.get_json(force=True)
    job_id = data.get('job')
    action = data.get('action')
    if not job_id or action not in ('pause', 'resume', 'stop'):
        return jsonify({'error': 'job and valid action required'}), 400

    with offline_jobs_lock:
        job = offline_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'job not found'}), 404

    with job.lock:
        if action == 'pause':
            job.paused = True
        elif action == 'resume':
            job.paused = False
        elif action == 'stop':
            job.mark_done()
            job.paused = False
    if action == 'stop':
        with offline_jobs_lock:
            offline_jobs.pop(job_id, None)

    metrics = job.metrics_summary()
    return jsonify({
        'status': 'ok',
        'action': action,
        'progress': job.processed_count,
        'total': job.total_estimated,
        'metrics': metrics
    })


def live_loop():
    ext = live_state['extractor']
    if not ext:
        return
    try:
        ext.start()
    except Exception as e:
        print(f"[live_loop] Sniff error: {e}", file=sys.stderr)
    finally:
        # Mark as not running when sniff exits (error or stop)
        with state_lock:
            live_state['running'] = False
            live_state['sniff_error'] = str(e) if 'e' in dir() else None


@app.route('/start_iface', methods=['POST'])
def start_iface():
    data = request.get_json(force=True)
    iface = data.get('iface')
    scaler_id = data.get('scaler_id', 'default')
    xgb_model = data.get('xgb_model', 'default')
    safetynet_model = data.get('safetynet_model', 'default')
    gnn_model = data.get('gnn_model', 'default')

    if not iface:
        return jsonify({'error': 'iface required'}), 400

    # Verify interface exists before starting
    if not os.path.exists(f'/sys/class/net/{iface}'):
        return jsonify({'error': f'Interface {iface} does not exist'}), 400

    with state_lock:
        if live_state['running']:
            return jsonify({'status': 'already_running'}), 200
        
        live_state['scaler_id'] = scaler_id
        live_state['xgb_model'] = xgb_model
        live_state['safetynet_model'] = safetynet_model
        live_state['gnn_model'] = gnn_model
        live_state['sniff_error'] = None  # Clear any previous error

        # Create extractor that appends to live_state flows in flush
        class LiveCIC(CICExtractor):
            def flush_flow(self, key):
                flow = self.flows.pop(key, None)
                if not flow:
                    return
                # Initialize variables to avoid UnboundLocalError
                final_verdict = None
                final_action = None
                rule_source = None
                rule_injected = None
                iso_forest = {}
                xgb_model_res = {}
                gnn_model_res = {}
                pred_start = time.time()
                pred_end = time.time()

                try:
                    feats = flow.compute_features()
                    src, dst, sport, dport, proto = flow.key
                    
                    sid = live_state.get('scaler_id', 'default')
                    mod_xgb = live_state.get('xgb_model', 'default')
                    mod_sn = live_state.get('safetynet_model', 'default')
                    mod_gnn = live_state.get('gnn_model', 'default')
                    
                    # Extract 15 features for prediction and storage
                    features_dict = {kk: feats[kk] for kk in FEATURE_KEYS}
                    
                    # GOLDEN RULE: Check Existing OVS Rules First!
                    # If a rule exists in dumpflows (injected_rules) that matches this flow, we obey it and SKIP prediction.
                    existing_rule = is_flow_covered(src, dst, dport, proto)
                    if existing_rule:
                         final_action = existing_rule.get('action', 'ALLOW').upper()
                         final_verdict = 'SKIP' # Skip prediction as rule determines fate
                         rule_source = 'OVS Dumpflow (' + existing_rule.get('match', '') + ')'
                    
                    # 3. ML Prediction (only if no prior rule)
                    if existing_rule:
                         # Skip ML
                         pred_end = time.time()
                         xgb_model_res = {'confidence': 1.0, 'note': 'Skipped due to active rule'}
                    else:
                         pred_start = time.time()
                         pred = predict_one(features_dict, src, dst, sid, mod_xgb, mod_sn, mod_gnn)
                         pred_end = time.time()
                         
                         final_verdict = pred.get('verdict', 'UNKNOWN')
                         raw_action = pred.get('action', '').upper()
                         
                         iso_forest = pred.get('isolation_forest', {})
                         xgb_model_res = pred.get('xgb', {})
                         gnn_model_res = pred.get('gnn', {})
                         
                         # Logic to determine action from ML
                         if not raw_action or raw_action.lower() in ['allow', 'block']:
                            if raw_action == 'BLOCK':
                                final_action = 'BLOCK'
                            elif final_verdict not in ['BENIGN', 'UNKNOWN', 'UNAVAILABLE']:
                                xgb_conf = xgb_model_res.get('confidence', 0)
                                if xgb_conf >= BLOCK_THRESHOLD:
                                    final_action = 'BLOCK'
                                elif xgb_conf >= RATE_LIMIT_THRESHOLD:
                                    final_action = 'RATE_LIMIT'
                                elif xgb_conf >= LOG_THRESHOLD:
                                    final_action = 'LOG'
                                else:
                                    final_action = 'ALLOW'
                            else:
                                final_action = 'ALLOW'
                         else:
                             final_action = raw_action
                         
                         # NEW: Inject Rules for EVERYTHING (including ALLOW)
                         # This replaces "Safe Zone" with explicit 5-tuple permits
                         if topo_state.get('running') and final_action in ['BLOCK', 'RATE_LIMIT', 'ALLOW']:
                             rule_injected = inject_ovs_rule(src, final_action, dst_ip=dst, dst_port=dport, protocol=proto)

                    total_latency_ms = round((pred_end - pred_start) * 1000, 2)
                    
                    details = {
                        'isolation_forest': iso_forest,
                        'xgb': xgb_model_res,
                        'gnn': gnn_model_res,
                        'rule_source': rule_source
                    }

                    record = {
                        'timestamp': flow.last_time,
                        'src_ip': src,
                        'dst_ip': dst,
                        'src_port': sport,
                        'dst_port': dport,
                        'protocol': proto,
                        'features': features_dict,
                        'prediction': final_verdict,
                        'action': final_action,
                        'confidence': xgb_model_res.get('confidence', 0.0) if xgb_model_res else 1.0 if rule_source else 0.0,
                        'gnn_verdict': gnn_model_res.get('flag'),
                        'gnn_confidence': gnn_model_res.get('confidence'),
                        'details': details,
                        'latency_ms': total_latency_ms,
                        'rule_injected': rule_injected
                    }
                    live_state['flows'].append(record)
                    
                except Exception as e:
                    print(f"Error in flushed flow: {e}")
                    traceback.print_exc()

        live_state['extractor'] = LiveCIC(iface=iface, timeout=0.5, print_interval=0.1)
        live_state['flows'] = []
        live_state['running'] = True
        t = threading.Thread(target=live_loop, daemon=True)
        live_state['thread'] = t
        t.start()
    return jsonify({'status': 'started'})


@app.route('/stop_iface', methods=['POST'])
def stop_iface():
    with state_lock:
        ext = live_state.get('extractor')
        if ext:
            ext.stop()
        live_state['running'] = False
    return jsonify({'status': 'stopped'})


@app.route('/flows', methods=['GET'])
def list_flows():
    with state_lock:
        # Return flows with 15 features included
        flows_with_features = []
        for flow in live_state['flows']:
            flow_copy = dict(flow)
            # Features should already be included in the record
            flows_with_features.append(flow_copy)
        return jsonify({'flows': flows_with_features, 'running': live_state['running']})


@app.route('/flows/clear', methods=['POST'])
def clear_flows():
    """Clear all accumulated live flows"""
    with state_lock:
        live_state['flows'] = []
    return jsonify({'status': 'cleared'})


# =============================================================================
# TOPOLOGY CONTROL ENDPOINTS
# =============================================================================

@app.route('/topo/start', methods=['POST'])
def start_topo():
    """Start the OVS network topology"""
    with topo_lock:
        if topo_state['running']:
            return jsonify({'status': 'already_running', 'message': 'Topology is already running'})
        
        try:
            cleanup_topology()
            http_proc = setup_topology()
            topo_state['http_server_proc'] = http_proc
            topo_state['running'] = True
            
            return jsonify({
                'status': 'started',
                'message': 'Topology started successfully',
                'monitor_interface': MONITOR_CAPTURE_IFACE  # mon-cap on host for capture
            })
        except Exception as e:
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500


@app.route('/topo/stop', methods=['POST'])
def stop_topo():
    """Stop the topology and all related processes"""
    with topo_lock:
        if not topo_state['running']:
            return jsonify({'status': 'not_running', 'message': 'Topology is not running'})
        
        try:
            # Stop attack if running
            if attack_state['running']:
                attack_state['running'] = False
                if attack_state['process']:
                    try:
                        os.killpg(os.getpgid(attack_state['process'].pid), signal.SIGTERM)
                    except:
                        pass
            
            # Stop traffic if running
            if traffic_state['running']:
                traffic_state['running'] = False
            
            # Stop HTTP server
            if topo_state['http_server_proc']:
                try:
                    os.killpg(os.getpgid(topo_state['http_server_proc'].pid), signal.SIGTERM)
                except:
                    pass
                topo_state['http_server_proc'] = None
            
            # Cleanup topology
            cleanup_topology()
            topo_state['running'] = False
            
            return jsonify({'status': 'stopped', 'message': 'Topology stopped successfully'})
        except Exception as e:
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500


@app.route('/topo/status', methods=['GET'])
def topo_status():
    """Get current topology status"""
    with injected_rules_lock:
        rules_copy = dict(injected_rules)
    return jsonify({
        'topo_running': topo_state['running'],
        'traffic_running': traffic_state['running'],
        'attack_running': attack_state['running'],
        'attack_type': attack_state['attack_type'],
        'injected_rules': rules_copy
    })


# =============================================================================
# OPTIMIZATION: CHECK EXISTING RULES
# =============================================================================

def is_flow_covered(src, dst, dport, proto):
    """
    Check if a flow matches any existing OVS rule locally.
    Returns rule_data if covered, else None.
    """
    # Proto map for comparison (int -> str)
    proto_map = {6: 'tcp', 17: 'udp', 1: 'icmp'}
    # If proto is already valid string, use it, else map
    try:
        if isinstance(proto, int) or (isinstance(proto, str) and proto.isdigit()):
             flow_proto_name = proto_map.get(int(proto), 'ip')
        else:
             flow_proto_name = str(proto).lower()
    except:
        flow_proto_name = 'ip'
    
    with injected_rules_lock:
        for match_str, rule_data in injected_rules.items():
            # Example match_str: "priority=2000,tcp,nw_src=10.0.0.1,tp_dst=80"
            parts = match_str.split(',')
            
            match = True
            for part in parts:
                part = part.strip()
                if part.startswith('priority='): continue
                if part == 'ip': continue 
                
                # Protocol check (if rule specifies proto, flow MUST match)
                if part in ['tcp', 'udp', 'icmp']:
                    if flow_proto_name != part:
                        match = False; break
                
                # IP checks
                if part.startswith('nw_src='):
                    rule_src = part.split('=')[1]
                    if rule_src != src:
                        match = False; break
                
                if part.startswith('nw_dst='):
                    rule_dst = part.split('=')[1]
                    if rule_dst != dst:
                        match = False; break
                        
                # Port checks
                if part.startswith('tp_dst='):
                    try:
                        rule_port = int(part.split('=')[1])
                        # If dport is None or empty, it doesn't match a specific port rule?
                        if not dport or int(dport) != rule_port:
                            match = False; break
                    except:
                        match = False; break
            
            if match:
                return rule_data
                
    return None


# =============================================================================
# OVS SWITCH FLOW MANAGEMENT ENDPOINTS
# =============================================================================

@app.route('/switch/flows', methods=['GET'])
def switch_flows():
    """Get current OVS flow table"""
    if not topo_state['running']:
        return jsonify({'error': 'Topology not running', 'flows': [], 'raw': ''})
    
    result = get_ovs_flows()
    return jsonify(result)


@app.route('/switch/ports', methods=['GET'])
def switch_ports():
    """Get OVS switch port information"""
    if not topo_state['running']:
        return jsonify({'error': 'Topology not running', 'info': ''})
    
    result = get_ovs_ports()
    return jsonify(result)


@app.route('/switch/rules', methods=['GET'])
def switch_rules():
    """Get currently injected rules by the IDS"""
    with injected_rules_lock:
        rules_copy = dict(injected_rules)
    return jsonify({'status': 'ok', 'rules': rules_copy, 'bridge': BRIDGE_NAME})


@app.route('/switch/inject', methods=['POST'])
def switch_inject():
    """Manually inject an OVS rule for an IP or tuple"""
    data = request.get_json(force=True)
    src_ip = data.get('src_ip')
    dst_ip = data.get('dst_ip')
    dst_port = data.get('dst_port')
    protocol = data.get('protocol')
    priority = data.get('priority')
    action = data.get('action', 'BLOCK')
    
    # Validation
    if not any([src_ip, dst_ip, dst_port, protocol]):
         return jsonify({'error': 'At least one match field required'}), 400

    result = inject_ovs_rule(
        src_ip=src_ip,
        action=action, 
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        priority=priority
    )
    return jsonify(result)


@app.route('/switch/remove', methods=['POST'])
def switch_remove():
    """Remove rule via match string"""
    data = request.get_json(force=True)
    match_str = data.get('match')
    src_ip = data.get('src_ip')
    
    if match_str:
        result = remove_ovs_rule(match_str)
    elif src_ip:
        # Fallback
        match_str = f"ip,nw_src={src_ip}"
        result = remove_ovs_rule(match_str)
    else:
        return jsonify({'error': 'match string required'}), 400
    
    return jsonify(result)
        

@app.route('/switch/clear', methods=['POST'])
def switch_clear():
    """Clear all custom OVS rules"""
    result = clear_all_ovs_rules()
    return jsonify(result)


# =============================================================================
# TRAFFIC GENERATION ENDPOINTS
# =============================================================================

@app.route('/traffic/start', methods=['POST'])
def start_traffic():
    """Start normal traffic generation"""
    if not topo_state['running']:
        return jsonify({'error': 'Topology must be running first'}), 400
    
    if traffic_state['running']:
        return jsonify({'status': 'already_running'})
    
    data = request.get_json(force=True) if request.is_json else {}
    duration = data.get('duration', 0)  # 0 = infinite
    
    traffic_state['running'] = True
    t = threading.Thread(target=generate_normal_traffic_loop, args=(duration,), daemon=True)
    traffic_state['thread'] = t
    t.start()
    
    return jsonify({'status': 'started', 'duration': duration})


@app.route('/traffic/stop', methods=['POST'])
def stop_traffic():
    """Stop normal traffic generation"""
    traffic_state['running'] = False
    return jsonify({'status': 'stopped'})


# =============================================================================
# ATTACK GENERATION ENDPOINTS
# =============================================================================

ATTACK_TYPES = {
    'syn': 'SYN Flood (DoS)',
    'udp': 'UDP Flood (DoS)',
    'scan': 'Port Scan (Probe)',
    'web': 'HTTP Flood (Web)',
    'botnet': 'C&C Beaconing (Botnet)'
}

# Available attacker namespaces
ATTACKER_NS = ['ns_attacker', 'ns_attacker2', 'ns_attacker3']


@app.route('/attack/types', methods=['GET'])
def get_attack_types():
    """Get available attack types and attacker namespaces"""
    attackers = []
    for ns in ATTACKER_NS:
        if ns in NAMESPACES:
            ip = NAMESPACES[ns]['ip'].split('/')[0]
            attackers.append({'ns': ns, 'ip': ip})
    return jsonify({
        'attack_types': ATTACK_TYPES,
        'attackers': attackers
    })


@app.route('/attack/start', methods=['POST'])
def start_attack():
    """Start an attack of specified type from a specified attacker namespace"""
    if not topo_state['running']:
        return jsonify({'error': 'Topology must be running first'}), 400
    
    data = request.get_json(force=True) if request.is_json else {}
    attack_type = data.get('attack_type')
    attacker_ns = data.get('attacker_ns', 'ns_attacker')
    duration = data.get('duration', 0)
    
    if not attack_type or attack_type not in ATTACK_TYPES:
        return jsonify({'error': f'Invalid attack type. Choose from: {list(ATTACK_TYPES.keys())}'}), 400
    
    if attacker_ns not in ATTACKER_NS:
        return jsonify({'error': f'Invalid attacker. Choose from: {ATTACKER_NS}'}), 400
    
    # Stop existing attack
    if attack_state['running']:
        attack_state['running'] = False
        if attack_state['thread']:
            attack_state['thread'].join(timeout=2)
    
    attack_state['running'] = True
    attack_state['attack_type'] = attack_type
    attack_state['attacker_ns'] = attacker_ns
    
    # --- CHANGED LOGIC START ---
    
    # 1. Check if CSV exists for this attack type
    # Mapping: 'web' -> 'test_attack_web.csv', 'syn' -> 'test_attack_syn.csv'
    csv_filename = f"test_attack_{attack_type}.csv"
    csv_path = os.path.join(CSV_DIR, csv_filename)
    
    if os.path.exists(csv_path):
        # MODE A: PLAYBACK (Hybrid)
        print(f"[Attack] Found CSV {csv_filename}. Starting PLAYBACK mode.")
        
        # Get Attacker IP for substitution
        attacker_ip = NAMESPACES[attacker_ns]['ip'].split('/')[0]
        
        t = threading.Thread(
            target=run_attack_playback_loop, 
            args=(csv_path, attacker_ip, duration, attack_type), 
            daemon=True
        )
        attack_state['thread'] = t
        t.start()
        mode_msg = "playback"
        
    else:
        # MODE B: CLI GENERATION (Original Fallback)
        print(f"[Attack] No CSV found for {attack_type}. Starting REAL TRAFFIC generation.")
        
        t = threading.Thread(
            target=run_attack_loop, 
            args=(attack_type, duration, attacker_ns), 
            daemon=True
        )
        attack_state['thread'] = t
        t.start()
        mode_msg = "generated"

    # --- CHANGED LOGIC END ---

    attacker_ip_display = NAMESPACES[attacker_ns]['ip'].split('/')[0]
    return jsonify({
        'status': 'started',
        'mode': mode_msg,
        'attack_type': attack_type,
        'attack_name': ATTACK_TYPES[attack_type],
        'attacker_ns': attacker_ns,
        'attacker_ip': attacker_ip_display,
        'duration': duration
    })


@app.route('/attack/stop', methods=['POST'])
def stop_attack():
    """Stop the current attack"""
    if not attack_state['running']:
        return jsonify({'status': 'not_running'})
    
    attack_state['running'] = False
    
    # Kill any running attack process
    if attack_state['process']:
        try:
            os.killpg(os.getpgid(attack_state['process'].pid), signal.SIGTERM)
        except:
            pass
        attack_state['process'] = None
    
    return jsonify({'status': 'stopped'})


# =============================================================================
# LIVE LOGS CSV EXPORT
# =============================================================================

@app.route('/flows/export', methods=['POST'])
def export_flows_csv():
    """Export current live flows to CSV and return as downloadable file or save to server"""
    with state_lock:
        flows = list(live_state.get('flows', []))
    
    if not flows:
        return jsonify({'error': 'No flows to export'}), 400
    
    data = request.get_json(force=True) if request.is_json else {}
    save_to_server = data.get('save_to_server', False)
    filename = data.get('filename', f"live_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    
    # Build CSV
    output = io.StringIO()
    
    # Headers: timestamp, 3-tuple info, 15 features, prediction info
    headers = [
        'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
    ] + FEATURE_KEYS + [
        'prediction', 'action', 'confidence', 'gnn_verdict', 'gnn_confidence'
    ]
    
    writer = csv.DictWriter(output, fieldnames=headers, extrasaction='ignore')
    writer.writeheader()
    
    for flow in flows:
        row = {
            'timestamp': flow.get('timestamp', ''),
            'src_ip': flow.get('src_ip', ''),
            'dst_ip': flow.get('dst_ip', ''),
            'src_port': flow.get('src_port', ''),
            'dst_port': flow.get('dst_port', ''),
            'protocol': flow.get('protocol', ''),
            'prediction': flow.get('prediction', ''),
            'action': flow.get('action', ''),
            'confidence': flow.get('confidence', ''),
            'gnn_verdict': flow.get('gnn_verdict', ''),
            'gnn_confidence': flow.get('gnn_confidence', ''),
        }
        
        # Add 15 features
        features = flow.get('features', {})
        for key in FEATURE_KEYS:
            row[key] = features.get(key, '')
        
        writer.writerow(row)
    
    csv_content = output.getvalue()
    
    if save_to_server:
        # Save to CSV_DIR
        filepath = os.path.join(CSV_DIR, filename)
        with open(filepath, 'w') as f:
            f.write(csv_content)
        return jsonify({
            'status': 'saved',
            'filename': filename,
            'rows': len(flows),
            'message': f'Saved {len(flows)} flows to {filename}'
        })
    else:
        # Return CSV content for download
        from flask import Response
        return Response(
            csv_content,
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )


@app.route('/stored_files', methods=['GET'])
def stored_files():
    def describe(dir_path):
        items = []
        try:
            for name in sorted(os.listdir(dir_path)):
                full = os.path.join(dir_path, name)
                if not os.path.isfile(full):
                    continue
                stat = os.stat(full)
                items.append({
                    'name': name,
                    'size': stat.st_size,
                    'mtime': stat.st_mtime
                })
        except Exception:
            pass
        return items
    return jsonify({'pcaps': describe(PCAP_DIR), 'csvs': describe(CSV_DIR)})


@app.route('/interfaces', methods=['GET'])
def list_interfaces_route():
    interfaces = list_network_interfaces()
    
    # Filter out topology-related interfaces if topology is not running
    # These interfaces (veth_*, mon-cap, ovs-*) should only appear when topo is active
    TOPO_INTERFACES = {'veth_mon', 'veth_serv', 'veth_user', 'veth_hack', 'veth_hack2', 'veth_hack3', 'mon-cap', 'ovs-system'}
    
    with topo_lock:
        topo_running = topo_state.get('running', False)
    
    if not topo_running:
        interfaces = [iface for iface in interfaces if iface['name'] not in TOPO_INTERFACES]
    else:
        # When topo is running, prioritize mon-cap at the top
        def sort_key(item):
            if item['name'] == 'mon-cap':
                return (0, item['name'])
            elif item['name'].startswith('veth_'):
                # Lower priority for internal OVS ports
                return (2, item['name'])
            else:
                return (1, item['name'])
        interfaces.sort(key=sort_key)
    
    return jsonify({'interfaces': interfaces})


@app.route('/csv_headers', methods=['GET'])
def csv_headers():
    """Get the headers of a stored CSV file."""
    filename = request.args.get('filename')
    if not filename:
        return jsonify({'error': 'filename required'}), 400
    
    filepath = os.path.join(CSV_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'file not found'}), 404
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            first_line = f.readline().strip()
            headers = [h.strip().replace('"', '') for h in first_line.split(',')]
            return jsonify({'headers': headers})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/get_mapping', methods=['GET'])
def get_mapping():
    """Get suggested column mapping for a CSV file based on Global Dict."""
    filename = request.args.get('filename')
    if not filename:
        return jsonify({'error': 'filename required'}), 400
    
    filepath = os.path.join(CSV_DIR, filename)
    if not os.path.exists(filepath):
        # Maybe it's an uploaded file not yet saved? 
        # But this endpoint is usually called for stored files or after upload.
        return jsonify({'error': 'file not found'}), 404

    # Read headers
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            headers = next(reader)
            
        suggested = get_suggested_mapping(headers)
        return jsonify(suggested)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/save_mapping', methods=['POST'])
def save_mapping_route():
    """Update global mapping with new aliases."""
    data = request.get_json(force=True)
    mapping = data.get('mapping')
    
    if not mapping:
        return jsonify({'error': 'mapping required'}), 400
    
    update_global_from_mapping(mapping)
    return jsonify({'status': 'ok', 'message': 'Global mapping updated'})
    trimmed_mapping = trim_metadata_values(mapping)
    save_metadata_file(filename, trimmed_mapping)
    return jsonify({'status': 'ok'})


@app.route('/save_file', methods=['POST'])
def save_file():
    """Save an uploaded file to permanent storage without processing."""
    if 'pcap' in request.files:
        saved = save_upload(request.files['pcap'], PCAP_DIR)
        return jsonify({'status': 'ok', 'name': saved['name'], 'type': 'pcap'})
    elif 'csv' in request.files:
        saved = save_upload(request.files['csv'], CSV_DIR)
        return jsonify({'status': 'ok', 'name': saved['name'], 'type': 'csv'})
    else:
        return jsonify({'error': 'No file provided'}), 400


@app.route('/analyze_recalibration', methods=['POST'])
def analyze_recalibration():
    # 1. Handle File (Upload or Stored)
    scaler_id = request.form.get('scaler_id', 'default')
    use_stored = request.form.get('filename') is not None
    src_path = None
    saved_name = None
    
    if use_stored:
        fname = request.form.get('filename')
        # We only support CSV for this
        if not fname:
            return jsonify({'error': 'filename required'}), 400
        candidate = os.path.join(CSV_DIR, os.path.basename(fname))
        if not os.path.exists(candidate):
            return jsonify({'error': f'stored file not found: {fname}'}), 404
        src_path = candidate
        saved_name = os.path.basename(candidate)
    else:
        if 'csv' not in request.files:
            return jsonify({'error': 'csv file required'}), 400
        saved = save_upload(request.files['csv'], CSV_DIR)
        src_path = saved['path']
        saved_name = saved['name']

    # 2. Handle Mapping
    mapping_str = request.form.get('mapping')
    metadata = None
    if mapping_str:
        try:
            metadata = json.loads(mapping_str)
        except:
            pass
    
    # If no mapping provided, try to load from disk
    if not metadata:
        metadata = load_metadata(saved_name)

    if not metadata:
        return jsonify({'error': 'Column mapping required'}), 400

    # 3. Determine Sample Size & Load CSV
    try:
        # Check if labelled data
        is_labelled = False
        target_benign_label = None
        target_benign_count = 30000
        
        if metadata and metadata.get('label'):
            is_labelled = True
            target_benign_label = metadata.get('benign_label', 'BENIGN')
            
        if is_labelled:
            # 3000 Benign samples logic
            print(f"[Analysis] Labelled data detected. Searching for up to {target_benign_count} '{target_benign_label}' samples...")
            
            # We pass limit=None (or very large) because we need to scan until we find the targets.
            # But maybe safety cap is still good? Let's say max 1M rows scan to find 3000 benigns.
            entries = load_csv_entries(
                src_path, 
                metadata=metadata, 
                filter_label=target_benign_label, 
                target_count=target_benign_count, 
                limit=1000000 # Safety scan limit
            )
            
            if len(entries) < target_benign_count:
                print(f"[Analysis] Warning: Only found {len(entries)} benign samples (Target: {target_benign_count}). Using all available samples.")
            else:
                 print(f"[Analysis] Successfully collected {target_benign_count} benign samples.")
                 
        else:
            # Unlabelled - 20% Logic
            # Fast line count
            total_lines = 0
            try:
                # Use wc -l if available (Linux)
                output = subprocess.check_output(['wc', '-l', src_path], text=True)
                total_lines = int(output.split()[0])
            except:
                # Fallback to python read
                with open(src_path, 'rb') as f:
                    total_lines = sum(1 for _ in f)
            
            # We need 20%
            # total_lines includes header, so rough estimate is fine
            limit = int(total_lines * 0.2)
            
            # Hard cap to prevent timeout on massive files (e.g. max 100k samples)
            # 100k samples is statistically more than enough for IQR/Median
            max_samples = 100000
            if limit > max_samples:
                print(f"[Analysis] Capping sample size at {max_samples} (20% was {limit})")
                limit = max_samples
                
            if limit < 100: limit = 100 # Min samples
            
            print(f"[Analysis] Loading ~{limit} samples from {total_lines} total lines (Unlabelled)...")
            entries = load_csv_entries(src_path, metadata=metadata, limit=limit)
        
    except Exception as e:
         return jsonify({'error': f'Failed to parse CSV: {str(e)}'}), 500

    if not entries:
         return jsonify({'error': 'No entries found in CSV'}), 400

    print(f"[Analysis] Loaded {len(entries)} samples.")

    # 4. Fetch Baseline Stats
    baseline = {}
    try:
        if '/' in PREDICT_URL:
            base_url = PREDICT_URL.rsplit('/', 1)[0]
        else:
            base_url = PREDICT_URL 
        
        url = f"{base_url}/scaler_stats?scaler_id={scaler_id}"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            baseline = resp.json()
        else:
            return jsonify({'error': 'Failed to fetch baseline stats from backend'}), 500
    except Exception as e:
        return jsonify({'error': f'Failed to connect to backend: {str(e)}'}), 500

    # 5. Compute Stats & Compare
    results = []
    consistent_count = 0
    valid_features_count = 0
    shift_magnitudes = []
    missing_features = []

    # Optimize: Single pass aggregation
    print("[Analysis] Aggregating feature values...")
    feature_buckets = {k: [] for k in FEATURE_KEYS}
    
    for e in entries:
        feats = e.get('features', {})
        for k in FEATURE_KEYS:
            v = feats.get(k)
            if v is not None:
                feature_buckets[k].append(v)
    
    print("[Analysis] Computing statistics...")
    for i, key in enumerate(FEATURE_KEYS):
        vals = feature_buckets[key]
        
        # 1. Data Sanitization
        if not vals:
            missing_features.append(key)
            continue
            
        arr = np.array(vals, dtype=float)
        
        # Remove NaN and Inf
        arr = arr[np.isfinite(arr)]
        
        # Check sample count
        if len(arr) < 50:
            status = "unstable (insufficient clean samples)"
            results.append({
                'feature': key,
                'median_ratio': 1.0,
                'iqr_ratio': 1.0,
                'status': status,
                'median_new': 0.0,
                'iqr_new': 0.0,
                'median_ref': 0.0,
                'iqr_ref': 0.0
            })
            continue # Exclude from decision metrics
        
        valid_features_count += 1
        
        # 2. Statistics (Median & IQR)
        median_new = float(np.median(arr))
        q75, q25 = np.percentile(arr, [75, 25])
        iqr_new = float(q75 - q25)
        if iqr_new <= 1e-9: iqr_new = 1e-6
        
        ref = baseline.get(key)
        if not ref:
             continue
             
        median_ref = float(ref.get('median', 0.0))
        iqr_ref = float(ref.get('iqr', 1e-6))
        if iqr_ref <= 1e-9: iqr_ref = 1e-6

        # 3. Ratio Computation with Noise Dead-Zone
        # Median Ratio
        if abs(median_ref) < 1e-9:
             # If baseline median is 0, we can't divide.
             # If new median is also near 0, ratio is 1. Else large.
             if abs(median_new) < 1e-9:
                 median_ratio = 1.0
             else:
                 median_ratio = 999.0 # Large shift
        else:
             median_ratio = median_new / median_ref

        # Apply dead-zone to median_ratio
        if median_ratio > 1e-9 and abs(math.log(median_ratio)) < 0.05:
            median_ratio = 1.0

        # IQR Ratio
        iqr_ratio = iqr_new / iqr_ref
        
        # Apply dead-zone to iqr_ratio
        if iqr_ratio > 1e-9 and abs(math.log(iqr_ratio)) < 0.05:
            iqr_ratio = 1.0
        
        # 4. Shape Consistency
        if abs(iqr_ratio) < 1e-9:
             ratio_of_ratios = 0
        else:
             ratio_of_ratios = median_ratio / iqr_ratio
            
        status = "shape_changed"
        if 0.5 <= ratio_of_ratios <= 2.0:
            status = "scale_consistent"
            consistent_count += 1
            
        results.append({
            'feature': key,
            'median_ratio': median_ratio,
            'iqr_ratio': iqr_ratio,
            'status': status,
            'median_new': median_new,
            'iqr_new': iqr_new,
            'median_ref': median_ref,
            'iqr_ref': iqr_ref
        })
        
        # 5. Shift Magnitude
        if median_ratio > 1e-9:
            shift_magnitudes.append(abs(math.log(median_ratio)))
        else:
            shift_magnitudes.append(5.0) # Penalty for non-positive or zero ratio

    print("[Analysis] Calculation finished.")
        
    if missing_features:
        return jsonify({'error': f'Missing features in CSV: {missing_features}'}), 400
        
    # 6. Global Decision Logic
    try:
        shape_score = consistent_count / valid_features_count if valid_features_count > 0 else 0
        avg_shift = float(np.mean(shift_magnitudes)) if shift_magnitudes else 0.0
        
        if shape_score < 0.6:
            recommendation = "RETRAIN"
        elif avg_shift <= 0.1:
            recommendation = "NO ACTION"
        else:
            recommendation = "RESCALE"
            
        # Sanitize results for JSON compliance (no NaN/Inf)
        sanitized_results = []
        for r in results:
            m_rat = r['median_ratio']
            i_rat = r['iqr_ratio']
            
            # Check for NaN/Inf
            if math.isnan(m_rat) or math.isinf(m_rat): m_rat = 0.0
            if math.isnan(i_rat) or math.isinf(i_rat): i_rat = 0.0
            
            sanitized_results.append({
                'feature': r['feature'],
                'median_ratio': m_rat,
                'iqr_ratio': i_rat,
                'status': r['status'],
                'median_new': r.get('median_new', 0.0),
                'iqr_new': r.get('iqr_new', 0.0),
                'median_ref': r.get('median_ref', 0.0),
                'iqr_ref': r.get('iqr_ref', 0.0)
            })
            
        return jsonify({
            'results': sanitized_results,
            'shape_score': float(shape_score),
            'scale_score': float(shape_score), # For frontend compatibility
            'avg_shift': float(avg_shift),
            'recommendation': recommendation,
            'valid_features': valid_features_count
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'Server Error during response generation: {str(e)}'}), 500


@app.route('/')
@app.route('/dashboard.html')
def serve_dashboard():
    return send_from_directory('.', 'dashboard.html')

@app.route('/api/scaler_stats')
def proxy_scaler_stats():
    try:
        base_url = get_base_url()
        scaler_id = request.args.get('scaler_id', SCALER_ID)
        url = f"{base_url}/scaler_stats?scaler_id={scaler_id}"
        print(f"Fetching stats from: {url}")
        resp = requests.get(url, timeout=5)
        return jsonify(resp.json())
    except Exception as e:
        print(f"Error fetching scaler stats: {e}")
        return jsonify({'error': str(e)}), 500

# --- Proxy Endpoints for Retrieve/Rescale ---

@app.route('/api/scalers', methods=['GET'])
def proxy_list_scalers():
    try:
        base = get_base_url()
        print(f"Proxying list_scalers to: {base}/scalers")
        resp = requests.get(f"{base}/scalers", timeout=5)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        print(f"Error in proxy_list_scalers: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/models', methods=['GET'])
def proxy_list_models():
    try:
        base = get_base_url()
        print(f"Proxying list_models to: {base}/models")
        resp = requests.get(f"{base}/models", timeout=5)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        print(f"Error in proxy_list_models: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/rescale', methods=['POST'])
def proxy_rescale():
    scaler_name = request.form.get('scaler_name')
    
    # File handling
    use_stored = request.form.get('use_stored') == 'true'
    filename = request.form.get('filename')
    
    # Mapping and Label params
    mapping_str = request.form.get('mapping')
    
    # Strict boolean parsing
    is_labelled = str(request.form.get('labelled', '')).lower() == 'true'
    label_col = request.form.get('label_col')
    benign_label = request.form.get('benign_label', 'BENIGN')
    
    src_path = None
    temp_path = None
    
    try:
        # 1. Resolve Source File
        if use_stored:
            if not filename:
                return jsonify({'error': 'filename required for stored file'}), 400
            src_path = os.path.join(CSV_DIR, filename)
            if not os.path.exists(src_path):
                # Try finding it in uploads just in case (e.g. legacy)
                 src_path = os.path.join(UPLOAD_DIR, filename)
                 if not os.path.exists(src_path):
                    return jsonify({'error': 'Stored file not found'}), 404
        else:
            if 'csv' not in request.files:
                return jsonify({'error': 'No file provided'}), 400
            file = request.files['csv']
            temp_dir = os.path.join(UPLOAD_DIR, 'temp_rescale')
            os.makedirs(temp_dir, exist_ok=True)
            temp_path = os.path.join(temp_dir, f"rescale_{uuid.uuid4().hex}.csv")
            file.save(temp_path)
            src_path = temp_path
            
        # 2. Resolve Mapping
        metadata = None
        if mapping_str:
             try:
                 metadata = json.loads(mapping_str)
                 update_global_from_mapping(metadata)
             except:
                 pass
        
        if not metadata:
            # Auto-detect
            try:
                with open(src_path, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader(f)
                    header = next(reader)
                metadata = get_suggested_mapping(header)
            except:
                pass
                
        if not metadata or 'features' not in metadata:
             # Clean up
            if temp_path and os.path.exists(temp_path): os.remove(temp_path)
            return jsonify({'error': 'Column mapping/features calculation failed. Provide mapping.'}), 400

        try:
            # 3. Load & Filter Data taking 10k Benign
            target_count = 10000
            filter_lbl = benign_label if is_labelled else None
            
            # Construct metadata for loader
            load_meta = metadata.copy()
            if is_labelled and label_col:
                load_meta['label'] = label_col
            elif is_labelled and 'label' in metadata:
                pass # Already set
            else:
                 # Check if label is in metadata
                 if 'label' in metadata:
                     if is_labelled: pass # good
                     else: load_meta.pop('label', None)
                
            print(f"[Rescale] Loading samples from {src_path}. Labelled={is_labelled}, Filter={filter_lbl}")
                
            entries = load_csv_entries(
                src_path,
                metadata=load_meta,
                filter_label=filter_lbl,
                target_count=target_count,
                limit=target_count if not is_labelled else None 
            )
            
            if not entries:
                 return jsonify({'error': f'No valid samples found (Labelled={is_labelled}, Label={filter_lbl})'}), 400
                 
            if len(entries) < 10:
                 return jsonify({'error': f'Insufficient samples ({len(entries)}) found for rescaling. Need at least 10.'}), 400

            print(f"[Rescale] Collected {len(entries)} valid samples for rescaling.")

            # 4. Generate Clean CSV for Backend
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=FEATURE_KEYS)
            writer.writeheader()
            
            for e in entries:
                writer.writerow(e['features'])
                
            output.seek(0)
            
            # 5. Send to Backend
            base = get_base_url()
            data = {'name': scaler_name} if scaler_name else {}
            
            mem_file = io.BytesIO(output.getvalue().encode('utf-8'))
            files = {'file': ('rescaled_cleaned.csv', mem_file, 'text/csv')}
            
            resp = requests.post(f"{base}/refit_scaler", files=files, data=data, timeout=120)
            return jsonify(resp.json()), resp.status_code

        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)

    except Exception as e:
        traceback.print_exc()
        if temp_path and os.path.exists(temp_path):
             os.remove(temp_path)
        return jsonify({'error': str(e)}), 500

@app.route('/api/retrain', methods=['POST'])
def proxy_retrain():
    model_type = request.form.get('model_type')
    model_name = request.form.get('model_name')
    label_col = request.form.get('label_col', 'Label')
    benign_label = request.form.get('benign_label', 'BENIGN')
    scaler_id = request.form.get('scaler_id', 'default')
    
    use_stored = request.form.get('use_stored') == 'true'
    filename = request.form.get('filename')
    
    mapping_str = request.form.get('mapping')
    
    if not model_type or not model_name:
         return jsonify({'error': 'model_type and model_name required'}), 400

    src_path = None
    temp_path = None
    file_handle = None

    try:
         # 1. Resolve Source
        if use_stored:
            if not filename: return jsonify({'error': 'filename required for stored file'}), 400
            src_path = os.path.join(CSV_DIR, filename)
            if not os.path.exists(src_path):
                return jsonify({'error': 'Stored file not found'}), 404
            file_handle = open(src_path, 'rb')
            filename_to_send = os.path.basename(src_path)
        else:
            if 'csv' not in request.files: return jsonify({'error': 'No file provided'}), 400
            file = request.files['csv']
            # We can stream directly from request.files if we didn't need to read headers for mapping...
            # But we might need to auto-detect mapping if not provided.
            if not mapping_str:
                # Need to read header
                temp_dir = os.path.join(UPLOAD_DIR, 'temp_retrain')
                os.makedirs(temp_dir, exist_ok=True)
                temp_path = os.path.join(temp_dir, f"retrain_{uuid.uuid4().hex}.csv")
                file.save(temp_path)
                src_path = temp_path
                file_handle = open(src_path, 'rb')
                filename_to_send = file.filename
            else:
                 # We have mapping, just stream
                 file_handle = file.stream
                 filename_to_send = file.filename

        # 2. Resolve Mapping
        metadata = None
        if mapping_str:
             try:
                 metadata = json.loads(mapping_str)
                 update_global_from_mapping(metadata)
             except: pass
        
        # If no mapping str provided, we must rely on auto-detection.
        # But if we stream directly from upload without saving, we can't easily peek...
        # So we enforced saving above if !mapping_str.
        if not metadata and src_path:
             try:
                # Peek header
                 with open(src_path, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader(f)
                    header = next(reader)
                 metadata = get_suggested_mapping(header)
             except: pass
             
        if not metadata or 'features' not in metadata:
             if temp_path and os.path.exists(temp_path): os.remove(temp_path)
             if file_handle: file_handle.close()
             return jsonify({'error': 'Column mapping required'}), 400
         
        # 3. Send to Backend
        base = get_base_url()
        
        # Note: file_handle position might need reset ?
        if src_path:
             file_handle.seek(0)
        else:
             file.stream.seek(0) # Reset stream if we read from it (we didn't read from file.stream directly above, we saved it.)
        
        # If we are sending a file stream, 'requests' works best with open files
        files = {'file': (filename_to_send, file_handle, 'text/csv')}
        data = {
            'model_name': model_name,
            'label_col': label_col,
            'benign_label': benign_label,
            'scaler_id': scaler_id,
            'mapping': json.dumps(metadata['features']) 
        }
        
        resp = requests.post(f"{base}/retrain/{model_type}", files=files, data=data, timeout=300)
        
        if temp_path and os.path.exists(temp_path): 
            try:
                file_handle.close()
            except: pass
            os.remove(temp_path)
        elif use_stored:
             file_handle.close()
             
        try:
            return jsonify(resp.json()), resp.status_code
        except:
             return jsonify({'error': 'Invalid JSON from backend', 'text': resp.text}), resp.status_code

    except Exception as e:
        if file_handle: 
            try: file_handle.close()
            except: pass
        if temp_path and os.path.exists(temp_path):
             try: os.remove(temp_path)
             except: pass
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # Ensure clean state at startup
    try:
        cleanup_topology()
    except Exception as e:
        print(f"Warning: Startup cleanup failed: {e}")
    
    app.run(host='0.0.0.0', port=5000)

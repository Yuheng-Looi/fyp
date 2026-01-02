import argparse
import time
import math
import requests
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
import threading

# CONFIGURATION
GPU_SERVER_URL = "http://10.100.10.15:8000/predict"

# Exact feature keys required by the classifier
FEATURE_KEYS = [
    'Fwd Header Len', 'Protocol', 'Init Bwd Win Byts', 'Tot Fwd Pkts', 'Pkt Len Max',
    'Pkt Len Mean', 'Tot Bwd Pkts', 'Dst Port', 'Bwd Pkt Len Max', 'Fwd Pkts/s',
    'Flow IAT Max', 'TotLen Bwd Pkts', 'TotLen Fwd Pkts', 'Bwd Pkt Len Std',
    'Bwd Pkt Len Mean'
]

class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, timestamp):
        self.key = (src_ip, dst_ip, src_port, dst_port, protocol)
        self.start_time = timestamp
        self.last_time = timestamp
        self.fwd_pkts = 0
        self.bwd_pkts = 0
        self.tot_len_fwd = 0
        self.tot_len_bwd = 0
        self.len_all = []
        self.len_bwd = []
        self.iat_all = []
        self.fwd_header_len = 0
        self.pkt_len_max = 0
        self.bwd_pkt_len_max = 0
        self.init_bwd_win = None

    @staticmethod
    def _header_len(pkt):
        ip = pkt[IP]
        ip_hdr = getattr(ip, 'ihl', 5) * 4  # default 20 bytes
        l4_hdr = 0
        if pkt.haslayer(TCP):
            l4_hdr = getattr(pkt[TCP], 'dataofs', 5) * 4  # default 20 bytes
        elif pkt.haslayer(UDP):
            l4_hdr = 8
        return ip_hdr + l4_hdr

    def add(self, pkt, timestamp, is_fwd):
        if self.last_time is not None:
            self.iat_all.append(timestamp - self.last_time)
        self.last_time = timestamp

        pkt_len = len(pkt)
        self.len_all.append(pkt_len)
        self.pkt_len_max = max(self.pkt_len_max, pkt_len)

        hdr_len = self._header_len(pkt)
        if is_fwd:
            self.fwd_pkts += 1
            self.tot_len_fwd += pkt_len
            self.fwd_header_len += hdr_len
        else:
            self.bwd_pkts += 1
            self.tot_len_bwd += pkt_len
            self.len_bwd.append(pkt_len)
            self.bwd_pkt_len_max = max(self.bwd_pkt_len_max, pkt_len)
            if self.init_bwd_win is None and pkt.haslayer(TCP):
                self.init_bwd_win = getattr(pkt[TCP], 'window', 0)

    def to_features(self):
        duration = max(self.last_time - self.start_time, 1e-6)
        flow_iat_max = max(self.iat_all) if self.iat_all else 0.0

        pkt_len_mean = float(np.mean(self.len_all)) if self.len_all else 0.0
        bwd_pkt_len_mean = float(np.mean(self.len_bwd)) if self.len_bwd else 0.0
        bwd_pkt_len_std = float(np.std(self.len_bwd, ddof=1)) if len(self.len_bwd) > 1 else 0.0

        fwd_pps = self.fwd_pkts / duration

        # Build feature map with exact keys
        features = {
            'Fwd Header Len': float(self.fwd_header_len),
            'Protocol': int(self.key[4]),
            'Init Bwd Win Byts': int(self.init_bwd_win) if self.init_bwd_win is not None else 0,
            'Tot Fwd Pkts': int(self.fwd_pkts),
            'Pkt Len Max': float(self.pkt_len_max),
            'Pkt Len Mean': float(pkt_len_mean),
            'Tot Bwd Pkts': int(self.bwd_pkts),
            'Dst Port': int(self.key[3]),
            'Bwd Pkt Len Max': float(self.bwd_pkt_len_max),
            'Fwd Pkts/s': float(fwd_pps),
            'Flow IAT Max': float(flow_iat_max),
            'TotLen Bwd Pkts': float(self.tot_len_bwd),
            'TotLen Fwd Pkts': float(self.tot_len_fwd),
            'Bwd Pkt Len Std': float(bwd_pkt_len_std),
            'Bwd Pkt Len Mean': float(bwd_pkt_len_mean)
        }
        return features

# Global Flow Storage
active_flows = {}
lock = threading.Lock()

def packet_handler(pkt):
    if not pkt.haslayer(IP):
        return

    # Prefer pcap timestamp if present
    timestamp = float(getattr(pkt, 'time', time.time()))
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    proto = pkt[IP].proto

    src_port = 0
    dst_port = 0

    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    key = (src_ip, dst_ip, src_port, dst_port, proto)
    reverse_key = (dst_ip, src_ip, dst_port, src_port, proto)

    with lock:
        if key in active_flows:
            active_flows[key].add(pkt, timestamp, is_fwd=True)
        elif reverse_key in active_flows:
            active_flows[reverse_key].add(pkt, timestamp, is_fwd=False)
        else:
            active_flows[key] = Flow(src_ip, dst_ip, src_port, dst_port, proto, timestamp)
            active_flows[key].add(pkt, timestamp, is_fwd=True)

def flow_exporter(interval=2.0):
    """
    Background thread to check for finished flows and send to GPU.
    """
    print(f"[*] Exporter thread started. Sending to {GPU_SERVER_URL}")
    while True:
        time.sleep(interval)
        current_time = time.time()
        
        with lock:
            keys_to_remove = []
            for key, flow in active_flows.items():
                # Logic: If flow is older than 3 seconds or idle for 1 second, export it
                if (current_time - flow.start_time > 3.0) or (current_time - flow.last_time > 1.0):
                    
                    # 1. Extract Features
                    data = flow.to_features()
                    
                    # 2. Send to GPU (Async to not block sniffing)
                    try:
                        threading.Thread(target=send_to_gpu, args=(data, key)).start()
                    except Exception as e:
                        print(f"[!] Error spawning send thread: {e}")
                        
                    keys_to_remove.append(key)
            
            # Cleanup
            for k in keys_to_remove:
                del active_flows[k]

def send_to_gpu(features, flow_key):
    try:
        # Wrap in expected JSON format
        payload = {"features": features}
        
        resp = requests.post(GPU_SERVER_URL, json=payload, timeout=1)
        
        if resp.status_code == 200:
            result = resp.json()
            verdict = result['verdict']
            conf = result['confidence']
            
            # Only print if it's interesting (Attack or Suspicious)
            if verdict != "BENIGN" or True:
                print(f"\n[ALERT] Flow {flow_key[0]}->{flow_key[1]}")
                print(f"        TYPE: {verdict} | CONF: {conf:.2f}")
                print(f"        FLAGS: {result['details']}")
        else:
            print(f"[!] Server Error: {resp.status_code}")
            
    except requests.exceptions.ConnectionError:
        pass # GPU server might be down, ignore to keep sniffing clean
    except Exception as e:
        print(f"[!] Send Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True, help="Interface to listen on (e.g., s1-snoop)")
    args = parser.parse_args()

    # Start Exporter Thread
    export_thread = threading.Thread(target=flow_exporter, daemon=True)
    export_thread.start()

    print(f"[*] Listening on {args.iface}...")
    try:
        sniff(iface=args.iface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
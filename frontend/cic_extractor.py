#!/usr/bin/env python3
"""
cic_extractor.py

Extract flows and compute 15 features aligned to CICFlowMeterV3 for a mirror/SPAN
interface (or offline pcap). Outputs CSV to stdout and optional file.

Flow key columns: src,dst,sport,dport,proto
Feature columns (15):
  1. Fwd Header Len
  2. Protocol
  3. Init Bwd Win Byts
  4. Tot Fwd Pkts
  5. Pkt Len Max
  6. Pkt Len Mean
  7. Tot Bwd Pkts
  8. Dst Port
  9. Bwd Pkt Len Max
 10. Fwd Pkts/s
 11. Flow IAT Max
 12. TotLen Bwd Pkts
 13. TotLen Fwd Pkts
 14. Bwd Pkt Len Std
 15. Bwd Pkt Len Mean
"""

import argparse
import time
import threading
import math
import sys
from typing import Dict, Tuple

from scapy.all import sniff, IP, TCP, UDP

FEATURE_KEYS = [
    'Fwd Header Len', 'Protocol', 'Init Bwd Win Byts', 'Tot Fwd Pkts', 'Pkt Len Max',
    'Pkt Len Mean', 'Tot Bwd Pkts', 'Dst Port', 'Bwd Pkt Len Max', 'Fwd Pkts/s',
    'Flow IAT Max', 'TotLen Bwd Pkts', 'TotLen Fwd Pkts', 'Bwd Pkt Len Std',
    'Bwd Pkt Len Mean'
]


class Flow:
    def __init__(self, key: Tuple[str, str, int, int, int], first_ts: float):
        self.key = key  # (src, dst, sport, dport, proto) as forward direction
        self.start_time = first_ts
        self.last_time = first_ts
        self.fwd_pkts = 0
        self.bwd_pkts = 0
        self.tot_len_fwd = 0.0
        self.tot_len_bwd = 0.0
        self.len_all = []
        self.len_bwd = []
        self.bwd_pkt_len_max = 0.0
        self.pkt_len_max = 0.0
        self.iat_all = []
        self.fwd_header_len = 0.0
        self.init_bwd_win = None

    @staticmethod
    def _ip_len(pkt) -> int:
        ip = pkt[IP]
        if hasattr(ip, 'len') and ip.len:
            return int(ip.len)
        # fallback to decoded IP payload length
        try:
            return len(ip)
        except Exception:
            return len(pkt)

    @staticmethod
    def _header_len(pkt) -> int:
        ip = pkt[IP]
        ip_hdr = getattr(ip, 'ihl', 5) * 4  # default 20 bytes
        l4_hdr = 0
        if pkt.haslayer(TCP):
            l4_hdr = getattr(pkt[TCP], 'dataofs', 5) * 4  # default 20 bytes
        elif pkt.haslayer(UDP):
            l4_hdr = 8
        return ip_hdr + l4_hdr

    def add(self, pkt, ts: float, is_fwd: bool):
        if self.last_time is not None:
            self.iat_all.append(ts - self.last_time)
        self.last_time = ts

        ip_len = float(self._ip_len(pkt))
        self.len_all.append(ip_len)
        self.pkt_len_max = max(self.pkt_len_max, ip_len)

        hdr_len = self._header_len(pkt)

        if is_fwd:
            self.fwd_pkts += 1
            self.tot_len_fwd += ip_len
            self.fwd_header_len += hdr_len
        else:
            self.bwd_pkts += 1
            self.tot_len_bwd += ip_len
            self.len_bwd.append(ip_len)
            self.bwd_pkt_len_max = max(self.bwd_pkt_len_max, ip_len)
            if self.init_bwd_win is None and pkt.haslayer(TCP):
                try:
                    self.init_bwd_win = int(pkt[TCP].window)
                except Exception:
                    pass

    def is_expired(self, now: float, timeout: float) -> bool:
        return (now - self.last_time) > timeout

    def compute_features(self) -> Dict[str, float]:
        duration = max(self.last_time - self.start_time, 1e-6)
        flow_iat_max = max(self.iat_all) if self.iat_all else 0.0
        pkt_len_mean = sum(self.len_all) / len(self.len_all) if self.len_all else 0.0
        if len(self.len_bwd) > 1:
            mean_bwd = sum(self.len_bwd) / len(self.len_bwd)
            var_bwd = sum((x - mean_bwd) ** 2 for x in self.len_bwd) / (len(self.len_bwd) - 1)
            bwd_std = math.sqrt(var_bwd)
        else:
            mean_bwd = self.len_bwd[0] if self.len_bwd else 0.0
            bwd_std = 0.0

        fwd_pps = self.fwd_pkts / duration

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
            'Bwd Pkt Len Std': float(bwd_std),
            'Bwd Pkt Len Mean': float(mean_bwd)
        }
        return features


class CICExtractor:
    def __init__(self, iface: str, timeout: float, print_interval: float, output_path: str = None):
        self.iface = iface
        self.timeout = timeout
        self.print_interval = print_interval
        self.output_path = output_path
        self.flows: Dict[Tuple[str, str, int, int, int], Flow] = {}
        self.lock = threading.Lock()
        self.running = True
        header = ['src', 'dst', 'sport', 'dport', 'proto'] + FEATURE_KEYS
        line = ','.join(header)
        print(line)
        if self.output_path:
            with open(self.output_path, 'w') as f:
                f.write(line + '\n')

    def packet_handler(self, pkt):
        if not pkt.haslayer(IP):
            return
        ts = float(getattr(pkt, 'time', time.time()))
        ip = pkt[IP]
        proto = ip.proto
        src = ip.src
        dst = ip.dst
        sport = 0
        dport = 0
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        key = (src, dst, sport, dport, proto)
        rkey = (dst, src, dport, sport, proto)

        with self.lock:
            if key in self.flows:
                flow = self.flows[key]
                direction = True
            elif rkey in self.flows:
                flow = self.flows[rkey]
                direction = False
            else:
                flow = Flow(key, ts)
                self.flows[key] = flow
                direction = True
            flow.add(pkt, ts, is_fwd=direction)

    def flush_flow(self, key):
        flow = self.flows.pop(key, None)
        if not flow:
            return
        features = flow.compute_features()
        src, dst, sport, dport, proto = flow.key
        out = [str(src), str(dst), str(sport), str(dport), str(proto)] + [str(features[k]) for k in FEATURE_KEYS]
        line = ','.join(out)
        print(line)
        if self.output_path:
            with open(self.output_path, 'a') as f:
                f.write(line + '\n')

    def flusher_loop(self):
        while self.running:
            now = time.time()
            to_flush = []
            with self.lock:
                for k, f in list(self.flows.items()):
                    if f.is_expired(now, self.timeout):
                        to_flush.append(k)
                for k in to_flush:
                    self.flush_flow(k)
            time.sleep(self.print_interval)

    def start(self, offline: str = None):
        self.flusher = threading.Thread(target=self.flusher_loop, daemon=True)
        self.flusher.start()
        try:
            if offline:
                sniff(offline=offline, prn=self.packet_handler, store=False)
            else:
                sniff(iface=self.iface, prn=self.packet_handler, store=False,
                      stop_filter=lambda x: not self.running)
        except Exception as e:
            print(f"Error while sniffing: {e}", file=sys.stderr)
            self.running = False

    def stop(self):
        self.running = False
        with self.lock:
            for k in list(self.flows.keys()):
                self.flush_flow(k)

    def extract_offline(self, pcap_path: str, timeout: float = None) -> list:
        """Parse pcap and return list of flows with timestamp and 5-tuple.
        Returns [{
            'timestamp': <last_time>,
            'src': str, 'dst': str, 'sport': int, 'dport': int, 'proto': int,
            'features': {FEATURE_KEYS}
        }, ...]
        """
        results = []
        # Temporarily override timeout if provided
        orig_timeout = self.timeout
        if timeout is not None:
            self.timeout = timeout
        self.flows.clear()
        try:
            sniff(offline=pcap_path, prn=self.packet_handler, store=False)
        finally:
            # Flush all flows and collect
            with self.lock:
                for k, f in list(self.flows.items()):
                    feats = f.compute_features()
                    src, dst, sport, dport, proto = f.key
                    results.append({
                        'timestamp': f.last_time,
                        'src': src, 'dst': dst, 'sport': sport, 'dport': dport, 'proto': proto,
                        'features': {kk: feats[kk] for kk in FEATURE_KEYS}
                    })
                self.flows.clear()
            self.timeout = orig_timeout
        return results


def main():
    parser = argparse.ArgumentParser(description='CICFlowMeterV3-aligned extractor')
    src_group = parser.add_mutually_exclusive_group(required=True)
    src_group.add_argument('--iface', help='Interface to sniff (e.g., s1-snoop)')
    src_group.add_argument('--pcap', help='Offline pcap to read')
    parser.add_argument('--timeout', type=float, default=1.0, help='Flow inactivity timeout (s)')
    parser.add_argument('--print_interval', type=float, default=0.2, help='Flusher sleep interval (s)')
    parser.add_argument('--output', help='Optional CSV output file path')
    args = parser.parse_args()

    extractor = CICExtractor(args.iface, timeout=args.timeout, print_interval=args.print_interval, output_path=args.output)

    def handle_signal(signum, frame):
        extractor.stop()
        sys.exit(0)

    import signal
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    if args.pcap:
        extractor.start(offline=args.pcap)
        extractor.stop()
    else:
        extractor.start()


if __name__ == '__main__':
    main()

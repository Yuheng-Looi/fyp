#!/usr/bin/env python3
"""
flow_extractor.py

Capture packets on a given interface and extract flow features.

Usage:
  sudo python3 flow_extractor.py --iface s1-eth3

Features computed (15 numeric features):
  1) duration (s)
  2) total_packets
  3) total_bytes
  4) forward_packets (src->dst)
  5) backward_packets (dst->src)
  6) forward_bytes
  7) backward_bytes
  8) min_packet_size
  9) max_packet_size
 10) mean_packet_size
 11) std_packet_size
 12) pkt_rate (pkts/s)
 13) byte_rate (bytes/s)
 14) avg_inter_arrival (s)
 15) tcp_syn_count (in forward direction)

Additionally, a conversion-time column (seconds) is appended to each CSV
line, measuring the time spent constructing that CSV line (not including
packet capture itself).

Prints one CSV line per flushed flow containing: flow_key fields then 15 features.

Dependencies: scapy (pip3 install scapy)
"""

import argparse
import time
import threading
import signal
import sys
from collections import defaultdict, deque
import math

try:
    # scapy import
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
except Exception as e:
    print("Error importing scapy. Install with: pip3 install scapy", file=sys.stderr)
    raise


class Flow:
    def __init__(self, key, first_ts):
        self.key = key  # (src, dst, sport, dport, proto)
        self.start_time = first_ts
        self.last_time = first_ts
        self.pkt_count = 0
        self.byte_count = 0
        self.forward_pkt = 0
        self.backward_pkt = 0
        self.forward_bytes = 0
        self.backward_bytes = 0
        self.sizes = []
        self.ts_list = []
        self.tcp_syn_count = 0

    def add_packet(self, ts, src, dst, size, direction, flags=None):
        self.pkt_count += 1
        self.byte_count += size
        self.sizes.append(size)
        self.ts_list.append(ts)
        self.last_time = ts
        if direction == 'f':
            self.forward_pkt += 1
            self.forward_bytes += size
            if flags and 'S' in flags and 'A' not in flags:
                self.tcp_syn_count += 1
        else:
            self.backward_pkt += 1
            self.backward_bytes += size

    def is_expired(self, now, timeout):
        return (now - self.last_time) > timeout

    def compute_features(self):
        duration = max(0.0, self.last_time - self.start_time)
        total_packets = self.pkt_count
        total_bytes = self.byte_count
        fwd_pkts = self.forward_pkt
        bwd_pkts = self.backward_pkt
        fwd_bytes = self.forward_bytes
        bwd_bytes = self.backward_bytes
        if self.sizes:
            min_size = min(self.sizes)
            max_size = max(self.sizes)
            mean_size = sum(self.sizes) / len(self.sizes)
            # sample std dev
            if len(self.sizes) > 1:
                var = sum((s - mean_size) ** 2 for s in self.sizes) / (len(self.sizes) - 1)
                std_size = math.sqrt(var)
            else:
                std_size = 0.0
        else:
            min_size = max_size = mean_size = std_size = 0.0

        pkt_rate = total_packets / duration if duration > 0 else float(total_packets)
        byte_rate = total_bytes / duration if duration > 0 else float(total_bytes)

        # inter-arrival times
        avg_iat = 0.0
        if len(self.ts_list) > 1:
            deltas = [t2 - t1 for t1, t2 in zip(self.ts_list[:-1], self.ts_list[1:])]
            avg_iat = sum(deltas) / len(deltas)

        features = [
            round(duration, 6),
            total_packets,
            total_bytes,
            fwd_pkts,
            bwd_pkts,
            fwd_bytes,
            bwd_bytes,
            min_size,
            max_size,
            round(mean_size, 2),
            round(std_size, 2),
            round(pkt_rate, 3),
            round(byte_rate, 3),
            round(avg_iat, 6),
            self.tcp_syn_count,
        ]

        return features


class FlowExtractor:
    def __init__(self, iface, timeout=5.0, print_interval=1.0, output_path=None):
        # iface may be None when reading from a pcap file
        self.iface = iface
        self.timeout = timeout
        self.print_interval = print_interval
        self.output_path = output_path
        self.flows = {}
        self.lock = threading.Lock()
        self.running = True
        # CSV header
        header_fields = ['src', 'dst', 'sport', 'dport', 'proto']
        feat_names = [
            'duration', 'total_packets', 'total_bytes', 'forward_packets', 'backward_packets',
            'forward_bytes', 'backward_bytes', 'min_pkt_size', 'max_pkt_size', 'mean_pkt_size',
            'std_pkt_size', 'pkt_rate', 'byte_rate', 'avg_inter_arrival', 'tcp_syn_count',
            'convert_time'
        ]
        header_line = ','.join(header_fields + feat_names)
        # print to stdout
        print(header_line)
        # and optionally write to file (overwrite existing)
        if self.output_path:
            try:
                with open(self.output_path, 'w') as f:
                    f.write(header_line + '\n')
            except Exception as e:
                print(f"Error opening output file {self.output_path}: {e}", file=sys.stderr)
                self.output_path = None

    def packet_handler(self, pkt):
        ts = time.time()
        # Only IP packets
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        proto = ip.proto
        src = ip.src
        dst = ip.dst
        sport = 0
        dport = 0
        flags = None
        if pkt.haslayer(TCP):
            l4 = pkt[TCP]
            sport = l4.sport
            dport = l4.dport
            # flags as letters
            flags = str(l4.flags)
        elif pkt.haslayer(UDP):
            l4 = pkt[UDP]
            sport = l4.sport
            dport = l4.dport
        elif pkt.haslayer(ICMP):
            l4 = pkt[ICMP]
            # Use ICMP type/code as pseudo ports to distinguish flows
            sport = int(getattr(l4, 'type', 0))
            dport = int(getattr(l4, 'code', 0))
        else:
            # other protocols -> use 0 ports
            pass

        size = len(pkt)

        key = (src, dst, sport, dport, proto)
        rkey = (dst, src, dport, sport, proto)

        with self.lock:
            if key in self.flows:
                flow = self.flows[key]
                direction = 'f'
            elif rkey in self.flows:
                flow = self.flows[rkey]
                direction = 'b'
            else:
                flow = Flow(key, ts)
                self.flows[key] = flow
                direction = 'f'

            flow.add_packet(ts, src, dst, size, direction, flags)

    def flush_flow(self, flow_key):
        flow = self.flows.pop(flow_key, None)
        if not flow:
            return
        # Measure conversion time: building CSV fields and joining
        t0 = time.time()
        features = flow.compute_features()
        # Print CSV line: flow key + features + convert_time
        src, dst, sport, dport, proto = flow.key
        out = [str(src), str(dst), str(sport), str(dport), str(proto)] + [str(x) for x in features]
        convert_time = time.time() - t0
        out.append(f"{convert_time:.6f}")
        line = ','.join(out)
        # print to stdout
        print(line)
        # append to file if configured
        if self.output_path:
            try:
                with open(self.output_path, 'a') as f:
                    f.write(line + '\n')
            except Exception as e:
                print(f"Error writing to output file {self.output_path}: {e}", file=sys.stderr)

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

    def start(self, offline=None):
        # Start flusher thread
        self.flusher = threading.Thread(target=self.flusher_loop, daemon=True)
        self.flusher.start()

        # Start sniffing (blocking)
        try:
            if offline:
                sniff(offline=offline, prn=self.packet_handler, store=False)
            else:
                sniff(iface=self.iface, prn=self.packet_handler, store=False)
        except Exception as e:
            print(f"Error while sniffing on {self.iface}: {e}", file=sys.stderr)
            self.running = False

    def stop(self):
        self.running = False
        # flush all flows
        with self.lock:
            keys = list(self.flows.keys())
            for k in keys:
                self.flush_flow(k)


def main():
    parser = argparse.ArgumentParser(description='Flow extractor - capture flows and compute features')
    src_group = parser.add_mutually_exclusive_group(required=True)
    src_group.add_argument('--iface', help='Interface to sniff on (e.g. s1-eth3)')
    src_group.add_argument('--pcap', help='PCAP file to read instead of a live interface')
    parser.add_argument('--timeout', type=float, default=0.2, help='Flow inactivity timeout in seconds')
    parser.add_argument('--print_interval', type=float, default=0.05, help='Flusher loop sleep interval')
    parser.add_argument('--output', help='Optional CSV output file path; if set, write header and lines there')
    args = parser.parse_args()

    extractor = FlowExtractor(args.iface, timeout=args.timeout, print_interval=args.print_interval, output_path=args.output)

    def handle_sigint(signum, frame):
        extractor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    # Live interface or offline pcap
    if args.pcap:
        extractor.start(offline=args.pcap)
        # After offline processing, ensure remaining flows are flushed
        extractor.stop()
    else:
        extractor.start()


if __name__ == '__main__':
    main()
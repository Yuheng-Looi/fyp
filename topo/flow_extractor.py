#!/usr/bin/env python3
"""
flow_extractor.py
Real-time flow feature extractor using Scapy.

Outputs CSV with 5-tuple + requested 15 features when flow ends or times out.

Run:
  sudo python3 flow_extractor.py -i enp5s0 -o /tmp/flows.csv --timeout 60
"""

import argparse
import csv
import time
import threading
from scapy.all import sniff, IP, IPv6, TCP, UDP
from collections import defaultdict, deque

# --- Configuration defaults ---
INACTIVITY_TIMEOUT = 60   # seconds; flush flows idle for this long
FLUSH_INTERVAL = 5        # seconds; background thread checks for timeouts

# --- Helper functions ---
def now_ts():
    return time.time()

def make_key(pkt):
    """Return canonical 5-tuple key (src,dst, sport, dport, proto) using IP layer."""
    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip is None:
        return None
    proto = ip.proto if hasattr(ip, 'proto') else (pkt.getlayer(TCP) and 6) or (pkt.getlayer(UDP) and 17) or 0
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    else:
        sport = 0; dport = 0
    # Use tuple normalized such that the first-seen direction is 'forward' -
    # we will set forward on first packet; for key we keep the raw tuple
    return (ip.src, ip.dst, sport, dport, proto)

# --- Flow state structure ---
class FlowState:
    def __init__(self, first_pkt, ts):
        # 5-tuple direction based on first packet
        self.first_pkt = first_pkt
        self.first_ts = ts
        self.last_ts = ts
        # id fields
        ip = first_pkt.getlayer(IP) or first_pkt.getlayer(IPv6)
        self.src = ip.src
        self.dst = ip.dst
        if first_pkt.haslayer(TCP):
            self.sport = first_pkt[TCP].sport
            self.dport = first_pkt[TCP].dport
            self.proto = 6
        elif first_pkt.haslayer(UDP):
            self.sport = first_pkt[UDP].sport
            self.dport = first_pkt[UDP].dport
            self.proto = 17
        else:
            self.sport = 0; self.dport = 0; self.proto = ip.proto if hasattr(ip,'proto') else 0

        # Counters
        self.fwd_pkts = 0
        self.bwd_pkts = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0

        # Packet length stats (per direction)
        self.fwd_pkt_len_sum = 0
        self.fwd_pkt_len_count = 0
        self.fwd_pkt_len_max = 0

        self.bwd_pkt_len_sum = 0
        self.bwd_pkt_len_count = 0
        self.bwd_pkt_len_max = 0

        # Header length stats (forward)
        self.fwd_header_len_sum = 0
        self.fwd_header_len_count = 0
        self.fwd_header_len_max = 0

        # IAT (inter-arrival time) stats per direction (seconds)
        self.prev_fwd_ts = None
        self.fwd_iat_min = None
        self.fwd_iat_sum = 0
        self.fwd_iat_count = 0

        self.prev_bwd_ts = None
        self.bwd_iat_min = None
        self.bwd_iat_sum = 0
        self.bwd_iat_count = 0
        self.bwd_iat_total = 0  # same as sum, kept for direct name match

        # Overall flow IAT
        self.prev_overall_ts = None
        self.flow_iat_min = None
        self.flow_iat_max = None

        # Init backward window bytes (from SYN+ACK if any)
        self.init_bwd_win_bytes = 0
        self.seen_syn = False
        self.seen_synack = False

        # Flags to detect termination
        self.terminated = False

    def update_on_packet(self, pkt, ts):
        """Update flow stats for the incoming packet. Determine direction
           by comparing pkt src/dst to first_pkt src/dst (forward = same as first src)."""
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip is None:
            return
        is_forward = (ip.src == self.src and ip.dst == self.dst and
                      ((pkt.haslayer(TCP) and pkt[TCP].sport == self.sport) or not pkt.haslayer(TCP)))
        plen = len(pkt)
        # header length estimate: IP.ihl*4 + transport header
        ip_hdr_len = getattr(ip, 'ihl', None)
        if ip_hdr_len is not None:
            ip_hdr_len = ip_hdr_len * 4
        else:
            ip_hdr_len = 20  # default guess

        trans_hdr_len = 0
        if pkt.haslayer(TCP):
            # TCP data offset in 32-bit words: dataofs
            doff = getattr(pkt[TCP], 'dataofs', None)
            trans_hdr_len = (doff * 4) if doff else 20
        elif pkt.haslayer(UDP):
            trans_hdr_len = 8
        header_len = ip_hdr_len + trans_hdr_len

        # update last timestamp
        self.last_ts = ts

        # overall IAT
        if self.prev_overall_ts is not None:
            iat = ts - self.prev_overall_ts
            if self.flow_iat_min is None or iat < self.flow_iat_min:
                self.flow_iat_min = iat
            if self.flow_iat_max is None or iat > self.flow_iat_max:
                self.flow_iat_max = iat
        self.prev_overall_ts = ts

        # update direction-specific
        if is_forward:
            self.fwd_pkts += 1
            self.fwd_bytes += plen
            # pkt len stats
            self.fwd_pkt_len_sum += plen
            self.fwd_pkt_len_count += 1
            if plen > self.fwd_pkt_len_max:
                self.fwd_pkt_len_max = plen
            # header stats
            self.fwd_header_len_sum += header_len
            self.fwd_header_len_count += 1
            if header_len > self.fwd_header_len_max:
                self.fwd_header_len_max = header_len
            # fwd IAT
            if self.prev_fwd_ts is not None:
                iatf = ts - self.prev_fwd_ts
                if self.fwd_iat_min is None or iatf < self.fwd_iat_min:
                    self.fwd_iat_min = iatf
                self.fwd_iat_sum += iatf
                self.fwd_iat_count += 1
            self.prev_fwd_ts = ts
        else:
            # backward direction
            self.bwd_pkts += 1
            self.bwd_bytes += plen
            self.bwd_pkt_len_sum += plen
            self.bwd_pkt_len_count += 1
            if plen > self.bwd_pkt_len_max:
                self.bwd_pkt_len_max = plen
            # bwd IAT
            if self.prev_bwd_ts is not None:
                iatb = ts - self.prev_bwd_ts
                if self.bwd_iat_min is None or iatb < self.bwd_iat_min:
                    self.bwd_iat_min = iatb
                self.bwd_iat_sum += iatb
                self.bwd_iat_total += iatb
                self.bwd_iat_count += 1
            self.prev_bwd_ts = ts

        # TCP-specific: record initial bwd window from SYN+ACK
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            # if we saw an initial SYN (outgoing), mark
            if flags & 0x02:  # SYN
                # If it's the FIRST packet and SYN, mark seen_syn
                self.seen_syn = True
            # check for SYN-ACK from responder (backward direction)
            if (flags & 0x12) == 0x12:  # SYN+ACK
                # record responder window
                w = getattr(pkt[TCP], 'window', 0)
                if w:
                    self.init_bwd_win_bytes = w
                    self.seen_synack = True

        # termination if FIN or RST observed in either direction
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if (flags & 0x01) != 0:  # FIN
                self.terminated = True
            if (flags & 0x04) != 0:  # RST
                self.terminated = True

    def compute_features(self):
        """Return a dict of computed features (15 requested)."""
        duration = max(0.000001, self.last_ts - self.first_ts)  # avoid zero
        total_pkts = self.fwd_pkts + self.bwd_pkts
        # Flow Pkts/s
        flow_pkts_per_s = total_pkts / duration if duration > 0 else 0.0

        # Fwd Header Len: mean (use average)
        fwd_header_len_mean = (self.fwd_header_len_sum / self.fwd_header_len_count) if self.fwd_header_len_count else 0.0

        # Pkt Len Max (overall)
        pkt_len_max = max(self.fwd_pkt_len_max, self.bwd_pkt_len_max)

        # Init Bwd Win Bytes
        init_bwd_win = self.init_bwd_win_bytes

        # Tot Fwd Pkts
        tot_fwd_pkts = self.fwd_pkts
        # Bwd IAT Min
        bwd_iat_min = self.bwd_iat_min if self.bwd_iat_min is not None else 0.0

        # Pkt Len Mean (overall)
        pkt_len_mean = 0.0
        total_pkt_len_count = self.fwd_pkt_len_count + self.bwd_pkt_len_count
        if total_pkt_len_count:
            pkt_len_mean = (self.fwd_pkt_len_sum + self.bwd_pkt_len_sum) / total_pkt_len_count

        # Tot Bwd Pkts
        tot_bwd_pkts = self.bwd_pkts

        # Flow IAT Max/Min
        flow_iat_max = self.flow_iat_max if self.flow_iat_max is not None else 0.0
        flow_iat_min = self.flow_iat_min if self.flow_iat_min is not None else 0.0

        # Bwd Pkt Len Max/Mean
        bwd_pkt_len_max = self.bwd_pkt_len_max
        bwd_pkt_len_mean = (self.bwd_pkt_len_sum / self.bwd_pkt_len_count) if self.bwd_pkt_len_count else 0.0

        # Dst Port
        dst_port = self.dport

        # Bwd IAT Tot
        bwd_iat_tot = self.bwd_iat_sum

        res = {
            "src_ip": self.src,
            "dst_ip": self.dst,
            "src_port": self.sport,
            "dst_port": dst_port,
            "proto": self.proto,
            "duration": duration,
            "Flow Pkts/s": flow_pkts_per_s,
            "Fwd Header Len": fwd_header_len_mean,
            "Protocol": self.proto,
            "Pkt Len Max": pkt_len_max,
            "Init Bwd Win Byts": init_bwd_win,
            "Tot Fwd Pkts": tot_fwd_pkts,
            "Bwd IAT Min": bwd_iat_min,
            "Pkt Len Mean": pkt_len_mean,
            "Tot Bwd Pkts": tot_bwd_pkts,
            "Flow IAT Max": flow_iat_max,
            "Bwd Pkt Len Max": bwd_pkt_len_max,
            "Flow IAT Min": flow_iat_min,
            "Bwd Pkt Len Mean": bwd_pkt_len_mean,
            "Dst Port": dst_port,
            "Bwd IAT Tot": bwd_iat_tot
        }
        return res

# --- Flow table and global locks ---
flows = dict()
flows_lock = threading.Lock()

# CSV header
CSV_FIELDS = [
    "ts", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "duration",
    "Flow Pkts/s", "Fwd Header Len", "Protocol", "Pkt Len Max",
    "Init Bwd Win Byts", "Tot Fwd Pkts", "Bwd IAT Min", "Pkt Len Mean",
    "Tot Bwd Pkts", "Flow IAT Max", "Bwd Pkt Len Max", "Flow IAT Min",
    "Bwd Pkt Len Mean", "Dst Port", "Bwd IAT Tot"
]

# --- Background flush thread (flush idle flows) ---
def flush_idle_flows(output_csv, timeout):
    while True:
        now = now_ts()
        to_flush = []
        with flows_lock:
            for k, fs in list(flows.items()):
                if fs.terminated or (now - fs.last_ts) > timeout:
                    to_flush.append((k, fs))
                    del flows[k]
        if to_flush:
            with open(output_csv, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                for k, fs in to_flush:
                    row = fs.compute_features()
                    row_out = {"ts": now}
                    row_out.update(row)
                    writer.writerow(row_out)
                    print(f"[FLUSH] {row_out['src_ip']}:{row_out['src_port']} -> {row_out['dst_ip']}:{row_out['dst_port']} proto={row_out['Protocol']} duration={row_out['duration']:.3f}")
        time.sleep(FLUSH_INTERVAL)

# --- Packet callback ---
def pkt_callback(pkt):
    ts = now_ts()
    key = make_key(pkt)
    if key is None:
        return
    # Use directioned key (raw tuple). But map to flow state keyed by that tuple.
    with flows_lock:
        fs = flows.get(key)
        if fs is None:
            fs = FlowState(pkt, ts)
            flows[key] = fs
        fs.update_on_packet(pkt, ts)
        # flush immediately if terminated
        if fs.terminated:
            # remove and write
            del flows[key]
            row = fs.compute_features()
            row_out = {"ts": ts}
            row_out.update(row)
            with open(args.output, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                writer.writerow(row_out)
            print(f"[END] {row_out['src_ip']}:{row_out['src_port']} -> {row_out['dst_ip']}:{row_out['dst_port']} proto={row_out['Protocol']} duration={row_out['duration']:.3f}")

# --- Main runner ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--iface', required=True, help='interface to sniff (mirrored port)')
    parser.add_argument('-o', '--output', required=True, help='output CSV file')
    parser.add_argument('--timeout', type=int, default=INACTIVITY_TIMEOUT, help='inactivity timeout (s)')
    parser.add_argument('--bpf', default='', help='optional BPF filter')
    args = parser.parse_args()

    # initialize CSV with header
    with open(args.output, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()

    # start flush thread
    t = threading.Thread(target=flush_idle_flows, args=(args.output, args.timeout), daemon=True)
    t.start()

    print("Starting sniff on", args.iface, "— output:", args.output)
    sniff(iface=args.iface, prn=pkt_callback, store=False, filter=args.bpf)
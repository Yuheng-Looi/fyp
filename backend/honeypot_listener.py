import datetime
import os
import sys

try:
    from scapy.all import sniff, IP
except ImportError as e:
    sys.stderr.write(f"Scapy import error: {e}\n")
    sys.exit(1)

log_path = "/home/fyp2025/fyp/backend/honeypot.log"

def packet_callback(pkt):
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_num = ip_layer.proto
        
        # Resolve protocol
        if proto_num == 6:
            protocol = "TCP"
        elif proto_num == 17:
            protocol = "UDP"
        elif proto_num == 1:
            protocol = "ICMP"
        else:
            protocol = str(proto_num)
            
        timestamp = datetime.datetime.now().isoformat()
        log_line = f"{timestamp}, {src_ip}, {dst_ip}, {protocol}\n"
        
        try:
            with open(log_path, "a") as f:
                f.write(log_line)
                f.flush()
        except Exception as e:
            sys.stderr.write(f"Error writing to honeypot.log: {e}\n")

if __name__ == "__main__":
    # Ensure directory exists
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    
    # Touch or clear the log file on launch
    try:
        with open(log_path, "w") as f:
            f.write("")
    except Exception as e:
        sys.stderr.write(f"Error initializing log file: {e}\n")
        sys.exit(1)
        
    sys.stdout.write(f"Honeypot listener started. Logging to {log_path}...\n")
    sys.stdout.flush()
    # Sniff on h99-eth0
    sniff(iface="h99-eth0", prn=packet_callback, store=0)

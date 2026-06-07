import time

class NormalTrafficGenerator:
    def __init__(self):
        self.net = None
        self.started = False

    def start(self, net=None):
        if not net:
            print("[traffic] No network to start traffic generator")
            return
        self.net = net
        self.started = True
        print("[traffic] Normal traffic started")

        hosts = list(net.hosts)
        
        # Servers are h2 and h3
        servers = [h for h in hosts if h.name in ("h2", "h3")]
        # Clients are other hosts (h1 in small, h1, h4, h5, h6 in large)
        clients = [h for h in hosts if h.name not in ("h2", "h3")]

        # Start iperf3 servers on h2 and h3
        for s in servers:
            s.cmd("iperf3 -s -D")

        # Start iperf3 clients sending traffic to the servers
        for c in clients:
            for s in servers:
                s_ip = s.IP()
                # Limit bandwidth to 500K to prevent crushing the network
                c.cmd(f"iperf3 -c {s_ip} -b 500K -t 300 -D")

    def stop(self):
        if not self.net:
            return
        print("[traffic] Normal traffic stopped")
        for h in self.net.hosts:
            h.cmd("pkill -9 iperf3")
        self.started = False

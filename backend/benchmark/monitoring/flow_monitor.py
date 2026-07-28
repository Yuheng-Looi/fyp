import os
import time


class FlowMonitor:
    def __init__(self):
        self.net = None
        self.running = False
        self.history = []
        self._last_bytes = {}
        self._last_time = None

    def start(self, net=None):
        self.net = net
        self.running = True
        self.history = []
        self._last_bytes = {}
        self._last_time = time.monotonic()
        print("[monitor] Flow monitor started")

    def stop(self):
        self.running = False
        print("[monitor] Flow monitor stopped")

    def _read_tx_bytes(self, client_host):
        pid = getattr(client_host, "pid", None)
        if pid:
            path = f"/proc/{pid}/root/sys/class/net/{client_host.name}-eth0/statistics/tx_bytes"
            if os.path.exists(path):
                try:
                    with open(path, "r") as f:
                        return int(f.read().strip())
                except Exception:
                    pass
        return 0

    def tick(self, elapsed, phase):
        if not self.running or not self.net:
            return

        now = time.monotonic()
        dt = max(0.001, now - self._last_time) if self._last_time else 1.0

        # Separate client hosts into Attacker Hosts (h1) and Benign User Hosts (h2)
        attacker_hosts = [h for h in self.net.hosts if h.name in ("h1",)]
        benign_hosts = [h for h in self.net.hosts if h.name in ("h2", "h4")]

        throughput = {}
        benign_throughput = {}
        attack_offered_bps = 0.0

        # Attacker Offered Load (h1)
        for a in attacker_hosts:
            curr = self._read_tx_bytes(a)
            prev = self._last_bytes.get(a.name, curr)
            rate = max(0, curr - prev) / dt
            self._last_bytes[a.name] = curr
            throughput[a.name] = rate
            attack_offered_bps += rate

        # Benign User Throughput (h2)
        for b in benign_hosts:
            curr = self._read_tx_bytes(b)
            prev = self._last_bytes.get(b.name, curr)
            rate = max(0, curr - prev) / dt
            self._last_bytes[b.name] = curr
            throughput[b.name] = rate
            benign_throughput[b.name] = rate

        self._last_time = now

        self.history.append({
            "elapsed": elapsed,
            "phase": phase,
            "throughput": throughput,
            "benign_throughput": benign_throughput,
            "attack_offered_bps": attack_offered_bps,
        })

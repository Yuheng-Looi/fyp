import time

class QosMonitor:
    def __init__(self):
        self.net = None
        self.running = False
        self.history = []  # list of dicts: {"elapsed": elapsed, "phase": phase, "throughput": {server: bytes/sec}}
        self._last_bytes = {}
        self._last_time = None

    def start(self, net=None):
        self.net = net
        self.running = True
        self.history = []
        self._last_bytes = {}
        self._last_time = time.monotonic()
        print("[monitor] QoS monitor started")

    def stop(self):
        self.running = False
        print("[monitor] QoS monitor stopped")

    def tick(self, elapsed, phase):
        if not self.running or not self.net:
            return
        
        now = time.monotonic()
        servers = [h for h in self.net.hosts if h.name in ("h2", "h3")]
        current_bytes = {}
        for s in servers:
            try:
                intf = f"{s.name}-eth0"
                out = s.cmd(f"cat /sys/class/net/{intf}/statistics/rx_bytes").strip()
                if not out.isdigit():
                    out = s.cmd("cat /sys/class/net/eth0/statistics/rx_bytes").strip()
                current_bytes[s.name] = int(out) if out.isdigit() else 0
            except Exception:
                current_bytes[s.name] = 0

        throughput = {}
        if self._last_time is not None:
            dt = now - self._last_time
            if dt > 0:
                for name in current_bytes:
                    prev = self._last_bytes.get(name, 0)
                    curr = current_bytes[name]
                    diff = max(0, curr - prev)
                    throughput[name] = diff / dt

        self._last_bytes = current_bytes
        self._last_time = now

        self.history.append({
            "elapsed": elapsed,
            "phase": phase,
            "throughput": throughput
        })

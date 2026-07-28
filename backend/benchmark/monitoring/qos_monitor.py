import os
import time


class QosMonitor:
    def __init__(self):
        self.net = None
        self.running = False
        self.history = []
        self._last_bytes = {}
        self._last_time = None
        self.link_capacity_bps = 2_560_000.0  # 20 Mbps limit (2.56 MB/s)

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

    def _read_sysfs(self, path):
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    content = f.read().strip()
                    if content.isdigit():
                        return int(content)
            except Exception:
                pass
        return 0

    def tick(self, elapsed, phase):
        if not self.running or not self.net:
            return

        now = time.monotonic()
        dt = max(0.001, now - self._last_time) if self._last_time else 1.0

        # 1. Switch-to-Server Bottleneck Link (s1-eth3 TX in Small topology, s2-eth2 in Large)
        sw_path = "/sys/class/net/s1-eth3/statistics/tx_bytes"
        if not os.path.exists(sw_path):
            sw_path = "/sys/class/net/s2-eth2/statistics/tx_bytes"
        if not os.path.exists(sw_path):
            sw_path = "/sys/class/net/s1-eth2/statistics/tx_bytes"

        curr_sw_tx = self._read_sysfs(sw_path)
        prev_sw_tx = self._last_bytes.get("sw_bottleneck_tx", curr_sw_tx)
        bottleneck_delivered_bps = max(0, curr_sw_tx - prev_sw_tx) / dt
        self._last_bytes["sw_bottleneck_tx"] = curr_sw_tx

        # 2. Target Server RX interface (h3-eth0 in Small topology, h5/h6 in Large)
        target_host = self.net.get("h3") if "h3" in self.net else (self.net.get("h5") if "h5" in self.net else None)
        curr_server_rx = 0
        if target_host and hasattr(target_host, "pid") and target_host.pid:
            curr_server_rx = self._read_sysfs(f"/proc/{target_host.pid}/root/sys/class/net/{target_host.name}-eth0/statistics/rx_bytes")
        prev_server_rx = self._last_bytes.get("target_server_rx", curr_server_rx)
        server_received_bps = max(0, curr_server_rx - prev_server_rx) / dt
        self._last_bytes["target_server_rx"] = curr_server_rx

        # 3. Bottleneck utilization percentage based strictly on delivered bottleneck bytes
        utilization_pct = min(100.0, (bottleneck_delivered_bps / self.link_capacity_bps) * 100.0)

        throughput_map = {
            target_host.name if target_host else "server": server_received_bps,
            "bottleneck": bottleneck_delivered_bps,
        }

        self._last_time = now

        self.history.append({
            "elapsed": elapsed,
            "phase": phase,
            "throughput": throughput_map,
            "bottleneck_delivered_bps": bottleneck_delivered_bps,
            "server_received_bps": server_received_bps,
            "bottleneck_utilization_pct": utilization_pct,
        })

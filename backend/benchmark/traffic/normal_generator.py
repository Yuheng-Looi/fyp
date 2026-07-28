"""
normal_generator.py — Reliable benign traffic generation for benchmarks.

Generates sustained benign service traffic (iperf3 + HTTP) from designated BENIGN USER hosts.
Attacker hosts (h1) are strictly excluded from benign user generation.
"""

import subprocess
import time


class NormalTrafficGenerator:
    def __init__(self):
        self.net = None
        self.started = False
        self._server_procs = []   # iperf3 server processes
        self._client_procs = []   # iperf3 client + HTTP traffic processes
        self._all_procs = []      # all tracked processes

    def start(self, net=None):
        """Start sustained benign traffic from Benign User hosts to Target Servers."""
        if not net:
            print("[traffic] No network to start traffic generator")
            return
        self.net = net
        self.started = True
        self._server_procs = []
        self._client_procs = []
        self._all_procs = []

        hosts = list(net.hosts)

        # Target Servers & Benign Users based on topology scale
        servers = [h for h in hosts if h.name.startswith("ws") or h.name.startswith("db") or h.name in ("h3", "h5", "h6")]
        clients = [h for h in hosts if h.name.startswith("usr") or h.name in ("h2", "h3", "h4") if h not in servers]

        # Benign traffic bandwidth target: 40% link capacity (1,000 KB/s Small vs 2,500 KB/s Large)
        is_large = len(hosts) > 20
        target_bandwidth_kbps = 2500.0 if is_large else 1000.0
        n_pairs = max(1, len(clients) * len(servers))
        iperf_rate_kbps = max(50.0, (target_bandwidth_kbps * 8.0) / float(n_pairs))  # in Kbps

        print(f"[traffic] Starting benign traffic: servers={[s.name for s in servers]}, "
              f"benign_users={[c.name for c in clients]} (Target Bandwidth: {target_bandwidth_kbps} KB/s)")

        # ---------------------------------------------------------------
        # 1. Start iperf3 servers on target server hosts
        # ---------------------------------------------------------------
        for s in servers:
            s.cmd("pkill -9 iperf3 2>/dev/null || true")
            time.sleep(0.1)

            proc = s.popen(
                ["iperf3", "-s", "-p", "5201"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            self._server_procs.append({"host": s.name, "proc": proc, "cmd": "iperf3 -s -p 5201", "role": "server"})
            self._all_procs.append({"host": s.name, "proc": proc, "role": "server"})

        time.sleep(0.5)

        # ---------------------------------------------------------------
        # 2. Start iperf3 clients from benign user hosts to target servers
        # ---------------------------------------------------------------
        for c in clients:
            for s in servers:
                s_ip = s.IP()
                rate_str = f"{int(iperf_rate_kbps)}K"
                cmd = ["iperf3", "-c", s_ip, "-p", "5201", "-b", rate_str, "-t", "300", "--forceflush"]
                proc = c.popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                cmd_str = f"iperf3 -c {s_ip} -p 5201 -b {rate_str} -t 300"
                self._client_procs.append({"host": c.name, "proc": proc, "cmd": cmd_str, "role": "client"})
                self._all_procs.append({"host": c.name, "proc": proc, "role": "client"})

        # ---------------------------------------------------------------
        # 3. Start deterministic HTTP request loops from benign user hosts
        # ---------------------------------------------------------------
        for c in clients:
            for s in servers:
                s_ip = s.IP()
                http_cmd = (
                    f"bash -c 'while true; do "
                    f"curl -s -o /dev/null -w \"%{{http_code}}\" --max-time 1 http://{s_ip}:8080/index.html 2>/dev/null; "
                    f"sleep 0.5; done'"
                )
                proc = c.popen(
                    http_cmd,
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self._client_procs.append({"host": c.name, "proc": proc, "cmd": f"curl loop -> {s_ip}:8080/index.html", "role": "http"})
                self._all_procs.append({"host": c.name, "proc": proc, "role": "http"})

        time.sleep(0.5)

    def stop(self):
        """Stop all benign traffic processes and clean up."""
        if not self.net:
            return
        print("[traffic] Stopping benign traffic...")

        for rec in self._all_procs:
            proc = rec.get("proc")
            if proc is None:
                continue
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=1)
            except Exception as e:
                print(f"[traffic] Error stopping {rec['role']} on {rec['host']}: {e}")

        for h in self.net.hosts:
            try:
                h.cmd("pkill -9 iperf3 2>/dev/null || true")
                h.cmd("pkill -9 -f 'while true; do curl' 2>/dev/null || true")
            except Exception:
                pass

        self._server_procs = []
        self._client_procs = []
        self._all_procs = []
        self.started = False
        print("[traffic] Benign traffic stopped and cleaned up")

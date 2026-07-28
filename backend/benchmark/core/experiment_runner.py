import os
import sys
import time
import subprocess

BENCHMARK_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BENCHMARK_DIR not in sys.path:
    sys.path.insert(0, BENCHMARK_DIR)

from core.timeline_manager import TimelineManager as BenchmarkTimeline
from core.state_manager import StateManager
from monitoring.asset_monitor import AssetMonitor
from monitoring.qos_monitor import QosMonitor
from monitoring.flow_monitor import FlowMonitor
from evaluation.scoring_engine import ScoringEngine
from traffic.normal_generator import NormalTrafficGenerator
from traffic.attack_generator import AttackGenerator


class ExperimentRunner:
    def __init__(
        self,
        config_path,
        scenario_path,
        controller_path=None,
        topology_name="small",
        real_time=None,
    ):
        self._config_path = config_path
        self._scenario_path = scenario_path
        self._controller_path = controller_path
        self._topology_name = topology_name
        self._real_time_override = real_time

        self._config = self._load_yaml(config_path)
        self._scenario = self._load_yaml(scenario_path)

        self._timeline = BenchmarkTimeline(config_path)
        self._state_manager = StateManager()

        self._asset_monitor = AssetMonitor(self._state_manager, self._config)
        self._qos_monitor = QosMonitor()
        self._flow_monitor = FlowMonitor()
        self._scoring = ScoringEngine()

        self._normal_traffic = NormalTrafficGenerator()
        self._attack = AttackGenerator()

        self._ryu_process = None
        self._infer_process = None
        self._infer_log_file = None
        self._net = None
        self._topology_module = None

        self._current_phase = None
        self._asset_states_history = []

        self._register_callbacks()

    def run(self):
        real_time = self._resolve_real_time()

        try:
            self._setup_network()
            self._timeline.run(real_time=real_time)
            scores = self._scoring.get_scores()
            scores["probe_history"] = self._asset_monitor.probe_history
            scores["qos_history"] = self._qos_monitor.history
            scores["flow_history"] = self._flow_monitor.history
            return scores
        except Exception as exc:
            print(f"[error] Experiment failed: {exc}")
            raise
        finally:
            self._teardown_network()

    def _resolve_real_time(self):
        if self._real_time_override is not None:
            return self._real_time_override
        return bool(self._config.get("mode", {}).get("real_time", False))

    def _register_callbacks(self):
        self._timeline.register("on_phase_start", self._on_phase_start)
        self._timeline.register("on_phase_end", self._on_phase_end)
        self._timeline.register("on_tick", self._on_tick)

        self._timeline.register("on_warmup_start", lambda _: self._normal_traffic.start(self._net))
        self._timeline.register("on_baseline_start", lambda _: self._start_monitors())
        self._timeline.register("on_attack_start", lambda _: self._attack.start_attack(self._scenario, net=self._net))
        self._timeline.register("on_attack_end", lambda _: self._attack.stop_attack())
        self._timeline.register("on_recovery_end", lambda _: (self._stop_monitors(), self._normal_traffic.stop()))
        self._timeline.register("on_evaluation_start", lambda _: self._scoring.evaluate(
            self._asset_states_history, self._qos_monitor.history, self._flow_monitor.history,
            probe_history=self._asset_monitor.probe_history,
            scenario_name=self._scenario.get("name", "ddos"),
            controller_name="controller_4" if "controller_4" in str(self._controller_path) else "simple_switch_13"
        ))

    def _on_phase_start(self, phase, elapsed):
        self._current_phase = phase
        print(f"[timeline] {phase} start at {int(elapsed)}s")

    def _on_phase_end(self, phase, elapsed):
        print(f"[timeline] {phase} end at {int(elapsed)}s")

    def _on_tick(self, elapsed):
        if not self._current_phase:
            return

        if self._should_use_network():
            self._qos_monitor.tick(elapsed, self._current_phase)
            self._flow_monitor.tick(elapsed, self._current_phase)

        assets = [a["name"] for a in self._config.get("monitoring", {}).get("assets", [])]
        states = {asset: self._state_manager.get_asset_state(asset, "ACTIVE") for asset in assets}
        self._asset_states_history.append({
            "elapsed": elapsed,
            "phase": self._current_phase,
            "states": states
        })

    def _start_monitors(self):
        if not self._should_use_network():
            return
        self._asset_monitor.start()
        self._qos_monitor.start(self._net)
        self._flow_monitor.start(self._net)

    def _stop_monitors(self):
        if not self._should_use_network():
            return
        self._asset_monitor.stop()
        self._qos_monitor.stop()
        self._flow_monitor.stop()

    def _setup_network(self):
        if not self._should_use_network():
            print("[setup] Dry-run mode: skipping Mininet/Ryu setup")
            return

        if self._controller_path and "controller_4" in self._controller_path:
            self._start_infer_server()

        self._start_ryu_controller()
        self._net = self._build_topology()
        self._net.start()
        self._net.staticArp()
        self._configure_monitor_host()
        self._start_asset_services()
        self._prewarm_forwarding_rules()

    def _prewarm_forwarding_rules(self):
        """Pre-warm ARP caches and install normal OpenFlow forwarding rules in switch table.
        
        Executes ping and HTTP requests between hosts and target server (10.0.0.3)
        to populate switch MAC learning tables BEFORE the attack phase starts.
        """
        print("[setup] Pre-warming network forwarding rules and ARP caches...")
        time.sleep(1.0)
        if not self._net:
            return
        hosts = self._net.hosts
        server_ip = "10.0.0.3"
        for h in hosts:
            if h.IP() != server_ip:
                h.cmd(f"ping -c 2 {server_ip} 2>/dev/null || true")
                h.cmd(f"curl -s -o /dev/null -m 2 http://{server_ip}:8080/ 2>/dev/null || true")
        time.sleep(1.0)
        print("[setup] Network pre-warming complete. Forwarding rules established.")

    def _teardown_network(self):
        try:
            self._attack.stop_attack()
        except Exception:
            pass
        try:
            self._normal_traffic.stop()
        except Exception:
            pass

        if self._net is not None:
            for h in self._net.hosts:
                try:
                    h.cmd("pkill -9 hping3 2>/dev/null || true")
                    h.cmd("pkill -9 iperf3 2>/dev/null || true")
                    h.cmd("pkill -9 -f 'while true' 2>/dev/null || true")
                except Exception:
                    pass
            self._net.stop()
            self._net = None

        if self._ryu_process is not None:
            self._ryu_process.terminate()
            try:
                stdout, _ = self._ryu_process.communicate(timeout=5)
                if stdout:
                    print("\n--- RYU CONTROLLER LOG ---")
                    print(stdout.strip())
                    print("--------------------------\n")
            except Exception as e:
                self._ryu_process.kill()
                print(f"Error reading Ryu stdout: {e}")
            self._ryu_process = None

        self._stop_infer_server()

        print("[teardown] Network teardown complete")

    def _start_infer_server(self):
        backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        infer_script = os.path.join(backend_dir, "infer_server.py")

        if not os.path.exists(infer_script):
            raise RuntimeError(f"Inference server not found: {infer_script}")

        fypenv_python = os.path.join(backend_dir, "fypenv", "bin", "python")
        if os.path.exists(fypenv_python):
            python_bin = fypenv_python
        else:
            python_bin = sys.executable

        print(f"[setup] Starting inference server: {infer_script}")
        env = os.environ.copy()
        env["PYTHONPATH"] = backend_dir

        log_path = "/tmp/infer_server.log"
        log_file = open(log_path, "w")
        self._infer_log_file = log_file

        cmd = [python_bin, infer_script]
        self._infer_process = subprocess.Popen(
            cmd,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            cwd=backend_dir,
            env=env,
        )

        time.sleep(3.0)

        if self._infer_process.poll() is not None:
            log_file.close()
            with open(log_path, "r") as f:
                content = f.read()
            raise RuntimeError(f"Inference server failed to start: {content[:500]}")

        print(f"[setup] Inference server running (PID {self._infer_process.pid})")

    def _stop_infer_server(self):
        if self._infer_process is not None:
            print("[teardown] Stopping inference server...")
            self._infer_process.terminate()
            try:
                self._infer_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._infer_process.kill()
            self._infer_process = None

        if self._infer_log_file is not None:
            try:
                self._infer_log_file.close()
            except Exception:
                pass
            self._infer_log_file = None

    def _start_ryu_controller(self):
        if not self._controller_path:
            print("[setup] No controller path specified, using default L2 switch")
            return

        ryu_bin = "/home/fyp2025/fyp/backend/benchmark/benchmarkenv/bin/ryu-manager"
        if not os.path.exists(ryu_bin):
            ryu_bin = "/home/fyp2025/fyp/backend/fypenv/bin/ryu-manager"
        if not os.path.exists(ryu_bin):
            ryu_bin = "ryu-manager"

        cmd = [
            ryu_bin,
            "--ofp-tcp-listen-port",
            "6653",
            self._controller_path,
        ]
        print(f"[setup] Launching Ryu controller: {' '.join(cmd)}")
        self._ryu_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        time.sleep(3.0)

        if self._ryu_process.poll() is not None:
            out, _ = self._ryu_process.communicate()
            raise RuntimeError(f"Ryu controller failed to start: {out}")

    def _build_topology(self):
        topo_name = self._topology_name.lower()
        if topo_name == "small":
            import topology.small as topo
        elif topo_name == "large":
            import topology.large as topo
        else:
            raise ValueError(f"Unknown topology: {self._topology_name}")

        self._topology_module = topo
        return topo.create_network()

    def _start_asset_services(self):
        if not self._net or not self._topology_module:
            return
        assets = self._config.get("monitoring", {}).get("assets", [])
        if hasattr(self._topology_module, "start_services"):
            self._topology_module.start_services(self._net, assets)

    def _configure_monitor_host(self):
        if not self._net:
            return
        monitor_host_name = self._config.get("monitoring", {}).get("monitor_host", "h2")
        monitor_host = self._net.get(monitor_host_name)
        if monitor_host:
            self._asset_monitor.set_monitor_host(monitor_host)

    def _should_use_network(self):
        return self._controller_path is not None

    def _load_yaml(self, path):
        import yaml
        with open(path, "r") as f:
            return yaml.safe_load(f)

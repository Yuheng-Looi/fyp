import importlib
import os
import socket
import subprocess
import sys
import time

import yaml

try:
    import threading
    from mininet.node import Node
    _node_cmd_lock = threading.Lock()
    _orig_node_cmd = Node.cmd
    def _thread_safe_cmd(self, *args, **kwargs):
        with _node_cmd_lock:
            return _orig_node_cmd(self, *args, **kwargs)
    Node.cmd = _thread_safe_cmd
except ImportError:
    pass

from core.state_manager import StateManager
from core.timeline_manager import TimelineManager
from evaluation.scoring_engine import ScoringEngine
from monitoring.asset_monitor import AssetMonitor
from monitoring.flow_monitor import FlowMonitor
from monitoring.qos_monitor import QosMonitor
from traffic.attack_generator import AttackGenerator
from traffic.normal_generator import NormalTrafficGenerator


class ExperimentRunner:
    def __init__(self, config_path, scenario_path, controller_path=None, topology_name="small", real_time=None):
        self._config_path = config_path
        self._scenario_path = scenario_path
        self._controller_path = controller_path
        self._topology_name = topology_name
        self._real_time_override = real_time

        with open(scenario_path, "r", encoding="utf-8") as handle:
            self._scenario = yaml.safe_load(handle) or {}

        with open(config_path, "r", encoding="utf-8") as handle:
            self._config = yaml.safe_load(handle) or {}

        self._state_manager = StateManager()
        self._timeline = TimelineManager(config_path)

        self._normal_traffic = NormalTrafficGenerator()
        self._attack = AttackGenerator()
        self._asset_monitor = AssetMonitor(self._state_manager, self._config)
        self._qos_monitor = QosMonitor()
        self._flow_monitor = FlowMonitor()
        self._scoring = ScoringEngine()

        self._net = None
        self._ryu_process = None
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
        self._timeline.register("on_attack_start", lambda _: self._attack.start_attack(self._scenario))
        self._timeline.register("on_attack_end", lambda _: self._attack.stop_attack())
        self._timeline.register("on_recovery_end", lambda _: (self._stop_monitors(), self._normal_traffic.stop()))
        self._timeline.register("on_evaluation_start", lambda _: self._scoring.evaluate(
            self._asset_states_history, self._qos_monitor.history, self._flow_monitor.history
        ))

    def _on_phase_start(self, phase, elapsed):
        self._current_phase = phase
        print(f"[timeline] {phase} start at {int(elapsed)}s")

    def _on_phase_end(self, phase, elapsed):
        print(f"[timeline] {phase} end at {int(elapsed)}s")

    def _on_tick(self, elapsed):
        if not self._current_phase:
            return
        
        # Update qos and flow monitors if network is running
        if self._should_use_network():
            self._qos_monitor.tick(elapsed, self._current_phase)
            self._flow_monitor.tick(elapsed, self._current_phase)

        # Record asset states tick-by-tick
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

        self._start_ryu_controller()
        self._net = self._build_topology()
        self._net.start()
        self._net.staticArp()
        self._configure_monitor_host()
        self._start_asset_services()

    def _teardown_network(self):
        if self._net is not None:
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

        print("[teardown] Network teardown complete")

    def _should_use_network(self):
        return self._resolve_real_time()

    def _start_ryu_controller(self):
        if not self._controller_path:
            print("[setup] No controller specified; skipping Ryu startup")
            return

        print(f"[setup] Starting Ryu controller: {self._controller_path}")
        command, extra_paths = self._resolve_ryu_command()
        env = os.environ.copy()
        if extra_paths:
            env["PATH"] = os.pathsep.join(extra_paths + [env.get("PATH", "")])

        compat_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "compat"))
        benchmark_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        backend_dir = os.path.dirname(benchmark_dir)
        frontend_dir = os.path.join(os.path.dirname(backend_dir), "frontend")
        system_packages_dir = "/usr/lib/python3/dist-packages"
        
        python_paths = []
        if os.path.isdir(compat_path):
            python_paths.append(compat_path)
        if os.path.isdir(backend_dir):
            python_paths.append(backend_dir)
        if os.path.isdir(frontend_dir):
            python_paths.append(frontend_dir)
        if os.path.isdir(system_packages_dir):
            python_paths.append(system_packages_dir)
            
        existing_pythonpath = env.get("PYTHONPATH", "")
        if existing_pythonpath:
            python_paths.append(existing_pythonpath)
            
        env["PYTHONPATH"] = os.pathsep.join(python_paths)

        self._ryu_process = subprocess.Popen(
            command + ["--ofp-tcp-listen-port", "6653", self._controller_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
        self._wait_for_port("127.0.0.1", 6653, timeout=10, process=self._ryu_process)

    def _resolve_ryu_command(self):
        extra_paths = []

        cwd_benchmarkenv_bin = os.path.join(os.getcwd(), "benchmarkenv", "bin")
        cwd_benchmarkenv_manager = os.path.join(cwd_benchmarkenv_bin, "ryu-manager")
        if os.path.exists(cwd_benchmarkenv_manager):
            extra_paths.append(cwd_benchmarkenv_bin)
            return [cwd_benchmarkenv_manager], extra_paths

        benchmark_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        repo_root = os.path.abspath(os.path.join(benchmark_dir, ".."))
        benchmarkenv_bin = os.path.join(benchmark_dir, "benchmarkenv", "bin")
        benchmarkenv_manager = os.path.join(benchmarkenv_bin, "ryu-manager")
        if os.path.exists(benchmarkenv_manager):
            extra_paths.append(benchmarkenv_bin)
            return [benchmarkenv_manager], extra_paths

        ryuenv_bin = os.path.join(repo_root, "ryuenv", "bin")
        ryuenv_manager = os.path.join(ryuenv_bin, "ryu-manager")
        if os.path.exists(ryuenv_manager):
            extra_paths.append(ryuenv_bin)
            return [ryuenv_manager], extra_paths

        python_bin_dir = os.path.dirname(sys.executable)
        extra_paths.append(python_bin_dir)
        ryu_path = os.path.join(python_bin_dir, "ryu-manager")
        if os.path.exists(ryu_path):
            return [ryu_path], extra_paths

        for venv_name in ("fypenv", "ryuenv", "benchmarkenv"):
            venv_bin = os.path.join(repo_root, venv_name, "bin")
            extra_paths.append(venv_bin)
            venv_ryu = os.path.join(venv_bin, "ryu-manager")
            if os.path.exists(venv_ryu):
                return [venv_ryu], extra_paths

            venv_python = os.path.join(venv_bin, "python")
            if os.path.exists(venv_python):
                venv_site = os.path.join(
                    os.path.dirname(venv_bin),
                    "lib",
                    f"python{sys.version_info.major}.{sys.version_info.minor}",
                    "site-packages",
                )
                if os.path.exists(os.path.join(venv_site, "ryu")):
                    return [venv_python, "-m", "ryu.cmd.manager"], extra_paths
                if os.path.exists(os.path.join(venv_site, "os_ken")):
                    return [venv_python, "-m", "os_ken.cmd.manager"], extra_paths

        return ["ryu-manager"], extra_paths

    def _wait_for_port(self, host, port, timeout=10, process=None):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process is not None and process.poll() is not None:
                output = ""
                if process.stdout is not None:
                    try:
                        output = process.stdout.read().strip()
                    except Exception:
                        output = ""
                raise RuntimeError(
                    "Ryu process exited early" + (f": {output}" if output else "")
                )
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((host, port)) == 0:
                    return
            time.sleep(0.5)
        raise RuntimeError(f"Timed out waiting for {host}:{port}")

    def _build_topology(self):
        self._topology_module = importlib.import_module(f"topology.{self._topology_name}")
        return self._topology_module.create_network(
            controller_ip="127.0.0.1", controller_port=6653
        )

    def _configure_monitor_host(self):
        if self._net is None:
            return
        monitor_name = self._config.get("monitoring", {}).get("monitor_host")
        if monitor_name:
            self._asset_monitor.set_monitor_host(self._net.get(monitor_name))

    def _start_asset_services(self):
        if self._net is None:
            return
        assets = self._config.get("monitoring", {}).get("assets", [])
        if self._topology_module and hasattr(self._topology_module, "start_services"):
            self._topology_module.start_services(self._net, assets)

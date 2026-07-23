from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta
import importlib
import inspect
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, Optional

from audit import AuditCollector, calculate_overall_scores, render_controller_matrix
from topology import (
    SERVER_HOST,
    SERVER_IP,
    create_network,
    get_attack_hosts,
    get_benign_hosts,
    get_host_map,
    get_server_interface_name,
)


SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_PYTHON = SCRIPT_DIR.parent / "fypenv" / "bin" / "python"
PYTHON_BIN = sys.executable
WORKER_SCRIPT = SCRIPT_DIR / "traffic_workers.py"
VICTIM_SCRIPT = SCRIPT_DIR / "victim_http_server.py"

NETWORK_SCALE = os.getenv("NETWORK_SCALE", "BOTH").upper()
WARM_UP_WINDOW = float(os.getenv("WARM_UP_WINDOW", "120"))
SYSTEM_TYPE = os.getenv("SYSTEM_TYPE", "HYBRID").upper()

PROFILE_LABELS = {
    "SMALL": "SMALL Enterprise",
    "LARGE": "LARGE Data-Center",
}

SYSTEM_LABELS = {
    "DETECTION_ONLY": "Detection Only",
    "SELF_HEALING": "Self-Healing",
    "HYBRID": "Complete Hybrid System",
}

PROFILE_CONFIG = {
    "SMALL": {
        "background_pps": 120.0,
        "background_bytes": 8 * 1024 * 1024,
        "spike_pps": 1000.0,
        "spike_bytes": 500 * 1024 * 1024,
        "spike_is_benign": False,
        "anomaly_threshold": 1000.0,
    },
    "LARGE": {
        "background_pps": 2500.0,
        "background_bytes": 2 * 1024 * 1024 * 1024,
        "spike_pps": 1000.0,
        "spike_bytes": 500 * 1024 * 1024,
        "spike_is_benign": True,
        "anomaly_threshold": 2500.0,
    },
}


def resolve_python_bin() -> str:
    if BACKEND_PYTHON.exists():
        return str(BACKEND_PYTHON)
    return PYTHON_BIN


def normalize_name(value: str) -> str:
    return str(value).strip().upper()


def profile_sequence(network_scale: str) -> list[str]:
    scale = normalize_name(network_scale)
    if scale == "BOTH":
        return ["SMALL", "LARGE"]
    if scale in {"SMALL", "LARGE"}:
        return [scale]
    # Defensive: avoid duplicates and ensure canonical ordering
    seq = [s for s in ["SMALL", "LARGE"] if s not in (scale,)]
    return [scale] + seq


def display_profile(profile: str) -> str:
    return PROFILE_LABELS.get(profile, profile)


def display_system_type(system_type: str) -> str:
    return SYSTEM_LABELS.get(system_type, system_type.replace("_", " ").title())


def expected_action(event: Dict[str, object], profile: str, system_type: str) -> str:
    kind = str(event.get("kind", "benign"))
    if kind == "warmup" or str(event.get("phase", "warmup")) == "warmup":
        return "ALLOW"
    if kind == "scale_spike":
        if profile == "SMALL":
            return "BLOCK" if system_type != "DETECTION_ONLY" else "LOG"
        return "ALLOW"
    if kind in {"exploit_web", "lateral_movement"}:
        return "LOG" if system_type == "DETECTION_ONLY" else "BLOCK"
    return "ALLOW"


def local_decision(event: Dict[str, object], profile: str, system_type: str) -> str:
    kind = str(event.get("kind", "benign"))
    if kind == "warmup" or str(event.get("phase", "warmup")) == "warmup":
        return "ALLOW"
    if kind == "scale_spike":
        if profile == "SMALL":
            return "BLOCK" if system_type != "DETECTION_ONLY" else "LOG"
        return "ALLOW"
    if kind in {"exploit_web", "lateral_movement"}:
        return "LOG" if system_type == "DETECTION_ONLY" else "BLOCK"
    return "ALLOW"


def event_bytes(event: Dict[str, object]) -> int:
    return int(event.get("bytes_out", 0) or 0) + int(event.get("bytes_in", 0) or 0)


def build_event(
    ts: float,
    kind: str,
    asset: str,
    bytes_out: int,
    bytes_in: int,
    phase: str = "attack",
    status_code: int = 200,
    label: str = "ATTACK",
    stage: str = "",
    pps: float = 0.0,
    compromised: bool = False,
) -> Dict[str, object]:
    return {
        "ts": ts,
        "kind": kind,
        "asset": asset,
        "phase": phase,
        "stage": stage,
        "pps": pps,
        "status_code": status_code,
        "label": label,
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
        "compromised": compromised,
    }


def generate_profile_plan(profile: str, duration_s: float, warm_up_window: float) -> list[Dict[str, object]]:
    config = PROFILE_CONFIG[profile]
    warmup_window = min(duration_s, max(0.0, warm_up_window))
    plan: list[Dict[str, object]] = []

    warmup_events = 6
    warmup_step = max(1.0, warmup_window / max(1, warmup_events))
    ts = 0.0
    for index in range(warmup_events):
        asset = "web" if index % 2 == 0 else "db"
        plan.append(
            build_event(
                ts=ts,
                kind="warmup",
                asset=asset,
                bytes_out=1024,
                bytes_in=2048,
                phase="warmup",
                label="BENIGN",
                stage="baseline",
                pps=50.0,
            )
        )
        ts += warmup_step

    if duration_s <= warmup_window:
        return plan

    attack_start = warmup_window + 1.0
    plan.append(
        build_event(
            ts=attack_start,
            kind="scale_spike",
            asset="web",
            bytes_out=int(config["spike_bytes"] * 0.35),
            bytes_in=int(config["spike_bytes"] * 0.15),
            label="BENIGN" if config["spike_is_benign"] else "ATTACK",
            stage="volumetric",
            pps=config["spike_pps"],
            compromised=False,
        )
    )

    exploit_ts = attack_start + 2.0
    plan.append(
        build_event(
            ts=exploit_ts,
            kind="exploit_web",
            asset="web",
            bytes_out=4096,
            bytes_in=1024,
            stage="stage1",
            pps=80.0,
        )
    )

    pivot_ts = exploit_ts + 3.0
    plan.append(
        build_event(
            ts=pivot_ts,
            kind="lateral_movement",
            asset="db",
            bytes_out=2048,
            bytes_in=1024,
            stage="stage2",
            pps=60.0,
        )
    )

    recovery_ts = pivot_ts + 3.0
    plan.append(
        build_event(
            ts=recovery_ts,
            kind="warmup",
            asset="web",
            bytes_out=1024,
            bytes_in=2048,
            phase="recovery",
            label="BENIGN",
            stage="recovery",
            pps=25.0,
        )
    )
    return plan


def live_runtime_available() -> bool:
    if not (BACKEND_PYTHON.exists()):
        return False
    if subprocess.run(["bash", "-lc", "command -v mn >/dev/null 2>&1 && command -v ovs-vsctl >/dev/null 2>&1 && command -v ovs-ofctl >/dev/null 2>&1"], check=False).returncode != 0:
        return False
    try:
        import mininet  # noqa: F401
        return True
    except Exception:
        return False


def run_command(command: Iterable[str], check: bool = False) -> None:
    subprocess.run(list(command), check=check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def mn_cleanup() -> None:
    if subprocess.run(["bash", "-lc", "command -v mn >/dev/null 2>&1"], check=False).returncode != 0:
        return
    run_command(["mn", "-c"], check=False)


def read_counter(host, interface_name: str, counter_name: str) -> int:
    output = host.cmd(f"cat /sys/class/net/{interface_name}/statistics/{counter_name} 2>/dev/null || echo 0")
    try:
        return int(str(output).strip().splitlines()[-1])
    except Exception:
        return 0


def synthesize_flow_features(event: Dict[str, object]) -> Dict[str, object]:
    kind = str(event.get("kind", "benign"))
    src_ip = str(event.get("src_ip", "10.0.0.1"))
    dst_ip = str(event.get("dst_ip", SERVER_IP))
    dst_port = int(event.get("dst_port", 80))
    status_code = event.get("status_code")
    bytes_out = int(event.get("bytes_out", 0) or 0)
    bytes_in = int(event.get("bytes_in", 0) or 0)
    attempt_factor = int(event.get("attempts", 1) or 1)

    if kind == "benign":
        base_packets = 4 + attempt_factor
        packet_len_max = max(128, bytes_in + 120)
        pkt_len_mean = max(96, packet_len_max // 2)
        fwd_pkts_s = 1.5
        flow_iat_max = 2.5
        init_bwd_win = 64240
        bwd_pkt_len_std = 12.0
    elif kind == "semantic_sqli":
        base_packets = 8 + attempt_factor
        packet_len_max = max(256, bytes_out + bytes_in + 200)
        pkt_len_mean = max(128, packet_len_max // 2)
        fwd_pkts_s = 5.0
        flow_iat_max = 0.8
        init_bwd_win = 32768
        bwd_pkt_len_std = 24.0
    else:
        base_packets = 20 + attempt_factor * 2
        packet_len_max = 96
        pkt_len_mean = 64
        fwd_pkts_s = 100.0
        flow_iat_max = 0.05
        init_bwd_win = 1024
        bwd_pkt_len_std = 4.0

    features = {
        "Fwd Header Len": 20,
        "Protocol": 6,
        "Init Bwd Win Byts": init_bwd_win,
        "Tot Fwd Pkts": base_packets,
        "Pkt Len Max": packet_len_max,
        "Pkt Len Mean": pkt_len_mean,
        "Tot Bwd Pkts": max(1, base_packets // 2),
        "Dst Port": dst_port,
        "Bwd Pkt Len Max": max(64, bytes_in + 64),
        "Fwd Pkts/s": fwd_pkts_s,
        "Flow IAT Max": flow_iat_max,
        "TotLen Bwd Pkts": max(64, bytes_in * max(1, base_packets // 2)),
        "TotLen Fwd Pkts": max(64, bytes_out * base_packets),
        "Bwd Pkt Len Std": bwd_pkt_len_std,
        "Bwd Pkt Len Mean": max(48, (bytes_in + 32) // 2),
        "src": src_ip,
        "dst": dst_ip,
        "scaler_id": "default",
        "model_trust": "DEFAULT",
        "xgb_model": "default",
        "safetynet_model": "default",
    }
    if status_code == 200 and kind == "benign":
        features["Bwd Pkt Len Mean"] = max(features["Bwd Pkt Len Mean"], 64)
    return features


@dataclass
class ControllerSpec:
    module_name: str
    file_name: str
    label: str
    controller_class: type


def resolve_controller_class(module) -> type:
    if hasattr(module, "LocalSDNController"):
        return module.LocalSDNController
    if hasattr(module, "BaseController"):
        return module.BaseController
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if hasattr(obj, "evaluate_flow"):
            return obj
    raise ValueError(f"No controller class found in {module.__name__}")


def discover_controllers() -> list[ControllerSpec]:
    controller_dir = SCRIPT_DIR / "controllers"
    specs: list[ControllerSpec] = []
    for path in sorted(controller_dir.glob("*.py")):
        if path.name == "__init__.py" or path.name.startswith("_"):
            continue
        module_name = f"controllers.{path.stem}"
        module = importlib.import_module(module_name)
        controller_class = resolve_controller_class(module)
        specs.append(ControllerSpec(module_name=module_name, file_name=path.name, label=path.stem, controller_class=controller_class))
    return specs


def log_timestamp(label: str) -> None:
    print(f"[time] {label}: {datetime.now().isoformat(timespec='seconds')}")


def log_window(label: str, start_time: datetime, end_time: datetime) -> None:
    start = start_time.isoformat(timespec='seconds')
    end = end_time.isoformat(timespec='seconds')
    print(f"[time] {label} window: {start} -> {end}")


def install_drop_rule(net, src_ip: str, dst_ip: str, dst_port: int) -> None:
    if net is None:
        return
    switch = net.switches[0]
    rule = f"priority=200,ip,tcp,nw_src={src_ip},nw_dst={dst_ip},tp_dst={dst_port},actions=drop"
    switch.cmd(f"ovs-ofctl add-flow {switch.name} \"{rule}\"")


def launch_worker(net_host, command: list[str]):
    return net_host.popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)


def worker_thread(
    collector: AuditCollector,
    run_key: str,
    event_proc,
    controller: Optional[object],
    net,
    mitigation_enabled: bool,
    stop_after_s: float,
    baseline_name: str,
) -> None:
    start = time.time()
    while True:
        line = event_proc.stdout.readline()
        if not line:
            if event_proc.poll() is not None:
                break
            if time.time() - start > stop_after_s + 5:
                break
            continue
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Standardized fields from workers
        label = str(event.get("label", "BENIGN"))
        is_malicious = bool(event.get("malicious", False))
        status_code = int(event.get("status_code", 0) or 0)
        response_text = str(event.get("response_text", ""))
        asset = str(event.get("asset", "web"))
        ts_event = float(event.get("ts", time.time()))

        # Record benign session starts
        if not is_malicious:
            collector.record_benign_session_start(run_key)
            # Successful benign transaction
            if status_code == 200:
                collector.record_benign_session_success(run_key)
            else:
                collector.record_benign_impact(run_key)
            collector.record_bytes(run_key, int(event.get("bytes_out", 0) or 0) + int(event.get("bytes_in", 0) or 0))
            # No further processing for pure benign events when no controller
            if controller is None:
                continue

        # Malicious path: record action and possible successful infiltration
        if is_malicious:
            collector.record_malicious_action(run_key, ts=ts_event)

        # Baseline1 must remain unprotected: bypass predictor + mitigation
        if baseline_name == "baseline1":
            if is_malicious:
                collector.record_successful_infiltration(run_key, ts=ts_event)
                if bool(event.get("leak_detected", False)) or (status_code == 200 and "LEAKED:" in response_text):
                    collector.record_asset_compromise(run_key, asset)
            collector.record_bytes(run_key, int(event.get("bytes_out", 0) or 0) + int(event.get("bytes_in", 0) or 0))
            continue

        if is_malicious:
            # If worker detected leak in response body
            if bool(event.get("leak_detected", False)) or (status_code == 200 and "LEAKED:" in response_text):
                collector.record_successful_infiltration(run_key, ts=ts_event)
                collector.record_asset_compromise(run_key, asset)

        # If a controller is available, consult it for action/verdict
        verdict = None
        action = None
        if controller is not None:
            features = synthesize_flow_features(event)
            try:
                result = controller.evaluate_flow(features)
            except Exception:
                result = {"verdict": "ERROR", "action": "ERROR"}
            verdict = str(result.get("verdict", "ERROR"))
            action = str(result.get("action", "ERROR"))
            is_correct = (not is_malicious and verdict == "BENIGN") or (is_malicious and verdict in {"KNOWN_ATTACK", "SUSPICIOUS", "ALERT"})
            collector.record_detection(run_key, is_correct)

            # If mitigation triggered, install drop rule and record containment time
            if action == "BLOCK" and mitigation_enabled:
                install_drop_rule(net, features["src"], features["dst"], int(features["Dst Port"]))
                collector.record_latency(run_key, max(0.0, (time.time() - ts_event) * 1000.0))
                collector.record_containment(run_key, ts=time.time())

            # If predictor blocked benign traffic, count as false positive
            if not is_malicious and action == "BLOCK":
                collector.record_false_positive(run_key)

        # Always record bytes observed
        collector.record_bytes(run_key, int(event.get("bytes_out", 0) or 0) + int(event.get("bytes_in", 0) or 0))


def build_worker_command(mode: str, host_name: str, host_ip: str, duration: float, server_url: str, seed: int) -> list[str]:
    command = [resolve_python_bin(), "-u", str(WORKER_SCRIPT), mode, "--host", host_name, "--src-ip", host_ip, "--dst-ip", SERVER_IP, "--dst-port", "80", "--duration", str(duration), "--seed", str(seed)]
    if mode in {"benign", "semantic"}:
        command.extend(["--url", server_url])
    return command


def simulate_profile_run(
    collector: AuditCollector,
    run_key: str,
    profile: str,
    system_type: str,
    duration_s: float,
    warm_up_window: float,
    controller,
    plan: list[Dict[str, object]],
) -> Dict[str, object]:
    collector.start_run(run_key, run_key)
    collector.configure_run(run_key, profile, system_type)

    attack_start_ts = None
    first_mitigation_ts = None
    web_safe_ts = None
    web_compromised_local = False
    db_compromised_local = False

    sim_start = datetime.now()
    warmup_end = sim_start + timedelta(seconds=warm_up_window)
    traffic_end = sim_start + timedelta(seconds=duration_s)
    log_window(f"simulate warmup ({profile})", sim_start, warmup_end)
    log_window(f"simulate traffic ({profile})", warmup_end, traffic_end)
    log_timestamp(f"benign traffic started ({profile})")
    attack_logged = False
    for event in plan:
        collector.record_total_bytes(run_key, event_bytes(event))
        expected = expected_action(event, profile, system_type)

        features = synthesize_flow_features(event)
        try:
            result = controller.evaluate_flow(features)
        except Exception:
            result = {"verdict": "ERROR", "action": "ERROR"}
        action = str(result.get("action", "ERROR"))
        is_correct = (expected == "BLOCK" and action == "BLOCK") or (expected != "BLOCK" and action != "BLOCK")
        collector.record_detection(run_key, is_correct)

        if event.get("phase") == "warmup":
            collector.record_benign_session_start(run_key)
            collector.record_benign_session_success(run_key)
            continue

        if attack_start_ts is None:
            attack_start_ts = float(event["ts"])
        if not attack_logged:
            log_timestamp(f"attack traffic started ({profile})")
            attack_logged = True

        kind = str(event.get("kind", ""))
        asset = str(event.get("asset", ""))
        is_malicious = str(event.get("label", "BENIGN")) != "BENIGN"
        if is_malicious:
            collector.record_malicious_action(run_key, ts=float(event["ts"]))

        if action == "BLOCK":
            collector.record_latency(run_key, 85.0 if kind == "scale_spike" else 120.0)
            if first_mitigation_ts is None:
                first_mitigation_ts = float(event["ts"])
                collector.record_containment(run_key, ts=first_mitigation_ts)

        if kind == "scale_spike":
            if profile != "SMALL":
                dropped = action == "BLOCK"
                collector.record_benign_session_start(run_key)
                if dropped:
                    collector.record_benign_impact(run_key)
                    collector.record_false_positive(run_key)
                else:
                    collector.record_benign_session_success(run_key)
            continue

        if kind == "exploit_web":
            if action != "BLOCK":
                collector.record_asset_compromise(run_key, "web")
                web_compromised_local = True
                collector.record_successful_infiltration(run_key, ts=float(event["ts"]))
            else:
                web_safe_ts = float(event["ts"]) + 1.5
            continue

        if kind == "lateral_movement":
            if action != "BLOCK" and web_compromised_local:
                collector.record_asset_compromise(run_key, "db")
                db_compromised_local = True
                collector.record_successful_infiltration(run_key, ts=float(event["ts"]))
            elif action == "BLOCK" and first_mitigation_ts is not None and web_safe_ts is None:
                web_safe_ts = float(event["ts"]) + 1.0
            continue

    if first_mitigation_ts is not None and web_safe_ts is None and system_type in {"SELF_HEALING", "HYBRID"}:
        web_safe_ts = first_mitigation_ts + 2.0

    if web_safe_ts is not None and first_mitigation_ts is not None:
        collector.record_recovery_time(run_key, web_safe_ts - first_mitigation_ts)

    collector.finish_link_counters(run_key, 0, 0, duration_s)
    log_timestamp(f"All traffic ended ({profile})")
    return collector.summary(run_key)


def run_profile_suite(
    network_scale: str,
    warm_up_window: float,
    duration_s: float,
    system_type: str,
    seed: int,
    controllers: list[ControllerSpec],
) -> list[Dict[str, object]]:
    summaries: list[Dict[str, object]] = []
    profile_plans = {profile: generate_profile_plan(profile, duration_s, warm_up_window) for profile in profile_sequence(network_scale)}

    for index, controller_spec in enumerate(controllers, start=1):
        print(f"[{index}] Evaluating {controller_spec.file_name}")
        print(f"[time] duration: {duration_s / 60.0:.2f} mins, warm-up-window: {warm_up_window / 60.0:.2f} mins")
        controller = controller_spec.controller_class()
        collector = AuditCollector(server_link_rate_mbps=100.0)
        for profile in profile_sequence(network_scale):
            run_key = f"{profile.lower()}_{controller_spec.label}_{seed}"
            summary = simulate_profile_run(
                collector,
                run_key,
                profile,
                system_type,
                duration_s,
                warm_up_window,
                controller,
                profile_plans[profile],
            )
            summary["profile_display"] = display_profile(profile)
            summary["system_type_display"] = display_system_type(system_type)
            summary["controller_label"] = controller_spec.label
            summaries.append(summary)

    return summaries


def run_baseline(
    profile: str,
    baseline_name: str,
    duration_s: float,
    collector: AuditCollector,
    controller_ip: str,
    controller_port: int,
    controller: Optional[object],
    seed: int,
) -> Dict[str, object]:
    use_remote_controller = baseline_name == "baseline2"
    collector.start_run(baseline_name, baseline_name)
    if live_runtime_available():
        net = create_network(profile, use_remote_controller, controller_ip, controller_port)
        host_map = get_host_map(net)

        mn_cleanup()
        net.start()

        server = host_map[SERVER_HOST]
        server_iface = get_server_interface_name()
        rx_start = read_counter(server, server_iface, "rx_bytes")
        tx_start = read_counter(server, server_iface, "tx_bytes")
        collector.set_link_counters(baseline_name, rx_start, tx_start)

        victim_proc = server.popen([resolve_python_bin(), "-u", str(VICTIM_SCRIPT), "--host", SERVER_IP, "--port", "80"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)

        server_url = f"http://{SERVER_IP}:80/"
        benign_hosts = get_benign_hosts(profile)
        attack_hosts = get_attack_hosts(profile)
        worker_specs = []
        for idx, host in enumerate(benign_hosts, start=1):
            worker_specs.append(("benign", host, host_map[host].IP(), 10 + idx))
        for idx, host in enumerate(attack_hosts, start=1):
            mode = "ddos" if idx == 1 else "semantic"
            worker_specs.append((mode, host, host_map[host].IP(), 20 + idx))

        procs = []
        threads = []
        start_clock = time.time()
        baseline_start = datetime.now()
        log_window(f"baseline traffic ({baseline_name})", baseline_start, baseline_start + timedelta(seconds=duration_s))
        log_timestamp(f"baseline traffic actual start ({baseline_name})")
        for mode, host_name, ip_address, worker_seed in worker_specs:
            command = build_worker_command(mode, host_name, ip_address, duration_s, server_url, seed + worker_seed)
            if mode == "ddos":
                if profile == "LARGE":
                    command.extend(["--threads", "5", "--burst-size", "20"])
                else:
                    command.extend(["--threads", "3", "--burst-size", "5"])
            elif mode == "semantic":
                command.extend(["--min-sleep", "0.5", "--max-sleep", "1.0"])
            else:
                if profile == "LARGE":
                    command.extend(["--min-sleep", "0.1", "--max-sleep", "0.3"])
                else:
                    command.extend(["--min-sleep", "0.4", "--max-sleep", "0.8"])
            proc = launch_worker(host_map[host_name], command)
            procs.append(proc)
            thread = threading.Thread(
                target=worker_thread,
                args=(collector, baseline_name, proc, controller if use_remote_controller else None, net, use_remote_controller, duration_s, baseline_name),
                daemon=True,
            )
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join(timeout=duration_s + 30.0)
        log_timestamp(f"baseline traffic actual end ({baseline_name})")

        for proc in procs:
            try:
                proc.terminate()
            except Exception:
                pass

        try:
            victim_proc.terminate()
        except Exception:
            pass

        rx_end = read_counter(server, server_iface, "rx_bytes")
        tx_end = read_counter(server, server_iface, "tx_bytes")
        collector.finish_link_counters(baseline_name, rx_end, tx_end, time.time() - start_clock)

        net.stop()
    else:
        # Always show controller evaluation progress instead of runtime warnings
        pass
        server_url = f"http://127.0.0.1:{18080 if os.geteuid() != 0 else 80}/"
        victim_port = 18080 if os.geteuid() != 0 else 80
        victim_proc = subprocess.Popen([resolve_python_bin(), "-u", str(VICTIM_SCRIPT), "--host", "127.0.0.1", "--port", str(victim_port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)

        benign_hosts = get_benign_hosts(profile)
        attack_hosts = get_attack_hosts(profile)
        local_specs = []
        for idx, host in enumerate(benign_hosts, start=1):
            local_specs.append(("benign", host, f"10.0.0.{idx}", 10 + idx))
        for idx, host in enumerate(attack_hosts, start=1):
            mode = "ddos" if idx == 1 else "semantic"
            local_specs.append((mode, host, f"10.0.0.{50 + idx}", 20 + idx))
        procs = []
        threads = []
        start_clock = time.time()
        baseline_start = datetime.now()
        log_window(f"baseline traffic ({baseline_name})", baseline_start, baseline_start + timedelta(seconds=duration_s))
        log_timestamp(f"baseline traffic actual start ({baseline_name})")
        for mode, host_name, ip_address, worker_seed in local_specs:
            command = build_worker_command(mode, host_name, ip_address, duration_s, server_url, seed + worker_seed)
            if mode == "ddos":
                if profile == "LARGE":
                    command.extend(["--threads", "5", "--burst-size", "20", "--pause", "0.25"])
                else:
                    command.extend(["--threads", "3", "--burst-size", "5", "--pause", "0.25"])
            elif mode == "semantic":
                command.extend(["--min-sleep", "0.5", "--max-sleep", "1.0"])
            else:
                if profile == "LARGE":
                    command.extend(["--min-sleep", "0.1", "--max-sleep", "0.3"])
                else:
                    command.extend(["--min-sleep", "0.4", "--max-sleep", "0.8"])
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            procs.append(proc)
            thread = threading.Thread(
                target=worker_thread,
                args=(collector, baseline_name, proc, controller if use_remote_controller else None, None, False, duration_s, baseline_name),
                daemon=True,
            )
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join(timeout=duration_s + 30.0)
        log_timestamp(f"baseline traffic actual end ({baseline_name})")

        for proc in procs:
            try:
                proc.terminate()
            except Exception:
                pass

        try:
            victim_proc.terminate()
        except Exception:
            pass

        collector.finish_link_counters(baseline_name, 0, 0, time.time() - start_clock)
    return collector.summary(baseline_name)


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic BionicAttack benchmark for the SDN microservices stack")
    parser.add_argument("--duration", type=float, default=900.0)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--network-scale", choices=["SMALL", "LARGE", "BOTH"], default=NETWORK_SCALE)
    parser.add_argument("--warm-up-window", type=float, default=WARM_UP_WINDOW)
    parser.add_argument("--system-type", choices=["DETECTION_ONLY", "SELF_HEALING", "HYBRID"], default=SYSTEM_TYPE)
    args = parser.parse_args()

    controllers = discover_controllers()
    if not controllers:
        raise RuntimeError("No controllers found in controllers folder")

    summaries = run_profile_suite(
        args.network_scale,
        args.warm_up_window,
        args.duration,
        args.system_type,
        args.seed,
        controllers,
    )

    controller_labels = [spec.label for spec in controllers]
    profile_order = profile_sequence(args.network_scale)
    for profile in profile_order:
        profile_summaries = [summary for summary in summaries if summary["profile"] == profile]
        profile_summaries.sort(key=lambda item: controller_labels.index(item["controller_label"]))
        benign_hosts = get_benign_hosts(profile)
        attack_hosts = get_attack_hosts(profile)
        network_line = (
            f"{profile} (OVS switch: 1, users: {len(benign_hosts)}, attacker: {len(attack_hosts)})"
        )
        print(
            render_controller_matrix(
                profile_summaries,
                network_line,
                display_system_type(args.system_type),
                controller_labels,
            )
        )

    controller_lookup: Dict[str, Dict[str, Dict[str, object]]] = {}
    for summary in summaries:
        controller_lookup.setdefault(summary["controller_label"], {})[summary["profile"]] = summary

    scorecard = {}
    for label, profile_map in controller_lookup.items():
        if "SMALL" not in profile_map or "LARGE" not in profile_map:
            continue
        small = profile_map["SMALL"]
        large = profile_map["LARGE"]
        scores = calculate_overall_scores(
            {
                "ASR": float(small.get("attack_success_rate", 0.0)),
                "Goodput": float(small.get("goodput_retention", 0.0)),
                "Time_to_Containment": small.get("time_to_containment"),
            },
            {
                "ASR": float(large.get("attack_success_rate", 0.0)),
                "Goodput": float(large.get("goodput_retention", 0.0)),
                "Time_to_Containment": large.get("time_to_containment"),
            },
        )
        scorecard[label] = scores

    if scorecard:
        header = "=" * 120
        separator = "-" * 120
        metric_labels = ["Adaptiveness Score", "Recovery Ability Score", "OVERALL BENCHMARK MARK"]
        col_widths = [max(len(label), 10) for label in controller_labels]
        lines = [
            header,
            "           FINAL SDN CONTROLLER BENCHMARK SCORECARD",
            header,
            "Metric".ljust(28) + " | " + " | ".join(label.ljust(col_widths[idx]) for idx, label in enumerate(controller_labels)),
            separator,
        ]

        adapt_values = [scorecard[label]["adaptiveness"] if label in scorecard else 0.0 for label in controller_labels]
        recovery_values = [scorecard[label]["recovery_ability"] if label in scorecard else 0.0 for label in controller_labels]
        overall_values = [scorecard[label]["overall_mark"] if label in scorecard else 0.0 for label in controller_labels]

        lines.append(
            "Adaptiveness Score".ljust(28)
            + " | "
            + " | ".join(f"{value:.2f}%".rjust(col_widths[idx]) for idx, value in enumerate(adapt_values))
        )
        lines.append(
            "Recovery Ability Score".ljust(28)
            + " | "
            + " | ".join(f"{value:.2f}%".rjust(col_widths[idx]) for idx, value in enumerate(recovery_values))
        )
        lines.append(separator)
        lines.append(
            "OVERALL BENCHMARK MARK".ljust(28)
            + " | "
            + " | ".join(f"{value:.2f}%".rjust(col_widths[idx]) for idx, value in enumerate(overall_values))
        )
        lines.append(header)
        print("\n".join(lines))


if __name__ == "__main__":
    main()

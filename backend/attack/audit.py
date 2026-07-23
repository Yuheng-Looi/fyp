from __future__ import annotations

from dataclasses import dataclass, field
import threading
from typing import Dict, List


def clamp_score(value: float) -> float:
    return max(0.0, min(100.0, value))


def compute_adaptiveness_score(small: Dict[str, object], large: Dict[str, object]) -> float:
    delta_asr = abs(float(small.get("attack_success_rate", 0.0)) - float(large.get("attack_success_rate", 0.0)))
    delta_goodput = abs(float(small.get("goodput_retention", 0.0)) - float(large.get("goodput_retention", 0.0)))
    return clamp_score(100.0 - ((delta_asr + delta_goodput) / 2.0))


def compute_recovery_ability_score(goodput: float, ttc: float | None, successful_infiltrations: int) -> float:
    penalty = 0.0
    if ttc is None and successful_infiltrations > 0:
        penalty = 50.0
    if ttc is not None:
        penalty += min(100.0, ttc * 5.0)
    return clamp_score(goodput - penalty)


def calculate_overall_scores(small_stats: dict, large_stats: dict) -> dict:
    asr_diff = abs(small_stats["ASR"] - large_stats["ASR"])
    goodput_diff = abs(small_stats["Goodput"] - large_stats["Goodput"])
    adaptiveness = max(0.0, 100.0 - (asr_diff + goodput_diff))

    avg_goodput = (small_stats["Goodput"] + large_stats["Goodput"]) / 2.0
    avg_asr = (small_stats["ASR"] + large_stats["ASR"]) / 2.0

    avg_ttc = (
        (small_stats.get("Time_to_Containment") or 0) + (large_stats.get("Time_to_Containment") or 0)
    ) / 2.0
    ttc_penalty = min(20.0, avg_ttc * 0.2)

    recovery_ability = max(0.0, (0.5 * avg_goodput) + (0.5 * (100.0 - avg_asr)) - ttc_penalty)
    overall_mark = (adaptiveness * 0.4) + (recovery_ability * 0.6)

    return {
        "adaptiveness": adaptiveness,
        "recovery_ability": recovery_ability,
        "overall_mark": overall_mark,
    }


@dataclass
class RunStats:
    label: str
    profile: str = "SMALL"
    system_type: str = "HYBRID"
    total_batches: int = 0
    correct_classifications: int = 0
    false_positives: int = 0
    benign_dropped_packets: int = 0
    benign_total_packets: int = 0
    compromised_count: int = 0
    web_compromised: bool = False
    db_compromised: bool = False
    response_latencies_ms: List[float] = field(default_factory=list)
    recovery_seconds: List[float] = field(default_factory=list)
    payload_bytes: int = 0
    total_bytes: int = 0
    # New counters for true metrics
    total_malicious_actions: int = 0
    successful_infiltrations: int = 0
    total_benign_sessions: int = 0
    successful_benign_sessions: int = 0
    benign_sessions_dropped: int = 0
    first_attack_ts: float | None = None
    containment_ts: float | None = None
    ttc_records: List[float] = field(default_factory=list)
    rx_bytes_start: int = 0
    rx_bytes_end: int = 0
    tx_bytes_start: int = 0
    tx_bytes_end: int = 0
    duration_s: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


class AuditCollector:
    def __init__(self, server_link_rate_mbps: float = 100.0):
        self.server_link_rate_mbps = server_link_rate_mbps
        self._runs: Dict[str, RunStats] = {}
        self._lock = threading.Lock()

    def start_run(self, run_key: str, label: str) -> None:
        with self._lock:
            self._runs[run_key] = RunStats(label=label)

    def configure_run(self, run_key: str, profile: str, system_type: str) -> None:
        run = self._runs[run_key]
        with run.lock:
            run.profile = profile
            run.system_type = system_type

    def set_link_counters(self, run_key: str, rx_start: int, tx_start: int) -> None:
        run = self._runs[run_key]
        with run.lock:
            run.rx_bytes_start = rx_start
            run.tx_bytes_start = tx_start

    def finish_link_counters(self, run_key: str, rx_end: int, tx_end: int, duration_s: float) -> None:
        run = self._runs[run_key]
        with run.lock:
            run.rx_bytes_end = rx_end
            run.tx_bytes_end = tx_end
            run.duration_s = duration_s

    def record_detection(self, run_key: str, is_correct: bool) -> None:
        run = self._runs[run_key]
        with run.lock:
            run.total_batches += 1
            if is_correct:
                run.correct_classifications += 1

    def record_false_positive(self, run_key: str) -> None:
        run = self._runs[run_key]
        with run.lock:
            run.false_positives += 1

    def record_benign_packet(self, run_key: str, dropped: bool = False) -> None:
        run = self._runs[run_key]
        with run.lock:
            run.benign_total_packets += 1
            run.total_benign_sessions += 1
            if dropped:
                run.benign_dropped_packets += 1
                run.benign_sessions_dropped += 1

    def record_compromise(self, run_key: str) -> None:
        run = self._runs[run_key]
        with run.lock:
            run.compromised_count += 1

    def record_malicious_action(self, run_key: str, ts: float | None = None) -> None:
        run = self._runs[run_key]
        with run.lock:
            run.total_malicious_actions += 1
            if run.first_attack_ts is None and ts is not None:
                run.first_attack_ts = ts

    def record_successful_infiltration(self, run_key: str, ts: float | None = None) -> None:
        run = self._runs[run_key]
        with run.lock:
            run.successful_infiltrations += 1
            if run.first_attack_ts is None and ts is not None:
                run.first_attack_ts = ts

    def record_benign_session_start(self, run_key: str) -> None:
        run = self._runs[run_key]
        with run.lock:
            run.total_benign_sessions += 1

    def record_benign_session_success(self, run_key: str) -> None:
        run = self._runs[run_key]
        with run.lock:
            run.successful_benign_sessions += 1

    def record_benign_impact(self, run_key: str) -> None:
        run = self._runs[run_key]
        with run.lock:
            run.benign_sessions_dropped += 1

    def record_containment(self, run_key: str, ts: float | None = None) -> None:
        run = self._runs[run_key]
        with run.lock:
            if run.containment_ts is None and ts is not None and run.first_attack_ts is not None:
                run.containment_ts = ts
                run.ttc_records.append(run.containment_ts - run.first_attack_ts)

    def record_latency(self, run_key: str, latency_ms: float) -> None:
        run = self._runs[run_key]
        with run.lock:
            run.response_latencies_ms.append(latency_ms)

    def record_bytes(self, run_key: str, byte_count: int) -> None:
        run = self._runs[run_key]
        with run.lock:
            total = max(0, byte_count)
            run.payload_bytes += total
            run.total_bytes += total

    def record_total_bytes(self, run_key: str, byte_count: int) -> None:
        run = self._runs[run_key]
        with run.lock:
            run.total_bytes += max(0, byte_count)

    def record_asset_compromise(self, run_key: str, asset: str) -> None:
        run = self._runs[run_key]
        with run.lock:
            run.compromised_count += 1
            if asset == "web":
                run.web_compromised = True
            elif asset == "db":
                run.db_compromised = True

    def record_recovery_time(self, run_key: str, seconds: float) -> None:
        run = self._runs[run_key]
        with run.lock:
            run.recovery_seconds.append(max(0.0, seconds))

    def summary(self, run_key: str) -> Dict[str, object]:
        run = self._runs[run_key]
        with run.lock:
            accuracy = (run.correct_classifications / run.total_batches * 100.0) if run.total_batches else 0.0
            # Attack Success Rate
            asr_raw = (run.successful_infiltrations / run.total_malicious_actions * 100.0) if run.total_malicious_actions else 0.0
            asr = clamp_score(asr_raw)

            # Goodput Retention Ratio (successful benign / total benign)
            goodput = (run.successful_benign_sessions / run.total_benign_sessions * 100.0) if run.total_benign_sessions else 100.0

            # False Positive Block Rate on network plane
            fpr_net = (run.benign_sessions_dropped / run.total_benign_sessions * 100.0) if run.total_benign_sessions else 0.0

            # Time to Containment (average)
            ttc = (sum(run.ttc_records) / len(run.ttc_records)) if run.ttc_records else None
            if ttc is None and run.successful_infiltrations > 0 and run.duration_s > 0:
                ttc = run.duration_s

            recovery_ability = compute_recovery_ability_score(goodput, ttc, run.successful_infiltrations)

            qos_score = clamp_score(goodput)
            security_score = clamp_score(100.0 - asr)  # lower ASR -> better security score
            throughput_efficiency = clamp_score(goodput)
            bytes_delta = max(0, (run.rx_bytes_end - run.rx_bytes_start) + (run.tx_bytes_end - run.tx_bytes_start))
            if bytes_delta <= 0:
                bytes_delta = run.payload_bytes * 2
            if run.duration_s <= 0:
                bandwidth_util = 0.0
            else:
                bandwidth_util = (bytes_delta * 8.0 / (self.server_link_rate_mbps * 1_000_000.0 * run.duration_s)) * 100.0
            bandwidth_util = max(0.0, min(100.0, bandwidth_util))
            latency = sum(run.response_latencies_ms) / len(run.response_latencies_ms) if run.response_latencies_ms else None
            recovery = sum(run.recovery_seconds) / len(run.recovery_seconds) if run.recovery_seconds else None
            return {
                "label": run.label,
                "profile": run.profile,
                "system_type": run.system_type,
                "accuracy": accuracy,
                "false_positives": run.false_positives,
                "attack_success_rate": asr,
                "goodput_retention": goodput,
                "fpr_net": fpr_net,
                "recovery_ability_score": recovery_ability,
                "qos_score": qos_score,
                "throughput_efficiency": throughput_efficiency,
                "security_score": security_score,
                "bandwidth_utilization": bandwidth_util,
                "compromised_count": run.compromised_count,
                "latency_ms": latency,
                "recovery_seconds": recovery,
                "time_to_containment": ttc,
                "total_batches": run.total_batches,
                "correct_classifications": run.correct_classifications,
                "benign_dropped_packets": run.benign_dropped_packets,
                "successful_infiltrations": run.successful_infiltrations,
                "total_malicious_actions": run.total_malicious_actions,
                "total_benign_sessions": run.total_benign_sessions,
                "successful_benign_sessions": run.successful_benign_sessions,
                "web_compromised": run.web_compromised,
                "db_compromised": run.db_compromised,
            }


def fmt_compromise(summary: Dict[str, object]) -> str:
    if summary.get("web_compromised") or summary.get("db_compromised"):
        leaked = []
        if summary.get("web_compromised"):
            leaked.append("Web")
        if summary.get("db_compromised"):
            leaked.append("DB")
        return f"YES ({', '.join(leaked)} Leaked)"
    return "NO (Contained)"


def fmt_latency(summary: Dict[str, object]) -> str:
    latency = summary["latency_ms"]
    if latency is None:
        return "0.00 ms"
    return f"{latency:.2f} ms"


def fmt_recovery(summary: Dict[str, object]) -> str:
    recovery = summary["recovery_seconds"]
    if recovery is None:
        return "0.00 sec"
    return f"{recovery:.2f} sec"


def render_asset_matrix(baseline: Dict[str, object], evaluated: Dict[str, object]) -> str:
    def baseline_value(key: str, default: float = 0.0) -> float:
        value = baseline.get(key, default)
        return float(value) if value is not None else default

    def baseline_text(key: str) -> str:
        value = baseline.get(key)
        return "N/A" if value is None else f"{float(value):0.2f}%"

    header = "=" * 80
    separator = "-" * 80
    baseline_label = baseline.get("column_label", "Baseline")
    evaluated_label = evaluated.get("column_label", "Evaluated System")
    lines = [
        header,
        "           BIONICATTACK-BENCH EVALUATION MATRIX (ASSET-WEIGHTED SCORE)",
        header,
        f"Run Context       : {evaluated.get('context_label', 'RUN')}",
        f"Target System Type: {evaluated.get('system_type_display', evaluated['system_type'])}",
        f"Evaluated Profile : {evaluated.get('profile_display', evaluated['profile'])}",
        separator,
        f"Benchmark Metric                  | {baseline_label} | {evaluated_label}",
        separator,
        f"Overall Adaptive Accuracy         | {baseline_text('accuracy'):>8}              | {evaluated['accuracy']:0.2f}%",
        f"Data-Plane Throughput Efficiency  | {baseline_text('throughput_efficiency'):>8}              | {evaluated['throughput_efficiency']:0.2f}%",
        f"Attack Success Rate (ASR)         | {baseline_text('attack_success_rate'):>8}              | {evaluated.get('attack_success_rate', 0.0):0.2f}%",
        f"Goodput Retention                 | {baseline_text('goodput_retention'):>8}              | {evaluated.get('goodput_retention', 0.0):0.2f}%",
        f"False Positive Rate (FPR_net)     | {baseline_text('fpr_net'):>8}              | {evaluated.get('fpr_net', 0.0):0.2f}%",
        f"QoS Preservation Score            | {baseline_text('qos_score'):>8}              | {evaluated['qos_score']:0.2f}%",
        f"Asset Security Score              | {baseline_value('security_score'):0.2f}% (Baseline)   | {evaluated['security_score']:0.2f}% ({fmt_compromise(evaluated)})",
        f"Mitiation Response Speed (Latency)| {fmt_latency(baseline)}              | {fmt_latency(evaluated)}",
        f"Time-to-Containment (avg)         | {baseline.get('time_to_containment', 0.0)}              | {evaluated.get('time_to_containment') if evaluated.get('time_to_containment') is not None else 0.00}",
        header,
    ]
    return "\n".join(lines)


def render_controller_matrix(
    summaries: List[Dict[str, object]],
    network_label: str,
    system_type_label: str,
    controller_labels: List[str],
) -> str:
    header = "=" * 80
    metrics = [
        ("Overall Adaptive Accuracy", lambda s: f"{s['accuracy']:.2f}%"),
        ("Data-Plane Throughput Efficiency", lambda s: f"{s['throughput_efficiency']:.2f}%"),
        ("Attack Success Rate (ASR)", lambda s: f"{s.get('attack_success_rate', 0.0):.2f}%"),
        ("Goodput Retention", lambda s: f"{s.get('goodput_retention', 0.0):.2f}%"),
        ("False Positive Rate (FPR_net)", lambda s: f"{s.get('fpr_net', 0.0):.2f}%"),
        ("QoS Preservation Score", lambda s: f"{s.get('qos_score', 0.0):.2f}%"),
        ("Asset Security Score", lambda s: f"{s.get('security_score', 0.0):.2f}% ({fmt_compromise(s)})"),
        ("Mitigation Response Speed (Latency)", fmt_latency),
        (
            "Time-to-Containment (avg)",
            lambda s: f"{s.get('time_to_containment') if s.get('time_to_containment') is not None else 0.0}",
        ),
    ]

    metric_width = max(len(label) for label, _ in metrics)
    value_matrix = [[formatter(summary) for summary in summaries] for _, formatter in metrics]
    col_widths = []
    for idx, label in enumerate(controller_labels):
        col_values = [row[idx] for row in value_matrix]
        col_widths.append(max(len(label), max(len(value) for value in col_values)))

    header_row = "Benchmark Metric".ljust(metric_width)
    header_row += " | " + " | ".join(label.ljust(col_widths[idx]) for idx, label in enumerate(controller_labels))
    separator = "-" * len(header_row)

    lines = [
        header,
        "           BIONICATTACK-BENCH EVALUATION MATRIX (ASSET-WEIGHTED SCORE)",
        header,
        f"Network scale: {network_label}",
        f"Target System Type: {system_type_label}",
        separator,
        header_row,
        separator,
    ]

    for row_idx, (label, _) in enumerate(metrics):
        values = value_matrix[row_idx]
        row = label.ljust(metric_width)
        row += " | " + " | ".join(values[idx].rjust(col_widths[idx]) for idx in range(len(values)))
        lines.append(row)

    lines.append(header)
    return "\n".join(lines)


def render_matrix(original: Dict[str, object], mitigated: Dict[str, object]) -> str:
    original = dict(original)
    mitigated = dict(mitigated)
    mitigated.setdefault("context_label", "LIVE BASELINE COMPARISON MATRIX")
    return render_asset_matrix(original, mitigated)

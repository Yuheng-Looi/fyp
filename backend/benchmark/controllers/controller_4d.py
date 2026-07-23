from __future__ import annotations

import builtins
builtins.buffer = memoryview

try:
    import ryu.utils
    ryu.utils.round_up = lambda x, y: ((x + y - 1) // y) * y
    
    import ryu.lib.addrconv
    _orig_text_to_bin = ryu.lib.addrconv.AddressConverter.text_to_bin
    def _patched_text_to_bin(self, text):
        if isinstance(text, bytes):
            text = text.decode('ascii')
        return _orig_text_to_bin(self, text)
    ryu.lib.addrconv.AddressConverter.text_to_bin = _patched_text_to_bin
    
    import ryu.ofproto.oxm_fields
    def _patched_from_user(self, i):
        res = []
        for _ in range(self.size):
            res.append(i & 255)
            i //= 256
        res.reverse()
        return bytes(res)
    ryu.ofproto.oxm_fields.IntDescr.from_user = _patched_from_user
    
    import threading
    from mininet.node import Node
    _node_cmd_lock = threading.Lock()
    _orig_node_cmd = Node.cmd
    def _thread_safe_cmd(self, *args, **kwargs):
        with _node_cmd_lock:
            return _orig_node_cmd(self, *args, **kwargs)
    Node.cmd = _thread_safe_cmd
except (ImportError, AttributeError):
    pass

import os
import sys
import time
import json
import joblib
import pandas as pd
import numpy as np
import xgboost as xgb
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field

import requests

# Import Ryu components
from ryu.base import app_manager
from ryu.controller import ofp_event, event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet
from ryu.lib import hub


class EventMLInferenceComplete(event.EventBase):
    def __init__(self, datapath, flow_key, flow_state, verdict, action, xgb_score=0.0, if_score=0.0, gnn_class="N/A"):
        super(EventMLInferenceComplete, self).__init__()
        self.datapath = datapath
        self.flow_key = flow_key
        self.flow_state = flow_state
        self.verdict = verdict
        self.action = action
        self.xgb_score = xgb_score
        self.if_score = if_score
        self.gnn_class = gnn_class

# Import Scapy for feature extraction
from scapy.all import Ether, IP, TCP, UDP

SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent.parent
FRONTEND_DIR = BACKEND_DIR.parent / "frontend"

if str(BACKEND_DIR) not in sys.path:
    sys.path.append(str(BACKEND_DIR))
if str(FRONTEND_DIR) not in sys.path:
    sys.path.append(str(FRONTEND_DIR))

from cic_extractor import Flow, FEATURE_KEYS
from scaler_utils import TriChannelScaler

EXPECTED_COLUMNS = [
    "Fwd Header Len",
    "Protocol",
    "Init Bwd Win Byts",
    "Tot Fwd Pkts",
    "Pkt Len Max",
    "Pkt Len Mean",
    "Tot Bwd Pkts",
    "Dst Port",
    "Bwd Pkt Len Max",
    "Fwd Pkts/s",
    "Flow IAT Max",
    "TotLen Bwd Pkts",
    "TotLen Fwd Pkts",
    "Bwd Pkt Len Std",
    "Bwd Pkt Len Mean",
]


@dataclass
class FlowState:
    flow_id: str
    src: str
    dst: str
    created_time: float
    expiry_time: float
    last_updated: float
    xgb_score: float = 0.0
    if_score: float = 0.0
    gnn_context: dict = field(default_factory=dict)
    risk_zone: str = 'Green'           # Green, Yellow, Red
    mitigation_action: str = 'ALLOW'   # ALLOW, RATE_LIMIT, BLOCK
    ovs_rule_id: int | None = None     # Map to OpenFlow cookie
    honeypot_result: str | None = None
    status: str = 'NEW'                # NEW, OBSERVING, READY, EVALUATED


def mac_to_str(mac):
    if isinstance(mac, bytes):
        return ':'.join('%02x' % b for b in mac)
    return mac


# ---------------------------------------------------------------------------
# Evidence Aggregator
# ---------------------------------------------------------------------------

class EvidenceAggregator:
    """
    Polls security telemetry logs (security_evidence.log, honeypot.log) and
    tracks raw counts of events observed in the last polling window.
    """

    EVIDENCE_LOG = "/home/fyp2025/fyp/backend/security_evidence.log"
    HONEYPOT_LOG = "/home/fyp2025/fyp/backend/honeypot.log"

    def __init__(self, window_seconds: float = 5.0):
        self._window = window_seconds
        self._evidence_log_offset = 0   # byte offset — only read new lines
        self._honeypot_log_offset = 0

    def poll_counts(self) -> Dict[str, int]:
        """
        Read new log lines since the last poll and return a dictionary of event counts.
        """
        counts = {
            "unauthorized_query": 0,
            "unauthorized_credential_query": 0,
            "exfiltration": 0,
            "honeypot_hit": 0
        }

        # --- security_evidence.log (JSON lines) ---
        try:
            with open(self.EVIDENCE_LOG, "r") as fh:
                fh.seek(self._evidence_log_offset)
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        entry = json.loads(raw)
                        event_type = entry.get("event", "")
                        if event_type in counts:
                            counts[event_type] += 1
                    except (json.JSONDecodeError, ValueError):
                        pass
                self._evidence_log_offset = fh.tell()
        except FileNotFoundError:
            self._evidence_log_offset = 0
        except Exception:
            pass

        # --- honeypot.log (CSV-like lines) ---
        try:
            with open(self.HONEYPOT_LOG, "r") as fh:
                fh.seek(self._honeypot_log_offset)
                for raw in fh:
                    raw = raw.strip()
                    if raw:
                        counts["honeypot_hit"] += 1
                self._honeypot_log_offset = fh.tell()
        except FileNotFoundError:
            self._honeypot_log_offset = 0
        except Exception:
            pass

        return counts


# ---------------------------------------------------------------------------
# Adaptive Rescaler
# ---------------------------------------------------------------------------

class AdaptiveRescaler:
    """
    Adjusts ML classification thresholds and TriChannelScaler statistics
    based on the decision returned by the local LLM.

    If decision == "stricter": become more aggressive
        - Lower block/log thresholds by 0.05 (clamped to floor)
        - Compress scaler stats (* 0.95) → increases anomaly sensitivity

    If decision == "relaxed": relax mitigation to restore QoS
        - Raise block/log thresholds by 0.05 (clamped to ceiling)
        - Expand scaler stats (* 1.05) → reduces false-positive sensitivity

    Threshold floors/ceilings match baseline of controller_4:
        log_threshold   : [0.30 – 0.70]
        block_threshold : [0.50 – 0.90]
    """

    LOG_FLOOR    = 0.30
    LOG_CEIL     = 0.70
    BLOCK_FLOOR  = 0.50
    BLOCK_CEIL   = 0.90
    STEP         = 0.05
    COMPRESS     = 0.95
    EXPAND       = 1.05

    def __init__(self, controller):
        self._ctrl = controller

    def adapt(self, decision: str):
        """
        Apply threshold and scaler adjustments based on the LLM's decision.
        Returns a human-readable description of the action taken.
        """
        if decision == "stricter":
            old_log   = self._ctrl.log_threshold
            old_block = self._ctrl.block_threshold
            self._ctrl.log_threshold   = max(self.LOG_FLOOR,   self._ctrl.log_threshold   - self.STEP)
            self._ctrl.block_threshold = max(self.BLOCK_FLOOR, self._ctrl.block_threshold - self.STEP)
            self._adjust_scaler(self.COMPRESS)
            return (
                f"LLM DECISION: stricter → TIGHTENING DETECTION. "
                f"log_thresh {old_log:.2f}→{self._ctrl.log_threshold:.2f}, "
                f"block_thresh {old_block:.2f}→{self._ctrl.block_threshold:.2f}, "
                f"scaler compressed ×{self.COMPRESS}"
            )
        elif decision == "relaxed":
            old_log   = self._ctrl.log_threshold
            old_block = self._ctrl.block_threshold
            self._ctrl.log_threshold   = min(self.LOG_CEIL,   self._ctrl.log_threshold   + self.STEP)
            self._ctrl.block_threshold = min(self.BLOCK_CEIL, self._ctrl.block_threshold + self.STEP)
            self._adjust_scaler(self.EXPAND)
            return (
                f"LLM DECISION: relaxed → RELAXING MITIGATION. "
                f"log_thresh {old_log:.2f}→{self._ctrl.log_threshold:.2f}, "
                f"block_thresh {old_block:.2f}→{self._ctrl.block_threshold:.2f}, "
                f"scaler expanded ×{self.EXPAND}"
            )
        else:
            return f"LLM DECISION: {decision} → MAINTAINING CURRENT STATE"

    def _adjust_scaler(self, factor: float):
        """Multiply all scaler p95 and median statistics by `factor`, then persist to disk."""
        scaler = self._ctrl.scaler
        if scaler and hasattr(scaler, 'stats_'):
            for col in scaler.stats_:
                scaler.stats_[col]['p95']    *= factor
                scaler.stats_[col]['median'] *= factor
            self._save_scaler()

    def _save_scaler(self):
        scaler_dir = BACKEND_DIR / "scalers"
        os.makedirs(scaler_dir, exist_ok=True)
        scaler_path = scaler_dir / f"scaler_{self._ctrl.scaler_id}.pkl"
        try:
            joblib.dump(self._ctrl.scaler, str(scaler_path))
        except Exception as e:
            self._ctrl.logger.error(f"[ADAPTIVE RESCALER] Failed to save scaler: {e}")


# ---------------------------------------------------------------------------
# Controller
# ---------------------------------------------------------------------------

class MLReactiveController(app_manager.RyuApp):
    """
    LLM-Driven Adaptive SDN Controller.
    Uses local Ollama SLMs for real-time security reasoning.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MLReactiveController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flows: Dict[tuple, Flow] = {}
        self.cookie_to_state: Dict[int, FlowState] = {}
        self.flow_key_to_state: Dict[tuple, FlowState] = {}
        self.next_cookie = 1
        self.pending_inference = {}

        # Adaptive detection state
        self.log_threshold   = 0.5
        self.block_threshold = 0.75
        self.scaler_id = "controller_4"
        self.scaler    = None
        self.xgb       = None
        self._load_local_models()
        self._save_custom_scaler()

        # Set model name
        self.model_name = "gemma4:e4b"

        # Logging setup
        import logging
        self.logger.handlers = []
        handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        # Telemetry aggregation & rescaler
        self._evidence_aggregator = EvidenceAggregator(window_seconds=5.0)
        self._adaptive_rescaler   = AdaptiveRescaler(self)

        # Register self as observer for custom ML complete event
        self.register_observer(EventMLInferenceComplete, self.name)

        # Background greenlets
        hub.spawn(self._periodic_graph_exporter)   # every 5 s
        hub.spawn(self._periodic_state_cleaner)    # every 0.5 s
        hub.spawn(self._llm_driven_rescaler)       # every 5 s

    # ------------------------------------------------------------------
    # Model helpers
    # ------------------------------------------------------------------

    def _load_local_models(self):
        xgb_path    = str(BACKEND_DIR / "models" / "xgb" / "xgb_binary_v1.json")
        scaler_path = str(BACKEND_DIR / "scalers" / "trichannel_scaler.pkl")

        if os.path.exists(xgb_path):
            try:
                self.xgb = xgb.XGBClassifier()
                self.xgb.load_model(xgb_path)
            except Exception as e:
                self.logger.error(f"Failed to load local XGBoost model: {e}")
        if os.path.exists(scaler_path):
            try:
                self.scaler = joblib.load(scaler_path)
            except Exception as e:
                self.logger.error(f"Failed to load local TriChannelScaler: {e}")

    def _save_custom_scaler(self):
        if self.scaler:
            scaler_dir  = BACKEND_DIR / "scalers"
            os.makedirs(scaler_dir, exist_ok=True)
            scaler_path = scaler_dir / f"scaler_{self.scaler_id}.pkl"
            try:
                joblib.dump(self.scaler, str(scaler_path))
                self.logger.info(f"[LLM CONTROLLER] Pre-created custom scaler at {scaler_path}.")
            except Exception as e:
                self.logger.error(f"[LLM CONTROLLER] Failed to pre-create custom scaler: {e}")

    # ------------------------------------------------------------------
    # Background greenlets
    # ------------------------------------------------------------------

    def _llm_driven_rescaler(self):
        """
        Asynchronous, non-blocking LLM reasoning loop.
        Formats counts of security events, sends prompt to local Ollama API,
        parses the JSON decision, and rescales parameters accordingly.
        """
        ollama_url = "http://localhost:11434/api/generate"

        while True:
            hub.sleep(5)
            try:
                # 1. Poll security log counts
                counts = self._evidence_aggregator.poll_counts()
                
                # 2. Format dynamic telemetry prompt
                prompt = (
                    f"In the last 5 seconds, the network experienced: "
                    f"{counts.get('unauthorized_query', 0)} SQLi attempts, "
                    f"{counts.get('unauthorized_credential_query', 0)} Credential attacks, "
                    f"{counts.get('honeypot_hit', 0)} Honeypot hits, "
                    f"{counts.get('exfiltration', 0)} Exfiltration events."
                )

                # 3. Formulate query payload to local Ollama
                payload = {
                    "model": self.model_name,
                    "prompt": prompt,
                    "system": "You are a Security Agent analyzing real-time network security telemetry. Based on the event counts in the prompt, make a decision on whether to apply stricter mitigation rules ('stricter'), relax existing mitigations to restore quality of service ('relaxed'), or maintain the current state ('maintain'). You must output exactly a JSON object in this structure: {\"decision\": \"stricter\" | \"relaxed\" | \"maintain\"}. Do not include any explanation or markdown formatting in your response.",
                    "stream": False,
                    "format": "json"
                }

                # 4. Asynchronous POST request with short timeout
                response = requests.post(ollama_url, json=payload, timeout=3.0)
                
                decision = "maintain"
                if response.status_code == 200:
                    try:
                        inner_response = response.json().get("response", "").strip()
                        res_json = json.loads(inner_response)
                        decision = res_json.get("decision", "maintain").lower()
                    except Exception as parse_err:
                        self.logger.error(f"[LLM RESCALER] JSON parsing error: {parse_err}")
                else:
                    self.logger.error(f"[LLM RESCALER] Ollama HTTP status {response.status_code}")

                # 5. Apply the scaling logic based on the LLM's parsed JSON decision
                result_msg = self._adaptive_rescaler.adapt(decision)
                self.logger.info(
                    f"[LLM RESCALER] Model={self.model_name} | {result_msg} | "
                    f"Thresholds → log={self.log_threshold:.2f}, block={self.block_threshold:.2f}"
                )

            except requests.exceptions.RequestException as req_ex:
                self.logger.error(f"[LLM RESCALER] Ollama connection error / timeout: {req_ex}")
            except Exception as e:
                self.logger.error(f"[LLM RESCALER] Unexpected error in reasoning loop: {e}")

    def _periodic_graph_exporter(self):
        while True:
            hub.sleep(5)
            try:
                self._export_graph_snapshot()
            except Exception as e:
                self.logger.error(f"Error in periodic graph exporter: {e}")

    def _periodic_state_cleaner(self):
        while True:
            hub.sleep(0.5)
            if os.path.exists("/tmp/clear_controller_state"):
                try:
                    self.flow_key_to_state.clear()
                    self.flows.clear()
                    self.pending_inference.clear()
                    self.cookie_to_state.clear()
                    if os.path.exists("/tmp/clear_controller_state"):
                        os.remove("/tmp/clear_controller_state")
                    self.logger.info("[🧹 CONTROLLER STATE] Cleared all flow states.")
                except Exception as e:
                    self.logger.error(f"Error clearing controller state: {e}")

    # ------------------------------------------------------------------
    # OpenFlow switch setup
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"Switch {datapath.id} initialized. Table-miss flow rule installed.")

        self.create_meter(datapath, meter_id=1, rate_kbps=128)
        self.create_meter(datapath, meter_id=2, rate_kbps=128)
        self.create_meter(datapath, meter_id=3, rate_kbps=256)
        self.logger.info(f"Meters (ID=1: 128k, ID=2: 128k, ID=3: 256k) pre-created on switch {datapath.id}.")

    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=0, hard_timeout=0, cookie=0, flags=0, meter_id=None):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        inst = []
        if meter_id is not None:
            inst.append(parser.OFPInstructionMeter(meter_id))
        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))
        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=cookie,
            cookie_mask=0,
            table_id=0,
            command=ofproto.OFPFC_ADD,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            priority=priority,
            buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=flags,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    def create_meter(self, datapath, meter_id, rate_kbps):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        bands   = [parser.OFPMeterBandDrop(rate=rate_kbps, burst_size=0)]
        req     = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS,
            meter_id=meter_id,
            bands=bands
        )
        datapath.send_msg(req)

    def delete_meter(self, datapath, meter_id):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        req     = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_DELETE,
            flags=0,
            meter_id=meter_id,
            bands=[]
        )
        datapath.send_msg(req)

    def modify_meter(self, datapath, meter_id, rate_kbps):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        bands   = [parser.OFPMeterBandDrop(rate=rate_kbps, burst_size=0)]
        req     = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_MODIFY,
            flags=ofproto.OFPMF_KBPS,
            meter_id=meter_id,
            bands=bands
        )
        datapath.send_msg(req)

    # ------------------------------------------------------------------
    # Flow removed handler (self-healing)
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg      = ev.msg
        dp       = msg.datapath
        ofproto  = dp.ofproto
        cookie   = msg.cookie
        reason   = msg.reason

        reason_strs = {
            ofproto.OFPRR_IDLE_TIMEOUT: "idle timeout",
            ofproto.OFPRR_HARD_TIMEOUT: "hard timeout",
            ofproto.OFPRR_DELETE:       "deleted",
            ofproto.OFPRR_GROUP_DELETE: "group deleted"
        }
        reason_str = reason_strs.get(reason, f"unknown reason ({reason})")

        self.logger.info(
            f"[🔄 SELF-HEALING] Flow removed: dpid={dp.id} cookie={cookie} "
            f"priority={msg.priority} reason={reason_str}"
        )

        if cookie in self.cookie_to_state:
            state = self.cookie_to_state[cookie]
            self.logger.info(
                f"[🔄 SELF-HEALING] Restoring flow from state tracker. "
                f"Flow ID: {state.flow_id}, Src: {state.src}, Dst: {state.dst}, "
                f"Action: {state.mitigation_action}"
            )
            del self.cookie_to_state[cookie]

            keys_to_remove = [k for k, st in self.flow_key_to_state.items() if st == state]
            for key in keys_to_remove:
                if key in self.flow_key_to_state:
                    del self.flow_key_to_state[key]
                if key in self.flows:
                    del self.flows[key]
                src_mac, dst_mac, sport, dport, proto = key
                rkey = (dst_mac, src_mac, dport, sport, proto)
                if rkey in self.flows:
                    del self.flows[rkey]

            for ck in [c for c, st in self.cookie_to_state.items() if st == state]:
                del self.cookie_to_state[ck]

            self.logger.info(f"[🔄 SELF-HEALING] State cleaned for Flow ID: {state.flow_id}.")

    # ------------------------------------------------------------------
    # Decision logging
    # ------------------------------------------------------------------

    def _log_decision(self, state, action, xgb_score, if_score, gnn_class):
        import datetime
        log_payload = {
            "timestamp":      datetime.datetime.now().isoformat(),
            "flow_id":        state.flow_id,
            "xgb_score":      xgb_score,
            "if_score":       if_score,
            "gnn_class":      gnn_class,
            "action":         action,
            "action_duration": time.time() - state.created_time
        }
        log_file_path = os.path.join(os.getcwd(), "decision_audit.log")
        try:
            with open(log_file_path, "a") as f:
                f.write(json.dumps(log_payload) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to write to decision_audit.log: {e}")

    # ------------------------------------------------------------------
    # Graph snapshot exporter
    # ------------------------------------------------------------------

    def _export_graph_snapshot(self):
        import datetime

        ip_to_role = {}
        if os.path.exists("/tmp/current_run_config.json"):
            try:
                with open("/tmp/current_run_config.json", "r") as f:
                    ip_to_role = json.load(f)
            except Exception:
                pass

        nodes = set()
        edges = []

        flow_key_to_state_copy = list(self.flow_key_to_state.items())
        flows_copy = dict(self.flows)

        current_time = time.time()
        for key, state in flow_key_to_state_copy:
            if state.status in ['OBSERVING', 'READY', 'EVALUATED']:
                if current_time - state.last_updated <= 10.0:
                    src_ip = state.src
                    dst_ip = state.dst
                    if not src_ip or not dst_ip:
                        continue

                    nodes.add(src_ip)
                    nodes.add(dst_ip)

                    flow_stat = flows_copy.get(key)
                    if not flow_stat:
                        src_mac, dst_mac, sport, dport, proto = key
                        rkey = (dst_mac, src_mac, dport, sport, proto)
                        flow_stat = flows_copy.get(rkey)

                    pkt_count  = (flow_stat.fwd_pkts + flow_stat.bwd_pkts) if flow_stat else 0
                    byte_count = (flow_stat.tot_len_fwd + flow_stat.tot_len_bwd) if flow_stat else 0

                    edges.append({
                        "source":            src_ip,
                        "target":            dst_ip,
                        "flow_id":           state.flow_id,
                        "status":            state.status,
                        "weight_packets":    pkt_count,
                        "weight_bytes":      byte_count,
                        "mitigation_action": state.mitigation_action
                    })

        snapshot = {
            "timestamp": datetime.datetime.now().isoformat(),
            "nodes":     [{"id": node, "role": ip_to_role.get(node, "client")} for node in sorted(nodes)],
            "edges":     edges
        }

        filename = os.path.join(os.getcwd(), "graph_snapshots.json")
        try:
            with open(filename, "a") as f:
                f.write(json.dumps(snapshot) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to export graph snapshot: {e}")

    # ------------------------------------------------------------------
    # Asynchronous ML inference
    # ------------------------------------------------------------------

    def _run_inference_async(self, datapath, flow_key, flow_features):
        url = "http://localhost:8000/predict"
        payload = {
            "features":         flow_features,
            "scaler_id":        self.scaler_id,
            "xgb_model":        None,
            "safetynet_model":  None,
            "gnn_model":        None,
            "model_trust":      "NO_ACTION"
        }

        xgb_score = 0.0
        if_score  = 0.0
        gnn_class = "N/A"

        try:
            response = requests.post(url, json=payload, timeout=2.0)
            if response.status_code == 200:
                result    = response.json()
                action    = result.get("action", "ALLOW")
                verdict   = result.get("verdict", "BENIGN")
                xgb_score = result.get("binary_confidence", 0.0)
                if_score  = float(result.get("if_flag", 0.0))
                xgb_pred  = result.get("xgb", {}).get("flag", 0)
                gnn_class = result.get("gnn_prediction", "N/A")

                # Re-classify using evidence-adapted thresholds
                if xgb_pred == 0:
                    action = "ALLOW"
                elif xgb_score < self.log_threshold:
                    action = "LOG"
                elif xgb_score < self.block_threshold:
                    action = "RATE_LIMIT"
                else:
                    action = "BLOCK"

                # Uncertainty check → escalate via GNN policy mapper
                uncertain = (xgb_pred != if_score) or (
                    self.log_threshold - 0.1 <= xgb_score <= self.block_threshold + 0.05
                )
                if uncertain:
                    self.logger.info(
                        f"[🧠 UNCERTAIN FLOW] score={xgb_score:.2f}, IF={if_score}. Invoking GNN Mapper."
                    )
                    action = self._policy_mapper(gnn_class, action)
                    if action in ["SOURCE_IP_QUARANTINE", "DEST_SUBNET_METER", "TARPIT_MIRROR",
                                  "GLOBAL_RATE_LIMIT", "HONEYPOT_REDIRECT"]:
                        verdict = (
                            "KNOWN_ATTACK" if action in ["SOURCE_IP_QUARANTINE", "DEST_SUBNET_METER"]
                            else "SUSPICIOUS"
                        )
            else:
                self.logger.error(f"[FastAPI API Error] HTTP {response.status_code}: {response.text}")
                action  = "ALLOW"
                verdict = "BENIGN"
        except Exception as e:
            self.logger.error(f"[FastAPI Connection Error] {e}")
            action  = "ALLOW"
            verdict = "BENIGN"

        state = self.flow_key_to_state.get(flow_key)
        if not state:
            src_mac, dst_mac, sport, dport, proto = flow_key
            rkey  = (dst_mac, src_mac, dport, sport, proto)
            state = self.flow_key_to_state.get(rkey)

        if state:
            ev = EventMLInferenceComplete(
                datapath, flow_key, state, verdict, action, xgb_score, if_score, gnn_class
            )
            self.send_event_to_observers(ev)

    def _policy_mapper(self, gnn_class: str, fallback_action: str) -> str:
        if gnn_class == "N-to-1":
            return "DEST_SUBNET_METER"
        elif gnn_class == "1-to-N":
            return "SOURCE_IP_QUARANTINE"
        elif gnn_class == "1-to-1":
            return "TARPIT_MIRROR"
        elif gnn_class == "N-to-N":
            return "GLOBAL_RATE_LIMIT"
        elif gnn_class == "service_transition":
            return "HONEYPOT_REDIRECT"
        return fallback_action

    # ------------------------------------------------------------------
    # ML inference completion handler
    # ------------------------------------------------------------------

    @set_ev_cls(EventMLInferenceComplete, MAIN_DISPATCHER)
    def ml_inference_complete_handler(self, ev):
        datapath = ev.datapath
        flow_key = ev.flow_key
        state    = ev.flow_state
        verdict  = ev.verdict
        action   = ev.action

        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        src_mac, dst_mac, sport, dport, proto = flow_key

        if dport == 3306:
            action  = "HONEYPOT_REDIRECT"
            verdict = "SUSPICIOUS"

        self.logger.info(
            f"[🧠 ASYNC DECISION] Flow {state.flow_id}: verdict={verdict}, "
            f"action={action}, GNN={ev.gnn_class}"
        )

        if flow_key in self.pending_inference:
            del self.pending_inference[flow_key]
        rkey = (dst_mac, src_mac, dport, sport, proto)
        if rkey in self.pending_inference:
            del self.pending_inference[rkey]

        state.status         = 'EVALUATED'
        state.risk_zone      = (
            'Red'    if action in ['BLOCK', 'SOURCE_IP_QUARANTINE'] else
            'Yellow' if action in ['RATE_LIMIT', 'DEST_SUBNET_METER',
                                   'TARPIT_MIRROR', 'GLOBAL_RATE_LIMIT', 'HONEYPOT_REDIRECT']
            else 'Green'
        )
        state.mitigation_action = action
        state.expiry_time       = time.time() + (60.0 if action != 'ALLOW' else 15.0)

        ip_src = state.src
        ip_dst = state.dst
        dpid   = datapath.id

        # --- Install OpenFlow enforcement rules ---

        if action in ("BLOCK", "SOURCE_IP_QUARANTINE"):
            self.logger.warning(f"[🛡️ MITIGATION] SOURCE_IP_QUARANTINE. Src IP: {ip_src}")
            cookie_ip  = self.next_cookie; self.next_cookie += 1
            cookie_mac = self.next_cookie; self.next_cookie += 1
            self.cookie_to_state[cookie_ip]  = state
            self.cookie_to_state[cookie_mac] = state

            match_ip  = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=ip_src)
            self.add_flow(datapath, 100, match_ip,  [], idle_timeout=60,
                          cookie=cookie_ip,  flags=ofproto.OFPFF_SEND_FLOW_REM)

            match_mac = parser.OFPMatch(eth_src=src_mac)
            self.add_flow(datapath, 100, match_mac, [], idle_timeout=60,
                          cookie=cookie_mac, flags=ofproto.OFPFF_SEND_FLOW_REM)

        elif action == "DEST_SUBNET_METER":
            self.logger.warning(f"[🛡️ MITIGATION] DEST_SUBNET_METER. Dst IP: {ip_dst}")
            out_port = self.mac_to_port.get(dpid, {}).get(dst_mac, ofproto.OFPP_FLOOD)
            actions  = [parser.OFPActionOutput(out_port, 0)]
            cookie   = self.next_cookie; self.next_cookie += 1
            self.cookie_to_state[cookie] = state
            match_dst = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=ip_dst)
            self.add_flow(datapath, 100, match_dst, actions, idle_timeout=60,
                          cookie=cookie, flags=ofproto.OFPFF_SEND_FLOW_REM, meter_id=2)

        elif action == "TARPIT_MIRROR":
            self.logger.warning(f"[🛡️ MITIGATION] TARPIT_MIRROR. Src IP: {ip_src}")
            out_port = self.mac_to_port.get(dpid, {}).get(dst_mac, ofproto.OFPP_FLOOD)
            actions  = [parser.OFPActionOutput(out_port, 0)]
            monitor_port = next(
                (p for m, p in self.mac_to_port.get(dpid, {}).items() if m == "00:00:00:00:00:01"),
                None
            )
            if monitor_port is not None and monitor_port != out_port:
                actions.append(parser.OFPActionOutput(monitor_port, 0))
            cookie = self.next_cookie; self.next_cookie += 1
            self.cookie_to_state[cookie] = state
            match_fields = {'eth_type': ether.ETH_TYPE_IP, 'ipv4_src': ip_src, 'ipv4_dst': ip_dst}
            if proto == 6:
                match_fields['ip_proto'] = 6
                if sport: match_fields['tcp_src'] = sport
                if dport: match_fields['tcp_dst'] = dport
            elif proto == 17:
                match_fields['ip_proto'] = 17
                if sport: match_fields['udp_src'] = sport
                if dport: match_fields['udp_dst'] = dport
            self.add_flow(datapath, 100, parser.OFPMatch(**match_fields), actions,
                          idle_timeout=60, cookie=cookie,
                          flags=ofproto.OFPFF_SEND_FLOW_REM, meter_id=1)

        elif action == "GLOBAL_RATE_LIMIT":
            self.logger.warning(f"[🛡️ MITIGATION] GLOBAL_RATE_LIMIT. Src IP: {ip_src}")
            out_port = self.mac_to_port.get(dpid, {}).get(dst_mac, ofproto.OFPP_FLOOD)
            actions  = [parser.OFPActionOutput(out_port, 0)]
            cookie   = self.next_cookie; self.next_cookie += 1
            self.cookie_to_state[cookie] = state
            match_fields = {'eth_type': ether.ETH_TYPE_IP, 'ipv4_src': ip_src, 'ipv4_dst': ip_dst}
            if proto == 6:
                match_fields['ip_proto'] = 6
                if sport: match_fields['tcp_src'] = sport
                if dport: match_fields['tcp_dst'] = dport
            elif proto == 17:
                match_fields['ip_proto'] = 17
                if sport: match_fields['udp_src'] = sport
                if dport: match_fields['udp_dst'] = dport
            self.add_flow(datapath, 100, parser.OFPMatch(**match_fields), actions,
                          idle_timeout=60, cookie=cookie,
                          flags=ofproto.OFPFF_SEND_FLOW_REM, meter_id=3)

        elif action == "HONEYPOT_REDIRECT":
            self.logger.warning(f"[🛡️ MITIGATION] HONEYPOT_REDIRECT. Src IP: {ip_src} → 10.0.0.99")
            honeypot_port = (
                self.mac_to_port.get(dpid, {}).get("00:00:00:00:00:99") or
                self.mac_to_port.get(dpid, {}).get(dst_mac, ofproto.OFPP_FLOOD)
            )
            actions = [
                parser.OFPActionSetField(eth_dst="00:00:00:00:00:99"),
                parser.OFPActionSetField(ipv4_dst="10.0.0.99"),
                parser.OFPActionOutput(honeypot_port, 0)
            ]
            cookie = self.next_cookie; self.next_cookie += 1
            self.cookie_to_state[cookie] = state
            match_fields = {'eth_type': ether.ETH_TYPE_IP, 'ipv4_src': ip_src, 'ipv4_dst': ip_dst}
            if proto == 6:
                match_fields['ip_proto'] = 6
                if sport: match_fields['tcp_src'] = sport
                if dport: match_fields['tcp_dst'] = dport
            elif proto == 17:
                match_fields['ip_proto'] = 17
                if sport: match_fields['udp_src'] = sport
                if dport: match_fields['udp_dst'] = dport
            self.add_flow(datapath, 100, parser.OFPMatch(**match_fields), actions,
                          idle_timeout=60, cookie=cookie, flags=ofproto.OFPFF_SEND_FLOW_REM)

        elif action == "RATE_LIMIT":
            self.logger.warning(
                f"[🛡️ MITIGATION] RATE_LIMIT. Src IP: {ip_src}, MAC: {src_mac}, Verdict: {verdict}"
            )
            out_port = self.mac_to_port.get(dpid, {}).get(dst_mac, ofproto.OFPP_FLOOD)
            actions  = [parser.OFPActionOutput(out_port, 0)]
            cookie   = self.next_cookie; self.next_cookie += 1
            self.cookie_to_state[cookie] = state
            match_fields = {'eth_type': ether.ETH_TYPE_IP, 'ipv4_src': ip_src, 'ipv4_dst': ip_dst}
            if proto == 6:
                match_fields['ip_proto'] = 6
                if sport: match_fields['tcp_src'] = sport
                if dport: match_fields['tcp_dst'] = dport
            elif proto == 17:
                match_fields['ip_proto'] = 17
                if sport: match_fields['udp_src'] = sport
                if dport: match_fields['udp_dst'] = dport
            self.add_flow(datapath, 100, parser.OFPMatch(**match_fields), actions,
                          idle_timeout=60, cookie=cookie,
                          flags=ofproto.OFPFF_SEND_FLOW_REM, meter_id=1)

        else:
            # ALLOW — install efficient hardware-offloaded rule
            self.logger.info(f"[🧠 ASYNC DECISION] Flow {state.flow_id} → BENIGN. Installing allow rule.")
            out_port = self.mac_to_port.get(dpid, {}).get(dst_mac, ofproto.OFPP_FLOOD)
            actions  = [parser.OFPActionOutput(out_port, 0)]
            match_fields = {'eth_type': ether.ETH_TYPE_IP, 'ipv4_src': ip_src, 'ipv4_dst': ip_dst}
            if proto == 6:
                match_fields['ip_proto'] = 6
                if sport: match_fields['tcp_src'] = sport
                if dport: match_fields['tcp_dst'] = dport
            elif proto == 17:
                match_fields['ip_proto'] = 17
                if sport: match_fields['udp_src'] = sport
                if dport: match_fields['udp_dst'] = dport
            match  = parser.OFPMatch(**match_fields)
            cookie = self.next_cookie; self.next_cookie += 1
            self.cookie_to_state[cookie] = state
            self.add_flow(datapath, 10, match, actions,
                          idle_timeout=15, cookie=cookie, flags=ofproto.OFPFF_SEND_FLOW_REM)

        self._log_decision(state, action, ev.xgb_score, ev.if_score, ev.gnn_class)

    # ------------------------------------------------------------------
    # Packet-In handler
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether.ETH_TYPE_LLDP:
            return

        dst  = mac_to_str(eth.dst)
        src  = mac_to_str(eth.src)
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info(f"[DEBUG] PacketIn: src={src} → dst={dst} ethertype={hex(eth.ethertype)}")

        scapy_pkt = None
        try:
            scapy_pkt = Ether(msg.data)
        except Exception as e:
            self.logger.error(f"Scapy parse failed: {e}")

        is_ip  = False
        ip_src = None
        ip_dst = None
        if scapy_pkt and scapy_pkt.haslayer(IP):
            is_ip  = True
            ip_src = scapy_pkt[IP].src
            ip_dst = scapy_pkt[IP].dst

        if is_ip:
            ts    = time.time()
            sport = 0
            dport = 0
            proto = scapy_pkt[IP].proto

            if scapy_pkt.haslayer(TCP):
                sport = scapy_pkt[TCP].sport
                dport = scapy_pkt[TCP].dport
            elif scapy_pkt.haslayer(UDP):
                sport = scapy_pkt[UDP].sport
                dport = scapy_pkt[UDP].dport

            is_monitor = (ip_src == "10.0.0.1" or ip_dst == "10.0.0.1")
            is_iperf   = (5201 <= sport <= 5210 or 5201 <= dport <= 5210)

            if not (is_monitor or is_iperf):
                key  = (src, dst, sport, dport, proto)
                rkey = (dst, src, dport, sport, proto)

                state = self.flow_key_to_state.get(key) or self.flow_key_to_state.get(rkey)
                if state:
                    state.last_updated = ts

                # --- EVALUATED ---
                if state and state.status == 'EVALUATED':
                    action = state.mitigation_action
                    if action in ['BLOCK', 'SOURCE_IP_QUARANTINE']:
                        return

                    self.mac_to_port[dpid][src] = in_port
                    out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

                    if action == "HONEYPOT_REDIRECT":
                        hp_port = self.mac_to_port.get(dpid, {}).get("00:00:00:00:00:99")
                        if hp_port is not None:
                            out_port = hp_port
                        actions = [
                            parser.OFPActionSetField(eth_dst="00:00:00:00:00:99"),
                            parser.OFPActionSetField(ipv4_dst="10.0.0.99"),
                            parser.OFPActionOutput(out_port, 0)
                        ]
                    else:
                        actions = [parser.OFPActionOutput(out_port, 0)]
                        if action == "TARPIT_MIRROR":
                            monitor_port = next(
                                (p for m, p in self.mac_to_port.get(dpid, {}).items()
                                 if m == "00:00:00:00:00:01"),
                                None
                            )
                            if monitor_port is not None and monitor_port != out_port:
                                actions.append(parser.OFPActionOutput(monitor_port, 0))

                    data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                    out  = parser.OFPPacketOut(
                        datapath=datapath, buffer_id=msg.buffer_id,
                        in_port=in_port, actions=actions, data=data
                    )
                    datapath.send_msg(out)
                    return

                # --- READY ---
                elif state and state.status == 'READY':
                    if key in self.pending_inference:
                        self.pending_inference[key]["packet_count"] += 1
                    elif rkey in self.pending_inference:
                        self.pending_inference[rkey]["packet_count"] += 1

                    out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
                    actions  = [parser.OFPActionOutput(out_port, 0)]
                    data     = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                    datapath.send_msg(parser.OFPPacketOut(
                        datapath=datapath, buffer_id=msg.buffer_id,
                        in_port=in_port, actions=actions, data=data
                    ))
                    return

                # --- OBSERVING ---
                elif state and state.status == 'OBSERVING':
                    if rkey in self.flows:
                        flow  = self.flows[rkey]
                        is_fwd = False
                    else:
                        if key not in self.flows:
                            self.flows[key] = Flow(key, ts)
                        flow  = self.flows[key]
                        is_fwd = True

                    flow.add(scapy_pkt, ts, is_fwd=is_fwd)
                    feats        = flow.compute_features()
                    tot_fwd_pkts = int(feats.get("Tot Fwd Pkts", 0))

                    if tot_fwd_pkts >= 3:
                        state.status = 'READY'
                        self.pending_inference[key] = {
                            "timestamp":    ts,
                            "packet_count": tot_fwd_pkts
                        }
                        flow_features = {kk: feats[kk] for kk in FEATURE_KEYS}
                        hub.spawn(self._run_inference_async, datapath, key, flow_features)

                    out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
                    actions  = [parser.OFPActionOutput(out_port, 0)]
                    data     = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                    datapath.send_msg(parser.OFPPacketOut(
                        datapath=datapath, buffer_id=msg.buffer_id,
                        in_port=in_port, actions=actions, data=data
                    ))
                    return

                # --- NEW ---
                else:
                    if key not in self.flows:
                        self.flows[key] = Flow(key, ts)
                    flow = self.flows[key]
                    flow.add(scapy_pkt, ts, is_fwd=True)

                    flow_id = f"{src}_{dst}_{sport}_{dport}_{proto}"
                    state   = FlowState(
                        flow_id=flow_id, src=ip_src, dst=ip_dst,
                        created_time=ts, expiry_time=ts + 5.0,
                        last_updated=ts, status='OBSERVING'
                    )
                    self.flow_key_to_state[key] = state

                    # Temporary holding rule → controller under tarpit meter
                    actions_tarpit = [
                        parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
                    ]
                    match_fields = {
                        'eth_type': ether.ETH_TYPE_IP,
                        'ipv4_src': ip_src, 'ipv4_dst': ip_dst
                    }
                    if proto == 6:
                        match_fields['ip_proto'] = 6
                        if sport: match_fields['tcp_src'] = sport
                        if dport: match_fields['tcp_dst'] = dport
                    elif proto == 17:
                        match_fields['ip_proto'] = 17
                        if sport: match_fields['udp_src'] = sport
                        if dport: match_fields['udp_dst'] = dport

                    self.add_flow(datapath, 50, parser.OFPMatch(**match_fields),
                                  actions_tarpit, idle_timeout=5, meter_id=1)

                    out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
                    actions  = [parser.OFPActionOutput(out_port, 0)]
                    data     = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                    datapath.send_msg(parser.OFPPacketOut(
                        datapath=datapath, buffer_id=msg.buffer_id,
                        in_port=in_port, actions=actions, data=data
                    ))
                    return

        # Non-IP / whitelisted: standard MAC-learning forwarding
        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port, 0)]

        # Install 15-second hardware-offloaded allow rule for known unicast destinations
        if out_port != ofproto.OFPP_FLOOD and is_ip and ip_src and ip_dst:
            match_fields = {
                'eth_type': ether.ETH_TYPE_IP,
                'ipv4_src': ip_src, 'ipv4_dst': ip_dst
            }
            if proto == 6:
                match_fields['ip_proto'] = 6
                if sport: match_fields['tcp_src'] = sport
                if dport: match_fields['tcp_dst'] = dport
            elif proto == 17:
                match_fields['ip_proto'] = 17
                if sport: match_fields['udp_src'] = sport
                if dport: match_fields['udp_dst'] = dport
            self.add_flow(datapath, 10, parser.OFPMatch(**match_fields), actions, idle_timeout=15)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        ))

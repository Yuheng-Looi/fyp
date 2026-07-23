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
from pathlib import Path
from typing import Dict, Any, Optional
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
    def __init__(self, datapath, flow_key, flow_state, verdict, action, xgb_score=0.0, if_score=0.0):
        super(EventMLInferenceComplete, self).__init__()
        self.datapath = datapath
        self.flow_key = flow_key
        self.flow_state = flow_state
        self.verdict = verdict
        self.action = action
        self.xgb_score = xgb_score
        self.if_score = if_score

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


class LocalSDNController:
    """Offline compatibility and prediction helper class for simulation mode, delegating to the decoupled FastAPI server."""
    def evaluate_flow(self, flow_features: dict) -> dict:
        url = "http://localhost:8000/predict"
        payload = {
            "features": flow_features,
            "scaler_id": "default",
            "xgb_model": None,
            "safetynet_model": None,
            "gnn_model": None,
            "model_trust": "NO_ACTION"
        }
        try:
            response = requests.post(url, json=payload, timeout=2.0)
            if response.status_code == 200:
                result = response.json()
                return {
                    "verdict": result.get("verdict", "BENIGN"),
                    "action": result.get("action", "ALLOW")
                }
        except Exception:
            pass
        return {"verdict": "BENIGN", "action": "ALLOW"}


def mac_to_str(mac):
    if isinstance(mac, bytes):
        return ':'.join('%02x' % b for b in mac)
    return mac


class MLReactiveController(app_manager.RyuApp):
    """Reactive Machine Learning-driven SDN controller subclass."""
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MLReactiveController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flows: Dict[tuple, Flow] = {}
        self.cookie_to_state: Dict[int, FlowState] = {}
        self.flow_key_to_state: Dict[tuple, FlowState] = {}
        self.next_cookie = 1
        self.pending_inference = {}

        # Ensure custom log messages are explicitly printed to stderr
        import logging
        self.logger.handlers = []
        handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        # Register self as observer for custom ML complete event
        self.register_observer(EventMLInferenceComplete, self.name)

        # Start periodic Graph Snapshot Exporter task (runs every 5 seconds)
        hub.spawn(self._periodic_graph_exporter)
        # Start periodic state cleaner task (runs every 0.5 seconds)
        hub.spawn(self._periodic_state_cleaner)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry (send packet to controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"Switch {datapath.id} initialized. Table-miss flow rule installed.")

        # Pre-create the tarpit meter (ID=1, 128 Kbps)
        self.create_meter(datapath, meter_id=1, rate_kbps=128)
        self.logger.info(f"Tarpit meter (ID=1, 128 Kbps) pre-created on switch {datapath.id}.")

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0, cookie=0, flags=0, meter_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = []
        if meter_id is not None:
            inst.append(parser.OFPInstructionMeter(meter_id))
        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions))
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
        parser = datapath.ofproto_parser
        bands = [
            parser.OFPMeterBandDrop(rate=rate_kbps, burst_size=0)
        ]
        req = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS,
            meter_id=meter_id,
            bands=bands
        )
        datapath.send_msg(req)

    def delete_meter(self, datapath, meter_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_DELETE,
            flags=0,
            meter_id=meter_id,
            bands=[]
        )
        datapath.send_msg(req)

    def modify_meter(self, datapath, meter_id, rate_kbps):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        bands = [
            parser.OFPMeterBandDrop(rate=rate_kbps, burst_size=0)
        ]
        req = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_MODIFY,
            flags=ofproto.OFPMF_KBPS,
            meter_id=meter_id,
            bands=bands
        )
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto

        cookie = msg.cookie
        reason = msg.reason

        reason_strs = {
            ofproto.OFPRR_IDLE_TIMEOUT: "idle timeout",
            ofproto.OFPRR_HARD_TIMEOUT: "hard timeout",
            ofproto.OFPRR_DELETE: "deleted",
            ofproto.OFPRR_GROUP_DELETE: "group deleted"
        }
        reason_str = reason_strs.get(reason, f"unknown reason ({reason})")

        self.logger.info(
            f"[🔄 SELF-HEALING] Flow removed event received: dpid={dp.id} cookie={cookie} "
            f"priority={msg.priority} reason={reason_str}"
        )

        if cookie in self.cookie_to_state:
            state = self.cookie_to_state[cookie]
            self.logger.info(
                f"[🔄 SELF-HEALING] Restoring flow from state tracker. Flow ID: {state.flow_id}, "
                f"Src: {state.src}, Dst: {state.dst}, Mitigation Action: {state.mitigation_action}"
            )
            # Remove from cookie map
            del self.cookie_to_state[cookie]

            # Find and clean up flow key map and self.flows
            keys_to_remove = []
            for key, st in self.flow_key_to_state.items():
                if st == state:
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                if key in self.flow_key_to_state:
                    del self.flow_key_to_state[key]
                if key in self.flows:
                    del self.flows[key]

                # Also handle reverse key cleanup
                src_mac, dst_mac, sport, dport, proto = key
                rkey = (dst_mac, src_mac, dport, sport, proto)
                if rkey in self.flows:
                    del self.flows[rkey]

            # Clean up all other cookies mapped to the same state to prevent memory leak
            cookies_to_del = [ck for ck, st in self.cookie_to_state.items() if st == state]
            for ck in cookies_to_del:
                del self.cookie_to_state[ck]

            self.logger.info(f"[🔄 SELF-HEALING] State tracker cleaned for Flow ID: {state.flow_id}. Prevents memory leaks.")

    def _log_decision(self, state, action, xgb_score, if_score):
        import json
        import datetime
        
        log_payload = {
            "flow_id": state.flow_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "xgb_score": xgb_score,
            "if_score": if_score,
            "decision": action,
            "action_duration": time.time() - state.created_time
        }
        
        log_file_path = os.path.join(os.getcwd(), "decision_audit.log")
        try:
            with open(log_file_path, "a") as f:
                f.write(json.dumps(log_payload) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to write to decision_audit.log: {e}")

    def _periodic_graph_exporter(self):
        while True:
            hub.sleep(5)
            try:
                self._export_graph_snapshot()
            except Exception as e:
                self.logger.error(f"Error in periodic graph exporter: {e}")

    def _periodic_state_cleaner(self):
        import os
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


    def _export_graph_snapshot(self):
        import json
        import os
        import time
        import datetime

        # Load dynamic roles configuration if present
        ip_to_role = {}
        if os.path.exists("/tmp/current_run_config.json"):
            try:
                with open("/tmp/current_run_config.json", "r") as f:
                    ip_to_role = json.load(f)
            except Exception:
                pass

        nodes = set()
        edges = []

        # Thread-safe copy of dictionaries to avoid size changes during iteration
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

                    pkt_count = (flow_stat.fwd_pkts + flow_stat.bwd_pkts) if flow_stat else 0
                    byte_count = (flow_stat.tot_len_fwd + flow_stat.tot_len_bwd) if flow_stat else 0

                    edges.append({
                        "source": src_ip,
                        "target": dst_ip,
                        "flow_id": state.flow_id,
                        "status": state.status,
                        "weight_packets": pkt_count,
                        "weight_bytes": byte_count,
                        "mitigation_action": state.mitigation_action
                    })

        snapshot = {
            "timestamp": datetime.datetime.now().isoformat(),
            "nodes": [{"id": node, "role": ip_to_role.get(node, "client")} for node in sorted(nodes)],
            "edges": edges
        }

        filename = os.path.join(os.getcwd(), "graph_snapshots.json")
        try:
            with open(filename, "a") as f:
                f.write(json.dumps(snapshot) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to export graph snapshot: {e}")

    def _run_inference_async(self, datapath, flow_key, flow_features):
        url = "http://localhost:8000/predict"
        payload = {
            "features": flow_features,
            "scaler_id": "default",
            "xgb_model": None,
            "safetynet_model": None,
            "gnn_model": None,
            "model_trust": "NO_ACTION"
        }
        
        xgb_score = 0.0
        if_score = 0.0
        
        try:
            response = requests.post(url, json=payload, timeout=2.0)
            if response.status_code == 200:
                result = response.json()
                action = result.get("action", "ALLOW")
                verdict = result.get("verdict", "BENIGN")
                xgb_score = result.get("binary_confidence", 0.0)
                if_score = float(result.get("if_flag", 0.0))
            else:
                self.logger.error(f"[FastAPI API Error] HTTP {response.status_code}: {response.text}")
                action = "ALLOW"
                verdict = "BENIGN"
        except Exception as e:
            self.logger.error(f"[FastAPI Connection Error] Failed to connect to FastAPI: {e}")
            action = "ALLOW"
            verdict = "BENIGN"

        state = self.flow_key_to_state.get(flow_key)
        if not state:
            src_mac, dst_mac, sport, dport, proto = flow_key
            rkey = (dst_mac, src_mac, dport, sport, proto)
            state = self.flow_key_to_state.get(rkey)

        if state:
            ev = EventMLInferenceComplete(datapath, flow_key, state, verdict, action, xgb_score, if_score)
            self.send_event_to_observers(ev)

    @set_ev_cls(EventMLInferenceComplete, MAIN_DISPATCHER)
    def ml_inference_complete_handler(self, ev):
        datapath = ev.datapath
        flow_key = ev.flow_key
        state = ev.flow_state
        verdict = ev.verdict
        action = ev.action

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        src_mac, dst_mac, sport, dport, proto = flow_key
        
        self.logger.info(
            f"[🧠 ASYNC DECISION] Inference complete for Flow ID: {state.flow_id}. "
            f"Verdict: {verdict}, Action: {action}"
        )

        if flow_key in self.pending_inference:
            del self.pending_inference[flow_key]
        
        rkey = (dst_mac, src_mac, dport, sport, proto)
        if rkey in self.pending_inference:
            del self.pending_inference[rkey]

        state.status = 'EVALUATED'
        state.risk_zone = 'Red' if action == 'BLOCK' else ('Yellow' if action == 'RATE_LIMIT' else 'Green')
        state.mitigation_action = action
        state.expiry_time = time.time() + 60.0 if action in ["BLOCK", "RATE_LIMIT"] else time.time() + 10.0

        ip_src = state.src
        ip_dst = state.dst

        if action == "BLOCK":
            self.logger.warning(
                f"[🛡️ MITIGATION] Async BLOCK rule installation. Src IP: {ip_src}, Src MAC: {src_mac}. Verdict: {verdict}"
            )
            cookie_ip = self.next_cookie
            self.next_cookie += 1
            cookie_mac = self.next_cookie
            self.next_cookie += 1

            self.cookie_to_state[cookie_ip] = state
            self.cookie_to_state[cookie_mac] = state

            match_ip = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=ip_src)
            self.add_flow(datapath, 100, match_ip, [], idle_timeout=60, cookie=cookie_ip, flags=ofproto.OFPFF_SEND_FLOW_REM)

            match_mac = parser.OFPMatch(eth_src=src_mac)
            self.add_flow(datapath, 100, match_mac, [], idle_timeout=60, cookie=cookie_mac, flags=ofproto.OFPFF_SEND_FLOW_REM)

        elif action == "RATE_LIMIT":
            self.logger.warning(
                f"[🛡️ MITIGATION] Async RATE_LIMIT rule installation. Src IP: {ip_src}, Src MAC: {src_mac}. Verdict: {verdict}"
            )

            dpid = datapath.id
            if dst_mac in self.mac_to_port.get(dpid, {}):
                out_port = self.mac_to_port[dpid][dst_mac]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port, 0)]

            cookie = self.next_cookie
            self.next_cookie += 1
            self.cookie_to_state[cookie] = state

            match_fields = {
                'eth_type': ether.ETH_TYPE_IP,
                'ipv4_src': ip_src,
                'ipv4_dst': ip_dst,
            }
            if proto == 6:  # TCP
                match_fields['ip_proto'] = 6
                if sport:
                    match_fields['tcp_src'] = sport
                if dport:
                    match_fields['tcp_dst'] = dport
            elif proto == 17:  # UDP
                match_fields['ip_proto'] = 17
                if sport:
                    match_fields['udp_src'] = sport
                if dport:
                    match_fields['udp_dst'] = dport

            match_rl = parser.OFPMatch(**match_fields)
            self.add_flow(datapath, 100, match_rl, actions, idle_timeout=60, cookie=cookie, flags=ofproto.OFPFF_SEND_FLOW_REM, meter_id=1)

        else:
            self.logger.info(f"[🧠 ASYNC DECISION] Flow {state.flow_id} classified as BENIGN. Installing 5-tuple routing rule.")
            dpid = datapath.id
            if dst_mac in self.mac_to_port.get(dpid, {}):
                out_port = self.mac_to_port[dpid][dst_mac]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port, 0)]

            match_fields = {
                'eth_type': ether.ETH_TYPE_IP,
                'ipv4_src': ip_src,
                'ipv4_dst': ip_dst,
            }
            if proto == 6:  # TCP
                match_fields['ip_proto'] = 6
                if sport:
                    match_fields['tcp_src'] = sport
                if dport:
                    match_fields['tcp_dst'] = dport
            elif proto == 17:  # UDP
                match_fields['ip_proto'] = 17
                if sport:
                    match_fields['udp_src'] = sport
                if dport:
                    match_fields['udp_dst'] = dport
            match = parser.OFPMatch(**match_fields)
            
            cookie = self.next_cookie
            self.next_cookie += 1
            self.cookie_to_state[cookie] = state
            
            self.add_flow(datapath, 10, match, actions, idle_timeout=15, cookie=cookie, flags=ofproto.OFPFF_SEND_FLOW_REM)

        # Log decision to decision_audit.log
        self._log_decision(state, action, ev.xgb_score, ev.if_score)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Ryu packet parsing
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether.ETH_TYPE_LLDP:
            return

        dst = mac_to_str(eth.dst)
        src = mac_to_str(eth.src)
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Log all packet-in events for debugging
        self.logger.info(f"[DEBUG] PacketIn received: src={src} -> dst={dst} ethertype={hex(eth.ethertype)}")

        # Scapy parsing for ML inspection
        scapy_pkt = None
        try:
            scapy_pkt = Ether(msg.data)
        except Exception as e:
            self.logger.error(f"Scapy packet parsing failed: {e}")

        # Extract features and inspect if packet is IP
        is_ip = False
        ip_src = None
        ip_dst = None
        if scapy_pkt and scapy_pkt.haslayer(IP):
            is_ip = True
            ip_src = scapy_pkt[IP].src
            ip_dst = scapy_pkt[IP].dst

        if is_ip:
            ts = time.time()
            sport = 0
            dport = 0
            proto = scapy_pkt[IP].proto

            if scapy_pkt.haslayer(TCP):
                sport = scapy_pkt[TCP].sport
                dport = scapy_pkt[TCP].dport
            elif scapy_pkt.haslayer(UDP):
                sport = scapy_pkt[UDP].sport
                dport = scapy_pkt[UDP].dport

            # Whitelist/bypass logic for:
            # 1. Any traffic to/from monitor host h1 (10.0.0.1)
            # 2. Any iperf3 traffic (port 5201)
            is_monitor = (ip_src == "10.0.0.1" or ip_dst == "10.0.0.1")
            is_iperf = (5201 <= sport <= 5210 or 5201 <= dport <= 5210)

            if not (is_monitor or is_iperf):
                key = (src, dst, sport, dport, proto)
                rkey = (dst, src, dport, sport, proto)

                # Retrieve state if existing
                state = None
                if key in self.flow_key_to_state:
                    state = self.flow_key_to_state[key]
                elif rkey in self.flow_key_to_state:
                    state = self.flow_key_to_state[rkey]

                if state:
                    state.last_updated = ts

                # Case EVALUATED: The AI has already decided. Skip ML, apply the existing action.
                if state and state.status == 'EVALUATED':
                    action = state.mitigation_action
                    if action == 'BLOCK':
                        return  # Drop

                    self.mac_to_port[dpid][src] = in_port
                    if dst in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][dst]
                    else:
                        out_port = ofproto.OFPP_FLOOD
                    actions = [parser.OFPActionOutput(out_port, 0)]
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                               in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)
                    return

                # Case READY: The AI is currently thinking. Do not spawn a new thread. Simply update statistics/packet counts and return.
                elif state and state.status == 'READY':
                    if key in self.pending_inference:
                        self.pending_inference[key]["packet_count"] += 1
                    elif rkey in self.pending_inference:
                        self.pending_inference[rkey]["packet_count"] += 1

                    # Forward current packet to keep connection alive during background inference
                    if dst in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][dst]
                    else:
                        out_port = ofproto.OFPP_FLOOD
                    actions = [parser.OFPActionOutput(out_port, 0)]
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                               in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)
                    return

                # Case OBSERVING: Flow is under observation. Increment count. Once Tot Fwd Pkts >= 3, transition to READY and trigger inference.
                elif state and state.status == 'OBSERVING':
                    is_fwd = True
                    if rkey in self.flows:
                        flow = self.flows[rkey]
                        is_fwd = False
                    else:
                        if key not in self.flows:
                            self.flows[key] = Flow(key, ts)
                        flow = self.flows[key]
                    
                    flow.add(scapy_pkt, ts, is_fwd=is_fwd)

                    # Compute features to check packet count
                    feats = flow.compute_features()
                    tot_fwd_pkts = int(feats.get("Tot Fwd Pkts", 0))

                    if tot_fwd_pkts >= 3:
                        state.status = 'READY'
                        # Register in pending inference queue
                        self.pending_inference[key] = {
                            "timestamp": ts,
                            "packet_count": tot_fwd_pkts
                        }
                        # Spawn asynchronous ML inference
                        flow_features = {kk: feats[kk] for kk in FEATURE_KEYS}
                        hub.spawn(self._run_inference_async, datapath, key, flow_features)

                    # Forward current packet
                    if dst in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][dst]
                    else:
                        out_port = ofproto.OFPP_FLOOD
                    actions = [parser.OFPActionOutput(out_port, 0)]
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                               in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)
                    return

                # Case NEW: First packet of a flow. Create state as OBSERVING, install temporary holding rule, and transition state.
                else:
                    is_fwd = True
                    if key not in self.flows:
                        self.flows[key] = Flow(key, ts)
                    flow = self.flows[key]
                    flow.add(scapy_pkt, ts, is_fwd=is_fwd)

                    # Create FlowState marked as OBSERVING
                    flow_id = f"{src}_{dst}_{sport}_{dport}_{proto}"
                    state = FlowState(
                        flow_id=flow_id,
                        src=ip_src,
                        dst=ip_dst,
                        created_time=ts,
                        expiry_time=ts + 5.0, # Temporary hold expiry
                        last_updated=ts,
                        status='OBSERVING'
                    )
                    self.flow_key_to_state[key] = state

                    # Temporary Holding Action: Install 5-second OVS rule routing this flow to the controller under the Tarpit Meter (128 Kbps)
                    actions_tarpit = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
                    match_fields = {
                        'eth_type': ether.ETH_TYPE_IP,
                        'ipv4_src': ip_src,
                        'ipv4_dst': ip_dst,
                    }
                    if proto == 6:  # TCP
                        match_fields['ip_proto'] = 6
                        if sport:
                            match_fields['tcp_src'] = sport
                        if dport:
                            match_fields['tcp_dst'] = dport
                    elif proto == 17:  # UDP
                        match_fields['ip_proto'] = 17
                        if sport:
                            match_fields['udp_src'] = sport
                        if dport:
                            match_fields['udp_dst'] = dport

                    match_temp = parser.OFPMatch(**match_fields)
                    # Install rule with priority 50, idle_timeout=5, meter_id=1
                    self.add_flow(datapath, 50, match_temp, actions_tarpit, idle_timeout=5, meter_id=1)

                    # Forward current packet
                    if dst in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][dst]
                    else:
                        out_port = ofproto.OFPP_FLOOD
                    actions = [parser.OFPActionOutput(out_port, 0)]
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                               in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)
                    return

        # Learn MAC address for simple learning switch behavior (for non-IP or whitelisted traffic)
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port, 0)]

        # Install short-lived 5-tuple flow rule for IP traffic with known destination
        if out_port != ofproto.OFPP_FLOOD and is_ip and ip_src and ip_dst:
            match_fields = {
                'eth_type': ether.ETH_TYPE_IP,
                'ipv4_src': ip_src,
                'ipv4_dst': ip_dst,
            }
            if proto == 6:  # TCP
                match_fields['ip_proto'] = 6
                if sport:
                    match_fields['tcp_src'] = sport
                if dport:
                    match_fields['tcp_dst'] = dport
            elif proto == 17:  # UDP
                match_fields['ip_proto'] = 17
                if sport:
                    match_fields['udp_src'] = sport
                if dport:
                    match_fields['udp_dst'] = dport
            match = parser.OFPMatch(**match_fields)
            self.add_flow(datapath, 10, match, actions, idle_timeout=15)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

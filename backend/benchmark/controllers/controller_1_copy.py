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
from typing import Dict, Any

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

# Import Ryu components
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet

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
from anomaly_utils import SafetyNet

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


class LocalSDNController:
    """Offline compatibility and prediction helper class."""
    def __init__(self, xgb_path: str | None = None, safety_net_path: str | None = None, scaler_path: str | None = None):
        self.xgb_model_path = xgb_path or str(BACKEND_DIR / "models" / "xgb" / "xgb_binary_v1.json")
        self.safety_net_path = safety_net_path or str(BACKEND_DIR / "models" / "safetynet" / "safety_net_v1.pkl")
        self.scaler_path = scaler_path or str(BACKEND_DIR / "scalers" / "trichannel_scaler.pkl")

        self.xgb = None
        self.safety_net = None
        self.scaler = None

        self.load_models()

    def load_models(self) -> None:
        if os.path.exists(self.xgb_model_path):
            xgb_model = xgb.XGBClassifier()
            xgb_model.load_model(self.xgb_model_path)
            self.xgb = xgb_model
        if os.path.exists(self.safety_net_path):
            self.safety_net = joblib.load(self.safety_net_path)
        if os.path.exists(self.scaler_path):
            self.scaler = joblib.load(self.scaler_path)

    def evaluate_flow(self, flow_features: dict) -> dict:
        if self.xgb is None or self.scaler is None:
            return {"verdict": "BENIGN", "action": "ALLOW"}

        # Bypass evaluation if flow is in early stages to prevent blocking SYN/initial packets
        if float(flow_features.get("Tot Fwd Pkts", 0.0) or 0.0) < 3.0:
            return {"verdict": "BENIGN", "action": "ALLOW"}

        row = {col: float(flow_features.get(col, 0.0) or 0.0) for col in EXPECTED_COLUMNS}
        df = pd.DataFrame([row], columns=EXPECTED_COLUMNS)

        try:
            df_scaled = self.scaler.transform(df)
        except Exception:
            return {"verdict": "BENIGN", "action": "ALLOW"}

        # SafetyNet Isolation Forest prediction
        is_anomaly = 0
        if self.safety_net is not None:
            try:
                is_anomaly = int(self.safety_net.predict(df_scaled)[0])
            except Exception:
                pass

        # XGBoost prediction
        xgb_pred = 0
        raw_prob_attack = 0.0
        try:
            xgb_pred = int(self.xgb.predict(df_scaled)[0])
            raw_prob_attack = float(self.xgb.predict_proba(df_scaled)[0][1])
        except Exception:
            pass

        # Combined decision logic from infer_server.py
        binary_pred = xgb_pred
        binary_conf = raw_prob_attack
        if_flag = is_anomaly

        LOG_THRESHOLD = 0.5
        BLOCK_THRESHOLD = 0.75

        # Adaptive tuning based on Isolation Forest
        if if_flag == 1:
            LOG_THRESHOLD = max(0.45, LOG_THRESHOLD - 0.05)
            BLOCK_THRESHOLD = max(0.65, BLOCK_THRESHOLD - 0.1)

        # Action selection
        action = "ALLOW"
        if binary_pred == 0:
            action = "ALLOW"
        elif binary_conf < LOG_THRESHOLD:
            action = "LOG"
        elif binary_conf < BLOCK_THRESHOLD:
            action = "RATE_LIMIT"
        else:
            action = "BLOCK"

        # Map action to verdict
        verdict = "BENIGN"
        if action in ["BLOCK", "RATE_LIMIT"]:
            verdict = "KNOWN_ATTACK"
        elif action == "LOG":
            verdict = "SUSPICIOUS"

        return {"verdict": verdict, "action": action}


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
        self.local_controller = LocalSDNController()
        self.flows: Dict[tuple, Flow] = {}

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

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=0,
            cookie_mask=0,
            table_id=0,
            command=ofproto.OFPFC_ADD,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            priority=priority,
            buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

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

            if is_monitor or is_iperf:
                action = "ALLOW"
                result = {"verdict": "BENIGN", "action": "ALLOW"}
            else:
                # Maintain flow state
                key = (src, dst, sport, dport, proto)
                rkey = (dst, src, dport, sport, proto)

                if key in self.flows:
                    flow = self.flows[key]
                    is_fwd = True
                elif rkey in self.flows:
                    flow = self.flows[rkey]
                    is_fwd = False
                else:
                    flow = Flow(key, ts)
                    self.flows[key] = flow
                    is_fwd = True

                flow.add(scapy_pkt, ts, is_fwd=is_fwd)

                # Evaluate flow features
                feats = flow.compute_features()
                flow_features = {kk: feats[kk] for kk in FEATURE_KEYS}
                result = self.local_controller.evaluate_flow(flow_features)
                action = result.get("action", "ALLOW")
            if action in ["BLOCK", "RATE_LIMIT"]:
                self.logger.warning(
                    f"[🛡️ MITIGATION] Blocking malicious traffic. Src IP: {ip_src}, Src MAC: {src}. Reason: {result}"
                )

                # Install OpenFlow Drop flow rules (actions=[]) with idle_timeout=60, priority=100
                # 1. Drop rule for Source IP
                match_ip = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=ip_src)
                self.add_flow(datapath, 100, match_ip, [], idle_timeout=60)

                # 2. Drop rule for Source MAC
                match_mac = parser.OFPMatch(eth_src=src)
                self.add_flow(datapath, 100, match_mac, [], idle_timeout=60)

                # DO NOT forward the packet
                return

        # Learn MAC address for simple learning switch behavior
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port, 0)]

        # Install short-lived 5-tuple flow rule for IP traffic with known destination
        # idle_timeout=15: switch handles packets at line rate for 15s, then re-verifies
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

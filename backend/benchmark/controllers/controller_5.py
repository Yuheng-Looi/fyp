"""
controller_5.py — Naive Block-All Ryu OpenFlow 1.3 Controller

Behavior:
  - Block EVERYTHING from start (t = 0s) to end (t = 65s).
  - No L2 learning allowed.
  - Installs a high-priority wildcard DROP rule (OFPMatch() -> no instructions) on switch connection.
  - All host traffic is dropped indiscriminately across the entire timeline.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3


class NaiveBlockAllController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NaiveBlockAllController, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install global wildcard DROP rule immediately from t=0s
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=100, match=match, instructions=inst
        )
        datapath.send_msg(mod)
        self.logger.info(f"[controller_5] Wildcard DROP ALL rule installed on DPID {datapath.id} from start to end (t=0s..65s)")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # Drop any packet_in without installing forwarding rules
        pass

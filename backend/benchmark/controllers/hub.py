# simple_switch_13 benchmark is ran on ryu-manager ryu.app.simple_switch_13
# For more about ryu controller refer to https://ryu.readthedocs.io/en/latest/developing.html
# Below is the sample code from website, feel free to create new controller or modify this file as your own controller

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)

    def evaluate_flow(self, flow_features: dict) -> dict:
        return {"verdict": "BENIGN", "action": "ALLOW"}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        # OpenFlow 1.3 retrieves in_port from msg.match
        in_port = msg.match['in_port']

        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
             data = msg.data

        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        dp.send_msg(out)

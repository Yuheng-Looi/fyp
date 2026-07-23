from ryu.app import simple_switch_13

class MyClassicForwarder(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(MyClassicForwarder, self).__init__(*args, **kwargs)
        print("Classic forwarder is active and ready!")

    def evaluate_flow(self, flow_features: dict) -> dict:
        return {"verdict": "BENIGN", "action": "ALLOW"}

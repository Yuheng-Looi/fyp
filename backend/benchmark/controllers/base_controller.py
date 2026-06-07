from __future__ import annotations


class BaseController:
    def evaluate_flow(self, flow_features: dict) -> dict:
        return {"verdict": "BENIGN", "action": "ALLOW"}

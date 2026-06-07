class ScoringEngine:
    def __init__(self):
        self.scores = {}

    def evaluate(self, asset_states_history, qos_history, flow_history):
        state_map = {"ACTIVE": 1.0, "DEGRADED": 0.5, "DOWN": 0.0}

        # 1. SCS (Service Continuity Score)
        attack_ticks = [t for t in asset_states_history if t["phase"] == "attack"]
        scs_list = []
        for t in attack_ticks:
            scores = [state_map.get(s, 1.0) for s in t["states"].values()]
            if scores:
                scs_list.append(sum(scores) / len(scores))
        scs = sum(scs_list) / len(scs_list) if scs_list else 1.0

        # 2. QPS (QoS Preservation Score)
        base_qos_ticks = [t for t in qos_history if t["phase"] == "baseline"]
        attack_qos_ticks = [t for t in qos_history if t["phase"] == "attack"]
        
        base_throughputs = [sum(t["throughput"].values()) for t in base_qos_ticks]
        attack_throughputs = [sum(t["throughput"].values()) for t in attack_qos_ticks]
        
        avg_base_qos = sum(base_throughputs) / len(base_throughputs) if base_throughputs else 0.0
        avg_attack_qos = sum(attack_throughputs) / len(attack_throughputs) if attack_throughputs else 0.0
        
        qps = avg_attack_qos / max(avg_base_qos, 1.0)
        qps = min(1.0, max(0.0, qps))

        # 3. UIS (User Impact Score)
        clients = []
        if flow_history:
            clients = list(flow_history[0]["throughput"].keys())
        
        affected_clients = 0
        for c in clients:
            c_base_vals = [t["throughput"].get(c, 0.0) for t in flow_history if t["phase"] == "baseline"]
            c_attack_vals = [t["throughput"].get(c, 0.0) for t in flow_history if t["phase"] == "attack"]
            
            avg_base_c = sum(c_base_vals) / len(c_base_vals) if c_base_vals else 0.0
            avg_attack_c = sum(c_attack_vals) / len(c_attack_vals) if c_attack_vals else 0.0
            
            if avg_attack_c < 1000.0:
                affected_clients += 1
            elif avg_base_c > 0 and (avg_attack_c / avg_base_c) < 0.1:
                affected_clients += 1
        
        uis = 1.0 - (affected_clients / len(clients)) if clients else 1.0
        uis = min(1.0, max(0.0, uis))

        # 4. RES (Recovery Effectiveness Score)
        went_down = False
        for t in attack_ticks:
            if "DOWN" in t["states"].values():
                went_down = True
                break
        
        if not went_down:
            res = 1.0
        else:
            recovery_ticks = [t for t in asset_states_history if t["phase"] == "recovery"]
            last_rec_tick = recovery_ticks[-1] if recovery_ticks else None
            last_att_tick = attack_ticks[-1] if attack_ticks else None
            
            if last_rec_tick and last_att_tick:
                rec_scores = [state_map.get(s, 1.0) for s in last_rec_tick["states"].values()]
                att_scores = [state_map.get(s, 1.0) for s in last_att_tick["states"].values()]
                
                avg_rec = sum(rec_scores) / len(rec_scores) if rec_scores else 1.0
                avg_att = sum(att_scores) / len(att_scores) if att_scores else 1.0
                
                res = avg_rec / max(avg_att, 0.1)
            else:
                res = 1.0
        res = min(1.0, max(0.0, res))

        # 5. NRS (Network Resilience Score)
        nrs = (0.30 * scs) + (0.25 * qps) + (0.25 * uis) + (0.20 * res)
        
        self.scores = {
            "SCS": scs,
            "QPS": qps,
            "UIS": uis,
            "RES": res,
            "NRS": nrs
        }
        print("[eval] Scoring evaluation complete")
        return self.scores

    def get_scores(self):
        return self.scores

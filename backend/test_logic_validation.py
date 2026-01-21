
def decide_action(binary_pred, binary_conf, model_trust="NO_ACTION", if_flag=0):
    # -- Thresholds --
    LOG_THRESHOLD = 0.5
    BLOCK_THRESHOLD = 0.75
    
    # Adaptive tuning
    if if_flag == 1:
        LOG_THRESHOLD = max(0.45, LOG_THRESHOLD - 0.05)
        BLOCK_THRESHOLD = max(0.65, BLOCK_THRESHOLD - 0.1)
        
    # -- Decision Logic --
    action = "ALLOW"
    
    if model_trust == "RETRAIN":
        action = "ALERT_ONLY"
    elif binary_pred == 0:
        action = "ALLOW"
    elif binary_conf < LOG_THRESHOLD:
        action = "LOG"
    elif binary_conf < BLOCK_THRESHOLD:
        action = "RATE_LIMIT"
    else:
        action = "BLOCK"
    return action

def test_logic():
    print("Testing Decision Logic...")
    
    # 1. BENIGN -> always ALLOW
    assert decide_action(0, 0.99, "NO_ACTION", 0) == "ALLOW", "Failed: BENIGN should be ALLOW"
    assert decide_action(0, 0.10, "NO_ACTION", 1) == "ALLOW", "Failed: BENIGN with IF=1 should be ALLOW"
    
    # 2. RETRAIN -> always ALERT_ONLY
    assert decide_action(1, 0.99, "RETRAIN", 0) == "ALERT_ONLY", "Failed: RETRAIN should be ALERT_ONLY"
    assert decide_action(0, 0.99, "RETRAIN", 0) == "ALERT_ONLY", "Failed: RETRAIN should override BENIGN" # Wait, benign logic is `elif binary_pred == 0`. RETRAIN is `if`. So RETRAIN overrides BENIGN. Which makes sense for safety/alerting but wait...
    # Prompt says: "if model_trust == 'RETRAIN': action = 'ALERT_ONLY' elif binary_pred == 0: action = 'ALLOW'"
    # So yes, RETRAIN overrides BENIGN.
    
    # 3. ATTACK + low confidence -> LOG
    # Default LOG_THRESHOLD = 0.5
    assert decide_action(1, 0.49, "NO_ACTION", 0) == "LOG", "Failed: Low conf attack should be LOG"
    
    # 4. ATTACK + high confidence -> BLOCK
    # Default BLOCK_THRESHOLD = 0.75
    assert decide_action(1, 0.76, "NO_ACTION", 0) == "BLOCK", "Failed: High conf attack should be BLOCK"
    
    # 5. Adaptive Thresholds
    # if_flag=1 -> LOG_THR=0.45, BLOCK_THR=0.65
    
    # Case: Conf 0.46. With IF=0 (Thr=0.5) -> LOG. With IF=1 (Thr=0.45) -> RATE_LIMIT (since < 0.65) or LOG (since > 0.45)?
    # Logic: < LOG_THRESHOLD -> LOG.
    # 0.46 > 0.45. So it goes to next check: < BLOCK_THRESHOLD?
    # 0.46 < 0.65. So RATE_LIMIT.
    assert decide_action(1, 0.46, "NO_ACTION", 1) == "RATE_LIMIT", "Failed: Adaptive threshold logic for RATE_LIMIT"
    
    # Case: Conf 0.66. With IF=0 (Thr=0.75) -> RATE_LIMIT. With IF=1 (Thr=0.65) -> BLOCK.
    assert decide_action(1, 0.66, "NO_ACTION", 1) == "BLOCK", "Failed: Adaptive threshold logic for BLOCK"

    print("✅ All logic tests passed!")

if __name__ == "__main__":
    test_logic()

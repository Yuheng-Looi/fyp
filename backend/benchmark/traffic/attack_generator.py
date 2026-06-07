class AttackGenerator:
    def __init__(self):
        self._active = False

    def start_attack(self, scenario):
        self._active = True
        name = scenario.get("name", "unknown")
        print(f"[attack] Attack started: {name}")

    def stop_attack(self):
        self._active = False
        print("[attack] Attack stopped")

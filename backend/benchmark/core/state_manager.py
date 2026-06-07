class StateManager:
    def __init__(self):
        self._assets = {}

    def set_asset_state(self, asset_name, state):
        self._assets[asset_name] = state

    def get_asset_state(self, asset_name, default=None):
        return self._assets.get(asset_name, default)

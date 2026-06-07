import time

import yaml


class TimelineManager:
    def __init__(self, config_path, time_provider=None, sleep_fn=None):
        self._config_path = config_path
        self._callbacks = {}
        self._time = time_provider or time.monotonic
        self._sleep = sleep_fn or time.sleep

        with open(config_path, "r", encoding="utf-8") as handle:
            self._config = yaml.safe_load(handle) or {}

        self._durations = self._config.get("timeline", {})
        self._tick_interval = self._config.get("monitoring", {}).get("tick_interval", 1)
        self._phase_order = ["warmup", "baseline", "attack", "recovery", "evaluation"]
        self._schedule = self._build_schedule()

    def _build_schedule(self):
        schedule = []
        cursor = 0
        for phase in self._phase_order:
            duration = int(self._durations.get(phase, 0))
            start = cursor
            end = cursor + duration
            schedule.append({"phase": phase, "start": start, "end": end, "duration": duration})
            cursor = end
        return schedule

    @property
    def total_duration(self):
        if not self._schedule:
            return 0
        return self._schedule[-1]["end"]

    def register(self, event_name, callback):
        self._callbacks.setdefault(event_name, []).append(callback)

    def run(self, real_time=True):
        if not self._schedule:
            return

        self._emit("on_timeline_start", 0)

        current_index = 0
        current = self._schedule[current_index]
        elapsed = 0.0

        self._emit_phase_start(current["phase"], elapsed)

        start_time = self._time()
        next_tick = start_time

        while True:
            if real_time:
                now = self._time()
                elapsed = now - start_time
            else:
                elapsed = float(elapsed)

            while elapsed >= current["end"]:
                self._emit_phase_end(current["phase"], elapsed)

                if current["phase"] == "evaluation":
                    self._emit("on_timeline_complete", elapsed)
                    return

                current_index += 1
                current = self._schedule[current_index]
                self._emit_phase_start(current["phase"], elapsed)

                if current["phase"] == "evaluation" and current["duration"] == 0:
                    self._emit_phase_end(current["phase"], elapsed)
                    self._emit("on_timeline_complete", elapsed)
                    return

            self._emit("on_tick", elapsed)

            if real_time:
                next_tick += self._tick_interval
                sleep_for = max(0.0, next_tick - self._time())
                if sleep_for > 0:
                    self._sleep(sleep_for)
            else:
                elapsed += self._tick_interval

    def _emit(self, event_name, *args):
        for callback in self._callbacks.get(event_name, []):
            callback(*args)

    def _emit_phase_start(self, phase, elapsed):
        self._emit("on_phase_start", phase, elapsed)
        self._emit(f"on_{phase}_start", elapsed)

    def _emit_phase_end(self, phase, elapsed):
        self._emit("on_phase_end", phase, elapsed)
        self._emit(f"on_{phase}_end", elapsed)

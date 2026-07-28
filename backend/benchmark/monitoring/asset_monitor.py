import subprocess
import threading
import time
import urllib.error
import urllib.request


class AssetMonitor:
    def __init__(self, state_manager, config):
        monitoring = config.get("monitoring", {})
        self._state_manager = state_manager
        self._assets = list(monitoring.get("assets", []))
        self._poll_interval = float(monitoring.get("poll_interval", 1))
        self._timeout_seconds = float(monitoring.get("timeout_seconds", 2))
        self._latency_threshold_ms = float(monitoring.get("latency_threshold_ms", 500.0))
        self._down_threshold = int(monitoring.get("down_threshold", 5))
        self._ping_enabled = bool(monitoring.get("ping_enabled", False))

        self._monitor_host = None
        self._running = False
        self._thread = None
        self._lock = threading.Lock()
        self._probe_history = []
        self._state_history = []
        self._current_state = {}
        self._failure_counts = {}

    def set_monitor_host(self, host):
        self._monitor_host = host

    @property
    def probe_history(self):
        with self._lock:
            return list(self._probe_history)

    @property
    def state_history(self):
        with self._lock:
            return list(self._state_history)

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        print("[monitor] Asset monitor started")

    def stop(self):
        if not self._running:
            return
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        print("[monitor] Asset monitor stopped")

    def _run_loop(self):
        while self._running:
            loop_start = time.monotonic()
            self._poll_assets()
            elapsed = time.monotonic() - loop_start
            sleep_for = max(0.0, self._poll_interval - elapsed)
            if sleep_for:
                time.sleep(sleep_for)

    def _poll_assets(self):
        for asset in self._assets:
            result = self._probe_asset(asset)
            self._update_state(asset, result)

    def _probe_asset(self, asset):
        ip = asset.get("ip")
        port = int(asset.get("port", 80))
        protocol = asset.get("protocol", "http")
        url = f"{protocol}://{ip}:{port}/"

        if self._monitor_host is not None:
            status_code, latency_ms, error = self._probe_http_via_host(url)
        else:
            status_code, latency_ms, error = self._probe_http_root(url)

        ping_loss = None
        if self._ping_enabled:
            ping_loss = self._probe_ping(ip)

        return {
            "status_code": status_code,
            "latency_ms": latency_ms,
            "error": error,
            "ping_loss": ping_loss,
        }

    def _probe_http_root(self, url):
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(url, timeout=self._timeout_seconds) as response:
                latency_ms = (time.perf_counter() - start) * 1000
                return response.getcode(), latency_ms, None
        except urllib.error.HTTPError as err:
            latency_ms = (time.perf_counter() - start) * 1000
            return err.code, latency_ms, str(err)
        except Exception as err:
            return None, None, str(err)

    def _probe_http_via_host(self, url):
        """Probe HTTP service from monitor host (h1) using curl with robust parsing."""
        try:
            parts = url.split("://")[1].split("/")[0].split(":")
            ip = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 8080
        except Exception as exc:
            return None, None, f"url-parse-error: {exc}"

        timeout = int(max(2, self._timeout_seconds))
        cmd = f"curl -s -o /dev/null -w '%{{http_code}} %{{time_total}}\\n' --max-time {timeout} http://{ip}:{port}/"
        try:
            output = self._monitor_host.cmd(cmd).strip()
        except Exception as exc:
            return None, None, f"cmd-error: {exc}"

        if not output:
            return None, None, "no-output"

        # Search line-by-line for HTTP status code and response time
        for line in output.splitlines():
            line = line.strip()
            tokens = line.split()
            if len(tokens) >= 2 and tokens[0].isdigit():
                try:
                    code = int(tokens[0])
                    time_sec = float(tokens[1])
                    lat_ms = time_sec * 1000.0
                    if code > 0:
                        return code, lat_ms, None
                except ValueError:
                    continue

        return None, 2000.0, f"parse-error: {output[:80]}"

    def _probe_ping(self, ip):
        cmd = f"ping -c 1 -W {int(self._timeout_seconds)} {ip}"
        if self._monitor_host is not None:
            output = self._monitor_host.cmd(cmd)
        else:
            try:
                output = subprocess.check_output(cmd, shell=True, text=True)
            except Exception:
                return 100

        for line in output.splitlines():
            if "packet loss" in line:
                percent = line.split("packet loss")[0].split()[-1]
                try:
                    return int(percent.strip("%"))
                except ValueError:
                    return 100
        return 100

    def _update_state(self, asset, result):
        name = asset.get("name", asset.get("ip", "unknown"))
        status_code = result.get("status_code")
        latency_ms = result.get("latency_ms")
        error = result.get("error")
        ping_loss = result.get("ping_loss")

        failures = self._failure_counts.get(name, 0)

        if status_code == 200:
            failures = 0
            if latency_ms is not None and latency_ms > 2000.0:
                state = "DOWN"
            elif latency_ms is not None and latency_ms > self._latency_threshold_ms:
                state = "DEGRADED"
            elif ping_loss is not None and ping_loss > 0:
                state = "DEGRADED"
            else:
                state = "ACTIVE"
        else:
            failures += 1
            if failures >= self._down_threshold:
                state = "DOWN"
            else:
                state = "DEGRADED"

        self._failure_counts[name] = failures

        probe_entry = {
            "timestamp": time.time(),
            "asset": name,
            "probe_type": "http",
            "state": state,
            "latency_ms": latency_ms if latency_ms is not None else 2000.0,
            "status_code": status_code,
            "error": error,
            "ping_loss": ping_loss,
        }

        with self._lock:
            self._probe_history.append(probe_entry)
            previous = self._current_state.get(name)
            self._current_state[name] = state
            if previous != state:
                entry = {
                    "timestamp": time.time(),
                    "asset": name,
                    "state": state,
                    "latency_ms": latency_ms,
                    "status_code": status_code,
                    "error": error,
                    "ping_loss": ping_loss,
                }
                self._state_history.append(entry)
                self._state_manager.set_asset_state(name, state)
                print(f"[monitor] {name} -> {state} (code={status_code}, lat={f'{latency_ms:.1f}ms' if latency_ms is not None else 'None'}, err={error})")

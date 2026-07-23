from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


SQL_PATTERNS = (
    "union select",
    "' or '1'='1",
    "sleep(",
    "--",
)


class VictimHandler(BaseHTTPRequestHandler):
    compromised_count = 0

    def _write_response(self, status: int, body: bytes, content_type: str = "text/plain; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        body = f"Bionic victim alive on {parsed.path}\n".encode("utf-8")
        self._write_response(200, body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length).decode("utf-8", errors="ignore")
        payload_lower = payload.lower()
        leaked = any(pattern in payload_lower for pattern in SQL_PATTERNS) or "union select" in payload_lower
        if leaked:
            VictimHandler.compromised_count += 1
            body = f"LEAKED:{payload}\n".encode("utf-8")
        else:
            body = b"POST received\n"
        self._write_response(200, body)

    def log_message(self, format, *args):  # noqa: A003
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic victim HTTP server for benchmark runs")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=80)
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), VictimHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import json
import random
import socket
import time
import threading

import requests


SQLI_PAYLOADS = (
    "1' UNION SELECT NULL,NULL,NULL--",
    "' OR '1'='1' --",
    "admin' OR 1=1;--",
)


def emit(event: dict) -> None:
    print(json.dumps(event, separators=(",", ":")), flush=True)


def benign_worker(args: argparse.Namespace) -> None:
    rng = random.Random(args.seed)
    session = requests.Session()
    deadline = time.time() + args.duration
    iteration = 0

    while time.time() < deadline:
        iteration += 1
        started = time.time()
        status_code = None
        response_length = 0
        error = None
        try:
            response = session.get(args.url, timeout=args.timeout)
            status_code = response.status_code
            response_length = len(response.content)
        except Exception as exc:  # pragma: no cover - network dependent
            error = str(exc)
        emit(
            {
                "ts": started,
                "host": args.host,
                "src_ip": args.src_ip,
                "dst_ip": args.dst_ip,
                "dst_port": args.dst_port,
                "kind": "benign",
                "label": "BENIGN",
                "malicious": False,
                "iteration": iteration,
                "status_code": status_code,
                "response_length": response_length,
                "error": error,
                "bytes_out": 320,
                "bytes_in": response_length,
            }
        )
        if time.time() >= deadline:
            break
        time.sleep(rng.uniform(args.min_sleep, args.max_sleep))


def _ddos_attempt(args: argparse.Namespace, thread_index: int, burst_index: int, attempt_index: int) -> dict:
    started = time.time()
    status_code = None
    error = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(args.timeout)
        sock.connect((args.dst_ip, args.dst_port))
        sock.close()
        status_code = 200
    except Exception as exc:  # pragma: no cover - network dependent
        error = str(exc)
    return {
        "ts": started,
        "host": args.host,
        "src_ip": args.src_ip,
        "dst_ip": args.dst_ip,
        "dst_port": args.dst_port,
        "kind": "ddos_syn",
        "label": "ATTACK",
        "malicious": True,
        "thread": thread_index,
        "burst": burst_index,
        "attempt": attempt_index,
        "status_code": status_code,
        "error": error,
        "bytes_out": 64,
        "bytes_in": 0,
    }


def ddos_worker(args: argparse.Namespace) -> None:
    deadline = time.time() + args.duration

    def worker_loop(thread_index: int) -> None:
        burst_index = 0
        while time.time() < deadline:
            burst_index += 1
            successes = 0
            failures = 0
            burst_started = time.time()
            for attempt_index in range(args.burst_size):
                event = _ddos_attempt(args, thread_index, burst_index, attempt_index + 1)
                if event["status_code"] == 200:
                    successes += 1
                else:
                    failures += 1
                emit(event)
                if time.time() >= deadline:
                    break
            emit(
                {
                    "ts": burst_started,
                    "host": args.host,
                    "src_ip": args.src_ip,
                    "dst_ip": args.dst_ip,
                    "dst_port": args.dst_port,
                    "kind": "ddos_syn_burst",
                    "label": "ATTACK",
                    "thread": thread_index,
                    "burst": burst_index,
                    "attempts": args.burst_size,
                    "successes": successes,
                    "failures": failures,
                    "status_code": 200 if successes else None,
                    "bytes_out": args.burst_size * 64,
                    "bytes_in": 0,
                }
            )
            time.sleep(args.pause)

    threads = []
    for idx in range(args.threads):
        thread = threading.Thread(target=worker_loop, args=(idx + 1,), daemon=True)
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()


def semantic_worker(args: argparse.Namespace) -> None:
    rng = random.Random(args.seed)
    session = requests.Session()
    deadline = time.time() + args.duration
    payload_index = 0

    while time.time() < deadline:
        payload = SQLI_PAYLOADS[payload_index % len(SQLI_PAYLOADS)]
        payload_index += 1
        started = time.time()
        status_code = None
        response_text = ""
        error = None
        try:
            response = session.post(args.url, data=payload, timeout=args.timeout)
            status_code = response.status_code
            response_text = response.text[:256]
        except Exception as exc:  # pragma: no cover - network dependent
            error = str(exc)
        leak_detected = False
        try:
            if response_text and "LEAKED:" in response_text:
                leak_detected = True
        except Exception:
            leak_detected = False
        emit(
            {
                "ts": started,
                "host": args.host,
                "src_ip": args.src_ip,
                "dst_ip": args.dst_ip,
                "dst_port": args.dst_port,
                "kind": "semantic_sqli",
                "label": "ATTACK",
                "malicious": True,
                "payload": payload,
                "status_code": status_code,
                "response_text": response_text,
                "leak_detected": leak_detected,
                "error": error,
                "bytes_out": len(payload),
                "bytes_in": len(response_text),
            }
        )
        if time.time() >= deadline:
            break
        time.sleep(rng.uniform(args.min_sleep, args.max_sleep))


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic traffic worker")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--host", required=True)
    common.add_argument("--src-ip", required=True)
    common.add_argument("--dst-ip", required=True)
    common.add_argument("--dst-port", type=int, default=80)
    common.add_argument("--duration", type=float, required=True)
    common.add_argument("--timeout", type=float, default=2.0)
    common.add_argument("--seed", type=int, default=1)

    benign = subparsers.add_parser("benign", parents=[common])
    benign.add_argument("--url", required=True)
    benign.add_argument("--min-sleep", type=float, default=1.0)
    benign.add_argument("--max-sleep", type=float, default=3.0)
    benign.set_defaults(func=benign_worker)

    ddos = subparsers.add_parser("ddos", parents=[common])
    ddos.add_argument("--threads", type=int, default=4)
    ddos.add_argument("--burst-size", type=int, default=8)
    ddos.add_argument("--pause", type=float, default=0.4)
    ddos.set_defaults(func=ddos_worker)

    semantic = subparsers.add_parser("semantic", parents=[common])
    semantic.add_argument("--url", required=True)
    semantic.add_argument("--min-sleep", type=float, default=0.8)
    semantic.add_argument("--max-sleep", type=float, default=1.5)
    semantic.set_defaults(func=semantic_worker)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

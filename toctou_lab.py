"""Local-only, reproducible one-time coupon TOCTOU demonstration."""

import argparse
import http.client
import json
import platform
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class CouponState:
    def __init__(self, mode):
        self.mode = mode
        self.used = False
        self.redemptions = 0
        self.events = []
        self.event_lock = threading.Lock()
        self.transaction_lock = threading.Lock()
        self.barrier = threading.Barrier(2) if mode == "vulnerable_parallel" else None
        self.started = time.monotonic()

    def record(self, request_id, action, **details):
        with self.event_lock:
            self.events.append(
                {
                    "sequence": len(self.events) + 1,
                    "elapsed_ms": round((time.monotonic() - self.started) * 1000, 3),
                    "request_id": request_id,
                    "action": action,
                    **details,
                }
            )

    def redeem(self, request_id):
        if self.mode == "fixed_parallel":
            with self.transaction_lock:
                self.record(request_id, "lock_acquired")
                return self._check_and_use(request_id)
        return self._check_and_use(request_id)

    def _check_and_use(self, request_id):
        self.record(request_id, "check", used=self.used)
        if self.used:
            self.record(request_id, "rejected", reason="already_used")
            return False, self.redemptions

        if self.barrier is not None:
            self.record(request_id, "waiting_at_race_window")
            self.barrier.wait(timeout=5)

        # This write is deliberately outside the earlier check in vulnerable mode.
        with self.event_lock:
            self.used = True
            self.redemptions += 1
            count = self.redemptions
        self.record(request_id, "accepted", total_redemptions=count)
        return True, count


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/redeem" or self.headers.get("X-Demo-User") != "alice":
                self.send_error(404)
                return
            request_id = self.headers.get("X-Request-ID", "unknown")
            state.record(request_id, "received", path=self.path)
            try:
                accepted, count = state.redeem(request_id)
            except threading.BrokenBarrierError:
                state.record(request_id, "barrier_timeout")
                self.send_error(500, "race synchronization failed")
                return
            body = json.dumps(
                {"accepted": accepted, "total_redemptions": count},
                separators=(",", ":"),
            ).encode("ascii")
            self.send_response(200 if accepted else 409)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format_string, *args):
            pass

    return Handler


def issue_request(port, request_id):
    headers = {"X-Demo-User": "alice", "X-Request-ID": request_id}
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    try:
        conn.request("POST", "/redeem", body=b"", headers=headers)
        response = conn.getresponse()
        body = response.read().decode("ascii")
        request_headers = dict(headers)
        request_headers["Host"] = f"127.0.0.1:{port}"
        request_headers["Content-Length"] = "0"
        return {
            "request_id": request_id,
            "request": {
                "method": "POST",
                "path": "/redeem",
                "headers": request_headers,
                "body": "",
            },
            "response": {
                "status": response.status,
                "reason": response.reason,
                "headers": dict(response.getheaders()),
                "body": json.loads(body),
            },
        }
    finally:
        conn.close()


def run_scenario(mode):
    state = CouponState(mode)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    port = server.server_address[1]
    results = {}

    try:
        if mode == "vulnerable_sequential":
            for request_id in ("A", "B"):
                results[request_id] = issue_request(port, request_id)
        else:
            start = threading.Event()
            errors = []

            def worker(request_id):
                start.wait()
                try:
                    results[request_id] = issue_request(port, request_id)
                except Exception as exc:
                    errors.append(f"{request_id}: {exc}")

            workers = [
                threading.Thread(target=worker, args=(request_id,))
                for request_id in ("A", "B")
            ]
            for worker_thread in workers:
                worker_thread.start()
            start.set()
            for worker_thread in workers:
                worker_thread.join(timeout=10)
            if errors or any(worker_thread.is_alive() for worker_thread in workers):
                raise RuntimeError(f"scenario {mode} failed: {errors}")

        ordered = [results[request_id] for request_id in ("A", "B")]
        accepted = sum(result["response"]["body"]["accepted"] for result in ordered)
        expected = 2 if mode == "vulnerable_parallel" else 1
        assert accepted == expected, (mode, ordered)
        assert state.redemptions == expected, (mode, state.redemptions)
        return {
            "mode": mode,
            "execution": "sequential" if mode.endswith("sequential") else "parallel",
            "requests": ordered,
            "events": state.events,
            "final_state": {
                "coupon_used": state.used,
                "successful_redemptions": state.redemptions,
            },
        }
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    scenarios = [
        run_scenario(mode)
        for mode in ("vulnerable_sequential", "vulnerable_parallel", "fixed_parallel")
    ]
    evidence = {
        "scope": "Local 127.0.0.1 simulated coupon service, no third-party target",
        "platform": platform.platform(),
        "python_version": sys.version.split()[0],
        "method": "HTTP POST; two attempts per fresh coupon; parallel case synchronized at check/use window",
        "scenarios": scenarios,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    for scenario in scenarios:
        statuses = [r["response"]["status"] for r in scenario["requests"]]
        count = scenario["final_state"]["successful_redemptions"]
        print(f"{scenario['mode']}: HTTP {statuses}; successful_redemptions={count}")
    print(f"Evidence: {args.output.resolve()}")


if __name__ == "__main__":
    main()

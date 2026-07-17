#!/usr/bin/env python3
"""Direct, Nix-independent test of the batching hypothesis for Model S.

Context (see docs/PROCESS_VS_PROVIDER_RESULTS.md's "Model S prototype"
section): connection reuse mechanically eliminated per-decision connect()
cost but did not improve measured closure-throughput over O-process. A
follow-up diagnostic (pure Python client, one already-open connection,
100 sequential single-decision requests) found a real per-decision floor
even with connection setup fully eliminated -- roughly 14ms/decision for
an ed25519-only signature set, roughly 42ms/decision when both an
Ed25519 and an ML-DSA-65 signature were included.

This script asks the next question directly, before touching any C++ or
the real Nix caller: does batching -- sending N decisions in ONE
request/response instead of N separate round trips over the same
connection -- amortize that floor? If it does, the floor is a
round-trip/scheduling cost. If it does not, the floor is dominated by
per-decision verification work itself (crypto, mostly ML-DSA-65, which
is far more expensive per-signature than Ed25519), and batching would
only be worth it in Nix's real caller as a code-simplicity matter, not a
performance one.

Method: alternate individual-call and batch-call rounds against the same
already-open connection, same payload, same registry, same machine, same
session -- matching this campaign's own interleaving discipline so a
transient load spike does not get misread as a real effect. Reports
median wall time per decision for each mode, for both the ed25519-only
payload (what the real Nix caller sends for these fixtures) and the
both-signatures payload (the shape that showed the larger floor in the
prior diagnostic).
"""

import json
import socket
import statistics
import sys
import time

SOCK_PATH = "/tmp/model-s-batching-diagnostic.sock"
N_DECISIONS = 100
N_ROUNDS = 5


def load_payloads():
    with open(
        "/srv/luminous-dynamics/.claude/worktrees/"
        "nix-authorization-boundary-experiments-1ebf353c/measurement/fixtures/"
        "verify-raw-request.json"
    ) as f:
        fixture = json.load(f)
    both = {
        "fingerprint": fixture["fingerprint"],
        "signatures": fixture["signatures"],
    }
    ed25519_only = {
        "fingerprint": fixture["fingerprint"],
        "signatures": [
            s for s in fixture["signatures"] if s.startswith("acme-release-ed25519")
        ],
    }
    assert len(ed25519_only["signatures"]) == 1
    assert len(both["signatures"]) == 2
    return {"ed25519_only": ed25519_only, "both_sigs": both}


def connect():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK_PATH)
    return s


def send_line(sock, obj):
    line = json.dumps(obj) + "\n"
    sock.sendall(line.encode("utf-8"))


def read_line(sock, buf):
    while b"\n" not in buf[0]:
        chunk = sock.recv(65536)
        if not chunk:
            raise EOFError("connection closed before a full line arrived")
        buf[0] += chunk
    line, _, rest = buf[0].partition(b"\n")
    buf[0] = rest
    return line


def run_individual(sock, buf, payload, n):
    start = time.monotonic()
    for _ in range(n):
        send_line(sock, payload)
        response = json.loads(read_line(sock, buf))
        assert "candidates" in response, response
    elapsed = time.monotonic() - start
    return elapsed


def run_batch(sock, buf, payload, n):
    batch = {"decisions": [payload] * n}
    start = time.monotonic()
    send_line(sock, batch)
    response = json.loads(read_line(sock, buf))
    elapsed = time.monotonic() - start
    assert "results" in response, response
    assert len(response["results"]) == n
    return elapsed


def main():
    payloads = load_payloads()
    results = {}

    for label, payload in payloads.items():
        sock = connect()
        buf = [b""]
        individual_times = []
        batch_times = []

        for round_num in range(N_ROUNDS):
            individual_times.append(run_individual(sock, buf, payload, N_DECISIONS))
            batch_times.append(run_batch(sock, buf, payload, N_DECISIONS))
            print(
                f"[{label}] round {round_num + 1}/{N_ROUNDS}: "
                f"individual={individual_times[-1] * 1000:.1f}ms "
                f"batch={batch_times[-1] * 1000:.1f}ms",
                file=sys.stderr,
            )

        sock.close()

        individual_per_decision_ms = [
            (t / N_DECISIONS) * 1000 for t in individual_times
        ]
        batch_per_decision_ms = [(t / N_DECISIONS) * 1000 for t in batch_times]

        results[label] = {
            "n_decisions": N_DECISIONS,
            "n_rounds": N_ROUNDS,
            "individual_total_ms": [t * 1000 for t in individual_times],
            "batch_total_ms": [t * 1000 for t in batch_times],
            "individual_per_decision_ms_median": statistics.median(
                individual_per_decision_ms
            ),
            "batch_per_decision_ms_median": statistics.median(batch_per_decision_ms),
            "individual_per_decision_ms_all": individual_per_decision_ms,
            "batch_per_decision_ms_all": batch_per_decision_ms,
        }

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()

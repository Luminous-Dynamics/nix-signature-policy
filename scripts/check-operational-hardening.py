#!/usr/bin/env python3
"""Fail when the operational-hardening surface silently drifts away."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(path: str, needles: list[str]) -> None:
    text = (ROOT / path).read_text()
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{path}: missing required operational markers: {missing}")


def main() -> int:
    require(
        "src/proxy.rs",
        [
            "Semaphore",
            "with_graceful_shutdown",
            "Policy::none()",
            'route("/healthz"',
            'route("/readyz"',
            'route("/metrics"',
            "proxy_overloaded",
            "nar_chunk_idle_timeout",
            "validate_narinfo_hash",
            "validate_narinfo_download_url",
            "requests_failed_total",
            "validate_cache_info",
            "serde_json::to_string(&record)",
        ],
    )
    require(
        "src/main.rs",
        [
            "max_in_flight",
            "queue_timeout_ms",
            "metadata_timeout_secs",
            "nar_idle_timeout_secs",
            "max_nar_bytes",
        ],
    )
    require(
        "tests/proxy_e2e.rs",
        [
            "read_only_routes_reject_request_bodies",
            "bounded_queue_refuses_excess_concurrency",
            "oversized_metadata_and_redirects_fail_closed",
            "narinfo_download_url_cannot_escape_the_proxy_namespace",
            "interrupted_nar_stream_surfaces_a_body_error_and_releases_capacity",
            "stalled_nar_stream_hits_the_idle_deadline",
            "graceful_shutdown_stops_accepting_and_returns_cleanly",
        ],
    )
    require(
        "docs/OPERATIONAL_HARDENING.md",
        [
            "Admission and backpressure",
            "Health, readiness, and metrics",
            "Structured logs",
            "Graceful shutdown",
            "Remaining production gaps",
        ],
    )
    print("operational hardening guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

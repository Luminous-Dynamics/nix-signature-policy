# Operational hardening profile

Status: implemented prototype profile.

This document describes the network and process-safety boundaries of the
`proxy` subcommand. It does not upgrade the repository's cryptographic
assurance level: the proxy remains unaudited and inherits the classical
upstream root of trust it translates.

## Admission and backpressure

The proxy owns a process-wide semaphore. Every metadata request and every NAR
response stream must hold one permit. NAR permits remain held until EOF, body
failure, client cancellation, or graceful shutdown, so a slow client cannot
escape the concurrency accounting after response headers are emitted.

Defaults:

| Control | Default |
|---|---:|
| Maximum in-flight requests/streams | 128 |
| Maximum queue wait | 1 second |
| Upstream connect timeout | 10 seconds |
| Metadata total timeout | 30 seconds |
| NAR header timeout | 30 seconds |
| NAR chunk idle timeout | 30 seconds |
| NAR total-size cap | unlimited unless configured |

A request that cannot obtain a permit before the queue deadline receives
`503 Service Unavailable` with the stable code `proxy_overloaded`. Request
bodies are rejected because the supported cache surface is read-only.

The limits are configurable through the `proxy` CLI:

```console
nix-pqc-cache-proxy proxy \
  --upstream https://cache.example \
  --upstream-pubkey cache.example-1:BASE64 \
  --key proxy-1.secret \
  --max-in-flight 128 \
  --queue-timeout-ms 1000 \
  --connect-timeout-secs 10 \
  --metadata-timeout-secs 30 \
  --nar-header-timeout-secs 30 \
  --nar-idle-timeout-secs 30 \
  --max-nar-bytes 68719476736
```

Omitting `--max-nar-bytes` preserves unlimited total NAR size while retaining
idle-time and concurrency bounds.

## Upstream boundary

The configured upstream URL must:

- use `http` or `https`;
- contain a host;
- contain no user-info credentials;
- contain no query or fragment.

Routes are appended with URL-segment APIs rather than string concatenation.
Redirects are disabled so an upstream cannot silently move verification or
streaming to a different origin. Narinfo hashes must be exactly 32 characters
from the Nix base32 alphabet. NAR filenames are bounded, single-segment ASCII
identifiers, and URL dot-segments are rejected.

Before re-signing upstream metadata, the proxy also requires the narinfo `URL:`
to have the exact relative shape `nar/<validated-filename>`. An absolute URL,
nested path, query, or other namespace is refused. This prevents authenticated
metadata from steering the Nix client around the proxy's bounded NAR streaming
path.

Buffered metadata is bounded independently of `Content-Length`, which is only
a precheck. `nix-cache-info` must be UTF-8, contain a normalized absolute
`StoreDir`, and use valid values for known numeric/boolean fields. HTML error
pages are refused rather than forwarded as cache metadata.

Only successful upstream NAR responses are streamed. The proxy does not
forward Range requests or advertise range support. NAR responses receive an
immutable cache policy; rewritten metadata receives a short cache lifetime.
Errors and operational endpoints are `no-store`.

## Health, readiness, and metrics

- `GET /healthz` proves the process and router are responsive. It does not
  contact the upstream.
- `GET /readyz` fetches and validates the upstream `nix-cache-info` document.
  It returns `503` when the upstream is unavailable or malformed.
- `GET /metrics` emits a low-cardinality Prometheus text exposition. No URLs,
  filenames, key material, signatures, or client identifiers are labels.

The metrics include active/completed/failed/incomplete requests, overload refusals,
invalid requests, upstream and signature failures, NAR stream failures,
readiness failures, and transmitted response bytes. `failed` means an admitted
handler or stream reached an explicit refusal/error; `incomplete` is reserved
for a response stream that was dropped before EOF without an explicit body
error, such as client cancellation.

These endpoints are unauthenticated because the default listener is loopback.
Operators exposing the proxy beyond a trusted host should place them behind a
separate network policy or reverse-proxy ACL.

## Structured logs

Operational events are emitted as one JSON object per stderr line. Records use
stable event and refusal codes and may include a monotonic process-local
request ID and coarse request kind. They deliberately omit:

- upstream URL and credentials;
- requested narinfo hash or NAR filename;
- key material and signatures;
- response bodies;
- client addresses.

Request-path logs emit stable codes rather than error-chain text, because
library errors may embed URLs. Clients receive only the same stable refusal
code and a process-local request ID. Startup configuration errors are returned
to the local operator through the CLI.

## Graceful shutdown

The CLI listens for Ctrl-C and, on Unix, SIGTERM. Axum stops accepting new
connections and drains admitted handlers and NAR streams before returning.
A caller-provided shutdown future is exposed for deterministic integration
tests and service wrappers.

There is intentionally no forced drain deadline in this patch: terminating an
active NAR stream after a fixed wall-clock interval would trade availability
for shutdown latency. A supervisor may still impose an outer process timeout.

## Fault-injection coverage

Hermetic socket-level tests cover:

- excessive concurrent requests and bounded queue refusal;
- oversized metadata bodies;
- upstream redirects;
- malformed readiness metadata;
- invalid route-segment input;
- re-signed narinfo URLs attempting to escape the proxy namespace;
- interrupted NAR bodies;
- stalled NAR bodies and idle deadlines;
- configured NAR size limits;
- graceful shutdown completion;
- health, readiness, and metrics behavior.

## Remaining production gaps

This patch improves operational safety but does not make the prototype a
production service. Remaining work includes TLS termination and client
identity, durable configuration management, distributed rate limiting,
supervisor packaging, long-duration soak tests, independent security review,
and a production post-quantum origin signing model.

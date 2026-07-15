# Prior art and design delta

This document names exactly what already exists in and around Nix, what this
project reuses from it, what gap remains, and what this project deliberately
does not propose. It exists so a reviewer can evaluate one specific,
unresolved delta instead of re-deriving the whole design space.

## What already exists

**[NixOS/nix#14451](https://github.com/NixOS/nix/issues/14451)** proposes a
`trusted-signatures-command` option: an executable, settable only by trusted
users, invoked with the artifact fingerprint and its signatures, whose exit
status decides admission. If both `trusted-public-keys` and
`trusted-signatures-command` are configured, the issue proposes that either
accepting is sufficient — explicitly for migration compatibility. The issue
author already flagged, as an open question, that exit-status-only decisions
are fragile ("it's easier to accidentally exit 0 ... than it is to
accidentally print a specific string") and cited `pam_exec` and OpenVPN as
prior art for the exit-code approach; a later comment from the same author
adds `httpd`'s `mod_authnz_external` and OpenSSH's
`AuthorizedKeysCommand`/`AuthorizedPrincipalsCommand` to that list, and
clarifies the command would be invoked once per narinfo, not once per
signature. A separate commenter raised the performance and process-model
objection directly — "shelling out on each signature check sounds quite
strange and crazy expensive" — proposing in-process PKCS#11 verification
instead; the rebuttal (same thread) is that narinfo fetch latency (~500ms
over the network) already dwarfs process spawn (~1ms), so exec overhead is
2-3 orders of magnitude smaller than a cost already being paid per
substitution.

**[NixOS/nix#15926](https://github.com/NixOS/nix/pull/15926)** (state
verified 2026-07-15: open, not yet merged — re-check before citing its
merge status as current) refactors `PublicKey`/`SecretKey` into a
`KeyType`-tagged, subclassable hierarchy so Nix's *existing* signature
representation can carry more than Ed25519. It's extracted from
[DeterminateSystems/nix-src#449](https://github.com/DeterminateSystems/nix-src/pull/449)
(also open as of the same verification date), which adds ecdsa-p384 and
ML-DSA-{44,65,87} concretely, gated behind an experimental `cnsa` feature,
and demonstrates that a hybrid-signed
path's `signatures` array is still just ordinary `"keyname:base64"` entries
— no new narinfo field, longer signature blob, same shape.

**[NixOS/rfcs#202](https://github.com/NixOS/rfcs/pull/202)**, this project's
own prior submission ("Hybrid post-quantum (Ed25519+ML-DSA-65) narinfo
signatures", proposing an additive `Sig-PQC:` field), was closed 2026-07-14
as superseded after review from two NixOS/nix maintainers.
[@grahamc](https://github.com/grahamc) pointed at #15926/nix-src#449 as
already doing this without a parallel field;
[@shlevy](https://github.com/shlevy) asked directly: "Why is 'PQC' special
from the Nix config's perspective? Why not just extend existing signatures
field to allow for extensible algo types". The closing comment on #202
agreed, and previewed exactly this project's current framing: algorithm
agility doesn't by itself provide a way to *require* a composed combination
(classical AND post-quantum, thresholds, distinct authorities) — an
any-valid-signature narinfo with both signature types present provides no
downgrade resistance, since removing the PQ signature still verifies.

A related, unresolved concern from a NixOS/nix member
([@mschwaig](https://github.com/mschwaig), on #14451) is architectural, not
about this project specifically: point-wise verification of the *final*
derivation is "strictly less useful" than reasoning about trust across the
whole build-time closure, and their own related work (content-addressed
derivations + quorums, informed by
[laut](https://github.com/mschwaig/laut)) targets that broader problem.

## What we reuse

- Ordinary, algorithm-tagged Nix signatures (#15926/nix-src#449's direction)
  as the sole representation — no `Sig-PQC:`, no parallel field. `docs/
  PRIOR_ART.md` and `docs/adr/0001-policy-over-transport.md` already record
  this decision; this document is where the *upstream conversation* that
  produced it is recorded, not just the outcome.
- An external, trusted-users-only, no-shell command as the extensibility
  point — #14451's core shape.
- The precedent that "external command as a security decision point" is an
  accepted, established pattern (`pam_exec`, `mod_authnz_external`, OpenVPN
  `--tls-verify`, OpenSSH `AuthorizedKeysCommand`), not a novel risk category
  Nix would be first to accept.
- The "OR with built-in trust for compatibility" idea — this is exactly what
  this project calls `supplemental` mode.
- The invoked-per-narinfo (not per-signature) granularity.

## What remains missing — the actual delta

1. **An explicit authoritative mode.** #14451's proposed combination is
   permissive-OR only. That's sufficient for migration and observation, but
   it cannot express "classical AND post-quantum both required," "N of M
   authorities," or any other mandatory composition — a valid built-in
   signature always wins. This project's `authoritative` mode (`docs/
   NIX_INTEGRATION_CONTRACT.md`) is the one property #14451 cannot express
   and RFC #202's reviewers pointed at as the actual gap.
2. **A resolved answer to the exit-code question #14451 left open.** This
   project's caller treats a successful process exit as "a structured
   response exists, parse it" and takes the accept/refuse decision *only*
   from that parsed response — never from the exit code alone (`docs/
   AUTHORIZATION_JSON_PROTOCOL.md`, `src/caller.rs`).
3. **Hostile-process handling.** Neither #14451 nor its proof-of-concept
   describes what happens when the configured command hangs, crashes,
   floods output, or leaves child processes behind. This project's
   `tests/helper_process_hostility.rs` is the concrete answer.
4. **Strict I/O bounds** on both the request and the response, and a closed,
   versioned wire format, rather than positional CLI arguments.

## What we are not proposing

- `Sig-PQC:` or any new narinfo field — closed by RFC #202 itself.
- A replacement for #15926/nix-src#449's algorithm-agility work — this
  project is additive to it, not competing with it.
- A replacement for in-process PKCS#11/HSM verification — that's a
  different layer (*is this one signature cryptographically valid?*) from
  what this project addresses (*is this combination of already-verified
  signatures sufficient?*). The two compose; neither obsoletes the other.
- An answer to closure-wide/transitive trust (mschwaig's concern). This
  project authorizes admission of one artifact at a time. That is a real,
  acknowledged limitation, not an oversight — closure-wide reasoning is a
  different, larger problem that a point-wise authorization boundary can
  compose with later, but does not need to solve first to be useful now.
- Adoption of this project's full Rust framework, policy language, or
  lifecycle/governance machinery as Nix-core functionality (`docs/
  UPSTREAM_MINIMAL_SLICE.md` already scopes this down explicitly).
- A general zero-trust platform, TUF/SLSA/in-toto replacement, or Sigstore
  integration — those are evidence sources a future policy could consume,
  not something this project redefines.

## What evidence we add

- A hostile-process failure-injection suite exercising the exact ambiguity
  #14451 flagged and left unresolved.
- Real measured process-spawn cost data (`docs/CALLER_SAFETY.md`: ~2ms mean
  over 1755 runs, even under real background load), settling the
  performance objection with numbers instead of restating jkarni's estimate.
- A frozen `core-v1` conformance profile with an independently-implemented
  Python model, so "does this authoritative mode actually work" isn't taken
  on faith.

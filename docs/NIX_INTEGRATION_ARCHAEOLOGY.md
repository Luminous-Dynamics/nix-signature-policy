# Nix integration archaeology

**Status: non-normative research snapshot, not a specification.** This
document records what a direct reading of the real Nix source and its
public process actually shows, as of one examination pass. It exists to
ground Phase B design discussion in evidence rather than assumption. It is
not a commitment to any particular mechanism, and several open questions
below are marked unresolved rather than guessed at. Re-verify any claim
here against current upstream state before relying on it in an upstream
conversation — the source revision and date are pinned below precisely so
that staleness is checkable.

- **Source examined**: `https://github.com/NixOS/nix`, commit
  `40f375fac1af1a432cbf48dfd15468b1921d458c` (shallow clone off the
  default branch).
- **Date examined**: 2026-07-15.
- **Current upstream state observed**: [NixOS/nix#15926](https://github.com/NixOS/nix/pull/15926)
  (the `PublicKey`/`SecretKey` polymorphism refactor) is open and unmerged
  (`mergedAt: null`, last updated 2026-06-21 — independently re-verified,
  not just taken from the earlier prior-art pass). The Determinate-side
  work it was extracted from, [DeterminateSystems/nix-src#449](https://github.com/DeterminateSystems/nix-src/pull/449),
  merged on Determinate's own fork 2026-05-20 — it has not yet reached
  `NixOS/nix` proper. Confirmed empirically: no `KeyType` enum or
  equivalent exists anywhere in the examined source; the current key model
  (`src/libutil/include/nix/util/signature/local-keys.hh`) is concrete,
  non-virtual, Ed25519-only via libsodium.

## Factual call-flow findings

### The admission function

`LocalStore::pathInfoIsUntrusted()` (`src/libstore/local-store.cc:1036-1039`)
is the decision function:

```cpp
bool LocalStore::pathInfoIsUntrusted(const ValidPathInfo & info)
{
    return config->requireSigs && !info.checkSignatures(*this, getPublicKeys());
}
```

`getPublicKeys()` (`local-store.cc:1028-1034`) lazily builds the trusted-key
map from the global `trusted-public-keys` setting. `ValidPathInfo::
checkSignatures()` (`src/libstore/path-info.cc:125-135`) counts how many of
a path's `.sigs` verify against that key map — any one valid signature is
sufficient (the "any-valid" behavior the whole project is a response to).

### Two call sites — and they are not equivalent

1. **Pre-download, in the substituter loop**
   (`src/libstore/build/substitution-goal.cc:116-121`):

   ```cpp
   /* Bail out early if this substituter lacks a valid
      signature. LocalStore::addToStore() also checks for this, but
      only after we've downloaded the path. */
   if (!sub->config.isTrusted && worker.store.pathInfoIsUntrusted(*info)) {
       warn("ignoring substitute for '%s' from '%s', as it's not signed...");
       continue;
   }
   ```

2. **Post-download, the real enforcement gate**
   (`LocalStore::addToStore(info, source, repair, checkSigs)`,
   `local-store.cc:1044-1048`):

   ```cpp
   if (checkSigs && pathInfoIsUntrusted(info))
       throw Error("cannot add path '%s' because it lacks a signature by a trusted key", ...);
   ```

**These play different roles and must be treated differently in any
design.** The pre-download check is a metadata-only optimization and
early filter — it exists purely to avoid wasting a download on a path
that's going to be rejected anyway. `addToStore()` is the actual
security-enforcement point: the code's own comment says exactly this
("`LocalStore::addToStore()` also checks for this, but only after we've
downloaded the path"). **No security guarantee for this project's proposal
should depend only on the early substituter-loop check.** The final
integration must ensure every protected path reaches the post-download
gate with sufficient evidence available for authorization, not just that
the early filter was consulted.

### Alternate ingress paths — the choke point is good news, with a caveat

`addToStore(..., CheckSigsFlag)` is a shared choke point, not reimplemented
per-caller:

- `nix copy` (`src/nix/copy.cc:8`) goes through the same flag, default
  `CheckSigs`, opt-out requires explicit `--no-check-sigs`.
- The nix-daemon remote protocol (`src/libstore/daemon.cc:494,510,926,935,955`)
  gates the same flag: a client can only request skipping checks if the
  daemon already considers that client `trusted`.
- `restricted-store.cc:98` (sandboxed builds) also defaults to `CheckSigs`.
- Local builds (`nix build` producing a fresh output) don't go through
  `addToStore` with `CheckSigs` at all — they're trusted by construction
  (the local builder produced them), a genuinely different trust boundary
  (build sandboxing), not a bypass of the substitution trust boundary.
- Content-addressed paths: **unresolved**, see below.

This is a real strength for the proposal — a hook at this one function
could plausibly cover substitution, `nix copy`, and daemon ingress at
once, not just the substituter path — but it has not been verified that
raw signature data and full context remain available at every one of
these call sites the way it's available in the substituter loop. That
needs the follow-up pass, not an assumption.

### Evidence available at the decision point

At `substitution-goal.cc:116`: `info` (a `ValidPathInfo`, often actually
`NarInfo`) carrying `.path`, `.sigs` (raw `Signature` set — keyName + raw
bytes), `.narSize`, `.references`; the substituter's identity via
`sub->config.getHumanReadableURI()`; `sub->config.isTrusted`. At
`local-store.cc:1048` (post-download): the same `info` plus store-local
context. Raw signature strings are available at both points confirmed so
far.

### Existing process-execution infrastructure: `post-build-hook`

`runPostBuildHook` (`src/libstore/build/derivation-building-goal.cc:1103-1149`)
is Nix's closest existing external-process mechanism. Concretely:

- **Inherits the full parent environment** (`OsStringMap hookEnvironment =
  getEnvOs();`, line 1119, then only *adds* variables — nothing is
  cleared first).
- **Uses `execvp`** (line 1140), which consults `PATH` — the hook is not
  required to be an absolute path.
- **No timeout anywhere** in this function or its caller
  (`derivation-building-goal.cc:833-846`'s wait loop has no deadline). No
  bounding mechanism was found to contradict this.
- Does close extra file descriptors and disable vfork — real but narrow
  hygiene, not equivalent to bounded I/O or process-group cleanup.
- No `setpgid`/process-group handling found — no evidence this mechanism
  reaps a hook's grandchildren.

Reported as fact for comparison, not as a criticism of Nix: this means a
*security-decision* hook cannot just copy the existing `post-build-hook`
pattern and inherit its safety properties, because that pattern doesn't
have the safety properties this project's `src/caller.rs` was built to
provide. `build-hook` (remote builder protocol) and the sandboxed-builder
spawn path were not evaluated in this pass.

## Design implications

### Two integration paths, not one — #15926 is not a blocker for both

The absence of `KeyType` upstream changes sequencing, but does not block
implementation outright. There are two distinct shapes:

**Raw-evidence provider** (matches #14451's original proposal shape):
Nix supplies the canonical fingerprint and raw signature entries; the
external provider verifies whichever algorithms it supports itself and
performs authorization; Nix enforces the returned decision.
- Implementable against current Nix, today, independent of #15926.
- Supports ML-DSA, certificate systems, or anything else Nix doesn't
  understand yet.
- Duplicates some signature-verification responsibility outside Nix.

**Verified-observation provider**: Nix verifies known algorithms itself
(requires multi-algorithm verification support — i.e. depends on #15926
or equivalent landing first) and hands the hook a per-algorithm pass/fail
map rather than raw bytes.
- Cleaner separation between verification and authorization.
- Keeps all supported cryptographic verification inside Nix.
- Cannot naturally support evidence types Nix doesn't understand.
- Depends on #15926 (or equivalent) actually merging upstream first.

Both are structurally available at the same call site today (raw
signatures are already in scope; the verified-observation path is a
well-scoped follow-on, since the per-algorithm-check loop already exists
in `ValidPathInfo::checkSignatures`, `path-info.cc:125-135` — not a
rearchitecture). The current unmerged state of #15926 is, if anything, a
reason to start with the raw-evidence shape rather than a reason to wait.

### Configuration scope

- `trusted-public-keys` (`src/libstore/include/nix/store/globals.hh:240-243`)
  is a **global** `Setting<Strings>`.
- `isTrusted` (`src/libstore/include/nix/store/store-api.hh:282-290`) is
  per-store (effectively per-substituter, since each substituter is its
  own `Store` instance) — but it's a coarse all-or-nothing "skip checking
  entirely for this substituter" flag, not a per-substituter *policy*.
- Genuine per-substituter authorization policy (not just skip/don't-skip)
  would be new capability, not an extension of an existing axis.

### Substituter fallback and authoritative semantics — this needs more care than "hard-fail everything"

Directly observed: a signature failure from one substituter is **not** a
hard failure of the whole goal today — it's `warn()` + `continue`, and the
loop tries the next configured substituter
(`substitution-goal.cc:44-121`). The goal only fails once every substituter
is exhausted.

An earlier pass of this memo suggested that `authoritative` mode would
need to be "threaded past this continue-on-failure structure" to hard-fail
the whole substitution attempt. That framing conflates two different
things and should be corrected: **authoritative mode means built-in
trusted-key acceptance cannot override the authorization provider for the
candidate and trust scope being evaluated — it does not automatically mean
that refusing one candidate must prevent trying another substituter.**

Consider: substituter A offers a candidate that the authorization policy
refuses; substituter B offers the same store path with independently
satisfactory evidence. Trying B may be entirely legitimate under an
authoritative policy that A's specific candidate simply didn't satisfy.
Collapsing "authoritative" into "abort all fallback" would be a stronger
and more disruptive semantic than the security property actually requires,
and risks over-scoping the eventual proposal.

The real open questions, not yet answered by this pass:

- Is authorization scoped per candidate, per substituter, or globally?
- Must every configured substituter use the same authorization policy?
- Can fallback legitimately cross from a hook-governed substituter into an
  ungoverned or merely-supplemental one, or should that require explicit
  configuration?
- Does helper invocation failure (crash, timeout, protocol error) mean
  "reject this one candidate" or "configuration/infrastructure failure —
  abort the goal"? These are different failure classes and may warrant
  different handling.
- Is the canonical artifact identity (the store path / narinfo
  fingerprint) sufficient to prevent different substituters from
  presenting semantically different evidence for what's nominally the
  same object?

A safer initial semantic model to design around, pending resolution of the
above:

- **Policy refusal of a candidate**: reject that candidate; another
  substituter may still be tried under an equally authoritative policy.
- **Built-in acceptance combined with policy refusal**: reject that
  candidate (authoritative wins over built-in, per the core property).
- **Helper unavailable or protocol failure**: treat as at least "reject
  every candidate governed by that unavailable provider," and quite
  possibly a terminal configuration-error condition for the whole goal in
  authoritative mode — this needs explicit decision, not inference from
  today's substituter-loop code.
- **Fallback into an ungoverned or merely-supplemental substituter after
  an authoritative refusal**: prohibited by default unless explicitly
  configured to allow it.

### Minimal diff shape (sketch only, no code)

- `src/libstore/include/nix/store/globals.hh`: new `Setting`(s) for helper
  command, mode, timeout — mirrors the existing `postBuildHook`
  `Setting<Path>` pattern rather than inventing a new configuration idiom.
- `src/libstore/local-store.cc`: extend `pathInfoIsUntrusted`/`addToStore`'s
  check with the hook's result, composed per enforcement mode.
- `src/libstore/build/substitution-goal.cc:116-121`: the pre-download
  check site needs the same composition, plus the candidate/substituter/
  goal-scoping distinction above — not a simple continue-to-hard-fail
  swap.
- A new process-invocation module (the C++ analog of `src/caller.rs`),
  likely under `src/libutil/` alongside the existing `startProcess` helper
  `runPostBuildHook` already uses.
- This reads as a handful of files and call sites, not a rearchitecture —
  *provided* the candidate/substituter/goal-scoping questions above are
  resolved deliberately rather than left implicit.

### RFC requirement

`CONTRIBUTING.md` does not impose a hard "RFC required" gate. It
recommends discussing far-reaching changes with maintainers before
investing significant implementation time; PRs against issues labeled
`idea approved` get prioritized review. #14451 itself is a plain GitHub
issue, not a formal `NixOS/rfcs` submission, and has received real
maintainer engagement. **Recommendation**: continue the design discussion
on #14451 (or a closely linked new issue) before a PR, rather than
assuming a formal RFC is required — though a maintainer could still
request one once a concrete diff exists.

## Unresolved questions

Marked explicitly rather than guessed at — this list is a feature of the
archaeology, not a gap to apologize for:

- Whether content-addressed paths meaningfully bypass the
  `pathInfoIsUntrusted` gate, or simply don't need it as much by
  construction (`isContentAddressed` appears at `substitution-goal.cc:85`;
  its interaction with signature checking was not traced to a conclusion).
- Realisation registration (`LocalStore::realisationIsUntrusted`,
  `local-store.cc:1041-1043`, exists in parallel to the path check) and
  whether it needs independent treatment in any hook design.
- Whether raw signature bytes remain available at every one of `addToStore`'s
  call sites (not just the substituter-loop path), or whether some callers
  reach it with less context.
- The closest Nix functional-test precedent to model a hook's test suite
  on — a `post-build-hook` functional test almost certainly exists given
  the feature is documented, but wasn't located in this pass.
- Trusted-user and trusted-store bypass paths beyond the ones already
  found (daemon `dontCheckSigs` requires the client already be `trusted`;
  is there a broader trusted-user escape hatch elsewhere in the config
  surface?).
- Whether helper results should be cached, and if so, keyed and
  invalidated how — not evaluated in this pass at all.
- Substituter fallback across different trust scopes, beyond the candidate/
  substituter/goal-scoping questions already raised above.

## Non-normative status

Nothing in this document should be read as a design decision, a
commitment to a specific enforcement mode's exact semantics, or a claim
that upstream will accept any particular shape. It is a factual snapshot
of one source revision, examined once, intended to replace assumption
with evidence before further design or implementation work — and to be
explicit about exactly where evidence runs out.

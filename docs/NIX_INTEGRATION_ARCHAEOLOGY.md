# Nix integration archaeology

**Status: non-normative research snapshot, not a specification.** This
document records what a direct reading of the real Nix source and its
public process actually shows, across two examination passes (an initial
pass and a narrower follow-up closing four specific open questions, both
against the same source revision). It exists to ground Phase B design
discussion in evidence rather than assumption. It is not a commitment to
any particular mechanism, and several open questions below are marked
unresolved rather than guessed at. Re-verify any claim here against
current upstream state before relying on it in an upstream conversation —
the source revision and date are pinned below precisely so that staleness
is checkable.

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

  **Updated by the follow-up pass below**: two more concrete items belong
  in this list, not just "provided" caveats — threading substituter
  identity into `addToStore()` (or `ValidPathInfo`) so the hook can know
  which substituter offered a candidate, and a decision on whether the
  CA-path short-circuit in `checkSignatures()` needs a second hook site
  or a change to that function itself. See "Follow-up pass" for why these
  aren't optional polish.

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

## Follow-up pass: closing four open questions

A second, narrower read-only pass against the same clone and commit
(`40f375fac1af1a432cbf48dfd15468b1921d458c`, same date, no new source
state to pin) resolved four of the items the first pass left open. All
citations below are new evidence from this pass; the most consequential
ones were independently re-verified line-for-line against the clone
before being written up here.

### 1. Content-addressed paths and realisations — resolved, and it's a real gap

**`ValidPathInfo::checkSignatures()` itself short-circuits for CA paths**,
before the first pass's finding about `pathInfoIsUntrusted` even comes
into play:

```cpp
// src/libstore/path-info.cc:124-133
size_t ValidPathInfo::checkSignatures(const StoreDirConfig & store, const PublicKeys & publicKeys) const
{
    if (isContentAddressed(store))
        return maxSigs;          // maxSigs = numeric_limits<size_t>::max()

    size_t good = 0;
    for (auto & sig : sigs)
        if (checkSignature(store, publicKeys, sig))
            good++;
    return good;
}
```

CA paths never reach the signature loop at all — this function reports
"maximally satisfied" unconditionally, so **every** call site gating on
`pathInfoIsUntrusted` (the substituter loop, `addToStore`) is bypassed
identically for CA paths. This is baked into the shared primitive, not a
caller-level gap to patch individually. `isContentAddressed()`
(`path-info.cc:108-121`) checks only that the path's own name matches
what its declared content-addressing method computes — **byte-integrity/
self-consistency, not authorization and not derivation-output binding**.
A CA path can pass this while being an entirely unauthorized but
internally-consistent artifact.

**Realisations do not get the CA shortcut** — `UnkeyedRealisation::
checkSignatures` (`realisation.cc:61-69`) always loops over
`.signatures`, with a `// FIXME: Maybe we should return maxSigs if...
input-addressed` comment showing the authors considered adding the same
shortcut here and didn't. But realisation registration
(`LocalStore::registerDrvOutput`, `local-store.cc:654-661`, gated by
`Xp::CaDerivations`) is a **structurally separate entry point from
`addToStore`** — a hook wired only into `addToStore`/`pathInfoIsUntrusted`
would not cover it. Verified: the daemon's `RegisterDrvOutput` RPC handler
(`daemon.cc:979-982`) calls the single-argument, no-signature-check
overload of `registerDrvOutput` unconditionally — every other operation in
`daemon.cc` gates signature-skipping on `trusted`, this one has no such
gate at all. Possibly intentional (realisations are usually build outputs,
trusted by construction like local builds generally), but structurally
inconsistent with the rest of the file, and worth flagging to a maintainer
rather than assuming either way.

### 2. Evidence at the final gate — resolved, and it's a real gap

All callers of `addToStore(info, source, repair, checkSigs)`:
`local-store.cc:1046` (the impl), `restricted-store.cc:215-218`,
`legacy-ssh-store.cc:151`, `remote-store.cc:447`,
`binary-cache-store.cc:311,627`, `daemon.cc:510,935,955` (gated by
`dontCheckSigs`), `store-api.cc:961`, `export-import.cc:89`. Two callers —
`nix-store.cc:1075`, `tarball.cc:87` — hardcode `NoCheckSigs`
unconditionally; both are local-import operations with a different trust
model (the user directly supplies the content).

**`addToStore`'s own signature carries no substituter-identity
parameter.** Raw signatures and the fingerprint *are* available via
`info`, but the substituter identity the first pass found in the
substitution-goal caller's local scope (`sub->config.getHumanReadableURI()`)
is not threaded into `addToStore()` at all. This is the concrete
data-flow gap the candidate/substituter/goal-scoping semantic model
recommended earlier in this document actually depends on: knowing *which*
substituter offered a refused candidate, so that refusing it doesn't
necessarily block a different substituter's independently-adequate
evidence for the same path. Closing this gap means either adding a
parameter to `addToStore` (touches all ~8 implementations/call sites
above) or threading substituter identity through `ValidPathInfo` itself
(touches a much more widely-shared data structure) — a real, scoped code
change, not hypothetical future plumbing.

### 3. Trusted-user and trusted-store bypasses — resolved, not a gap

`daemon.cc:494`'s `dontCheckSigs` gate requires the connection already be
`trusted`, and `trusted` comes from Nix's own long-standing
`trusted-users`/`allowed-users` multi-user daemon model
(`daemon.cc:221`, used throughout the file for repair mode, GC-root
visibility, and restricted-setting overrides — infrastructure that
predates this discussion entirely). **This is an intentional, established
administrative trust boundary, not an accidental bypass relative to
authoritative policy.** Recommendation: a first proposal should explicitly
*exclude* trusted-daemon-client ingress from scope, documented as
inheriting Nix's existing multi-user trust model. "Enforce for trusted
ingress too" is a coherent later option for operators who want the
boundary to apply even to locally-trusted clients, but is different scope
from the substituter-facing proposal and shouldn't be bundled into the
first ask.

### 4. Functional-test precedent — resolved

- **`tests/functional/post-hook.sh`** — the actual post-build-hook test
  (not `post-build-hook.sh` as guessed in the first pass); real
  `nix-build --post-build-hook <script>` against a throwaway
  `$TEST_ROOT` store, shell-level assertions.
- **`tests/functional/signing.sh`** — real keypairs via
  `nix-store --generate-binary-cache-key`, asserts on `nix path-info
  --json` and `nix store verify --sigs-needed N` behavior via an
  `expect <code> <cmd>` idiom.
- **`tests/functional/binary-cache.sh:232` vs. `:236`** — direct existing
  precedent for the exact property this project's semantic model depends
  on:
  ```sh
  (! nix-store -r "$outPath" --substituters "file://$cacheDir2" --trusted-public-keys "$publicKey")
  # ... a second, adequately-evidenced substituter added:
  nix-store -r "$outPath" --substituters "file://$cacheDir2 file://$cacheDir" --trusted-public-keys "$publicKey"
  ```
  One substituter's evidence is rejected; a second substituter with
  adequate evidence for the same path still succeeds — already tested
  today, independent of this proposal, and a direct pattern to extend
  rather than invent.
- `tests/functional/ca/signatures.sh` and `ca/substitute.sh` exist and are
  the natural place to extend CA-specific coverage once (1) above is
  acted on. No single `require-sigs`-specific test file — the flag is
  exercised across 13 files, consistent with it being cross-cutting.

**Smallest harness shape**: extend `binary-cache.sh`'s multi-substituter
pattern with a hook script analogous to `post-hook.sh`'s
`--post-build-hook <script>` wiring, using `signing.sh`'s
`expect <code>` idiom, to prove: (a) hook absent → behavior identical to
today's `binary-cache.sh`; (b) hook always-refuses → a
`trusted-public-keys`-valid path is still rejected in authoritative mode;
(c) hook missing/crashing → rejection, not silent accept; (d) the exact
`cacheDir2`-then-`cacheDir` pattern, hook refusing only `cacheDir2`'s
candidate → `cacheDir` still succeeds; (e) hook governs one substituter,
a second ungoverned substituter is available → fallback is refused by
default or requires explicit opt-in, and is logged either way.

### Decision table

| Question | Observed behavior | Security implication | Initial-scope recommendation |
|---|---|---|---|
| CA paths | `checkSignatures()` returns `maxSigs` unconditionally for any content-addressed path, before the signature loop ever runs | A hook at the existing gate is fully bypassed for CA paths — they get byte-integrity, never authorization, under the current primitive | State CA paths out of scope for v1 explicitly, or add a second, distinct hook path — do not assume the input-addressed gate covers them |
| Realisations | Structurally separate entry point (`registerDrvOutput`, gated by `Xp::CaDerivations`); real signature checking with no CA shortcut, but the daemon RPC bypasses it unconditionally | A hook covering only `addToStore` misses realisation registration entirely; the daemon-RPC gap may allow unsigned realisation registration regardless of trust | Scope realisations explicitly in or out for v1; flag the daemon RPC gap for a maintainer to confirm intentional |
| Evidence at `addToStore` | Raw signatures + fingerprint present in `info`; substituter identity is not part of `addToStore`'s signature, only available in the substitution-goal caller's local scope | A hook needing "which substituter offered this" (for the candidate/substituter-scoping semantics already recommended) needs new plumbing, not just a new check | Confirms a small, scoped internal data-flow change is needed if per-substituter context matters to the hook design |
| Trusted-user bypass | `dontCheckSigs` requires the connection already be `trusted` per Nix's pre-existing multi-user daemon model | Intentional, established boundary, not a new gap this proposal introduces | Exclude from v1 scope explicitly; document as inherited; offer "enforce for trusted ingress too" as a distinct future option |
| Test precedent | `binary-cache.sh` already tests exactly the multi-substituter-fallback property this design depends on; `post-hook.sh` shows the CLI-wiring pattern; `signing.sh` shows the failure-assertion idiom | Strong structural precedent exists — a hook's test suite extends established patterns, not a new methodology | Model functional tests directly on `binary-cache.sh` + `post-hook.sh` |

### Conclusion

**A small internal data-flow change is needed before the experiment —
*conditionally*, depending on v1 scope. Under a narrower, arguably better
v1 scope, it isn't.**

The substituter-identity gap above only matters if v1 requires *policy*
that varies by substituter. It does not require that. Re-read
`substitution-goal.cc:108-121` directly: `pathInfoIsUntrusted(*info)` is
already called once per loop iteration, once per substituter, with that
substituter's own candidate evidence (`*info`, carrying that candidate's
own raw `.sigs`) in scope. A hook plugged into this exact call site
inherits correct per-candidate, try-the-next-substituter-on-refusal
behavior **for free from the loop's existing structure — no explicit
substituter-identity parameter needs to be threaded anywhere — as long as
the policy itself is global** (the same evaluation applied uniformly to
whichever candidate's evidence is currently in scope, not "policy X for
substituter A, policy Y for substituter B"). This matches both current
Nix (`trusted-public-keys` is already global) and #14451's own original
shape (one configured `trusted-signatures-command`, not a per-substituter
one). Verified directly against the loop, not just reasoned about.

So: **a v1 scoped as one global provider, evaluating raw signatures for
input-addressed paths only, needs no substituter-identity plumbing at
all** — that data-flow gap becomes irrelevant, not because the finding
was wrong, but because it was only a blocker for a more ambitious
per-substituter-policy design this project doesn't need to attempt first.
The CA-path short-circuit remains a real, unconditional gap regardless of
scope — it isn't scope-dependent the way the substituter-identity finding
was, and v1 should explicitly exclude CA paths rather than assume the
existing gate covers them (see the decision table above, unchanged).

Revised bottom line: **current Nix can support a minimal, global,
input-addressed-only raw-evidence authorization experiment cleanly, with
no dependency on #15926 and no data-flow change required** — provided v1
deliberately does not attempt per-substituter policy, CA-path coverage,
or realisation coverage. Those three remain real, identified gaps; they
just don't have to be closed before a first experiment, because a first
experiment doesn't need to attempt them.

## Unresolved questions

Marked explicitly rather than guessed at — this list is a feature of the
archaeology, not a gap to apologize for. Items resolved by the follow-up
pass above have been removed from this list; what remains:

- Whether helper results should be cached, and if so, keyed and
  invalidated how — not evaluated in either pass.
- Substituter fallback across different trust scopes, beyond the
  candidate/substituter/goal-scoping questions already raised.
- Whether the `daemon.cc:979` `RegisterDrvOutput` RPC's unconditional
  no-signature-check is intentional (matches "realisations are trusted
  build output" reasoning) or an oversight relative to the rest of
  `daemon.cc`'s consistent `trusted`-gating — needs a maintainer's answer,
  not another archaeology pass.
- Whether closing the CA-path gap should mean a second hook site, or a
  change to `checkSignatures`/`pathInfoIsUntrusted` themselves — both are
  plausible, neither has been designed.

## Non-normative status

Nothing in this document should be read as a design decision, a
commitment to a specific enforcement mode's exact semantics, or a claim
that upstream will accept any particular shape. It is a factual snapshot
of one source revision, examined once, intended to replace assumption
with evidence before further design or implementation work — and to be
explicit about exactly where evidence runs out.

# Trusted Timestamping for the stash Audit Log — Assessment

Status: proposal / pre-implementation. Grounded in the current Go code, not the
Python framing in the task brief (this repo is Go; see §1).

## 1. What is actually in the repo today

The audit log is a single, self-contained Go package: `internal/audit/audit.go`
(tests in `audit_test.go`). It is **per-node**, append-only, lives in its own
bbolt file (`audit.db`), and is **not** part of the replicated Raft store — each
node attests only to the operations it actually served.

Concrete facts the timestamping design has to respect:

- **Entry schema** — `Entry` struct (`audit.go:38`): `Seq, Time, Identity,
  Action, Path, Result, Node, PrevHash, Hash, Sig`. `Time` is a self-asserted
  local wall clock: `time.Now().UTC().Format(time.RFC3339Nano)` (`audit.go:207`).
  `Sig` is `omitempty`.
- **Digest** — `entryDigest(e) [32]byte` (`audit.go` ~`:159`): canonical SHA-256
  over `Seq,Time,Identity,Action,Path,Result,Node,PrevHash`, NUL-separated.
  **Excludes `Hash` and `Sig`.** `hashEntry` is its hex form.
- **Chain** — each entry sets `PrevHash = l.last`; `Verify()` walks in seq order
  checking `PrevHash` linkage and `hashEntry(e) == e.Hash`.
- **Signature** — per-entry Ed25519 over the digest (`Record`, `audit.go:210`).
  Key is a persistent Ed25519 key at `<data>/audit.key` (`LoadOrCreateKey`),
  loaded via the `WithSigningKey` option. `Verify()` enforces signatures from a
  **signing epoch** (first signed entry) onward, exempting any legacy unsigned
  prefix.
- **Storage** — bbolt bucket `audit`, keyed by big-endian `uint64` seq.
- **External fan-out already exists** — `Log.Stream(sink)` ships each persisted
  entry to a sink; `cmd/stash/loki.go` ships to Loki best-effort. **This is an
  existing off-host channel we can reuse to publish anchor receipts.**
- **Read API** — `GET /v1/audit` (admin) returns `{entries, verified, count}`
  (`internal/server/server.go:595`), calling `Page` + `Verify`.
- **Dependencies** — only four direct: `hashicorp/raft`,
  `hashicorp/raft-boltdb/v2`, `bbolt`, `golang.org/x/crypto`. CLAUDE.md:
  "Don't add dependencies casually." This is the single biggest constraint on
  the options below.

### What the current design does and does **not** defend against

Hash-chain + Ed25519 signature is tamper-evident against an **outsider without
the key**: they cannot rewrite an entry without recomputing its hash, which
forces a re-signature they cannot produce. That is the gap that was just closed.

It does **nothing** against the threat this task targets: a **malicious key
holder / post-compromise attacker who also controls the system clock**. They
hold `audit.key`, so they can rewrite every entry, set every `Time` to whatever
they like, recompute every `Hash`, and re-sign the whole chain. The result is
internally perfect. `Verify()` returns `intact = true`. Self-asserted `Time` is
worthless here. This is exactly why external, unforgeable time binding is needed.

## 2. What each mechanism actually buys (honest crypto semantics)

This matters because the brief's "combined window" framing can over-promise.
Against a key holder who controls the clock:

- **Upper-bound anchoring (proof an entry existed *no later than* T)** — the
  **load-bearing defense against backdating.** Periodically send the current
  chain head hash to an external append-only, time-bearing record and keep the
  receipt. The attacker controls their key and clock but **cannot forge the
  external authority's statement** (a TSA signature, a Bitcoin block, a Rekor
  signed checkpoint) that "this head existed at T." Because the head transitively
  commits to every prior entry, one anchor timestamps all history before it. To
  rewrite an anchored entry the attacker would need an anchor over the *new* head
  dated at the *old* time — which no honest TSA/Bitcoin/Rekor will ever produce.
  Their only move is to present a log with **missing/younger anchor coverage**,
  which a verifier that expects anchors at a known cadence flags. → Backdating
  resolution = anchoring cadence. **This is the mechanism that does the real
  work.**

- **Lower-bound beacon embedding (proof *no earlier than* T)** — weaker than the
  brief implies **for the backdating threat specifically.** Embedding a recent
  unpredictable beacon (drand round, etc.) proves an entry could not have been
  *precomputed* before that round — it defends against **forward-dating /
  precomputation and proves freshness/liveness.** But a backdating attacker wants
  entries to look *older*, and old beacon values are public, so they can simply
  embed an old round. Lower bounds alone do **not** stop backdating. Their real
  value in this system: (a) liveness ("the log was active at least this recently"
  — useful against a held-back/replayed log), and (b) tightening the *window*
  when paired with anchoring.

- **Combined → a verifiable window** — anchoring gives the upper edge, beacon the
  lower edge. Genuinely useful, but note the residual: between two anchors a key
  holder can still slot a fabricated entry anywhere in `[embedded-beacon-time,
  next-anchor-time]`. The window is only as tight as the anchor cadence. So
  beacon-per-entry mostly buys liveness + a coarse floor; it is not a substitute
  for frequent anchoring.

- **Forward-secure sealing (FSS, à la systemd-journald)** — the **only mechanism
  that protects *already-written* entries against the key holder themselves.**
  The signing key is evolved one-way each epoch and the prior epoch key is
  destroyed; verification material (the seed) is kept off-host. After compromise
  the attacker has only the *current* epoch key and cannot derive past epoch keys,
  so they cannot silently re-sign sealed prior epochs. Limits: it protects only
  entries sealed *before* compromise (all future entries are forgeable once the
  key is held), and it gives **ordering/epoch integrity, not wall-clock time.**
  It complements anchoring: anchoring = external wall-clock + anti-backdating;
  FSS = cheap, fully-offline, no-privacy-surface protection of the past *between*
  anchors. Tying a sealing epoch to each anchoring interval is the natural fit.

**Bottom line:** for the stated threat, **upper-bound anchoring is mandatory and
sufficient as a first step**; FSS is the high-value second layer; per-entry
beacon embedding is a nice-to-have that should not be over-sold.

## 3. Option-by-option evaluation

Privacy note up front: **all three anchor options send only a 32-byte hash** (the
chain head). No entry contents, paths, identities, or plaintext ever leave the
host. This satisfies the hard privacy constraint for RFC 3161, OpenTimestamps,
and Rekor alike.

| Option | Latency | New dependency | Offline verify | Proof storage | Trust model | UX |
|---|---|---|---|---|---|---|
| **RFC 3161 TSA** | ~1 HTTP round-trip (sync) | RFC3161/CMS is **not** in stdlib → either add a small lib (e.g. `digitorus/timestamp`) or hand-roll ASN.1+PKCS7 (large, stdlib has no PKCS7 verify) | **Yes** — token verifies against the TSA root cert, no network | DER token per anchor (~few KB) | Trust an audited TSA authority | Easy: configure a TSA URL + pin its root cert |
| **OpenTimestamps → Bitcoin** | **Hours** (wait for block confirmation); receipt is "pending" until then | OTS proof format + a calendar client; verify needs Bitcoin block headers | **Partial** — deterministic given a trusted block-header source you keep locally | `.ots` proof per anchor (grows until upgraded) | **Trustless** (no authority) | Two-phase (stamp now, upgrade later); operationally heavier |
| **Sigstore Rekor** | ~1 round-trip to hosted log | Rekor client + Sigstore trust root (TUF) | **Yes given** Rekor pubkey + checkpoint, but proofs are fetched online | Signed entry timestamp + inclusion proof | Trust a hosted transparency log + its monitors | Easy API, but adds a hosted external dependency + Sigstore trust root |
| **drand beacon (lower bound)** | Embed-time only (fetch latest round) | drand HTTP client + pinned group public key | **Yes** — round signature verifies against the group key offline | Round id + signature stored in/with the entry | Trust the League of Entropy threshold network | Changes the **entry digest** (see §4) |
| **FSS (forward-secure sealing)** | None (local) | None — `golang.org/x/crypto` already present has what's needed (HKDF/HMAC); journald-style FSPRG can be built in-tree | **Yes** — fully local | Evolving key state on-host; **verify seed off-host** | No external party | Operator must store the off-host verification seed safely |

Reading of the table for **this** project (hobby, minimal deps, offline-friendly,
single static binary, air-gap-tolerant):

- **RFC 3161** is the best default anchor: synchronous, low-latency, one hash out,
  token verifies fully offline against a pinned root. The only cost is the
  dependency question — see §6.
- **OpenTimestamps** is the right *optional* trustless upgrade for operators who
  refuse to trust any TSA and can tolerate hours of latency + heavier ops. Good
  as a second backend behind the same interface, not the default.
- **Rekor** is capable but the least aligned: it adds a hosted dependency and the
  Sigstore trust root, which is heavier than this project's ethos. Skip for now.
- **drand** only delivers the lower bound, which (§2) is the weakest piece for the
  backdating threat and forces an entry-schema change. Defer / optional.
- **FSS** adds **zero external dependencies and zero privacy surface** and is the
  strongest protection of past entries against the key holder — the natural
  phase-2 layer, epoch-aligned to anchoring.

## 4. Recommendation

A two-layer design, implemented incrementally:

1. **Phase 1 (recommended PoC): periodic chain-head anchoring, upper bound.**
   Default backend **RFC 3161**, structured behind an `Anchorer` interface so
   **OpenTimestamps** can drop in later without touching callers. Off by default,
   enabled by a feature flag. Cadence is a tunable that directly sets backdating
   resolution. Anchor receipts stored in a new bucket and **also shipped over the
   existing Loki `Stream` channel** so they live off-host independently of
   `audit.db`.

2. **Phase 2 (optional, high value): forward-secure sealing**, epochs aligned to
   the anchoring interval — seal-and-anchor at the same boundary. No new deps, no
   data leaves the host, and it is the only layer that constrains the key holder's
   ability to rewrite already-sealed entries.

3. **Deferred / optional: per-entry drand beacon** for liveness + a coarse lower
   bound, only if a verifiable *window* (not just an upper bound) is required.
   Gate it exactly like the existing signing epoch (§5).

Rationale: anchoring is the mechanism that actually answers the threat in the
brief, RFC 3161 fits the latency/offline/privacy constraints with the smallest
footprint, and the interface keeps the trustless (OTS) path open. FSS is the
correct next layer precisely because anchoring alone leaves the *between-anchors*
window and *post-compromise future* exposed.

## 5. Back-compatibility analysis

**The recommended Phase-1 design changes the `Entry` digest path not at all.**
Anchors reference head **hashes**; they are stored *beside* the chain, never
inside `Entry`. Therefore:

- `entryDigest` / `hashEntry` / `PrevHash` linkage / the Ed25519 signature epoch
  logic in `Verify()` are **byte-for-byte unchanged**. Existing entries remain
  valid; historical logs do not need rewriting.
- `Verify()` (chain + signature) is untouched. Anchor checking is a **separate,
  additive** routine (`VerifyAnchors`), so a node with anchoring disabled behaves
  exactly as today. The `GET /v1/audit` response gains an **optional** `anchors`
  summary field; absent it, old clients/console are unaffected.
- **Migration path is purely additive and self-healing for history:** the *first*
  anchor stamps the *current head*, which transitively covers the entire
  pre-existing log. So switching anchoring on immediately gives all prior history
  a (coarse, "existed by first-anchor-time") upper bound — no backfill, no
  invalidation. Resolution sharpens going forward at the configured cadence.
- Feature flag (e.g. `-audit-tsa <url>` / `STASH_AUDIT_TSA`, plus a pinned root
  cert path and a cadence): unset → zero behavior change.

**If/when beacon embedding (Phase 3) is added**, it *does* change the digest
(a new field must be hashed). The codebase already has the exact pattern for this:
the **signing epoch** in `Verify()`. Mirror it — add the beacon field as
`omitempty`, include it in `entryDigest` only from a recorded epoch seq onward,
and make verification tolerant of its absence in the pre-epoch prefix. This keeps
old entries verifiable while new ones carry the beacon. No historical rewrite.

FSS (Phase 2) changes key handling, not entry serialization; it layers on the
existing signature and is gated by its own flag, so non-FSS logs verify unchanged.

## 6. Scoped PoC (Phase 1) — IMPLEMENTED

Decision taken (maintainer): **option (A)** — add the focused dependency
`github.com/digitorus/timestamp` (pulls in `digitorus/pkcs7` indirectly) for
RFC 3161 token build/verify, rather than hand-rolling CMS/ASN.1 (stdlib has no
PKCS7 verify). What shipped, all behind an off-by-default flag:

- **`internal/audit/anchor.go`**:
  - `Anchor{HeadSeq, HeadHash, Backend, Time, Token}` stored in a new bbolt bucket
    `anchors` **inside the existing `audit.db`**, keyed by big-endian `HeadSeq`.
    Anchoring never touches `Entry` serialization.
  - `Anchorer` interface (`Stamp(ctx, headHash) -> token, genTime, backend`) with a
    `TSAAnchorer` RFC 3161 implementation. Room for an `ots` backend later behind
    the same interface.
  - `Log.Anchor(ctx, Anchorer)` — snapshots the current head under the lock, does
    the TSA round-trip outside it, persists the `Anchor`. No-op on an empty log.
    Sends only `SHA-256(headHash)` to the TSA.
  - `Log.VerifyAnchors(roots)` + `Log.Anchors()` — for each anchor: re-derive the
    entry at `HeadSeq`, confirm it still hashes to the anchored head, confirm the
    token imprint commits to that head, and verify the token chains to a pinned
    root with the timestamping EKU. Deterministic, **network-free**. Returns
    per-anchor `{HeadSeq, Time, OK, Err}`.
- **`cmd/stash` wiring** (mirrors `-audit-loki`, both `server` and `join`):
  `-audit-tsa <url>` / `$STASH_AUDIT_TSA` plus `-audit-anchor-interval`
  (default 1h — the backdating resolution knob). `startAuditAnchoring` stamps once
  at startup (so existing history gets an immediate upper bound) then on each tick;
  best-effort, failures logged and retried. Unset flag → zero behavior change.
- **Tests (`internal/audit/anchor_test.go`)** against a **fully local fake RFC 3161
  TSA** (its own CA + timestamping leaf, `httptest` server — no network):
  happy-path stamp→store→`VerifyAnchors` asserting the proven time; a malicious
  key holder rewriting the anchored head entry with a fresh consistent hash is
  caught by `VerifyAnchors` while `Verify()`'s chain check stays green;
  untrusted-root rejection; empty-log no-op.

### Status

- **Chosen TSA: DigiCert** (`http://timestamp.digicert.com`) — free, no auth,
  reliable, and its timestamping root is in the system trust store, so
  verification works against system roots with nothing to distribute.
- **Verification surface: done.** `stash audit verify [-data DIR] [-tsa-roots
  FILE]` runs the chain + signature check and `VerifyAnchors` offline, printing
  the proven upper bound and a non-zero exit on any failure. Uses `audit.key` for
  signature verification when present, else chain-only (e.g. on an off-host copy).
- **Live smoke test: done.** A real anchor + verify round-trip against DigiCert
  passes end-to-end (token ~6 KB, verified against system roots), and the shipped
  `stash audit verify` binary reports `OK` on a clean log and fails closed on a
  tampered one.

### Remaining next increments (not yet done)

- **Off-host anchor shipping** (push anchor tokens to Loki via the existing
  `Stream` channel) is described in §4 but not wired; anchors currently persist in
  `audit.db` only. Worth adding so anchor coverage survives disk loss.
- **`anchors` summary on `GET /v1/audit`** for the web console (requires extending
  the server `Auditor` interface) — kept out to stay scoped; the CLI covers
  verification for now.
- **Phase 2 (FSS)** and **Phase 3 (drand lower bound)** remain future work as in §4.

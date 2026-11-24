# ZKC Credential Lifecycle & Revocation Freshness

**Status:** Reference (non-normative)
**Implementation:** `python/zkc_issuer/adapter.py` (renewal), `python/zkc_holder/lifecycle.py` (holder upkeep), `python/zkc_revocation/` (chained announcements, gap detection, durable issuer storage)

**Launch implementation status:** the issuer publication path now emits `zkc:epoch-announcement:v3` in authenticated metadata v2, and the durable service variant persists and recovers its ordered history. The verifier cache and private witness provider now enforce the complete v3 chain, pre-pinned key and accumulator ids, freshness, bounded backfill, durable checkpoints, and signed-fork evidence retention. Implementations MUST NOT claim end-to-end v3 launch conformance until they also pass the authenticated-revocation conformance suite.

Privacy-preserving proofs are only acceptable to verifiers when credentials are demonstrably FRESH: unexpired, unrevoked, and proven against an accumulator state within `MAX_EPOCH_LAG`. This document describes the production lifecycle handling the reference stack implements.

## Lifecycle state diagram (holder view)

```
                 issue / renew
                      │
                      ▼
                ┌──────────┐   witness lag enters refresh margin,
   refresh ───▶ │  FRESH   │   or expiry within expiry margin
   (tick)       └────┬─────┘ ──────────────────────────────┐
                     ▲                                      ▼
                     │  refresh (tick)                ┌──────────┐
                     └─────────────────────────────── │  AGING   │
                                                      └────┬─────┘
                                                           │ lag exceeds
                                                           │ MAX_EPOCH_LAG
                     refresh (tick)                        ▼
                     ┌─────────────────────────────  ┌──────────┐
                     │   (recoverable)               │  STALE   │  proofs
                     ▼                               └────┬─────┘  REJECTED
                ┌──────────┐    expired / revoked /       │
                │  FRESH   │    refresh refused           ▼
                └──────────┘ ◀── renewal /          ┌──────────┐
                                 re-issuance ────── │ UNUSABLE │
                                                    └──────────┘
```

- **FRESH** — proof generation succeeds; no action.
- **AGING** — usable, action recommended: witness lag ≥ `MAX_EPOCH_LAG − refresh_margin_epochs` (refresh now, before rejection) or expiry within `expiry_margin_seconds` (plan renewal).
- **STALE** — witness lag > `MAX_EPOCH_LAG`: proofs are rejected until the witness is refreshed. Recoverable.
- **UNUSABLE** — expired, revoked, or witness-less: refresh cannot help; renewal (active credentials) or full re-issuance (revoked subjects) is required.

## Holder upkeep: `RefreshPolicy` + `LifecycleManager`

`RefreshPolicy` is a **pure scheduling computation** — given `refresh_margin_epochs` and `expiry_margin_seconds` it defines `refresh_due_lag` and `next_refresh_epoch(witness_epoch)`. There is no daemon: the embedding application calls `LifecycleManager.tick(now)` (cron, event loop, or before a proof session), which:

1. assesses every stored credential (`assess_credential` — pure, no I/O);
2. refreshes every witness that is due (AGING-by-lag or STALE) through the holder's accumulator provider;
3. reports structured outcomes (`TickReport`): refreshed ids, refresh refusals (revoked/unknown — surfaced as renewal-required, never silently skipped), and credentials needing renewal.

Failure modes covered by tests (`tests/python/test_credential_lifecycle.py`):
missed refresh → proof rejected stale → recovered by one `tick()`;
revoked → refresh refused at the next scheduled refresh → renewal path.

## Issuer renewal: atomic re-issuance

`BaseIssuerAdapter.renew_credential({"credentialId": …, "expiresAt": …})` re-issues an ACTIVE credential:

- **holder commitment preserved** (no new binding ceremony; the subject's existing verified + holder-bound state is required and re-checked);
- **bounded validity** (`expiresAt`, a future u64 integer no later than the original provider-verified expiry when that expiry is nonzero) and a **fresh accumulator slot** (new credential id). Omission keeps the current credential's expiry. Shortening and later restoring validity within the original provider bound is allowed; repeated renewal never raises that bound. Provider expiry zero means no provider deadline, but renewal still requires a finite future expiry;
- **the old credential is revoked atomically** — `IssuerAccumulator.replace` validates everything up front, then performs register-new + revoke-old as ONE epoch transition (both-or-neither). Any earlier failure (unknown id, revoked id, unverified subject, expired key, past expiry) leaves the accumulator and epoch untouched.

Renewal accepts only `credentialId` and optional `expiresAt`, applies the adapter's active privacy profiles and per-client rate limit, and requires the trusted authenticated session that owns the current lineage. Unknown and foreign credential ids receive the same refusal before any status lookup. Revoked, superseded, and expired credentials cannot be renewed. Renewal does not add a recovery path for a closed lineage; production re-verification and re-issuance remain subject to issuer policy.

## Epoch-publication hardening: authenticated chained announcements

Launch epoch announcements are **signed and chained** (`zkc:epoch-announcement:v3`): each announcement carries `previousAnnouncementHash`, the SHA-256 commitment to the canonical complete signed predecessor announcement. The deterministic signature transcript binds the version, accumulator id, root, epoch, publication time, maximum epoch lag, signing-key id, and predecessor hash. The verification key is pinned by local trust policy (or separately authenticated delegation), never accepted merely because the same metadata document asserts it.

The launch `zkc_revocation.AnnouncementChain` contract is the holder/verifier-side consumer:

- signature verified against the allowlisted issuer key;
- the key is trusted only inside its pin: each `AnnouncementKeyPin` carries `notBefore`/`notAfter` (Unix seconds, half-open) and an optional `retireAfterEpoch`, and an authentic announcement whose `announcedAt` or epoch falls outside them raises **`AnnouncementKeyWindowError`** (`ANNOUNCEMENT_KEY_OUTSIDE_VALIDITY`). The check covers the head, backfilled and caught-up history, and a reloaded checkpoint. A bare `(x, y)` pin is refused;
- epochs must advance (replay rejected);
- a skipped epoch raises **`EpochGapError`** — structured, with `missing_epochs` — so the caller can backfill from `announcement_for_epoch` and re-ingest in order;
- a signed announcement that does not commit to the observed predecessor raises **`ChainLinkageError`**: the issuer produced a forked signed history, which holders/verifiers must treat as a revocation-distribution failure and retain as signed evidence.

At launch, `VerifierAccumulatorCache` and the holder witness providers (`PrivateWitnessProvider`, `WitnessUpdateProvider`, and `HTTPWitnessUpdateProvider`) MUST ingest through this chain contract, reject same-epoch replacement, enforce the signed freshness fields, and persist both the last trusted checkpoint and conflicting signed evidence. The reference implementations enforce that contract and require explicit verifier-local key/accumulator identity policy (holders pin the accumulator id with `accumulator_ids` or a `(source, accumulator_id)` target) and a `VerifierCheckpointStore`; production callers use `SQLiteVerifierCheckpointStore`, while the in-memory store is test-only. A persisted checkpoint never moves backwards, also when several workers, threads, or holder processes share one store. Each ingest re-reads the persisted head under a per-(issuer, accumulator) lock and validates the candidate against that head, so a worker whose own view is older still rejects an older announcement as a replay. The store then re-reads the head in the same write transaction (`BEGIN IMMEDIATE` for SQLite). It rejects a write with a lower epoch, a write that replaces a retained announcement, and a write that does not extend the head it re-read. These consumers write only through `compare_and_swap_checkpoint`, so a custom store must implement that method atomically. Threads that share one `SQLiteVerifierCheckpointStore` instance must open it with `check_same_thread=False`. A checkpoint more than `max_backfill` (default 32) epochs behind the head is never discarded. `catch_up` on `VerifierAccumulatorCache` or `PrivateWitnessProvider` verifies at most `max_backfill` announcements past it per call, persists that step through the same compare-and-swap, and returns a resumable `CatchUpStatus`. Historical announcements need not be fresh; the head keeps the age rule (specification §2.4.1). `VerifierAccumulatorCache` accepts only metadata v2 and returns an immutable authenticated state. A caller-created `IssuerAccumulatorState` cannot authenticate a selective-disclosure root.

### What the launch chain does and does not prove

The launch construction separates four failure modes:

- **Stalling** — the issuer stops advancing or publishing. Local freshness limits eventually reject the stale view, but do not prove that the issuer has a newer hidden view. A quiet but honest issuer is not stalling: it keeps its unchanged head fresh with signed `zkc:epoch-liveness:v1` statements (specification §2.4.2), which consumers verify under the same key pins and windows and use only for the exact head each one names. An issuer that stops attesting goes stale `max_announcement_age` seconds after its last attestation.
- **Omission** — a party is not given an existing announcement. A later gap is detectable and must be backfilled, but an isolated party held on a valid prefix cannot distinguish omission from no new mutations.
- **Replay** — a previously valid announcement is served again. A verifier with a persisted newer checkpoint rejects it; a cold-start verifier has no prior checkpoint and relies on the signed freshness bounds. Re-serving the persisted head itself is not a replay: re-polling unchanged metadata changes nothing and reports no error. A replayed liveness statement extends freshness only up to its own `issuedAt`.

Revocation latency is bounded in time, not only in epochs. `VerifierAccumulatorCache.state()` serves a superseded root only while the earliest `announcedAt` of the announcements after it is within `max_announcement_age`, and the head's root only while the head's freshness time is. A revoked credential therefore stops verifying at most `max_announcement_age + max_clock_skew` seconds (3900 seconds by default) after the issuer signs the revoking announcement, however few epochs follow. Obtain the state for each verification. `accumulator_states()` evaluates each issuer separately and leaves out an issuer whose state cannot be served; `accumulator_state_results()` reports the reason. Liveness statements are kept in memory by each verifier worker and holder provider, not in the checkpoint store.
- **Equivocation / split view** — the issuer signs different successors or histories for different parties. Each isolated history can remain internally valid. Signatures and predecessor commitments ensure that conflicting views become durable, attributable evidence, but detection happens only when checkpoints or announcements from the views are compared.

Accordingly, a valid signature prevents an untrusted third party from substituting a root, and a local checkpoint lets one verifier detect a fork that crosses its observed history. Neither property establishes global agreement. Two isolated holders or verifiers can follow different consistent signed chains indefinitely if their views never meet.

The planned post-launch mitigation is a per-issuer CT-v2-style append-only revocation log. Inclusion and consistency proofs are necessary for auditing a served log view, but they are not sufficient to discover two separately consistent views. Independent monitors must fetch and retain checkpoints, and holders/verifiers must gossip or otherwise compare those checkpoints so an equivocating issuer cannot keep the audiences permanently isolated.

## Durable issuer storage and announcement-key rotation

`DurableRevocationAccumulatorService` persists the issuer side through an `AccumulatorStateStore` (`SQLiteAccumulatorStateStore` in production, the in-memory store in tests). The store is an append-only log, version `zkc:revocation-accumulator-state:v3`:

- a header written once (`version`, `accumulatorId`, `maxEpochLag`);
- one signer record per announcement key (`keyId`, `publicKey`, `fromEpoch`; public material only);
- one epoch record per epoch (`epoch`, the `operation` that produced it, and the signed announcement verbatim).

This log is the issuer's private recovery store. It is not the planned public CT-style revocation log described above.

Each mutation appends exactly one epoch record. Its size depends on the changed leaves and the announcement, not on the history length (about 0.6 KB per issuance with 254-bit ids). The SQLite schema rejects UPDATE and DELETE on log rows. Leaves, the credential index, the revoked set and the delta snapshots are not stored. Recovery rebuilds them by replaying the operations, and fails closed unless:

- each announcement verifies under the signer recorded for its epoch and commits to its predecessor;
- each replayed root equals the signed root of its epoch;
- the supplied signing key is the last recorded signer.

The live service keeps leaf snapshots only for the newest `DELTA_SNAPSHOT_WINDOW` (33) epochs before the current one. That is the default `max_backfill` (32) of `VerifierAccumulatorCache` and `PrivateWitnessProvider` plus the epoch the client already holds; it also exceeds `MAX_EPOCH_LAG`. A `fromEpoch` outside the window gets a full refresh, never an error.

The service signs only with a key valid at the epoch's `announcedAt`. Under a key outside its window, an issuance, revocation or renewal fails with `EXPIRED_ISSUER_KEY` before the accumulator, the epoch, the announcements or the store change. Recovery still opens with an expired active key, so its history stays readable; rotate to a valid successor to sign again.

To rotate the announcement key, call `rotate_signing_key(successor)`. The successor must be valid when it is rotated in. The successor is recorded with `fromEpoch` = current epoch + 1 before it signs; nothing is re-signed, and the next announcement commits to the old key's chain head. Verifiers must pre-pin the successor key id before that epoch. After a restart, open the service with the successor key. A retired key, or an unrecorded key, fails closed. If only the successor's private key is available, `open(..., allow_rotation=True)` verifies the history and then records the supplied key as the successor. Key ids and public keys of recorded signers are never reused. The store authenticates history against its own signer records; the trust boundary for a signer remains the verifier's pre-pinned keys.

A store written by the earlier single-document format (`zkc:revocation-accumulator-state:v2`) is migrated on open with the key that signed its history. The service derives each epoch's operation from consecutive v2 snapshots and verifies the result like any log. The result must also reproduce the v2 leaves, credential index, revoked set and chain head; only then does one transaction replace the document with the log. Any inconsistency, or a different key, leaves the document untouched and fails closed. A v2 store whose history spans more than one announcement key cannot be migrated (v2 never recorded the earlier public key). Reset such a store: start a new accumulator id, have verifiers pin it, and re-issue the active credentials.

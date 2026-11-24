# ZKC Metadata Leakage: Threat Model & Mitigations

**Status:** Reference threat model (non-normative)
**Scope:** metadata that leaks AROUND the cryptography — what observers learn even when every credential attribute is hidden inside a valid ZK proof.
**Implemented assertions:** `tests/python/test_metadata_leakage.py` (CI-pinned)

ZKC hides credential *contents* cryptographically. It does not, by itself, hide *that* a proof happened, *which predicate* it used, *which issuer's* accumulator it referenced, or *when*. This document systematically models those channels per flow × observer, states which mitigations the reference stack actually implements, and is honest about residual risk.

Observers considered:

- **V** — the verifier in the interaction
- **I** — the issuer / its revocation service
- **R** — the registry host (whoever serves discovery/registry data)
- **N** — a network observer (sees endpoints, sizes, timing; not payloads when transport encryption is used)
- **P** — a platform/transport intermediary relaying messages for the holder/agent (e.g. a credential-proxy-style service)

## 1. Flow × observer analysis

### 1.1 Issuance

| Observer | What leaks | Linkability risk | Severity |
|---|---|---|---|
| I | Subject identity (inherent: KYC verification), holder commitment, schema, issuance time | Issuer can link the commitment to the real-world subject — by design; the commitment is what later proofs are bound to | High (inherent, bounded) |
| N | That the holder contacted issuer X at time T; message sizes | Holder↔issuer relationship | Medium |
| P | Same as N if the holder routes issuance through a platform | Holder↔issuer relationship + frequency | Medium |

The issuer knowing the subject is the trust premise of attestation, not a leak. What MUST NOT leak at issuance: the master seed and binding key (never leave the client — enforced + tested in the holder SDK and by the issuer adapter's recursive forbidden-field rejection).

### 1.2 Witness refresh (revocation freshness)

| Observer | What leaks | Linkability risk | Severity |
|---|---|---|---|
| I | **Per-credential protocol:** WHICH credential refreshed, when, from which network vantage | The revocation service can build a refresh timeline per credential and correlate it with verifier-side proof timing ("credential C refreshed minutes before each session at exchange E") | **High — mitigated (implemented)** |
| N | That a holder synced accumulator X at time T | Issuer-relationship only (with the epoch-fetch protocol, not which credential) | Low–Medium |

### 1.3 Registry / discovery lookups

| Observer | What leaks | Linkability risk | Severity |
|---|---|---|---|
| R | Which predicates/issuers/verifiers a holder is interested in, query timing — a *pre-interaction intent signal* | Registry host could profile upcoming compliance interactions | **High — mitigated (implemented)** |
| N | That a registry copy was fetched | Low (bulk fetch is uniform) | Low |

### 1.4 Proof presentation

| Observer | What leaks | Linkability risk | Severity |
|---|---|---|---|
| V | Predicate type(s), predicate parameters, **issuer public key** (a public input), accumulator epoch, proof timing, holder commitment | The commitment is a STABLE identifier across that verifier's sessions; issuer choice narrows the holder's population ("issued by a small regional issuer") | High (partially inherent) |
| N | Holder↔verifier contact, timing, message sizes | Session-level linkability | Medium |
| P | Everything V sees if the platform relays envelopes | Platform-side profile of compliance activity | High when a relay is used |

A verifier that fixes the Merkle root and inclusion path can test for one
credential code. A successful proof confirms that code. A refusal based on
the credential can also leak information about it. The holder refuses these
requests before consulting credential holdings unless the holder explicitly
authorizes exact-code disclosure for the predicate. The local audit log records
that opt-in without the code or witness. For jurisdiction requests with
canonical codes, the holder checks the root and computes its own path.
Canonical sets can still disclose a narrow condition, including equality
when the list contains a single distinct code. See specification §7.2c.5.

### 1.5 Refusals (negotiation / agent responses)

| Observer | What leaks | Linkability risk | Severity |
|---|---|---|---|
| V | Whether a refusal means "holder has no such credential" vs "policy refused" — if messages differ, a verifier can PROBE holdings without ever receiving a proof | Population narrowing via probing | **High — mitigated (implemented)** |

### 1.6 Revocation check (verifier side)

| Observer | What leaks | Linkability risk | Severity |
|---|---|---|---|
| I | Which verifiers track its accumulator (announcement fetches) | Verifier↔issuer business graph | Low |
| V | Nothing new (epochs/roots are public inputs) | — | — |

### 1.7 Audit export

| Observer | What leaks | Linkability risk | Severity |
|---|---|---|---|
| Auditor | Exactly the scoped proof set + verification context (by construction) | Bounded by the holder-signed scope | Low (by design) |
| P | Bundle hash/size if relayed; contents are schema-restricted (no credentials/seeds/history) | Existence of an audit relationship | Low–Medium |

### 1.8 Authenticated epoch publication

| Observer | What leaks | Linkability risk | Severity |
|---|---|---|---|
| Anyone fetching metadata or announcements | Exact successful accumulator-mutation count since genesis, plus each mutation's publication time | With external events or issuer traffic, observers can estimate issuance, revocation, and renewal timing and volume; the announcement does not identify credentials or distinguish the mutation type | **Medium — accepted launch residual** |
| I | The mutation type and affected credential (inherent issuer state) | Issuer already knows the lifecycle event it performs | Inherent |

### 1.9 Revocation publication views

| Observer / party | What it can establish at launch | Residual risk |
|---|---|---|
| Holder or verifier | A pinned key authenticates the issuer; a persisted checkpoint plus predecessor commitment detects replay, gaps, or a fork that crosses the locally observed history | It cannot tell whether an issuer is withholding a newer announcement or serving a different internally consistent history elsewhere |
| Independent network observer | Endpoint and timing metadata only when transport encryption is used | It does not automatically receive or compare signed checkpoints and therefore is not a monitor |
| Issuer | Can sign two conflicting successors or maintain two signed histories | The conflict creates attributable signed evidence, but isolated audiences do not detect it until their views meet |

Authentication and global consistency are different guarantees. The launch signature gives **third-party substitution resistance**. The chained predecessor and persisted checkpoint give **locally observed fork detection**. Neither gives **global split-view detection**: two isolated parties can each hold an internally consistent, correctly signed view.

### 1.10 Credential identifiers and operator mutations

Credential identifiers are public. Each active credential id is a leaf of the issuer accumulator, and M2 publishes the whole leaf set: the anonymous `zkc:epoch-delta-request:v1` full mode returns every active id, and delta mode shows which slot changed in each epoch. This exposure is inherent to client-side witness computation and is accepted, not hidden. It reveals no claim, holder commitment, or subject.

A credential id therefore must never act as authorization. Knowing one proves nothing about who holds the credential.

| Surface | Who may call it | Why |
|---|---|---|
| Stage 1-3 issuance routes (`IssuerServer`) | The caller of the authenticated session that the adapter's trusted callback names | Issuance continuations bind to that session |
| `renew_credential`, `sign_rebind_attestation` | The authenticated session that owns the credential's lineage | The id only names the credential; the session authorizes it |
| Revoke and renew over HTTP (`IssuerAdminServer`) | An operator holding a pinned operator key | Separate listener; each request is an ECDSA secp256k1 signature over the issuer id, method, request target, body digest, timestamp and a single-use nonce |
| Stage 4 `publish_revocation_handle` | Anyone (rate-limited) | A public status and witness oracle, see below |
| Witness-update request (`RevocationServer`) | Anyone | The same public oracle; deployments rate-limit it at their gateway |

The holder-facing `IssuerServer` routes no mutation that lacks a principal; an anonymous `POST /v1/issuer/revoke` is not routed (HTTP 404). Revocation and renewal live only on `IssuerAdminServer`. It refuses unsigned, unknown-key, stale (outside the clock-skew window), replayed, body-tampered, retargeted and high-s requests with one HTTP 401 shape before it parses the body. The reference server has no TLS; bind the admin listener to an operator-only interface.

Stage 4 is a **public status and witness oracle**. For any id it returns `active` with a membership witness, `revoked`, or `unknown`. It is not holder-authorized because it releases nothing beyond the published leaf set: anyone can rebuild the accumulator from the epoch delta and compute the same status and witness. An observer that has followed the deltas also knows the `revoked`/`unknown` distinction. The adapter rate-limits stage 4 per window even when no per-stage limit is configured (`default_publication_reads_per_window`, 600). Unauthenticated callers share one bucket, so a flood can delay other public readers but cannot reach state.

| Observer | What leaks | Linkability risk | Severity |
|---|---|---|---|
| Anyone fetching the epoch delta or stage 4 | Every active credential id, each epoch's added and removed slot, and per-id status | Ids link a credential's own issuance, renewal and revocation epochs; they carry no subject data | **Low — inherent to M2, accepted** |

## 2. Mitigations table

| # | Leak | Status | Mitigation |
|---|---|---|---|
| M1 | Registry lookups as intent signal (1.3) | **Implemented (pre-existing — referenced here)** | ALL registry reads are local-copy: `PredicateRegistry.from_repo` and `DiscoveryRegistry.from_repo` operate on a local clone of the registry tree with **no network access at lookup time** (`zkc_registry.store` docstring: "the registry is an advisory cache that works fully offline"). The registry host sees at most a uniform bulk clone/pull, never per-predicate queries. CI-pinned: registry loads succeed with networking disabled. |
| M2 | Per-credential witness refresh tells the issuer which credential refreshed (1.2) | **Implemented over HTTP** | `zkc_revocation.PrivateWitnessProvider` pins the accumulator id and issuer keys and fetches the full leaf set via `zkc:epoch-delta-request:v1`. The request body is identical for all holders of that accumulator and omits both the credential id and `fromEpoch`. The holder checks the leaves against the exact signed head obtained independently from a configured common publication source and computes membership witnesses locally. Each refresh downloads O(leaf count). `WitnessUpdateProvider` and `HTTPWitnessUpdateProvider` send the credential id and use compact witnesses. |
| M3 | Refusal shape reveals credential holdings (1.5) | **Implemented (req'd by planner/agent API; pinned here)** | Constant-shape refusals: every holder/agent wire refusal carries the same message (`zkc_holder.REFUSAL_MESSAGE`, "cannot satisfy this proof request") whether the private cause is no-credential, policy refusal, consent refusal, or an opaque predicate — and planning is store-independent (the planner never reads the credential store), so even response *behavior* does not branch on holdings. CI-pinned: wire equality across all causes, including the no-credential case. |
| M4 | Proof timing correlation (1.4, and refresh-then-prove correlation with 1.2) | **Documented guidance (partial)** | Do not refresh a witness immediately before the proof that uses it from the same network vantage; prefer scheduled background refresh (`LifecycleManager.tick` on a cadence decouples refresh time from proof time) and M2 so the refresh names no credential. Spec §8.3 already lists randomized proof generation for timing side-channels. Residual: traffic analysis by a global network observer is out of scope. |
| M5 | Holder commitment as a stable cross-session identifier at one verifier (1.4) | **Residual (documented)** | Inherent to the current envelope (`holderBinding.commitment` is how multi-proof envelopes bind to one holder). Cross-VERIFIER linkability is already limited (the commitment is the only stable field and contexts differ); per-verifier pairwise commitments are future work (requires a circuit change — KDC-derived per-audience binding). |
| M6 | Issuer choice narrows holder population (1.4) | **Residual (documented)** | The issuer key is a public input the verifier must check against its allowlist. Spec §8.2 states that issuer privacy is not provided by the current circuits: the verifier learns the specific issuer. (An earlier §8.2 claim that the verifier "learns issuer type, not specific issuer" was aspirational and has been corrected.) Future work: issuer-set membership proofs (prove "an issuer in this allowlist signed" without revealing which). |
| M7 | Platform/transport relays see proof flows (1.4 P) | **Residual (documented)** | Out of protocol scope: ZKC defines no relay. Guidance: holders/agents should talk to verifiers directly over transport encryption; when a relay is unavoidable, it sees envelopes (proofs, public inputs) but never credentials/seeds (non-custodial boundary) — and audit bundles are schema-restricted (M1/M3 in `docs/zkc_audit_disclosure.md`). |
| M8 | Issuance metadata (1.1) | **Residual (inherent, bounded)** | The issuer knows the subject — that is attestation. Bounded by: secrets never leave the client; rebinding/audit mappings are sealed + minimized (spec §4.5). |
| M9 | Signed epoch cadence reveals issuance/revocation/renewal volume (1.8) | **Accepted launch residual; semantics frozen in v3** | `zkc:epoch-announcement:v3` advances once per successful state mutation and never for failure/no-op. Announcements contain no credential identifier or mutation-type field. Batching, a minimum epoch period, and padding were rejected for launch as described below; changing this cadence requires a new protocol version. Head liveness statements (specification §2.4.2) advance no epoch and carry no mutation information. |
| M10 | Revocation split view / issuer equivocation (1.9) | **Launch local mitigation implemented; global detection remains partial** | The issuer publishes v3 signatures and complete predecessor commitments; the durable issuer retains ordered history, while verifier and holder-witness consumers enforce pre-pinned keys, freshness, bounded backfill, persisted checkpoints, and signed-conflict evidence. Stalling, omission, replay, and equivocation remain distinct: freshness bounds address stale data, backfill addresses observable gaps, checkpoints reject local replay, and signed conflicts provide attributable evidence. None proves that an isolated valid view is globally unique. A post-launch per-issuer CT-v2-style log must be paired with independent monitoring and checkpoint gossip; inclusion or consistency proofs alone only validate the particular view served to their requester. |

With M2, a leaf service cannot choose a tag by selectively serving a different
valid signed head. A mismatch fails refresh, including during mirror lag or
concurrent publication. Raw delta requests still disclose their `fromEpoch`
when a caller supplies it. Proofs still expose the accepted accumulator epoch,
and addresses, request timing, and publication-history lookups can correlate
activity. M2 depends on a shared publication view independent of the leaf service.
A publication source that serves selective views can still tag proofs (1.9).

## 2.1 Launch decision: epoch cadence and issuance-volume leakage

The launch profile deliberately keeps the existing accumulator lifecycle: genesis is epoch 0; a successful registration/issuance advances one epoch; a successful revocation advances one; an atomic renewal/replace advances one for the combined add/remove; and a validation failure, duplicate, rejected mutation, or no-op advances none. The issuer signs and durably publishes one complete announcement for every such successful transition.

The pre-launch alternatives were evaluated as follows:

| Alternative | Privacy effect | Security/operational cost | Launch decision |
|---|---|---|---|
| Per-mutation advancement | Exposes exact mutation cadence and total successful lifecycle mutations; does not identify a credential or mutation type | Revocation visible to every verifier within `A + S` seconds (3900 seconds with the reference defaults, specification §2.4.2), simple witnesses, deterministic historical backfill, and matches the implemented accumulator | **Selected** |
| Batched advancement | Coarsens volume and timing within a batch | Delays revocation, requires queue durability and atomic batch semantics, and changes witness/epoch meaning | Rejected for v3 |
| Minimum epoch period | Coarsens time but still leaks whether a period changed | Couples acceptable revocation latency to a global cadence and needs explicit empty-period behavior | Rejected for v3 |
| Padding / cover updates | Can hide whether a transition was real if cover traffic is sustained | Adds permanent signing, storage, bandwidth, and operator-schedule assumptions; sparse or stopped cover traffic is itself revealing | Rejected for v3 |

The selected rule prioritizes prompt, unambiguous revocation and a small launch surface over lifecycle-volume privacy. This is an explicit acceptance, not an unspecified future mitigation. A deployment that needs batching, a minimum period, or cover updates must use a new announcement version that redefines epoch meaning, witness freshness, mutation failure behavior, and canonical bytes; it cannot reinterpret v3.

Per-mutation epochs alone gave no time bound on revocation: a credential revoked by a low-volume issuer stayed provable until `maxEpochLag` further mutations happened, and a quiet issuer's head went stale after the age limit. The separately versioned `zkc:epoch-liveness:v1` statement (specification §2.4.2) closes both gaps without changing the epoch rule. It is not a cover update: it advances no epoch, changes no root, and carries no credential identifier or mutation information, so it adds nothing to the M9 cadence leakage. It reveals only that the issuer was online and willing to sign at `issuedAt`. The reference issuer re-signs it on demand once the previous statement is older than its interval, so `issuedAt` can also show approximately when some consumer first requested metadata or an update after that interval; an issuer that wants request-independent timing calls `sign_liveness()` on a fixed schedule.

## 3. CI leakage assertions

`tests/python/test_metadata_leakage.py` pins the implemented behaviors so they cannot silently regress:

1. **M1** — `PredicateRegistry.from_repo` + `DiscoveryRegistry.from_repo` succeed with socket creation monkey-blocked (no network at lookup time).
2. **M2** — holders with different credentials and checkpoints send byte-identical HTTP bodies. A still-fresh signed older response fails against the independently observed head. The locally computed witness verifies end to end at the published epoch, and revocation still fails closed.
3. **M3** — wire refusals are byte-identical (modulo nonce) across: no-credential, policy-block, untrusted-verifier, overbroad-request, and opaque-predicate causes — planner exceptions carry the same constant message, and the planner provably never touches the credential store.
4. **M4** — `LifecycleManager.tick` refresh works through the anonymous provider (refresh decoupled from proof time, no credential named).
5. **M9** — the issuer-metadata validator pins the v3 transcript, signed cadence-policy field, and complete predecessor-announcement hash; lifecycle tests pin +1 for issuance/revocation/atomic renewal and +0 for failures.
6. **1.10** — `tests/python/test_issuer_operator_router.py` pins that the holder listener routes no mutation, that the admin router refuses every unsigned or altered operator request, that stage 4 releases only what the public leaf set reveals, and that stage 4 is rate-limited by default.

## 4. Relationship to the spec

Non-normative: this document and its mitigations change no envelope, circuit, or verification rule. Spec §8 (Security Considerations) gains a pointer to this threat model; §8.2/§8.3 remain the normative privacy/attack tables.

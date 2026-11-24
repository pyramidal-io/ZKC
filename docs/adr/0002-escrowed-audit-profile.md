# ADR 0002: Escrowed Audit Presentation Profile

**Status: Accepted**
**Date:** 2026-07-02
**Accepted:** 2026-07-02

## Context

ADR 0001 established a presentation-profile ladder whose only decided axis is *which linking handle a presentation exposes to the verifier*: none (`anonymous`), a per-scope pseudonym (`scoped`), or the global `holderCommitment` (`linkable`). The same ADR recorded, as a deferred direction, an **escrowed audit handle**: a presentation that exposes *nothing linkable to the verifier* while carrying a verifiable encryption of the global commitment under a designated auditor key, so that a named authority can link retrospectively under an explicit governance process. This ADR is that promised dedicated record. It decides the *direction, placement, and hard invariants* of the escrowed profile — it does **not** finalize the cryptographic construction, and it explicitly does not assert soundness.

The motivation is real and narrow. ZKC is a compliance protocol, and some regulated flows genuinely require "an authority can link under due process." Today an operator wanting that property has only one lever: route the flow through the `linkable` profile, which hands the *verifier* the global `holderCommitment` — prospective, unbounded, cross-verifier linkability forever. That is a blunt instrument. The escrowed handle is the strictly narrower one: to the verifier it is observationally an anonymous (or scoped) presentation; the only party whose knowledge can change is a pre-designated auditor, only retrospectively, and only through an explicit governance step.

Two structural facts from ADR 0001 shape the entire design and are load-bearing here:

- **ZKC presents SNARK proofs about credentials, not credentials.** Linkability is purely a function of which public inputs a profile exposes. An escrow ciphertext is a *new public value*, so it lands squarely inside ADR 0001's public-input determinism invariant and must be reasoned about there, not as an out-of-band artifact.
- **The stable `holderCommitment = poseidon2(DOMAIN_ZKC_BINDING, cbk)` is deterministic in credential-only material by design.** So is the scoped `presentation_pseudonym = poseidon3(DOMAIN_ZKC_PRESENTATION_SCOPE, cbk, scope_id)`. The determinism invariant tolerates each only because it is the *declared* handle of its profile. An escrow ciphertext is **not** a declared verifier-facing handle — the verifier is supposed to be unable to open it — so a *deterministic* encryption of a `cbk`-derived value would fall under the invariant's *forbidden* clause and silently become a cross-verifier equality-join key. This is the sharpest hazard of the whole direction and the origin of this ADR's first hard invariant.

The proving system is Noir / UltraHonk over BN254. Poseidon and the entire existing gadget set are BN254-native; the one non-native gadget already in the suite is the secp256k1 ECDSA issuer-signature verification, which is the single most expensive component of a v2 predicate proof. Any escrow construction must be evaluated against that reality, not against an abstract scheme on paper.

## Decision

ZKC will adopt the **escrowed audit handle as a declared, opt-in *attribute*** of the ADR 0001 `anonymous` and `scoped` profiles (`anonymous+escrow`, `scoped+escrow`) — **not** a fourth mutually-exclusive profile enum value (see Placement below) — positioned as *strictly narrower disclosure than the `linkable` profile*, and governed by the hard invariants below. Consistent with ADR 0001, this ADR records **direction and invariants only** and is **Accepted** on that basis. Acceptance is a human governance act for an open standard; it ratifies the direction and the hard invariants below — it does **not** ratify any specific cryptographic construction, nor authorize implementation. The construction, the auditor-key governance, and the implementation are separate, gated deliverables (see Follow-up); no escrow code ships until the independent cryptographic review clears.

### Placement on the ladder

Escrow is modeled as an **orthogonal attribute of the `anonymous` and `scoped` profiles**, not a fourth mutually-exclusive rung. The ladder's only decided axis is the verifier-facing handle; escrow does not change that handle at all — it adds a *second, verifier-invisible recipient* (the auditor). The coherent combinations are therefore **`anonymous+escrow`** and **`scoped+escrow`**. `linkable+escrow` is explicitly incoherent and MUST be rejected: the verifier already holds the global commitment, so re-encrypting it to an auditor grants the auditor strictly less than the verifier already has, and requesting it would be a footgun (a holder might read "escrow" as *adding* privacy on top of linkable when linkable already leaks more). Modeling escrow as a fourth mutually-exclusive rung would wrongly force giving up anonymity to gain auditability — the exact opposite of the compliance sweet spot this profile exists to serve.

To a verifier, `anonymous+escrow` is observationally equal to `anonymous`, and `scoped+escrow` to `scoped`: the escrow ciphertext, being a CPA-secure randomized encryption, reveals nothing the verifier can act on. The verifier's linkability delta versus the corresponding non-escrowed profile is **exactly zero**. The only party whose knowledge changes is the auditor, and only after an explicit governance-gated opening.

### Hard invariant 1 — per-presentation ciphertext randomization (MUST)

The escrow value **MUST** be a randomized/probabilistic encryption with fresh, independent randomness `r` per presentation, so that the ciphertext is **NOT a deterministic function of `cbk` or of the global `holderCommitment`**. This is the load-bearing invariant of the entire direction.

A deterministic escrow ciphertext (fixed `r`, or `r` derived deterministically from `cbk`) would be byte-identical across every presentation of the same credential and would become a perfect cross-verifier equality-join key — a handle *silently worse than the `linkable` profile*, because it would link even across presentations the holder chose to make `anonymous` or `scoped`. That is precisely the unlinkability the ladder was built to remove, reintroduced through the escrow channel.

The invariant is not satisfied by "use randomized ElGamal" as a slogan. It imposes a concrete circuit obligation: the well-formedness proof MUST constrain `r` as a genuinely fresh in-circuit witness (bound to per-session context such as `proof_context`, range/consistency-checked, never reusable as a constant), so a malicious prover cannot reuse or deterministically derive `r`. Whether a given construction actually enforces this is a soundness question for the independent cryptographer (see Governance and Follow-up); this ADR states the requirement, not its proof.

### Hard invariant 2 — consent, declaration, and downgrade-only (MUST)

Escrow **MUST** obey the identical negotiation discipline ADR 0001 imposes on the `scoped` profile. It is a compliance feature, but compliance does **not** exempt it from consent — the whole point of the ladder is that even compliance linkability is opt-in and negotiated, never ambient.

- **Declared, never ambient.** Escrow MUST be affirmatively named in an authenticated APR (Safeguard 6). It MUST NOT be reachable by absence of a block the way `anonymous` is the absent-block default. An absent escrow block means *no escrow*.
- **Holder-consented.** Escrow requires a distinct consent flag on the holder `ProofRequest` (analogous to `allow_protocol_scope`), plus an authenticated, trust-rooted auditor key (below).
- **Downgrade-only / never silently upgraded.** The holder MAY refuse escrow and present the underlying `anonymous`/`scoped` profile instead. The holder MUST NOT be silently upgraded into escrow. The failure direction is always *more privacy, never less* — a verifier that "loses" escrow merely receives a non-auditable presentation.
- **Recorded in the Disclosure Receipt.** The receipt gives the holder portable evidence that an escrow handle was demanded, under what purpose, and against which auditor key-epoch — the holder's lever that an escrow was even created (see Reconciliation → APR and receipts).

### Auditor key is a consent-bearing, trust-rooted parameter (MUST)

The named auditor public key is a consent-bearing act, directly analogous to `verifierIdentity` in scope derivation. The holder SDK MUST authenticate the auditor key against a trust root; it MUST NOT accept an arbitrary verifier-supplied opaque auditor blob. Otherwise a malicious verifier names *itself* as the auditor and re-obtains global linkability, defeating the entire "narrower than linkable" claim. The auditor key MUST be a single ecosystem-wide-or-governance-scoped published value (like `accumulator_root`), resolvable to a specific epoch, never a per-holder or per-verifier value — a per-verifier auditor key could itself become a holder-correlated linkage tag even with a randomized `r`.

This constraint is reconcilable with treating the auditor as a distinct per-flow registry role (Governance → Custody, per ADR 0001 Safeguard 1): a deployment picks a *named* auditor from among a small set of published, governance-scoped keys per flow-class. But per-verifier keys are not the only correlation hazard — key *proliferation* is. A compliance ecosystem that publishes many narrow governance-scoped auditor keys can, in aggregate, approximate per-verifier keys and reintroduce exactly the holder-correlation the per-verifier prohibition forbids: the set of concurrently-valid auditor keys a holder faces in a given flow-class is itself a partitioning tag. The population of concurrently-valid published auditor keys applicable to a given flow-class MUST therefore be bounded and small, and the independent cryptographic review gate (see "Follow-up" below) and the auditor-key governance ADR MUST evaluate key proliferation — not merely the per-verifier-key case — as a correlation hazard in its own right.

### Disclosure framing — strictly narrower than `linkable`

Against the `linkable` profile, escrow narrows on three axes simultaneously, and this is the honest framing the profile must be described with:

1. **Who can link.** `linkable` → any verifier holding the receipt/public
   input, plus any colluding set of them, unboundedly. Escrow → exactly the
   pre-designated auditor (or auditor quorum), nobody else.
2. **When.** `linkable` grants the verifier *prospective* recognition forever,
   from the moment it holds the commitment. Escrow grants only *retrospective*
   linkage, to the auditor, over presentations already collected — zero
   real-time recognition for the verifier.
3. **Under what control.** `linkable` linkage is unconditional once the value is
   out. Escrow linkage is gated behind an explicit governance/due-process step
   to invoke the auditor key.

This MUST NOT be overstated as "zero disclosure." The auditor is a real trust assumption and the ciphertext-at-rest is a real, durable, subpoena-reachable artifact. Escrow deliberately *manufactures* a compelled-disclosure target that `anonymous` and `scoped` structurally do not have (ADR 0001: "an identifier that is never emitted cannot be correlated, leaked, or subpoenaed"). It converts ZKC's "nothing to subpoena" posture back into "something to subpoena" — and is acceptable *only* where a specific regulated flow genuinely requires non-cooperative retrospective linkage, and a privacy foot-gun everywhere else.

### Construction is deliberately NOT finalized here

ADR 0001's phrase "Camenisch–Shoup style" is **indicative intent** — "verifiable encryption to a designated auditor" — and MUST NOT be read as a committed scheme choice. As the Alternatives below detail, Camenisch–Shoup lives in an RSA/Paillier composite-modulus group that does not natively fit BN254, and proving its well-formedness inside an UltraHonk circuit is at best impractical. The realistic in-circuit candidate is embedded-curve ElGamal on a curve whose base field *is* BN254's scalar field (Baby Jubjub / Grumpkin), and a commit-and-prove split is the conservative out-of-circuit fallback. **Which construction is correct is an open cryptographer decision**, gated on the independent cryptographic review described under "Follow-up" below. This ADR commits to the *direction and invariants*, not the scheme.

## Alternatives Considered

The alternatives fall on two axes: *where the verifiable encryption is proven* (in-circuit vs. out-of-circuit) and *how many parties hold the opening key* (single vs. threshold).

### In-circuit Camenisch–Shoup over BN254 — rejected as the primary

Camenisch–Shoup verifiable encryption is defined over an RSA/Paillier group (`Z_{n^2}`, with `n` a ~3072-bit modulus) and rests on the Decisional Composite Residuosity assumption. Its arithmetic is modular exponentiation on 3072-bit integers — a group entirely unrelated to BN254's scalar field. Proving a CS ciphertext well-formed *inside* a Noir/UltraHonk BN254 circuit means simulating 3072-bit modular arithmetic via limb decomposition over a 254-bit field: plausibly hundreds of thousands to millions of constraints per modular exponentiation, and CS well-formedness needs several. This is not the "significant work item" framing ADR 0001 used — in-circuit it is effectively impractical. Rejected as the primary construction. (CS's natural home is an out-of-circuit sigma/NIZK proof; it ships *with* its own non-SNARK proof of correct encryption. So "CS-style" effectively forces a commit-and-prove split rather than an in-Noir proof — see below.)

### In-circuit embedded-curve ElGamal (Baby Jubjub / Grumpkin) — leading candidate

The SNARK-friendly path is exponential/additive ElGamal on a twisted-Edwards curve whose base field equals BN254's scalar field `Fr` — Baby Jubjub (or Grumpkin, the BN254 2-cycle partner). Because the curve's coordinates *are* `Fr` elements, point additions and scalar multiplications are native field arithmetic in the circuit — no non-native emulation. Encryption is `C = (rG, M + rP_aud)` where `P_aud` is the (trust-rooted, epoch-pinned) auditor public key and `M` encodes the linking value. The circuit proves (a) the ciphertext is well-formed w.r.t. a fresh committed randomness `r`, and (b) that `M` binds to the **same private `cbk`** the predicate already constrains via `derive_holder_commitment(cbk) == holder_commitment` (the constraint already present in `zkc_kyc_v2/src/main.nr`). This is the only path that keeps well-formedness *inside* the existing UltraHonk proof rather than bolting on a second proof system. It is the **leading candidate**, but it is greenfield for this suite (no embedded-curve gadget is used anywhere today) and remains subject to the cryptographer gate.

Two sub-decisions it forces, neither settled here:

- **The field-element-plaintext problem.** `cbk`/`holderCommitment` are full ~254-bit `Fr` elements; exponential ElGamal (`M = mG`) only decrypts via discrete-log search, feasible only for small `m`. Candidate encodings, in increasing soundness cost: (1) encrypt a *point* the auditor matches against a known candidate set — a *linkability oracle* ("does this presentation belong to holder X from a known population?"), which may be exactly the compliance need. Option (1) is not merely a soundness-cost tradeoff: it changes the *disclosure semantics* and the consent surface. It shifts the auditor's capability from "link this presentation to its single global commitment" (the retrospective single-target linkage this profile is scoped to) to *set-membership testing against an arbitrary candidate population* — a different privacy property that silently widens *who* can be tested against without a fresh consent axis. The cryptographer gate and the auditor-key governance ADR MUST treat option (1) as a *capability* decision (population-testing), not purely an encoding/soundness tradeoff. (2) bit-decompose into ~8 small limbs and encrypt each (≈8× the EC cost); (3) encrypt a small decryptable *escrow tag* bound to `cbk` via Poseidon, so the ciphertext carries a short recoverable handle while the ZK binding does the heavy lifting. Option (3) is the most circuit-economical and is the leading sub-candidate — but which encoding gives the auditor *exactly* the intended capability without over- or under-disclosing is a cryptographer decision.
- **Proving cost.** A variable-base Baby Jubjub scalar-mul over a ~254-bit scalar is ~254 conditional point-additions (low thousands of constraints each), and ElGamal needs at least two, more if the plaintext is limb-decomposed. Order-of-magnitude estimate (which MUST be replaced by real `nargo` gate counts, not accepted from this ADR): one Baby Jubjub ElGamal + binding adds on the order of 10k–60k constraints, plausibly 2–10× the current ~2^17-row predicate, pushing circuits toward 2^18–2^19 rows with proportional prover time/memory. Aggregation circuits, already the heaviest, would be worst-hit. This is a materially heavier circuit, not a marginal add.

### Out-of-circuit verifiable encryption (commit-and-prove split) — documented fallback

Instead of proving encryption well-formedness inside UltraHonk, a presentation can: (a) inside the existing SNARK, expose a Poseidon *commitment* to the escrow value bound to `cbk` (one extra public input, ≈1 Poseidon, near-zero cost); and (b) alongside, carry a *separate* purpose-built verifiable-encryption proof (a sigma-protocol / Groth–Sahai NIZK, or a CS ciphertext with its native CS proof) that the ciphertext encrypts the *same* committed value. The shared commitment is the link. This keeps the heavy EC/RSA work *out* of the BN254 circuit (leaving predicate circuits nearly untouched) at the cost of a second proof artifact, a second verifier code path, and a **cross-proof binding argument whose soundness is the whole ballgame** — the classic place subtle unsoundness hides. It is a legitimate, arguably lower-risk near-term direction and is recorded here as the conservative fallback, explicitly gated on the cryptographer confirming the cross-system binding has no malleability/re-binding gap.

### Single-auditor (1-of-1) custody — rejected as the reference

A single decryption key is a single point of privacy failure whose blast radius is *every escrowed presentation ever recorded, retroactively* — a worse failure mode than the `linkable` profile it is meant to be narrower than. `linkable` leaks one holder to one verifier prospectively; a compromised or coerced single-auditor key de-anonymizes the entire escrowed population at once and makes the auditor a standing hack-and-subpoena target. Single-key custody is at most a degenerate deployment choice the spec MUST NOT bless as the default or reference.

### Threshold t-of-n custody — recommended reference

The reference escrow MUST specify threshold `t`-of-`n` distributed decryption, with custodians across distinct legal/operational domains and an explicit non-collusion assumption, so no single party (and no single warrant) can link unilaterally. Crucially, threshold is *nearly free on the circuit side*: the circuit still encrypts to a single aggregate/joint auditor public key `P_aud = ΣP_i` (or a DKG-generated joint key); thresholding lives entirely in key generation (a DKG among the `n` auditors) and decryption (partial decryptions combined off-line). This is a strong argument for embedded-curve ElGamal over CS, where threshold Paillier is far more painful. The DKG, rogue-key/key-aggregation resistance on `ΣP_i`, and the `t`-of-`n` combine are governance and key-ceremony work items — and cryptographer-gate items — not in-circuit cost.

### Designated-verifier encryption — noted and set aside

Designated-verifier proofs convince only a named party and are sometimes floated for "auditor-only" semantics. But the escrow requirement is *retrospective, non-interactive, committee-transferable* linkability, not "convince one online party now." Designated-verifier constructions do not give the auditor a durable, later-decryptable handle without the holder online, so they do not meet the stated need. Set aside.

## Reconciliation

### Ladder placement and profile identifiers

Escrow rides the existing ladder as the orthogonal `+escrow` attribute of
`anonymous` and `scoped` (Decision → Placement). The cleaner encoding for the
APR/registry — consistent with how `scoped` added `pseudonym`+`scopeId` as a
conditional block rather than forking the profile enum — is to keep the base
`profile ∈ {anonymous, scoped, linkable}` and add a *sibling* `escrow` object,
so the accepted-profiles policy gate stays two-dimensional
(`profile × escrow-required`) instead of exploding the enum. Consistent with the
hard rejection in Decision → Placement, `linkable+escrow` **MUST** be rejected
at schema level, not silently allowed-but-pointless.

### Public-input determinism invariant — amendment REQUIRED

ADR 0001's invariant as written —

> No public input may be deterministic in credential-only material unless it is the declared linking handle of the active profile.

— would forbid the escrow ciphertext, since it is *derived from* credential material and is not a verifier-facing declared handle. ADR 0001 states this as a single rule with one declared-handle exception (it does not enumerate a numbered list of carve-outs). This ADR therefore **amends the invariant by adding an explicit exception for a per-presentation verifiable encryption**:

> A per-presentation verifiable encryption of the global commitment is a permitted public value **iff** (a) it is randomized with fresh per-presentation coins so it is NOT deterministic in credential-only material, and (b) it is openable only by the designated (threshold) auditor key, never by the verifier.

The conformance suite gains a new **negative** vector — the escrow analogue of `presentation-scoped-cross-scope`: two escrowed presentations of the *same* credential under the *same* auditor key MUST produce *different* ciphertexts, and an equality join across them MUST fail. This is the machine-check that guards Hard Invariant 1; a passing suite without it is not evidence the invariant holds.

### KDC / ZKA note-binding — no new edge

Escrow does not change the seed-path model. The ZKA value-address and the ZKC credential-commitment remain unlinkable without the seed. Upon opening, the auditor learns the ZKC global `holderCommitment` **only** — never the ZKA value-address (no new KDC edge is created). This non-interference claim is stated explicitly so it is reviewed, not assumed.

### Revocation accumulator — escrow is NOT an accumulator key

Non-revocation stays keyed by credential-id leaves with the witness private and `accumulator_root`/`accumulator_epoch` public (unchanged from ADR 0001). The escrow ciphertext is **not** an accumulator key and MUST NOT become one. An auditor opening the commitment MUST gain *no* revocation-linkage capability. This is a cryptographer-checkable non-interference claim.

### Aggregation — orthogonal to the ciphertext

Same-holder aggregation is a continuity claim seeded on `presentation_pseudonym` and requires `scope_id != 0` (design §4.3). Whether escrowed proofs aggregate depends on the *underlying* `anonymous`/`scoped` handle, **not** on the escrow ciphertext; the aggregation circuit MUST ignore the escrow field. The single-`cbk` binding suggests at most one escrow sub-proof per session pseudonym rather than one per inner proof; if aggregation is to cover escrow, the aggregation public-input commitment shape must be extended to include it — an open question, not decided here.

### Credential-rebind — escrow the new commitment, no cross-mapping leak

Rebind v2 is scoped-only and commits to old/new pseudonyms (design §4.2). If an escrow field is ever added to rebind, it MUST escrow the *new* commitment under Hard Invariant 1, and the auditor's opening MUST NOT correlate old↔new outside the sealed, issuer-assisted rebind mapping (which stays forbidden from public surfaces per ADR 0001).

### APR, consent, and Disclosure Receipts

The APR `presentation` object gains an optional `escrow` sub-object, covered by the existing APR signature (`apr_digest_from_dict` extends to include it), e.g.:

```jsonc
"escrow": {
  "required": true,
  "auditorKeyId": "…",        // resolves to a published, epoch-stamped key
  "keyEpoch": 7,
  "auditorKeyResolver": "…"    // how the holder authenticates the auditor key
}
```

Naming the auditor key is consent-bearing (Decision → Auditor key). The holder SDK MUST authenticate it against a trust root and MUST require an explicit `allow_escrow` consent flag; a verifier-supplied opaque auditor value is a protocol error. `linkable+escrow` is refused.

Disclosure Receipts bind **the base profile's handle plus escrow *metadata*, never the plaintext**: `{auditorKeyId, keyEpoch, ciphertextDigest}` (a hash of the escrow ciphertext), alongside the base handle (nothing for `anonymous+escrow`; `pseudonym`+`scopeId` for `scoped+escrow`). The receipt MUST NOT contain the global `holderCommitment` — that would re-create the linkable leak in the receipt channel, exactly the failure ADR 0001 §Reconciliation warns about. The digest's receipt-safety is not a separate conditional property: it follows directly from Hard Invariant 1 — the digest is receipt-safe *because* the underlying ciphertext is randomized per presentation, so a `ciphertextDigest` is a per-presentation value carrying no cross-presentation holder linkage. (If two parties who each hold a copy of the *same* presentation's receipt compare digests, they can confirm same-presentation identity — but the digest is presentation-unique by construction and links nothing across presentations, so for holder-custodied receipts this is harmless.) A deterministic ciphertext — and hence a deterministic digest — is exactly what Hard Invariant 1 forbids; the independent cryptographic review gate confirms the chosen construction upholds it in the receipt channel too. This gives the holder portable evidence of *which* auditor could de-anonymize this presentation, under which key epoch — supporting the required governance process — without the receipt itself being a de-anonymization oracle.

### Malleability / replay binding

The escrow ciphertext MUST be bound into the per-presentation `claim_binding`/`proof_context` (which already rotate per presentation via `proof_context` + `timestamp`, `main.nr`) so a ciphertext cannot be lifted from one presentation and spliced onto another — otherwise a verifier could staple a known-holder escrow blob onto an anonymous proof, or a relay could mix holder A's ciphertext onto holder B's predicate proof. That the shared-context binding actually prevents this splice/relay attack is a cryptographer-gate item.

## Governance

Escrow's privacy guarantee is a **governance-plus-non-collusion assumption layered on an in-circuit (or cross-proof) encryption construction**, not a pure cryptographic guarantee. It is strictly narrower than `linkable` *only if* the threshold custody, the opening transparency, and the non-ambient consent all hold; it is a privacy foot-gun if any of them fail. The governance surface is therefore first-class, not an afterthought — and much of it lives *outside* the protocol's cryptographic guarantees, which this ADR states honestly rather than papering over.

- **Custody.** Threshold `t`-of-`n` across distinct legal/operational domains, with an explicit non-collusion assumption; single-key is not the reference. Whether the spec mandates a minimum floor (e.g. `n ≥ 3`, `t ≥ 2`) or leaves `t`-of-`n` to deployment policy is an open governance question — a too-permissive floor (1-of-1 allowed) undermines the narrower-than-`linkable` claim.
- **Auditor as a distinct registry role.** The auditor is *not* analogous to a verifier or issuer and needs its own versioned registry atom: public key, threshold params, key-epoch, `notBefore`/`notAfter`, governance/warrant-policy URI, and transparency-log locator — pinned so the in-circuit well-formedness proof can assert encryption under a *specific published epoch key*. Per ADR 0001 Safeguard 1 this stays a per-flow *choice*: no auditor may be protocol-canonical or mandated; a deployment opts into a named auditor, ZKC never imposes one.
- **Key rotation and retrospective escrow.** Escrow ciphertexts persist to be opened later, so old ciphertexts under a retired key cannot simply be discarded. Ciphertexts MUST be bound to an auditor *key-epoch* (a first-class field), and the well-formedness proof MUST assert encryption under that epoch's canonical published key. Rotation caps *forward* blast radius per epoch (like `scoped`'s `rotationEpoch`); it does **not** retroactively protect already-recorded ciphertexts — a shard-set compromise for epoch `E` exposes all epoch-`E` escrows until shares are destroyed. This residual is normative, not implied protection.
- **Opening accountability — a new layer beyond Safeguard 6.** Safeguard 6 makes the verifier's *request* accountable (no signed APR ⇒ no proof). But the auditor's *opening* happens after the presentation, out-of-band, with no holder in the loop — structurally closer to "decision accountability is unreachable" than to request accountability. Escrow therefore needs its own primitives: a mandatory append-only opening-transparency log (each opening signed, timestamped, purpose/warrant-referenced), per-presentation opening (never bulk), rate limits, and threshold approval so no single shareholder opens unilaterally. Ideally an opening is *cryptographically invalid* unless it emits a published log commitment ("accountable decryption") — whether that is achievable or only an honest-log policy assumption is a cryptographer-gate item.
- **Compelled disclosure.** Threshold across jurisdictions raises the cost of a single warrant compelling all shares; per-presentation, purpose-keyed opening makes bulk de-anonymization not one operation; separation of the decrypt capability from the warrant/authorization gate limits unilateral misuse. None of these fully solves a wholly-compromised threshold set plus a coordinated cross-jurisdiction warrant; that residual MUST be disclosed normatively.
- **Coercive de-facto default.** Even with anonymous-by-default and per-presentation consent, a powerful verifier (or a regulator leaning on verifiers) can *require* escrow as a condition of service, turning "consent" into take-it-or-leave-it. ZKC cannot stop a verifier from demanding escrow; it can and MUST make that demand a *named, signed, purpose-bound, receipt-retained* APR artifact — the same move Safeguard 6 makes for verifier requests generally — so a coercive "you must escrow to transact" demand becomes attributable evidence rather than an invisible ambient setting.
- **Interaction with Freedom Safeguards.** Whether escrow should be *excluded entirely* from certain flows (e.g. anything touching ZKA settlement, to protect No-Revocability / Exit Rights) so it can never become a lever over custody/transferability — only over a counterparty's acceptance of a proof — is an open governance question flagged here, not decided.

The trigger boundary for a lawful opening, the data-retention/destruction model for ciphertexts and shares (which directly sets the compelled-disclosure window), and whether the auditor identity must be anchored to a named AID (as `verifierId` is) are governance deliverables for the auditor-key ADR, named here so their deferral is explicit rather than implicit.

## Consequences

- **A new, separate, draft-status circuit artifact.** Any escrow construction is a *new* Noir package (e.g. `noir/zkc_escrow_v1/` or `noir/<predicate>_escrow/`) with its own pinned `sourceSha256`/`acirHash`/`vkHash`, and its own `registry/predicates/<id>/<ver>/entry.json` carrying `review.status: "draft"` and `activation.activatedAt: null` — exactly the discipline the v2 entries already follow (the `zkc-kyc` 2.0.0 entry is `review.status: "draft"`, `evidence: []`). It cannot ride on any reviewed KYC entry, and it stays unactivated behind the crypto-review gate.
- **Composable sub-proof, not a per-predicate fork.** The recommended shape is a single composable escrow sub-proof bound to the main predicate proof (via shared `proof_context` + reuse of `assert_presentation_binding` / `derive_holder_commitment` over the same `cbk`), mirroring the aggregation binding pattern — adding *one* circuit and re-auditing *zero* frozen v2 predicates, rather than forking all five predicate circuits into `_escrow` variants (the 5×2 explosion) or minting a v3 family that repeats the whole v1→v2 migration for a feature only a minority of flows need. Carry it by *extending* the v2 envelope with an optional `presentationBinding.escrow` block plus a new `zkc:proof:escrow:v1` entry in `proofs[]` — not a v3 envelope. `zkc_lib` is reused additively (the escrow binding helpers), leaving v1/v2 ACIR/VK untouched.
- **Materially heavier proving.** Where the construction is in-circuit embedded-curve ElGamal, the circuit grows on the order of 2–10× the current ~2^17-row predicate (to be confirmed by real `nargo` gate counts), concentrated in the Baby Jubjub scalar-mul gadget, with aggregation worst-hit. Where it is the out-of-circuit commit-and-prove split, predicate circuits stay nearly untouched but the envelope gains a second proof artifact, a second verifier code path, and a cross-proof binding argument.
- **A new registry role and expanded conformance surface.** A versioned, epoch-stamped auditor-key registry atom; a new escrow public-input encoder; the amended determinism invariant; and a new negative escrow-unlinkability conformance vector. The per-predicate v2 registry entries are *untouched* — the payoff of the composable design.
- **A real, honestly-stated trust and compelled-disclosure cost.** Escrow re-introduces a decryptable artifact that `anonymous`/`scoped` structurally avoid. It is strictly narrower than `linkable`, but it is not free, and it must be documented as a governance-plus-non-collusion assumption, never marketed as "zero disclosure."
- **The existing holder-authorized AuditBundle remains the default compliance linkage.** ZKC already ships holder-authorized audit disclosure (`docs/zkc_audit_disclosure.md`), where the holder explicitly releases selected envelopes to a named auditor per window/purpose, gated on principal approval. That is a categorically *different* trust model (holder cooperates at disclosure time) and MUST NOT be conflated with escrow (auditor links without holder cooperation at link time). The escrowed handle is reserved for the specific regulatory regimes that genuinely mandate non-cooperative retrospective linkage; the holder-authorized AuditBundle stays the default everywhere else.

## Follow-up

Implementation is a **separate future requirement**, deliberately not opened by this ADR and gated on two conditions:

1. **Acceptance of this ADR — SATISFIED (Accepted 2026-07-02).** Acceptance was a human governance act ratifying the direction and invariants; it did not authorize implementation, which remains gated on condition 2 — now the sole remaining blocker.
2. **Independent cryptographic review.** No escrow soundness claim in this ADR is established until that review clears it. The review MUST cover, at minimum:
   - that the chosen verifiable-encryption scheme is IND-CPA and its in-circuit (or cross-proof) well-formedness genuinely guarantees the ciphertext encrypts a value bound to the *same* private `cbk` the predicate constrains — no "encrypt garbage / encrypt someone else's tag" gap;
   - that per-presentation randomness `r` is soundly enforced as genuinely fresh and non-reusable (Hard Invariant 1) — "randomized ElGamal on paper" does not by itself prove the circuit forbids constant-`r`;
   - the field-element-plaintext encoding choice (small decryptable tag vs. limb-decomposition vs. point/match-only) gives the auditor *exactly* the intended capability, over- and under-disclosing neither;
   - that ADR 0001's "Camenisch–Shoup style" wording is not implementable in-circuit over BN254 and, if CS is used at all, only as an out-of-circuit NIZK — and, for that fallback, the cross-system binding has no malleability/re-binding gap;
   - the threshold DKG, joint-key generation, rogue-key resistance on `ΣP_i`, and `t`-of-`n` partial-decryption combine;
   - the malleability/replay binding of the ciphertext to per-presentation context (splice/relay resistance);
   - that the randomized ciphertext preserves the amended determinism invariant in *every* channel it appears (public inputs, envelope, receipt) and re-introduces no cross-verifier or cross-channel linkability;
   - independent confirmation that the escrow handle's disclosure is genuinely *strictly narrower* than the `linkable` profile under the *actual* construction, threshold model, and rotation/retention model — proven, not assumed.

Until both gates clear, the escrow registry entry stays `review.status: "draft"` and unactivated, and no escrow circuit ships.

A companion **auditor-key governance ADR** (custody, DKG/key-ceremony, rotation and retention model, opening-transparency and accountable-decryption requirements, the lawful-opening trigger boundary, and any Freedom-Safeguard exclusions) is a separate deliverable, named here so its deferral is explicit.

Reference: ADR 0001 (`docs/adr/0001-multi-show-unlinkable-presentations.md`) and the presentation-profile design (`docs/zkc_presentation_profiles_design.md`), which lists the escrowed profile as out of scope for the ladder's follow-up implementation work.

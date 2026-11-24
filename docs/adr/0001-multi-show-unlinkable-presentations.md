# ADR 0001: Multi-Show Unlinkable Credential Presentations

**Status: Accepted** (amended)
**Date:** 2026-07-02
**Amended:** 2026-07-02 — the single scoped-pseudonym default is subsumed into a presentation-profile ladder with an anonymous (no-handle) default; the alternatives analysis is corrected for ZKC's SNARK-presentation architecture; Disclosure Receipt / APR reconciliation and the public-input determinism invariant are added.

## Context

ZKC's current presentation profile exposes `holderCommitment = H("zkc/binding", cbk)` as a proof public input. That value is intentionally stable for a credential binding key: it lets a circuit prove a credential belongs to the holder and lets issuer signatures bind the credential to the holder's private seed path without revealing the seed or real-world identity.

The same stability makes repeated presentations linkable by equality whenever the public input is visible. A single verifier can recognize the holder across sessions, and two colluding verifiers can compare public inputs. This is pseudonymity, not cross-verifier multi-show unlinkability.

A structural fact shapes the whole design space: **ZKC does not present credentials — it presents SNARK proofs about credentials.** The issuer signature is verified inside the Noir circuit; the credential, signature, and revocation witness are private witnesses. Linkability is therefore purely a function of which public inputs a presentation profile chooses to expose. Nothing else in a presentation is holder-linkable. This makes the linking handle a per-profile choice, not a property of the credential stack.

The design goal is:

- no holder-linkable emission at all by default — an identifier that is never emitted cannot be correlated, leaked, or subpoenaed;
- no cross-verifier tracking in any default or continuity profile;
- repeat recognition only inside an explicit verifier or protocol scope, requested and purpose-bound;
- stable-holder linking only when the holder opts into a flow that needs it, such as auditability or same-holder aggregation.

## Decision

ZKC will adopt a **presentation-profile ladder**. Every verifier-facing presentation declares exactly one profile, negotiated through the Authenticated Proof Request (§5.5) and fixed by the presentation's own public inputs (see the APR reconciliation below; the proof context does not encode the presentation profile). The stable `holderCommitment` remains the credential's private/load-bearing binding anchor in all profiles; it is never a required public input outside the explicit linkable profile.

| Profile | Public handle | Cross-verifier | Within-scope | Repeat recognition |
|---------|---------------|----------------|--------------|--------------------|
| `zkc:presentation:anonymous:v1` | none | unlinkable | unlinkable | none |
| `zkc:presentation:scoped:v1` | `presentationPseudonym` | unlinkable | linkable | per-scope |
| `zkc:presentation:linkable:v1` | global `holderCommitment` | linkable | linkable | global |
| escrowed audit handle | verifiably-encrypted commitment | unlinkable to verifiers | unlinkable to verifiers | auditor-only, retrospective |

### Anonymous profile — the default

`zkc:presentation:anonymous:v1` exposes **no holder-derived public input**. The circuit proves possession of a validly-issued, non-revoked credential whose private `holderCommitment` derives from the holder's `cbk`, and binds the proof to the session via `proofContext`. A pure gate check ("KYC'd and over 18") needs no continuity, so it emits no handle. This is the default profile: a verifier that wants continuity must request it as a declared, purpose-bound capability, not receive it ambiently.

**Amendment (security review 2026-10-04): the anonymous profile has no same-holder semantics.** "KYC'd and over 18" works anonymously because it is ONE proof over ONE credential. A conjunction across several proofs ("KYC'd AND accredited", or "KYC'd AND not sanctioned") is a same-holder claim, and anonymous proofs bind to no holder: two people each holding one credential can splice their honest anonymous proofs into one envelope that satisfies the conjunction. Verifiers therefore reject an anonymous envelope answering two or more distinct requested proof types (`UNBOUND_COMPOSITE`) unless their policy declares the proofs independent. Conjunctive gates use the scoped profile with the `session` scope policy, whose scope derives from the request's own context value: the proofs share one in-circuit pseudonym for that session only, so the gate gains a same-holder guarantee without cross-session or cross-verifier linkability. A successor statement with an anonymous per-context link tag `H(D_LINK, cbk, proofContext)` would offer the same guarantee inside the anonymous profile; it is not needed while the session scope exists and is not specified here.

### Scoped profile — domain-specific / scope-exclusive pseudonyms

`zkc:presentation:scoped:v1` publishes a scoped presentation pseudonym derived from the same binding key and a verifier or protocol scope:

```text
presentationPseudonym = H("zkc/presentation-scope:v1", cbk, scopeId)
```

A valid proof shows, in zero knowledge, that the credential's private `holderCommitment` and the public `presentationPseudonym` both derive from the same `cbk`. Presentations to different verifier scopes are unlinkable by equality; presentations within the same scope remain repeat-recognizable — this is what preserves per-scope Sybil resistance, rate limiting, and returning-holder continuity.

`scopeId` construction is the security boundary of this profile and is normatively constrained:

```text
scopeId = H("zkc/scope:v1", verifierIdentity, scopePolicy [, rotationEpoch])
```

- **Default: verifier-identity binding.** `verifierIdentity` is the authenticated verifier identity already established by Safeguard 6 / APR verification. The holder SDK derives `scopeId` itself from the authenticated request; it never accepts an arbitrary verifier-supplied opaque scope.
- **Broad protocol scopes are a consented exception, not a peer option.** A shared multi-verifier scope (a consortium, a federation) re-creates a broad pseudonym by construction. It requires its own explicit consent surface, distinct from ordinary scoped consent.
  Implementation clarification: the current canonical derivation includes the APR signer's identity for every policy string, including `protocol:<name>`. These names are signer-local and retain distinct consent. A shared multi-verifier scope remains a future extension; identical names under distinct signing keys do not share a pseudonym.

- **Optional rotation.** `rotationEpoch` (a coarse time bucket declared in `scopePolicy`) caps the historical-linkage blast radius of a later verifier compromise or subpoena to one epoch. Rotation lives inside `scopeId` construction so the pseudonym derivation — and the circuit — stay fixed across rotation policies. Verifiers relying on repeat recognition accept that recognition resets at epoch boundaries; a scope with rotation cannot simultaneously claim long-horizon Sybil resistance.

The prior art for this profile is deliberate: it is the Direct Anonymous Attestation *basename* construction (ISO/IEC 20008, TPM 2.0), Semaphore's *external nullifier*, and the pairwise pseudonymous subject identifier (PPID) of OIDC/SAML — a well-worn pattern, not an invention.

### Linkable profile — explicit only

`zkc:presentation:linkable:v1` is the current stable-commitment behavior, retained only as an explicit linkable presentation mode. It must be requested and consented to as such. Existing `zkc:proof:*:v1` envelopes are grandfathered as instances of this profile; callers must not describe them as unlinkable.

### Escrowed audit handle — recorded direction, separate ADR before implementation

ZKC is a compliance protocol, and some compliance flows genuinely require "an authority can link under due process." The recorded direction for those flows is **retrospective, auditor-only linkability**: the presentation carries a verifiable encryption of the global commitment under a designated auditor key (Camenisch–Shoup style), proven well-formed in zero knowledge. Verifiers see nothing linkable; a designated auditor can link after the fact under an explicit governance process. This is strictly narrower disclosure than routing audit flows through the linkable profile, which grants the *verifier* prospective linkability forever. Verifiable encryption inside the Noir circuit suite is a significant, separable work item: this ADR records the direction and defers the design to a dedicated ADR; the escrowed profile is **not** part of the follow-up implementation requirement below. The concrete direction is now recorded in docs/adr/0002-escrowed-audit-profile.md.

## Alternatives Considered

The alternatives are best understood on two independent axes, which the original version of this ADR conflated:

- **Axis 1 — presentation mechanism:** rerandomizable-signature shows versus SNARK-over-witness presentation. ZKC already sits at the strong end: the signature is a private witness, so no presentation reveals it.
- **Axis 2 — linking handle exposed:** none, scoped, global, or escrowed. This is the only axis actually being decided, and it is a per-profile choice.

### Domain-specific / scope-exclusive pseudonyms

Accepted, as the continuity profile of the ladder (not, after amendment, as the default). It is the smallest redesign that removes cross-verifier tracking while preserving per-verifier continuity, and it preserves the current issuer signature model, credential binding key, revocation accumulator shape, and proof-verifier trust policy model.

Residual risks — stated plainly, because the first is the profile's actual security assumption rather than a footnote:

- **Scope governance is the guarantee.** Cryptography enforces one pseudonym per `(cbk, scopeId)`; it cannot prevent an ecosystem from converging on a broad shared `scopeId`. The unlinkability claim of the scoped profile is therefore *contingent on the canonical `scopeId` derivation rule and on Safeguard 6 verifier authentication being enforced*. Both failure directions collapse onto `scopeId`: a verifier-broadened scope destroys unlinkability; a holder-rotated scope destroys repeat recognition.
- A verifier can still link all presentations inside its own scope, including historically after a compromise or subpoena (bounded by `rotationEpoch` where rotation is in force).
- Scoped pseudonyms remove only the *trivial equality join*. Colluding verifiers can still correlate via disclosed attribute values and transport metadata (network address, timing). Attribute minimization and transport privacy remain load-bearing; see the metadata leakage threat model (`docs/zkc_metadata_leakage_threat_model.md`).

### Rerandomizable credentials

BBS+, Coconut, and Idemix-style rerandomizable credentials are frequently described as the "stronger" alternative. For ZKC that framing is wrong on the privacy axis: because ZKC verifies the issuer signature in-circuit, the anonymous profile already delivers presentation unlinkability equivalent to a rerandomized show — including within a single verifier scope — without touching the signature scheme. What rerandomizable credentials would actually buy ZKC is **presentation cost** (no SNARK proving time per show) and ecosystem interoperability with anonymous-credential stacks (cf. the IETF BBS per-verifier linkability work, which independently arrives at the same scoped-pseudonym construction for its continuity mode).

They remain a future research track on those grounds — cost and bridging, not privacy — and are not the near-term profile because they would require replacing the credential signature scheme, revocation integration, issuer adapter contract, proof envelope shape, and likely parts of the Noir circuit suite at once. Reconsider if presentation latency becomes a product constraint or if an issuer ecosystem standardizes on an anonymous-credential stack that must be bridged into the ZKC proof envelope.

## Reconciliation

### ZKA note-binding

ZKA note-binding stays anchored to the private binding key path. The proof can verify the credential's private `holderCommitment` and derive a scoped public pseudonym — or, in the anonymous profile, no public handle at all — without revealing the holder's ZKA value-address or the global commitment. The KDC fact remains separate: the ZKA value-address and ZKC credential-commitment are unlinkable without the seed.

### Revocation accumulator

The revocation accumulator remains keyed by credential identifier leaves, with the accumulator root and epoch as public inputs and the witness private. The scoped presentation pseudonym is not an accumulator key. Issuers may still know the holder commitment they issued against; verifiers do not need that global commitment to check non-revocation in any profile.

`accumulatorEpoch` staleness is a minor fingerprinting surface: holders who update witnesses lazily partition into linkable epoch cohorts. Holder SDKs SHOULD refresh witnesses to the current epoch before presenting under the anonymous and scoped profiles, and `MAX_EPOCH_LAG` should stay tight.

### 7.3 aggregation

**Current status.** The paragraph below records the original design intent. The published aggregation circuits perform no recursive verification. The reference verifier rejects anonymous and scoped aggregation blocks and checks linkable v1 blocks only as commitments over individually verified proofs. See the specification §7.3 for the circuit constraints and verifier rules.

Aggregation keeps explicit consent per active proof. Same-holder aggregation is inherently a continuity claim, so it requires at least the scoped profile: the aggregation circuit requires all input proofs to carry the same `presentationPseudonym` for the same `scopeId`, not the global `holderCommitment`. Stable-holder aggregation across scopes remains available only in the explicit linkable presentation mode. Anonymous-profile proofs are not aggregable as "same holder" — by design, nothing attests that they are.

### Credential-rebind

Credential-rebind keeps proving continuity between old and new credential bindings, but public surfaces use scoped old/new presentation pseudonyms when a verifier-facing rebind proof is needed. Issuer-assisted rebind mappings remain sealed, minimized, access-controlled, and forbidden from public logs, proof public inputs, settlement records, indexer records, note discovery, compliance bundles, and revocation feeds.

### Authenticated Proof Requests and Disclosure Receipts (§5.5, §5.6)

The APR carries the **requested profile** (and, for the scoped profile, the scope policy) so that continuity is a declared, purpose-bound request under the existing Safeguard 6 machinery, and the holder SDK can refuse or downgrade.

**Correction (security review 2026-10-04).** An earlier text said that the profile identifier is bound into the proof context. It is not: the proof context hashes the *context* profile (for example `zkc:context:verifier-session:v1`), never the *presentation* profile. A proof still cannot be replayed as another profile, for a different reason: the profile is fixed by the proof's own public inputs. An anonymous proof carries `presentationPseudonym == 0` and `scopeId == 0`, a scoped proof carries a non-zero `scopeId` and its pseudonym, and a linkable proof is a v1-family circuit. The verifier's shape-consistency check (spec §5.9.4 rule 2) and envelope-generation binding reject any envelope whose declared profile disagrees with those inputs (`PROFILE_MISMATCH`).

Neither mechanism stops a *downgrade*. A holder may answer a scoped APR anonymously (spec §5.9.2 rule 4), and a default verifier accepts that answer. The verifier result therefore reports the effective profile, its holder handle, and whether `scopeId` was recomputed from the verifier's own identity. A verifier that relies on continuity sets a continuity-required policy, which rejects an anonymous answer with `PROFILE_MISMATCH` (spec §5.9.4).

Disclosure Receipts bind **the active profile's handle, never more**: under the anonymous profile the receipt binds the proof and context only; under the scoped profile it binds the `presentationPseudonym`; only a linkable-profile receipt may carry the global `holderCommitment`. This matters because receipts are *portable, holder-custodied evidence* — a receipt embedding the global commitment would re-create, in the receipt channel, exactly the cross-verifier equality join the ladder removes from the proof channel.

### Public-input determinism invariant

The property that makes any of this hold is stated as an invariant rather than left incidental:

> No public input of a presentation may be deterministic in credential-only material unless it is the declared linking handle of the active profile.

Audit of the current public inputs against this invariant: `holderCommitment` is the declared handle (linkable profile only); `claimBinding` passes because its preimage includes `proofContext` and `timestamp`, so it rotates per presentation — that inclusion is now load-bearing and MUST be preserved; `accumulatorRoot`/`accumulatorEpoch` are ecosystem-wide values shared across holders; `proofContext` is per-session by construction. Conformance tests must enforce the invariant for every new public input a profile adds.

## Consequences

- New proof profiles need public-input and schema changes for `presentationPseudonym` and `scopeId`, and every proof envelope carries an explicit **profile identifier** from the first schema revision — profile negotiation is the thing that cannot be retrofitted cheaply.
- Verifier policy and APR handling need to bind `scopeId` to authenticated verifier identity by default, with broad protocol scopes as an explicitly consented exception, and to negotiate the profile per request.
- Existing `zkc:proof:*:v1` envelopes remain valid as the current linkable profile; callers must not describe them as multi-show unlinkable.
- Documentation and conformance tests should distinguish seed-path unlinkability from presentation unlinkability, and must include per-profile vectors: cross-scope unlinkability negatives, within-scope recognition positives, and determinism-invariant checks.
- The escrowed audit handle gets its own ADR before any implementation.

## Follow-up

Follow-up implementation requirement: implement the anonymous, scoped, and linkable profiles of the ladder across proof public inputs, schemas, holder proof generation, verifier parsing, aggregation, credential-rebind, APR/receipt handling, and conformance tests.

Implementation spec: `docs/zkc_presentation_profiles_design.md`.

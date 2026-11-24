# Zero-Knowledge Compliance (ZKC) Protocol Specification

**Version:** 0.4.1-draft
**Status:** Draft Specification
**License:** Apache 2.0, with a royalty-free patent non-assertion covenant for conformant implementations (see [License](#license))
**Domain:** ZKC.dev
**Date:** 2026-11-18
**Proving System:** Noir / UltraHonk (BN254) — proving-system-agnostic at protocol level

> This is the canonical, evolving specification (currently v0.4.1-draft). Versioned point-in-time snapshots live in [docs/archive/](archive/).

> **Current AFP-KDC authority.** AFP-KDC v1.0.3 is the current ownership and registry-metadata release. The Poseidon2 parameters, field-derivation profile, and KAT provenance remain the immutable AFP-KDC v1.0.2 profile.

---

## Abstract

Zero-Knowledge Compliance (ZKC) is a protocol for user-controlled compliance in privacy-preserving systems. ZKC enables users to generate cryptographic proofs satisfying regulatory requirements without revealing underlying private data. Compliance becomes a capability controlled by the user, not an enforcement mechanism controlled by the protocol.

ZKC is designed to integrate with privacy-preserving payment systems (including ZKA), authorization layers (including ZKM), and settlement layers (Namada, Penumbra, Ethereum L2s) while remaining agnostic to specific implementations.

---

## 1. Overview

### 1.1 Design Philosophy

**Compliance as Capability, Not Constraint**

Traditional compliance models require protocols to enforce rules—blocking non-compliant transactions, freezing assets, or enabling force transfers. ZKC inverts this model:

| Traditional Model | ZKC Model |
|-------------------|-----------|
| Protocol enforces compliance | User generates compliance proofs |
| Counterparty demands access | User chooses what to disclose |
| Compliance is mandatory | Compliance is optional capability |
| Protocol knows identity | Protocol is identity-blind |
| Regulators access protocol | Regulators verify user proofs |

**Core Principles:**

1. **User Sovereignty**: Users control when, what, and to whom they disclose
2. **Protocol Neutrality**: No compliance logic in the base protocol
3. **Verifier Flexibility**: Verifiers decide what proofs they accept
4. **Portability**: Works across multiple chains and payment systems
5. **Privacy Preservation**: Proofs reveal minimum necessary information

### 1.2 Protocol Components

```
┌─────────────────────────────────────────────────────────────────┐
│                     ZKC PROTOCOL STACK                          │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    PROOF TYPES                            │  │
│  │  KYC | Jurisdiction | Accreditation | Tax | Source | ...  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                 ATTESTATION LAYER                         │  │
│  │  Credential Format | Issuance | Revocation | Registry     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    CLIENT SDK                             │  │
│  │  Proof Generation | Key Management | Credential Store     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                   VERIFIER SPEC                           │  │
│  │  Proof Formats | Verification | Trust Policies            │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2a Relationship to ZKM (Informative)

Within the ZK protocol family, **ZKC establishes eligibility**, **ZKM establishes principal-issued spend authority**, and **ZKA establishes whether the value transition settles**. ZKC does not issue, consume, delegate, or revoke ZKM mandates, and ZKM mandate revocation does not alter ZKC credential validity.

[ZKM §5, Authorization Predicate and Proofs](https://zkm.dev/spec/#5-authorization-predicate-and-proofs) defines two optional same-subject statements. At issuance, `zkm:issuance-zkc:v1` binds the credential subject to the mandate principal. At spend, `zkm:spend-zkc-binding:v1` binds the credential subject to the ZKA recipient. The spend companion has no settlement authority on its own. Under the direct atomic route, the target verifies the accepted ZKC proof, the companion, and the matching `zkm:spend-conjoined:v2` proof before applying the settlement effects together. ZKA defines [bundle carriage in §5.4](https://zka.dev/spec/#54-compliance-bundle) and [direct atomic settlement in §5.4.1](https://zka.dev/spec/#541-zkm-authorization-carriage-and-atomic-settlement). `zka:bundle:v1` has no ZKM member.

Support is specific to the target, the exact registry-selected ZKM statement and verification key (VK), and the accepted inner ZKC VK and presentation profile. A matching proof context alone cannot establish either subject relationship. Ordinary ZKA custody, transfers, withdrawals and force exits remain independent of this optional route.

### 1.3 Notation

| Symbol | Meaning |
|--------|---------|
| `H(domain, x...)` | Poseidon2 hash over BN254 with domain tag, per AFP-KDC v1.0.2 §A.3 (AFP.dev, `docs/kdc_specification.md`) |
| `commit(v, r)` | Poseidon2 commitment to value `v` with randomness `r` |
| `π` | Zero-knowledge proof (proving-system-agnostic; primary implementation: Noir/UltraHonk) |
| `cred` | Verifiable credential |
| `isk` | Issuer signing key |
| `ivk` | Issuer verification key |
| `cbk` | Credential binding key |
| `acc` | Cryptographic accumulator |
| `proofContext` | Deployment/profile-defined replay context bound into a ZKC proof |

The `zkc/*` artifact identifiers and operational domain tags are owned by ZKC; the `zkm/*` namespace is owned by ZKM. A future ZKC revision that adds a domain tag MUST collision-check it against the KDC registry and the published operational tags of sibling protocols, including ZKA and ZKM. Namespace adjacency does not make a ZKM proof, receipt, delegation, or revocation artifact a ZKC artifact.

---

### 1.4 Freedom Safeguards (Normative)

ZKC operates beneath the Freedom Safeguards defined normatively in **ZKA Specification §1.6**. These are architectural commitments that distinguish privacy infrastructure from a compliance control mechanism. Safeguards 3 (No Revocability) and 5 (Agent Exit Rights) are core invariants of the settlement layer; ZKC's design MUST NOT introduce any mechanism that undermines them. In particular, ZKC credential revocation MUST affect only a counterparty's acceptance of a proof — never the validity, custody, or transferability of any underlying note or asset (see §2.4, §4.4).

Safeguards 1, 2, and 4 are integration-level invariants that bind ZKC credential and predicate artifacts directly; **Safeguard 6 — Verifier Accountability** (added in v0.3.0) is a new axis that binds the *counterparty* rather than the protocol or operator. A conforming ZKC implementation MUST satisfy all four:

**Safeguard 1 — Predicate Pluralism.** No credential type, proof type, predicate, or issuer is privileged, canonical, or required by this protocol. ZKC MUST NOT define any mechanism that designates an "official" or "default" credential or predicate set. The identifiers in Appendix A and the schemas in §3.1–3.7 are *well-known reference definitions for interoperability*, not a closed or mandated set: a verifier's trust policy (§6) MAY accept credential types, predicates, or issuers outside this specification, and is never required to accept any particular one. Credential and predicate providers are independent and permissionless.

**Safeguard 2 — Minimal Disclosure by Default.** ZKC proofs MUST be atomic — each proof attests a single predicate (e.g., "not sanctioned"). Composite disclosure MUST require explicit, separate, principal-readable consent per predicate (see §5, §6.1). SDK defaults MUST generate the minimal proof satisfying a request; broader disclosure MUST require explicit additional configuration.

**Safeguard 4 — Open-Source Predicate Verification.** All ZKC credential and predicate circuits MUST be open-source and publicly auditable, expressed in inspectable source (Noir or equivalent). Predicate and credential-schema updates MUST be versioned, published, and subject to a public review period before activation. A conforming ZKC SDK MUST, by default, refuse to generate a proof against a predicate or schema the holder cannot inspect; overriding this default MUST require explicit, logged opt-in.

**Safeguard 6 — Verifier Accountability.** A verifier that requests a disclosure MUST authenticate the request under a stable verifier identity (an Authenticated Proof Request, §5.5), and the holder MUST be able to retain a self-contained Disclosure Receipt (§5.6) of exactly what was demanded, for what declared purpose (§2.2), and what was answered. A conforming ZKC SDK MUST refuse by default to answer an unauthenticated request (mirroring the Safeguard 4 fail-closed posture; overriding the default MUST require explicit, logged opt-in), MUST bind declared purpose into the proof context under the purpose-bound profile, and MUST NOT require any operator, prover, proxy, indexer, hosted SDK, or compliance service to custody receipts. This is the first safeguard to constrain the *counterparty* rather than the protocol or operator; operator-blindness and verifier-accountability are orthogonal (a blind operator and an unaccountable verifier are independent failures), so it is a distinct invariant, not an extension of Safeguard 2. It governs the verifier's *request*, and distinguishes **request accountability** — which is reachable, because a holder has the transaction leverage to demand a signed request (no signature ⇒ no proof) — from **decision accountability**, which is structurally unreachable: a verifier may decline in silence, and the protocol cannot force a signed decision (§5.8, residual limit E.1).

**Audit check (Safeguard 6).** A conforming deployment is checkable: the SDK refuses unauthenticated requests by default; purpose is a bound public input under the purpose-bound profile (`zkc:context:purpose-bound:v1`); and receipts are holder-custodied with operator retention absent. These are exercised as executable ZKC-Core conformance cases (`safeguard-6-*`, §9.2) alongside the Safeguard 1 and Safeguard 4 checks.

A conforming ZKC deployment MUST NOT require an issuer, verifier, predicate provider, prover service, compliance service, indexer, proxy, or hosted SDK operator to receive `masterSeed`, spending keys, ZKA addresses, note plaintext, unencrypted ZKC witness material, payment history, or custody of Disclosure Receipts. Remote services MAY assist with issuance, proof generation, verification, witness updates, or audit export only when they receive public inputs, encrypted witness material, viewing-limited material, or holder-controlled delegated authority that is insufficient for unilateral spending or linkable identity reconstruction.

> Where this specification and ZKA §1.6 differ in wording, the safeguard *intent* as stated in ZKA §1.6 governs.

---

### 1.5 ZKM Relationship and Protocol-Family Boundaries (Informative)

ZKC, Zero-Knowledge Mandates (ZKM), and ZKA occupy distinct layers of a composable protocol family. Their artifacts may be bound together by an integration profile, but conformance to one layer does not imply conformance to either of the others:

| Layer | Responsibility | Does not establish |
|-------|----------------|--------------------|
| **ZKC eligibility** | Proves holder-controlled facts and predicates, such as credential validity, jurisdiction, or accreditation. | A mandate, permission to act, transaction approval, or spending authority. |
| **ZKM authorization** | Proves that a principal authorized an agent to perform a bounded action under a mandate. | Eligibility for a regulated action or successful settlement. |
| **ZKA settlement** | Defines shielded assets, transactions, custody, and settlement validity. | The holder's eligibility or an agent's mandate. |

A composed flow may therefore require all three independently: a ZKC proof that the relevant party is eligible, a ZKM proof that the action is authorized, and ZKA validation that the resulting transaction settles. The presence or validity of one artifact is not evidence for a different layer unless an explicit integration profile binds and verifies the required artifacts.

**Domain-namespace ownership.** ZKC owns domain-separation tags under `zkc/*`; ZKM owns tags under `zkm/*`. Each owning specification defines the preimages and semantics of its namespace. ZKC extensions do not assign semantics under `zkm/*`, and ZKM extensions do not redefine or mint new semantics under `zkc/*`. A cross-protocol construction composes separately namespaced values or uses an extension profile defined by the namespace owner; it does not transfer namespace ownership.

**Proof-context extension.** `ProofContextProfile` (§2.2) allows additional profiles to map an interaction into ZKC's circuit-facing `Hash`. ZKM owns its issuance and spend context derivations and the statements that establish the subject relationships in §1.2a. Future context profiles and RFIP policy-bound verification are separate extensions. The direct route activates no RFIP policy.

**Delegation terminology.** ZKC delegated proof generation (§5.3) delegates a narrowly scoped computation, and `delegateViewing` (§5.4) delegates access to viewing-limited material for that computation. Neither operation creates or proves a ZKM mandate, authorizes an action on a principal's behalf, or conveys custody, transaction-signing, withdrawal, or spending authority. An integration that needs mandate or spend authorization obtains and verifies that authority separately under ZKM or the applicable settlement protocol.

---

## 2. Cryptographic Primitives

### 2.1 Credential Binding

ZKC credentials bind to shielded identities (e.g., ZKA addresses) without revealing the identity. This enables proving "I hold credential X" without revealing "I am address Y."

```typescript
interface CredentialBinding {
  // User's credential binding key (derived from master seed)
  credentialBindingKey: CredentialBindingKey;

  // Public commitment to binding key (used in credentials)
  bindingCommitment: Hash;  // H("zkc/binding", cbk)

  // Proof that credential applies to a shielded identity
  // without revealing which identity
  bindingProof: ZKProof;
}

// Credential-binding-key derivation is defined by AFP-KDC v1.0.2 §A.6
// in AFP.dev (docs/kdc_specification.md). ZKC does not restate it.
//
//   cbk        = H("zkc/credential", masterSeed)   // KDC §A.6
//   commitment = H("zkc/binding",    cbk)          // KDC §A.6
//
// `masterSeed` is a 256-bit seed: a standalone master seed, or — under
// AFP entity identity (AFP §4.3) — a per-entity sub-seed M' (KDC §A.5).
// `cbk` derives from the seed, not from the spending key; the credential
// commitment and the ZKA address derive along separate paths and are
// unlinkable without the seed (KDC §A.6, derivation facts 1 and 2).
//
// A conforming ZKC implementation MUST derive cbk and the binding
// commitment per AFP-KDC v1.0.2.
```

**Canonical master-seed profile.** AFP-KDC v1.0.2 preserves ZKC's frozen `afp-kdc:master-seed:v1.0.1` compatibility identifier and its byte-for-byte behavior. A seed is exactly 32 secret bytes. For the circuit-facing KDC input, interpret those bytes as one unsigned big-endian integer and reduce it modulo the BN254 scalar-field modulus `r`; a Noir `Field` parameter is this already-mapped value, not a second serialization of the seed. Host APIs MUST preserve the original 32 bytes for every byte-domain derivation and MUST NOT reconstruct them from the reduced field element. SDK byte-array inputs are normative. A compatibility integer input is encoded as unsigned, big-endian, left-zero-padded to 32 bytes and MUST be in `[0, 2^256)`; JSON profiles encode a seed as exactly `0x` plus 64 lowercase hexadecimal digits. Booleans, floats, negative or overflowing integers, variable-width bytes, noncanonical hex, and implicit string-to-integer coercions MUST be rejected.

The modulo mapping intentionally admits KDC aliases: for example, seed `r` maps to the same KDC field input as seed zero. AFP-KDC v1.0.2 retains this explicitly versioned v1.0.1 behavior for byte-for-byte compatibility with deployed identities. It applies only at the KDC circuit boundary. Receipt, audit-authorization, delegation, and any other byte-domain derivation consume the original 32 seed bytes, so they MUST NOT collapse such aliases. The frozen boundary and asymmetric cases are published in [`tests/vectors/kdc_master_seed_v1.json`](../tests/vectors/kdc_master_seed_v1.json); the complete current KDC conformance package is published in [`tests/vectors/crypto/afp_kdc_v1_0_2_conformance.json`](../tests/vectors/crypto/afp_kdc_v1_0_2_conformance.json).

New seeds MUST be generated as 32 bytes directly from a cryptographically secure random source. Implementations MUST NOT generate a host integer and truncate it, reduce generated bytes modulo `r`, or serialize only the KDC field input; doing so either loses entropy or prevents exact recovery of the seed. Migration is representation-only: every existing valid 32-byte seed retains its AFP-KDC v1.0.1 identity and its byte-identical AFP-KDC v1.0.2 outputs and byte-domain keys. Legacy stores holding an exact unsigned 256-bit integer may convert it once to the canonical 32-byte big-endian encoding. A store that retained only the reduced field input cannot recover the seed and MUST NOT silently treat that field element as the original seed; it requires an explicitly versioned legacy identity or a user-authorized rotation/rebind.

> **Cross-reference.** `bindingCommitment = H("zkc/binding", cbk)` is derived per AFP-KDC v1.0.2 §A.6 (AFP.dev, `docs/kdc_specification.md`). It is the shared anchor on which ZKA's identity-binding circuit is layered (ZKA Specification §5.2). That circuit is a ZKA-side addition and is not specified here; ZKC remains authoritative for credential-internal mechanics (structure, issuance, revocation, accumulators), and KDC is authoritative for the derivation of `cbk` and the binding commitment.

### 2.2 Proof Context Binding

Every ZKC proof is bound to a replay context. The context is a deployment/profile-defined hash that identifies the session, counterparty, and purpose for which the proof is valid. Implementations MAY expose structured fields for user readability, but the proof-circuit-facing value is always a single `Hash`.

```typescript
type ProofContextProfile =
  | "zkc:context:verifier-session:v1"
  | "zkc:context:purpose-bound:v1"     // verifier accountability (§5.5–§5.7)
  | "afp:session_context:v1"            // legacy; not an AFP 0.3.11-or-later proof context
  | string;                             // additional owner-defined context profiles

interface ProofContext {
  // Names the context construction profile.
  profile: ProofContextProfile;

  // Circuit-facing replay context.
  // For "zkc:context:verifier-session:v1":
  //   value = H("zkc/context", profile, verifierId, sessionId, timestamp)
  // For "zkc:context:purpose-bound:v1":
  //   purposeTag = H("zkc/purpose", canonicalPurpose)
  //   value      = H("zkc/context", profile, verifierId, sessionId, purposeTag, timestamp)
  // For legacy "afp:session_context:v1" only:
  //   value = afp:envelope:v1.session_context
  value: Hash;

  // Principal-readable fields, when the profile defines them.
  verifierId?: VerifierIdentifier;
  sessionId?: Hash;
  timestamp: Timestamp;
  purpose?: string;
  purposeTag?: Hash;  // present under the purpose-bound profile
}
```

`ProofContextProfile` can carry additional ZKM-defined context profiles. Mandate and spend authority depend on the ZKM statements selected for the interaction (§1.2a). A ZKM profile MUST be defined and namespaced by ZKM under `zkm/*`, MUST specify how its structured authorization context maps to the circuit-facing `Hash`, and MUST be explicitly requested and verified by both sides. ZKC does not infer ZKM authorization from an unrecognized profile string.

`claimBinding` MUST commit to the context value. A verifier MUST reject a proof when `proof.metadata.context.value` does not equal the requested context value, or when profile-specific structured fields do not reconstruct the same value.

#### Purpose-Bound Profile (`zkc:context:purpose-bound:v1`)

Under the base verifier-session profile, `purpose` is a principal-readable field that is **not** committed into the circuit-facing context value, so a disclosure obtained for one stated purpose (e.g. billing KYC) is not cryptographically distinct from one for another (e.g. an access gate) and cross-purpose re-derivation goes uncaught. The purpose-bound profile closes this by folding the declared purpose into the **same** context value via a `purposeTag`:

```
purposeTag = H("zkc/purpose", canonicalPurpose)      // canonicalPurpose: NFC-normalized, registry-tagged
value      = H("zkc/context", profile, verifierId, sessionId, purposeTag, timestamp)
```

- `purposeTag` **MUST** be committed as a public input of every individual proof generated under this profile — it enters the preimage of the `proofContext` public input that proofs already carry — and the verifier **MUST** reconstruct the same `value` from the request's own fields (§6.2 step 0). No new circuit family is introduced and no new acceptance logic is required; purpose simply enters the hash preimage.
- A verifier requesting under one `purposeTag` **MUST** reject a proof carrying any other, via the existing `CONTEXT_MISMATCH` path (and the verifier-side `PURPOSE_MISMATCH` pre-step of §6.2).
- `canonicalPurpose` strings are drawn from a **non-exclusive** purpose registry: Safeguard 1 applies — there is no canonical or mandated purpose set, verifiers MAY define their own purposes, and holders MAY refuse purposes they cannot read.

This profile is OPTIONAL to *offer*, but once a verifier requests it, binding is mandatory. Deployments handling reusable plaintext credentials (passports, KYC dossiers) SHOULD default to it (§5.7). Existing verifier-session contexts are unchanged. `afp:session_context:v1` is a legacy pre-AFP 0.3.11 profile and MUST NOT be selected as the ZKC proof context for an AFP 0.3.11-or-later tuple; those tuples select `afp:zkc-presentation-context:v2` instead.

When a ZKC proof is carried in a ZKA `zka:bundle:v1`, the ZKA bundle remains authoritative for the bundle envelope. In a payment bundle, the ZKA-side note-to-credential binding links the payment note to the ZKC holder commitment. In a transaction-absent ZKA v0.9.2-draft work-attestation bundle, there is no note and therefore no note-to-credential binding. AFP retains the authenticated raw `X_...` session identifier in `afp:envelope:v1.session_context`; ZKA bundle metadata, transaction public inputs, and Coord receipts use only its fixed nonzero BN254 `session_context_field` projection. A ZKC proof instead uses AFP's separately authenticated `afp:zkc-presentation-context:v2` presentation-purpose context. A verifier MUST NOT substitute either session representation for that ZKC proof context. ZKC validators verify the ZKC proof and its context; ZKA validators enforce bundle substantiveness, `coord_proof` verification, and `EMPTY_BUNDLE` rejection.

The machine-checked composition boundary is epoch `zka:protocol-family:2026-11-19.1` in ZKA's canonical `protocol-family/` package. The ZKC source tree pins it in `protocol-family/snapshot-lock.json`. It binds ZKA v0.9.2-draft, ZKC v0.4.1-draft, AFP v0.3.14-draft, AFP-KDC v1.0.3 current registry metadata with its immutable v1.0.2 crypto profile, and ZKM v0.1.0-draft (rev 13) with statement-set identity `sha256:f367e0504bcbbe4ca2a150f9c56a7640d5ed21bdb9dec1c1ce4acaa6e023ab49` and its beta.25/BB 5.0.0 proving toolchain. AFP 0.3.14 adds its native credential-only carrier and the corresponding AFP-owned schema and interface-set pin, while retaining the published venue-neutral payment descriptor and separately versioned v2 policy, quote, and receipt records. This composition update changes no ZKC circuit, verification key, proof envelope, public-input ABI, or presentation-context mode. ZKC vendors a commit-locked snapshot and rejects unknown, unmatched, ambiguous, or incomplete family combinations without changing frozen v1 bytes. For the role of each protocol, see [ZKA §1.2, Protocol Family](https://zka.dev/spec/#12-protocol-family).

### 2.3 Credential Structure

```typescript
interface ZKCCredential {
  // === Credential Header ===
  header: {
    version: "zkc:cred:v1";
    type: CredentialType;
    issuer: IssuerIdentifier;
    issuedAt: Timestamp;
    expiresAt: Timestamp | null;
  };

  // === Credential Body ===
  body: {
    // Commitment to holder's binding key (not the key itself)
    holderCommitment: Hash;

    // Type-specific claims (structure varies by credential type)
    claims: CredentialClaims;

    // Credential identifier for revocation, unique within its issuer and in [1, r)
    credentialId: Hash;
  };

  // === Issuer Signature ===
  signature: {
    scheme: "ECDSA_SECP256K1" | "BLS" | "Schnorr";
    value: Uint8Array;
    issuerKey: IssuerVerificationKey;
  };

  // === Revocation Info ===
  revocation: {
    // Accumulator membership witness (for non-revocation proofs)
    accumulatorWitness: AccumulatorWitness;
    accumulatorEpoch: u64;
  };
}
```

The initial Noir conformance profile defines `ECDSA_SECP256K1` as the mandatory issuer-signature circuit profile. BLS and Schnorr remain protocol-recognized credential metadata schemes, but a verifier MUST reject them unless it has an auditable circuit implementation for that scheme.

A `credentialId` MUST be a canonical integer in `[1, r)`, where `r` is the BN254 scalar-field modulus. An issuer MUST enforce this range before signing, issuing, renewing, or registering a credential. Implementations MUST reject out-of-range identifiers before field conversion.

### 2.4 Accumulator-Based Revocation

Credentials use cryptographic accumulators for privacy-preserving revocation checks:

```typescript
interface RevocationAccumulator {
  // Current accumulator value: the Poseidon2 Merkle root over the active
  // credentialId leaves (conformance profile, below and §2.4.1)
  value: Hash;

  // Epoch (increments by exactly one on each successful update, §2.4.1)
  epoch: u64;

  // Update: remove credential from accumulator (revoke)
  revoke(credentialId: Hash): AccumulatorUpdate;

  // Prove membership (credential not revoked)
  proveMembership(
    credentialId: Hash,
    witness: AccumulatorWitness
  ): NonRevocationProof;
}

// Non-revocation proof
interface NonRevocationProof {
  // Proves credentialId is still in accumulator
  // without revealing which credential
  proof: ZKProof;

  // Public inputs (carried by every root-carrying circuit as
  // accumulator_root and accumulator_epoch)
  publicInputs: {
    accumulatorValue: Hash;   // the Merkle root the proof uses
    accumulatorEpoch: u64;
    // Note: credentialId is NOT revealed
  };
}
```

Zero is reserved for empty and revoked accumulator slots. A credential predicate that proves membership MUST constrain the authenticated credential identifier to be nonzero. Published historical circuit identities retain their original constraints.

The initial Noir conformance profile uses a Poseidon2 Merkle accumulator over active `credentialId` leaves. An issuer publishes the accumulator root and epoch; holders receive Merkle path witness updates out-of-band or through privacy preserving broadcast channels. A verifier accepts an accumulator epoch only when `currentEpoch - accumulatorEpoch <= MAX_EPOCH_LAG` and MUST reject future epochs. For authenticated roots it also applies the time bound of §2.4.2: a superseded root expires a fixed number of seconds after the issuer superseded it, however few epochs follow. Because every circuit proves membership only in the root the prover supplies, a verifier MUST also compare the proof's `accumulator_root` with the root the issuer published for that epoch and MUST reject a proof whose epoch has no recorded root (§6.2 step 4c); an epoch check alone enforces no revocation, since a revoked holder can prove membership in a self-made tree at the current epoch. Revocation changes only future proof acceptance by counterparties; it never changes ZKA note validity, custody, or transferability.

Issuer metadata for accumulator publication, update endpoints, epoch freshness, and revocation service levels is specified in `docs/zkc_issuer_adapter_protocol_v1.md` and `schemas/issuer-metadata.schema.json`.

#### 2.4.1 Authenticated revocation publication (launch profile)

For the issuer-authoritative selective-disclosure profile in §7.2b, an unsigned `currentRoot`/`currentEpoch` pair is discovery data only. A verifier MUST accept a root only from a trust-anchored `zkc:epoch-announcement:v3` carried by `zkc:issuer-metadata:v2`. Metadata v1 remains parseable for legacy consumers but MUST NOT authenticate a §7.2b root; silently treating it as v2 is a downgrade failure.

The v3 announcement is the following closed object; additional or missing fields make it malformed:

```text
version:                  "zkc:epoch-announcement:v3"
accumulatorId:            UTF-8 text (1..65535 bytes)
root:                     canonical 32-byte lower-case 0x hex field element
epoch:                    u64
announcedAt:              positive Unix seconds as u64
maxEpochLag:              u64 in [0, 10]
signingKeyId:             UTF-8 text (1..65535 bytes)
previousAnnouncementHash: 32-byte lower-case 0x hex
signature:                64-byte lower-case 0x ECDSA secp256k1 r||s
```

The exact bytes signed are independent of JSON serialization. Define `lp16(s) = u16be(len(UTF8(s))) || UTF8(s)`. The signing transcript is:

```text
ASCII("ZKC-EPOCH-ANNOUNCEMENT") || 0x00 || 0x03 ||
lp16(version) || lp16(accumulatorId) || root[32] ||
u64be(epoch) || u64be(announcedAt) || u64be(maxEpochLag) ||
lp16(signingKeyId) || previousAnnouncementHash[32]
```

The transcript length `len(T)` MUST NOT exceed 65535 bytes, because the complete record below frames it with `u16be(len(T))`. The fixed parts of `T` take 143 bytes, so `accumulatorId` and `signingKeyId` together hold at most 65392 UTF-8 bytes. An issuer MUST NOT sign, and a verifier MUST reject, an announcement whose transcript is longer. Every length bound in this section counts UTF-8 bytes, not Unicode code points; JSON Schema `maxLength` counts code points, so a schema check alone does not enforce these bounds.

The hex fields are closed encodings. A parser MUST match a field's exact pattern before it decodes the field: `root` and `previousAnnouncementHash` are `0x` plus exactly 64 lower-case hex digits, and `signature` is `0x` plus exactly 128. Whitespace, `_` separators, upper-case digits, a missing or upper-case `0x`, and short forms are malformed, even where a general-purpose decoder would accept them. Otherwise one string could decode to different bytes (for example, a decoder that skips whitespace reads a 64-character `root` as 31 bytes), and implementations would disagree on which announcements are valid. The same rule applies to every field element a revocation wire message carries, such as `credentialId` and the leaves of an epoch-state response.

The signer computes `d = OS2IP(SHA-256(transcript)) mod p`, where `p` is the BN254 scalar-field modulus, encodes `d` as a 32-byte big-endian field element, and signs those bytes with deterministic low-s ECDSA secp256k1. This transcript binds the protocol version, accumulator identity, root, epoch, freshness time, lag policy, key identifier, and predecessor commitment. Because the object is closed, an issuer cannot introduce an unsigned security-relevant announcement field.

Verifiers MUST apply the same low-s rule. Let `n` be the secp256k1 group order. A signature `r || s` is valid only when `1 <= r < n` and `1 <= s <= floor(n / 2)`, which is the bound `s < (n + 1) / 2` that the in-circuit secp256k1 verifier enforces. A verifier MUST reject the high-s twin `(r, n - s)` of a valid signature, although it satisfies the ECDSA verification equation. Otherwise any relay, mirror, or network attacker without the issuer key could re-encode a signed announcement, change its complete hash, and make an honest successor fail its predecessor commitment. The same acceptance rule applies to every secp256k1 signature that ZKC verifies: epoch announcements, Authenticated Proof Requests, Disclosure Receipts, delegation tokens, audit-bundle authorizations, and issuer credential signatures.

Announcement conflicts are classified by signing transcript, not by signature bytes. When a candidate for the retained checkpoint's epoch has the same signing transcript as the retained checkpoint but different signature bytes, it states nothing new. The verifier MUST reject it as an authentication failure, MUST NOT report it as a fork or as issuer equivocation, and MUST NOT retain it as equivocation evidence. The retained checkpoint stays in force, so the honest chain continues to advance. The reference stack reports `ANNOUNCEMENT_AUTHENTICATION_FAILED` for this case and reserves `CHAIN_FORKED` for two different signed transcripts.

Equivocation evidence names the two announcements that actually conflict. They are the announcement the consumer had accepted immediately before the candidate and the candidate itself. The first is the retained checkpoint, or the announcement verified just before the candidate in the same backfill or catch-up step. A consumer MUST NOT record the persisted checkpoint in place of that predecessor. A consumer retains the pair as evidence only when both announcements name the same `accumulatorId` and the same `signingKeyId`, verified under that one pinned key. An announcement for an accumulator other than the consumer's pinned accumulator is a scope mismatch, not a fork. One issuer key may sign several accumulators, so a relay without the key can substitute the issuer's genuine announcement of another accumulator. The consumer MUST reject that announcement, MUST NOT report it as a fork, and MUST NOT retain it as evidence. A linkage conflict between announcements signed by two different keys fails closed as a fork but is not retained as evidence. The reference stack reports `ACCUMULATOR_ID_MISMATCH` for a scope mismatch and retains `zkc:revocation-equivocation-evidence:v2` records with `predecessor` and `candidate` fields.

The predecessor commitment covers the complete canonical signed predecessor, not merely its root. Let `T` be that predecessor's signing transcript and `S` its 64-byte signature. Its canonical complete bytes are:

```text
ASCII("ZKC-EPOCH-ANNOUNCEMENT-COMPLETE") || 0x00 || 0x03 ||
u16be(len(T)) || T || S
```

`previousAnnouncementHash` is `SHA-256(completeBytes)`, with 32 zero bytes at genesis. `tests/vectors/revocation_announcement_v3.json` is the normative known-answer vector for both encodings.

Metadata v2 MUST publish the current complete announcement atomically inside `revocation.currentAnnouncement`. The convenience fields `accumulatorId`, `currentRoot`, `currentEpoch`, and `maxEpochLag` MUST exactly equal the signed announcement values, with the same JSON type: `true` does not equal the epoch `1`, and `10.0` does not equal the lag `10`. A mismatch fails closed. The current announcement MUST already be durable and retrievable, and every intervening historical announcement MUST remain retrievable in epoch order for bounded gap backfill, before metadata exposes the new head.

A gap wider than a consumer's per-call backfill bound is ordinary traffic, because every successful mutation advances the epoch. A verifier or holder whose retained checkpoint is that far behind the current head MUST NOT recover by discarding the checkpoint and restarting from the head: that is a cold start, and it discards replay and fork protection. It catches up in bounded, resumable steps instead. Each step starts at the persisted checkpoint. It fetches at most the bound's number of consecutive announcements, and for each one it verifies the signature under a pinned key, epoch continuity, and the `previousAnnouncementHash` link to its predecessor, starting from the checkpoint. It then persists the last announcement as the new checkpoint with a write that cannot move the checkpoint backwards. A historical announcement carries no freshness requirement, because its signature and its link to the retained checkpoint authenticate it. The current head keeps the freshness rule: the consumer checks the head's freshness time (its signed `announcedAt`, or a liveness statement that names it, §2.4.2) before each step and verifies the head's signature and link in the step that reaches it. While the persisted checkpoint is an intermediate announcement outside the consumer's freshness policy, the consumer serves no root from it. A signature, continuity, or linkage failure in any step fails closed, persists nothing from that step, and is classified as it is for a single bounded backfill. The reference verifier and holder expose this as `catch_up`. Each call verifies at most `max_backfill` announcements past the checkpoint (default 32) and returns a resumable status, so a consumer 1000 epochs behind reaches the head in 32 calls.

A native v3 accumulator begins at epoch 0 with the zero predecessor. A deployment migrating an already populated legacy accumulator MAY publish one v3 migration checkpoint at its existing epoch with the zero predecessor, but only to a verifier that has no retained v3 checkpoint and whose local policy explicitly authorizes that accumulator migration. That policy is a set of authorized migrations, each an `(issuerId, accumulatorId, epoch)` entry, configured on the verifier or holder and never taken from issuer metadata. At cold start, a verifier or holder MUST refuse a first announcement whose `previousAnnouncementHash` is the zero hash at an epoch above 0 unless one entry names exactly that issuer, accumulator, and epoch. A cold start at epoch 0 with the zero predecessor, or at a head with a non-zero predecessor, remains a local trust-on-first-use checkpoint. The reference `VerifierAccumulatorCache` and holder witness providers take this policy as `authorized_migrations` and report `MIGRATION_CHECKPOINT_UNAUTHORIZED`. An authorized migration checkpoint is accepted as a local checkpoint, not as proof of legacy-chain continuity or a globally unique view. Once any v3 checkpoint is retained, another zero-predecessor announcement or an attempt to splice a v2 announcement into the v3 predecessor hash fails closed. Reusing v1 metadata or v2 announcement bytes as though they were v3 is never migration.

`signingKeyId` selects a key already authorized by verifier-local trust policy. `accumulatorId` likewise MUST match the accumulator identity pinned for that issuer; a different id is a separately authorized migration, not a cold-start checkpoint. A holder pins it too, in local configuration. It MUST NOT take the accumulator id from the service or source it refreshes from, and it rejects a service, response, or announcement that names another accumulator. This prevents restart from erasing continuity merely by changing the signed accumulator namespace. The same metadata document's `signingKeys` entry is discovery material and MUST NOT bootstrap its own authority. Launch rotation is pre-authorized: verifiers pin the successor key out of band before accepting the first announcement it signs. An implementation MAY accept a separately specified delegation authenticated by an already pinned key, but metadata v2 defines no self-authenticating delegation object. An unknown key id, an unpinned same-document key, an unauthorized rotation, or a return to metadata v1 fails closed.

A key pin is not only a public key. Each pin MUST carry the key's validity window `notBefore` and `notAfter`, and MAY carry `retireAfterEpoch`. The key may sign an announcement only when `notBefore <= announcedAt < notAfter`, the same half-open rule as the issuer's own key window. When `retireAfterEpoch` is present, the key may sign only epochs at or below it. A verifier or holder MUST apply these bounds to every announcement it accepts under the pin: the current head, every announcement fetched by bounded backfill or catch-up, and a persisted checkpoint when it is loaded again. Historical announcements are exempt from freshness, not from the window. An announcement outside its signer's window fails closed as an authentication failure, even when its signature verifies. A pin without a window MUST be refused, because it would trust the key indefinitely, including after the key expired or leaked. An operator who learns that a key was compromised narrows its pin. Retained checkpoints that the narrowed pin no longer covers then fail closed, and the consumer re-anchors under the corrected policy. The reference stack reports `ANNOUNCEMENT_KEY_OUTSIDE_VALIDITY` and refuses a bare `(x, y)` pin.

The issuer applies the same window when it signs. It reads `announcedAt` once per epoch and MUST refuse with `EXPIRED_ISSUER_KEY` when the active announcement key is not valid at that time. The refusal happens before the accumulator, the epoch, the announcement history, or durable state changes, so a refused issuance, revocation, or renewal leaves no trace. Rotation to a successor that is valid at the time of rotation restores signing. A metadata endpoint that cannot publish a valid document, for example because the published key does not cover the current announcement, reports an issuer-side failure (HTTP 5xx in an HTTP binding), not a client error.

Epoch semantics are frozen for this launch version. Genesis is epoch 0. Each successful credential registration/issuance advances exactly one epoch and publishes one announcement; each successful revocation does the same; an atomic renewal/replace advances exactly one epoch for the combined add/remove. Validation failures, duplicate/no-op requests, and rejected mutations do not advance the epoch or publish. Batching, minimum epoch periods, and padding or cover updates were evaluated but are not part of v3; the resulting observable issuance/revocation cadence is an explicit accepted launch leakage described in `docs/zkc_metadata_leakage_threat_model.md`. Changing this rule requires a new announcement version.

A consumer MUST bound its work by authenticated values before it allocates memory or does work in proportion to unauthenticated input. Two consequences follow. First, a gap between the retained checkpoint at epoch `c` and a candidate head at epoch `h` is sized arithmetically as `h - c - 1` and compared with the backfill bound before any per-epoch work; a consumer MUST NOT list the missing epochs first, because one validly signed far-future epoch (an issuer fault or a leaked key) would otherwise exhaust memory instead of producing `ANNOUNCEMENT_BACKFILL_LIMIT_EXCEEDED`. Second, by the epoch rule above an accumulator gains at most one leaf slot per epoch: genesis has no slot, a registration or a renewal appends one, and a revocation only zeroes one. An accumulator at epoch `e` therefore has at most `e` slots, and between epochs `f` and `e` at most `e - f` slots are added and at most `2(e - f)` slots change. Trailing zero leaves do not change the root, so the root check alone cannot detect a leaf set padded by a relay. A consumer that rebuilds the accumulator from leaves (credential-anonymous refresh) MUST verify the signature of the announcement it will compare the root with, and MUST refuse a leaf set or delta larger than these bounds before it decodes or hashes the leaves. A consumer whose local policy authorizes a migration checkpoint (above) MAY raise the slot bound by the number of slots the migrated accumulator held beyond its epoch.

#### 2.4.2 Head liveness and bounded revocation latency

The epoch advances only on a successful mutation (§2.4.1), so the current announcement of a quiet issuer keeps its old `announcedAt`. Without a further signal, a consumer's freshness rule rejects an honest issuer that is online but has nothing to announce, and operators who widen the age limit also widen the time in which a frozen or withheld view is accepted. A `zkc:epoch-liveness:v1` statement lets the issuer attest that its current announcement is still its head without a new epoch. The statement is the following closed object; additional or missing fields make it malformed:

```text
version:       "zkc:epoch-liveness:v1"
accumulatorId: UTF-8 text (1..65535 bytes)
epoch:         u64
headHash:      32-byte lower-case 0x hex
issuedAt:      positive Unix seconds as u64
signingKeyId:  UTF-8 text (1..65535 bytes)
signature:     64-byte lower-case 0x ECDSA secp256k1 r||s
```

`headHash` is the complete hash of the announcement the statement vouches for, computed exactly as `previousAnnouncementHash` (§2.4.1). The signing transcript is:

```text
ASCII("ZKC-EPOCH-LIVENESS") || 0x00 || 0x01 ||
lp16(version) || lp16(accumulatorId) || u64be(epoch) ||
headHash[32] || u64be(issuedAt) || lp16(signingKeyId)
```

The transcript MUST NOT exceed 65535 bytes, the same bound as the announcement transcript. Its fixed parts take 95 bytes, so `accumulatorId` and `signingKeyId` together hold at most 65440 UTF-8 bytes. An issuer MUST NOT sign, and a consumer MUST reject, a statement whose transcript is longer. As for an announcement (§2.4.1), `headHash` and `signature` are closed encodings matched against their exact lower-case pattern before decoding, and `epoch` and `issuedAt` are accepted only as JSON integers, so `true` is not epoch `1`. The signer reduces `SHA-256(transcript)` into the BN254 field and signs it with deterministic low-s ECDSA secp256k1, exactly as for an announcement. The domain tag differs from both announcement domains, so no liveness signature verifies as an announcement and no announcement signature verifies as a liveness statement.

A liveness statement obeys these rules:

1. **Signer.** It is signed by an announcement key under the pin rules of §2.4.1, with `issuedAt` in place of `announcedAt`: the key id MUST be pinned, `notBefore <= issuedAt < notAfter` MUST hold, and `epoch` MUST NOT exceed the pin's `retireAfterEpoch`. The issuer signs with its active announcement key and refuses with `EXPIRED_ISSUER_KEY` outside that key's window. After a rotation the successor signs liveness statements for the head its predecessor announced, so a consumer pins a successor before the issuer rotates to it, not only before its first announcement.
2. **Not a chain member.** It never advances, replaces, or reorders an epoch, never changes a root or the announcement history, and is never part of a persisted checkpoint. It is not a padding or cover update in the sense of §2.4.1: the v3 epoch rule and announcement transcript are unchanged.
3. **Bound to one head.** A consumer uses a statement only for the announcement whose `accumulatorId`, `epoch`, and complete hash it names: for a candidate head while it ingests that head, and for its persisted head afterwards. The head's **freshness time** is the later of its `announcedAt` and the `issuedAt` of the newest verified statement that names it. A statement whose `issuedAt` is further in the future than the consumer's clock-skew allowance MUST be refused.
4. **Fail closed, never evidence.** A statement that fails authentication or its key window is refused, and so is the document or response that carries it. A statement that names another head is refused (`LIVENESS_HEAD_MISMATCH` in the reference stack). The consumer still classifies the head first, so a signed fork keeps its evidence (§2.4.1), and it persists nothing from the refused document. A liveness statement alone is never fork or equivocation evidence: it carries no root and no predecessor, so it cannot show which history its signer published.
5. **Re-polling is a no-op.** Ingesting an announcement that is byte-identical to the persisted head changes no checkpoint and reports no error. Only an announcement below the persisted head is a replay, and only a different signed transcript at its epoch is a fork.

Metadata v2 MAY carry the statement for its current announcement as `revocation.currentLiveness`, published atomically with that announcement. Witness-update and epoch-delta responses MAY carry it as `liveness`. Both fields are additive: a consumer that does not know them ignores them and applies the v3 rules alone, so its view of a quiet issuer goes stale as before. The issuer re-signs the statement at an interval `L`; the reference default is 900 seconds.

**Time-bounded roots.** A verifier serves an authenticated root only while the issuer attested it current within the verifier's maximum announcement age `A`. The head's root is served while `now - freshnessTime(head) <= A`. A superseded root at epoch `e` stopped being current no later than the earliest `announcedAt` among epochs `e + 1` up to the head, and it is served only while `now` minus that time is at most `A`. This rule applies in addition to the epoch-lag rule of §2.4, so a superseded root expires after `A` seconds even when fewer than `maxEpochLag` epochs follow it.

**Worst-case revocation latency.** Let `A` be the verifier's maximum announcement age and `S` its clock-skew allowance, and assume that the honest issuer's clock is within `S` of the verifier's clock. Let `t_r` be the time at which the issuer signs the announcement that removes a credential. Every root that contains the credential belongs to an earlier epoch, so it is superseded no later than `t_r + S` in verifier time. An honest issuer signs liveness statements only for its current head, so no statement issued after `t_r` names a pre-revocation head. Therefore no verifier serves a root that contains a revoked credential later than

`W = A + S` seconds after the revoking announcement is signed.

With the reference defaults (`A` = 3600 seconds, `S` = 300 seconds), **the worst-case revocation latency is 3900 seconds**. The bound does not depend on `maxEpochLag`, on the number of epochs after the revocation, on the liveness interval, or on how often the verifier polls. A verifier that never receives the revoking announcement, for example because a relay withholds it, stops serving its stale head by the same bound. A verifier MAY apply a tighter `A`, for example one required by signed verifier policy, and `W` shrinks with it. No liveness statement or metadata field can widen `A`. A verifier obtains its accumulator state for each verification: a state kept past the moment it was produced does not apply the bound.

**Availability of a quiet issuer.** A quiet issuer stays verifiable while `L + C + R + S <= A`, where `C` is the longest time a cache may serve a metadata document (`serviceLevels.metadataCacheSeconds`) and `R` is the verifier's polling interval. With the reference defaults (`L` = 900, `C` = 300, `S` = 300, `A` = 3600 seconds), a verifier that polls at least every 2100 seconds keeps a quiet issuer verifiable. An issuer whose active key has expired publishes no statement, so its head goes stale `A` seconds after its last attestation until a valid successor is rotated in. Liveness statements are not part of the shared checkpoint: each verifier worker or holder process records the statements it has verified, and a restarted worker serves a quiet issuer's roots again after its next poll.

Each issuer's state is evaluated on its own. A verifier that holds states for several issuers MUST NOT let one stale or unreadable issuer state prevent it from serving the others; a proof against the stale issuer fails closed. The reference `VerifierAccumulatorCache.accumulator_states()` returns only the servable states, and `accumulator_state_results()` returns each issuer's state or the error that refused it. `RevocationAccumulatorService.current_liveness()` produces the statement on its interval, and the verifier cache and the holder witness providers apply rules 1 to 5. The `liveness` block of `tests/vectors/revocation_equivocation_v1.json` and the `quiet-issuer-liveness-and-time-bound` case of `conformance/run_revocation.py` pin the transcript and the consumer behavior.

---

## 3. Credential Types

The credential schemas in §3.1–3.7 are **reference schemas**: well-known interoperability profiles, not a closed or mandated set. Per §1.4 (Safeguard 1 — Predicate Pluralism), no credential type or issuer defined here is privileged or required, and verifiers MAY accept credential types and predicates outside this specification. These schemas exist so independent issuers and verifiers can interoperate without coordination, not to designate an official taxonomy.

The `claims` body of each credential interface and the `claim` block of each proof interface below are conceptual summaries. They are not the reference issuer's signed claim layout and they are not the request contract. A published proof identity proves only the predicate that its circuit constrains (§7.1–§7.2b), and a verifier requests it with the parameters of §6.2.1. Where a `claim` block names a condition that the named proof identity does not prove, a comment says so. A proof of the named identity is not evidence of such a condition. A verifier that needs it relies on its issuer trust policy (what a trusted issuer checks before it signs) or on a different predicate.

### 3.1 KYC Credential

Proves identity verification by an accredited provider.

```typescript
interface KYCCredential extends ZKCCredential {
  header: {
    type: "zkc:cred:kyc:v1";
    // ...
  };

  body: {
    holderCommitment: Hash;
    credentialId: Hash;

    claims: {
      // Verification level (tiered KYC)
      level: "basic" | "enhanced" | "institutional";

      // What was verified (not the actual data)
      verifiedAttributes: {
        name: boolean;
        dateOfBirth: boolean;
        address: boolean;
        governmentId: boolean;
        livenessCheck: boolean;
      };

      // Jurisdiction of verification
      jurisdiction: ISO3166Alpha2;

      // Sanctions screening performed
      sanctionsScreened: boolean;
      sanctionsScreenDate: Timestamp;
    };
  };
}

// Proof: "I hold valid KYC from a trusted issuer"
// (linkable zkc:proof:kyc:v1, zkc_kyc encoder; the anonymous/scoped sibling
// zkc:proof:kyc:v2 replaces holder_commitment with presentation_pseudonym and
// scope_id, §5.9)
interface KYCProof {
  proofType: "zkc:proof:kyc:v1";

  // What is proven
  claim: {
    // Minimum verification level
    minLevel: "basic" | "enhanced" | "institutional";

    // Required verified attributes
    requiredAttributes: string[];

    // Issuer trust requirement
    issuerRequirement: IssuerRequirement;
  };

  // The proof
  proof: ZKProof;

  // Public inputs: the exact encoder-declared names (§6.1)
  publicInputs: {
    holder_commitment: Hash;     // linkable holder handle (§5.9)
    claim_binding: Hash;         // prevents proof reuse for different claims
    proof_context: Hash;         // replay context (§2.2)
    accumulator_root: Hash;      // non-revocation anchor (§2.4)
    accumulator_epoch: u64;
    timestamp: u64;              // freshness
    current_epoch: u64;
    issuer_public_key_x: Bytes32;
    issuer_public_key_y: Bytes32;
  };
}
```

### 3.2 Jurisdiction Credential

Proves residency or citizenship without revealing identity.

```typescript
interface JurisdictionCredential extends ZKCCredential {
  header: {
    type: "zkc:cred:jurisdiction:v1";
    // ...
  };

  body: {
    holderCommitment: Hash;
    credentialId: Hash;

    claims: {
      // Type of jurisdictional claim
      claimType: "residency" | "citizenship" | "tax_residency";

      // Jurisdiction (hidden in proofs, proven via set membership)
      jurisdiction: ISO3166Alpha2;

      // Verification method
      verificationMethod: "government_id" | "utility_bill" | "tax_return" | "passport";

      // Validity period
      validFrom: Timestamp;
      validUntil: Timestamp;
    };
  };
}

// Proof: "I am resident of an allowed jurisdiction"
// (current identities: v3 linkable, v4 anonymous/scoped; v1/v2 are deprecated
// historical identities, see §7.2a and §7.2c.7; v5 is a draft, unactivated
// republication of the v4 statement, §6.2.1)
interface JurisdictionProof {
  proofType: "zkc:proof:jurisdiction:v3";

  claim: {
    // Allowed jurisdictions (verifier specifies)
    allowedJurisdictions: ISO3166Alpha2[];

    // Or: blocked jurisdictions
    blockedJurisdictions?: ISO3166Alpha2[];

    // Claim type required
    claimType: "residency" | "citizenship" | "tax_residency";
  };

  proof: ZKProof;

  // Public inputs: the exact zkc_jurisdiction_v3 encoder names (§6.1)
  publicInputs: {
    holder_commitment: Hash;
    claim_binding: Hash;
    proof_context: Hash;

    // Merkle root of allowed/blocked jurisdiction set
    jurisdiction_set_root: Hash;

    // Proves: my jurisdiction ∈ allowedSet OR my jurisdiction ∉ blockedSet
    membership_type: u8;         // 0 = inclusion, 1 = exclusion

    accumulator_root: Hash;
    accumulator_epoch: u64;
    timestamp: u64;
    current_epoch: u64;
    issuer_public_key_x: Bytes32;
    issuer_public_key_y: Bytes32;
  };
}
```

### 3.3 Accreditation Credential

Proves accredited investor status or institutional classification.

```typescript
interface AccreditationCredential extends ZKCCredential {
  header: {
    type: "zkc:cred:accreditation:v2";   // v2 schema: required for v7/v8 proofs (§7.2a)
    // ...
  };

  body: {
    holderCommitment: Hash;
    credentialId: Hash;

    claims: {
      // Accreditation type
      accreditationType:
        | "accredited_investor"      // US SEC definition
        | "qualified_purchaser"      // US higher threshold
        | "professional_investor"    // EU MiFID II
        | "eligible_counterparty"    // EU highest tier
        | "institutional";           // Generic institutional

      // Jurisdiction of accreditation
      jurisdiction: ISO3166Alpha2;

      // Basis for accreditation (not the actual values)
      basis: {
        incomeTest: boolean;
        netWorthTest: boolean;
        professionalCertification: boolean;
        entityType: boolean;
      };
    };
  };
}

// Proof: "I meet accreditation requirements"
interface AccreditationProof {
  proofType: "zkc:proof:accreditation:v7";

  // Conceptual. zkc:proof:accreditation:v7 proves only that the issuer-signed
  // level is at least the requested level (required0) and, when requested,
  // the issuer-signed institutional flag (§6.2.1, §7.2a).
  claim: {
    // Required accreditation level
    requiredType: AccreditationType[];

    // Accepted jurisdictions.
    // NOT proven by this identity: set_root is 0 and no jurisdiction is bound.
    acceptedJurisdictions: ISO3166Alpha2[];
  };

  proof: ZKProof;

  publicInputs: {
    holder_commitment: Hash;
    claim_binding: Hash;
    proof_context: Hash;
    predicate_type: u8;
    set_root: Hash;              // 0 for accreditation
    accumulator_root: Hash;
    accumulator_epoch: u64;
    timestamp: u64;
    current_epoch: u64;
    issuer_public_key_x: Bytes32;
    issuer_public_key_y: Bytes32;
  };
}
```

### 3.4 Source of Funds Credential

Proves funds originated from verified sources.

```typescript
interface SourceCredential extends ZKCCredential {
  header: {
    type: "zkc:cred:source:v2";          // v2 schema: required for v7/v8 proofs (§7.2a)
    // ...
  };

  body: {
    holderCommitment: Hash;
    credentialId: Hash;

    claims: {
      // Source category
      sourceType:
        | "employment_income"
        | "business_income"
        | "investment_returns"
        | "inheritance"
        | "gift"
        | "sale_of_assets"
        | "regulated_exchange"
        | "other_verified";

      // Verification details
      verification: {
        method: "bank_statement" | "tax_return" | "exchange_records" | "legal_documents";
        verifierType: "bank" | "accountant" | "exchange" | "legal";
      };

      // Amount range (not exact amount)
      amountRange: {
        currency: ISO4217;
        min: u64;
        max: u64;
      };

      // Time period
      period: {
        from: Timestamp;
        to: Timestamp;
      };
    };
  };
}

// Proof: "My funds come from verified sources"
interface SourceProof {
  proofType: "zkc:proof:source:v7";

  // Conceptual. zkc:proof:source:v7 proves only that the issuer-signed,
  // non-zero source code is a member of the verifier's accepted-source set
  // root (setRoot, §6.2.1, §7.2a).
  claim: {
    // Acceptable source types (the accepted-source set)
    acceptableSources: SourceType[];

    // Minimum verification standard.
    // NOT proven by this identity: no verification level is signed or bound.
    minVerificationLevel: "self_declared" | "document_verified" | "third_party_verified";
  };

  proof: ZKProof;

  publicInputs: {
    holder_commitment: Hash;
    claim_binding: Hash;
    proof_context: Hash;
    predicate_type: u8;
    set_root: Hash;              // Accepted source-code set
    accumulator_root: Hash;
    accumulator_epoch: u64;
    timestamp: u64;
    current_epoch: u64;
    issuer_public_key_x: Bytes32;
    issuer_public_key_y: Bytes32;
  };
}
```

### 3.5 Tax Compliance Credential

Proves tax obligations have been met.

```typescript
interface TaxCredential extends ZKCCredential {
  header: {
    type: "zkc:cred:tax:v2";             // v2 schema: required for v7/v8 proofs (§7.2a)
    // ...
  };

  body: {
    holderCommitment: Hash;
    credentialId: Hash;

    claims: {
      // Tax jurisdiction
      jurisdiction: ISO3166Alpha2;

      // Tax year (issuer-signed claim1, u64, §7.2a)
      taxYear: u64;

      // Compliance status
      status: "filed" | "filed_and_paid" | "no_liability";

      // What was reported (not actual values)
      reportedCategories: {
        capitalGains: boolean;
        income: boolean;
        foreignAssets: boolean;
      };

      // Issuer type
      issuerType: "tax_authority" | "licensed_accountant" | "tax_software";
    };
  };
}

// Proof: "I have met tax obligations for jurisdiction X"
interface TaxProof {
  proofType: "zkc:proof:tax:v7";

  // Conceptual. zkc:proof:tax:v7 proves only that the issuer-signed, non-zero
  // tax-jurisdiction code is a member of the verifier's accepted set root
  // (setRoot) and that the one issuer-signed tax year is at least the
  // requested minimum (required1, u64) (§6.2.1, §7.2a).
  claim: {
    // Required jurisdiction (the accepted tax-jurisdiction set)
    jurisdiction: ISO3166Alpha2;

    // Required tax years.
    // NOT proven as a list by this identity: it proves one credential year
    // >= one minimum year. A later year says nothing about an earlier year.
    taxYears: u64[];

    // Minimum status.
    // NOT proven by this identity: no filing or payment status is signed or bound.
    minStatus: "filed" | "filed_and_paid";
  };

  proof: ZKProof;

  publicInputs: {
    holder_commitment: Hash;
    claim_binding: Hash;
    proof_context: Hash;
    predicate_type: u8;
    set_root: Hash;              // Accepted tax-jurisdiction set
    accumulator_root: Hash;
    accumulator_epoch: u64;
    timestamp: u64;
    current_epoch: u64;
    issuer_public_key_x: Bytes32;
    issuer_public_key_y: Bytes32;
  };
}
```

### 3.6 Sanctions Clearance Credential

Proves absence from sanctions lists (negative proof).

```typescript
interface SanctionsClearanceCredential extends ZKCCredential {
  header: {
    type: "zkc:cred:sanctions:v2";       // v2 schema: required for v7/v8 proofs (§7.2a)
    // ...
  };

  body: {
    holderCommitment: Hash;
    credentialId: Hash;

    claims: {
      // Lists checked
      listsChecked: {
        OFAC: boolean;
        UN: boolean;
        EU: boolean;
        UK: boolean;
        other: string[];
      };

      // Screening date
      screeningDate: Timestamp;

      // Result
      result: "clear" | "potential_match_resolved";

      // Screening provider
      providerType: "regulated_entity" | "compliance_service";
    };
  };
}

// Proof: "I am not on sanctions lists"
interface SanctionsClearanceProof {
  proofType: "zkc:proof:sanctions:v7";

  // Conceptual. zkc:proof:sanctions:v7 proves only that the issuer-signed
  // screening code is not a member of the verifier's canonical blocked-code
  // set (canonicalSet and setRoot, §6.2.1, §7.2a, §7.2c).
  claim: {
    // Required lists.
    // NOT proven by this identity: no list coverage is signed or bound.
    requiredLists: ("OFAC" | "UN" | "EU" | "UK")[];

    // Maximum age of screening.
    // NOT proven by this identity: no screening date is signed or bound.
    maxScreeningAge: Duration;
  };

  proof: ZKProof;

  publicInputs: {
    holder_commitment: Hash;
    claim_binding: Hash;
    proof_context: Hash;
    predicate_type: u8;
    set_root: Hash;              // Blocked screening-code set
    accumulator_root: Hash;
    accumulator_epoch: u64;
    timestamp: u64;
    current_epoch: u64;
    issuer_public_key_x: Bytes32;
    issuer_public_key_y: Bytes32;
  };
}
```

### 3.7 Issuer-Authoritative Attribute-Set Credential

`zkc:cred:attribute-set:v1` is the reference credential for revealing selected raw field attributes while proving that every revealed value and position came from issuer-authoritative state. It contains an issuer-signed active `attributeCount` (1–8) and eight fixed attribute slots; slots at or above the count MUST be zero.

Its proof entry is `zkc:proof:selective_disclosure:v1`, carried only in a `zkc:proof:v2` anonymous or scoped presentation envelope. The public statement contains `credential_attribute_count`, `disclosure_count`, `disclosed_flags[8]`, and `disclosed_attributes[8]`. Array index is the attribute position. A hidden slot is `(false, 0)` and a disclosed zero is `(true, 0)`; implementations MUST NOT infer disclosure from whether the value is zero.

Legacy attribute sets MUST use one layout per exact issuer signing key. Draft `zkc:cred:attribute-set:v2` authenticates the layout in the issuer signature and is used by `zkc:proof:selective_disclosure:v3`. The request names the layout explicitly in both generations. See §7.2b for the legacy trust pin and the successor's public binding.

The complete issuer digest, typed transcript, public-input ABI, and consumer boundary are normative in `docs/zkc_selective_disclosure.md`. ZKA and AFP MAY carry the resulting versioned ZKC envelope but MUST delegate its cryptographic and issuer-state verification to ZKC.

---

## 4. Attestation Layer

### 4.1 Issuer Registration

```typescript
interface Issuer {
  // Unique identifier: the exact issuerId string the issuer publishes in its
  // metadata (schemas/issuer-metadata.schema.json, "zkc:issuer:<name>"). It
  // does not derive from a key, so it stays stable across key rotation
  // (keyHistory below). Only the credential-rebind circuits carry it, as
  // issuerIdHash = string_to_field(issuerId) (§7.4.1). The KYC, jurisdiction,
  // remaining-predicate, and selective-disclosure circuits carry no issuer
  // identifier: they expose the issuer public key, which the verifier matches
  // against its own trust policy (§6.2 step 4d).
  id: IssuerIdentifier;

  // Public information
  metadata: {
    name: string;
    jurisdiction: ISO3166Alpha2;
    website: URL;
    credentialTypes: CredentialType[];

    // Regulatory status
    regulatoryStatus: {
      regulated: boolean;
      regulator?: string;
      licenseNumber?: string;
    };

    // Optional issuer-assisted credential rebinding support.
    // SECURITY: "zkc:proof:credential_rebind:v1" is a historical, contained
    // identity (§4.5): it authenticates no credential and MUST NOT be
    // advertised or accepted for live migration.
    credentialRebinding?: {
      supported: boolean;
      modes: ("zkc:proof:credential_rebind:v1" | "issuer_assisted")[];
      auditMapping?: {
        sealedAtRest: boolean;
        accessControlled: boolean;
        purpose: "migration_audit_compliance";
        retention: "minimum_applicable_period";
        publicSurfacesForbidden: (
          | "settlement"
          | "indexer"
          | "note_discovery"
          | "compliance_bundle"
          | "public_proof"
          | "public_log"
        )[];
      };
    };
  };

  // Cryptographic keys
  keys: {
    // Current signing key
    currentKey: IssuerVerificationKey;

    // Key rotation history
    keyHistory: {
      key: IssuerVerificationKey;
      validFrom: Timestamp;
      validUntil: Timestamp;
      revoked: boolean;
    }[];
  };

  // Revocation accumulator (Poseidon2 Merkle profile, §2.4; authenticated
  // publication, §2.4.1)
  accumulator: {
    current: Hash;   // current Merkle root
    epoch: u64;
    updateEndpoint: URL;
  };
}
```

### 4.2 Issuer Registry

The issuer registry is **decentralized and verifier-controlled**:

```typescript
interface IssuerRegistry {
  // No central authority
  // Each verifier maintains their own trust list

  // Registry provides discovery, not trust
  discover(query: IssuerQuery): Issuer[];

  // Verifiers publish their trust policies
  publishTrustPolicy(policy: TrustPolicy): void;

  // Users can find verifiers that accept their credentials
  findAcceptingVerifiers(credential: ZKCCredential): Verifier[];
}

interface TrustPolicy {
  // Verifier identifier
  verifier: VerifierIdentifier;

  // Trusted issuers by credential type
  trustedIssuers: {
    credentialType: CredentialType;
    issuers: IssuerIdentifier[];

    // Or: minimum requirements for any issuer
    requirements?: {
      regulated: boolean;
      jurisdictions: ISO3166Alpha2[];
      minReputation?: u64;
    };
  }[];

  // Policy metadata
  metadata: {
    name: string;
    description: string;
    lastUpdated: Timestamp;
  };
}
```

### 4.2a Registry Governance (Reference Registry)

This repository ships a reference, file-based registry (`registry/`) realizing §4.2 and the Safeguard 1/4 obligations for predicates: versioned predicate entries with hash-pinned circuit identity, review status, and public review evidence (`registry/predicates/`), issuer metadata documents (`registry/issuers/`), and published verifier trust policies (`registry/verifiers/`). Governance process, immutability/evolution/deprecation rules, and review-status semantics are specified in `docs/zkc_predicate_registry_governance.md`.

Normative constraints (restating §1.4 for any ZKC registry, including this one):

- A registry is **advisory**. Registry membership MUST NOT be necessary or sufficient for trust: verifiers decide via their own key-exact policies, which MAY reference predicates and issuers that appear in no registry. Registry absence MUST NOT cause verification failure when a verifier's local policy pins the predicate and issuer directly and no entry-v2 artifact alias requires binding-policy evidence. A manifest-declared alias whose binding record is unavailable MUST fail closed because its independent lifecycle and review gates cannot be checked.
- A registry MUST be **non-exclusive** (Safeguard 1): multiple entries from independent authors MAY serve the same proof type; lookups MUST be able to return all of them; and no registry mechanism may designate a canonical, default, or mandatory entry.
- Predicate entries MUST be **versioned and immutable once merged to the public default branch** (Safeguard 4), regardless of `review.status` or activation state. The committed identity is `predicateId`, `entryVersion`, `proofTypes`, the complete `circuit` block, and `publicInputEncoder`; the bytes of the direct circuit package, every recursively referenced repository-local dependency package, and the public-input encoder MUST remain immutable. The reference Noir registry MUST bind each circuit name to the matching regular workspace `bin` package entry point, reject missing, escaping, or symlinked local-dependency closures, and bind the encoder path to the generated artifact manifest before first publication. Review evidence/status, activation, and deprecation metadata MAY transition without changing that identity. `activation.activatedAt` records activation (published-for-use), not first publication. Circuit evolution MUST be strictly additive: a previously unreferenced source package, generated artifacts, public-input encoder, entry version whose `activation.supersedes` names the immediate prior version in that lineage, and—until explicit entry-version selection exists—a distinct proof type for a same-lineage replacement; a version bump alone is insufficient. Old sources, dependency packages, encoders, artifacts, and entries MUST be retained; deprecation only flags an entry and never removes it. Review and activation history MUST be public.
- The additive entry-v2 format separates a predicate source identity from its artifact bindings. `sourceId` MUST hash the canonical exact source-file closure plus public-input contract. Each child `bindingId` MUST independently hash its source parent, proof system, exact compiler/backend provenance, build profile, artifact paths, and ACIR/VK identities. Source and binding review and lifecycle state are independent, and all committed identity inputs and referenced bytes remain immutable. A selector-free proof retains its v1 proof type, circuit, public-input contract, and verification key. When that exact legacy artifact also has a v2 binding, the verifier MUST apply the binding's source-review, binding-review, activation, deprecation, and local-policy gates; it MUST reject absent, conflicting, cross-wired, or ambiguous alias evidence. The verifier identifies the legacy artifact by the VK digest, VK hash, and ACIR digest its artifact manifest pins; an absent pin is not compared, but a malformed pin fails closed. When the manifest pins no VK identity for a proof type or circuit name that an entry-v2 binding uses, the verifier cannot show that no alias exists and MUST fail closed. A shared artifact may have distinct v1 and v2 circuit names or proof types only when its source bytes, ordered public-input contract, ACIR digest, VK digest, and VK hash agree exactly. This policy check does not select a different artifact or rewrite the presented proof type.
- An entry-v2 artifact MUST be selected by the exact tuple `(predicateId, entryVersion, bindingId)`. Resolution MUST be a single exact lookup with no latest-version rule, ordering preference, ambient toolchain, fallback, or verification-key trial. Unknown, malformed, inactive, deprecated, locally disallowed, or source-cross-wired selectors MUST fail closed. The selected tuple and artifact provenance MUST be retained as verification audit evidence. A verifier-local allowlist MAY narrow admitted binding ids but registry presence alone never authorizes one; it applies to a selector-free proof through that proof's exact same-artifact alias. The allowlist does not exclude a v1-only sibling spelling of the same predicate whose artifact is no binding's artifact (for example a linkable `zkc:proof:kyc:v1` answer); verifiers restrict those with `accepted_profiles` and `accepted_review_statuses`. Both plain and authenticated verification MUST reject a missing or mismatched proof selector when the verifier request pins one. An inferred same-artifact alias MUST be labeled as such in audit evidence.
- A registry MUST be usable from a **local copy** without network access; it stores no revocation state and cannot revoke anything.

Conformance: an implementation that treats registry membership as trust fails ZKC-Core (seeded negative `safeguard-1-registry-membership-not-trust`).

### 4.3 Credential Issuance Flow

```
CREDENTIAL ISSUANCE
═══════════════════

┌──────────┐         ┌──────────┐         ┌──────────┐
│   User   │         │  Issuer  │         │ Registry │
└────┬─────┘         └────┬─────┘         └────┬─────┘
     │                    │                    │
     │  1. Request        │                    │
     │  credential        │                    │
     │  (with binding     │                    │
     │   commitment)      │                    │
     │───────────────────>│                    │
     │                    │                    │
     │                    │  2. Verify         │
     │                    │  identity          │
     │                    │  (off-chain KYC)   │
     │                    │                    │
     │  3. Issue          │                    │
     │  credential        │                    │
     │  (signed, with     │                    │
     │   accumulator      │                    │
     │   witness)         │                    │
     │<───────────────────│                    │
     │                    │                    │
     │                    │  4. Update         │
     │                    │  accumulator       │
     │                    │  (add credential)  │
     │                    │───────────────────>│
     │                    │                    │
     │  5. Store          │                    │
     │  credential        │                    │
     │  locally           │                    │
     │                    │                    │
```

### 4.4 Revocation Flow

```
CREDENTIAL REVOCATION
═════════════════════

┌──────────┐         ┌──────────┐         ┌──────────┐
│  Issuer  │         │ Registry │         │ Verifier │
└────┬─────┘         └────┬─────┘         └────┬─────┘
     │                    │                    │
     │  1. Revoke         │                    │
     │  credential        │                    │
     │  (remove from      │                    │
     │   accumulator)     │                    │
     │───────────────────>│                    │
     │                    │                    │
     │                    │  2. Publish        │
     │                    │  new accumulator   │
     │                    │  epoch             │
     │                    │───────────────────>│
     │                    │                    │
     │                    │                    │  3. Verifiers
     │                    │                    │  require proofs
     │                    │                    │  against new
     │                    │                    │  epoch
     │                    │                    │
```

### 4.5 Credential Rebinding and Issuer Audit Mappings

Credential rebinding is a **continuity claim, not a migration.** An issuer-authenticated rebind proof (§7.4) shows that whoever controls the binding key an issuer bound a credential to also controls a new key, without revealing either seed. It does not move the credential: the credential digest stays bound to the old holder commitment, so the new key can neither present the credential's predicates nor rebind it again, and the old key keeps full power. Moving a credential to a new holder commitment after key rotation or recovery requires the issuer to re-issue it to the new commitment (§4.3). A verifier that treats an accepted rebind as an account move MUST apply the state rules of §7.4.7.

A rebind proof **is** an old-to-new link, presented to the verifier: the linkable statement publishes both holder commitments, and the scoped statement publishes both presentation pseudonyms under one `scopeId` together with the issuer-assigned `credentialId`. The verifier, and anyone it forwards the proof to (for example through an audit bundle), learns that the two handles belong to one holder. The sealed-mapping rules below govern mappings an issuer retains; they do not make the proof itself unlinkable, and holders SHOULD treat every rebind as disclosing the link to its recipient.

> **Security containment (2026-09-06) — the published rebind statements are unauthenticated.** The four published rebind identities, `zkc:proof:credential_rebind:v1`, `zkc:proof:rebind:v2`, `zkc:proof:credential_rebind:v2`, and `zkc:proof:rebind:v3`, constrain only that the prover knows the credential binding keys behind the old and new holder handles. Every credential field they carry (holder commitment, credential identifier, issuer and schema hashes, both validity bounds) is an unconstrained private witness chosen by the prover, and no issuer signature and no accumulator membership are verified. A cryptographically valid proof under any of them is therefore evidence of attacker-chosen key continuity only; it is **not** evidence of credential ownership, issuance, or live (non-revoked) continuity, and it MUST NOT be described or accepted as such.
>
> Normative consequences: (1) a holder MUST NOT select, generate, or negotiate any of the four identities for live credential migration, and MUST fail an explicit request with a stable security error; (2) a verifier MUST reject any envelope or request naming one of them with `UNAUTHENTICATED_CREDENTIAL` before backend verification, at every entry point, with an empty and with a configured issuer trust policy alike — an Authenticated Proof Request establishes requester accountability, never credential issuance; (3) request-pinned `issuerIdHash` / `schemaIdHash` values are equality filters over prover-chosen values and are never issuer authentication; (4) the historical circuit sources, encoders, binding sidecars, artifacts, and registry pins stay byte-frozen as historical records and are never reinterpreted; (5) the registry entries `zkc-credential-rebind@1.0.0`–`4.0.0` are `deprecated` with no historical-verification exception, because the statements never authenticated the fact they were used to assert. The supported mechanism is the pair of additive issuer-authenticated successors specified in §7.4 — `zkc:proof:credential_rebind:v3` (linkable) and `zkc:proof:rebind:v4` (scoped) — which verify the issuer's signature over the `zkc:attestation:credential-rebind:v1` transcript recomputed in-circuit from constrained fields and prove fresh non-revocation for the same credential identifier. A request MUST name a successor explicitly; implementations MUST NOT map a deprecated identity to a successor or a successor to a deprecated identity (no downgrade path).

Issuer-assisted migration MAY be offered as an integration optimization, but it MUST NOT replace the core rebind proof. If an issuer retains any old-holder-commitment to new-holder-commitment mapping, the mapping MUST be sealed and minimized:

1. Access-controlled and encrypted or equivalently sealed at rest.
2. Purpose-limited to migration audit/compliance.
3. Retained for the minimum applicable period.
4. Excluded from settlement, indexer, note-discovery, compliance-bundle, public-proof, public-log, analytics, and metadata surfaces.
5. Unusable to affect ZKA note validity, custody, transferability, withdrawal, or exit rights.

Conformance tests for issuer-assisted rebinding MUST include negative cases asserting that retained mappings are not emitted in issuer metadata, credential payloads, proof public inputs, compliance bundles, note announcements, public logs, indexer records, or revocation feeds.

---

## 5. Client SDK

### 5.1 Core Interface

```typescript
interface ZKCClient {
  // === Initialization ===

  // Initialize from the canonical 32-byte AFP-KDC v1.0.2 seed
  static fromSeed(seed: Uint8Array): ZKCClient;

  // Initialize from existing ZKA key hierarchy
  static fromZKAKeys(keys: ZKAKeyHierarchy): ZKCClient;

  // === Credential Management ===

  // Store credential. credentialId is issuer-chosen, so a holder keys
  // stored credentials by (issuer, credentialId): a credential from another
  // issuer that reuses an identifier is stored alongside, never in place of,
  // one already stored.
  storeCredential(credential: ZKCCredential): void;

  // List stored credentials
  listCredentials(filter?: CredentialFilter): ZKCCredential[];

  // Update accumulator witness (for non-revocation proofs). Without issuerId,
  // fails (AMBIGUOUS_CREDENTIAL) when stored credentials from more than one
  // issuer carry credentialId; never guesses.
  updateWitness(credentialId: Hash, issuerId?: IssuerIdentifier): Promise<AccumulatorWitness>;

  // === Proof Generation ===

  // Generate compliance proof
  generateProof(
    request: ProofRequest,
    credentials: ZKCCredential[]
  ): Promise<ComplianceProof>;

  // Generate compliance proof with a remote prover that cannot inspect
  // witness plaintext or obtain spending authority.
  generateDelegatedProof(
    request: DelegatedProofRequest,
    credentials: EncryptedCredentialWitness[]
  ): Promise<ComplianceProof>;

  // === Binding ===

  // Get binding commitment (for credential requests)
  getBindingCommitment(): Hash;

  // Prove credential binds to shielded identity
  proveBinding(
    credential: ZKCCredential,
    targetIdentity: IdentityProof
  ): Promise<BindingProof>;
}
```

### 5.2 Proof Generation

```typescript
interface ProofRequest {
  // What the verifier requires
  requirements: {
    // Required proof types
    proofTypes: ProofType[];

    // Type-specific parameters
    parameters: ProofParameters;

    // Freshness requirement
    maxProofAge: Duration;

    // Context binding (prevents replay across sessions/profiles)
    context: ProofContext;
  };

  // Verifier's trust policy (which issuers accepted)
  trustPolicy: TrustPolicy;

  // OPTIONAL signed presentation policy (§5.9). Absence requests anonymous.
  presentation?: {
    profile: "zkc:presentation:anonymous:v1" |
             "zkc:presentation:scoped:v1" |
             "zkc:presentation:linkable:v1";
    scopePolicy?: string;
    rotationEpochSeconds?: u64;       // 0 = no rotation
  };
}

interface DelegatedProofRequest {
  proofRequest: ProofRequest;

  // Remote prover identity and accepted predicate source hashes.
  prover: ProverIdentifier;
  acceptedPredicateSources: PredicateSourceHash[];

  // Encrypted witness payloads; plaintext credentials, cbk, masterSeed,
  // spending keys, ZKA addresses, note plaintext, and payment history are
  // forbidden in delegated requests.
  encryptedWitnesses: EncryptedWitnessTransport[];

  // Holder-controlled authorization. This may allow one proof generation for
  // the stated context, but MUST NOT authorize spending, withdrawal, credential
  // export, or generation for a different context.
  delegation: DelegationToken;
}

// Generate proof
async function generateComplianceProof(
  client: ZKCClient,
  request: ProofRequest
): Promise<ComplianceProof> {
  // 1. Find matching credentials
  const credentials = client.listCredentials({
    types: request.requirements.proofTypes,
    issuers: request.trustPolicy.trustedIssuers,
    notExpired: true
  });

  if (credentials.length === 0) {
    throw new Error("No matching credentials");
  }

  // 2. Update accumulator witnesses
  for (const cred of credentials) {
    await client.updateWitness(cred.body.credentialId, cred.header.issuer);
  }

  // 3. Generate proofs
  const proofs: IndividualProof[] = [];

  for (const proofType of request.requirements.proofTypes) {
    const cred = credentials.find(c => c.header.type === proofType);

    const proof = await generateIndividualProof(
      proofType,
      cred,
      request.requirements.parameters[proofType],
      request.requirements.context
    );

    proofs.push(proof);
  }

  // 4. Include the individually context-bound proofs in the envelope.
  //    Linkable v1 envelopes can also carry the commitments defined in §7.3.
  return buildComplianceEnvelope(proofs, request.requirements.context);
}
```

### 5.3 Delegated Proof Generation

Agents MAY delegate proof generation to a remote prover or compliance service, but baseline ZKC conformance is non-custodial. A delegated prover MUST NOT receive `masterSeed`, spending keys, ZKA addresses, note plaintext, unencrypted credential witnesses, raw credential-binding keys, or payment history. The holder SDK MUST fail closed when a service requests those materials.

Delegated proof generation authorizes only production of the scoped ZKC proof. It MUST NOT be interpreted as a ZKM mandate, permission to act for the holder, transaction approval, a reusable holder capability, or delegation of custody, signing, withdrawal, or spending authority.

A delegation token and every field it carries MUST be treated as untrusted input. Before generating or releasing holder-controlled proof material, the holder SDK MUST resolve the expected delegation verification key from authenticated local holder state and verify the token under that locally resolved key. It MUST NOT use `holderKeyX`, `holderKeyY`, or any other token-carried key as the authorization trust anchor. In the reference 32-byte affine-coordinate profile, the SDK MUST reject non-exact coordinate encodings, compare both coordinates with constant-time byte comparisons against the locally derived key, and reject a malformed key, coordinate mismatch, or invalid signature before proof or material generation.

Scope, expiry, nonce, consent, credential, predicate-registry, issuer-policy, accumulator, and proving-backend checks are additive controls. An implementation MUST NOT treat any of them as a substitute for the cryptographic holder-key anchor above. Token-carried holder-key coordinates MAY remain in a wire representation for compatibility and token self-consistency checks, but they do not authenticate the holder or widen the delegated authority.

The holder commitment alone also MUST NOT bootstrap delegation authority. Under the frozen AFP-KDC mapping, distinct exact seed-byte strings can be KDC aliases with the same commitment; byte-domain delegation-key derivation intentionally keeps those seeds distinct. A token signed by an alias seed therefore fails the locally resolved delegation-key check even when its claimed holder commitment is equal.

A conforming delegated proving flow has these properties:

1. The holder constructs a `ProofContext` and reviews the principal-readable predicate request before delegation.
2. The holder encrypts witness material to a prover mechanism that can produce the requested proof without exposing witness plaintext to the service operator, or uses an equivalent holder-controlled execution environment.
3. The delegated authorization is scoped to one proof request, one context value, one predicate source set, and one expiry. The predicate source set is that of the proof types the holder emits for the request under its presentation profile (§5.9), not necessarily the requested spellings.
4. The prover returns a ZKC proof envelope whose public inputs include the requested `proofContext`. The envelope follows the reviewed request's presentation profile (§5.9): `zkc:proof:v2` with the presentation-resolved sibling proof type under the default anonymous profile, and `zkc:proof:v1` only when the holder explicitly consented to the linkable profile. The scoped profile is refused, because a scope derives from an authenticated verifier key and a delegated request carries no Authenticated Proof Request. For the same reason the holder SDK applies the Safeguard 6 default (§1.4) and refuses a delegated request unless the holder explicitly opts in, with the override logged. The reference holder SDK checks the following before it consumes any delegated use: the Safeguard 6 opt-in, the presentation profile and linkable consent, secret and unknown parameter keys, binding selectors, the proof context, composite and anonymous-composite rules, credential-rebind containment, the Safeguard 4 review gate, and credential selection (a trusted, unexpired stored credential that satisfies the requested level and attributes, and canonical-set reconciliation). Witness refresh, revocation and accumulator checks, backend availability, and proving run after the use is reserved; a failure there still consumes the reserved uses, and in a batch any proofs already generated are discarded.
5. The holder or verifier rejects the result if the context, predicate source hash, issuer trust policy, accumulator epoch, or proof type differs from the delegated request as resolved under its presentation profile (§5.9): for example, a delegated `zkc:proof:jurisdiction:v3` request answered anonymously carries `zkc:proof:jurisdiction:v4`, and the consumer requests and trusts that identity.

Hosted custody profiles, managed wallets, and compliance outsourcing products MAY exist as deployment/product profiles, but they MUST NOT be represented as baseline ZKC conformance unless the host lacks unilateral spend authority and cannot reconstruct holder identity linkage beyond the explicitly delegated scope.

### 5.4 Agent API

```typescript
// Agent-native interface for programmatic compliance
interface ZKCAgentClient extends ZKCClient {
  // === Automated Compliance ===

  // Configure auto-response to proof requests
  setCompliancePolicy(policy: AgentCompliancePolicy): void;

  // Handle incoming proof request automatically
  handleProofRequest(request: ProofRequest): Promise<ComplianceProof | Rejection>;

  // === Principal Viewing Delegation (not spend authority) ===

  // Delegate viewing-limited access to principal.
  // This conveys no ZKM mandate or spending authority.
  // Minting derives the delegation key and holder commitment from the same
  // authenticated local masterSeed. Token-carried holder-key coordinates are
  // compatibility metadata, never the authorization trust anchor.
  delegateViewing(
    principal: PublicKey,
    scope: ViewingScope
  ): DelegationToken;

  // === Batch Operations ===

  // Pre-generate proofs for anticipated requests
  precomputeProofs(anticipatedRequests: ProofRequest[]): void;

  // Verify counterparty compliance before transacting
  verifyCounterparty(
    counterpartyProof: ComplianceProof,
    requirements: ProofRequest
  ): VerificationResult;
}

interface AgentCompliancePolicy {
  // Auto-respond to these proof types
  autoRespond: {
    proofType: ProofType;
    maxDisclosure: DisclosureLevel;
    trustedVerifiers: VerifierIdentifier[];
  }[];

  // Require approval for these
  requireApproval: ProofType[];

  // Never respond to these
  block: ProofType[];

  // Principal to notify on compliance events
  notifyPrincipal: PublicKey;
}
```

**Disclosure ceiling (`maxDisclosure`).** `maxDisclosure` is a per-proof-type parameter ceiling, compared per parameter in the direction that discloses more: a threshold the circuit compares as `value >= required` may not exceed the ceiling and MUST be within the circuit's unsigned domain, and a requirement flag may be true only where the ceiling's is true. Unordered values (set roots, membership modes, claim types, selectors) MUST equal the ceiling exactly. A proof type without such a typed comparison MUST NOT be auto-disclosed. A set-membership request whose inclusion witness is fixed by verifier-supplied paths, rather than derived by the holder from a canonical code list, discloses the holder's exact member and MUST NOT be auto-disclosed without the principal's explicit opt-in for that proof type. The reference comparator table is in [`zkc_minimal_disclosure_planning.md`](zkc_minimal_disclosure_planning.md).

`delegateViewing` delegates only the stated viewing scope. It MUST NOT be represented or accepted as a ZKM mandate, a delegation of ZKA spending authority, or authority to generate a proof outside that viewing scope.

**Delegation minting contract.** A conforming implementation MUST canonicalize `masterSeed` once and derive both the delegation signing key and `holderCommitment` from those same authenticated local seed bytes. If a lower-level minting API accepts a caller-supplied `holderCommitment` for compatibility, it MUST accept only the exact integer representation, recompute the commitment from the canonical seed bytes, reject any mismatch before signing, and serialize and sign the recomputed value. The public-key coordinates emitted in the token identify the derived key for wire compatibility; consumers MUST still apply the local-holder key invariant in §5.3 rather than trusting those coordinates. This contract neither exports the seed nor changes the token wire format or the authority delegated by `delegateViewing`.

**Delegation token digest (v2).** The holder's delegation key signs `digest = SHA-256(transcript)`, and every consumer recomputes the same transcript from the token fields before it verifies the signature. Every field is length-prefixed, the proof-type list carries an explicit count, and the reviewed request commitment is a field of the same transcript:

```text
F(v)       = u32be(len(v)) || v
transcript = "zkc/delegation-token:v2" || 0x00
          || F(principalKeyX) || F(principalKeyY)        // 32 bytes each
          || u32be(n) || F(utf8(t_1)) || ... || F(utf8(t_n))
          || F(u256be(contextValue))
          || F(utf8(verifierId))
          || F(u64be(expiresAt)) || F(u32be(maxUses))
          || F(u256be(holderCommitment))
          || F(u64be(issuedAt)) || F(u256be(nonce))
          || F(requestDigest)                            // 0 or 32 bytes
```

`t_1 ... t_n` are the distinct proof types of the scope, ordered by their UTF-8 bytes; a scope is a set, so order and repetition in the input do not change the digest. Integers are fixed-width big-endian and MUST be exact integers in range before serialization: `contextValue`, `holderCommitment`, and `nonce` in `[0, r)` with `r` the BN254 scalar-field modulus, `expiresAt` and `issuedAt` in `[0, 2^64)`, and `maxUses` in `[1, 2^32)`. Booleans, floats, strings, and modular aliases are rejected, not reduced. An empty `requestDigest` marks an inspection-only token, which cannot authorize holder material; an authorizing token carries the 32-byte reviewed-request commitment. Known answers are in [`tests/vectors/delegation_token_digest_v2.json`](../tests/vectors/delegation_token_digest_v2.json).

The v1 transcript (domain `zkc/delegation-token`) NUL-terminated the proof types and `verifierId` with no length prefix or count, and folded the request commitment in with a second hash. It was not injective: a token signed for one proof type containing NUL had the digest of a token for two proof types, and the holder gate authorized both (security review 2026-10-04, R3.8). Implementations MUST NOT produce or accept v1 delegation digests. A token's digest version is part of its representation; minting, the holder authorization gate, and delegated provers MUST fail closed on any version other than 2. There is no compatibility path for v1 tokens: they are short-lived, holder-local capabilities, and a holder re-mints them. A re-minted token MUST use a fresh `nonce`. The holder's durable use store keys each token by `H(holderKey || nonce)` and records the digest it first saw, so a v2 token that reuses the nonce of a token already used under v1 fails closed ("delegation nonce was already bound to another token").

**Delegation identifier characters.** Each proof type and the `verifierId` of a viewing scope MUST be a nonempty Unicode string that encodes to fewer than `2^32` UTF-8 bytes, and MUST NOT contain a code point whose Unicode General Category is `Cc` (controls, including NUL, C0, DEL, and C1), `Cf` (format characters, including zero-width space, joiners, and non-joiners, bidirectional embeddings, overrides, isolates and marks, soft hyphen, byte-order mark, and tag characters), `Cs` (surrogates), `Co` (private use), `Cn` (unassigned in the implementation's Unicode database), `Zl`, or `Zp` (line and paragraph separators). Minting MUST refuse such a scope before signing, and the holder authorization gate MUST refuse it before it compares keys, checks the signature, or reserves a use, even when the holder's key signed it. The v2 framing is injective without this rule; the rule exists so that a holder cannot be shown one string and sign another (for example an invisible NUL or bidirectional override in a review interface). It is not a confusables policy. The following remain the responsibility of the review interface, which SHOULD display identifiers with non-ASCII code points escaped: visible look-alike characters; default-ignorable combining marks and variation selectors (for example U+034F COMBINING GRAPHEME JOINER, U+FE0F VARIATION SELECTOR-16, and U+180B MONGOLIAN FREE VARIATION SELECTOR ONE); blank symbols such as U+2800 BRAILLE PATTERN BLANK; `Zs` space separators, including U+00A0 NO-BREAK SPACE, U+3000 IDEOGRAPHIC SPACE, and leading or trailing spaces; and invisible letters such as the Hangul fillers. Because `Cn` depends on the Unicode version, an implementation with an older Unicode database can refuse a newly assigned character that a newer one accepts; a code point that is unassigned in the older database is refused there, whatever category a later version gives it.

### 5.5 Authenticated Proof Request

A verifier that wishes to receive a proof **MUST** present an **Authenticated Proof Request (APR)**: its `ProofRequest` (§5.2), signed under a verifier identity key. The APR wraps the request and adds no holder-identifying data. The optional `presentation` policy is part of that signed request.

```typescript
interface AuthenticatedProofRequest {
  request: ProofRequest;               // §5.2, including optional presentation policy
  verifierId: VerifierIdentifier;      // SHOULD anchor to an AFP/KERI AID (§5.8, E.2)
  nonce: Hash;                         // anti-replay; unique per request
  issuedAt: Timestamp;
  expiresAt: Timestamp;

  // Signature over canonical serialization of the complete request plus:
  //   H("zkc/apr", verifierId, request, nonce, issuedAt, expiresAt)
  signature: {
    scheme: "ECDSA_SECP256K1" | "Ed25519";
    value: Uint8Array;
    verifierKey: VerifierVerificationKey;
  };
}
```

**Normative SDK behavior.**

- A conforming SDK **MUST** refuse, by default, to generate a proof in response to a request that is not a valid APR — valid signature, unexpired (`now ≤ expiresAt`), and a fresh, previously-unseen `nonce`. This mirrors the Safeguard 4 fail-closed posture toward opaque predicates. Overriding the default **MUST** require explicit, logged opt-in.
- The SDK **MUST** verify that `request.requirements.context.value` recomputes from the APR's own fields, so the signature covers the bound purpose (under the purpose-bound profile, §2.2).
- The effective proof types and predicate parameters used for witness construction **MUST** exactly equal the proof types and parameters in the verified APR. The SDK **MUST NOT** combine a signed APR with a separately supplied broader request.
- When a request selects an entry-v2 artifact binding, `request.extensions["zkc:request:binding-selectors:v1"].selectors` **MUST** contain one closed record `{ proofType, predicateId, entryVersion, bindingId }` for that requested proof type. The APR digest commits the canonical extension under the domain `zkc/apr/extensions:v1`; APRs without `extensions` retain their original digest exactly. The holder MUST copy the three-field selector unchanged into the emitted proof entry as `bindingSelector`. Selection from an unsigned extension, an uncommitted local hint, an ambient toolchain, or a "latest" rule is forbidden.
- The APR signature does **not** identify or constrain the holder. It binds the *verifier* to having asked. (See §5.8 residual limit E.3: this is verifier-deniability spend, not holder-privacy spend.)

**Reference authenticated-verification boundary.** `VerifierTrustPolicy.verifier_id`
and `verifier_signing_keys` are verifier-owned configuration. Keys are compressed
SEC1 public keys; an empty set trusts no APR, and an explicit tuple supports
managed key rotation. Neither pin is learned from the received APR, issuer
policy, or registry. An unknown key, wrong verifier ID, or disagreement between
the complete APR context and the local verification context is `UNSIGNED_REQUEST`
and returns before scope derivation or proof verification. Known context profiles
use closed, type-strict metadata; any supplied value or purpose tag must
reconstruct from every structured field.

Holder and hosted admission likewise compare the complete canonical APR context
with the supplied `ProofContext` before generating any proof. Opaque contexts
require the signed verification-context extension below, whose context must
agree with both copies. Admission snapshots the APR and the supplied context
reference so caller mutations during proving cannot relabel the validated
context in the resulting proof or receipt. Fields that would disappear when serializing the
supplied context are refused. Known reference profiles retain their legacy
no-extension form and normalization of optional derived fields. A context that
contradicts a valid signed APR is a hard refusal, including when
`allow_unauthenticated=True` is set; that opt-in remains available for an
unauthenticated request and records the existing override. These checks do not
change the APR digest or receipt signature bytes.

The published legacy APR digest remains byte-identical. For those APRs the
reference verification profile fixes `maxProofAge` to **3600 seconds**. A custom
age or opaque context requires the versioned signed extension
`request.extensions["zkc:request:verification-context:v1"]`, with exactly
`{ "context": <complete context metadata>, "maxProofAge": <nonnegative integer> }`.
The existing `zkc/apr/extensions:v1` commitment authenticates this block. Its
context must agree with both the APR context and local request; a supplied
`request.maxProofAge` must agree with the block (or legacy 3600 default).
`verification_context_extension(context, max_proof_age)` constructs the block
before signing. This extension does not authenticate the separate legacy
`trustPolicy` member.

A successfully verified APR consumes its canonical nonce. Concurrent calls must
reserve it atomically before proof verification; failure releases the reservation.
The reference default cache lasts for one `ZKCVerifier` instance. Recreated
instances must share the explicit mutable nonce store; services spanning processes
or restarts must enforce atomic shared, durable replay protection at their
integration boundary. Noncanonical nonce aliases and unwritable stores fail
closed. Holder and verifier APR admission use wall-clock Unix seconds when
`now` is omitted. An explicit `now` is a trusted caller-owned u64 time for
historical verification or deterministic simulation; it MUST NOT be derived
from the received APR or proof context for a live expiry decision.

**Canonical host integers.** APR `issuedAt`, `expiresAt`, context `timestamp`,
and explicit `now` MUST be exact integers in `[0, 2^64)` (reference authenticated
context validation additionally requires positive timestamps). Context `sessionId`
and other scalar-field inputs MUST decode to exact integers in `[0, r)`.
Booleans, floats, coercible strings and modular aliases are rejected before
signing, signature verification or freshness evaluation. Existing hex field
wire forms decode to scalar integers; they are not reduced modulo `r`.
The reference Poseidon sponge retains its arithmetic mode for circuit/KAT
compatibility and uses `hash_fields(..., strict=True)` for APR, context and
receipt host commitments. Delegation uses the length-prefixed SHA-256 v2
transcript of §5.4 and applies the same exact-integer validator before
serialization, including canonical scalar nonces and u64 issuance/expiry. The
integer validation changes no transcript bytes; apart from the separate
delegation v1-to-v2 transcript change (§5.4), existing KATs are unchanged. Receipt signature verification remains historical
evidence verification; live APR freshness is checked separately at admission.

When named-entity evidentiary value is required, `verifierId` SHOULD anchor to an AFP/KERI AID so the signing key has the identity continuity a counterparty or court recognizes (§5.8, E.2).

### 5.6 Disclosure Receipt

On answering — or explicitly refusing — an APR, the SDK **MUST** retain a **Disclosure Receipt**: holder-custodied, self-contained evidence of exactly what was demanded and what was answered. A third party verifies the demand from the receipt alone; it verifies the holder's part only against a holder key it anchors out of band (§5.6.1).

```typescript
interface DisclosureReceipt {
  apr: AuthenticatedProofRequest;      // the verifier-signed demand, verbatim
  outcome: "answered" | "refused";
  // Present iff answered. Binds the active presentation profile's handle
  // and nothing more (§5.9.3); the linkable shape is shown here.
  response?: {
    holderCommitment: Hash;            // linkable profile only (§8.2)
    contextValue: Hash;                // == apr.request.requirements.context.value
    answeredProofTypes: ProofType[];
  };
  holderSignature: {
    scheme: "ECDSA_SECP256K1" | "Ed25519";
    value: Uint8Array;                 // over H("zkc/receipt", apr, outcome, response)
    holderKey: HolderPublicKey;        // profile-scoped key (§5.6.1); NOT a trust anchor
  };
  recordedAt: Timestamp;
}
```

**Custody and service boundary (normative).**

- Receipts are **holder-custodied**. A hosted SDK, prover, proxy, indexer, or compliance service **MUST NOT** retain receipts, and **MUST NOT** be required to in order for the holder to transact (parallel to the ZKC §1.4 and ZKA §1.6 non-custodial mandates). The APR `nonce` + signature is a linkable tag; it stays in holder custody and on the verifier's own side, and is never broadcast.
- The holder **MAY** export a receipt to any third party. A third party verifies the *verifier* signature (proving the demand) and the *holder* signature against a holder key it anchors itself (§5.6.1). No issuer, registry, or operator participates in verification.

#### 5.6.1 Holder keys and what a receipt proves (normative)

The `holderKey` carried in a receipt is self-asserted. Anyone can sign a well-formed receipt under a key of their own, naming any APR they hold and any handle they have seen (for example another holder's linkable `holderCommitment`). A carried key is therefore **never** a trust anchor. A relying party **MUST** compare the carried key with an **expected holder key** that it obtained from the holder through a channel it authenticates as that holder (for example the holder's enrolment with that relying party). It **MUST NOT** take the expected key from the receipt, from the APR signer, or from any party other than the holder. Without an expected key, verification **MUST** fail closed. The comparison is over the exact 64-byte `x || y` encoding, in constant time, and counts only when the holder signature verifies under that key.

Anchoring the key does not anchor the response handle: a holder can sign a receipt that names another holder's commitment under its own, correctly anchored key. The relying party **MUST** therefore also compare the response handle (`holderCommitment`, or `presentationPseudonym` together with `scopeId`) with the handle it associated with the anchored key when it obtained that key, and **MUST** treat a mismatch as invalid.

Reference: `verify_receipt(receipt, expected_holder_key=…)` returns `valid` only when `aprValid`, `holderValid`, `holderKeyAnchored` and `contextBound` all hold. `holderKeyAnchored` is true only when the signature is valid and the carried key equals the expected key. The handle comparison is the caller's, because only the caller knows which handle it associated with the key. `aprValid` alone is the verifier-accountability evidence.

**Key scope.** A receipt key **MUST NOT** link more than the active presentation profile's handle (§5.9.3). A conforming holder therefore **MUST** sign linkable receipts under an authenticated APR with one key per verifier identity: stable across that identity's receipts (so the relying party's anchor stays valid) and different for different identities (so the key is no cross-verifier handle). It **MUST** use one stable key per `scopeId` for scoped receipts, and a fresh key for every anonymous, refused or unauthenticated receipt. The reference derivations use HMAC-SHA512 keyed by the exact 32 master-seed bytes (never the reduced field element). `frame(p_1, …, p_n)` is `u32be(len(p_1)) || p_1 || … || u32be(len(p_n)) || p_n`, and a 64-byte output `d` maps to the secp256k1 private key `int_be(d) mod (n − 1) + 1`:

```text
receiptKey(label, inputs…) = map(HMAC-SHA512(seed, frame("zkc/receipt-key:v2", label, inputs…)))

linkable  (authenticated APR):   label "linkable-verifier", inputs be32(verifierIdentity)        (§5.9.1)
scoped    (authenticated APR):   label "scoped",            inputs be32(scopeId)                 (§5.9.1, scopeId != 0)
anonymous, refused, or any
unauthenticated answer:          label "fresh",             inputs nonce, be32(receiptDigest)
```

For the fresh key, `nonce` is 32 bytes from the system CSPRNG, drawn for this receipt and discarded after signing. `receiptDigest` is the receipt's own `H("zkc/receipt", apr, outcome, response)` (§5.6, reference `receipt_digest_from_dict` of the unsigned receipt), which is known before signing. Mixing it in means that a repeated CSPRNG output (for example after a virtual-machine snapshot is cloned) still cannot give two different receipts the same key. Because the nonce is discarded, **nobody can derive a fresh key again, the holder included**; its public half exists only inside the receipt.

| Receipt | Key | Same key on two receipts when … | What the receipt proves to a third party |
|---|---|---|---|
| linkable, authenticated APR | stable per verifier identity | same holder, same APR signer key | Anchored, with the handle check: the verifier key asked X, and the holder known under that key and that `holderCommitment` answered in this context. The key adds no link beyond the global commitment the linkable profile already discloses. |
| scoped | stable per `scopeId` | same holder, same scope (verifier identity, scope policy, rotation epoch) | Anchored, with the handle check: the verifier key asked X, and the holder known under that scope key and that pseudonym answered in this context. It links only what the pseudonym already links. |
| anonymous | fresh per receipt | never | **Cannot be anchored by a third party.** Only `aprValid` (the verifier key asked X) and `contextBound` (the response names that demand's context) carry third-party meaning. The holder signature proves only the receipt's integrity under the key it carries. It does not identify the holder or prove which envelope was presented. Passing the carried key as the expected key means only that the presenter vouches for that key. |
| refused | fresh per receipt | never | Cannot be anchored by a third party: `aprValid` proves the demand, and the holder signature proves integrity under the carried key. |
| any unauthenticated answer | fresh per receipt | never | Cannot be anchored by a third party. `aprValid` may still hold (for example a validly signed APR that is stale, replayed, or does not match the request), but the holder did not authenticate the demand: the receipt is the holder's own record. |

No receipt proves that the holder's credential satisfies the predicate (that is the proof's job), that the verifier accepted the answer (§5.8 E.1), or that a handle belongs to a particular person. An anonymous receipt cannot be used to claim that a specific holder answered, because it carries no handle. A receipt forged under a non-holder key fails against the expected key; a receipt that a real holder signs over another holder's handle fails the handle comparison above. The SDK never logs, serializes or stores a derived private key. A holder gives a relying party a stable key's public half out of band, together with the handle it uses there (reference: `HolderClient.receipt_public_key(verifier_identity=…)` or `(scope_id=…)`).

**Audit authorizations.** A holder-authorized audit bundle (`zkc:audit-bundle:v1`, [docs/zkc_audit_disclosure.md](zkc_audit_disclosure.md)) follows the same rule. Its `holderAuthorizationKey` is self-asserted, and an auditor **MUST** verify the authorization against the holder key it obtained from the holder out of band, failing closed without one. The reference key is stable per auditor: `root = HMAC-SHA512(seed, frame("zkc/audit-authorization-root:v2"))`, then `map(HMAC-SHA512(root, frame("zkc/audit-authorization-key:v2", utf8(auditorKeyId))))` over the exact `auditorKeyId` of the authorization record. The root yields keys for every auditor, so an implementation **MUST** keep it as holder-local as the seed (the reference exporter refuses serialization and redacts its `repr`). An anchored bundle proves that the holder known to that auditor authorized disclosure of exactly these members, for this auditor, window and purpose. It does not prove that the bundled envelopes were produced from that holder's credentials: anonymous envelopes bind no holder, and a linkable envelope ties to a holder only through a commitment the auditor already knows.

**Compatibility.** The receipt digest, the receipt fields and the `holderSignature` shape are unchanged. Earlier reference holders (before this section) used one seed-global key per purpose. Such a document verifies only when the relying party passes that key explicitly as the expected key, and it remains linkable through that key. With `seed` the exact 32 master-seed bytes and `n` the secp256k1 group order, the legacy keys were:

```text
legacy receipt key (every receipt):     k = int_be(BLAKE2b-512("ZKC-Receipt-Key" || seed)) mod n; k = 1 if k == 0
legacy audit-authorization key:         k = int_be(SHA-256("zkc/audit-authorization:v1:" || seed)) mod n  (k == 0 is an error)
```

The current SDK does not derive the legacy keys; a holder that needs to anchor a legacy document computes the public key from these formulas.

### 5.7 Plaintext-Disclosure Scope (Normative)

A purpose binding that covers only ZK proofs leaves the plaintext channel as a laundering path: a verifier obtains a real passport "for billing" and re-evaluates nationality outside ZKC entirely.

Therefore a conforming deployment that accepts **any** holder attribute in plaintext, or in a form the verifier can re-evaluate (KYC dossiers, document scans, revealed claims), **MUST** gate that disclosure behind an APR (§5.5) carrying a `purpose-bound` context (§2.2), and **MUST** retain a receipt (§5.6) on the same terms as a ZK proof. A purpose declared for a plaintext disclosure is a binding representation: re-evaluating that attribute under a different purpose without a fresh APR is a **provable purpose violation**, evidenced by the holder's receipt set. ZKC cannot prevent the re-evaluation; it makes the violation attributable.

### 5.8 Residual Accountability Limits (Normative)

These limits are normative disclosure. They **MUST NOT** be omitted by downstream documentation or softened into optional notes.

**E.1 — Decision accountability is unreachable.** Receipts attest the *request* and the holder's *response*, never the verifier's *decision*. A verifier may decline silently. Against a single-predicate request a decline is nearly dispositive; against a compound predicate, which-conjunct-failed remains ambiguous and cannot be forced into the open. This is a leverage asymmetry, not an implementation gap: a holder has the leverage to demand a signed *request* (no signature ⇒ no proof) but none to demand a signed *decision*.

**E.2 — Evidentiary value is parasitic on verifier-identity continuity.** A receipt proves "key K asked me X." It proves "*Verifier V* asked me X" only if K is bound to V with continuity a court or counterparty recognizes. Throwaway per-request keys degrade the receipt to an anonymous record. Real verifiers (exchanges, banks, model providers) cannot transact under throwaway identity and remain the entity you are transacting with; adversarial ones can. Anchoring `verifierId` to an AFP/KERI AID is therefore **REQUIRED** for the receipt to carry named-entity weight. The cryptography is neutral; the real-world binding is not in scope of this mechanism.

**E.3 — Cost falls on the verifier, not the holder.** The APR binds the verifier to its demand while the holder discloses nothing new (the verifier already observed the proof). The price paid is verifier *deniability*, not holder privacy. A benign verifier asking lawful predicates incurs no meaningful cost; a coercive one resists signing, and that refusal is the signal.

### 5.9 Presentation Profiles (Normative)

The base v1 presentation exposes a stable, cross-verifier-linkable `holderCommitment` in every proof (§8.2). The **presentation-profile ladder** corrects this: a presentation is one predicate family plus one **presentation profile** that determines whether — and how narrowly — the holder is re-identifiable across presentations. Three profiles are defined; this design implements amended ADR 0001 ([docs/adr/0001-multi-show-unlinkable-presentations.md](adr/0001-multi-show-unlinkable-presentations.md)).

| Presentation profile | Public handle | Selection |
|---|---|---|
| `zkc:presentation:anonymous:v1` | none (pseudonym and scope both `0`) | **default** — used whenever no `presentation` block is requested |
| `zkc:presentation:scoped:v1` | `presentationPseudonym` + `scopeId` | requested via an authenticated APR (§5.5) |
| `zkc:presentation:linkable:v1` | global `holderCommitment` | explicit consent; the legacy v1 envelope/circuit surfaces, unchanged |

`zkc:presentation:anonymous:v1` is the default profile: anonymity is the ambient default, and continuity is always an explicit, signed, purpose-bound request — never ambient. The holder's profile choice is holder-local configuration: an implementation MUST NOT take it from verifier wire input, and linkable consent is an explicit holder decision separate from the request object. Under an authenticated APR, that decision is the holder's linkable ceiling together with an APR that asks for the linkable profile or is silent on presentation. Whenever no verifier is authenticated (an unauthenticated request, the logged Safeguard 6 override, or delegated generation), the holder must consent separately (reference SDK: `allow_linkable=True`). The escrowed auditor-linkable profile is out of scope (separate ADR).

**Implementation model.** The anonymous and scoped profiles are served by the v2 circuit family and the `zkc:proof:v2` envelope (§6.1). Those circuits move `holderCommitment` to a private witness and add two public inputs, `presentationPseudonym` and `scopeId`, governed by a single sentinel rule: `scopeId == 0` means anonymous (the circuit constrains `presentationPseudonym == 0`, so the handle carries no holder information); `scopeId != 0` means scoped (the circuit constrains the pseudonym to derive from the credential binding key and the scope). The linkable profile is **not** reimplemented — it is the existing, byte-for-byte-frozen v1 circuit/envelope family, grandfathered and consent-gated. A verifier that forces `scopeId = 0` merely downgrades itself to anonymous; the failure direction is *more* privacy, never less.

#### 5.9.1 Derivations

All new domain constants follow the existing `derive_domain` pattern (§1.3, KDC §A.3) and are pinned by assertion plus golden vector:

```text
DOMAIN_ZKC_PRESENTATION_SCOPE = derive_domain("zkc/presentation-scope:v1")
DOMAIN_ZKC_SCOPE              = derive_domain("zkc/scope:v1")
DOMAIN_ZKC_VERIFIER_ID        = derive_domain("zkc/verifier-id:v1")
```

The **presentation pseudonym** is the only derivation that must be provable in-circuit, so it uses Poseidon:

```text
presentationPseudonym = H("zkc/presentation-scope:v1", cbk, scopeId)
```

The **verifier identity** and **scope id** are computed natively by the holder and the verifier — never proven in-circuit — over the APR signer's SEC1 compressed public key:

```text
verifierIdentity = H("zkc/verifier-id:v1", sec1_compressed(aprVerifierPubkey))
scopeId          = H("zkc/scope:v1", verifierIdentity, scopePolicy, rotationEpoch)
```

- `scopePolicy` is the APR-declared policy string (e.g. `"verifier"`, or `"protocol:<name>"` for a named scope local to the APR signer).
- `protocol:<name>` remains signer-local: the same name under different signing keys derives different scopes. Distinct holder consent and verifier declaration remain required. A shared multi-verifier scope needs a separately specified identity/governance mechanism and is not implemented by this derivation.
- For `scopePolicy: "session"`, hash `"session:" || hex(contextValue)` of the APR request context as the policy label. Every proof answering that context shares one pseudonym, while fresh contexts and distinct verifier identities derive unrelated scopes. The `"session:"` prefix is reserved and MUST be refused when named literally.
- Session unlinkability requires a fresh context for each session. Reusing a context repeats the session scope and is not unlinkable; the existing proof-context freshness contract remains mandatory.
- `rotationEpoch = floor(timestamp / rotationEpochSeconds)` when the APR declares `rotationEpochSeconds > 0`, else `0`. Rotation therefore lives entirely in `scopeId` construction; the pseudonym derivation and the circuits never change with rotation policy.
- A derived `scopeId` of exactly `0` MUST be rejected (it is the anonymous sentinel; probability ≈ 2⁻²⁵⁴).

#### 5.9.2 APR presentation block

The APR `request` object gains an OPTIONAL `presentation` block, covered by the existing APR signature (`apr_digest_from_dict` extends to include it):

```jsonc
"presentation": {
  "profile": "zkc:presentation:scoped:v1",
  "scopePolicy": "verifier",          // or "session", or "protocol:<name>"
  "rotationEpochSeconds": 0            // 0 = no rotation
}
```

An absent block ⇒ `zkc:presentation:anonymous:v1`. Holder-side rules:

1. Scoped requests require an **authenticated** APR (Safeguard 6, §5.5). An
   unauthenticated request cannot establish `verifierIdentity`, so it can only
   be answered anonymously (or refused).
2. The holder derives `scopeId` itself from the APR signer key. A
   verifier-supplied literal `scopeId` anywhere in the request is a protocol
   error — the holder NEVER accepts a verifier-supplied opaque scope.
3. A `scopePolicy` starting with `"protocol:"` requires a distinct consent flag
   (`allow_protocol_scope`) on the holder's `ProofRequest`.
4. The holder MAY downgrade scoped → anonymous; it MUST NOT silently upgrade
   anonymous → scoped or scoped → linkable.
5. When the effective profile is anonymous, the holder MUST refuse, before
   proving, a request for two or more distinct proof types (reference:
   `ANONYMOUS_COMPOSITE_REFUSED`), unless it has explicitly opted in
   (reference: `allow_unlinked_composite` on the `ProofRequest`) for a
   verifier that declares the requested proofs independent facts (§5.9.4).
   Anonymous proofs bind to no single holder, so a conforming verifier
   otherwise rejects the answer (`UNBOUND_COMPOSITE`, §5.9.4), and producing
   it would only disclose which predicates the holder satisfies. A
   conjunction is answered under the scoped profile, preferably with
   `scopePolicy` `"session"`, which needs both the APR to request it and the
   holder's own profile ceiling to permit it (rule 4). Downgrading a
   multi-proof scoped request to anonymous therefore yields this refusal
   rather than an anonymous answer. Single-proof anonymous answers are
   unaffected.

#### 5.9.3 Per-profile receipts

The Disclosure Receipt `response` (§5.6) binds the **active profile's handle, never more**:

| Profile | `response` contents | `holderSignature.holderKey` (§5.6.1) |
|---|---|---|
| anonymous | `contextValue`, `answeredProofTypes` — no holder-derived handle | fresh per receipt |
| scoped | + `presentationPseudonym`, `scopeId` | stable per `scopeId` |
| linkable | the legacy v1 shape (`holderCommitment`, …) — unchanged | stable per verifier identity (fresh when the APR does not authenticate) |

The global `holderCommitment` MUST NOT enter an anonymous or scoped (v2) receipt. The receipt signing key is part of the handle surface: it MUST NOT be shared across profiles, verifiers or scopes in a way that links more than the response handle does.

#### 5.9.4 Verifier rules

**Envelope-generation binding (both envelope versions).** The holder handle a
verifier credits a presentation to is read by name from `publicInputs`, but a
proof system only binds the inputs its circuit's public-input encoder declares
(§6.1). For every proof entry evaluated for the request in either envelope version the verifier MUST
therefore apply, before reading any public input:

- **Exact public-input names.** The `publicInputs` object MUST contain exactly
  the names declared by the encoder of the circuit that verifies the entry —
  no more, no fewer — else `MALFORMED_PROOF`. An undeclared key is a value no
  proof constrains; reading it (a `holderCommitment` above all) would let the
  presenter choose it.
- **Circuit family.** A circuit whose encoder declares `holder_commitment` or
  `old_holder_commitment` is a *linkable-family* circuit and is admissible only
  in a `zkc:proof:v1` envelope; one whose encoder declares
  `presentation_pseudonym` or `old_presentation_pseudonym` is a
  *presentation-family* circuit and is admissible only in a `zkc:proof:v2`
  envelope. Any other placement is `PROFILE_MISMATCH`. The family is derived
  from the encoder document, never from the proof type's spelling.
- **Rebind routing.** Every issuer-authenticated rebind proof type (§7.4) is
  verified by the rebind rules (§7.4.5) whichever envelope carries it, so a
  misplaced rebind still reports issuer-identity disagreement
  (`UNTRUSTED_ISSUER`) in addition to `PROFILE_MISMATCH`, and no rebind
  statement is ever accepted under the anonymous profile.

Unrequested entries remain ignored for validity and reported as
`OVER_DISCLOSURE` (§6.2 step 4a); they establish no verified claim.

**Linkable gate.** A `zkc:proof:v1` envelope is the linkable profile. A
verifier whose policy sets `TrustPolicy.accepted_profiles` explicitly MUST
reject a v1 envelope with `PROFILE_NOT_ACCEPTED` unless that set contains
`zkc:presentation:linkable:v1`. A policy that leaves `accepted_profiles` unset
accepts v1 envelopes for backward compatibility; the linkable-consent
requirement itself lives in the holder/APR emission layer (§5.9.2).

**Authenticated profile agreement.** On the authenticated path (§6.2 step 0),
when the APR carries a `presentation` block, an envelope MUST NOT be more
linkable than the APR's profile (anonymous < scoped < linkable; a v1 envelope
is linkable), else `PROFILE_MISMATCH`. A less linkable envelope is a legitimate
holder downgrade (§5.9.2 rule 4) and is not rejected by this rule.

**Reporting the effective presentation.** Because a downgrade is legitimate, the
profile a verifier asked for is not the profile it received. A verifier MUST
report, with every verification result, the effective presentation of the
envelope:

| Result field (reference name) | Value |
|---|---|
| profile (`presentation_profile`) | `presentationBinding.profile` of a `zkc:proof:v2` envelope; `zkc:presentation:linkable:v1` for a `zkc:proof:v1` envelope |
| handle (`presentation_handle`) | scoped: `presentationBinding.pseudonym`; linkable: `holderBinding.commitment`; anonymous: none |
| scope (`scope_id`) | scoped: `presentationBinding.scopeId`; otherwise none |
| scope recomputed (`scope_recomputed`) | true only when the verifier recomputed `scopeId` from its own authenticated identity (rule 3 below) and it matched |

The values describe the envelope as parsed; a caller relies on them only for a
valid result. The handle and scope (and so a true "scope recomputed") are
reported only when at least one requested proof was checked against the
envelope binding: an envelope that answers no requested proof (for example
one presented to a request listing no proof types) has an unproven,
presenter-chosen binding handle, and reports none. A verifier MUST NOT treat a scoped pseudonym as a continuity
handle unless the scope was recomputed: on the unauthenticated path the holder
chooses `scopeId`, and a fresh `scopeId` gives a fresh pseudonym. The reference
wire result (`VerificationResult.to_dict()`) carries these values as a
`presentation` object (`profile`, `scopeRecomputed`, and for scoped
`pseudonym` and `scopeId`) for `zkc:proof:v2` envelopes only; the
`zkc:proof:v1` wire result keeps its legacy shape.

**Continuity-required policy.** A verifier that relies on repeat recognition
(for example one claim per holder) MAY require continuity in its local policy
(reference: `VerifierTrustPolicy.require_presentation_continuity`, default
off). This is verifier-local policy, not an APR field: the signed APR format is
unchanged. Under this policy the verifier MUST reject:

- an anonymous envelope with `PROFILE_MISMATCH` (it carries no holder handle,
  so a scoped request answered anonymously fails instead of passing silently);
- a scoped envelope whose `scopeId` it did not recompute from its own
  authenticated identity with `SCOPE_MISMATCH` — on the unauthenticated path
  (no APR) this is every scoped envelope;
- a scoped or linkable envelope in which no requested proof bound the handle
  with `PROFILE_MISMATCH`.

A linkable envelope satisfies the policy: its global `holderCommitment` is a
stable handle that no presentation parameter changes. It is still subject to
the linkable gate and to authenticated profile agreement.

One holder has a different handle under each handle-bearing profile (a scoped
`presentationPseudonym` and the linkable `holderCommitment`), so a verifier
that de-duplicates holders on the handle MUST accept exactly one
handle-bearing profile: scoped or linkable, not both. Under this policy the
verifier's `accepted_profiles` MUST therefore admit exactly one of them
(listing the anonymous profile is allowed; it is rejected anyway). A policy
that leaves `accepted_profiles` unset admits scoped v2 and, for compatibility,
linkable v1 envelopes, so the reference refuses to construct a
continuity-required policy without an explicit set (`ValueError`).

Even under one profile, the handle is constant only while `scopeId` is.
`scopeId` derives from the APR signer key, the `scopePolicy` and the rotation
epoch, so one holder holds a different scoped handle at the same verifier for
each pinned verifier signing key (including across a signing-key rotation),
for each `scopePolicy`, and for each rotation epoch; `scopePolicy` `"session"`
gives one handle per request context, not across sessions. A verifier that
de-duplicates on the handle MUST keep these inputs fixed for the period it
de-duplicates over. The handle identifies a credential binding key, not a
person; one handle per person holds only as far as issuance gives one binding
key per person.

**Same-holder semantics of each profile.** A presentation answering several
requested proof types is a conjunctive claim only if its proofs are bound to
one holder:

| Profile | Same-holder binding across the envelope's proofs |
|---|---|
| linkable (`zkc:proof:v1`) | every proof's `holderCommitment` equals `holderBinding.commitment` |
| scoped | every proof's in-circuit `presentationPseudonym` (derived from the holder's binding key) equals the envelope pseudonym; with `scopePolicy` `"session"` this adds no linkability beyond one fresh request context |
| anonymous | **none** — no public input derives from the binding key, so proofs from different holders are indistinguishable from one holder's |

A verifier MUST therefore reject an anonymous envelope that answers two or
more distinct requested proof types with `UNBOUND_COMPOSITE`, unless its policy explicitly
declares that every multi-proof request it makes is a set of independent facts
that different holders may prove (reference: `accept_independent_anonymous_proofs`).
A verifier that needs a conjunction over several credentials requests the
scoped profile, preferably with `scopePolicy` `"session"`. An over-disclosed
proof the request did not ask for is not an answer and does not count. Duplicate
entries of a single type do not create another conjunct or fill a missing type.
Both independence flags require actual booleans; strings and integer aliases
MUST NOT authorize unlinked composite disclosure. A
conforming holder refuses to produce such an anonymous answer unless it has
opted in (§5.9.2 rule 5).

For a `zkc:proof:v2` envelope, the verifier (§6.2) additionally applies, in order:

1. **Policy gate.** `presentationBinding.profile` MUST be in
   `TrustPolicy.accepted_profiles` (default `{anonymous, scoped}`) else
   `PROFILE_NOT_ACCEPTED`.
2. **Shape consistency (anti-replay).** For every proof entry: anonymous ⇒
   `presentationPseudonym == 0 && scopeId == 0`; scoped ⇒ `scopeId != 0`,
   `presentationPseudonym == presentationBinding.pseudonym`, and
   `scopeId == presentationBinding.scopeId`. Any mismatch ⇒ `PROFILE_MISMATCH`.
   This replaces the v1 envelope-vs-proof `holderCommitment` consistency check.
3. **Scope recomputation** (scoped + authenticated path). The verifier
   recomputes `scopeId` from its own signing identity, the APR `scopePolicy`,
   and the rotation epoch; a mismatch ⇒ `SCOPE_MISMATCH`. Without an APR the
   verifier cannot recompute `scopeId`: it accepts any shape-consistent
   non-zero scope and reports it as not recomputed. Every scope must
   derive from a locally pinned signing identity. A named protocol scope also
   requires an explicit verifier declaration; it never bypasses that identity check.
4. **Rebind / aggregation.** Scoped rebind requires `scopeId != 0`. The verifier reads
   `presentationPseudonym` rather than `holderCommitment` and enforces
   old/new-pseudonym and envelope-scope consistency. The only rebind statement
   admissible under the scoped profile is the issuer-authenticated
   `zkc:proof:rebind:v4` (§7.4), together with its draft beta.25 republication
   `zkc:proof:rebind:v5` (§7.4.3); the deprecated `zkc:proof:rebind:v2` /
   `zkc:proof:rebind:v3` identities are rejected (§4.5). The verifier MUST
   reject aggregation blocks in both anonymous and scoped envelopes with
   `INVALID_AGGREGATION` (§7.3).

`PROFILE_MISMATCH`, `SCOPE_MISMATCH`, `PROFILE_NOT_ACCEPTED`, and `UNBOUND_COMPOSITE` join the existing structured error family (§6.2). A `zkc:proof:v1` envelope takes the v1 verification path and is classified `zkc:presentation:linkable:v1`; it is subject to the envelope-generation binding and the linkable gate above.

#### 5.9.5 Public-input determinism invariant

The property that makes the ladder hold is stated normatively, not left incidental:

> No public input of a presentation may be deterministic in credential-only material unless it is the declared linking handle of the active profile.

This is a **MUST**: under the anonymous profile `presentationPseudonym` and `scopeId` are the constant `0`; under the scoped profile the only credential-deterministic handle is `presentationPseudonym`, which is scope-exclusive (it changes with `scopeId`). In particular `claimBinding` satisfies the invariant only because its preimage retains `proofContext` and `timestamp`, so it rotates per presentation — **that inclusion is load-bearing and MUST be preserved** in every v2 circuit. Conformance tests MUST enforce the invariant for every public input a profile adds (§9.2).

---

## 6. Verifier Specification

### 6.1 Proof Format

```typescript
interface ComplianceProof {
  // Protocol version
  version: "zkc:proof:v1";

  // Proof metadata
  metadata: {
    generatedAt: Timestamp;
    expiresAt: Timestamp;

    // Context binding
    context: ProofContext;
  };

  // Individual proofs (may be aggregated)
  proofs: {
    proofType: ProofType;
    proof: ZKProof;
    publicInputs: PublicInputs;
  }[];

  // Holder binding (links all proofs to same identity)
  holderBinding: {
    commitment: Hash;
    bindingProof: ZKProof;
  };

  // Optional v1 envelope commitments (§7.3)
  aggregation?: {
    proof: ZKProof;
    inputProofCommitments: Hash[];
    aggregationCommitment: Hash;
    aggregatedClaimBinding: Hash;
  };
}
```

**Envelope v2 (`zkc:proof:v2`).** Anonymous and scoped presentations (§5.9) use the `zkc:proof:v2` envelope (`schemas/compliance-proof-v2.schema.json`). It replaces `holderBinding` with a `presentationBinding` block and never carries `holderBinding`:

```typescript
interface ComplianceProofV2 {
  version: "zkc:proof:v2";
  metadata: { generatedAt; expiresAt; context: ProofContext };
  proofs: { proofType; proof; publicInputs }[];   // v2 proof types, §4/§5.9
  presentationBinding: {
    profile: "zkc:presentation:anonymous:v1" | "zkc:presentation:scoped:v1";
    // present iff profile == scoped, and equal to every proof's public inputs:
    pseudonym?: Hash;   // == presentationPseudonym
    scopeId?: Hash;     // == scopeId
  };
  // The wire schema can represent this block. Verifiers reject it (§7.3).
  aggregation?: ComplianceProofV1["aggregation"];
  // NOTE: no `holderBinding` — that field exists only in v1 (linkable) envelopes.
}
```

`zkc:proof:v1` envelopes (with `holderBinding.commitment`) remain valid and are classified `zkc:presentation:linkable:v1`; the envelope-level `presentationBinding` and the per-proof public inputs are cross-checked (§5.9.4) so profile ⇔ public-input shape consistency prevents cross-profile replay. The Disclosure Receipt `response` (§5.6) is per-profile (§5.9.3): anonymous binds only `contextValue` + `answeredProofTypes`; scoped adds `presentationPseudonym`
+ `scopeId`; only the linkable v1 path binds `holderCommitment`.

Within every proof entry, the canonical wire key for each encoder-declared public input is exactly the snake_case `name` entry from the encoder document for the circuit selected by `proofType` (`schemas/public-inputs/<circuit>.json`), and the input MUST be serialized under that key verbatim. A `camelName` published by a public-input binding sidecar MUST NOT be used as a proof-entry wire key: request `parameters` and the v1 and v2 `aggregation` blocks use camelCase at their own layers. `publicInputs` MUST contain no other key: a verifier rejects an undeclared or missing name with `MALFORMED_PROOF`, and admits a proof only in the envelope version of its circuit family (§5.9.4).

### 6.2 Verification Algorithm

```typescript
interface ZKCVerifier {
  // Trust policy
  trustPolicy: TrustPolicy;

  // Accumulator cache
  accumulatorCache: Map<IssuerIdentifier, AccumulatorState>;

  // Verify compliance proof
  verify(proof: ComplianceProof, request: ProofRequest): VerificationResult;

  // Authenticated path: step 0 below, then the same checks as verify
  // (reference verify_authenticated(apr, envelope, request), §6.2.1)
  verifyAuthenticated(
    apr: AuthenticatedProofRequest,
    proof: ComplianceProof | ComplianceProofV2,
    request: ProofRequest
  ): VerificationResult;
}

/**
 * Normative step-4e dispatcher. Implementations MAY organize these checks
 * differently, but every accepted individual proof MUST have one name-keyed
 * contract and MUST produce the same fail-closed outcomes.
 */
function verifyTypeSpecificRequirements(
  individualProof: IndividualProof,
  request: ProofRequest
): VerificationError[] {
  const contract = requestBindingContract(individualProof.proofType);
  if (contract === undefined || contract.kind !== "individual") {
    return [{
      code: "UNBOUND_PROOF_TYPE",
      message: `No request-binding contract for ${individualProof.proofType}`
    }];
  }

  const parameters = request.requirements.parameters[individualProof.proofType];
  if (!isPlainObject(parameters)) {
    return [{
      code: "REQUIREMENTS_NOT_MET",
      message: `Missing or unusable parameters for ${individualProof.proofType}`
    }];
  }

  const errors: VerificationError[] = [];
  for (const entry of contract.typeSpecificInputs) {
    try {
      // Public inputs are resolved by their snake_case names, never by field
      // offset. In particular, remaining-predicates v1/v2 reverse the order of
      // predicate_type and set_root.
      const actual = readPublicInputByName(individualProof, entry.name);
      if (entry.class === "bound") {
        const expected = resolveBoundValue(entry.source, parameters, request);
        if (!typeStrictEqual(actual, expected)) {
          errors.push(requirementsNotMet(entry.name, individualProof.proofType));
        }
      } else if (entry.class === "derived") {
        const expected = recomputeDerivedValue(entry, parameters, request, individualProof);
        if (!typeStrictEqual(actual, expected)) {
          errors.push(requirementsNotMet(entry.name, individualProof.proofType));
        }
      }
      // A free input has no request-side expected value. Its binding document
      // MUST contain the written soundness justification required by §6.2.1;
      // acceptance MUST NOT be represented as enforcing that value.
    } catch (error) {
      errors.push({
        code: error instanceof PublicInputDecodeError
          ? "MALFORMED_PROOF"
          : "REQUIREMENTS_NOT_MET",
        message: error.message
      });
    }
  }
  errors.push(...contract.familyChecks(individualProof, parameters, request));
  return errors;
}

async function verifyComplianceProof(
  verifier: ZKCVerifier,
  proof: ComplianceProof | ComplianceProofV2,
  request: ProofRequest,
  apr: AuthenticatedProofRequest   // §5.5: the verifier's own signed demand
): Promise<VerificationResult> {
  const errors: VerificationError[] = [];
  const warnings: VerificationWarning[] = [];   // advisory; never affect validity

  // 0. Authenticated request (Safeguard 6, §5.5). The verifier echoes its own
  //    APR; the holder/relay checks it. SDK-side, generation is refused
  //    without it. This step is ADDITIVE — steps 1+ are unchanged, and an
  //    existing proof/bundle verifies exactly as before.
  if (!locallyPinnedVerifier(apr) || !verifyAPRSignature(apr) || aprExpired(apr) || nonceSeen(apr.nonce)) {
    errors.push({ code: "UNSIGNED_REQUEST", message: "Request not authenticated" });
    return { valid: false, errors };
  }
  if (canonicalSerialize(request) !== canonicalSerialize(apr.request)) {
    errors.push({ code: "UNSIGNED_REQUEST", message: "Request differs from signed APR" });
    return { valid: false, errors };
  }
  for (const individualProof of proof.proofs) {
    const selector = request.bindingSelectors[individualProof.proofType];
    if (selector && !typeStrictEqual(individualProof.bindingSelector, selector)) {
      errors.push({ code: "MALFORMED_BINDING_SELECTOR", message: "Binding selector changed" });
      return { valid: false, errors };
    }
  }
  if (apr.request.requirements.context.profile === "zkc:context:purpose-bound:v1" &&
      proof.metadata.context.value !== recomputePurposeBoundContext(apr)) {
    errors.push({ code: "PURPOSE_MISMATCH", message: "Bound purpose does not match request" });
  }

  // 1. Check proof freshness
  if (proof.metadata.generatedAt < request.requirements.context.timestamp - request.requirements.maxProofAge) {
    errors.push({ code: "STALE_PROOF", message: "Proof too old" });
  }

  // 2. Check context binding
  if (proof.metadata.context.value !== request.requirements.context.value ||
      proof.metadata.context.profile !== request.requirements.context.profile) {
    errors.push({ code: "CONTEXT_MISMATCH", message: "Proof bound to different context" });
  }

  // 3. Verify the envelope-version-specific binding. Selective-disclosure
  //    presentations use v2 and therefore never enter the holderBinding path.
  let scopeRecomputed = false;   // §5.9.4 rule 3 (scoped + authenticated only)
  if (proof.version === "zkc:proof:v1") {
    if (explicitlyConfigured(verifier.trustPolicy.acceptedProfiles) &&
        !verifier.trustPolicy.acceptedProfiles.includes("zkc:presentation:linkable:v1")) {
      errors.push({ code: "PROFILE_NOT_ACCEPTED", message: "Linkable envelope not accepted" });
    }
    if (!verifyHolderBinding(proof.holderBinding)) {
      errors.push({ code: "INVALID_BINDING", message: "Holder binding invalid" });
    }
  } else if (proof.version === "zkc:proof:v2") {
    const binding = verifyPresentationBinding(
      proof.presentationBinding,
      proof.proofs,
      apr.request.presentation
    );
    errors.push(...binding.errors); // PROFILE_* / SCOPE_* errors from §5.9.4
    scopeRecomputed = binding.scopeRecomputed;
  } else {
    errors.push({ code: "MALFORMED_PROOF", message: "Unknown proof envelope version" });
    return { valid: false, errors };
  }
  if (apr.request.presentation &&
      profileRank(envelopeProfile(proof)) > profileRank(apr.request.presentation.profile)) {
    errors.push({ code: "PROFILE_MISMATCH", message: "Envelope more linkable than the APR" });
  }
  if (verifier.trustPolicy.requirePresentationContinuity) {
    // §5.9.4: anonymous => PROFILE_MISMATCH; scoped && !scopeRecomputed => SCOPE_MISMATCH.
    errors.push(...continuityErrors(envelopeProfile(proof), scopeRecomputed));
  }

  // 4. Verify each individual proof
  for (const individualProof of proof.proofs) {
    // 4a. Check proof type is required
    if (!request.requirements.proofTypes.includes(individualProof.proofType)) {
      continue; // Extra proof, ignore
    }

    // 4a'. Envelope-generation binding (§5.9.4): exactly the encoder-declared
    //      public inputs, and only a circuit of this envelope version's family.
    const encoder = publicInputEncoder(individualProof);
    if (!sameKeySet(individualProof.publicInputs, encoder.declaredNames)) {
      errors.push({ code: "MALFORMED_PROOF", message: "Undeclared or missing public input" });
      continue;
    }
    if (circuitFamily(encoder) !== envelopeFamily(proof.version)) {
      errors.push({ code: "PROFILE_MISMATCH", message: "Proof belongs to the other envelope version" });
      if (!isAuthenticatedRebind(individualProof.proofType)) continue;
    }

    // 4b. Verify the ZK proof
    const vk = getVerificationKey(individualProof.proofType);
    if (!zkVerify(vk, individualProof.publicInputs, individualProof.proof)) {
      errors.push({
        code: "INVALID_PROOF",
        message: `Invalid proof for ${individualProof.proofType}`
      });
      continue;
    }

    if (individualProof.publicInputs.proof_context !== proof.metadata.context.value) {
      errors.push({
        code: "CONTEXT_MISMATCH",
        message: `Proof context mismatch for ${individualProof.proofType}`
      });
    }

    // 4c. Check accumulator epoch and root (non-revocation). Every circuit
    //     only proves membership in the accumulator_root the PROVER supplies,
    //     so the root MUST equal the issuer root the verifier records for the
    //     proof's epoch, for EVERY root-carrying proof type: an unrecorded
    //     epoch is rejected, never accepted on the epoch alone (otherwise a
    //     revoked holder proves against a self-made one-leaf tree). Selective
    //     disclosure (v1, v2) and the authenticated rebind successors
    //     (§7.4.5) additionally require the recorded root to come from
    //     authenticated metadata-v2 announcement-chain ingestion.
    const issuer = extractIssuer(individualProof);
    const currentAccumulator = await verifier.getAccumulator(issuer);

    if (requiresAuthenticatedAccumulator(individualProof.proofType) &&
        !currentAccumulator.authenticatedMetadataV2) {
      errors.push({
        code: "UNAUTHENTICATED_ACCUMULATOR",
        message: "Accumulator root was not accepted through authenticated metadata v2"
      });
      continue;
    }

    // MAX_EPOCH_LAG: verifiers accept proofs from within 10 accumulator epochs of current.
    // An epoch is not a time period: each successful registration/issuance, revocation,
    // or atomic renewal advances exactly one epoch, and nothing else does (§2.4.1).
    // Signed announcedAt freshness is a separate check (§2.4.1, §8.3).
    const MAX_EPOCH_LAG = 10;

    if (individualProof.publicInputs.accumulator_epoch > currentAccumulator.epoch) {
      errors.push({
        code: "STALE_ACCUMULATOR",
        message: `Accumulator epoch is ahead of verifier view for ${individualProof.proofType}`
      });
      continue;
    } else if (individualProof.publicInputs.accumulator_epoch < currentAccumulator.epoch - MAX_EPOCH_LAG) {
      errors.push({
        code: "STALE_ACCUMULATOR",
        message: `Accumulator epoch too old for ${individualProof.proofType}`
      });
    }
    const recordedRoot =
      currentAccumulator.roots[individualProof.publicInputs.accumulator_epoch];
    if (recordedRoot === undefined &&
        !requiresAuthenticatedAccumulator(individualProof.proofType) &&
        verifier.trustPolicy.allowUnrecordedAccumulatorRoots) {
      // UNSAFE, explicit, logged opt-out: revocation is not checked.
      warnings.push({ code: "UNCHECKED_ACCUMULATOR_ROOT", message: "No recorded issuer root" });
    } else if (recordedRoot !== individualProof.publicInputs.accumulator_root) {
      errors.push({
        code: "STALE_ACCUMULATOR",
        message: `Accumulator root unrecorded or mismatched for ${individualProof.proofType}`
      });
    }

    // 4d. Check issuer trust
    if (!verifier.trustPolicy.trusts(issuer, individualProof.proofType)) {
      errors.push({
        code: "UNTRUSTED_ISSUER",
        message: `Issuer not trusted for ${individualProof.proofType}`
      });
    }

    // 4e. Check type-specific requirements
    const typeErrors = verifyTypeSpecificRequirements(
      individualProof,
      request
    );
    errors.push(...typeErrors);
  }

  // 5. Check all required proof types are present
  for (const required of request.requirements.proofTypes) {
    if (!proof.proofs.some(p => p.proofType === required)) {
      errors.push({
        code: "MISSING_PROOF",
        message: `Required proof type missing: ${required}`
      });
    }
  }

  // 6. Check envelope commitments (§7.3)
  if (proof.aggregation) {
    if (proof.version === "zkc:proof:v2") {
      errors.push({ code: "INVALID_AGGREGATION", message: "Aggregation unsupported in v2 envelopes" });
    } else if (proof.proofs.some(p => !request.requirements.proofTypes.includes(p.proofType))) {
      errors.push({ code: "INVALID_AGGREGATION", message: "Aggregation includes an unrequested proof" });
    } else if (!checkAggregationCommitments(proof.aggregation, proof.proofs, proof.holderBinding, request.context)) {
      errors.push({ code: "INVALID_AGGREGATION", message: "Aggregation commitment check failed" });
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    // §5.9.4 "Reporting the effective presentation". The reference wire
    // result omits this field for zkc:proof:v1 envelopes (legacy shape).
    presentation: effectivePresentation(proof, scopeRecomputed)
  };
}
```

#### 6.2.1 Type-specific request-binding contract (normative)

`verifyTypeSpecificRequirements` is the single step-4e dispatcher for
individual proof entries. The authenticated path first establishes that the
effective `ProofRequest` agrees with the signed APR; the checks below then use
that request's parameters, context value, and timestamp as authority. Running
these checks only from `verifyAuthenticated` is non-conformant: every ordinary
`verify` entry point MUST reach the same dispatcher, while authenticated
verification adds APR agreement before it.

The machine-readable, name-keyed bound/derived/free classifications in
`schemas/public-input-bindings/` and their ratified transcription in
[`docs/zkc_public_input_classification.md`](zkc_public_input_classification.md)
define the complete public-input contract. Steps 3, 4b, 4c, and 4d enforce the
common envelope/profile, context, accumulator, timestamp, and issuer-key rows;
step 4e enforces the family-specific rows below. A conforming implementation
MUST NOT infer a field's meaning from its encoder offset, treat a derived field
as a substitute for a separate bound field, or treat a justified free field as
a satisfied verifier requirement.

Numeric request parameters are exact JSON integers, not field residues or
coercible values. Before hashing or comparison, every value that enters a
BN254 `Field` slot MUST be in `[0, r)`, and values entering a narrower circuit
type MUST also be in that type's range. In particular, an implementation MUST
reject `x + k*r` for non-zero `k` instead of reducing it to `x`; it MUST also
reject booleans, strings, and floats as integer aliases. The KYC
`requiredLevel` and jurisdiction `requiredClaimType` are `u8` values.
For **every remaining-predicate generation**, accreditation `required0` MUST
be an exact integer in `[0, 256)` and tax-residency `required1` MUST be an
exact integer in `[0, 2^64)`. A verifier MUST reject an out-of-domain request
with `REQUIREMENTS_NOT_MET`, even if its full-Field claim binding matches a
cryptographically valid proof. The holder MUST refuse these requests before
proving, without coercing or truncating their values. These rules also apply
to authenticated APRs and explicit historical-identity opt-ins.

| Individual proof family | Mandatory step-4e behavior |
|---|---|
| KYC v1/v2 | Require a `u8` integer `requiredLevel` and exactly five boolean `requiredAttributes`; recompute `claim_binding = compute_claim_binding_2(requiredLevel, attribute_flags_hash(requiredAttributes), request.context.value, request.context.timestamp)`. |
| KYC v3 and community KYC v2 (`zkc:proof:kyc:v3`, `zkc:proof:community_kyc:v2`) | Apply the KYC v1/v2 contract unchanged. These draft, unactivated identities republish byte-identical circuit sources under the Noir beta.25 / Barretenberg 5.0.0 toolchain: `zkc:proof:kyc:v3` the anonymous/scoped `zkc:proof:kyc:v2` statement and `zkc:proof:community_kyc:v2` the linkable `zkc:proof:kyc:v1` statement. Their public inputs, sidecar classifications, and claim binding are unchanged. |
| Jurisdiction v1/v2 | Require `membershipType`, `requiredClaimType`, and `jurisdictionSetRoot`; compare `membership_type` directly; compare `jurisdiction_set_root` directly; and recompute `claim_binding = compute_claim_binding_3(expectedRoot, membershipType, requiredClaimType, request.context.value, request.context.timestamp)`. Exclusion additionally requires `jurisdictionCanonicalSet`, from which the verifier MUST independently derive `expectedRoot` and require agreement with `jurisdictionSetRoot`. Inclusion performs the same derivation when canonical codes are supplied; otherwise the mandatory request root is compared directly. |
| Jurisdiction v3/v4/v5 | Apply the jurisdiction v1/v2 contract unchanged. The circuits additionally constrain exclusion-neighbour adjacency (§7.2c.7). v3 (linkable) and v4 (anonymous/scoped) are the current identities; v5 is a draft, unactivated republication of the v4 statement under the beta.25 toolchain. |
| Accreditation v1/v2 | Resolve `predicate_type` from the published proof-type map and require value `1`; require `required0`, default `required1` to `0`, require `set_root == 0`, and recompute the three-slot claim binding. Because these immutable circuits do not bind `flagRequired`, a verifier MUST reject exact `true` and every non-boolean value with `REQUIREMENTS_NOT_MET`; only false/absent is usable. |
| Accreditation v3/v4 | Apply the same selector, required-slot, and `set_root == 0` checks; resolve `flagRequired` as an exact JSON boolean (absent defaults false); and recompute `claim_binding = compute_claim_binding_4(predicateType, required0, required1, flagRequired, request.context.value, request.context.timestamp)`. The circuit MUST use the same private flag in both this transcript and its conditional check against issuer-signed `claim_1`. |
| Accreditation v7/v8 | Apply the v3/v4 accreditation contract with the same four-slot transcript. These are the current hardened linkable/presentation identities; their credential digest also authenticates `validFrom`. |
| Source-of-funds v1/v2 | Resolve and compare `predicate_type == 2`; default `required0` / `required1` to `0`; require `setRoot`, compare it directly with `set_root`, and recompute the three-slot claim binding. `set_root` is outside that binding preimage, so the direct comparison is mandatory. |
| Source-of-funds v3/v4 | Apply the v1/v2 checks, require `flagRequired` to be false when supplied, and recompute the four-slot claim binding with its fixed false flag. |
| Source-of-funds v7/v8 | Apply the v3/v4 verifier checks. The circuit additionally MUST constrain the private raw source code to be non-zero before accepting Merkle membership, and the credential digest MUST authenticate `validFrom`. |
| Tax-residency v1/v2 | Resolve and compare `predicate_type == 3`; default `required0` to `0`; require `required1` and `setRoot`; compare `set_root` directly and recompute the three-slot claim binding. |
| Tax-residency v3/v4 | Apply the v1/v2 checks, require `flagRequired` to be false when supplied, and recompute the four-slot claim binding with its fixed false flag. |
| Tax-residency v7/v8 | Apply the v3/v4 verifier checks. The circuit additionally MUST constrain the private raw tax-jurisdiction code to be non-zero before accepting Merkle membership, and the credential digest MUST authenticate `validFrom`. |
| Sanctions-clearance v1/v2 | Resolve and compare `predicate_type == 4`; default both required slots to `0`; require `canonicalSet` and `setRoot`; independently derive the canonical exclusion root, require the two request parameters to agree, compare the derived root directly with `set_root`, and recompute the three-slot claim binding. |
| Sanctions-clearance v3/v4 | Apply the v1/v2 checks, require `flagRequired` to be false when supplied, and recompute the four-slot claim binding with its fixed false flag. |
| Sanctions-clearance v7/v8 | Apply the v3/v4 verifier checks. The circuit additionally MUST constrain `successor_path_index == predecessor_path_index + 1`; membership and strict ordering checks remain mandatory, and the credential digest MUST authenticate `validFrom`. |
| Remaining predicates v5/v6 (all four meanings) | Apply the v3/v4 row of the same meaning. These identities are deprecated (§7.2a): their credential digest omits `validFrom`. |
| Remaining predicates v9 (all four meanings) | Apply the v7/v8 row of the same meaning. v9 is a draft, unactivated republication of the v8 statement under the beta.25 toolchain (§7.2a). |
| Selective disclosure v1/v2 | Require a canonical nonzero `layoutId` matching the local trust pin for the exact issuer key. Require unique, in-range integer `disclosedPositions`, matching public flags, and a nonzero `disclosure_count` equal to their population count. Recompute the typed disclosure binding. Credential attribute count and disclosed values are authenticated proof outputs. |
| Selective disclosure v3 | Apply the same disclosure-mask and count checks. Require the canonical `layoutId` to equal the issuer-signed public `layout_id`. Recompute the v3 transcript including this field. The identity remains draft and unactivated (§7.2b). |
| Credential rebind (`zkc:proof:credential_rebind:v1`, `zkc:proof:rebind:v2`, `zkc:proof:credential_rebind:v2`, `zkc:proof:rebind:v3`) | **Reject unconditionally** with `UNAUTHENTICATED_CREDENTIAL` before any backend verification (§4.5 security containment). These statements verify no issuer signature and no accumulator membership, so no request parameter, trust-policy entry, or authenticated request can turn them into evidence of credential continuity. The former structural checks (old/new handle bound to the envelope, claim-binding recomputation, optional `issuerIdHash` / `schemaIdHash` equality filters) never authenticated the credential and are retained in the reference verifier only as frozen, unreachable documentation of the historical statements. |
| Authenticated credential rebind v3 (linkable, `zkc:proof:credential_rebind:v3`) | Apply the full issuer-authenticated path of steps 4b–4d exactly as for KYC: the public issuer key MUST be an exact allowlist member trusted for this proof type, the public `issuer_id_hash` MUST equal `string_to_field` of the matched issuer's identifier, and the accumulator state MUST be an **authenticated** (metadata-v2 announcement-chain) state for that issuer whose `currentEpoch` equals the proof's `current_epoch`, whose lag bound admits `accumulator_epoch`, and whose recorded root for that epoch equals `accumulator_root` (§7.4.5). Then bind `old_holder_commitment` to `holderBinding.commitment`, require `new_holder_commitment != old_holder_commitment`, recompute `claim_binding = compute_claim_binding_3(old_holder_commitment, new_holder_commitment, credential_id, proofContext, timestamp)`, and apply the optional sidecar-declared `schemaIdHash` pin as an exact equality filter **after** issuer authentication. A missing, unauthenticated, stale, ahead-of-view, or mismatched accumulator state, an untrusted key, or an issuer-identity mismatch MUST reject; the request pin can only narrow acceptance, never widen it. `issuerIdHash` is **not** an optional pin here: it is a mandatory bound comparison against the verifier's own matched trusted issuer, which is strictly stronger than the filter the deprecated statements offered. |
| Authenticated credential rebind v4 (scoped, `zkc:proof:rebind:v4`) | Same issuer-trust, issuer-identity, and authenticated-revocation checks as v3. The envelope MUST declare the scoped profile; `scope_id` MUST be non-zero, equal `presentationBinding.scopeId`, and (on the authenticated path) recompute from the verifier's identity per §5.9.4 rule 3; `old_presentation_pseudonym` MUST equal `presentationBinding.pseudonym`; `new_presentation_pseudonym` MUST differ; recompute `claim_binding = compute_claim_binding_3(old_presentation_pseudonym, new_presentation_pseudonym, credential_id, proofContext, timestamp)`; apply the optional `schemaIdHash` pin after authentication. |
| Authenticated credential rebind v5 (scoped, `zkc:proof:rebind:v5`) | Apply the v4 row unchanged. v5 is a draft, unactivated republication of the v4 statement under the beta.25 toolchain (§7.4.3). |

For the remaining-predicate v3-v9 rows, `compute_claim_binding_4(a, b, c,
flag, context, timestamp)` is exactly
`Poseidon3(Poseidon2(Poseidon4(DOMAIN_ZKC_CLAIM, a, b, c), flag ? 1 : 0),
context, timestamp)`. Implementations MUST reject non-boolean flag aliases
before hashing. `tests/vectors/zkc_core_vectors.json` pins both flag values.

The three aggregation identifiers (`zkc:proof:aggregation:v1`,
`zkc:proof:aggregate:v2`, and `zkc:proof:aggregate:v3`, §7.3) describe
envelope-level artifacts and have no individual step-4e contract. Step 6
checks v1 commitments and rejects v2 envelope aggregation blocks.
If one is presented as an individual proof entry, or if any known individual
proof type lacks a contract, verification MUST fail with
`UNBOUND_PROOF_TYPE`. Missing, non-object, malformed, internally inconsistent,
or mismatched request parameters produce `REQUIREMENTS_NOT_MET`. Missing or
undecodable public inputs produce `MALFORMED_PROOF`. Unknown proof identifiers
remain `UNKNOWN_PROOF_TYPE` at the earlier registry-resolution step.

**Closed request-parameter vocabulary (normative).** Each proof type's
request-binding contract accepts a closed set of parameter keys. The set is
the union of (a) every request parameter that the circuit's binding sidecar
references structurally with `param:` (the leading reference of a bound
field's `source`, a derived field's `from` list, or a free field's
`pinnedBy` rule), and (b) the documented request-only keys in the table
below. Request-only keys are keys a verifier or holder reads that are not
circuit public inputs: canonical code sets from which both parties derive a
bound root (§7.2c.5); filters the verifier reads but the circuit does not
bind (legacy accreditation `flagRequired`, the frozen rebind
`issuerIdHash`/`schemaIdHash` filters); and holder inputs that state no
verifier requirement (Merkle-path witness hints and the authenticated
rebind's `credentialId`). A verifier MUST reject a parameter object for a
proof type that contains any other key with `REQUIREMENTS_NOT_MET` on both
`verify` and `verifyAuthenticated`, and the error detail MUST name the
unknown key(s) and the proof type. A verifier that ignored such a key would
apply the default of the key it meant to send: for example, a misspelled
`flagrequired` silently dropped the accreditation institutional requirement
while the signed APR still carried the misspelling. A holder MUST refuse,
before proving, a request whose parameter object for a proof type contains a
key outside that proof type's set. A request that names secret material is
still refused first with `SECRET_IN_REQUEST` (§7.4.4), and a misplaced
canonical-set key keeps its canonical-set refusal. A successor identity takes
the sidecar part of its set from its own sidecar, so an additive generation
inherits no stale vocabulary. The table is keyed by circuit family (the
circuit name without its trailing `_vN` generation) and, for a circuit whose
sidecar publishes a `predicateTypes` map, by the proof-type meaning
(`zkc:proof:<meaning>:vN`). A family or meaning absent from the table has no
request-only keys.

| Circuit family | Meaning | Request-only keys |
|---|---|---|
| `zkc_kyc` | any | none |
| `zkc_community_kyc` | any | none |
| `zkc_selective_disclosure` | any | `layoutId` |
| `zkc_jurisdiction` | any | `jurisdictionCanonicalSet`, `membershipPathIndex`, `membershipSiblings`, `predecessorCode`, `predecessorPathIndex`, `predecessorSiblings`, `successorCode`, `successorPathIndex`, `successorSiblings` |
| `zkc_remaining_predicates` | `accreditation` | `flagRequired` |
| `zkc_remaining_predicates` | `source` | `pathIndex`, `siblings` |
| `zkc_remaining_predicates` | `tax` | `pathIndex`, `siblings` |
| `zkc_remaining_predicates` | `sanctions` | `canonicalSet`, `predecessorCode`, `predecessorPathIndex`, `predecessorSiblings`, `successorCode`, `successorPathIndex`, `successorSiblings` |
| `zkc_credential_rebind` | any | `issuerIdHash`, `schemaIdHash` |
| `zkc_credential_rebind_binding` | any | none |
| `zkc_credential_rebind_v2_binding` | any | none |
| `zkc_credential_rebind_auth` | any | `credentialId` |
| `zkc_aggregation` | any | none |

The witness-hint keys (`pathIndex`, `siblings`, `membership*`,
`predecessor*`, `successor*`) are holder inputs only: the verifier never
reads them, they are not authoritative when a canonical code set is present
(§7.2c.5), and they carry no requirement that a verifier could drop. The
accreditation `flagRequired` entry matters only for v1/v2, whose sidecars do
not bind it; from v3 the sidecar binds it. The authenticated rebind
`credentialId` selects the credential the holder migrates (§7.4.4: among
stored credentials carrying it, only those whose issuer the request trusts for
the rebind proof type; two such credentials are refused with
`AMBIGUOUS_CREDENTIAL`, never guessed between); no step-4e rule
compares it with the proof's free `credential_id` public input. A verifier
that receives it MUST emit the `UNBINDABLE_PARAMETER` warning, and a consumer
that needs a specific credential MUST compare `credential_id` itself.

The parameter table itself is closed too. Every key of `parameters` MUST be a
proof type the request lists, in the request's own spelling (on the
authenticated path, the spelling of the effective request that agrees with
the signed APR). A verifier MUST reject any other block with
`REQUIREMENTS_NOT_MET`, naming it, because no per-proof check reads it. A
holder MUST refuse such a request before proving. This mirrors the APR rule
that signed `parameters` keys equal `proofTypes`.

When a holder answers a requested identity under another identity (for
example `zkc:proof:source:v1` answered as `zkc:proof:source:v7` or `:v8`),
the closed set of the emitted identity governs the request, because that is
the vocabulary the verifier enforces. A `flagRequired: false` in a `source:v1`
request is therefore admitted. A holder that does not yet know the
presentation profile (for example while planning) MUST require every key to
be in the set of every identity it could emit.

A verifier MUST reject a proof type whose closed set cannot be derived (no
binding sidecar, or a malformed `param:` reference) with
`UNBOUND_PROOF_TYPE`. A holder MUST refuse a non-empty parameter block whose
emitted identity has no derivable set, including when its encoder or sidecar
documents are absent or ambiguous. It MUST NOT treat that block as
unconstrained.

**New structured error codes (verifier accountability).** Step 0 introduces `UNSIGNED_REQUEST` (the request is not a validly signed, unexpired, fresh APR) and `PURPOSE_MISMATCH` (a proof bound under a different declared purpose, caught before the existing `CONTEXT_MISMATCH` path). Both join the existing `STALE_PROOF` / `CONTEXT_MISMATCH` structured error family and the conformance runner (§9.2). They are *additive*: `STALE_PROOF`, `CONTEXT_MISMATCH`, and every other existing code retain their semantics, and proof-envelope compatibility is unchanged. The reference verifier implements step 0 as an additive `verify_authenticated(apr, envelope, request)` entrypoint, leaving the existing `verify(envelope, request)` path (and its codes) byte-for-byte unchanged for existing proofs and bundles.

**Request-binding error code.** `UNBOUND_PROOF_TYPE` means a known individual
proof type has no registered step-4e contract. It is distinct from
`UNKNOWN_PROOF_TYPE` (no registry circuit), `REQUIREMENTS_NOT_MET` (a known
contract whose request requirements cannot be resolved or do not match), and
`MALFORMED_PROOF` (public inputs cannot be decoded). Implementations MUST NOT
replace `UNBOUND_PROOF_TYPE` with silent acceptance or a permissive fallback.

**Credential-authentication error code.** `UNAUTHENTICATED_CREDENTIAL` means
the exchange names a proof identity that asserts credential continuity without
authenticating issuance or live revocation state — today the four contained
credential-rebind identities of §4.5. It is raised before backend verification
and before any request-binding check, on the unauthenticated and the
authenticated entry point alike, and it is independent of the trust policy and
of any request pin: backend proof validity MUST NOT be reported as credential
continuity for such an identity. Implementations MUST NOT downgrade it to a
warning or to a trust-policy decision.

### 6.3 Integration Patterns

```typescript
// Illustrative only. Each gate signs its demand as an Authenticated Proof
// Request (Safeguard 6, §1.4; §5.5) and verifies the answer on the
// authenticated path (§6.2 step 0). Its own trust policy pins its verifier
// key (§5.5). Each example uses one presentation profile, so its proof types
// and envelope version agree (§5.9, §6.1).
//
// Each gate retains the APR it signed, keyed by its own trusted session
// state, and verifies against that retained copy. It never takes the expected
// request from the message that carries the proof: a valid signature by the
// gate's key shows only that the gate once signed that request, not that it
// is the request for this operation. An APR that the gate signed for a weaker
// policy or for another session would otherwise be accepted here (§5.5
// reference authenticated-verification boundary; §6.2 step 0).

// Exchange integration. Three facts about one holder form a conjunction, so
// the request uses the scoped profile with the "session" scope policy
// (§5.9.2 rule 5). The answer is a scoped zkc:proof:v2 envelope that carries
// the presentation-family identities requested here.
class ExchangeComplianceGate {
  private verifier: ZKCVerifier;
  private verifierKey: VerifierSigningKey;
  // Demands this gate signed and has not yet settled, by deposit session.
  private pending: Map<DepositSessionId, AuthenticatedProofRequest>;

  // Step 1: build and sign the demand, retain it for this deposit session,
  // then send the APR to the holder.
  requestDepositProof(session: DepositSessionId): AuthenticatedProofRequest {
    const request: ProofRequest = {
      requirements: {
        proofTypes: ["zkc:proof:kyc:v2", "zkc:proof:source:v8", "zkc:proof:sanctions:v8"],
        // Every key must be in the proof type's closed parameter set
        // (§6.2.1), and every block must be for a listed proof type.
        parameters: {
          "zkc:proof:kyc:v2": {
            requiredLevel: 2,
            requiredAttributes: [true, false, false, false, false]
          },
          "zkc:proof:source:v8": { setRoot: this.acceptedSourcesRoot },
          "zkc:proof:sanctions:v8": {
            canonicalSet: this.blockedScreeningCodes,
            setRoot: this.blockedScreeningRoot
          }
        },
        // Reference age for an APR without the signed
        // verification-context extension (§5.5).
        maxProofAge: 3600,
        context: this.generateContext()   // fresh for every request (§5.9.1)
      },
      trustPolicy: this.trustPolicy,
      presentation: {
        profile: "zkc:presentation:scoped:v1",
        scopePolicy: "session",
        rotationEpochSeconds: 0
      }
    };
    const apr = signAPR(request, this.verifierKey);   // fresh nonce, issuedAt, expiresAt
    this.pending.set(session, apr);
    return apr;
  }

  // Step 2: verify the holder's envelope against the demand this gate
  // retained for this deposit session. The session comes from the gate's own
  // authenticated state, and the expected request from `pending`.
  async checkDeposit(
    session: DepositSessionId,
    userProof: ComplianceProofV2
  ): Promise<DepositDecision> {
    const expected = this.pending.get(session);
    if (expected === undefined) {
      return { allowed: false, reasons: [{ code: "UNSIGNED_REQUEST", message: "No pending demand for this session" }] };
    }
    const result = await this.verifier.verifyAuthenticated(expected, userProof, expected.request);
    if (result.valid) this.pending.delete(session);   // one accepted answer per demand
    return result.valid
      ? { allowed: true }
      : { allowed: false, reasons: result.errors };
  }
}

// DeFi protocol integration. One predicate under the default anonymous
// profile (§5.9): the APR carries no presentation block, and the answer is an
// anonymous zkc:proof:v2 envelope.
class ComplianceDeFiVault {
  private verifier: ZKCVerifier;
  private verifierKey: VerifierSigningKey;
  // Demands this vault signed and has not yet settled, by requesting address.
  private pending: Map<Address, AuthenticatedProofRequest>;

  // userAddress is authenticated by the vault's own means (for example a
  // signed session) before either method runs; ZKC does not authenticate it.
  requestAccessProof(userAddress: Address): AuthenticatedProofRequest {
    // accessRequest lists only "zkc:proof:sanctions:v8" and its parameters.
    const apr = signAPR(this.accessRequest(this.generateContext()), this.verifierKey);
    this.pending.set(userAddress, apr);
    return apr;
  }

  async checkAccess(
    userAddress: Address,
    userProof: ComplianceProofV2
  ): Promise<boolean> {
    // Verify off-chain, on the authenticated path, against the demand this
    // vault retained for this address.
    const apr = this.pending.get(userAddress);
    if (apr === undefined) return false;
    const result = await this.verifier.verifyAuthenticated(apr, userProof, apr.request);
    if (!result.valid) return false;
    this.pending.delete(userAddress);

    // Keep the decision in the vault's own access state. Do not publish the
    // proof, a hash of it, the APR, or its nonce. The APR nonce and signature
    // are a linkable tag that is never broadcast (§5.6). A proof hash next to
    // userAddress links that address to this presentation for anyone who
    // holds the proof or the holder's receipt.
    this.grantAccess(userAddress, apr.expiresAt);

    // LINKABILITY TRADE-OFF: if the vault also publishes an on-chain
    // allowlist entry for userAddress, that entry states that this address
    // passed a compliance check. That is a choice of the integration, not a
    // ZKC output (compare Appendix C.5).
    return true;
  }
}
```

---

## 7. Circuit Specifications

### 7.1 KYC Proof Circuit

```
KYC PROOF CIRCUIT
═════════════════

Public Inputs:
  - holderCommitment: Hash
  - claimBinding: Hash
  - proofContext: Hash
  - accumulatorRoot: Hash
  - accumulatorEpoch: u64
  - timestamp: Timestamp
  - currentEpoch: u64
  - issuerPublicKeyX: Bytes32
  - issuerPublicKeyY: Bytes32

Private Inputs:
  - credential: KYCCredential
  - credentialBindingKey: Scalar
  - accumulatorWitness: AccumulatorWitness
  - requiredLevel: u8
  - requiredAttributes: [bool; 5]

Constraints:
  1. BINDING VERIFICATION
     holderCommitment == H("zkc/binding", credentialBindingKey)
     credential.body.holderCommitment == holderCommitment

  2. SIGNATURE VERIFICATION
     verify_signature(credential, credential.signature)

  3. NON-REVOCATION
     verify_accumulator_membership(
       credential.body.credentialId,
       accumulatorWitness,
       accumulatorEpoch
     )

  4. LEVEL CHECK
     credential.body.claims.level >= requiredLevel

  5. ATTRIBUTE CHECK
     for i in 0..5:
       if requiredAttributes[i]:
         credential.body.claims.verifiedAttributes[i] == true

  6. EXPIRY CHECK
     credential.header.expiresAt > timestamp OR credential.header.expiresAt == null

  7. CLAIM BINDING
     claimBinding == H("zkc/claim", requiredLevel, requiredAttributes, proofContext, timestamp)

Parameters:
  - Proving system: Noir / UltraHonk (BN254)
  - Rows: ~2^17
  - Proving time: ~3s (native), ~5s (WASM)
  - Proof size: ~6 KB
  - Verification time: ~15ms
```

The `zkc_kyc` Noir package exposes the public inputs in the order shown above. The `zkc:proof:v1` envelope maps them into `publicInputs.{holder_commitment, claim_binding, proof_context, accumulator_root, accumulator_epoch, timestamp, current_epoch, issuer_public_key_x, issuer_public_key_y}`. The proof body remains the UltraHonk proof artifact; the envelope is an SDK or verifier serialization of the proof plus these public inputs.

### 7.2 Jurisdiction Proof Circuit

```
JURISDICTION PROOF CIRCUIT
══════════════════════════

Public Inputs:
  - holderCommitment: Hash
  - claimBinding: Hash
  - proofContext: Hash
  - jurisdictionSetRoot: Hash
  - membershipType: u8  (0 = inclusion, 1 = exclusion)
  - accumulatorRoot: Hash
  - accumulatorEpoch: u64
  - timestamp: Timestamp
  - currentEpoch: u64
  - issuerPublicKeyX: Bytes32
  - issuerPublicKeyY: Bytes32

Private Inputs:
  - credential: JurisdictionCredential
  - credentialBindingKey: Scalar
  - accumulatorWitness: AccumulatorWitness
  - jurisdictionMerklePath: MerklePath
  - requiredClaimType: u8

Constraints:
  1. BINDING VERIFICATION (same as KYC)

  2. SIGNATURE VERIFICATION (same as KYC)

  3. NON-REVOCATION (same as KYC)

  4. JURISDICTION SET MEMBERSHIP
     credential.body.claims.claimType == requiredClaimType
     // every set leaf is H(code, requiredClaimType) (§7.2c.4)
     if membershipType == 0:  // inclusion
       verify_merkle_membership(
         credential.body.claims.jurisdiction,
         jurisdictionMerklePath,
         jurisdictionSetRoot
       )
     else:  // exclusion
       verify_merkle_non_membership(
         credential.body.claims.jurisdiction,
         jurisdictionMerklePath,
         jurisdictionSetRoot
       )

  5. VALIDITY PERIOD
     credential.body.claims.validFrom <= timestamp
     credential.body.claims.validUntil >= timestamp

  6. CLAIM BINDING
     claimBinding == H("zkc/claim", jurisdictionSetRoot, membershipType, requiredClaimType, proofContext, timestamp)
     // = compute_claim_binding_3(jurisdictionSetRoot, membershipType, requiredClaimType,
     //                           proofContext, timestamp) (§6.2.1)

Parameters:
  - Rows: ~2^17
  - Proving time: ~3s
  - Proof size: ~6 KB
```

The initial `zkc_jurisdiction` Noir profile implements inclusion as Merkle membership in `jurisdictionSetRoot`. Its deprecated exclusion branch uses sorted neighbours from a blocked-set root and lacks the adjacency constraint required by §7.2c.7. The `zkc:proof:v1` envelope maps the public inputs into `publicInputs.{holder_commitment, claim_binding, proof_context, jurisdiction_set_root, membership_type, accumulator_root, accumulator_epoch, timestamp, current_epoch, issuer_public_key_x, issuer_public_key_y}`.

Jurisdiction circuits through v6 check the signed `u64` validity interval
inclusively at the proof timestamp. A `validUntil` of zero cannot satisfy
that check at a positive timestamp. Issuers MUST require a nonzero
`validUntil` greater than `validFrom` for jurisdiction credentials.

### 7.2a Remaining Predicate Profiles

The `zkc_remaining_predicates` and `_v2` Noir packages define the immutable
initial circuit profiles for the remaining ZKC-Standard/ZKC-Full predicates.
The additive `_v3` linkable and `_v4` anonymous/scoped packages bind the exact
`flagRequired` request bit without changing the issuer credential digest. The
published `_v5` linkable and `_v6` anonymous/scoped packages retain their
existing identities. Additive `_v7` linkable and `_v8` anonymous/scoped
packages retain that four-slot transcript and public ABI while combining the
raw-code, exact-adjacency, and validity-bound credential protections. The
additive `_v9` anonymous/scoped package (`zkc:proof:accreditation:v9`,
`:source:v9`, `:tax:v9`, `:sanctions:v9`; registry
`zkc-remaining-predicates@9.0.0`) republishes the `_v8` statement under the
Noir beta.25 / Barretenberg 5.0.0 toolchain. Its circuit source, public ABI,
predicate selectors, and binding contract are byte-identical to `_v8`; only the
package, encoder, proof types, and artifact identities are new. The entry is
`draft` and not activated, and a v9 identity is emitted only when a request
names it exactly. The predicates are:

- Accreditation: prove credential level is at least the requested level and, when requested, prove the institutional flag.
- Source-of-funds: prove the credential source code is a member of a verifier accepted-source Merkle root.
- Tax-residency: prove tax jurisdiction membership and a minimum tax year.
- Sanctions-clearance: prove sorted-neighbor non-membership against a blocked screening-list Merkle root, which is sound only over a canonically constructed set (§7.2c).

The published source-of-funds and tax-residency profiles accept a root and a
fixed path. Holders MUST apply the exact-code disclosure consent rule in
§7.2c.5 to both predicates. A canonical construction for these profiles would
need to specify full-field code encoding and padding semantics. A future
circuit or registry entry that changes the statement MUST use a new identity.

**Request and issuer-claim domains (normative).** Accreditation levels are
`u8`: issuers MUST sign `claim0` in `[0, 2^8)`, and verifiers MUST request
`required0` in that same domain. Tax years are `u64`: issuers MUST sign
`claim1` in `[0, 2^64)`, and verifiers MUST request `required1` in that same
domain. Sanctions screening codes require issuer-signed `claim0` in
`[0, 2^16)` (the canonical-set subject restrictions in §7.2c still apply).
Issuers MUST reject out-of-domain claims before signing; holders MUST refuse
such credentials before proving. All these integers are exact, with no
boolean, string, float, modular or truncation aliases.

The frozen v1-v9 circuits bind full Field request slots but compare truncated
`u8`/`u64`/`u16` casts. Those casts do **not** prove the original slots are
in range. Host request admission and issuer claim validation are therefore
required; the frozen statements alone do not establish these domain rules.
Any new successor remaining-predicate package MUST explicitly assert these
request and claim ranges before casting or comparing, with negative circuit
tests for accreditation `required_0 = 256` and `claim_0 = 256`, tax
`required_1 = 2^64` and `claim_1 = 2^64`, and sanctions `claim_0 = 65536`.
It MUST use a new source package and registry identity with complete artifact
pins, preserving every published predecessor unchanged (§4.2a).

The draft `zkc-remaining-predicates@10.0.0` range-only successor adds those
assertions under distinct accreditation/source/tax/sanctions `:v10` proof
types while retaining v9's anonymous/scoped public ABI. The entry is
unactivated and requires explicit identity selection and local draft-policy
acceptance; v7/v8 defaults and all frozen predecessors remain unchanged.

All ten generations share the same base constraints: holder binding, issuer signature verification, non-revocation, credential validity period, proof context binding, and claim binding. In v3-v10, the private `flag_required` value participates in the four-slot public claim binding and, on accreditation, gates the check of issuer-signed `claim_1`. V7-v10 authenticate `validFrom` in the issuer credential digest, require source/tax raw codes to be non-zero, and require sanctions neighbour indices to be consecutive. Existing v1 credentials remain usable only for historical verification; current proof generation requires the issuer-authenticated v2 credential schema. Each proof remains atomic; aggregation MUST preserve separate predicate consent.

These circuits and the code-space-bound v11 successor require
`validFrom <= timestamp`. A `validUntil` of zero explicitly means no expiry. A nonzero
`validUntil` is an inclusive upper bound on the proof timestamp. At issuance,
a finite `validUntil` MUST be greater than `validFrom`. Issuers MUST set a
nonzero `validUntil` whenever a credential is intended to expire. The
reference issuer requires the envelope's `expiresAt` to equal the signed
`validUntil` for issuable remaining-predicate schemas.

The v1-v6 circuit identities are immutable and deprecated (v1-v4: raw-code
padding and non-adjacent sanctions neighbours; v5/v6: the credential digest
omits `validFrom`). They remain available only for historical verification
under an explicit policy that accepts deprecated entries: a verifier MUST
reject these known unsafe identities on the authenticated path with
`DEPRECATED_PROOF_TYPE` unless its own policy lists `deprecated` among its
accepted review statuses. This requirement is independent of registry presence
or labels: an absent registry or an additional current-status listing cannot
reactivate a frozen unsafe identity. Unauthenticated historical verification
retains its `UNSIGNED_REQUEST` refusal. A signed APR naming a
deprecated identity is not that opt-in: an APR is fresh, so only a newly
generated — and therefore forgeable — proof can answer it. The same rule
applies to jurisdiction v1/v2 (§7.2c.7). A holder MUST resolve new linkable
remaining-predicate proofs to v7 and new anonymous/scoped proofs to v8; it
MUST NOT fall back to v1-v6 when a current entry is unavailable.

### 7.2b Issuer-Authoritative Selective Disclosure

The `zkc_selective_disclosure_v1` circuit proves holder binding, anonymous or scoped presentation binding, an issuer signature over the complete fixed-slot attribute credential, fresh non-revocation, exact positional disclosure, and a typed transcript bound to `proofContext` and `timestamp`.

Public Inputs:

```text
presentation_pseudonym, scope_id, claim_binding, proof_context,
accumulator_root, accumulator_epoch, timestamp, current_epoch,
issuer_public_key_x[32], issuer_public_key_y[32],
credential_attribute_count, disclosure_count,
disclosed_flags[8], disclosed_attributes[8]
```

The circuit MUST reject issuer-signature mismatch, noncanonical credential padding, disclosure outside the active count, public values that differ from their issuer-signed positions, nonzero hidden values, count/mask mismatch, expired or revoked credentials, stale accumulator state, and transcript or presentation mismatch. The `zkc_selective_disclosure_v2` circuit (`zkc:proof:selective_disclosure:v2`, registry `zkc-selective-disclosure@2.0.0`, draft and not activated) republishes this statement under the Noir beta.25 / Barretenberg 5.0.0 toolchain; its source, public ABI, binding contract, and in-circuit `zkc:proof:selective_disclosure:v1` transcript type are unchanged. A conforming verifier MUST require principal consent, enforce the versioned type-specific proof-entry schema without additional fields, and require the proof's accumulator epoch/root to exactly match an authenticated issuer root accepted under §2.4.1. In particular, metadata v1, an unsigned convenience field, a self-asserted metadata key, a malformed or stale v3 announcement, or a metadata/announcement mismatch is not an authenticated root; missing or downgraded root data is a fail-closed rejection. See `docs/zkc_selective_disclosure.md`.

For v1 and v2 proof identities, issuers MUST dedicate each exact signing key to a single legacy layout and publish its `attributeLayoutId` on the signing-key metadata. Verifiers MUST use a locally established layout pin for that key. Holders MUST compare the request layout with the credential's issuer-delivered or locally provisioned layout. Metadata discovery and a signed accumulator announcement do not establish legacy layout provenance. Implementations MUST refuse legacy disclosure when the issuer key has missing or conflicting layout provenance.

The draft `zkc_selective_disclosure_v3` successor (`zkc:proof:selective_disclosure:v3`, registry `zkc-selective-disclosure@3.0.0`) adds a public `layout_id` immediately before `credential_attribute_count`. Its `zkc:cred:attribute-set:v2` signature digest and v3 disclosure transcript both commit to that field. The verifier MUST require exact equality with the canonical nonzero field encoding in the request's `layoutId`. The remaining consent, position, holder-binding, issuer-trust, and non-revocation conditions apply to v3 as well.

### 7.2c Canonical Blocked-Set Construction and Root Distribution

This section is **normative** for jurisdiction exclusion and
sanctions-clearance blocked sets. It also defines the reference canonical
construction available to jurisdiction inclusion. The public API is exported
from `zkc_crypto`; its deterministic conformance vectors and implementation are
part of the repository's `PUBLIC_ALLOWLIST`.

Source-of-funds and tax-residency are not covered by this u16 protocol. Their
private codes are full `Field` values. In deprecated remaining-predicate
profiles v1-v4, raw code `0` aliases an empty padding leaf. Current v7/v8
profiles close that ambiguity by constraining the raw code to be non-zero
without narrowing the full field domain; for example, code `70000` remains
valid. They retain the direct request-root binding of §6.2. Applying this
builder to them would truncate their domain and is non-conforming.

#### 7.2c.1 Why construction and distribution are protocol requirements

The exclusion branches prove non-membership by exhibiting two blocked-set
leaves that contain a subject between them. A Merkle root commits to leaf
values and positions, but does not attest that the values were unique, sorted,
consecutive, or bounded by sentinels. A verifier that accepts an opaque root
cannot determine whether its tree has the structure required by the proof.

The verifier therefore MUST publish both the canonical code list and its
derived root in the signed Authenticated Proof Request (APR). The holder and
verifier MUST independently rebuild the same tree. A root literal by itself is
not evidence of canonical construction, and an exclusion request containing
only a root MUST be rejected. The verifier MUST compare the rebuilt root
directly with the proof public input `jurisdiction_set_root` or `set_root`;
recomputing only `claim_binding` is insufficient because the remaining-
predicate claim-binding preimage does not contain `set_root`.

The reference implementation is `python/zkc_crypto/canonical_set.py`.
`tests/vectors/canonical_set_vectors.json` and
`tests/vectors/validate_canonical_set_vectors.py` pin the construction,
positive witnesses, boundary behavior, and malformed-input refusals.

#### 7.2c.2 Modes and canonical procedure

The construction mode is mandatory:

- **Exclusion** is used by jurisdiction when `membershipType = 1` and always by
  sanctions clearance. It is sentinel-bracketed.
- **Inclusion** is used by jurisdiction when `membershipType = 0`. It is not
  sentinel-bracketed: otherwise the circuit's ordinary membership branch would
  make the sentinel codes provable members.

Given an array of codes and a mode, a conforming implementation MUST:

1. Reject a non-array input, a non-integer or boolean entry, a reserved or
   out-of-domain code, and an offline construction input longer than 65,534
   entries before deduplication.
2. Deduplicate repeated codes; duplicates are not otherwise an error.
3. Sort the member codes in ascending numeric order.
4. In exclusion mode only, prepend code `0` and append code `65535`.
5. Place the resulting leaves at consecutive indices beginning with index 0.
6. Encode every occupied leaf as specified by §7.2c.4.
7. Pad the rest of the depth-32 tree using §7.2c.3.

The construction is deterministic. Input ordering and repetition do not alter
the root. Inclusion and exclusion over the same member codes intentionally
produce different roots because only exclusion has sentinel leaves.

Empty arrays are valid. Empty exclusion produces the two sentinel leaves,
which bracket every valid subject. Empty inclusion occupies no leaves, has root
`zeroSubtree[32]`, and cannot yield a membership witness.

#### 7.2c.3 Code domain, sentinels, depth, and padding

Jurisdiction and sanctions-clearance codes are `u16`. The canonical domain is:

| Role | Code |
| --- | --- |
| Minimum exclusion sentinel | `0` |
| Valid member and subject codes | `1` .. `65534` |
| Maximum exclusion sentinel | `65535` |

Codes `0` and `65535` are reserved in both modes and MUST NOT be supplied as
members or subjects. Issuers MUST reject either value as a `jurisdictionCode`
or `screeningCode` before signing. A deployment needing either value MUST remap
its code space. Sentinels are encoded like other occupied leaves and serve as
structural brackets.

Trees are depth-32 Poseidon2 Merkle trees. A path index is consumed least-
significant-bit first, with bit `i` selecting left or right at tree level `i`.
Padding uses the recursive zero-subtree convention:

```text
zeroSubtree[0]     = 0
zeroSubtree[k + 1] = H(zeroSubtree[k], zeroSubtree[k])
```

An absent subtree of height `k` contributes `zeroSubtree[k]`, not a literal
zero except at height 0. Consequently, a one-member canonical tree is not the
same as a one-leaf tree whose 32 siblings are all literal zero.

For raw sanctions leaves, the minimum sentinel encodes to field element `0`,
the same value as an empty leaf. Implementations MUST use the occupied index,
not the leaf value alone, to identify the sentinel. Its fixed position at index
0 and the maximum sentinel after the last member preserve the bracket
invariant.

#### 7.2c.4 Predicate leaf encodings

| Predicate | Mode | Leaf encoding |
| --- | --- | --- |
| Jurisdiction | Inclusion or exclusion | `H(code, requiredClaimType)` |
| Sanctions clearance | Exclusion | `code` as a field element |

`requiredClaimType` MUST be an integer that fits in `u8` and is folded into
every occupied jurisdiction leaf, including exclusion sentinels. A jurisdiction
root is therefore scoped to one claim type. Sanctions roots have no leaf-level
domain separator and MUST NOT be reused for another predicate.

#### 7.2c.5 Authenticated request parameter contract

For jurisdiction exclusion, the signed APR parameters for the proof type MUST
contain all of:

```text
membershipType: 1
requiredClaimType: <u8 integer>
jurisdictionCanonicalSet: <array of canonical-domain codes>
jurisdictionSetRoot: <BN254 field integer>
```

For sanctions clearance, the signed APR parameters MUST contain:

```text
canonicalSet: <array of canonical-domain codes>
setRoot: <BN254 field integer>
```

The root fields distribute the verifier-selected root to the holder. The code
arrays make that root independently derivable. Both are required for exclusion
and MUST agree. The holder MUST verify the APR signature and effective-request
agreement, derive the root, compare it with the APR root, and build the
membership or adjacent-neighbour witness locally before proving. APR-supplied
path indices or sibling arrays are not authoritative and MUST NOT override the
locally derived witness.

An online APR code array MUST contain no more than 4,096 entries before
deduplication. This request-processing budget is intentionally tighter than the
65,534-code offline construction limit: a valid signature authenticates the
sender but does not make its computational workload safe. Holders and verifiers
MUST reject an oversized signed array before copying or hashing it. The
reference limit is exported as `CANONICAL_SET_MAX_REQUEST_CODES`.

The verifier MUST perform the same derivation from its authenticated request,
compare the result with the APR root, then compare that result directly with
the proof public input. A mismatch at any comparison is a rejection. A bare
root fallback, warning-only provenance, or use of an operator-supplied root
without derivation is non-conforming for exclusion.

For jurisdiction inclusion, when `jurisdictionCanonicalSet` is present,
`jurisdictionSetRoot` MUST equal the canonical inclusion root. The holder and
verifier MUST independently derive and compare the root. The holder MUST
derive its membership path from the list and ignore any supplied inclusion
path hints. The inclusion code array contains no sentinels. A malformed list
or mismatched root MUST cause refusal even with exact-code disclosure consent.

An inclusion request with only a root and a fixed path constrains the proof
to one leaf, including when the witness builder supplies the default path.
The holder MUST refuse such a request with `EXACT_MEMBER_CONSENT_REQUIRED`
before selecting a credential or proving, unless the holder has explicitly
consented to exact-code disclosure for that requested predicate. This rule
applies to authenticated, unauthenticated, agent, and delegated generation.
The reference SDK takes holder-local `exact_member_consents` keyed by requested
proof type, with the exact boolean `True` for each authorized predicate. APR
signatures and ordinary per-predicate consent do not grant this authorization.
The holder MUST log its use of the opt-in without recording claims or witness
data. Verifiers continue to compare the established root parameter to the
proof's public input for these requests.

`canonicalSet` is reserved for sanctions and `jurisdictionCanonicalSet` for
jurisdiction. Supplying either reserved key to source-of-funds, tax-residency,
accreditation, or another unsupported predicate, or supplying the wrong key to
a supported predicate, MUST be rejected rather than silently ignored.

#### 7.2c.6 Witness behavior and boundary cases

For inclusion, the holder MUST refuse to produce a membership witness for an
absent code. For exclusion, it MUST refuse to produce a non-membership witness
for a present code. A subject below the smallest member is bracketed by the
minimum sentinel and that member; a subject above the largest is bracketed by
the largest member and the maximum sentinel. The empty exclusion set uses the
two sentinels directly.

The reference builder returns consecutive predecessor and successor indices.
The verifier's canonical derivation guarantees that an honest holder receives
the same root and can produce its witness without APR-distributed paths.

#### 7.2c.7 Implementation status of the circuit adjacency constraint

The historical remaining-predicate v1-v4 and jurisdiction v1/v2 circuits
verify membership of both neighbours and the inequality
`predecessor < subject < successor`, but do **not** constrain
`successor_path_index == predecessor_path_index + 1`. Canonical construction
and derived-root binding prevent substitution of a different tree, but cannot
make those circuits inspect adjacency. A malicious prover can use two
non-adjacent leaves from the honest canonical tree to bracket a code that is
actually present.

The remaining-predicate v5-v11 sanctions branches and jurisdiction v3-v6
exclusion branches additionally constrain the successor index to equal the
predecessor index plus one. They are sound only when combined with every
canonical construction and authenticated-root obligation above. The
code-space-bound v11 and v6 branches use the typed leaves in §7.2d.
Implementations MUST NOT describe historical remaining-predicate v1-v4 or
jurisdiction v1/v2 exclusion proofs as sound against a malicious prover, and
a verifier MUST reject them with `DEPRECATED_PROOF_TYPE` unless its policy
explicitly accepts deprecated entries (§7.2a).

#### 7.2c.8 Implementer note (non-normative)

The external construction obligation is a consequence of proving
non-membership with sorted neighbours over a plain Merkle tree. An indexed
accumulator whose leaf commits to its successor could let the circuit attest
adjacency directly, at the cost of a different leaf format and update
procedure. Such a circuit is outside this version.

### 7.2d Issuer-bound code spaces for draft set predicates

The code-space-bound identities are `zkc:proof:jurisdiction:v6` with
`zkc:cred:jurisdiction:v2`, and `zkc:proof:source:v11`, `zkc:proof:tax:v11`,
and `zkc:proof:sanctions:v11` with their respective `zkc:cred:*:v3` schemas.
They are unactivated drafts and require explicit selection and local
review-status acceptance. An existing credential needs issuer reissuance
from verified claims to satisfy these identities.

#### 7.2d.1 Canonical integer encodings

| Field | Assigned values |
|---|---|
| `jurisdictionCode`, `taxResidencyCode` | The integer value of the assigned ISO 3166-1 numeric-3 country or territory code, using the exact pinned alpha-2 lookup. `BB` maps to 52, `IR` to 364, `DE` to 276, and `US` to 840. |
| `claimType` | `0` residency, `1` citizenship, `2` tax residency. |
| `verificationMethod` | `1` government ID, `2` utility bill, `3` tax return, `4` passport. |
| `sourceOfFundsCode` | `1` employment income, `2` business income, `3` investment returns, `4` inheritance, `5` gift, `6` sale of assets, `7` regulated exchange, `8` other verified. Code 8 requires an explicit verified classification. |
| `screeningCode` | The stable integer in `1..65534` assigned to the subject by the named screening registry. Exclusion sentinels are `0` and `65535`. |

The reference issuer MUST accept only exact assigned integers. The pinned
lookup in `python/zkc_crypto/code_spaces.py` supplies the country and
territory assignments and the manifests. It cites the
[UN Statistics Division table](https://unstats.un.org/unsd/methodology/m49/overview/)
for the source rows. ISO alpha-2 labels are inputs to lookup and never a
packed representation of the country code. The conformance vectors in
`tests/vectors/code_spaces_v1.json` pin the manifest IDs and sample mappings.

Each screening space identifies an exact list, registry authority, subject
matching rules, and an assigned-code universe covering both listed and
unlisted subjects in its supported population. A missing subject assignment
or an unresolved list entry MUST cause refusal. Code assignments are stable
and unique inside that registry. The reference ships two synthetic bounded
registries for conformance. A live registry requires a governed mapping
shared by issuers and verifiers. The proof attests exclusion from the exact
requested set under the committed mapping. Registry identity and the requested
root scope the proof to that population and set.

#### 7.2d.2 Manifest, issuer signature, and typed leaves

`codeSpaceId` is the canonical 32-byte lowercase `0x` field encoding of
`string_to_field("zkc:code-space:v1:" + JCS(manifest))` (nonzero BN254 scalar).
The manifest uses [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) with ASCII
strings and exact small integers. It identifies the predicate family and all
normative mappings. A changed mapping yields a new ID. Updates to blocked
members within one mapping yield a new set root. The public proof carries the
registry ID and keeps the credential's subject code private.

The issuer MUST declare the applicable IDs in `supportedSchemas[].codeSpaceIds`.
Issue and renew only when the provider-verified claims name an approved ID for
that schema and the associated code is assigned in that registry. With `S`
the field ID and `D` the predecessor credential digest, the successor signs
`Poseidon3(string_to_field(credentialType), S, D)`. The predecessor is the
jurisdiction v1 credential digest or the source, tax, and sanctions v2
credential digest, respectively. The successor passes the same public `S` to
the issuer-signature check and the set proof.

Let `L` be `string_to_field("zkc:set-leaf:" + kind + ":v1")`, where `kind`
is `jurisdiction`, `source`, `tax`, or `sanctions`. Jurisdiction uses
`Poseidon4(L, S, code, claimType)` and the other kinds use
`Poseidon3(L, S, code)`. Exclusion sentinels use the same leaf encoding.
Construct the tree from sorted distinct integer codes, with depth, adjacency,
and padding as in §7.2c. Inclusion excludes sentinel leaves. Jurisdiction
uses the requested inclusion or exclusion mode. Source and tax use inclusion,
and screening uses exclusion.

#### 7.2d.3 Authenticated request and proof binding

An Authenticated Proof Request MUST name the exact successor, `codeSpaceId`,
and both the set root and the canonical member list. Use `jurisdictionSetRoot`
and `jurisdictionCanonicalSet` for jurisdiction, and `setRoot` and
`canonicalSet` for the other three kinds. The holder confirms the signed
credential names that space and derives the witness from the list. The
verifier independently derives the root and compares it with the signed APR
root and the proof's public root. Both reject missing or unknown IDs, invalid
codes, cross-space claims, and mismatched roots. The existing 4,096-entry
online bound applies. A request whose set leaves only one possible code
requires explicit holder consent to exact-code disclosure.

Jurisdiction requires `membershipType` and `requiredClaimType` and may state
`requiredVerificationMethod` in `1..4`. The proof's public method selector is
zero for an omitted request key. For a present key the circuit requires the
issuer-signed method to match, and the verifier compares the public selector
to the APR. Tax uses `required1` as the optional exact `u64` minimum tax year
(default 0). `required0` and `flagRequired` are reserved at `0` and `false`.
For source and sanctions, `required1` is also reserved at `0`.

The verifier compares public `code_space_id` with `param:codeSpaceId` and
recomputes the statement binding. Let `B` be the predecessor claim binding
and `T = string_to_field("zkc:set-binding:" + kind + ":v1")`. Jurisdiction
uses `Poseidon4(T, S, B, requiredVerificationMethod)` (zero when omitted),
and the other three use `Poseidon3(T, S, B)`. The predecessor `B` comes from
the jurisdiction v5 or remaining-predicate v10 statement, with the same
request context and the new typed root in the jurisdiction root slot.

### 7.3 Aggregation Circuit

```
PROOF AGGREGATION CIRCUIT (simulated recursion)
═══════════════════════════════════════════════

Generations:
  zkc_aggregation     zkc:proof:aggregation:v1   linkable: holder handle holder_commitment
  zkc_aggregation_v2  zkc:proof:aggregate:v2     scoped: holder handle presentation_pseudonym
  zkc_aggregation_v3  zkc:proof:aggregate:v3     the v2 source, republished under beta.25
                                                 (draft, not activated)

Public Inputs (declaration order):
  - aggregation_commitment: Field
  - aggregated_claim_binding: Field
  - holder_commitment: Field                     (v1)
  - presentation_pseudonym: Field, scope_id: Field  (v2, v3)
  - context: Field
  - num_proofs: u32
  - input_proof_commitments: [Field; 8]

Private Inputs (8 fixed slots):
  - verification_keys: [[Field; 64]; 8]
  - proofs: [[Field; 64]; 8]
  - proof_public_inputs: [[Field; 12]; 8]
  - proof_types: [Field; 8]
  - proof_holder_commitments (v1) | proof_presentation_pseudonyms (v2, v3): [Field; 8]
  - consent_flags: [bool; 8]

Constraints (every generation; "handle" is holder_commitment or presentation_pseudonym):
  1. RANGE AND NON-ZERO
     1 <= num_proofs <= 8;  context != 0;  handle != 0
     v2, v3 only: scope_id != 0
  2. COMMITMENT CONSISTENCY (a hash, not a proof verification)
     for each active slot i < num_proofs:
       input_proof_commitments[i] == Poseidon4(chain(verification_keys[i]), chain(proofs[i]),
                                               chain(proof_public_inputs[i]), proof_types[i])
     for each inactive slot: input_proof_commitments[i] == 0
  3. HOLDER-HANDLE WITNESS EQUALITY
     v1:     proof_holder_commitments[i] == holder_commitment
     v2, v3: proof_presentation_pseudonyms[i] == presentation_pseudonym
             proof_public_inputs[i][0] == presentation_pseudonym
  4. CONSENT
     consent_flags[i] == true for each active slot
  5. AGGREGATION COMMITMENT AND CLAIM BINDING
     aggregation_commitment == aggregate_commitments(context, handle, num_proofs,
                                   input_proof_commitments, proof_types, consent_flags)
     aggregated_claim_binding == Poseidon2(aggregation_commitment, context)

Not constrained by any generation:
  - that an inner proof verifies: the circuit hashes the supplied verification key,
    proof fields, and public-input fields, and checks none of them
  - that the committed fields are an inner proof's real verification key, proof, or
    public inputs: their packing into slot fields is deployment-defined
  - v1: that an inner proof carries holder_commitment: proof_holder_commitments is a
    free private witness, unconnected to proof_public_inputs
  - v2, v3: an inner proof's scope_id or any public input other than element 0

Parameters:
  - Slots: 8 fixed; the circuit processes every slot whatever num_proofs is
  - Native recursive verification: not used
```

The `zkc_aggregation` packages implement simulated recursion. Their slot
commitments bind supplied representations of a verification key, proof bytes,
public inputs, and proof type. The circuits constrain each active consent flag
and derive `aggregated_claim_binding` from the commitment and context. These
constraints do not establish component proof validity, common holder identity,
or satisfaction of the request. In v1, holder-handle equality concerns a free
private witness that is independent of the committed component public inputs.

**Linkable envelopes.** The holder can attach a v1 aggregation block as an
additional commitment. A verifier MUST individually verify every covered
entry against the request and envelope holder binding (§6.2 step 4). The block
covers all envelope proof entries in order. If any entry is unrequested and
therefore skipped in step 4, the verifier MUST reject the aggregate with
`INVALID_AGGREGATION`. The reference verifier checks `inputProofCommitments`,
`aggregationCommitment`, and `aggregatedClaimBinding` by recomputing them
using the component entries, manifest-pinned verification-key hashes, and the
reference packing (`python/zkc_holder/aggregation.py`). It does not verify the
block's `proof` bytes. Shared holder binding comes from the individual checks.

**Anonymous and scoped envelopes.** The v2/v3 circuits require slot public-input
field 0 to equal the presentation pseudonym. Reference packing hashes the
entire canonical public-input JSON into field elements, so slot field 0 does
not carry the component pseudonym and the reference packing does not implement
that circuit input contract. The holder supports aggregation only in linkable
envelopes. A verifier MUST reject any structurally valid aggregation block in
a `zkc:proof:v2` envelope with `INVALID_AGGREGATION`, including blocks with
matching host-recomputed commitments. This covers both `zkc:proof:aggregate:v2`
and `zkc:proof:aggregate:v3`. The JSON envelope schemas are
`schemas/compliance-proof-v1.schema.json` and `schemas/compliance-proof-v2.schema.json`.

### 7.4 Authenticated Credential Rebind Circuits

This section specifies the additive, issuer-authenticated successors to the deprecated credential-rebind statements of §4.5. Design rationale is recorded in ADR 0004 (`docs/adr/0004-authenticated-credential-rebind.md`). Both successors prove, for one credential, that (a) the credential was created by a specific issuer for a specific holder commitment, schema, identifier, and validity window, (b) the credential is a live member of that issuer's non-revocation accumulator at a fresh epoch, (c) the prover controls the binding key behind that holder commitment, and (d) the prover controls the binding key behind a distinct new holder handle. Nothing about the credential is prover-chosen: every credential field in the statement is either public and compared by the verifier, or bound by the issuer's signature recomputed in-circuit.

#### 7.4.1 The `zkc:attestation:credential-rebind:v1` transcript

An issuer that permits a credential to be rebound signs a **rebind attestation** for it, at issuance time or later on the holder's request. The attestation is schema-agnostic: it binds the credential's identity rather than its schema-specific claims, so one circuit serves every credential schema.

```text
REBIND_ATTESTATION_TYPE = string_to_field("zkc:attestation:credential-rebind:v1")
issuerIdHash            = string_to_field(issuerId)
schemaIdHash            = string_to_field(schemaId)

header = Poseidon4(DOMAIN_ZKC_CLAIM, REBIND_ATTESTATION_TYPE, issuerIdHash, schemaIdHash)
body   = Poseidon4(holderCommitment, credentialId, validFrom, validUntil)
digest = Poseidon2(header, body)

signature = ECDSA_secp256k1_sign(issuerSigningKey, digest.to_be_bytes(32))
```

- `DOMAIN_ZKC_CLAIM` is the registered `zkc/claim` domain (§1.3); the explicit type field and fixed slot order make the transcript distinct from every credential digest of §3 and from the selective-disclosure transcript of §7.2b, so no signature over one can be replayed as another.
- `issuerId` and `schemaId` are the exact strings the issuer publishes in its metadata (§4.1); `holderCommitment` and `credentialId` are the credential's own; `validFrom` / `validUntil` are `u64` seconds with `validUntil == 0` meaning no expiry and otherwise `validUntil > validFrom`.
- The signing key is an issuer signing key published in issuer metadata, with the same `ECDSA_SECP256K1` profile as credential signatures (§2.3). Verifiers trust it by exact key, never by registry membership (Safeguard 1).
- Issuers MUST NOT sign a rebind attestation for a credential they did not issue, and MUST NOT include any new-holder value in it: the attestation names only the holder the credential is currently bound to, so issuing it reveals nothing about a future rebind and does not create an old-to-new mapping (§4.5 audit-mapping rules are unaffected).
- An issuer MUST sign only the exact `(issuerId, schemaId, holderCommitment, credentialId)` tuple it recorded when it issued or renewed the credential, and only while that credential is currently active: a live member of its accumulator, neither revoked nor superseded by renewal, and not expired. The window MUST NOT exceed the credential's own validity: `validFrom` is the credential's own start (0 when it has none), and `validUntil` is the earlier of its claimed `validUntil` (when non-zero) and `expiresAt − 1` (when `expiresAt` is non-zero), because the attestation window end is inclusive while credential expiry is exclusive. `validUntil == 0` is permitted only when the credential itself has no expiry. The signing key MUST be within its published validity window at signing time. Renewal MUST NOT revive an expired credential: an expired credential needs fresh subject verification before a new credential or attestation is issued for it.
- A later, holder-requested attestation MUST name only the `credentialId`. The issuer MUST derive the schema, holder commitment, and window from its own issuance record, and MUST reject a request that supplies any of them. It MUST serve only the authenticated session that owns the credential's issuance lineage, never an identity asserted in the request body. Unknown credentials, foreign credentials, revoked or superseded credentials, expired credentials, and expired signing keys MUST all fail closed. The reference `BaseIssuerAdapter.sign_rebind_attestation({"credentialId": …})` implements these rules.

The credential envelope (§4.3) carries the attestation as an additive `rebindAttestation` member of `credential`:

```jsonc
"rebindAttestation": {
  "version": "zkc:attestation:credential-rebind:v1",
  "schemaId": "zkc:cred:kyc:v1",
  "validFrom": 1000,
  "validUntil": 2000000,
  "signature": "0x…64 bytes…"
}
```

`issuerId`, `holderCommitment`, and `credentialId` are taken from the enclosing credential, so the attestation cannot name a different credential than the one it travels with.

#### 7.4.2 `zkc:proof:credential_rebind:v3` — linkable profile (`zkc_credential_rebind_auth`)

```
AUTHENTICATED CREDENTIAL REBIND CIRCUIT (linkable)
═══════════════════════════════════════════════════

Public Inputs (declaration order; 75 field elements):
  0  old_holder_commitment: Field
  1  new_holder_commitment: Field
  2  credential_id: Field
  3  issuer_id_hash: Field
  4  schema_id_hash: Field
  5  proof_context: Field
  6  timestamp: u64
  7  claim_binding: Field
  8  accumulator_root: Field
  9  accumulator_epoch: u64
  10 current_epoch: u64
  11 issuer_public_key_x: [u8; 32]
  12 issuer_public_key_y: [u8; 32]

Private Inputs:
  old_credential_binding_key: Field
  new_credential_binding_key: Field
  credential_valid_from: u64
  credential_valid_until: u64
  issuer_signature: [u8; 64]
  nonrevocation_siblings: [Field; 32]
  nonrevocation_path_index: Field
  statement_domain: Field

Constraints:
  1. STATEMENT IDENTITY
     statement_domain == string_to_field("zkc:proof:credential_rebind:v3")
  2. HOLDER CONTROL (old and new)
     old_holder_commitment == H("zkc/binding", old_credential_binding_key)
     new_holder_commitment == H("zkc/binding", new_credential_binding_key)
     old_holder_commitment != new_holder_commitment
  3. ISSUER AUTHENTICATION (recomputed transcript, no digest input)
     digest = rebind_attestation_digest(issuer_id_hash, schema_id_hash,
                                        old_holder_commitment, credential_id,
                                        credential_valid_from, credential_valid_until)
     verify_signature_secp256k1(issuer_public_key_x, issuer_public_key_y,
                                issuer_signature, digest.to_be_bytes())
  4. NON-REVOCATION (same credential_id as the transcript)
     verify_accumulator_membership(credential_id, nonrevocation_path_index,
                                   nonrevocation_siblings, accumulator_root)
     current_epoch >= accumulator_epoch
     current_epoch - accumulator_epoch <= MAX_EPOCH_LAG
  5. VALIDITY
     credential_valid_from <= timestamp
     credential_valid_until == 0 OR credential_valid_until >= timestamp
     timestamp != 0
  6. CONTEXT AND CLAIM BINDING
     proof_context != 0
     claim_binding == compute_claim_binding_3(old_holder_commitment, new_holder_commitment,
                                              credential_id, proof_context, timestamp)
```

The proof is carried in a `zkc:proof:v1` envelope whose `holderBinding.commitment` MUST equal `old_holder_commitment` (the rebind is presented under the holder's current identity).

#### 7.4.3 `zkc:proof:rebind:v4` — scoped profile (`zkc_credential_rebind_auth_v2`)

```
AUTHENTICATED CREDENTIAL REBIND CIRCUIT (scoped)
═════════════════════════════════════════════════

Public Inputs (declaration order; 76 field elements):
  0  old_presentation_pseudonym: Field
  1  new_presentation_pseudonym: Field
  2  scope_id: Field
  3  credential_id: Field
  4  issuer_id_hash: Field
  5  schema_id_hash: Field
  6  proof_context: Field
  7  timestamp: u64
  8  claim_binding: Field
  9  accumulator_root: Field
  10 accumulator_epoch: u64
  11 current_epoch: u64
  12 issuer_public_key_x: [u8; 32]
  13 issuer_public_key_y: [u8; 32]

Private Inputs:
  old_holder_commitment: Field
  new_holder_commitment: Field
  old_credential_binding_key: Field
  new_credential_binding_key: Field
  credential_valid_from: u64
  credential_valid_until: u64
  issuer_signature: [u8; 64]
  nonrevocation_siblings: [Field; 32]
  nonrevocation_path_index: Field
  statement_domain: Field

Constraints:
  1. STATEMENT IDENTITY
     statement_domain == string_to_field("zkc:proof:rebind:v4")
  2. SCOPED PRESENTATION (no anonymous rebind)
     scope_id != 0
     old_presentation_pseudonym == H("zkc/presentation-scope:v1", old_credential_binding_key, scope_id)
     new_presentation_pseudonym == H("zkc/presentation-scope:v1", new_credential_binding_key, scope_id)
     old_presentation_pseudonym != new_presentation_pseudonym
  3. HOLDER CONTROL over the (private) commitments — as 7.4.2 constraint 2
  4. ISSUER AUTHENTICATION — as 7.4.2 constraint 3, over the private old_holder_commitment
  5. NON-REVOCATION — as 7.4.2 constraint 4
  6. VALIDITY — as 7.4.2 constraint 5
  7. CONTEXT AND CLAIM BINDING
     proof_context != 0
     claim_binding == compute_claim_binding_3(old_presentation_pseudonym, new_presentation_pseudonym,
                                              credential_id, proof_context, timestamp)
```

The proof is carried in a scoped `zkc:proof:v2` envelope whose `presentationBinding.pseudonym` MUST equal `old_presentation_pseudonym` and whose `presentationBinding.scopeId` MUST equal `scope_id` (§5.9.4 rules 2–4).

`zkc:proof:rebind:v5` (`zkc_credential_rebind_auth_v3`, registry `zkc-credential-rebind@7.0.0`) republishes this scoped statement under the Noir beta.25 / Barretenberg 5.0.0 toolchain. Its public inputs, constraints, and binding contract equal `zkc:proof:rebind:v4`, and its in-circuit statement domain stays `string_to_field("zkc:proof:rebind:v4")`; its source differs only in a test diagnostic. The entry is draft and not activated, and a holder emits it only when a request names it exactly.

#### 7.4.4 Holder rules

- Credential identifiers are unique only within their issuer, so the `credentialId` parameter can match stored credentials from several issuers. A holder MUST consider only those whose issuer the request's trust policy trusts for the rebind proof type, and MUST refuse before proving when more than one remains (the reference SDK raises `AmbiguousCredentialError`, `AMBIGUOUS_CREDENTIAL`); it MUST NOT choose between them.
- A holder MUST build the witness only from a stored credential that carries a `rebindAttestation`, and MUST verify the attestation signature locally against the trust policy's key for the credential's issuer before proving. Missing, zero, malformed (wrong length or non-canonical), mismatched (different issuer, schema, holder, or identifier), expired (validity window excludes the request timestamp), stale (accumulator witness older than the lag bound and not refreshable), or revoked material MUST fail closed before any proof is generated; the reference SDK raises `ConstraintViolationError` / `StaleWitnessError` and never copies unauthenticated credential-object fields into the witness.
- **The new secret travels only through a holder-local channel.** The new binding key (or the fresh master seed it derives from) is the holder's next root secret: anyone who learns it computes the holder's pseudonyms at every verifier and acts as the holder. It MUST be generated and supplied locally (the reference SDK's `RebindSecret`, passed as `ProofRequest.rebind_secret`) and MUST NOT appear in request `parameters`, an APR, a negotiation request, a verifier policy, a Disclosure Receipt, a `VerificationRequest`, an audit bundle, a log, an exception message, or a `repr`. Request parameters are verifier-chosen and, on the authenticated path, verifier-signed and retained (§5.5): a secret carried there would be disclosed to the verifier, and a malicious verifier could choose it and rebind the holder to a commitment it controls. A holder MUST therefore refuse, before proving, any request, APR, negotiation request, or verifier policy that names a secret parameter (e.g. `newMasterSeed`, `newCredentialBindingKey`); the reference SDK raises `SecretInRequestError` (`SECRET_IN_REQUEST`) with a value-free diagnostic. The rebind request names only the credential to migrate (`credentialId`); the proof itself publishes the new holder handle.
- Presentation follows §5.9: the linkable profile yields `zkc:proof:credential_rebind:v3`; the scoped profile yields `zkc:proof:rebind:v4`; the anonymous profile has no rebind statement and MUST be refused.
- **No downgrade.** A request MUST name a successor identity explicitly. The deprecated identities of §4.5 MUST NOT be resolved, negotiated, or emitted, and a successor request MUST NOT be silently satisfied by a deprecated statement or vice versa.

#### 7.4.5 Verifier rules

The successor rows of the §6.2 type-specific table are normative. In particular a verifier MUST require, for the proof's public issuer key, an exact trust-policy match that is trusted for the proof type; MUST require `issuer_id_hash == string_to_field(issuerId)` of the matched issuer; MUST hold an **authenticated** accumulator state (§2.4, metadata v2 signed announcement chain) for that issuer and reject a proof whose `current_epoch` differs from its own view, whose `accumulator_epoch` is ahead of that view or older than the tighter of the policy and announcement lag bounds, or whose `accumulator_root` differs from the recorded root for that epoch; and MUST apply the optional `schemaIdHash` request pin only after these checks. The per-field contract is machine-readable in `schemas/public-input-bindings/zkc_credential_rebind_auth{,_v2,_v3}.json`, where `issuer_id_hash` is **bound** (compared against the verifier's own matched issuer identifier) rather than an optional filter. A prover-controlled `current_epoch` or `accumulator_root` is never revocation authentication, and an Authenticated Proof Request never substitutes for issuer authentication. `verify()` and `verify_authenticated()` MUST apply identical semantics, and MUST apply them to every successor whichever envelope version carries it: `zkc:proof:credential_rebind:v3` is admissible only in a `zkc:proof:v1` envelope and `zkc:proof:rebind:v4` / `zkc:proof:rebind:v5` only in a scoped `zkc:proof:v2` envelope, and a misplaced successor is `PROFILE_MISMATCH` while still being checked against these rules (§5.9.4).

#### 7.4.6 Migration, recovery, privacy, and vectors

- **Continuity, not migration.** An accepted rebind proves key continuity for one credential at one verifier; it is neither exclusive nor one-time, and the credential remains bound to the old holder commitment. Real migration is issuer re-issuance to the new commitment. Verifier-side consequences are normative in §7.4.7.
- **Existing credentials.** An issuer MAY emit the rebind attestation for an already-issued credential on request (representation-only: no credential field, digest, or witness changes). Credentials without an attestation cannot be rebound through this mechanism and MUST NOT be rebound through the deprecated one.
- **Issuer-assisted recovery.** The attestation does not enable recovery of a credential whose old binding key is lost: constraint 2 requires the old key. Recovery is re-issuance (§4.3), and any issuer-retained mapping remains subject to §4.5.
- **Context binding and expiry.** `proof_context` and `timestamp` are inside the claim binding; the credential validity window is issuer-signed; envelope freshness is verified per §6.2 steps 1–2.
- **Privacy.** Every rebind discloses an old-to-new link to its recipient (§4.5): the linkable profile reveals both holder commitments, the scoped profile both pseudonyms; both reveal `credential_id`, `issuer_id_hash`, `schema_id_hash`, the issuer key, and the accumulator root/epochs, as every issuer-authenticated predicate reveals its issuer key and accumulator state. The public field set matches the deprecated statements, but its meaning is **widened**: `credential_id` is now issuer-authenticated rather than a prover-chosen witness, so it is a reliable cross-scope and cross-verifier handle. A verifier seeing one `credential_id` in rebinds under different scopes links them, and the issuer that assigned it can map it back to the subject: issuer-verifier collusion de-pseudonymizes a scoped rebind. Holders SHOULD rebind only toward verifiers they accept learning the link. The §5.9.5 determinism invariant holds: `claim_binding` retains `proof_context` and `timestamp`.
- **Vectors.** `tests/vectors/zkc_core_vectors.json` `credential_rebind_attestation_v1` pins the transcript type field, issuer/schema hashes, holder commitments, digest, the TEST-ONLY issuer signature, both statement domains, the scoped pseudonyms, and both claim bindings; conformance MUST additionally cover an accepted live credential and rejection of fabricated, zero-signature, tampered-field, expired, revoked, stale/future-epoch, untrusted-key, wrong-scope, relabelled, and deprecated-identity cases for both profiles (§9.2).

#### 7.4.7 Verifier state rules for accepted rebinds

Nothing in the rebind statements makes a rebind exclusive or one-time: the
circuits carry no nullifier, and the attestation binds only the old holder. One
old key therefore yields accepted rebinds to any number of new keys (credential
fan-out), and a thief holding a compromised old key can race the owner. A
verifier that relies on an accepted rebind for anything beyond the single
presentation MUST keep per-verifier continuity state with these rules (the
reference implementation is `zkc_verifier.RebindLedger`):

1. **One-time per credential.** At most one continuity claim is honoured per
   `(issuerIdHash, credentialId)` at the verifier, across both statements and
   every scope — otherwise a presenter could dodge a conflict by choosing a
   fresh scope (on the unauthenticated path the scope is presenter-chosen) or
   the other statement. An identical replay of an honoured claim is
   idempotent. A verifier with rotating scopes therefore honours one rebind
   per credential in total; renewed continuity after rotation is issuer
   re-issuance.
2. **Retire the old handle.** After honouring `old -> new` for a credential,
   the verifier MUST NOT treat `old` as that credential's holder any longer.
3. **Conflict freezes.** A second, different claim for the same credential
   MUST NOT move continuity to either new handle. The verifier freezes the
   credential's continuity and treats it as a possible old-key compromise: it
   cannot distinguish owner from thief, so resolution is issuer-side —
   revoke the credential and re-issue it to the intended holder commitment.
4. Only claims the verifier itself checked are recorded: proof entries that
   answer a proof type of the request it verified, in an envelope it
   accepted. An unrequested entry is skipped by verification (an
   over-disclosure warning only), so recording it would let a presenter
   attach a forged claim to any valid envelope. The state adds exclusivity,
   never authentication.

These rules give per-verifier exclusivity from the public `credential_id`
alone. A successor statement with a nullifier
`H(domain, old_cbk, credentialId[, scopeId])` was considered and is **not**
adopted: it would give the same per-verifier (or per-scope) exclusivity, but it
cannot resolve an old-key compromise race either (the first prover wins
whichever party it is), and a cross-verifier nullifier would add a stable
linking handle. Issuers remain the only party able to resolve a conflict.

A scoped request that names the linkable spelling
`zkc:proof:credential_rebind:v3` is answered by the holder with the scoped
statement `zkc:proof:rebind:v4`; a verifier comparing the request with its
Authenticated Proof Request (§5.5) MUST accept that answer for that position:
rebind has no anonymous statement, so the scoped spelling is resolved under the
scoped profile (§5.9) rather than the anonymous one.

---

## 8. Security Considerations

### 8.1 Cryptographic Assumptions

| Assumption | Consequence if Broken |
|------------|----------------------|
| Poseidon2 preimage resistance (BN254, AFP-KDC v1.0.2 parameters, §1.3) | Credential binding key recovery: `cbk` from `holderCommitment = H("zkc/binding", cbk)` or from a scoped `presentationPseudonym` (§2.1, §5.9.1) |
| Poseidon2 collision resistance | Credential forgery: one issuer signature over a colliding credential or rebind-attestation digest covers different claims (§7.4.1); claim-binding collisions; forged Merkle roots for verifier sets |
| ECDSA secp256k1 unforgeability (the mandatory issuer-signature profile, §2.3) | Credential and rebind-attestation signature forgery (§7.4.1); forged epoch announcements (§2.4.1), which bypass revocation; forged APRs and receipts where they select `ECDSA_SECP256K1` (§5.5, §5.6) |
| ZK proving system soundness (UltraHonk/Barretenberg) | Invalid proofs accepted if broken |
| ZK proving system zero knowledge | Private witness values (credential claims, `cbk`) leak from proofs |
| Poseidon2 Merkle accumulator (Poseidon2 collision resistance), together with the verifier's recorded-root check (§2.4, §6.2 step 4c) | Revocation bypass: a revoked `credentialId` proves membership |
| SHA-256 collision resistance (host transcripts) | Epoch-announcement signing digest and predecessor-hash collisions (§2.4.1); delegation-token digest collisions (§5.4) |
| HMAC-SHA512 as a PRF keyed by the 32 master-seed bytes | Receipt and audit-authorization keys become predictable or linkable across verifiers, scopes, or auditors (§5.6.1) |
| BLAKE2b-512 collision resistance after reduction into the BN254 scalar field (reference host hash-to-field: `derive_domain`, `string_to_field`, and the native `verifierIdentity` / `scopeId` derivations of §5.9.1) | Two identifier strings (issuer, schema, statement-domain, or scope-policy identifiers, §7.4.1) or two verifier keys map to one field element, so a signature or proof bound to one is accepted for the other; two domain tags collide; two verifiers or scopes share a `scopeId` and therefore a pseudonym |

BLS and Schnorr are metadata-only signature schemes (§2.3): no conformance circuit implements them, and a verifier rejects them without an auditable circuit implementation. This profile therefore assumes nothing about them. APRs and receipts that select `Ed25519` (§5.5, §5.6) additionally rely on Ed25519 unforgeability.

### 8.2 Privacy Properties

| Property | Guarantee |
|----------|-----------|
| Credential binding pseudonymity | `holderCommitment = H("zkc/binding", cbk)` hides the holder's seed and real-world identity from the verifier, but it is a stable, deterministic, cross-verifier-linkable pseudonymous anchor, not an unlinkability mechanism. The v2 anonymous profile removes the linkable anchor from default presentations entirely (see §5.9); a scoped presentation exposes only a scope-exclusive `presentationPseudonym`. |
| Seed-path unlinkability | The ZKA value-address and ZKC credential-commitment derive along separate KDC A.6 paths and are unlinkable without the seed. This is not cross-verifier multi-show unlinkability. |
| Issuer privacy | **Not provided by the current circuits.** The issuer public key is a public input that the verifier checks against its trust policy, so the verifier learns which issuer signed the credential. Hiding the specific issuer within a trusted set needs issuer-set membership proofs, which are future work (metadata-leakage threat model M6). |
| Claim privacy | Only requested claims are proven, others hidden |
| Temporal privacy | Credential issuance date hidden |

**Known limitation / open item.** This equality-linkability limitation applies to **v1/linkable envelopes** (`zkc:presentation:linkable:v1`): two presentations of the same credential that expose the same `holderCommitment` are linkable by equality, including by colluding verifiers. Which presentation profile governs a given presentation now determines the exposure (§5.9): the default anonymous profile exposes no holder-derived handle (pseudonym and scope are `0`), a scoped presentation exposes only a scope-exclusive `presentationPseudonym`, and the stable `holderCommitment` is exposed **only** under the explicitly consented linkable profile. Genuine cross-verifier multi-show unlinkability is thus a matter of profile choice; the accepted design direction and its ladder are recorded in `docs/adr/0001-multi-show-unlinkable-presentations.md`.

### 8.3 Attack Mitigations

| Attack | Launch mitigation and residual risk |
|--------|-------------------------------------|
| Credential sharing | Every proof needs the credential binding key `cbk`. `cbk` derives from the master seed along its own KDC path, not from the spending key (§2.1), so sharing it does not hand over spending authority. The deterrent is what `cbk` itself gives away: its holder can compute the holder's commitment and the holder's pseudonym in every scope, and can prove any credential bound to that commitment that it also obtains (§5.9.1, §7.4.4). This is a **partial launch mitigation**: a holder who accepts that cost can still share `cbk` or prove on another party's behalf, and ZKC cannot detect it. |
| Proof replay | Context binding and timestamps. |
| Issuer collusion | Verifier-controlled trust policies. |
| Accumulator stalling | Epoch freshness requirements reject an announcement whose freshness time (signed `announcedAt` or a liveness statement that names it, §2.4.2) or epoch lag is outside local policy. A quiet, honest issuer keeps its head fresh with liveness statements, so verifiers need no wide age limit; an issuer that stops attesting goes stale, and no root of a stalled view is served more than `A + S` seconds after the issuer last attested it. This is a **partial launch mitigation**: a verifier cannot prove that an issuer has omitted a newer state that the verifier has never observed. |
| Announcement omission | Historical backfill and fail-closed gap handling expose an omitted intermediate epoch to a verifier that later receives a successor. This is a **partial launch mitigation**: a party kept on an internally consistent prefix cannot distinguish omission from an idle issuer without an independent observation. |
| Announcement replay | The signed timestamp, monotonic epoch, and persisted local checkpoint reject an older announcement after a newer one has been accepted. A replayed liveness statement extends a head's freshness only up to its own signed `issuedAt`. Cold start still depends on freshness policy and cannot establish that no fresher view exists elsewhere. |
| Revocation split view / issuer equivocation | A pinned signing key prevents third-party substitution, and the complete predecessor-announcement commitment makes a conflicting successor detectable once compared with a verifier's persisted checkpoint. This is a **partial launch mitigation**, not global consistency: a malicious issuer can sign and serve two individually valid histories to isolated parties. The conflicting signed announcements are evidence of equivocation only when the views meet through direct comparison, monitoring, or gossip. |
| Timing correlation | Randomized proof generation. |
| Rebind under a compromised old key / credential fan-out | An accepted rebind is a continuity claim, not exclusive or one-time (§4.5, §7.4.6): a thief holding the old binding key can rebind the credential to its own key, racing the owner, and one old key can fan a credential out to many keys. Verifiers MUST apply the §7.4.7 state rules (one-time per credential, retire the old handle, freeze on conflict). Response to a suspected compromise: the issuer revokes the credential and re-issues it to the owner's new commitment; revocation is effective only after the accumulator lag window. |

These guarantees are deliberately distinct. Signature verification establishes **third-party substitution resistance**; predecessor and checkpoint comparison provide **locally observed fork detection**; neither supplies **global split-view detection**. A verifier MUST NOT infer that its valid local chain is the issuer's only chain.

Post-launch work specifies a per-issuer CT-v2-style append-only revocation log. Log inclusion and consistency proofs can establish membership and consistency within the view a log serves, but consistency proofs alone do not reveal two isolated, internally consistent views. Global split-view detection therefore also requires independent monitors and cross-party checkpoint gossip.

The rows above are normative launch requirements. The reference issuer now publishes signed v3 metadata, and its durable service variant persists the ordered announcement history. The verifier and private witness provider now enforce pre-pinned key and accumulator ids, exact metadata equality, signed freshness, bounded ordered backfill with resumable catch-up, durable checkpoints, replay/linkage rejection, and signed conflict evidence retention. End-to-end launch conformance additionally requires passing the authenticated-revocation conformance suite.

### 8.4 Metadata Leakage (Non-Normative Pointer)

The tables above address cryptographic attacks. Metadata that leaks AROUND the cryptography — predicate type, issuer choice, proof timing, verifier endpoints, credential-freshness queries, registry lookups — is analyzed systematically (per flow × observer, with implemented mitigations and honest residual risk) in the reference threat model: [`docs/zkc_metadata_leakage_threat_model.md`](zkc_metadata_leakage_threat_model.md). Implemented reference mitigations include local-copy registry reads, credential-anonymous witness refresh (`zkc:epoch-delta-request:v1`), and constant-shape refusals; the reference test suite pins these behaviors (`tests/python/test_metadata_leakage.py`). This section is a pointer only — it changes no envelope, circuit, or verification rule.

---

## 9. Conformance

### 9.1 Conformance Levels

Core conformance is a strictly monotonic ladder; each level is a superset of the one below it. **ZKC-Full is the highest core level.**

| Level | Requirements |
|-------|--------------|
| **ZKC-Core** | KYC proofs, basic verification |
| **ZKC-Standard** | Core + jurisdiction, accreditation, source |
| **ZKC-Full** | Standard + tax, sanctions, and linkable v1 aggregation (§7.3) |

**ZKC-Agent** is an orthogonal extension profile — *not* a level above ZKC-Full. It denotes a deployment that exposes the agent API (§5.4) for automated compliance on top of any claimed core level (typically ZKC-Full). Tooling MUST NOT infer an ordering in which ZKC-Agent ranks above ZKC-Full, and MUST treat the level name as ZKC-namespaced rather than inferring rank from any other protocol's conformance taxonomy.

### 9.2 Test Vectors

Canonical ZKC core test vectors are published in `tests/vectors/zkc_core_vectors.json`. Implementations MUST treat these as golden vectors for the BN254/Poseidon2 profile: domain separators, Poseidon2 KATs, KDC A.6 credential binding derivation, holder commitment derivation, claim binding examples, and the purpose-bound context KATs (`purposeTag` derivation and the `purpose-bound` context preimage, §2.2) MUST match byte-for-byte.

The same vector file contains the `selective_disclosure_v1` issuer-digest and typed-transcript KATs plus the required negative-case inventory, and the `credential_rebind_attestation_v1` KATs for the issuer-authenticated rebind transcript, statement domains, scoped pseudonyms, and claim bindings of §7.4. The transcript uses the AFP-KDC v1.0.3 current registry's `zkc/claim` operational domain with an explicit `zkc:proof:selective_disclosure:v1` type field; the domain field and Poseidon2 profile remain immutable AFP-KDC v1.0.2 crypto evidence.

Authenticated revocation launch conformance is pinned by `tests/vectors/revocation_equivocation_v1.json` and the network-independent `conformance/run_revocation.py` runner. The public deterministic vectors cover the exact signed transcript and complete predecessor hash, every signed-field tamper, the rejected high-s twin of a valid signature, a same-transcript re-signature that is an authentication failure and not a fork, metadata mismatch, unauthorized key substitution and rotation, replay, gap/backfill failure, durable restart, and signed fork evidence. They also pin the genesis-to-issuance-to-revocation adapter lifecycle. The cold-start case accepts a correctly pinned first announcement only as a **local checkpoint**; it rejects an untrusted or malformed first view and makes no global consistency claim. The two-view case demonstrates that isolated, internally consistent forks remain undetected until their signed checkpoints are compared. The runner also checks key-pin validity windows against the same vectors: it refuses a pin without a window and rejects an announcement outside its signer's pinned window or above its `retireAfterEpoch`. The `liveness` block pins the `zkc:epoch-liveness:v1` transcript, digest, and signature of a statement for a head two hours old, a signed statement for another head, a statement by an unpinned key, and a signed-field tamper matrix. Its runner case shows that the quiet head is stale without the statement and fresh with it, that re-polling the same metadata changes nothing, that neither refusal changes the checkpoint or retains evidence, and that only the head's root remains servable once every earlier root was superseded more than `A` seconds before.

A runnable conformance suite for the behavioral requirements (holder generation/refusal, verifier acceptance/rejection with structured error codes, and the executable Freedom Safeguard checks for Safeguards 1, 4, and 6) is published in `conformance/` with machine-readable ZKC-Core vectors and a documented third-party adapter contract (`conformance/README.md`). Step-4e request binding is executable, not prose-only: KYC, jurisdiction, accreditation, source-of-funds, tax-residency, and sanctions-clearance each have an honest round-trip control plus a `core-verifier-*-requirements-not-met` case that leaves a valid proof untouched and verifies it against a different, internally valid request. A conforming verifier MUST reject each such out-of-request proof with `REQUIREMENTS_NOT_MET`; `INVALID_PROOF` does not satisfy these cases because no proof byte or public input was mutated. The Safeguard 6 (verifier accountability) coverage includes generation refusal on an unsigned request, `PURPOSE_MISMATCH` when a billing-purpose proof is presented to an access-purpose request, third-party Disclosure-Receipt round-trip verification with no operator in the loop, and hosted-SDK receipt-retention refusal (`safeguard-6-*` cases). The concrete canonical serialization of the purpose-bound, APR, and Disclosure-Receipt digests — in particular how the structured `proofTypes` and `parameters` members commit into the field-based preimage, and how the receipt binds the signed APR — is pinned byte-for-byte by the reference implementation (`python/zkc_crypto/apr.py`) and these vectors, which are authoritative for clean-room reproduction. Profiles above Core attach to the same runner as expansion hooks.

---

## Appendix A: Well-Known Identifier Registry (Non-Exclusive)

This appendix is a **non-exclusive registry of well-known identifiers** published for interoperability. It is **not** a closed or mandated schema, and it does not define an "official" or "default" credential or predicate set (see §1.4, Safeguard 1).

Normatively:

- No credential type, proof type, or provider listed here is privileged or required by the protocol.
- A verifier's trust policy (§6) **MAY** accept credential types, proof types, predicates, or issuers that are **not** listed here, and is never obligated to accept any that are.
- The identifier registry defines **no** mechanism for designating, registering, or blessing a canonical credential or predicate catalog; listing an identifier here confers no special status.
- The credential schemas in §3.1–3.7 are **reference schemas** for the corresponding well-known types — illustrative interoperability profiles, not the only permissible structures for a given concept.

Well-known credential and proof type identifiers (reference, non-exhaustive):

```typescript
const CREDENTIAL_TYPES = {
  KYC_V1: "zkc:cred:kyc:v1",
  JURISDICTION_V1: "zkc:cred:jurisdiction:v1",
  ACCREDITATION_V1: "zkc:cred:accreditation:v1",
  SOURCE_V1: "zkc:cred:source:v1",
  TAX_V1: "zkc:cred:tax:v1",
  SANCTIONS_V1: "zkc:cred:sanctions:v1",
  // Issuer-authenticated v2 schemas (digest authenticates validFrom). The
  // current remaining-predicate proofs (v7/v8) and their draft v9
  // republication require them (§7.2a). Only the four remaining-predicate v1
  // schemas above (accreditation, source, tax, sanctions) remain for
  // historical verification only; KYC_V1 and JURISDICTION_V1 are the current
  // schemas for their proof types.
  ACCREDITATION_V2: "zkc:cred:accreditation:v2",
  SOURCE_V2: "zkc:cred:source:v2",
  TAX_V2: "zkc:cred:tax:v2",
  SANCTIONS_V2: "zkc:cred:sanctions:v2",
  // Issuer-authoritative attribute set (§3.7).
  ATTRIBUTE_SET_V1: "zkc:cred:attribute-set:v1",
};

const PROOF_TYPES = {
  // Current identities: linkable (v1 envelope) / anonymous-or-scoped (v2 envelope).
  // "Current" means the identities this specification directs holders to emit
  // for new proofs (§5.9, §7.2a, §7.4.4). Review and activation state is
  // recorded per registry entry (registry/predicates/, §4.2a) and is not
  // restated here; activation is not an assurance claim.
  KYC_V1: "zkc:proof:kyc:v1",
  KYC_V2: "zkc:proof:kyc:v2",
  JURISDICTION_V3: "zkc:proof:jurisdiction:v3",
  JURISDICTION_V4: "zkc:proof:jurisdiction:v4",
  ACCREDITATION_V7: "zkc:proof:accreditation:v7",
  ACCREDITATION_V8: "zkc:proof:accreditation:v8",
  SOURCE_V7: "zkc:proof:source:v7",
  SOURCE_V8: "zkc:proof:source:v8",
  TAX_V7: "zkc:proof:tax:v7",
  TAX_V8: "zkc:proof:tax:v8",
  SANCTIONS_V7: "zkc:proof:sanctions:v7",
  SANCTIONS_V8: "zkc:proof:sanctions:v8",
  // Historical, deprecated identities (§7.2a, §7.2c.7): forgeable against a
  // malicious prover. Holders never generate them; verifiers reject them with
  // DEPRECATED_PROOF_TYPE unless their policy explicitly accepts "deprecated":
  //   zkc:proof:jurisdiction:v1, zkc:proof:jurisdiction:v2,
  //   zkc:proof:{accreditation,source,tax,sanctions}:v1 ... :v6.
  // Historical, contained identifier (§4.5): authenticates no credential;
  // holders never generate it and verifiers reject it unconditionally. The
  // same containment covers zkc:proof:rebind:v2, zkc:proof:credential_rebind:v2,
  // and zkc:proof:rebind:v3.
  CREDENTIAL_REBIND_V1: "zkc:proof:credential_rebind:v1",
  // Issuer-authenticated credential rebind (§7.4): linkable and scoped.
  CREDENTIAL_REBIND_V3: "zkc:proof:credential_rebind:v3",
  REBIND_V4: "zkc:proof:rebind:v4",
  // Issuer-authoritative selective disclosure (§3.7, §7.2b); v2 envelope only.
  SELECTIVE_DISCLOSURE_V1: "zkc:proof:selective_disclosure:v1",
  // Envelope-level aggregation blocks (§7.3); never individual proof entries.
  AGGREGATION_V1: "zkc:proof:aggregation:v1",   // linkable
  AGGREGATE_V2: "zkc:proof:aggregate:v2",       // scoped circuit, rejected in envelopes
  // Draft, unactivated beta.25 transport identities. Each republishes the
  // named predecessor statement unchanged under Noir beta.25 / Barretenberg
  // 5.0.0 (§6.2.1, §7.2a, §7.2b, §7.3, §7.4.3). No holder default resolves to
  // them; a holder emits one only when a request names it exactly.
  KYC_V3: "zkc:proof:kyc:v3",                                // = kyc:v2
  COMMUNITY_KYC_V2: "zkc:proof:community_kyc:v2",            // = kyc:v1
  JURISDICTION_V5: "zkc:proof:jurisdiction:v5",              // = jurisdiction:v4
  ACCREDITATION_V9: "zkc:proof:accreditation:v9",            // = accreditation:v8
  SOURCE_V9: "zkc:proof:source:v9",                          // = source:v8
  TAX_V9: "zkc:proof:tax:v9",                                // = tax:v8
  SANCTIONS_V9: "zkc:proof:sanctions:v9",                    // = sanctions:v8
  SELECTIVE_DISCLOSURE_V2: "zkc:proof:selective_disclosure:v2", // = selective_disclosure:v1
  REBIND_V5: "zkc:proof:rebind:v5",                          // = rebind:v4
  AGGREGATE_V3: "zkc:proof:aggregate:v3",                    // = aggregate:v2, also rejected
};

const ATTESTATION_TYPES = {
  // Issuer-signed credential transcript consumed by the §7.4 rebind circuits.
  CREDENTIAL_REBIND_V1: "zkc:attestation:credential-rebind:v1",
};
```

---

## Appendix B: Issuer Reputation (Future)

Framework for decentralized issuer reputation (draft):

```typescript
// Reputation accumulates from:
// - Successful verifications (verifiers report)
// - Age of operation
// - Stake (if applicable)
// - Regulatory status

interface IssuerReputation {
  issuerId: IssuerIdentifier;

  metrics: {
    totalCredentialsIssued: u64;
    totalVerifications: u64;
    successfulVerifications: u64;

    // Decentralized reputation score
    reputationScore: u64;  // 0-1000

    // Time-weighted factors
    operatingSince: Timestamp;
    lastActivity: Timestamp;
  };

  // Verifier-submitted reports
  reports: {
    verifier: VerifierIdentifier;
    outcome: "success" | "failure" | "suspicious";
    timestamp: Timestamp;
  }[];
}
```

---

## Appendix C: Aztec-Native Deployment Profile (Informative)

This appendix describes how ZKC relates to the Aztec-native deployment of ZKA, which ZKA ADR 0010 selects as the protocol family's strategic flagship. It is informative. It adds no requirement, identifier, domain tag, credential type, circuit, proof envelope, presentation profile, conformance level, or test vector, and it changes neither the protocol-family interface surface nor its epoch. The normative requirements it refers to are the ones already stated in the cited sections of this specification.

ZKA owns every Aztec contract that touches ZKC artifacts; ZKC.dev contains no Aztec code. Each statement below about Aztec behaviour cites the ZKA Specification section, ZKA ADR, or ZKA.dev source file it describes. The reference state is ZKA Specification v0.9.2-draft and the ZKA.dev Aztec workspace at commit `268660044e5c834f708dcfbf14b61854c1a9250c` (2026-10-26), with Aztec CLI/node/SDK 6.0.0 and the `aztec-labs-eng/aztec-nr` dependency pinned to v6.0.0. Every ZKA source-file and specification citation in this appendix refers to that commit. The committed cost measurements retain their historical V5 provenance (§C.9). Where the ZKA Specification and the ZKA.dev code differ, this appendix records what the code does and lists the difference as an open ZKA item (§C.9). ZKC remains authoritative for credential-internal mechanics (§2.1); ZKA remains authoritative for its contracts and its settlement semantics.

### C.1 Status and Production Gates

Nothing in this appendix is a production, conformance, or certification claim. ZKA ADR 0010 permits no ZKA production use before official Aztec V6 proving-issue resolution and permitted deployment guidance, plus all applicable qualification, audit, operational-acceptance, and explicit activation gates; a V6 release alone is insufficient. Public-value deployment on Aztec V5 remains prohibited. V6 local/testnet validation prepares qualification work and does not qualify a production deployment (ZKA ADR 0005, "V6 Fast Inbox clients"); the historical V5 tests and measurements remain design inputs only. A flagship label or a `supported` adapter tier grants no production authority (ZKA ADR 0010, "Decision and authority" and "Routing, failure and rollback").

### C.2 Location and Ownership

| Component | Location (ZKA.dev) | Role |
|---|---|---|
| `ZKACredential` contract | `aztec/zka_credential_aztec/src/main.nr` | Pins one credential issuer key at deployment, stores per-owner credential notes (`CredNote`), exposes attribute-disclosure functions, holds the public `compliance_set` registry, and has one `admin` who may revoke. It has no revocation map: `revoke` emits a nullifier siloed to this contract (§C.5). |
| `ZKATransfer` contract | `aztec/zka_transfer_aztec/src/main.nr` | Holds no local compliance registry. Its opt-in `transfer_with_compliance` calls the private view `ZKACredential.assert_compliant(recipient)` cross-contract. Its admin can only set the credential-contract address and switch that opt-in check on or off; both changes take effect after a delay. |
| Shared derivations | `aztec/zka_aztec_lib`, `noir/zka_lib` | `derive_zka_cbk` and `derive_credential_commitment` (AFP-KDC v1.0.2 §A.6); in `zka_aztec_lib` also the issuance transcript and signature check (`issuance_digest`, `verify_issuer_signature`) and `revocation_nullifier`. |
| Cross-environment tests | `aztec/zka_cross_env_tests` | Pin that the Aztec adapter functions and the standalone Noir functions return identical `cbk`, commitment, and disclosed-attribute hash for the same seed value. |

### C.3 Key Derivation and the ZKA Binding

The KDC derivations of §2.1 do not change on Aztec: `cbk = H("zkc/credential", seed)` and `holderCommitment = H("zkc/binding", cbk)`. ZKA Specification §8.3 maps the KDC seed to Aztec's app-siloed nullifier secret `nsk_app`. In the reference contract, `ZKACredential` obtains `nsk_app` with `request_nhk_app` for the caller's key and computes `cbk` and the commitment with the shared `zka_lib` functions. The commitment that the contract stores and checks is therefore exactly the ZKC `holderCommitment` of §2.1 and §8.2.

Aztec silos `nsk_app` by contract address. The secret from which `ZKACredential` derives `cbk` is therefore not the secret that `ZKATransfer` uses for its notes, which are owned by an Aztec address and nullified with the transfer contract's own app-siloed key (ZKA Specification §8.1). The two are not KDC seed siblings at run time. The cross-environment tests show that the derivation functions agree for one seed value; they do not show seed sharing between two contracts.

The ZKA identity-binding circuit (ZKA Specification §5.2, the cross-reference in §2.1) binds a ZKA note to a ZKC `holderCommitment` in the standalone profile. The Aztec reference produces no §5.2 proof. A compliance-gated transfer binds a credential to a recipient only through the recipient's Aztec account address (`assert_compliant(recipient)`). ZKA Specification §8.6 now records that the reference contracts keep an account-level registry and produce no §5.2 proof. ZKA §8.3 and the §8.6 delegation table still present `sk` and `cbk` as siblings of one `nsk_app`, and ZKA §5.8 still introduces the §5.2 proof as composable on Aztec without saying that the reference does not produce one (§C.9).

### C.4 Credential Issuance

`ZKACredential` pins one credential issuer at deployment. Its constructor takes `(admin, issuer)`, where `issuer` is an uncompressed secp256k1 public key. The key is written once and has no setter, so a different issuer needs a new deployment. `bind_credential(credential_data, attributes, issuer_signature)` stores a credential note only if `issuer_signature` is a valid ECDSA secp256k1 signature by the pinned key over the SHA-256 digest of a fixed 320-byte transcript. The transcript has ten 32-byte slots: the tag `zka/aztec/credential-issuance/v1`, the chain ID, the rollup version, the credential contract address, the `holderCommitment` that the contract derives from the caller's own key (§C.3), `credential_data`, and the four attributes (`aztec/zka_aztec_lib/src/lib.nr`, `issuance_digest`). A signature therefore works only for one holder, in one contract instance, on one chain, and the holder cannot change any signed value. The intended off-chain issuance flow lets the issuer sign a `holderCommitment` supplied by the holder's wallet. The issuance transcript contains no holder Aztec address, and `bind_credential` enqueues no public call carrying the holder address or commitment. These function-level properties do not establish what the issuer knows from other sources (§C.5).

Only originator notes count as credentials. `verify_compliance()` and every disclosure function load the caller's note through a constrained note selection on `context == 0` and on the caller's own `holderCommitment`. A note that `disclose_to` delivers to another account carries a non-zero `context` and the discloser's commitment, so it can neither register nor disclose. The ZKA.dev TXE tests refuse a self-asserted credential, a signature by a key other than the pinned one, altered attributes, altered `credential_data`, a signature made for another holder or for another contract instance, and a constructor with an unset key. They also show that an account whose only bind attempt was self-asserted cannot register (`aztec/zka_credential_aztec/src/test.nr`).

This is issuer authentication for one contract, not ZKC issuance or verification. The transcript and digest are ZKA-defined: they are neither the claim transcript of §7.4.1 nor the announcement digest of §2.4.1, so a ZKC issuer signature does not verify under `ZKACredential`, and the reverse. The contract verifies no ZKC credential proof, issuer registry entry (§4.1, §4.2), §4.3 issuance flow, accumulator membership (§2.4), or validity window; the pinned key is its whole issuer trust policy. Revocation prevents a new `verify_compliance()` registration anchored after the revocation. It preserves the originator credential note and its disclosure functions, and it does not clear an existing compliance registration (§C.5; `aztec/zka_credential_aztec/src/test.nr`, `revoking_real_commitment_preserves_credential_note`). A `compliance_set` registration records a successful credential and non-revocation check at its anchor; disclosure results are computed from the issuer-signed credential data and attributes for that holder. They are not ZKC compliance evidence (§C.7).

### C.5 Revocation Checks and What They Publish

`verify_compliance()` loads the caller's issuer-signed originator note privately (§C.4) and proves in private that the revocation nullifier of the caller's `holderCommitment` did not exist at the transaction's anchor block. It then enqueues one public call, `_register_compliance(owner)`. Its only public output is the caller's Aztec address, which the public `compliance_set` holds by design; `holderCommitment` does not leave private execution. The registration transaction expires one hour after its anchor block, which bounds the age of the non-revocation witness used for a new registration. This expiration does not expire the stored registration or bound its lifetime after a later revocation (ZKA Specification §5.8).

- The revocation state is a set of nullifiers siloed to `ZKACredential`. The admin's `revoke(credential_commitment)` emits the inner nullifier `H2("zka/aztec/revocation/v1", holderCommitment)` and publishes the revoked `holderCommitment` as a public statement about that holder anchor; the revoke transaction carries no holder address. Anyone who already knows a `holderCommitment` can test it with `is_revoked`. This is not the accumulator of §2.4, and it has none of the signed-announcement freshness, backfill, or equivocation properties of §8.3.
- A revocation does not remove an existing `compliance_set` registration, and a repeat `verify_compliance()` does not refresh one. An address registered before revocation can therefore continue passing `assert_compliant` and the optional transfer gate, which read the stored registry value. The contract comments advise against periodic re-verification, because the break in cadence after a revocation would link the `holderCommitment` to the address. Registration expiry has no design yet.
- `transfer_with_compliance(to, …)` reads the gate configuration and calls `assert_compliant(to)` in private, and it enqueues no public call. A gated transfer therefore publishes neither its recipient nor the fact that the gate ran. Registry and configuration changes take effect after a delay equal to Aztec's maximum transaction lifetime, so a gated transfer has the same expiration as a plain transfer. While a configuration change is pending, gated transfers of that deployment expire just before the public time of change, which reveals them as gated but not their recipients (ZKA Specification §5.8).
- `disclose_to` delivers a note that carries `holderCommitment` to its recipient. This is not public, but each recipient learns the global anchor, so two recipients can link the holder.
- A private read takes its witness from the node that serves the holder's PXE. For a registration, that witness is keyed by the siloed revocation nullifier, which anyone who knows `holderCommitment` can compute. The same node usually relays the registration transaction, so it can pair `holderCommitment` with the registering address. For a gated transfer, the node learns the recipient (ZKA Specification §5.8).

Consequence for ZKC privacy: `holderCommitment` is the stable, cross-verifier linkable anchor of §8.2. The reference contract no longer publishes it with the holder's address, so registration alone does not make the holder's `zkc:presentation:linkable:v1` presentations linkable on chain to that address. Additional Aztec-side exposures include the following: a `disclose_to` recipient learns the anchor, the PXE's node can pair the anchor with the registrant, and a revocation publishes the anchor, so any verifier that already holds it from a linkable presentation learns that it is revoked. ZKA Specification §5.8 and §8.4 describe these outputs. The metadata analysis in [`docs/zkc_metadata_leakage_threat_model.md`](zkc_metadata_leakage_threat_model.md) (§8.4) does not yet cover them.

### C.6 Presentation Profiles and Verifier Policy on Aztec

The Aztec reference implements none of the ZKC presentation surfaces: no `zkc:proof:v1` or `zkc:proof:v2` envelope, none of the three presentation profiles of §5.9, no Authenticated Proof Request (§5.5), and no Disclosure Receipt (§5.6). Its disclosure functions are ZKA-defined attribute disclosures, each taking a caller-supplied, non-zero `context` as a separate constrained argument. `prove_disclosure` and the named wrappers (`prove_kyc`, `prove_jurisdiction`, `prove_source_of_funds`) return the raw, context-independent disclosed-attribute hash. `aggregate_disclosures` returns the Poseidon2 fold of two such raw hashes; its value is also context-independent. `disclose_to` delivers a `CredNote` carrying the raw hash in `credential_data`, the session context in a separate field, the masked attributes, and the holder commitment (`aztec/zka_credential_aztec/src/main.nr`, `aztec/zka_aztec_lib/src/lib.nr`, ZKA ADR 0001). The context is not derived from an authenticated verifier request. The pinned issuer key controls credential-note issuance; the delayed admin configuration of `ZKATransfer` (`set_credential_contract`, `enable_compliance`) controls only the optional recipient-compliance gate. Neither supplies the missing ZKC verifier policy.

A ZKC presentation can still accompany an Aztec payment off-chain. The holder generates it with a ZKC SDK, a ZKC verifier checks it under §6.2, and it may be carried in a ZKA bundle (ZKA Specification §5.4). That path is the ordinary ZKC path; it gains nothing from the Aztec host and is not an Aztec-native ZKC profile.

### C.7 Evidence a ZKC Conformance Claim on Aztec Would Need

The ZKA.dev Aztec reference described here makes no ZKC conformance claim. A future claim would have to show, for the exact Aztec artifacts, that the requirements this specification already states hold there:

1. **Issuance.** Credentials verified against issuer authentication and a verifier trust policy (§4, §6.2), with a negative test proving that a self-asserted credential is refused. ZKA.dev meets part of this: `bind_credential` authenticates one pinned issuer key, and its TXE tests refuse self-asserted, untrusted-key, and altered credentials (§C.4). ZKC credential proofs and a §4/§6.2 verifier trust policy (issuer registry, accumulator, validity window) are still absent.
2. **Presentation profiles.** The §5.9 profiles with the anonymous profile as default, and the public-input determinism invariant (§5.9.5) applied to every value the Aztec transaction makes public, including public-call arguments, public storage keys, public logs, and note-discovery metadata.
3. **Verifier accountability.** Authenticated requests (§5.5), purpose binding (§2.2), and holder-custodied receipts (§5.6), so that Safeguard 6 (§1.4) holds without an operator in the loop.
4. **Revocation.** Revocation semantics and freshness equivalent to §2.4 and §8.3, with revocation limited to counterparty refusal.
5. **Safeguards.** The properties in §C.8.
6. **Executable conformance.** The ZKC-Core suite and its Safeguard cases (§9.2) passed through the `conformance/` adapter contract.

### C.8 Freedom Safeguards on Aztec

§1.4 already requires that ZKC revocation affect only a counterparty's acceptance of a proof, never the validity, custody, or transferability of a note. ZKA ADR 0010's capability matrix classifies compliance as an optional interaction capability whose rejection "never changes note validity or gates plain transfer/withdrawal". The ZKA.dev reference meets these properties:

- The state effect of `revoke` is the revocation nullifier; its public call also publishes the holder commitment (§C.5). It has no code path to any note. The pinned issuer key gates only the creation of new credential notes, never an existing note (`aztec/zka_credential_aztec/src/main.nr`, Safeguard 3 header).
- `claim_private`, `transfer`, and `withdraw` take no compliance, credential, or admin input, and `withdraw` works whether compliance is enabled or not (`aztec/zka_transfer_aztec/src/main.nr` header; Safeguards 3 and 5).
- `transfer_with_compliance` is a separate opt-in function. A failed check reverts the whole transaction, and the sender keeps the funds.
- Neither contract has a pause, upgrade, or administrative path over note validity (ZKA Specification §8.1).

### C.9 Cost and Open Items

The cost of the compliance-gated transfer class is **unmeasured**. On 2026-10-26 ZKA.dev `docs/economics/zka_pay_aztec_comparison.md` still listed this class as a remaining measurement gap. The committed owner-direct measurements were collected on Aztec 5.1.0/5.2.0 and retain those toolchain identities; the V6 source pin above does not relabel them as V6 results. Those figures do not apply to the compliance-gated class. `transfer_with_compliance` adds a private read of the gate configuration and a private cross-contract call to `assert_compliant`, which reads the registry privately. `bind_credential` adds a SHA-256 hash of the 320-byte transcript and an ECDSA secp256k1 verification. `verify_compliance` adds a private nullifier non-inclusion proof and one enqueued public call.

ZKA items that follow from the differences recorded above:

| Section | ZKA item | Status |
|---|---|---|
| §C.3 | State the app-siloed source of each derived key in ZKA §8.3 and the §8.6 delegation table, and describe the Aztec credential-to-note binding in ZKA §5.8/§8.4 as implemented (account-level, with no §5.2 proof). | Open |
| §C.4 | Add issuer authentication to `ZKACredential`, or document it as a holder-asserted attribute contract that gives no compliance evidence. | Addressed by ZKA.dev: issuance is authenticated against one pinned issuer key (§C.4). A ZKC verifier trust policy remains open for any conformance claim (§C.7 item 1). |
| §C.5 | Stop publishing the global `holderCommitment` with the holder's address, address the recipient disclosure of `transfer_with_compliance`, and correct the ZKA §5.8/§8.4 privacy statement. | Addressed by ZKA.dev: registration publishes only the address, gated transfers publish no recipient, and ZKA §5.8/§8.4 describe the remaining outputs (§C.5). |
| §C.9 | Measure the cost of the compliance-gated transfer class. | Open |

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| Unreleased | 2026-11-18 | **Aggregation verification (security review 2026-10-04, R5.5).** §7.3 clarifies the simulated-recursion constraints and the v1 circuit's independent holder witness. Verifiers reject aggregation blocks in v2 envelopes with `INVALID_AGGREGATION`. Legacy v1 aggregation remains an envelope commitment over requested, individually verified proofs. |
| Unreleased | 2026-11-18 | **Fork-evidence classification and migration-checkpoint authorization (security review 2026-10-04, R7.11).** §2.4.1 states which conflicts are equivocation evidence: the announcement the consumer accepted immediately before the candidate and the candidate, both under the same `accumulatorId` and the same `signingKeyId`. An announcement for another accumulator is a scope mismatch, rejected and never retained; a cross-key linkage conflict fails closed but is not retained. §2.4.1 also makes the migration authorization concrete: a local `(issuerId, accumulatorId, epoch)` policy, without which a cold-start anchor with the zero predecessor at an epoch above 0 is refused, and holders pin the accumulator id in local configuration. The reference stack previously reported an accumulator mismatch as `CHAIN_FORKED`, retained the persisted checkpoint instead of the actual predecessor (so a relay that substituted the issuer's genuine announcement of a second accumulator planted false evidence), accepted any cold-start anchor, and read the holder's accumulator id from the service object. It now reports `ACCUMULATOR_ID_MISMATCH` and `MIGRATION_CHECKPOINT_UNAUTHORIZED`, retains `zkc:revocation-equivocation-evidence:v2` records with `predecessor` and `candidate`, takes `authorized_migrations` on `VerifierAccumulatorCache` and the holder providers, and takes the holder pin from `accumulator_ids` or a `(source, accumulator_id)` target. No circuit, encoder, sidecar, registry, transcript, announcement, metadata, test-vector, or wire-format identity changes. |
| Unreleased | 2026-11-18 | **Quiet-issuer liveness and time-bounded revocation latency (security review 2026-10-04, R7.7).** New §2.4.2 defines `zkc:epoch-liveness:v1`, a separately versioned, domain-separated signed statement `{accumulatorId, epoch, headHash, issuedAt}` that keeps a quiet issuer's unchanged head fresh without a new epoch. It is signed under the announcement key pins and windows of §2.4.1, uses its canonical encodings and 65535-byte transcript bound, names exactly one head by its complete hash, never changes an epoch, root, history, or checkpoint, and is never fork evidence. Metadata v2 carries it as the additive `revocation.currentLiveness` field and the update responses as `liveness`. A head's freshness time is the later of its `announcedAt` and the newest verified statement that names it. A superseded root is served only while the announcement that superseded it is within the age limit `A`, so the worst-case revocation latency is `A + S` seconds (3900 seconds with the reference defaults) regardless of `maxEpochLag` or later mutations. Re-polling the persisted head is a no-op, and per-issuer states keep one stale issuer from blocking the others. The reference stack previously treated identical re-polls as `ANNOUNCEMENT_REPLAY`, failed `accumulator_states()` for every issuer when one was stale, refused to refresh an active credential of an issuer quiet for more than an hour, and kept a revoked credential provable for `maxEpochLag` further mutations with no time bound. `RevocationAccumulatorService` now signs liveness on a 900-second interval, the verifier cache and holder providers verify and apply it, `accumulator_state_results()` reports each issuer's outcome, `tests/vectors/revocation_equivocation_v1.json` gains a `liveness` block, and `conformance/run_revocation.py` gains the `quiet-issuer-liveness-and-time-bound` case. No change to the v3 announcement transcript, the epoch rule, circuits, encoders, sidecars, or registry entries. |
| Unreleased | 2026-11-18 | **Bounded work before authentication and canonical revocation encodings (security review 2026-10-04, R7.12).** §2.4.1 states that the v3 signing transcript is at most 65535 bytes (so `accumulatorId` and `signingKeyId` together hold at most 65392 UTF-8 bytes) and that every length bound counts UTF-8 bytes, not code points. Hex fields are matched against their exact lower-case pattern before decoding, and metadata convenience fields must equal the signed values with the same JSON type. A consumer sizes an epoch gap arithmetically before any per-epoch work, and bounds a rebuilt leaf set by the authenticated epoch (at most one slot per epoch) before decoding it, since trailing zero leaves do not change the root. The reference stack previously listed every missing epoch before its backfill check (a signed epoch 2^62 raised `MemoryError`), decoded and hashed a relay-padded leaf set before any signature check, accepted whitespace-padded hex and `currentEpoch: true`, and its HTTP transport dropped connections on malformed input, read bodies and responses without a size or time bound, and started unbounded threads; `schemas/issuer-metadata.schema.json` now records the byte bounds. |
| Unreleased | 2026-11-18 | **Announcement signing-key validity windows (security review 2026-10-04, R7.5).** §2.4.1 requires every verifier and holder key pin to carry `notBefore`/`notAfter` and optionally `retireAfterEpoch`. An announcement is accepted only when its signed `announcedAt` lies in its signer's half-open window and its epoch is at or below `retireAfterEpoch`. The bounds apply to the head, to backfilled and caught-up history, and to a reloaded checkpoint; a pin without a window is refused. The issuer refuses to sign with a key outside its window (`EXPIRED_ISSUER_KEY`) before any state changes, and a metadata endpoint that cannot publish a valid document reports a server-side failure. The reference verifier and holder previously pinned bare `(x, y)` keys, so an announcement signed years after the key expired was accepted; the issuer signed with an expired key, and the metadata failure surfaced as HTTP 400. The reference stack now pins `AnnouncementKeyPin` values, reports `ANNOUNCEMENT_KEY_OUTSIDE_VALIDITY`, maps metadata faults to HTTP 503, and the revocation conformance runner adds the `announcement-key-validity-window` case. No change to the announcement transcript, metadata v2, test vectors, circuits, or the protocol-family epoch. |
| Unreleased | 2026-11-18 | **Resumable bounded revocation catch-up (security review 2026-10-04, R7.6).** §2.4.1 states how a verifier or holder whose checkpoint is more than its per-call backfill bound behind the current head recovers. It MUST NOT discard the checkpoint and cold-start from the head. It catches up in bounded steps from the persisted checkpoint: each step verifies the signature, epoch continuity, and predecessor link of each announcement, and persists the last one with a monotonic write. Historical announcements need not be fresh; the current head keeps the freshness rule, and no root is served from a stale intermediate checkpoint. The reference stack previously refused every gap wider than `max_backfill` (32), and historical heads could not be ingested once they were older than the age limit, so a consumer more than 32 epochs behind was locked out until its checkpoint was deleted. `VerifierAccumulatorCache.catch_up` and `PrivateWitnessProvider.catch_up` now verify at most `max_backfill` announcements past the checkpoint per call and return a resumable `CatchUpStatus`. Single-call ingestion keeps its all-or-nothing bound. No circuit, encoder, sidecar, registry, transcript, announcement, metadata, or wire-format identity changes. |
| Unreleased | 2026-11-18 | **Rebind continuity semantics (security review 2026-10-04, R4.3).** §4.5 and §7.4.6 define an authenticated rebind as a continuity claim, not a migration (real migration is issuer re-issuance). New §7.4.7 adds normative verifier state rules — one claim per credential per verifier across statements and scopes, retire the old handle, freeze on conflict, record only checked entries — with the reference `RebindLedger`, and records the decision not to adopt a rebind nullifier. §8.3 adds the compromised-old-key / fan-out row. Verifiers now accept the `zkc:proof:rebind:v4` answer to a scoped request naming `zkc:proof:credential_rebind:v3`. No circuit identity changes. |
| Unreleased | 2026-11-18 | **Rebind linkage and identity statements corrected (security review 2026-10-04; documentation only).** §4.5 states that every rebind proof discloses an old-to-new link to its recipient (and onward through audit bundles); §7.4.6 replaces "disclosed set unchanged / not widened" with the issuer-authenticated `credential_id` cross-verifier handle and the issuer-verifier collusion exposure of scoped rebinds. ADR 0004 D4 records that `zkc:proof:rebind:v5` shares v4's statement domain, so its ACIR/VK distinctness rests on the toolchain lane. |
| Unreleased | 2026-11-18 | **Low-s ECDSA verification and transcript-classified announcement conflicts (security review 2026-10-04, R7.3).** §2.4.1 adds the verifier low-s rule: a secp256k1 signature is valid only with `1 <= s <= floor(n / 2)`, the bound the in-circuit verifier enforces, so the high-s twin `(r, n - s)` of a valid signature is rejected. The reference verifier previously accepted it, so a party without the issuer key could re-encode an announcement: a re-served checkpoint was retained as false equivocation evidence against an honest issuer, and a re-encoded next epoch was accepted and persisted, after which every honest successor failed linkage. The rule covers every ZKC secp256k1 signature: announcements, APRs, receipts, delegation tokens, audit-bundle authorizations, and issuer credentials, and the holder's Python constraint mirror now refuses a high-s credential signature as the circuit does. §2.4.1 also classifies announcement conflicts by signing transcript: a same-epoch candidate with the retained transcript and different signature bytes is an authentication failure, never `CHAIN_FORKED`, and is not retained as evidence. `tests/vectors/revocation_equivocation_v1.json` gains a `signatureMalleation` block (a high-s twin and a same-transcript re-signature) and `conformance/run_revocation.py` gains the `signature-malleation-by-transcript` case. Signatures from the reference signers are already low-s and do not change. No circuit, encoder, sidecar, registry, transcript, or wire-format identity changes. |
| Unreleased | 2026-11-17 | **Holder consent for fixed inclusion paths.** §7.2b and §7.2c require a coded default refusal for inclusion paths that identify one leaf. Holders may authorize exact-code disclosure locally per predicate and must log the opt-in. Jurisdiction derives the witness from canonical codes when supplied. |
| Unreleased | 2026-11-15 | **Appendix C reference host removed (documentation only).** The ZKA.dev reference commit in Appendix C is now named by its commit id without a hyperlink to a non-public host. No requirement, identifier, transcript, public-input ABI, schema, circuit, registry entry, or test vector changes. |
| Unreleased | 2026-11-14 | **Stale-section reconciliation (documentation only).** Brings early and overview text into line with the later normative sections, the committed circuits, encoders, binding sidecars, registry entries, and the reference issuer, holder, and verifier. §2.4 and §4.1 type the accumulator value as the Poseidon2 Merkle root (`Hash`). §3.1 and §3.2 show the exact encoder-declared public-input names; §3 credential `header.type` values use the reference issuer's `zkc:cred:*` identifiers, with the v2 schemas for v7/v8 remaining-predicate proofs, and §3.5 types the tax year as `u64`. §4.1 describes `Issuer.id` as the published, key-independent `issuerId`. §6.2 adds the `verifyAuthenticated` entry point to the illustrative verifier interface, and its step-4c comment follows §2.4.1 epoch semantics. §6.2.1 adds request-binding rows for KYC v3, community KYC v2, jurisdiction v3–v5, remaining-predicate v5/v6 and v9, selective disclosure v2, and rebind v5, and names the three aggregation identifiers. §3 states that the `claims` and `claim` blocks are conceptual and marks each condition that the named proof identity does not prove (accreditation jurisdiction, source verification level, tax status and year lists, sanctions list coverage and screening age). §6.3 examples build and sign an APR, retain it in local session state, verify on the authenticated path against that retained request, use one presentation profile each, and no longer publish a proof hash on chain. §7.2 adds `requiredClaimType` to the claim binding. §7.2a, §7.2b, §7.2c.7, §7.4.3, §7.4.5, and Appendix A define the draft, unactivated beta.25 republications (`kyc:v3`, `community_kyc:v2`, `jurisdiction:v5`, remaining-predicate `:v9`, `selective_disclosure:v2`, `rebind:v5`, `aggregate:v3`). §7.3 states what each aggregation generation constrains and does not prove. §8.1 lists the primitives the profile uses, including the reference host BLAKE2b hash-to-field, and §8.3 states the credential-sharing deterrent and its residual risk. The `0.2.4` history row now precedes `0.2.5`. No requirement, identifier, transcript, public-input ABI, schema, circuit, registry entry, or test vector changes. |
| Unreleased | 2026-11-04 | **Length-prefixed delegation token digest (security review 2026-10-04, R3.8).** §5.4 specifies the delegation token digest exactly. The new `zkc/delegation-token:v2` transcript length-prefixes every field with a `u32be` length, carries an explicit proof-type count, orders distinct proof types by UTF-8 bytes, and makes the reviewed request commitment a field of the same transcript. The v1 transcript NUL-terminated proof types and `verifierId` without a length or count, so a token signed for one NUL-bearing proof type had the digest of a token for two proof types, and the holder gate authorized both. v1 digests are no longer produced or accepted, and minting, the holder gate, and delegated provers fail closed on any other digest version; holders re-mint outstanding tokens with a fresh nonce. Proof types and `verifierId` MUST be nonempty and MUST NOT contain code points of General Category `Cc`, `Cf`, `Cs`, `Co`, `Cn`, `Zl`, or `Zp`; minting and the holder gate refuse them. `contextValue` stays an exact integer in `[0, r)`, and the transcript itself refuses `maxUses` outside `[1, 2^32)`. New known answers are in `tests/vectors/delegation_token_digest_v2.json`. Every delegation token digest and signature changes. Reference API: `DelegationToken` gains `digest_version` (default 2), and minting requires a tuple of proof types and 32-byte principal key coordinates. No circuit, encoder, sidecar, registry, envelope, or receipt change. |
| Unreleased | 2026-11-04 | **Issuer-qualified holder credential keys (security review 2026-10-04, R3.9).** §2.3 and §5.1 state that `credentialId` is issuer-chosen and unique only within its issuer. A holder keys stored credentials by `(issuer, credentialId)`, so a second issuer reusing an identifier no longer evicts the first credential. `updateWitness` takes an optional `issuerId` and fails with `AMBIGUOUS_CREDENTIAL` rather than guess when identifiers collide. §6.2.1 and §7.4.4 state that authenticated rebind narrows a `credentialId` to issuers the request trusts and refuses two trusted matches. The reference encrypted credential file moves to `zkc-credential-store:v2` (PBKDF2-HMAC-SHA256 master key with label-separated HMAC subkeys, MAC over a length-framed header, fixed 16-byte nonce, private atomic writes) and migrates v1 files; the SQLite store migrates its schema and makes its files 0600. Reference Python API break: `CredentialStore.get`/`delete` take an optional `issuer_id`, and the holder client passes it on every witness refresh, so a third-party store with the old signature raises `TypeError` on every accumulator-backed proof, not only on collisions; `TickReport.refreshed` holds `(issuer_id, credential_id)` pairs. Holder-local storage only: no circuit, encoder, sidecar, registry, or wire-format identity changes. |
| Unreleased | 2026-11-04 | **Anchored, profile-scoped holder keys (security review 2026-10-04, R3.7).** New §5.6.1: a receipt's `holderKey` and an audit bundle's `holderAuthorizationKey` are self-asserted, so receipt and bundle verification require an expected holder key from the holder and fail closed without one; a forged receipt naming another holder's commitment and a verifier-minted bundle are rejected. Receipt keys are derived from the exact seed bytes per verifier identity (linkable), per `scopeId` (scoped), or fresh per receipt (anonymous, refused, unauthenticated), so anonymous receipts no longer share a cross-verifier linking key; audit-authorization keys are per auditor. §5.6.1 states what each receipt and bundle proves, requires the relying party to compare the response handle with the anchored key's handle, and documents the legacy seed-global keys. Fresh keys mix the receipt digest into the derivation. Receipt digest, receipt and bundle fields, and envelope bytes are unchanged. Reference API breaks: `verify_receipt` and `verify_audit_bundle` need `expected_holder_key`; `AuditExporter.authorization_public_key(auditor_key_id)` is a method; `derive_authorization_key(seed, auditor_key_id)` takes the auditor id; conformance holder adapters return `receiptHolderKey` and verifier adapters take `verify_receipt(receipt, *, expected_holder_key)`, and the runner probes receipt anchoring and receipt key scope. |
| Unreleased | 2026-11-04 | **Typed agent disclosure ceilings (security review 2026-10-04, R3.6).** §5.4 states how `maxDisclosure` is compared: per parameter in the direction that discloses more, with thresholds inside the circuit's unsigned domain, unordered values matched exactly, no auto-disclosure for a proof type without a typed comparison, and explicit principal opt-in for a set-membership proof whose inclusion witness is fixed by verifier-supplied paths (it discloses the exact member). The reference agent previously compared only KYC values, so its ceiling failed open for accreditation, source, tax, sanctions, and jurisdiction. No circuit, encoder, sidecar, registry, or wire-format change. |
| Unreleased | 2026-11-04 | **Delegated proofs follow the presentation profile (security review 2026-10-04).** §5.3 property 4 no longer fixes delegated output to `zkc:proof:v1`: the envelope follows the reviewed request's presentation profile (§5.9), so the default anonymous profile yields `zkc:proof:v2`, and a delegated request, which carries no Authenticated Proof Request, falls under the Safeguard 6 default refusal with an explicit, logged override. Properties 3 and 5 compare against the presentation-resolved proof type and source: consumers of default delegated material MUST request and trust the v2 sibling identity (for example `zkc:proof:jurisdiction:v4` for a `zkc:proof:jurisdiction:v3` request). The scoped profile is refused without an APR. Property 4 lists what the reference SDK checks before a delegated use is consumed; witness refresh, revocation, backend, and proving failures still consume reserved uses. §5.9 states that the holder's profile choice is holder-local and that linkable consent is an explicit holder decision. No circuit, encoder, sidecar, registry, vector, or envelope format changes. |
| Unreleased | 2026-11-04 | **Closed request-parameter vocabulary (security review 2026-10-04, R2.4).** §6.2.1 gives every proof type's request-binding contract a closed set of parameter keys: the `param:` references of its binding sidecar plus a documented table of request-only keys. Verifiers MUST reject any other key with `REQUIREMENTS_NOT_MET` on both entry points, naming the key and proof type; holders MUST refuse such a request before proving, after the `SECRET_IN_REQUEST` check. Previously a misspelled optional key (for example `flagrequired`) was ignored and its requirement defaulted away while the signed APR carried the misspelling. The parameter table is closed as well: a block for an unlisted proof type is `REQUIREMENTS_NOT_MET` at the verifier and refused by the holder. An aliased request is checked against the emitted identity's set. Behaviour changes for previously ignored keys: authenticated rebind `issuerIdHash` (never a pin there; the issuer identity is a mandatory bound comparison) and `flagRequired` on source/tax/sanctions v1/v2 verification requests are now rejected, and a verifier warns `UNBINDABLE_PARAMETER` for the authenticated rebind `credentialId`. No circuit, encoder, sidecar, registry, or wire-format identity changes. |
| Unreleased | 2026-10-27 | **Selector-free artifact-binding enforcement.** §4.2a applies binding review, lifecycle, and local-allowlist gates to a selector-free legacy artifact when its source, public-input contract, ACIR, and VK uniquely match one exact entry-v2 binding, and rejects unresolved or conflicting aliases. Both verifier entrypoints enforce requested selector pins. The original v1 proof type, circuit, encoder, VK, and authenticated APR digest remain unchanged. |
| Unreleased | 2026-10-04 | **Holder refuses unbound anonymous composites (security review 2026-10-04).** §5.9.2 rule 5 requires a holder whose effective profile is anonymous to refuse, before proving, a request for two or more distinct proof types (`ANONYMOUS_COMPOSITE_REFUSED`): a conforming verifier rejects that answer (`UNBOUND_COMPOSITE`, §5.9.4), so producing it would only disclose which predicates the holder satisfies. Conjunctions are answered under the scoped profile, preferably with `scopePolicy` `"session"`; an explicit holder opt-in (`allow_unlinked_composite`) covers verifiers that declare the proofs independent. The §5.9.2 example lists the `"session"` scope policy. No circuit or wire-format identity changes. |
| Unreleased | 2026-10-04 | **Same-holder composites (security review 2026-10-04).** §5.9.4 states the same-holder semantics of each presentation profile and requires verifiers to reject an anonymous envelope answering two or more distinct requested proof types with `UNBOUND_COMPOSITE` (anonymous proofs bind to no holder, so two holders' proofs could be pooled to satisfy a conjunction) unless their policy declares the proofs independent. §5.9.1 adds the `"session"` scope policy, whose scope derives from the APR's own context value, so a conjunctive answer shares one in-circuit pseudonym without cross-session or cross-verifier linkability; the `"session:"` label prefix is reserved. New presentation vectors `presentation-anonymous-composite-pooling`, `presentation-session-scoped-composite`, and `presentation-session-scope-unlinkable`. No circuit identity changes. |
| Unreleased | 2026-10-26 | **Aztec V6 reference-state audit (informative).** Re-verifies Appendix C against ZKA.dev commit `268660044e5c834f708dcfbf14b61854c1a9250c`, pins Aztec CLI/node/SDK 6.0.0 and aztec-nr v6.0.0, and retains historical V5 measurement provenance and ADR-0010 production gates. Clarifies persistent compliance registrations after revocation, preserved credential notes/disclosures, the scope of the registration witness expiration, and the distinct disclosure return/note-delivery shapes. Scopes issuer-address and conformance statements to the audited reference. No normative interface, credential, circuit, schema, envelope, presentation-profile, conformance, test-vector, or epoch change. |
| Unreleased | 2026-10-26 | **Aztec-native deployment profile refreshed (informative).** Updates Appendix C to the ZKA.dev Aztec workspace as of 2026-10-26. §C.2 and §C.5 record that `ZKACredential` keeps revocation as contract-siloed nullifiers instead of a public map and that `ZKATransfer` checks compliance through the private view `assert_compliant`. §C.4 records that issuance is now authenticated by one pinned secp256k1 issuer key over a ZKA-defined transcript, which is still not ZKC issuance or verification, and that only originator notes count as credentials. §C.5 records that registration no longer publishes `holderCommitment`, that gated transfers publish no recipient, and the exposures that remain. §C.7 item 1 is marked as partly met, and the §C.9 table marks the §C.4 and §C.5 items as addressed by ZKA.dev; the §C.3 binding item and the cost item stay open. Informative only: no change to identifiers, credentials, circuits, schemas, proof envelopes, presentation profiles, conformance, test vectors, the interface surface, or the protocol-family epoch. |
| Unreleased | 2026-10-21 | **Aztec-native deployment profile (informative).** Adds Appendix C, which records how ZKC relates to ZKA's Aztec-native flagship deployment (ZKA ADR 0010) against ZKA Specification v0.9.2-draft and the ZKA.dev Aztec workspace as of 2026-10-21: ownership and location of the ZKA credential contract and compliance registry, KDC derivation from the credential contract's app-siloed `nsk_app` and the absence of a ZKA §5.2 binding proof on Aztec, the absence of issuer authentication, what the non-revocation and compliance-gated paths publish, the absence of ZKC presentation profiles and authenticated verifier policy on Aztec, the evidence a future ZKC conformance claim on Aztec would need, the Freedom Safeguard properties, the production gates, and the unmeasured compliance-gated transfer cost, with the open ZKA items that follow from each gap. Informative only: no change to credentials, circuits, schemas, proof envelopes, presentation profiles, conformance, test vectors, the interface surface, or the protocol-family epoch. |
| Unreleased | 2026-10-04 | **Deprecated-identity opt-in (security review 2026-10-04).** The known unsafe historical identities are rejected on the authenticated path with `DEPRECATED_PROOF_TYPE` unless the verifier's policy explicitly accepts `deprecated`, independently of absent or additional registry listings (§7.2a, §7.2c.7); a literal APR is no longer sufficient, since it can only be answered by a freshly forged proof. Remaining-predicates 5.0.0/6.0.0 are deprecated (their digest omits `validFrom`; use v7/v8). §3.2 and Appendix A name current identities and mark v1-v6 / jurisdiction v1-v2 historical. |
| Unreleased | 2026-10-04 | **Holder-local rebind secret (security review 2026-10-04).** §7.4.4 now requires a rebind's new binding key or master seed to travel only through a holder-local channel and never in request parameters, an APR, a negotiation request, a verifier policy, receipts, verification requests, audit bundles, logs, errors, or reprs, and requires holders to refuse any request naming a secret parameter before proving (`SECRET_IN_REQUEST`). Previously the prescribed `newCredentialBindingKey`/`newMasterSeed` request parameter placed the holder's next root secret inside the verifier-signed APR. No circuit or wire-format identity changes. |
| Unreleased | 2026-10-04 | **Envelope-generation binding (security review 2026-10-04).** §5.9.4 and §6.1 require every proof entry's `publicInputs` to carry exactly its encoder-declared names (`MALFORMED_PROOF`), admit a proof only in the envelope version of its circuit family as derived from the encoder's holder-handle inputs (`PROFILE_MISMATCH`), and route every authenticated rebind successor to the §7.4.5 rules from either envelope. An explicitly configured `accepted_profiles` is now the v1/linkable gate (`PROFILE_NOT_ACCEPTED`), and an authenticated envelope more linkable than its APR's declared profile is `PROFILE_MISMATCH`. Closes the presenter-chosen holder handle reachable by re-wrapping a proof in the other envelope version. Verifier-side only: no circuit, encoder, sidecar, or registry identity changes. |
| Unreleased | 2026-09-10 | **Predicate-entry v2 source identity and artifact bindings.** Adds the immutable source/contract `sourceId`, independently reviewed and activated artifact-binding records, exact `(predicateId, entryVersion, bindingId)` resolution, the APR-authenticated `zkc:request:binding-selectors:v1` extension, proof-carried selectors, verifier-local binding policy, retained binding/provenance audit evidence, and explicit v1 adoption without mutation. Selector-free v1 behavior and legacy APR digests remain unchanged. |
| Unreleased | 2026-09-06 | **Security containment of unauthenticated credential-rebind statements.** §4.5 records that `zkc:proof:credential_rebind:v1`, `zkc:proof:rebind:v2`, `zkc:proof:credential_rebind:v2`, and `zkc:proof:rebind:v3` prove holder-key continuity only (their credential fields are unconstrained witnesses; no issuer signature or accumulator membership is verified) and are never evidence of credential ownership or live continuity. Holders MUST NOT generate them; verifiers MUST reject them at every entry point with the new structured error `UNAUTHENTICATED_CREDENTIAL` (§6.2), independent of trust policy, request pins, or request authentication. Historical circuits, encoders, sidecars, artifacts, and registry pins are byte-frozen; the four registry entries are deprecated with no historical-verification exception. **Authenticated credential rebind (§7.4, ADR 0004).** Specifies the issuer-signed `zkc:attestation:credential-rebind:v1` transcript (`Poseidon2(Poseidon4(DOMAIN_ZKC_CLAIM, type, issuerIdHash, schemaIdHash), Poseidon4(holderCommitment, credentialId, validFrom, validUntil))`), the additive linkable `zkc:proof:credential_rebind:v3` and scoped `zkc:proof:rebind:v4` circuits that recompute it from constrained fields, verify the issuer signature against the public key, and prove fresh non-revocation for the same credential identifier, their exact public/private input ABIs and claim bindings, the verifier's issuer-trust, issuer-identity, and authenticated-revocation acceptance rules (§6.2), the no-downgrade rule, the privacy analysis, migration of existing credentials, and the `credential_rebind_attestation_v1` known-answer vectors (§9.2). |
| Unreleased | 2026-09-03 | Added the issuer-authoritative `zkc:cred:attribute-set:v1` / `zkc:proof:selective_disclosure:v1` reference profile, fixed-position Noir circuit, typed AFP-KDC-domain transcript, versioned proof-entry and public-input schemas, KATs, and ZKA/AFP opaque-consumer boundary. Canonicalized master seeds as exact 32-byte values under the frozen `afp-kdc:master-seed:v1.0.1` big-endian-mod-`r` profile; added boundary/asymmetric vectors, strict host decoding, full-entropy generation, and representation-only migration rules without changing existing identities. Updated current authority to AFP-KDC v1.0.2, added seven raw-sponge KATs and the explicit 260-field parameter digest gate in Noir and Python, and synchronized the ZKM-aware protocol-family epoch without changing any derived value or frozen identity. Defined the step-4e `verifyTypeSpecificRequirements` request-binding contract, including default-deny `UNBOUND_PROOF_TYPE` behavior, and added honest plus out-of-request conformance vectors for every Core compliance predicate family. Clarified the delegation-token trust boundary: holder authorization MUST anchor token keys to authenticated local holder state, same-seed minting MUST bind the delegation key and holder commitment, and token-carried key coordinates remain compatibility metadata rather than a trust anchor. This clarification changes no token wire format, circuit, proof envelope, or delegated authority. |
| 0.1.0 | 2026-01-19 | Initial specification |
| 0.2.0 | 2026-02-16 | Proving system migration: Halo 2 (Pallas) → Noir/UltraHonk (BN254). `Halo2Proof` → `ZKProof` throughout. Protocol now proving-system-agnostic at spec level. |
| 0.2.1 | 2026-03-06 | Notation alignment with ZKA v0.5.0: `H(x)` updated to Poseidon2 over BN254 with domain tag; `commit(v, r)` updated from Pedersen to Poseidon2; §8.1 cryptographic assumptions removes stale Halo 2 reference. |
| 0.2.2 | 2026-05-15 | Alignment with ZKA v0.6.0 Freedom Safeguards (ZKA §1.6). Added §1.4 Freedom Safeguards (normative), including the open-source predicate-verification mandate (Safeguard 4) and the §2.1 ZKA §5.2 cross-reference. Reframed Appendix A as a non-exclusive well-known identifier registry and §3.1–3.6 as reference (non-mandatory) schemas per Safeguard 1 (Predicate Pluralism). Made §9.1 conformance monotonic: ZKC-Full is the highest core level; ZKC-Agent is an orthogonal extension profile, not a level above Full. Resolves the three ZKC-layer divergences in ZKA v0.6.0 Appendix C.1. |
| 0.2.3 | 2026-06-04 | Credential-binding-key derivation relocated to the Key Derivation Core (KDC v1.0.0, AFP Specification Appendix A) and referenced normatively from §2.1; §1.3 notation re-pointed from a ZKA-version reference to KDC §A.3. The `CredentialBinding` interface is unchanged. Relocation only — no change to any derived value, credential structure, circuit, or test vector. |
| 0.2.4 | 2026-06-10 | Align proof context binding with ZKA v0.6.2-draft transaction-absent work-attestation bundles. `ProofContext` is now profile-defined and hash-based, preserving verifier-session contexts while allowing AFP `session_context` to bind ZKC proofs carried in pure Coord/work-attestation bundles. Adds non-custodial delegated proof generation, service-boundary requirements, and sealed/minimized issuer audit mappings for credential rebinding. ZKA remains authoritative for `zka:bundle:v1` substantiveness and `coord_proof` verification. |
| 0.2.5 | 2026-06-11 | Registry governance: added §4.2a (reference registry layout, advisory/non-exclusive/immutable-version constraints, local-copy operation, membership-is-not-trust conformance hook) anchoring the in-repo `registry/` and `docs/zkc_predicate_registry_governance.md`. Normative deltas restate §1.4 Safeguards 1/4 for registries; no change to credentials, circuits, proofs, or test vectors. Same-day addendum: non-normative §8.4 metadata-leakage pointer to `docs/zkc_metadata_leakage_threat_model.md` (no normative change). |
| 0.3.0 | 2026-06-13 | **Verifier accountability.** Added Safeguard 6 — Verifier Accountability (§1.4, mirrored normatively from ZKA §1.6), the first safeguard binding the *counterparty* rather than the operator. Added the `zkc:context:purpose-bound:v1` profile binding declared purpose into the proof context via `purposeTag` (§2.2); the Authenticated Proof Request (§5.5); the holder-custodied Disclosure Receipt (§5.6); the plaintext-disclosure scope rule (§5.7); and the normative residual limits — decision-accountability ceiling, verifier-identity continuity, verifier-deniability cost (§5.8). Added the verifier-side authenticated-request pre-step with `UNSIGNED_REQUEST` / `PURPOSE_MISMATCH` structured errors (§6.2) and the `safeguard-6-*` executable conformance vectors plus purpose-bound golden KATs (§9.2). No change to existing circuits, credentials, notes, bundles, or proof envelopes; all prior proofs remain valid instances and existing `STALE_PROOF` / `CONTEXT_MISMATCH` semantics are unchanged. |
| 0.3.1-draft | 2026-06-15 | Co-publication cross-reference harmonization: the §2.2 work-attestation-bundle reference is retargeted from ZKA v0.6.2 to **ZKA v0.7** (the co-published ZKA revision). No change to credentials, circuits, proofs, contexts, conformance, or test vectors — ZKC v0.3.0's verifier-accountability machinery (Safeguard 6, Authenticated Proof Request §5.5, Disclosure Receipt §5.6, purpose-bound context §2.2) already supports unknown-counterparty verification with no modification. See the AFP ADR for the cross-spec unknown-counterparty trust-model record. |
| 0.3.2-draft | 2026-07-02 | Corrects the §8.2 privacy-properties claim for `holderCommitment`: current presentations are pseudonymous but linkable by equality when the stable commitment is public. Adds the multi-show unlinkability ADR pointer and records the scoped-pseudonym direction for a future presentation-profile change. |
| 0.4.0-draft | 2026-07-02 | **Presentation-profile ladder** (implements amended ADR 0001). Adds §5.9 Presentation Profiles (normative): the three profiles (`zkc:presentation:anonymous:v1` default, `:scoped:v1`, `:linkable:v1`), the pseudonym/scope/verifier-identity derivations, the APR `presentation` block, per-profile Disclosure Receipts, the verifier rules with new structured errors `PROFILE_MISMATCH` / `SCOPE_MISMATCH` / `PROFILE_NOT_ACCEPTED`, and the public-input determinism invariant as a MUST. Documents the `zkc:proof:v2` envelope (`presentationBinding`, no `holderBinding`) in §6.1 and updates §8.2 (anonymous profile removes the linkable anchor from default presentations; the equality-linkability limitation applies to v1/linkable envelopes, governed by profile choice). v1 circuits/encoders/envelopes/registry entries stay byte-for-byte frozen; all changes are additive. |
| 0.4.1-draft | 2026-08-05 | Documents the protocol-family boundary between ZKC eligibility, ZKM authorization, and ZKA settlement; assigns `zkc/*` and `zkm/*` domain-namespace ownership; identifies `ProofContextProfile` as the extension point for a future ZKM-defined profile; and clarifies that ZKC delegated proving and `delegateViewing` convey neither mandate nor spending authority. Documentation only: no change to credentials, circuits, schemas, proof envelopes, presentation profiles, conformance, or test vectors. |

---

## License

This specification is released under the Apache 2.0 License.

### Patent Non-Assertion Covenant

The Apache 2.0 patent grant (License §3) covers patent claims necessarily infringed by a contribution alone or by its combination with the Work it was submitted to. An independent implementation of this specification — one written from the specification text without deriving from any reference code — falls outside that scope, and so is not clearly covered by that grant. The following covenant, modeled on the Open Web Foundation Agreement (OWFa) 1.0 non-assert and the patent commitment of the Community Specification License 1.0, closes that gap. By submitting a contribution to this specification (for example, a pull request modifying this document), each contributor accepts and makes this covenant for every version of this specification that incorporates its contribution.

Each contributor to this specification irrevocably covenants, on behalf of itself and its successors and assigns, not to assert any Essential Claims against any party for making, having made, using, selling, offering for sale, importing, or distributing a Conformant Implementation of this specification. **Essential Claims** are patent claims owned or controlled by the contributor — now or in the future, including claims later acquired — that are necessarily infringed by implementing the required portions (those designated MUST, REQUIRED, or SHALL) of a version of this specification to which the contributor contributed. "Necessarily infringed" follows the W3C Patent Policy definition of Essential Claims: it applies only where no commercially reasonable non-infringing alternative exists, and it excludes claims covering implementation choices this specification leaves open and technologies this specification merely references rather than describes in detail. A **Conformant Implementation** is any implementation that conforms to those required portions — whether or not it derives from any contributor's code or specification text; where an implementation forms part of a larger work, this covenant extends only to the portions that so conform. This covenant is royalty-free and worldwide, and supplements — never limits — the rights granted under the Apache 2.0 License.

This covenant runs with the Essential Claims: it is intended to bind any future owner, assignee, or exclusive licensee that acquires the right to enforce them, and a contributor that transfers a patent containing Essential Claims satisfies this obligation by notifying the transferee of this covenant. The covenant is suspended with respect to any party that asserts a patent infringement claim alleging that a Conformant Implementation of this specification infringes that party's patents (excluding claims brought defensively in response to a prior such assertion by a contributor or any successor or assignee bound by this covenant), for as long as that assertion is maintained.

---

*ZKC: User-controlled compliance for privacy-preserving systems.*

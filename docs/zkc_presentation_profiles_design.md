# ZKC Presentation Profiles — Implementation Design

**Status:** Design for implementation (implements amended ADR 0001)
**Date:** 2026-07-02
**ADR:** [docs/adr/0001-multi-show-unlinkable-presentations.md](adr/0001-multi-show-unlinkable-presentations.md)

This document is the normative design for the presentation-profile ladder. The corresponding `zkc_specification.md` sections (and a version bump to v0.4.0-draft) land with the implementation, consistent with this design.

---

## 1. Profiles

| Profile identifier | Public handle | Default? |
|---|---|---|
| `zkc:presentation:anonymous:v1` | none | **yes** |
| `zkc:presentation:scoped:v1` | `presentation_pseudonym` + `scope_id` | requested via APR |
| `zkc:presentation:linkable:v1` | global `holder_commitment` | explicit consent; = legacy v1 surfaces |

The escrowed auditor-linkable profile is **out of scope** (separate ADR).

**Implementation strategy in one paragraph.** The v2 circuit family moves `holder_commitment` from public input index 0 to a private witness, and adds two public inputs: `presentation_pseudonym` and `scope_id`. A single sentinel rule makes one circuit serve both new profiles: `scope_id == 0` means *anonymous* (the circuit then constrains `presentation_pseudonym == 0`, so the "handle" is a constant carrying no holder information); `scope_id != 0` means *scoped* (the circuit constrains `presentation_pseudonym == poseidon3(DOMAIN_ZKC_PRESENTATION_SCOPE, cbk, scope_id)`). Unaffected linkable predicates retain their existing v1 circuit/envelope family, grandfathered and consent-gated. Jurisdiction and remaining-predicate linkable requests instead use the v3 successors required by the sorted-neighbour exclusion update below; their v1 identities are historical only. A malicious verifier that forces `scope_id = 0` merely downgrades itself to anonymous — the failure direction is *more* privacy, never less.

**Sorted-neighbour exclusion update.** For jurisdiction exclusion and sanctions
clearance, v1/v2 circuit identities are historical: they retain no
in-circuit constraint that the two sorted-neighbour paths have consecutive
indices. Jurisdiction current generation uses v3 linkable
(`zkc_jurisdiction_v3`) and v4 anonymous/scoped (`zkc_jurisdiction_v4`).
The four remaining predicates have a stricter current boundary: published
v3/v4 identities bind `flagRequired`, but their sanctions path still lacks
exact adjacency and their issuer digest omits `validFrom`. New linkable
remaining-predicate requests therefore use `zkc_remaining_predicates_v7` and
`:v7` proof types; new anonymous or scoped requests use
`zkc_remaining_predicates_v8` and `:v8` proof types. v7/v8 enforce
`successor_path_index == predecessor_path_index + 1` and require the matching
credential schema `zkc:cred:{accreditation,source,tax,sanctions}:v2`, whose
issuer digest is `poseidon4(poseidon4(holder, credential_id, predicate_type,
valid_from), claim0, claim1, valid_until)`. That assertion is necessary but
not self-sufficient: holders and verifiers must also derive the unique
canonical sorted root from the signed APR set before proving or accepting.
Canonical construction makes consecutive indices value-adjacent; the circuit
makes that adjacency part of the proof.

## 2. Derivations

All new domain constants follow the existing `derive_domain` pattern (`python/zkc_crypto/kdc.py`, mirrored in `noir/zkc_lib/src/lib.nr`) and are pinned by assertion + golden vector:

```text
DOMAIN_ZKC_PRESENTATION_SCOPE = derive_domain("zkc/presentation-scope:v1")
DOMAIN_ZKC_SCOPE              = derive_domain("zkc/scope:v1")
DOMAIN_ZKC_VERIFIER_ID        = derive_domain("zkc/verifier-id:v1")
```

**Presentation pseudonym** (in-circuit, Poseidon — must be provable):

```text
presentation_pseudonym = poseidon3(DOMAIN_ZKC_PRESENTATION_SCOPE, cbk, scope_id)
```

**Verifier identity** (native only — never proven in-circuit, so the cheap Blake2b-to-field reduction used by `derive_domain` applies; input is the APR signer's SEC1 compressed public key):

```text
verifier_identity = hash_bytes_to_field("zkc/verifier-id:v1", sec1_compressed(apr_verifier_pubkey))
```

**Scope id** (native only; computed independently by holder and verifier — the holder NEVER accepts a verifier-supplied opaque `scope_id`):

```text
scope_id = hash_bytes_to_field(
    "zkc/scope:v1",
    field_be_bytes(verifier_identity)
      || field_be_bytes(string_to_field(scope_policy))
      || u64_be_bytes(rotation_epoch),
)
```

- `scope_policy` is the APR-declared policy string (e.g. `"verifier"`, or `"protocol:<name>"` for a named scope local to the APR signer).
- Named `protocol:<name>` scopes still include the pinned signer key. They do not share pseudonyms across distinct signing identities; a shared multi-verifier scope is a future extension requiring separate governance. Holder consent and verifier declaration remain mandatory.
- `rotation_epoch = floor(timestamp / rotation_epoch_seconds)` when the APR declares `rotationEpochSeconds > 0`, else `0`. Rotation therefore lives in `scope_id` construction; the pseudonym derivation and circuits never change with rotation policy. `timestamp` is the **shared session-context timestamp** (the APR/proof-context value), never wall clock, so holder and verifier derive the same epoch by construction — divergence fails closed as `SCOPE_MISMATCH`. Residual: a verifier may choose an APR timestamp near an epoch's tail to smear recognition slightly past the boundary; this is bounded by the APR freshness window (`expiresAt` + nonce replay, §5.5) and is immaterial whenever `rotationEpochSeconds` ≫ that window — deployments SHOULD keep rotation periods much longer than APR freshness.
- A derived `scope_id` of exactly `0` is rejected and re-derived is not attempted (probability ≈ 2⁻²⁵⁴; the check exists so the anonymous sentinel can never be produced by accident).

## 3. Envelope v2

New envelope version `zkc:proof:v2` (`schemas/compliance-proof-v2.schema.json`). Differences from v1:

```jsonc
{
  "version": "zkc:proof:v2",
  "metadata": { /* unchanged from v1 */ },
  "proofs": [ /* v2 proof types, see §4 */ ],
  "presentationBinding": {
    "profile": "zkc:presentation:anonymous:v1" | "zkc:presentation:scoped:v1",
    // present iff profile == scoped:
    "pseudonym": "0x…",   // == presentation_pseudonym public input of every proof
    "scopeId": "0x…"      // == scope_id public input of every proof
  }
  // NOTE: no "holderBinding" — that field exists only in v1 (linkable) envelopes
}
```

- `zkc:proof:v1` envelopes (with `holderBinding.commitment`) remain valid and are classified as `zkc:presentation:linkable:v1`. A verifier policy that sets `TrustPolicy.accepted_profiles` explicitly accepts a v1 envelope only when it lists the linkable profile; a policy that leaves it unset keeps accepting v1 envelopes for backward compatibility (§6, `VerifierTrustPolicy.accepts_linkable_envelopes`).
- Each envelope version carries only its own circuit family: linkable-family circuits (encoder declares `holder_commitment` / `old_holder_commitment`) only in v1, presentation-family circuits (encoder declares `presentation_pseudonym` / `old_presentation_pseudonym`) only in v2, and every evaluated proof entry's `publicInputs` carries exactly its encoder-declared names (§6).
- The envelope-level `presentationBinding` and the per-proof public inputs are cross-checked (§6): profile ⇔ public-input shape consistency is what prevents cross-profile replay.

The initial presentation migration introduced `zkc:proof:kyc:v2`,
`zkc:proof:jurisdiction:v2`, `zkc:proof:accreditation:v2` (and siblings),
`zkc:proof:rebind:v2`, and aggregation `zkc:proof:aggregate:v2`. Those
remaining-predicate v2 identities are historical. Current anonymous/scoped
accreditation, source, tax, and sanctions generation uses the distinct `:v8`
proof types paired with `zkc_remaining_predicates_v8`; linkable generation
uses their `:v7` counterparts. Published v5/v6 identities remain historical
verification-compatibility surfaces.

## 4. Public-input shapes (v2 circuits)

### 4.1 `zkc_kyc` v2 (pattern for jurisdiction / remaining_predicates)

| Index | Name | Type | v1 → v2 change |
|---|---|---|---|
| 0 | `presentation_pseudonym` | Field | **replaces** `holder_commitment` |
| 1 | `scope_id` | Field | **new** |
| 2 | `claim_binding` | Field | unchanged (preimage keeps `proof_context`, `timestamp` — load-bearing, see ADR determinism invariant) |
| 3 | `proof_context` | Field | unchanged |
| 4 | `accumulator_root` | Field | unchanged |
| 5 | `accumulator_epoch` | u64 | unchanged |
| 6 | `timestamp` | u64 | unchanged |
| 7 | `current_epoch` | u64 | unchanged |
| 8–9 | `issuer_public_key_{x,y}` | [u8;32] | unchanged |

`holder_commitment` becomes a **private witness**; the existing constraint `derive_holder_commitment(cbk) == credential.holder_commitment` is retained verbatim, now over private values only.

New v2 constraints (identical block in every v2 predicate circuit):

```text
if scope_id == 0 { assert presentation_pseudonym == 0 }            // anonymous
else { assert presentation_pseudonym ==
       poseidon3(DOMAIN_ZKC_PRESENTATION_SCOPE, cbk, scope_id) }   // scoped
```

`zkc_jurisdiction` v2 and `zkc_remaining_predicates` v2 apply the same index-0/1 replacement to their 11-field shapes. For sorted-neighbour exclusion these identities are historical only. Jurisdiction v4 is the current anonymous/scoped replacement and jurisdiction v3 retains the linkable shape with adjacency. For accreditation, source, tax, and sanctions, remaining-predicate v7 retains the linkable v1 public-input shape and v8 uses this v2 presentation shape; both add the combined raw-code, exact sanctions-adjacency, and validity-bound `:v2` credential-digest protections. v1–v6 remaining-predicate proof identities remain resolvable only for historical verification and MUST NOT be selected by current generation.

### 4.2 `zkc_credential_rebind` v2

| Index | Name | v1 → v2 change |
|---|---|---|
| 0 | `old_presentation_pseudonym` | **replaces** `old_holder_commitment` |
| 1 | `new_presentation_pseudonym` | **replaces** `new_holder_commitment` |
| 2 | `scope_id` | **new** (shared by old and new pseudonyms) |
| 3–5 | `credential_id`, `issuer_id_hash`, `schema_id_hash` | unchanged |
| 6–8 | `proof_context`, `timestamp`, `claim_binding` | unchanged |

Old/new global commitments become private witnesses; the circuit keeps all four derivation assertions private (`derive_holder_commitment(old_cbk) == old_holder_commitment`, same for new, `old != new`, credential bound to old) and adds the two pseudonym constraints plus `assert(old_presentation_pseudonym != new_presentation_pseudonym)`. Rebind is verifier-facing continuity by definition, so **rebind v2 requires `scope_id != 0`** — there is no anonymous rebind presentation. `claim_binding` v2 commits to the pseudonyms, not the commitments: `compute_claim_binding_3(old_pseudonym, new_pseudonym, credential_id, proof_context, timestamp)`.

> **Security containment (2026-09-06).** Neither this v2 statement nor the v1 statement it re-keys (nor their binding-contract-v2 successors `zkc:proof:credential_rebind:v2` / `zkc:proof:rebind:v3`) authenticates the credential: `credential_holder_commitment`, `credential_issuer_id_hash`, `credential_schema_id_hash`, and both validity bounds are unconstrained private witnesses, and no issuer signature or accumulator membership is verified. "Credential bound to old" above is therefore a statement about a prover-chosen value, not about an issued credential. All four identities are contained — holders never generate them and verifiers reject them with `UNAUTHENTICATED_CREDENTIAL` — and the presentation-ladder design in this section is retained only as the historical record of their public-input shape. See spec §4.5.

### 4.3 `zkc_aggregation` v2

The v2 circuit requires `scope_id != 0`. Public input 2 becomes `presentation_pseudonym` (replacing `holder_commitment`), public input 3 adds `scope_id`, and the circuit checks two per-slot equalities:

```text
assert(proof_presentation_pseudonyms[i] == presentation_pseudonym)
assert(proof_public_inputs[i][0] == presentation_pseudonym)
```

The accumulator seed uses the presentation pseudonym. Reference packing hashes the whole component public-input JSON into each slot field, so it cannot supply the pseudonym in field 0. The circuit also performs no recursive proof verification. Reference holders emit aggregation commitments only in linkable v1 envelopes, and verifiers reject aggregation blocks in every v2 envelope with `INVALID_AGGREGATION` (spec §7.3). Scoped holder continuity is established by individually verified proofs.

## 5. APR, consent, and receipts

### 5.1 APR presentation request

The APR `request` object gains an optional `presentation` block, covered by the existing APR signature (`apr_digest_from_dict` extends to include it):

```jsonc
"presentation": {
  "profile": "zkc:presentation:scoped:v1",
  "scopePolicy": "verifier",          // or "protocol:<name>"
  "rotationEpochSeconds": 0            // 0 = no rotation
}
```

- Absent block ⇒ `zkc:presentation:anonymous:v1`. Anonymity is the ambient default; continuity is always an explicit, signed, purpose-bound request.
- `profile: linkable` in an APR is valid only alongside the existing v1 consent surfaces and yields a v1 envelope.

### 5.2 Holder-side rules (`zkc_holder/client.py`)

1. Scoped requests require an **authenticated** APR (Safeguard 6). An
   unauthenticated request cannot establish `verifier_identity`, so it can
   only be answered anonymously (or refused).
2. The holder derives `scope_id` itself (§2) from the APR signer key. A
   verifier-supplied literal `scope_id` anywhere in the request is a
   protocol error.
3. `scopePolicy` starting with `"protocol:"` requires the distinct consent
   flag `allow_protocol_scope=True` on the holder's `ProofRequest`. The name
   remains within the signer's identity namespace; it does not create a shared
   pseudonym across independently keyed verifiers.
4. The holder MAY downgrade scoped → anonymous (policy hook); it MUST NOT
   silently upgrade anonymous → scoped or scoped → linkable.

### 5.3 Disclosure Receipts

The receipt `response` binds **the active profile's handle, never more**:

| Profile | `response` contents |
|---|---|
| anonymous | `contextValue`, `answeredProofTypes` |
| scoped | + `presentationPseudonym`, `scopeId` |
| linkable (v1 path) | existing v1 shape (`holderCommitment`, …) — unchanged |

`_answer_receipt` in `zkc_holder/client.py` branches on the active profile; the global `holderCommitment` never enters a v2 receipt.

## 6. Verifier rules (`zkc_verifier/verifier.py`)

New structured error codes: `PROFILE_MISMATCH`, `SCOPE_MISMATCH`, `PROFILE_NOT_ACCEPTED`.

`verify()` **version-dispatches** on the envelope: a `zkc:proof:v1` envelope (has `holderBinding`, no `presentationBinding`) takes the v1 path — it is implicitly the linkable profile. Only a `zkc:proof:v2` envelope runs the profile machinery below. (Corrected 2026-07-02: enforcing "linkable requires consent" by *rejecting* v1 envelopes at verify time would break backward compatibility; the linkable-consent requirement lives in the holder/APR emission layer, not in verify-side rejection. Refusing v1/linkable at verify time is an OPTIONAL policy knob, off by default.)

The knob is `TrustPolicy.accepted_profiles` itself (added 2026-10-04): left unset, v1 envelopes keep verifying; set explicitly, a v1 envelope is `PROFILE_NOT_ACCEPTED` unless the set lists `zkc:presentation:linkable:v1`. On both paths every evaluated proof entry is also bound to its envelope generation (security review 2026-10-04): its `publicInputs` must carry exactly the encoder-declared names (`MALFORMED_PROOF` otherwise), its circuit family — derived from the encoder's holder-handle inputs — must match the envelope version (`PROFILE_MISMATCH` otherwise), and every authenticated rebind type is routed to the rebind rules from either envelope. Without this a presenter could wrap a presentation-family proof in a v1 envelope beside an injected, unconstrained `holder_commitment`. On the authenticated path an envelope more linkable than the APR's declared profile is `PROFILE_MISMATCH`.

For a **v2 envelope**, in `verify` / `verify_authenticated`:

1. **Policy gate.** `presentationBinding.profile ∈ TrustPolicy.accepted_profiles`
   (default `{anonymous, scoped}`) else `PROFILE_NOT_ACCEPTED`. v1 envelopes
   meet the same gate only under an explicitly configured `accepted_profiles`
   (see above).
2. **Shape consistency** (anti-replay). For every proof entry:
   - anonymous ⇒ `presentation_pseudonym == 0 && scope_id == 0`;
   - scoped ⇒ `scope_id != 0`, `presentation_pseudonym == presentationBinding.pseudonym`,
     `scope_id == presentationBinding.scopeId`.
   Any mismatch ⇒ `PROFILE_MISMATCH`. This replaces the v1
   envelope-vs-proof `holder_commitment` consistency check.
3. **Scope recomputation** (scoped + authenticated path only). The verifier
   recomputes `scope_id` from its own identity key, the APR `scopePolicy`,
   and the rotation epoch; a mismatch ⇒ `SCOPE_MISMATCH`. All scopes include
   a locally pinned signing identity. Declaring a named protocol scope is an
   additional gate and never bypasses that identity check.
4. **Rebind / aggregation.** `_verify_rebind` parses old/new pseudonyms and
   checks `old != new` plus `scope_id` consistency with the envelope.
   Any aggregation block in a v2 envelope yields `INVALID_AGGREGATION`.

## 7. Backward compatibility

- v1 envelopes, v1 proof types, v1 circuits, v1 encoder schemas: classified linkable and consent-gated at verifier policy. A v1 aggregate can cover only requested, individually verified proofs (spec §7.3).
- For jurisdiction exclusion and sanctions clearance specifically, v1/v2 circuit identities are deprecated for **new** proofs: their sorted-neighbour constraints did not prove that the two paths were adjacent. They are retained solely for historical proof resolution. The v3 linkable and v4 anonymous/scoped identities are the current selections, and enforce consecutive neighbour indices in-circuit. Every new exclusion proof still requires canonical root construction from the authenticated APR; canonical construction and circuit adjacency are jointly required.
- **Circuit versions coexist as separate packages** (corrected 2026-07-02 after implementation showed in-place evolution is infeasible). A SNARK proof is bound to its circuit's verification key, so a `:v1` proof — which *is* the linkable profile, a live offered mode, not merely a back-compat artifact — can only ever verify against the unchanged v1 VK. Evolving a circuit in place would change its VK and permanently break every `:v1` proof, and it also breaks the registry entry (which pins `sourceSha256`/`acirHash`/`vkHash`, immutable) and the Python verifier/backend (which load the canonical encoder at runtime to resolve `:v1` proof types, fail-closed).
- Therefore v1 packages, encoders, registry entries, and Python v1 paths stay **byte-for-byte frozen and untouched.** v2 is added as *new* Noir packages `noir/<circuit>_v2/` (registered in `noir/Nargo.toml`), new encoders `schemas/public-inputs/<circuit>_v2.json` (each maps to its own live v2 package under the existing validator — no `frozen/` archive, no validator surgery), new `:v2` proof types, new Python v2 witness-assembly + verifier branches selected by profile, and new registry predicate entries.
- `zkc_lib` gains the shared `assert_presentation_binding` / `derive_presentation_pseudonym` helpers — additive only: it does not touch any circuit's pinned `main.nr` source hash, and the helpers are unused by v1 circuits so v1 ACIR/VK are unchanged.
- **Registry:** proof types are fail-closed — the holder refuses any proof type not published by a registry entry (`OPAQUE_PREDICATE_REFUSED`). Each v2 predicate therefore needs its own `registry/predicates/<id>/<ver>/entry.json` (a *new* entry; immutability only forbids mutating existing ones), carrying a freshly-compiled `acirHash`/`vkHash`/`vkSha256` from `scripts/build_artifact_manifest.py` and a `review.status` reflecting its true state (`draft` — unreviewed and not self-attested) — never copy v1's status or evidence. (The v1 entries themselves carry `self_attested` as of 2026-07-31; none has been independently reviewed.)
- `holderBinding` never appears in a v2 envelope; `presentationBinding` never appears in v1.

## 8. Conformance matrix (minimum vectors)

| Vector | Kind | Asserts |
|---|---|---|
| `presentation-anonymous-unlinkable` | positive | two anonymous presentations of the same credential share **no** holder-derived public value (pseudonym/scope both 0; all other public inputs session-scoped or ecosystem-wide) |
| `presentation-scoped-cross-scope` | **negative** | same credential, two distinct `scope_id`s ⇒ different pseudonyms; equality join fails |
| `presentation-scoped-within-scope` | positive | same credential, same `scope_id`, two sessions ⇒ same pseudonym (repeat recognition) |
| `presentation-scoped-rotation` | positive | same scope, two rotation epochs ⇒ different pseudonyms |
| `presentation-profile-replay` | negative | scoped proof presented under an anonymous `presentationBinding` (and vice versa) ⇒ `PROFILE_MISMATCH` |
| `presentation-scope-mismatch` | negative | scoped proof for scope A presented to authenticated verifier B ⇒ `SCOPE_MISMATCH` |
| `presentation-profile-not-accepted` | negative | v2 envelope whose profile ∉ `accepted_profiles` (e.g. scoped presented to a verifier accepting only `{anonymous}`) ⇒ `PROFILE_NOT_ACCEPTED`. (v1 envelopes are NOT gated by default — the corrected v2-only gate.) |
| `presentation-determinism-invariant` | invariant | across the anonymous vectors, no public input is deterministic in credential-only material; `claim_binding` preimage retains `proof_context` + `timestamp` |
| KATs | golden | pinned `DOMAIN_ZKC_PRESENTATION_SCOPE`, `DOMAIN_ZKC_SCOPE`, `DOMAIN_ZKC_VERIFIER_ID`, a seed-42 `presentation_pseudonym`, and a full `scope_id` derivation |

## 9. Out of scope

- Escrowed auditor-linkable profile (verifiable encryption) — separate ADR.
- Rerandomizable-credential bridging — research track per ADR 0001.
- Revocation accumulator changes — none; the pseudonym is not an accumulator key and witness privacy is unchanged.

Authenticated verification pins its own verifier ID and accepted signing keys, compares the complete signed context and proof age, and records successful APR nonces. See specification §5.5 for the additive signed verification-context extension, legacy 3600-second age rule, and replay-cache lifetime.

A multi-predicate conjunction requires same-holder binding. Linkable envelopes
bind every proof to one holder commitment; scoped envelopes bind every proof
to one in-circuit pseudonym; anonymous envelopes provide no such binding.
Anonymous answers to two or more distinct requested proof types are rejected
with `UNBOUND_COMPOSITE` unless verifier policy explicitly declares them
independent. The holder refuses these answers before consent/proving with
`ANONYMOUS_COMPOSITE_REFUSED`, unless `allow_unlinked_composite=True` is explicit;
per-predicate consent still applies. Neither negotiation nor planning upgrades
an anonymous holder ceiling. Both independence opt-ins require exact booleans.

For a same-holder answer without continuity across fresh contexts, the signed
APR requests scoped `scopePolicy: "session"` and the holder must permit scoped
presentation. The native policy label is `"session:" + canonical_hex(contextValue)`;
it still includes the pinned verifier signing identity. The literal `session:`
prefix is reserved. Fresh session contexts and distinct signing keys produce
distinct scopes/pseudonyms; context reuse repeats the scope. Circuits, encoders
and published identities are unchanged.

# ZKC Public-Input Classification (bound / derived / free)

**Status:** Ratified v1/v2. Normative for every verifier of ZKC proofs.
**Machine-readable source of truth:** `schemas/public-input-bindings/<circuit>.json`
(validated by the exact v1 or v2 schema selected by the sidecar and CI-gated by
`tests/vectors/validate_public_input_encoders.py`). The tables below are transcribed
from those documents — `tests/python/test_public_input_bindings.py` pins every
class in both places, so the two cannot drift silently — and ratified against each
circuit's `main()` `pub` parameter list in `noir/<circuit>/src/main.nr`.

## 1. Purpose

This document is the written request-binding contract that the authenticated
request-binding chokepoint in the ZKC verifier implements (punch-list P1) and that
`verifyTypeSpecificRequirements` conformance (punch-list P3) is measured against.
For every public input of every committed circuit it answers one question: **who is
allowed to choose this value, and what must the verifier compare it against before
accepting the proof?**

The classification is built against each circuit's **public-input list**, never
against the claim-binding preimage. The two are not the same set, and the
difference is exactly where soundness escapes: in `zkc_remaining_predicates` the
claim-binding preimage is `(predicate_type, required_0, required_1, proof_context,
timestamp)` while `set_root` is a public input **outside** that preimage. A
verifier that "checks the claim binding" and stops has never checked the
membership set at all — the prover can supply a root for a set it invented. Every
routine that generalizes over public inputs MUST therefore enumerate the `pub`
list, then consult this contract per field.

The converse escape also exists and is recorded where it occurs: a **request
parameter with no public-input coverage** cannot be enforced by any verifier
check. The immutable v1/v2 remaining-predicate circuits have this limitation for
`flagRequired`; a verifier MUST reject a positive legacy request. Their additive
v3-v8 successors keep the flag private but fold its exact boolean value into the
public claim binding, making request/witness disagreement verifiable without
placing verifier policy in the issuer credential digest.

## 2. Classes

Every public input carries exactly one class:

- **bound** — the verifier MUST validate the field against a value it knows
  independently of the prover, and reject on mismatch. The `source` reference
  names where the expected value comes from; the optional `check` field names the
  comparison kind — `equals` (the default), `member_of` an authenticated set
  (e.g. the issuer-key allowlist, checked as one `(x, y)` pair via `group`), or
  `policy_range` against a policy bound (e.g. the accumulator epoch-lag window).
- **derived** — the verifier MUST recompute the field from the references in
  `from` and reject on mismatch. The mandatory `note` states the exact
  recomputation, including any interior hashing of the referenced values (e.g.
  KYC folds `requiredAttributes` through `attribute_flags_hash` before
  `compute_claim_binding_2`). A derived check proves the value is
  **reproducible**; its request-binding force comes only from its `param:` /
  `context:` / bound references — a derived field whose preimage includes free
  (prover-chosen) inputs commits to their integrity but does not bind them to the
  request, and it never substitutes for the direct comparison of a bound field
  that happens to appear in its preimage.
- **free** — the prover chooses the value; the verifier has no request-side
  expectation. Every free field carries a **written justification** of why that is
  sound (typically: the value is attested in-circuit by the issuer signature, or
  is committed by the claim binding so it cannot be swapped, or is the proof's
  intended output). CI fails on a free field without one. Under the v2 binding
  contract, a free scalar `Field` may additionally declare
  `pinnedBy: "param:<camelName>"`. This is a
  conditional request pin: when that parameter is present, the verifier MUST
  require it to equal the public input; when it is absent, the public input
  remains free. `pinnedBy` is not valid for bound or derived fields, arrays, or
  integer public inputs, and it MUST name exactly the entry's own `camelName` —
  it is never a general reference or a prose annotation.

**Absent request parameters fail closed.** A `param:` reference on a bound
field's source — or in a derived field's `from` list — is REQUIRED in the
authenticated request: a request that does not carry the parameter MUST be
rejected rather than silently defaulted, unless the entry's own text declares an
explicit expectation for that case (e.g. `set_root` MUST be 0 for accreditation).

### Reference vocabulary

| Prefix | Meaning |
|---|---|
| `context:value`, `context:timestamp` | The authenticated request context (Safeguard 6 APR). |
| `param:<camelName>` | `request.parameters[proofType].<camelName>` from the authenticated request. |
| `envelope:<path>` | An authenticated element of the presentation envelope (holder binding, presentation binding, the proofs list). An element the active profile omits — e.g. `presentationBinding.pseudonym` under the anonymous profile — resolves to the sentinel named in the entry's text (0). |
| `policy:<path>` | Verifier trust policy or verifier-local authenticated state (issuer allowlist, accumulator state, the registry-pinned circuit identity for a proof type). |
| `map:predicateTypes[proofType]` | The proof-type → `predicate_type` map published in the circuit's binding document. |
| `public:<name>` | Another public input of the same circuit. |

**Terminology note.** "Derived" here means *verifier-recomputable*. It is
unrelated to KDC-derived key material (`derive_holder_commitment`,
credential-binding keys), and orthogonal to the ADR-0001 determinism invariant:
that invariant classifies public inputs by *linkability* (deterministic in
credential-only material or not); this contract classifies them by *request
binding* (who fixes the value). Both apply simultaneously — e.g.
`presentation_pseudonym` is the declared linking handle under ADR-0001 **and**
bound to the envelope presentation binding here. The ADR-0002 escrow profile adds
a deterministic-but-escrowed value class to the determinism invariant; when its
circuit lands, its public inputs get classified in this contract like any others.

## 3. Bind by name, never by offset

`zkc_remaining_predicates` v1 orders `(predicate_type, set_root)` at indices 3–4;
v2 orders `(set_root, predicate_type)` at indices 4–5. Same names, different
offsets. Any generic compare-all routine that indexes positionally will compare
the wrong fields across versions and fail open. Consumers MUST resolve fields by
`name` through the encoder document, and MUST consult the binding sidecar by the
same name. The `zkc_crypto.PublicInputBindings` class provides name-keyed access,
the snake_case ↔ camelCase map, and the predicate-type map:

```python
from zkc_crypto import PublicInputBindings

bindings = PublicInputBindings.for_circuit(repo_root, "zkc_remaining_predicates_v2")
bindings.binding_class("set_root")                      # "bound"
bindings.camel_name("set_root")                         # "setRoot"
bindings.snake_name("jurisdictionSetRoot")              # ValueError (wrong circuit)
bindings.predicate_type_for("zkc:proof:sanctions:v2")   # 4
```

### Name layers and the name map

Three JSON layers name the same fields, and they do NOT share a convention:

- a proof entry's **`publicInputs` object is keyed by the snake_case `name`
  itself** (`proof_context`, `jurisdiction_set_root`) — `camelName` MUST NOT be
  used to read it;
- request **`parameters`** are camelCase (`jurisdictionSetRoot`, `setRoot`,
  `requiredLevel`, `disclosedPositions`);
- the v1 and v2 **aggregation envelope blocks** are camelCase (`aggregationCommitment`,
  `inputProofCommitments`, `aggregatedClaimBinding`).

Every binding entry publishes its `camelName` for the latter two layers, and CI
enforces that it equals the mechanical conversion (`jurisdiction_set_root` ↔
`jurisdictionSetRoot`), so the layers can never drift apart silently. The
canonical proof-entry rule is specified in `docs/zkc_specification.md` §6.1, and
CI checks §7's explicit `publicInputs` mappings against the encoder `name`
entries.

### Proof-type → predicate-type map (per-meaning domain separation)

One verification key covers the four `zkc_remaining_predicates` meanings, selected
by the public `predicate_type`. A verifier that accepts any value lets a proof
generated for one meaning satisfy a request for another. The binding documents
publish the map; CI ratifies its values against the `PREDICATE_*` constants
declared in the circuit source and requires the `predicate_type` entry itself to
be bound to `map:predicateTypes[proofType]`; the verifier MUST pin
`predicate_type` to `predicateTypes[proofType]` for the proof entry it is
checking:

| Proof type (v1 / v2) | `predicate_type` |
|---|---|
| `zkc:proof:accreditation:*` | 1 |
| `zkc:proof:source:*` | 2 |
| `zkc:proof:tax:*` | 3 |
| `zkc:proof:sanctions:*` | 4 |

## 4. Why a sidecar, and how it is enforced

Encoder documents (`schemas/public-inputs/*.json`) are **registry-immutable**:
`registry/check_immutability.py` rejects any byte change to an encoder referenced
by a committed registry entry, because they define the wire identity of committed
proofs. The classification is a *verifier-side* contract, so it lives in a
name-keyed sidecar per circuit under `schemas/public-input-bindings/`, leaving
encoder bytes untouched while reserving an additive versioning path. Admission
supports exactly these selector pairs:

- `zkc:public-input-bindings:v1` with
  `https://zkc.dev/schemas/public-input-binding-v1.schema.json`; and
- `zkc:public-input-bindings:v2` with
  `https://zkc.dev/schemas/public-input-binding-v2.schema.json`.

The v2 contract adds structured conditional request pins; v1 does not interpret
or admit `pinnedBy`.
The same history gate derives that sidecar from the committed encoder filename
and byte-protects the complete sidecar plus the exact canonical schema selected
by its version/`$schema` pair.
Existing entry documents need no backfill. A future schema version requires
explicit schema dispatch, selector validation, and history protection before CI
will admit it; adding a new schema file alone is insufficient.

The CI gate (`tests/vectors/validate_public_input_encoders.py`, run by the
`Check & Test` job) fails when:

- an encoder — new or changed — has any public input without a classification,
  or no binding document at all;
- a binding document classifies a field the encoder does not declare, or
  classifies one twice;
- a `free` field lacks a written justification (≥ 40 characters and ≥ 8 words);
- a `bound` field lacks a structured, resolvable `source` reference, or a
  `derived` field lacks a well-formed `from` list or a recomputation `note`, or a
  `public:` reference names a non-existent field, or a `map:` reference points at
  a map the document does not publish;
- a binding entry has an undeclared key (the gate explicitly enforces this
  because its lightweight schema validator does not implement JSON Schema's
  `additionalProperties` / conditional keywords), or a `pinnedBy` declaration is
  not a free scalar `Field` with exactly `param:<that entry's camelName>`;
- a `camelName` drifts from the mechanical conversion of `name`;
- a circuit exposing `predicate_type` fails to publish a `predicateTypes` map
  covering its proof types exactly, with distinct meanings that match the
  `PREDICATE_*` constants in the circuit source — or classifies the selector as
  anything but bound-to-the-map.

`tests/python/test_public_input_bindings.py` covers the same contract from the
reference test suite and additionally pins the ratified class of every field
(the golden table). That table is review aid and current-state consistency
evidence; historical immutability comes from the byte comparison above, so a
coordinated sidecar/table/documentation rewrite still fails.

## 5. Ratified per-circuit tables

Legend: **B** = bound, **D** = derived, **F** = free (justification in the
binding document, abbreviated here). Non-default check kinds are noted as
`(member_of)` / `(policy_range)`. `#` is the entry index in the (immutable)
encoder order — shown for reference only; consumers bind by name.

### `zkc_kyc`

KYC level/attribute predicate, v1 (public holder commitment). Proof types: `zkc:proof:kyc:v1`.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `holder_commitment` | `Field` | **B** | `envelope:holderBinding.commitment` |
| 1 | `claim_binding` | `Field` | **D** | `param:requiredLevel`, `param:requiredAttributes`, `context:value`, `context:timestamp` |
| 2 | `proof_context` | `Field` | **B** | `context:value` |
| 3 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 4 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` (policy_range) |
| 5 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 6 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 7 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 8 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |

- **`claim_binding`** — compute_claim_binding_2(requiredLevel, attribute_flags_hash(requiredAttributes), proof_context, timestamp); the verifier MUST recompute it from the request parameters and reject on mismatch.

### `zkc_kyc_v2`

KYC predicate under presentation profiles (pseudonym + scope). Proof types: `zkc:proof:kyc:v2`.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `presentation_pseudonym` | `Field` | **B** | `envelope:presentationBinding.pseudonym` |
| 1 | `scope_id` | `Field` | **B** | `envelope:presentationBinding.scopeId` |
| 2 | `claim_binding` | `Field` | **D** | `param:requiredLevel`, `param:requiredAttributes`, `context:value`, `context:timestamp` |
| 3 | `proof_context` | `Field` | **B** | `context:value` |
| 4 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 5 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` (policy_range) |
| 6 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 7 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 8 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 9 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |

- **`claim_binding`** — compute_claim_binding_2(requiredLevel, attribute_flags_hash(requiredAttributes), proof_context, timestamp); the verifier MUST recompute it from the request parameters and reject on mismatch.

### `zkc_jurisdiction`

Jurisdiction set membership/exclusion, v1. Proof types: `zkc:proof:jurisdiction:v1`.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `holder_commitment` | `Field` | **B** | `envelope:holderBinding.commitment` |
| 1 | `claim_binding` | `Field` | **D** | `public:jurisdiction_set_root`, `public:membership_type`, `param:requiredClaimType`, `context:value`, `context:timestamp` |
| 2 | `proof_context` | `Field` | **B** | `context:value` |
| 3 | `jurisdiction_set_root` | `Field` | **B** | exclusion: `derived:jurisdictionCanonicalSet` + `param:jurisdictionSetRoot`; inclusion: derived when codes are present, otherwise direct parameter |
| 4 | `membership_type` | `u8` | **B** | `param:membershipType` |
| 5 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 6 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` (policy_range) |
| 7 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 8 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 9 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 10 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |

- **`claim_binding`** — compute_claim_binding_3(jurisdiction_set_root, membership_type, requiredClaimType, proof_context, timestamp); recomputed from the request-bound values, so it does not substitute for the direct set-root and membership-type comparisons.
- **`jurisdiction_set_root`** — for exclusion, independently derive the canonical root from the signed APR's `jurisdictionCanonicalSet`, require equality with `jurisdictionSetRoot`, and compare the derived value directly with this public input. Inclusion retains the legacy direct-root shape, but uses the same derivation when canonical codes are supplied.

### `zkc_jurisdiction_v2`

Jurisdiction predicate under presentation profiles. Proof types: `zkc:proof:jurisdiction:v2`.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `presentation_pseudonym` | `Field` | **B** | `envelope:presentationBinding.pseudonym` |
| 1 | `scope_id` | `Field` | **B** | `envelope:presentationBinding.scopeId` |
| 2 | `claim_binding` | `Field` | **D** | `public:jurisdiction_set_root`, `public:membership_type`, `param:requiredClaimType`, `context:value`, `context:timestamp` |
| 3 | `proof_context` | `Field` | **B** | `context:value` |
| 4 | `jurisdiction_set_root` | `Field` | **B** | exclusion: `derived:jurisdictionCanonicalSet` + `param:jurisdictionSetRoot`; inclusion: derived when codes are present, otherwise direct parameter |
| 5 | `membership_type` | `u8` | **B** | `param:membershipType` |
| 6 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 7 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` (policy_range) |
| 8 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 9 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 10 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 11 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |

- **`claim_binding`** — compute_claim_binding_3(jurisdiction_set_root, membership_type, requiredClaimType, proof_context, timestamp); recomputed from the request-bound values, so it does not substitute for the direct set-root and membership-type comparisons.
- **`jurisdiction_set_root`** — for exclusion, independently derive the canonical root from the signed APR's `jurisdictionCanonicalSet`, require equality with `jurisdictionSetRoot`, and compare the derived value directly with this public input. Inclusion retains the legacy direct-root shape, but uses the same derivation when canonical codes are supplied.

### `zkc_jurisdiction_v3`

Sorted-neighbour-safe linkable jurisdiction successor. Proof types: `zkc:proof:jurisdiction:v3`.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `holder_commitment` | `Field` | **B** | `envelope:holderBinding.commitment` |
| 1 | `claim_binding` | `Field` | **D** | `public:jurisdiction_set_root`, `public:membership_type`, `param:requiredClaimType`, `context:value`, `context:timestamp` |
| 2 | `proof_context` | `Field` | **B** | `context:value` |
| 3 | `jurisdiction_set_root` | `Field` | **B** | exclusion: `derived:jurisdictionCanonicalSet` + `param:jurisdictionSetRoot`; inclusion: derived when codes are present, otherwise direct parameter |
| 4 | `membership_type` | `u8` | **B** | `param:membershipType` |
| 5 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 6 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` (policy_range) |
| 7 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 8 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 9 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 10 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |

- **`claim_binding`** — compute_claim_binding_3(jurisdiction_set_root, membership_type, requiredClaimType, proof_context, timestamp); recomputed from the request-bound values, so it does not substitute for the direct set-root and membership-type comparisons.
- **`jurisdiction_set_root`** — exclusion additionally requires the circuit's predecessor and successor membership paths to be adjacent in the canonical sorted set; the verifier independently derives and directly compares the signed canonical root.

### `zkc_jurisdiction_v4`

Sorted-neighbour-safe jurisdiction successor under anonymous/scoped presentation profiles. Proof types: `zkc:proof:jurisdiction:v4`.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `presentation_pseudonym` | `Field` | **B** | `envelope:presentationBinding.pseudonym` |
| 1 | `scope_id` | `Field` | **B** | `envelope:presentationBinding.scopeId` |
| 2 | `claim_binding` | `Field` | **D** | `public:jurisdiction_set_root`, `public:membership_type`, `param:requiredClaimType`, `context:value`, `context:timestamp` |
| 3 | `proof_context` | `Field` | **B** | `context:value` |
| 4 | `jurisdiction_set_root` | `Field` | **B** | exclusion: `derived:jurisdictionCanonicalSet` + `param:jurisdictionSetRoot`; inclusion: derived when codes are present, otherwise direct parameter |
| 5 | `membership_type` | `u8` | **B** | `param:membershipType` |
| 6 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 7 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` (policy_range) |
| 8 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 9 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 10 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 11 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |

- **`claim_binding`** — compute_claim_binding_3(jurisdiction_set_root, membership_type, requiredClaimType, proof_context, timestamp); recomputed from the request-bound values, so it does not substitute for the direct set-root and membership-type comparisons.
- **`jurisdiction_set_root`** — exclusion additionally requires the circuit's predecessor and successor membership paths to be adjacent in the canonical sorted set; the verifier independently derives and directly compares the signed canonical root.

### `zkc_remaining_predicates`

Shared profile circuit for accreditation / source-of-funds / tax-residency / sanctions-clearance, v1. One VK, four meanings selected by `predicate_type`. Proof types: `zkc:proof:accreditation:v1`, `zkc:proof:source:v1`, `zkc:proof:tax:v1`, `zkc:proof:sanctions:v1`.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `holder_commitment` | `Field` | **B** | `envelope:holderBinding.commitment` |
| 1 | `claim_binding` | `Field` | **D** | `public:predicate_type`, `param:required0`, `param:required1`, `context:value`, `context:timestamp` |
| 2 | `proof_context` | `Field` | **B** | `context:value` |
| 3 | `predicate_type` | `u8` | **B** | `map:predicateTypes[proofType]` |
| 4 | `set_root` | `Field` | **B** | predicate-specific: fixed `0` / direct `param:setRoot` / sanctions `derived:canonicalSet` + `param:setRoot` |
| 5 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 6 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` (policy_range) |
| 7 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 8 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 9 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 10 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |

- **`claim_binding`** — compute_claim_binding_3(predicate_type, required_0, required_1, proof_context, timestamp). The preimage does NOT include set_root or flagRequired. A conforming verifier rejects `flagRequired: true` (and non-boolean values) for this legacy proof type; false/absent remains usable because it requests no institutional condition.
- **`set_root`** — NOT covered by the claim-binding preimage (predicate_type, required_0, required_1, proof_context, timestamp). It MUST be compared directly: fixed to `0` for accreditation, bound directly to `param:setRoot` for source/tax, and for sanctions independently derived from the signed APR's `canonicalSet` and required to equal its `setRoot`.

### `zkc_remaining_predicates_v2`

Shared profile circuit under presentation profiles. **Field order differs from v1**: v2 orders (`set_root`, `predicate_type`). Proof types: `zkc:proof:accreditation:v2`, `zkc:proof:source:v2`, `zkc:proof:tax:v2`, `zkc:proof:sanctions:v2`.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `presentation_pseudonym` | `Field` | **B** | `envelope:presentationBinding.pseudonym` |
| 1 | `scope_id` | `Field` | **B** | `envelope:presentationBinding.scopeId` |
| 2 | `claim_binding` | `Field` | **D** | `public:predicate_type`, `param:required0`, `param:required1`, `context:value`, `context:timestamp` |
| 3 | `proof_context` | `Field` | **B** | `context:value` |
| 4 | `set_root` | `Field` | **B** | predicate-specific: fixed `0` / direct `param:setRoot` / sanctions `derived:canonicalSet` + `param:setRoot` |
| 5 | `predicate_type` | `u8` | **B** | `map:predicateTypes[proofType]` |
| 6 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 7 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` (policy_range) |
| 8 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 9 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 10 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 11 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |

- **`claim_binding`** — compute_claim_binding_3(predicate_type, required_0, required_1, proof_context, timestamp). The preimage does NOT include set_root or flagRequired. A conforming verifier rejects `flagRequired: true` (and non-boolean values) for this legacy proof type; false/absent remains usable because it requests no institutional condition.
- **`set_root`** — NOT covered by the claim-binding preimage (predicate_type, required_0, required_1, proof_context, timestamp). It MUST be compared directly: fixed to `0` for accreditation, bound directly to `param:setRoot` for source/tax, and for sanctions independently derived from the signed APR's `canonicalSet` and required to equal its `setRoot`.

### `zkc_remaining_predicates_v3`

Deprecated flag-bound linkable profile. The public ABI matches v1; all proof identities
are distinct: `zkc:proof:accreditation:v3`, `zkc:proof:source:v3`,
`zkc:proof:tax:v3`, and `zkc:proof:sanctions:v3`.

This profile remains verifiable for historical proofs, but holders MUST NOT
generate new v3 proofs. Its raw-code inclusion predicates accept code `0`
against sparse-tree padding, and its sanctions exclusion predicate does not
prove that the supplied neighbours are adjacent. Use v7 for new linkable
proofs.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `holder_commitment` | `Field` | **B** | `envelope:holderBinding.commitment` |
| 1 | `claim_binding` | `Field` | **D** | `public:predicate_type`, `param:required0`, `param:required1`, `param:flagRequired`, `context:value`, `context:timestamp` |
| 2 | `proof_context` | `Field` | **B** | `context:value` |
| 3 | `predicate_type` | `u8` | **B** | `map:predicateTypes[proofType]` |
| 4 | `set_root` | `Field` | **B** | predicate-specific: fixed `0` / direct `param:setRoot` / sanctions `derived:canonicalSet` + `param:setRoot` |
| 5 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 6 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` (policy_range) |
| 7 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 8 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 9 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 10 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |

- **`claim_binding`** — `compute_claim_binding_4(predicate_type, required_0, required_1, flag_required, proof_context, timestamp)`. `flagRequired` is an exact JSON boolean; absent defaults to false. For non-accreditation meanings it is fixed false. A false witness cannot match a true request binding.
- **`set_root`** — remains outside the four-slot preimage and MUST be compared directly under the same predicate-specific rules as v1.

### `zkc_remaining_predicates_v4`

Deprecated flag-bound anonymous/scoped profile. The public ABI and presentation semantics
match v2, with distinct proof types `zkc:proof:accreditation:v4`,
`zkc:proof:source:v4`, `zkc:proof:tax:v4`, and
`zkc:proof:sanctions:v4`.

This profile remains verifiable for historical proofs, but holders MUST NOT
generate new v4 proofs. It has the same raw-code padding and non-adjacent
sanctions-neighbour defects as v3. Use v8 for new anonymous or scoped proofs.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `presentation_pseudonym` | `Field` | **B** | `envelope:presentationBinding.pseudonym` |
| 1 | `scope_id` | `Field` | **B** | `envelope:presentationBinding.scopeId` |
| 2 | `claim_binding` | `Field` | **D** | `public:predicate_type`, `param:required0`, `param:required1`, `param:flagRequired`, `context:value`, `context:timestamp` |
| 3 | `proof_context` | `Field` | **B** | `context:value` |
| 4 | `set_root` | `Field` | **B** | predicate-specific: fixed `0` / direct `param:setRoot` / sanctions `derived:canonicalSet` + `param:setRoot` |
| 5 | `predicate_type` | `u8` | **B** | `map:predicateTypes[proofType]` |
| 6 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 7 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` (policy_range) |
| 8 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 9 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 10 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 11 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |

- **`claim_binding`** — the same four-slot formula as v3, with the same exact-boolean/default rules. The v4 presentation fields do not enter the claim preimage; they retain their independent envelope/scope checks.
- **`set_root`** — remains outside the four-slot preimage and MUST be compared directly under the same predicate-specific rules as v2.

### `zkc_remaining_predicates_v5`

Published historical linkable profile. Its public ABI and four-slot request-binding
transcript are byte-for-byte compatible with v3, but it has distinct proof
identities: `zkc:proof:accreditation:v5`, `zkc:proof:source:v5`,
`zkc:proof:tax:v5`, and `zkc:proof:sanctions:v5`.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `holder_commitment` | `Field` | **B** | `envelope:holderBinding.commitment` |
| 1 | `claim_binding` | `Field` | **D** | `public:predicate_type`, `param:required0`, `param:required1`, `param:flagRequired`, `context:value`, `context:timestamp` |
| 2 | `proof_context` | `Field` | **B** | `context:value` |
| 3 | `predicate_type` | `u8` | **B** | `map:predicateTypes[proofType]` |
| 4 | `set_root` | `Field` | **B** | predicate-specific: fixed `0` / direct `param:setRoot` / sanctions `derived:canonicalSet` + `param:setRoot` |
| 5 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 6 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` (policy_range) |
| 7 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 8 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 9 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 10 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |

- **`claim_binding`** — exactly the v3 `compute_claim_binding_4` formula and exact-boolean rules. Circuit-version selection is not inferred from the transcript version.
- **`set_root`** — checked under the same predicate-specific rules as v3. In addition, source and tax witnesses constrain their private raw code to be non-zero, and sanctions witnesses constrain the successor path index to equal the predecessor path index plus one.

### `zkc_remaining_predicates_v6`

Published historical anonymous/scoped profile. Its public ABI, presentation
semantics, and four-slot request-binding transcript are byte-for-byte
compatible with v4, with distinct proof identities
`zkc:proof:accreditation:v6`, `zkc:proof:source:v6`,
`zkc:proof:tax:v6`, and `zkc:proof:sanctions:v6`.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `presentation_pseudonym` | `Field` | **B** | `envelope:presentationBinding.pseudonym` |
| 1 | `scope_id` | `Field` | **B** | `envelope:presentationBinding.scopeId` |
| 2 | `claim_binding` | `Field` | **D** | `public:predicate_type`, `param:required0`, `param:required1`, `param:flagRequired`, `context:value`, `context:timestamp` |
| 3 | `proof_context` | `Field` | **B** | `context:value` |
| 4 | `set_root` | `Field` | **B** | predicate-specific: fixed `0` / direct `param:setRoot` / sanctions `derived:canonicalSet` + `param:setRoot` |
| 5 | `predicate_type` | `u8` | **B** | `map:predicateTypes[proofType]` |
| 6 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 7 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` (policy_range) |
| 8 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 9 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 10 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 11 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |

- **`claim_binding`** — exactly the v4 `compute_claim_binding_4` formula and exact-boolean rules.
- **`set_root`** — checked under the same predicate-specific rules as v4, with the same non-zero raw-code and adjacent sanctions-neighbour constraints as v5.

### `zkc_remaining_predicates_v7`

Current combined hardened linkable profile. It has the same public-input ABI,
binding classes, and four-slot `compute_claim_binding_4` transcript as v5,
but distinct proof identities `zkc:proof:accreditation:v7`,
`zkc:proof:source:v7`, `zkc:proof:tax:v7`, and
`zkc:proof:sanctions:v7`. Its credential authentication additionally signs
`validFrom` under the v2 profile digest. Source/tax raw codes are non-zero and
the sanctions predecessor and successor leaves must be exactly adjacent.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `holder_commitment` | `Field` | **B** | `envelope:holderBinding.commitment` |
| 1 | `claim_binding` | `Field` | **D** | `public:predicate_type`, `param:required0`, `param:required1`, `param:flagRequired`, `context:value`, `context:timestamp` |
| 2 | `proof_context` | `Field` | **B** | `context:value` |
| 3 | `predicate_type` | `u8` | **B** | `map:predicateTypes[proofType]` |
| 4 | `set_root` | `Field` | **B** | predicate-specific: fixed `0` / direct `param:setRoot` / sanctions `derived:canonicalSet` + `param:setRoot` |
| 5 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 6 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` (policy_range) |
| 7 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 8 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 9 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 10 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |

- **`claim_binding`** — exactly the v5 `compute_claim_binding_4` formula and exact-boolean rules.
- **`set_root`** — checked under the same predicate-specific rules and hardening constraints as v5.

### `zkc_remaining_predicates_v8`

Current combined hardened anonymous/scoped profile. It has the same
public-input ABI, presentation semantics, and binding classes as v6, but
distinct proof identities `zkc:proof:accreditation:v8`,
`zkc:proof:source:v8`, `zkc:proof:tax:v8`, and
`zkc:proof:sanctions:v8`. It applies the v2 validity-bound credential digest,
non-zero source/tax checks, and exact sanctions-neighbour adjacency. The v5/v6
identities remain verifiable only as historical compatibility surfaces.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `presentation_pseudonym` | `Field` | **B** | `envelope:presentationBinding.pseudonym` |
| 1 | `scope_id` | `Field` | **B** | `envelope:presentationBinding.scopeId` |
| 2 | `claim_binding` | `Field` | **D** | `public:predicate_type`, `param:required0`, `param:required1`, `param:flagRequired`, `context:value`, `context:timestamp` |
| 3 | `proof_context` | `Field` | **B** | `context:value` |
| 4 | `set_root` | `Field` | **B** | predicate-specific: fixed `0` / direct `param:setRoot` / sanctions `derived:canonicalSet` + `param:setRoot` |
| 5 | `predicate_type` | `u8` | **B** | `map:predicateTypes[proofType]` |
| 6 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 7 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` (policy_range) |
| 8 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 9 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 10 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 11 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |

- **`claim_binding`** — exactly the v6 `compute_claim_binding_4` formula and exact-boolean rules.
- **`set_root`** — checked under the same predicate-specific rules and hardening constraints as v6.

### `zkc_selective_disclosure_v1`

Selective disclosure of issuer-signed attributes (pseudonym + scope; disclosed values are the proof's output). Proof types: `zkc:proof:selective_disclosure:v1`.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `presentation_pseudonym` | `Field` | **B** | `envelope:presentationBinding.pseudonym` |
| 1 | `scope_id` | `Field` | **B** | `envelope:presentationBinding.scopeId` |
| 2 | `claim_binding` | `Field` | **D** | `public:credential_attribute_count`, `public:disclosed_flags`, `public:disclosed_attributes`, `context:value`, `context:timestamp` |
| 3 | `proof_context` | `Field` | **B** | `context:value` |
| 4 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 5 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` (policy_range) |
| 6 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 7 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 8 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 9 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 10 | `credential_attribute_count` | `u8` | **F** | A property of the credential, not of the request: the issuer signature verified in-circuit covers the credential digest, whose preimage includes this count, … |
| 11 | `disclosure_count` | `u8` | **D** | `public:disclosed_flags` |
| 12 | `disclosed_flags` | `[bool; 8]` | **B** | `param:disclosedPositions` |
| 13 | `disclosed_attributes` | `[Field; 8]` | **F** | These are the proof's output — the attribute values the verifier is learning — so no request-side expectation exists by design. |

- **`claim_binding`** — compute_selective_disclosure_binding: a typed transcript folding flags and values as position-labelled pairs, so a disclosed zero differs from a hidden slot and moving a value changes the transcript.
- **`disclosure_count`** — MUST equal the population count of disclosed_flags and be at least 1.

### `zkc_jurisdiction_v6`

Draft issuer-bound code space. The verifier derives the canonical set root and compares the public registry ID to the authenticated request.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `presentation_pseudonym` | `Field` | **B** | `envelope:presentationBinding.pseudonym` |
| 1 | `scope_id` | `Field` | **B** | `envelope:presentationBinding.scopeId` |
| 2 | `claim_binding` | `Field` | **D** | `public:jurisdiction_set_root`, `public:membership_type`, `param:requiredClaimType`, `context:value`, `context:timestamp`, `public:code_space_id`, `public:required_verification_method` |
| 3 | `proof_context` | `Field` | **B** | `context:value` |
| 4 | `jurisdiction_set_root` | `Field` | **B** | `param:jurisdictionSetRoot` |
| 5 | `membership_type` | `u8` | **B** | `param:membershipType` |
| 6 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 7 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` |
| 8 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 9 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 10 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` |
| 11 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` |
| 12 | `code_space_id` | `Field` | **B** | `param:codeSpaceId` |
| 13 | `required_verification_method` | `u8` | **B** | `param:requiredVerificationMethod` |

### `zkc_remaining_predicates_v11`

Draft issuer-bound code space. The verifier derives the canonical set root and compares the public registry ID to the authenticated request.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `presentation_pseudonym` | `Field` | **B** | `envelope:presentationBinding.pseudonym` |
| 1 | `scope_id` | `Field` | **B** | `envelope:presentationBinding.scopeId` |
| 2 | `claim_binding` | `Field` | **D** | `public:predicate_type`, `param:required0`, `param:required1`, `param:flagRequired`, `context:value`, `context:timestamp`, `public:code_space_id` |
| 3 | `proof_context` | `Field` | **B** | `context:value` |
| 4 | `set_root` | `Field` | **B** | `param:setRoot` |
| 5 | `predicate_type` | `u8` | **B** | `map:predicateTypes[proofType]` |
| 6 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 7 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` |
| 8 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 9 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 10 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` |
| 11 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` |
| 12 | `code_space_id` | `Field` | **B** | `param:codeSpaceId` |

### `zkc_selective_disclosure_v3`

Draft layout-bound disclosure. Proof type `zkc:proof:selective_disclosure:v3`.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `presentation_pseudonym` | `Field` | **B** | `envelope:presentationBinding.pseudonym` |
| 1 | `scope_id` | `Field` | **B** | `envelope:presentationBinding.scopeId` |
| 2 | `claim_binding` | `Field` | **D** | `public:layout_id`, `public:credential_attribute_count`, `public:disclosed_flags`, `public:disclosed_attributes`, `context:value`, `context:timestamp` |
| 3 | `proof_context` | `Field` | **B** | `context:value` |
| 4 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` |
| 5 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` (policy_range) |
| 6 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 7 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 8 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 9 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (member_of) |
| 10 | `layout_id` | `Field` | **B** | `param:layoutId` and the issuer signature over the v2 credential digest |
| 11 | `credential_attribute_count` | `u8` | **F** | A property of the credential, not of the request: the issuer signature verified in-circuit covers the credential digest, whose preimage includes this count, … |
| 12 | `disclosure_count` | `u8` | **D** | `public:disclosed_flags` |
| 13 | `disclosed_flags` | `[bool; 8]` | **B** | `param:disclosedPositions` |
| 14 | `disclosed_attributes` | `[Field; 8]` | **F** | These are the proof's output — the attribute values the verifier is learning — so no request-side expectation exists by design. |

The issuer-signed `layout_id` carries the meaning and encoding of the credential slots. Its public value must equal the exact request layout. The typed v3 transcript commits to the layout before folding the positional flags and values.

> **Security containment (2026-09-06) — the four `zkc_credential_rebind*`
> statements below are unauthenticated and contained.** Each verifies no
> issuer signature and no accumulator membership; the private credential
> fields their public `credential_id` / `issuer_id_hash` / `schema_id_hash`
> are equated to are unconstrained prover witnesses. The classifications and
> justifications below are therefore accurate descriptions of *why the
> verifier cannot bind those fields*, not a contract under which the proofs
> may be accepted: the reference verifier rejects every one of these proof
> types with `UNAUTHENTICATED_CREDENTIAL` before backend verification and the
> reference holder never generates them (spec §4.5). The sidecars and tables
> are byte-frozen historical records.

### `zkc_credential_rebind`

Credential rebind (old → new holder commitment), v1. No issuer signature or accumulator witness in this circuit. Proof types: `zkc:proof:credential_rebind:v1`. **Contained: rejected unconditionally (see the notice above).**

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `old_holder_commitment` | `Field` | **B** | `envelope:holderBinding.commitment` |
| 1 | `new_holder_commitment` | `Field` | **F** | The migration target is chosen by the holder: no request-side expected value exists for a freshly derived binding key. |
| 2 | `credential_id` | `Field` | **F** | The verifier request vocabulary carries no credentialId expectation, and the rebind circuit carries no issuer signature, so this value is holder-asserted. |
| 3 | `issuer_id_hash` | `Field` | **F** | The rebind circuit carries no issuer signature, and the private credential_issuer_id_hash this public value is equated to is an unconstrained witness — the p… |
| 4 | `schema_id_hash` | `Field` | **F** | The rebind circuit carries no issuer signature, and the private credential_schema_id_hash this public value is equated to is an unconstrained witness — the p… |
| 5 | `proof_context` | `Field` | **B** | `context:value` |
| 6 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 7 | `claim_binding` | `Field` | **D** | `public:old_holder_commitment`, `public:new_holder_commitment`, `public:credential_id`, `context:value`, `context:timestamp` |

- **`issuer_id_hash`** — A request MAY pin the expected issuer via the issuerIdHash parameter; a supplied pin MUST be equality-checked and MUST be treated as a filter, never as attestation.
- **`schema_id_hash`** — A request MAY pin the expected schema via the schemaIdHash parameter; a supplied pin MUST be equality-checked and MUST be treated as a filter, never as attestation.
- **`claim_binding`** — compute_claim_binding_3 over the rebind public values; the verifier MUST recompute it so the public holders/credential/context cannot be swapped under a stale binding.

### `zkc_credential_rebind_v2`

Credential rebind under presentation profiles (pseudonym-keyed, scoped-only). Proof types: `zkc:proof:rebind:v2`. **Contained: rejected unconditionally (see the notice above `zkc_credential_rebind`).**

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `old_presentation_pseudonym` | `Field` | **B** | `envelope:presentationBinding.pseudonym` |
| 1 | `new_presentation_pseudonym` | `Field` | **F** | The migration target is chosen by the holder: no request-side expected value exists for a pseudonym freshly derived from the new binding key under the shared… |
| 2 | `scope_id` | `Field` | **B** | `envelope:presentationBinding.scopeId` |
| 3 | `credential_id` | `Field` | **F** | The verifier request vocabulary carries no credentialId expectation, and the rebind circuit carries no issuer signature, so this value is holder-asserted. |
| 4 | `issuer_id_hash` | `Field` | **F** | The rebind circuit carries no issuer signature, and the private credential_issuer_id_hash this public value is equated to is an unconstrained witness — the p… |
| 5 | `schema_id_hash` | `Field` | **F** | The rebind circuit carries no issuer signature, and the private credential_schema_id_hash this public value is equated to is an unconstrained witness — the p… |
| 6 | `proof_context` | `Field` | **B** | `context:value` |
| 7 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 8 | `claim_binding` | `Field` | **D** | `public:old_presentation_pseudonym`, `public:new_presentation_pseudonym`, `public:credential_id`, `context:value`, `context:timestamp` |

- **`issuer_id_hash`** — A request MAY pin the expected issuer via the issuerIdHash parameter; a supplied pin MUST be equality-checked and MUST be treated as a filter, never as attestation.
- **`schema_id_hash`** — A request MAY pin the expected schema via the schemaIdHash parameter; a supplied pin MUST be equality-checked and MUST be treated as a filter, never as attestation.
- **`claim_binding`** — compute_claim_binding_3 over the pseudonym-keyed rebind public values; the verifier MUST recompute it so the public pseudonyms/credential/context cannot be swapped under a stale binding.

### `zkc_credential_rebind_binding_v2`

Strictly additive binding-contract-v2 identity for linkable credential rebind.
Its public-input shape and rebind semantics match `zkc_credential_rebind`, while
an exact private proof-type domain gives the successor a distinct ACIR and
verification key. The distinct proof type and identity select the structured
conditional-pin contract without reinterpreting the frozen predecessor. Proof types:
`zkc:proof:credential_rebind:v2`. **Contained: rejected unconditionally (see the
notice above `zkc_credential_rebind`).**

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `old_holder_commitment` | `Field` | **B** | `envelope:holderBinding.commitment` |
| 1 | `new_holder_commitment` | `Field` | **F** | The migration target is chosen by the holder: no request-side expected value exists for a freshly derived binding key. |
| 2 | `credential_id` | `Field` | **F** | The verifier request vocabulary carries no credentialId expectation, and the rebind circuit carries no issuer signature, so this value is holder-asserted. |
| 3 | `issuer_id_hash` | `Field` | **F** | Free unless `pinnedBy: param:issuerIdHash` is supplied; then it MUST compare equal. This is a filter, never issuer attestation. |
| 4 | `schema_id_hash` | `Field` | **F** | Free unless `pinnedBy: param:schemaIdHash` is supplied; then it MUST compare equal. This is a filter, never schema attestation. |
| 5 | `proof_context` | `Field` | **B** | `context:value` |
| 6 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 7 | `claim_binding` | `Field` | **D** | `public:old_holder_commitment`, `public:new_holder_commitment`, `public:credential_id`, `context:value`, `context:timestamp` |

- **`issuer_id_hash`** — `pinnedBy: param:issuerIdHash` is the machine-readable optional issuer filter; a supplied pin MUST compare equal and remains a filter, never attestation.
- **`schema_id_hash`** — `pinnedBy: param:schemaIdHash` is the machine-readable optional schema filter; a supplied pin MUST compare equal and remains a filter, never attestation.
- **`claim_binding`** — compute_claim_binding_3 over the rebind public values; the verifier MUST recompute it so the public holders/credential/context cannot be swapped under a stale binding.

### `zkc_credential_rebind_v2_binding_v2`

Strictly additive binding-contract-v2 identity for scoped, pseudonym-keyed
credential rebind. Its public-input shape and rebind semantics match
`zkc_credential_rebind_v2`, while an exact private proof-type domain gives the
successor a distinct ACIR and verification key. The distinct proof type and
identity select the structured conditional-pin contract without reinterpreting
the frozen predecessor. Proof types: `zkc:proof:rebind:v3`. **Contained: rejected
unconditionally (see the notice above `zkc_credential_rebind`).**

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `old_presentation_pseudonym` | `Field` | **B** | `envelope:presentationBinding.pseudonym` |
| 1 | `new_presentation_pseudonym` | `Field` | **F** | The holder chooses the migration target, which is derived in-circuit from the new binding key under the shared scope. |
| 2 | `scope_id` | `Field` | **B** | `envelope:presentationBinding.scopeId` |
| 3 | `credential_id` | `Field` | **F** | The verifier request vocabulary carries no credentialId expectation, and the rebind circuit carries no issuer signature, so this value is holder-asserted. |
| 4 | `issuer_id_hash` | `Field` | **F** | Free unless `pinnedBy: param:issuerIdHash` is supplied; then it MUST compare equal. This is a filter, never issuer attestation. |
| 5 | `schema_id_hash` | `Field` | **F** | Free unless `pinnedBy: param:schemaIdHash` is supplied; then it MUST compare equal. This is a filter, never schema attestation. |
| 6 | `proof_context` | `Field` | **B** | `context:value` |
| 7 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 8 | `claim_binding` | `Field` | **D** | `public:old_presentation_pseudonym`, `public:new_presentation_pseudonym`, `public:credential_id`, `context:value`, `context:timestamp` |

- **`issuer_id_hash`** — `pinnedBy: param:issuerIdHash` is the machine-readable optional issuer filter; a supplied pin MUST compare equal and remains a filter, never attestation.
- **`schema_id_hash`** — `pinnedBy: param:schemaIdHash` is the machine-readable optional schema filter; a supplied pin MUST compare equal and remains a filter, never attestation.
- **`claim_binding`** — compute_claim_binding_3 over the pseudonym-keyed rebind public values; the verifier MUST recompute it so the public pseudonyms/credential/context cannot be swapped under a stale binding.

### `zkc_credential_rebind_auth`

Issuer-authenticated credential rebind, linkable profile (spec section 7.4.2). The issuer signature over the recomputed `zkc:attestation:credential-rebind:v1` transcript and the non-revocation proof for the same credential id are what make this statement evidence of an issuer-created, live credential. Proof types: `zkc:proof:credential_rebind:v3`.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `old_holder_commitment` | `Field` | **B** | `envelope:holderBinding.commitment`; also the holder commitment inside the issuer-signed transcript |
| 1 | `new_holder_commitment` | `Field` | **F** | The migration target is chosen by the holder; derived in-circuit from the new binding key and committed by claim_binding. |
| 2 | `credential_id` | `Field` | **F** | Authenticated in-circuit by the issuer-signed rebind attestation and proven non-revoked; the request vocabulary carries no credentialId expectation. |
| 3 | `issuer_id_hash` | `Field` | **B** | `policy:issuerAllowlist` - `string_to_field(issuerId)` of the trust-policy issuer matched by the exact public key |
| 4 | `schema_id_hash` | `Field` | **F** | Authenticated by the issuer signature; free unless `pinnedBy: param:schemaIdHash` is supplied, then it MUST compare equal. |
| 5 | `proof_context` | `Field` | **B** | `context:value` |
| 6 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 7 | `claim_binding` | `Field` | **D** | `public:old handle`, `public:new handle`, `public:credential_id`, `context:value`, `context:timestamp` |
| 8 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` (AUTHENTICATED announcement-chain state) |
| 9 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` epoch-lag window |
| 10 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 11 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (exact `(x, y)` member; trusted for this proof type) |
| 12 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (checked with x as one key) |

- **`issuer_id_hash`** - bound, not an optional pin: it is compared against the verifier's own matched trusted issuer identifier, which is strictly stronger than the filter the deprecated rebind statements offered.
- **`schema_id_hash`** - `pinnedBy: param:schemaIdHash` is the machine-readable optional schema filter, applied only AFTER cryptographic issuer authentication.
- **`claim_binding`** - compute_claim_binding_3 over the profile's handles, the authenticated credential id, and the request context/timestamp.

### `zkc_credential_rebind_auth_v2`

Issuer-authenticated credential rebind, scoped profile (spec section 7.4.3): the pseudonym-keyed form of `zkc_credential_rebind_auth` with the same authenticated core. Proof types: `zkc:proof:rebind:v4`.

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `old_presentation_pseudonym` | `Field` | **B** | `envelope:presentationBinding.pseudonym`; derives from the private holder commitment the issuer signed |
| 1 | `new_presentation_pseudonym` | `Field` | **F** | The migration target is chosen by the holder; derived in-circuit from the new binding key under the shared scope. |
| 2 | `scope_id` | `Field` | **B** | `envelope:presentationBinding.scopeId` (non-zero; scoped profile only) |
| 3 | `credential_id` | `Field` | **F** | Authenticated in-circuit by the issuer-signed rebind attestation and proven non-revoked; the request vocabulary carries no credentialId expectation. |
| 4 | `issuer_id_hash` | `Field` | **B** | `policy:issuerAllowlist` - `string_to_field(issuerId)` of the trust-policy issuer matched by the exact public key |
| 5 | `schema_id_hash` | `Field` | **F** | Authenticated by the issuer signature; free unless `pinnedBy: param:schemaIdHash` is supplied, then it MUST compare equal. |
| 6 | `proof_context` | `Field` | **B** | `context:value` |
| 7 | `timestamp` | `u64` | **B** | `context:timestamp` |
| 8 | `claim_binding` | `Field` | **D** | `public:old handle`, `public:new handle`, `public:credential_id`, `context:value`, `context:timestamp` |
| 9 | `accumulator_root` | `Field` | **B** | `policy:accumulatorState.roots[accumulatorEpoch]` (AUTHENTICATED announcement-chain state) |
| 10 | `accumulator_epoch` | `u64` | **B** | `policy:accumulatorState` epoch-lag window |
| 11 | `current_epoch` | `u64` | **B** | `policy:accumulatorState.currentEpoch` |
| 12 | `issuer_public_key_x` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (exact `(x, y)` member; trusted for this proof type) |
| 13 | `issuer_public_key_y` | `[u8; 32]` | **B** | `policy:issuerAllowlist` (checked with x as one key) |

- **`issuer_id_hash`** - bound, not an optional pin: it is compared against the verifier's own matched trusted issuer identifier, which is strictly stronger than the filter the deprecated rebind statements offered.
- **`schema_id_hash`** - `pinnedBy: param:schemaIdHash` is the machine-readable optional schema filter, applied only AFTER cryptographic issuer authentication.
- **`claim_binding`** - compute_claim_binding_3 over the profile's handles, the authenticated credential id, and the request context/timestamp.

### `zkc_aggregation`

Linkable envelope commitments over up to 8 component proofs, v1. Proof type: `zkc:proof:aggregation:v1`. The verifier accepts the block only when each covered entry is requested and passes individual verification, including the shared holder-binding check. It recomputes the commitments and ignores the aggregate proof bytes (spec §7.3).

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `aggregation_commitment` | `Field` | **D** | `context:value`, `public:holder_commitment`, `public:input_proof_commitments`, `public:num_proofs`, `envelope:proofs`, `policy:registryCircuitForProofType` |
| 1 | `aggregated_claim_binding` | `Field` | **D** | `public:aggregation_commitment`, `context:value` |
| 2 | `holder_commitment` | `Field` | **B** | `envelope:holderBinding.commitment` |
| 3 | `context` | `Field` | **B** | `context:value` |
| 4 | `num_proofs` | `u32` | **B** | `envelope:proofs` |
| 5 | `input_proof_commitments` | `[Field; 8]` | **D** | `envelope:proofs`, `policy:registryCircuitForProofType` |

- **`aggregation_commitment`** — aggregate_commitments over the context, the shared holder commitment, and each active (index < num_proofs) slot's poseidon2(proof_commitment, proof_type) gated by principalConsent; the verifier MUST recompute it from the envelope's component proofs and the registry-pinned circuit identities.
- **`aggregated_claim_binding`** — poseidon2(aggregation_commitment, context); the verifier MUST recompute it and reject on mismatch.
- **`input_proof_commitments`** — Each active slot MUST equal the commitment recomputed over that component proof's verification-key stand-in (derived from the registry-pinned circuit for the slot's proof type, not from the envelope), proof, public inputs, and proof type, under the deployment-defined packing (reference: python/zkc_holder/aggregation.py); inactive slots MUST be 0.

### `zkc_aggregation_v2`

Scoped aggregation circuit. Proof type: `zkc:proof:aggregate:v2`. The table describes the published circuit's input roles. The verifier rejects aggregation blocks in all v2 envelopes with `INVALID_AGGREGATION`, which also covers the `zkc:proof:aggregate:v3` successor (spec §7.3).

| # | Public input | Type | Class | Checked against / recomputed from / why free |
|---|---|---|---|---|
| 0 | `aggregation_commitment` | `Field` | **D** | `context:value`, `public:presentation_pseudonym`, `public:input_proof_commitments`, `public:num_proofs`, `envelope:proofs`, `policy:registryCircuitForProofType` |
| 1 | `aggregated_claim_binding` | `Field` | **D** | `public:aggregation_commitment`, `context:value` |
| 2 | `presentation_pseudonym` | `Field` | **B** | `envelope:presentationBinding.pseudonym` |
| 3 | `scope_id` | `Field` | **B** | `envelope:presentationBinding.scopeId` |
| 4 | `context` | `Field` | **B** | `context:value` |
| 5 | `num_proofs` | `u32` | **B** | `envelope:proofs` |
| 6 | `input_proof_commitments` | `[Field; 8]` | **D** | `envelope:proofs`, `policy:registryCircuitForProofType` |

- **`aggregation_commitment`** — `aggregate_commitments` keyed on the presentation pseudonym.
- **`aggregated_claim_binding`** — `poseidon2(aggregation_commitment, context)`.
- **`input_proof_commitments`** — Each active slot commits to the supplied verification-key, proof, and public-input fields plus the proof type. The circuit also requires public-input slot field 0 to equal the presentation pseudonym. Inactive commitments must be zero.

### Beta.25 artifact-successor aliases

The following additive circuit identities are compiled with Noir beta.25 and
Barretenberg 5.0.0. Except for the range-hardened v10 statement described
below, each preserves its predecessor's statement, public ABI,
and every public-input classification above. The distinct circuit package,
proof type, encoder, binding sidecar, verification key, and registry entry bind
the new toolchain artifacts without changing any historical record.

| Beta.25 successor | Classification predecessor |
|---|---|
| `zkc_community_kyc_v2` | `zkc_kyc` |
| `zkc_kyc_v3` | `zkc_kyc_v2` |
| `zkc_aggregation_v3` | `zkc_aggregation_v2` |
| `zkc_credential_rebind_auth_v3` | `zkc_credential_rebind_auth_v2` |
| `zkc_jurisdiction_v5` | `zkc_jurisdiction_v4` |
| `zkc_remaining_predicates_v9` | `zkc_remaining_predicates_v8` |
| `zkc_remaining_predicates_v10` | `zkc_remaining_predicates_v9` |
| `zkc_selective_disclosure_v2` | `zkc_selective_disclosure_v1` |

The draft v10 remaining-predicate successor preserves only the public ABI and
classification shown here. Its private statement adds explicit u8/u64/u16
range assertions; its source and verification key differ from v9.

### Nonzero credential identifier successors

These draft entries inherit the public-input ABI and binding classification
of the circuit listed below. Each successor adds a constraint that the same
credential identifier used for issuer authentication and revocation is nonzero.

| Nonzero successor | Classification predecessor |
|---|---|
| `zkc_community_kyc_v3` | `zkc_community_kyc_v2` |
| `zkc_credential_rebind_auth_linkable_v2` | `zkc_credential_rebind_auth` |
| `zkc_credential_rebind_auth_v4` | `zkc_credential_rebind_auth_v3` |
| `zkc_jurisdiction_v7` | `zkc_jurisdiction_v3` |
| `zkc_jurisdiction_v8` | `zkc_jurisdiction_v6` |
| `zkc_kyc_v4` | `zkc_kyc_v3` |
| `zkc_remaining_predicates_v12` | `zkc_remaining_predicates_v7` |
| `zkc_remaining_predicates_v13` | `zkc_remaining_predicates_v10` |
| `zkc_remaining_predicates_v14` | `zkc_remaining_predicates_v11` |
| `zkc_selective_disclosure_v4` | `zkc_selective_disclosure_v3` |

## 6. Implementation status at ratification (2026-08-26)

The reference verifier (`python/zkc_verifier/verifier.py`) enforces, per this
contract: context/timestamp binding, envelope holder/presentation-binding
consistency, scope recomputation for scoped v2 envelopes, issuer allowlist
membership, accumulator epoch checks, the KYC / selective-disclosure / rebind
claim-binding recomputations, `disclosedPositions`, and recomputation of the
envelope aggregation block (commitments and aggregated claim binding).

The request-binding chokepoint (punch-list P1, ADR 0003) has landed and closes
the jurisdiction and `zkc_remaining_predicates` gaps this section previously
described as unchecked. The mechanism differs by field, and the distinction is
load-bearing (§3 above): a field inside the claim-binding preimage is verified
*by recomputing the binding*, never by a standalone compare; a field outside
it — `set_root` — is verified *only* by a direct public-input compare, because
recomputing the claim binding never touches it.

- **`zkc_jurisdiction` / `_v2`.** `membership_type` is compared directly with
  `param:membershipType`. For exclusion, `jurisdiction_set_root` is derived
  independently from the signed APR's `jurisdictionCanonicalSet`, required to
  match `param:jurisdictionSetRoot`, and compared directly with the proof public
  input. Inclusion uses the same derivation when canonical codes are supplied
  and otherwise retains the established direct-root binding. The jurisdiction
  claim binding is independently recomputed as
  `compute_claim_binding_3(jurisdiction_set_root, membership_type,
  requiredClaimType, proof_context, timestamp)` against the request's
  (mandatory) `param:requiredClaimType` — closing the gap this section
  previously flagged. `requiredClaimType` has no direct public input of its
  own, so the claim-binding recomputation is the *only* mechanism that binds
  it; it is therefore mandatory on the request (no silent default), unlike the
  `zkc_remaining_predicates` slots below.
- **All `zkc_remaining_predicates` generations.** `predicate_type` is compared against
  `map:predicateTypes[proofType]` — resolved exclusively via
  `PublicInputBindings.for_circuit(root, circuit).predicate_type_for
  (proof_type)` (`python/zkc_crypto/encoders.py:111-165`) over the P4 sidecar
  the generation's `schemas/public-input-bindings/zkc_remaining_predicates*.json`, never
  a literal; a proof type absent from the sidecar is rejected
  (`UNBOUND_PROOF_TYPE`), not defaulted. Per §3's caveat, `set_root` sits
  outside the claim-binding preimage and is bound **only** by a direct public-
  input compare. The expected value is fixed `0` for accreditation, direct
  `param:setRoot` for source/tax, and for sanctions the canonical root derived
  independently from the signed APR's `canonicalSet` and required to equal its
  `setRoot`. Recomputing the claim binding alone would silently accept a
  prover-chosen set. The claim binding itself is recomputed as
  `compute_claim_binding_3(predicate_type, required_0, required_1,
  proof_context, timestamp)` against the request's `required0`/`required1`,
  mirroring the holder's own defaulting (`.get(key, 0)`) exactly, so the
  recompute stays bit-for-bit correct whether or not the request supplies
  those slots explicitly (they are mandatory only where the corresponding
  circuit branch is live for that `predicate_type` — see the per-predicate
  semantics in ADR 0003(d)). v3-v8 add the exact boolean flag as a fourth
  slot while preserving the direct `set_root` comparison.
- **`flagRequired` (institutional-accreditation flag) is enforced only by
  v3-v8.** The immutable v1/v2 circuits keep it private and outside their
  three-slot binding, so a conforming verifier rejects `true` or malformed
  legacy requests and accepts only false/absent. v3-v8 still keep the policy
  bit private, but commit it through `compute_claim_binding_4`; the verifier
  resolves an exact JSON boolean and recomputes that public binding. The
  actual institutional fact is independently issuer-authoritative through
  signed `claim_1`, so the request bit is not added to the credential digest.
- `accumulator_root` is compared against
  `policy:accumulatorState.roots[accumulatorEpoch]` for every root-carrying
  proof type, and an epoch with no recorded root is rejected
  (`STALE_ACCUMULATOR`) — closing the gap this section previously flagged,
  where a verifier with no recorded roots accepted a prover-chosen root
  (security review 2026-10-04). Selective disclosure and the authenticated
  rebind successors additionally require the root to come from authenticated
  metadata-v2 ingestion. The only exception is the explicit, logged
  `allow_unrecorded_accumulator_roots` verifier opt-out, which surfaces every
  unchecked acceptance as an `UNCHECKED_ACCUMULATOR_ROOT` warning.
- Rebind `issuer_id_hash` / `schema_id_hash` pins were enforced only when the
  request supplied them (consistent with their `free` classification — see the
  written justifications). Since 2026-09-06 that path is unreachable: all four
  `zkc_credential_rebind*` proof types are rejected with
  `UNAUTHENTICATED_CREDENTIAL` before backend verification, because a pin over
  a prover-chosen value never authenticated the credential (§5 notice, spec §4.5).
- The v2 envelope carries no accepted aggregation block. Scoped holder binding
  is checked on individual proofs.

Remaining known gaps (unchanged by this update) are listed above alongside the
newly-closed ones so this section stays a single accurate status list rather
than requiring a reader to cross-reference a prior revision.

## 7. Change control

- Adding or changing a circuit public input requires a new encoder document (the
  registry forbids mutating committed ones) **and** a classification for every
  field — CI fails otherwise. There is no way to add an unclassified field.
- Reclassifying a field—or changing `source`, `check`, `group`, `from`, `note`,
  `justification`, or `predicateTypes`—is a verifier-contract identity change.
  A committed sidecar MUST NOT be edited in place, even for an apparent
  `free`→`bound` tightening. Until the protocol can select a binding-contract
  version independently, publish the complete additive successor identity
  required by the predicate-registry governance policy, retain the old sidecar
  and schema, and add a new table/documentation section for the successor.
- This table was ratified against the `pub` parameter list of each circuit's
  `main()` as validated by `tests/vectors/validate_public_input_encoders.py`
  (which parses the Noir source directly) on the ratification date above.

**References.** `docs/zkc_specification.md` §6.2 (`verifyComplianceProof`,
`verifyTypeSpecificRequirements`), §5.9.5 (public-input determinism invariant);
`docs/adr/0001-multi-show-unlinkable-presentations.md`;
`docs/adr/0002-escrowed-audit-profile.md`;
`docs/zkc_presentation_profiles_design.md` §4 (v2 public-input shapes).

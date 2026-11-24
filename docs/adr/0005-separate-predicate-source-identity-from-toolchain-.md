# ADR-0005: Separate predicate source identity from toolchain artifact bindings

**Status: Accepted**
**Date:** 2026-09-09
**Accepted:** 2026-09-09
**Deciders:** ZKC maintainers through public review
**Tags:** registry, governance, noir, toolchain, compatibility

## Context

Predicate-entry v1 places two different kinds of identity in one immutable
`circuit` block:

- source identity: `name`, `sourcePath`, and `sourceSha256`; and
- generated-artifact identity: `scheme`, `acirHash`, `vkHash`, and
  `vkSha256`.

The entry also binds one public-input encoder. The admission validator and
history gate correctly protect the complete direct and repository-local source
closure, encoder, binding sidecar, selected binding schema, and generated
artifacts. That protection is load-bearing and must not be weakened.

The model nevertheless treats a compiler or proving-backend change as if it
were a semantic circuit change. A toolchain-only rebuild changes ACIR and
verification-key bytes, so v1 requires a new entry version, proof type, source
package, encoder, and holder/verifier mapping even when the reviewed source and
public-input contract are byte-identical. The beta.25 / Barretenberg 5.0.0
successor rebuild changes all 23 artifacts while preserving the intended
predicate statements.

The registry must be able to say two things independently:

1. these exact source and public-input-contract bytes implement this predicate
   statement and have this review history; and
2. this exact toolchain produced these exact ACIR and verification-key
   artifacts from that source, with this separate review and activation
   history.

That separation cannot introduce ambiguous verification-key selection, inherit
review claims across unverified compiler output, establish a registry-wide
preferred toolchain, or reinterpret any committed identity.

## Decision

### D1. Add a normalized v2 registry model; leave predicate-entry v1 frozen

ZKC will introduce `zkc:registry:predicate-entry:v2` as an additive schema. A
v2 predicate entry is the immutable, source-centric record for one semantic
lineage version. Toolchain outputs are separate child documents using a new
`zkc:registry:artifact-binding:v1` schema:

```text
registry/predicates/<predicateId>/<entryVersion>/entry.json
registry/predicates/<predicateId>/<entryVersion>/bindings/<bindingId>.json
```

The v2 `entry.json` owns:

- `predicateId`, `entryVersion`, author, title, and `proofTypes`;
- a content-derived `sourceId`;
- a canonical manifest of the direct Noir package and its complete recursive
  repository-local dependency closure, with normalized paths and SHA-256 pins;
- the public-input encoder, its binding sidecar, and the exact selected binding
  schema, all with paths and SHA-256 pins;
- source/statement review status and evidence; and
- a same-lineage `supersedes` link for semantic successors and for the one-time
  adoption of a frozen v1 entry into the v2 schema.

The `sourceId` is the SHA-256 of a specified canonical JSON serialization of
the complete source-and-contract manifest. It is not merely the hash of
`src/main.nr`. Canonicalization, path normalization, closure traversal, and
duplicate handling must be defined by the implementation schema and shared by
the admission validator and history checker. A source review therefore binds
the bytes that determine both constraint behavior and verifier interpretation.

Bindings are discovered from the `bindings/` directory rather than from a
mutable array in `entry.json`. Publishing another toolchain binding adds one
new file and new generated artifacts; it never edits or copies the source
record.

Each binding document owns:

- its parent tuple (`predicateId`, `entryVersion`, `sourceId`);
- a content-derived `bindingId`;
- the exact proof system, Noir compiler, Barretenberg version, build profile,
  and integrity-pinned toolchain provenance needed for reproduction;
- an artifact-manifest key and immutable ACIR/VK paths;
- `acirHash`, `vkHash`, and `vkSha256`;
- binding-specific review status and evidence; and
- binding-specific activation, supersession, and deprecation metadata.

`bindingId` is the SHA-256 of the canonical immutable portion of the binding
document, including the parent `sourceId`, toolchain identity, artifact paths,
and artifact hashes. Review, activation, and deprecation lifecycle metadata is
excluded from that digest so only the narrowly allowed lifecycle transitions
can occur after publication.

Predicate-entry v1 remains supported exactly as published. Its schema,
identity fields, directory contents, history rules, source bytes, encoders,
sidecars, artifacts, activation records, and runtime resolution behavior are
not migrated or reinterpreted. A v1 entry never acquires an implicit or
synthesized `bindingId`.

Because a committed v1 `entry.json` already occupies its lineage/version path,
adopting those same frozen bytes into v2 requires one new entry version. That
adoption is the sole non-semantic entry-version transition permitted by this
decision. It must name the exact v1 predecessor, reuse its proof types only
through the selector-bearing path below, and carry machine-checked evidence
that the complete source closure and public-input contract are identical. Once
a lineage is represented in v2, later entry-version changes again mean source
or contract changes; toolchain-only changes add bindings without advancing the
entry version.

### D2. Treat source review and artifact-binding review as independent gates

The source record's `review` describes review of the predicate statement,
constraint source, dependency closure, public-input layout, and binding
contract. A toolchain binding's `review` describes reproducibility and the
correct association of that exact source identity with its exact generated
ACIR and VK. Binding review does not claim that the compiler or proving system
is sound, and source review does not attest to generated bytes it did not
examine.

Binding evidence must cover an independent rebuild where the claimed status
requires independent review, artifact/manifest hash agreement, public-input
ABI agreement, applicable conformance and proof/verification tests, and an
explicit assessment of relevant compiler/backend changes and known issues.

The existing status vocabulary (`draft`, `in_review`, `self_attested`,
`reviewed`, `deprecated`) is retained but scoped to the record carrying it.
An implementation must evaluate both records independently. Effective
assurance is conjunctive: a binding is usable only when the source status and
binding status each satisfy the holder's or verifier's local policy. In
particular:

- a reviewed source does not upgrade a draft or self-attested binding;
- an independently reproduced binding does not upgrade self-attested source;
- evidence for one binding cannot activate or review another binding; and
- status remains an evidence claim, never a registry grant of trust.

A binding may be publicly committed in `draft` or `in_review` status, but it
may be activated only when both its own status and its source record's status
are `self_attested` or `reviewed` with the required evidence. A deprecated
record may retain its historical activation timestamp but cannot authorize a
new activation. Activation is per binding. Multiple bindings may be active
concurrently because different implementations may support different
toolchains; activation creates no global default or ordering.
`activation.supersedes` may name an earlier binding for operational lineage,
but the earlier binding and its artifacts remain present. Deprecation is a flag
and never deletion.

Changing source bytes, the dependency closure, encoder, binding sidecar, or
binding schema is a semantic-source successor: publish a new v2 entry version
and source identity. Changing only the compiler, backend, build profile, ACIR,
or VK is an artifact successor: add a binding beneath the same source entry.

### D3. Select verification keys by an exact, untrusted binding selector

Proof type alone cannot safely select among several verification keys. New
proofs produced through a v2 source entry therefore carry this per-proof
selector as transport metadata:

```json
{
  "predicateId": "zkc-kyc",
  "entryVersion": "<v2 entry version>",
  "bindingId": "sha256:<64 lowercase hex characters>"
}
```

The selector is not a trust assertion and is not a circuit public input. It is
an untrusted exact lookup key into the verifier's locally accepted registry.
After lookup, the verifier must check all of the following before invoking the
backend:

1. the binding belongs to the selected predicate entry and repeats its exact
   `sourceId`;
2. the proof type is published by that source entry;
3. source and binding review states satisfy local policy;
4. the binding is active unless the local policy explicitly permits an
   inactive binding;
5. the artifact manifest repeats the binding's exact immutable pins; and
6. the VK bytes match `vkSha256`, after which the proof is verified with that
   key.

There is no fallback from a present selector to proof-type-only resolution,
no "latest" binding, and no trial verification against multiple keys. An
unknown, malformed, disallowed, inactive, or mismatched selector fails closed.

The holder selects a binding from the intersection of (a) an exact selector
required by an authenticated proof request or verifier policy, (b) the
holder's local source/review policy, (c) active bindings, and (d) locally
available toolchains/artifacts. Explicit local configuration may further
narrow that set. More than one candidate after applying those inputs is an
ambiguity error; the registry does not choose a winner by version, activation
time, or lexical order. The emitted proof entry records the exact selected
tuple.

An authenticated request may add an optional allowlist of exact binding
selectors only through a versioned request extension whose digest explicitly
commits to that allowlist (or through an exact per-proof parameter that the
existing digest demonstrably commits to). An implementation must not place the
allowlist in an unknown top-level field that the current APR digest ignores.
This lets a verifier advertise supported bindings without turning the registry
into a canonical preference service. A request without a cryptographically
bound extension retains its existing meaning and cannot require a binding.

The binding selector is an additive proof-entry metadata field. It does not
alter proof bytes, predicate semantics, the proof-type domain separator, the
ordered public inputs, claim binding, presentation binding, holder binding, or
any public-input encoder. The existing general envelope schemas and shared
validator permit additional proof-entry properties, although some
type-specific proof-entry validators intentionally use a closed field set. The
implementation must add the selector consistently to every applicable schema
and validator while preserving acceptance of all selector-free historical
entries; it must not rely on permissive parsing alone. Audit exports and
verification results must retain the exact selector and resolved `vkHash`.

Aggregation already commits to each selected verification-key hash. When an
input uses a v2 registry binding, aggregation must additionally enforce that
the selector resolves to that exact committed `vkHash`; no aggregation public
input or circuit ABI changes solely because the registry now names the same
hash through a binding.

### D4. Preserve selector-free proof handling as a closed legacy path

Every existing proof type and every already-produced v1/v2 proof envelope
continues down the current selector-free path:

```text
proofType -> committed predicate-entry v1 -> circuit name
          -> committed artifact manifest -> exact historical VK bytes
```

The ordered public inputs and all type-specific verification checks remain
unchanged. Implementations must not backfill v1 bindings, prefer a v2 binding
for a selector-free proof, or reinterpret a historical proof according to a
new source record.

For a selector-bearing proof, the exact tuple selects the v2 path. Stripping or
rewriting the selector cannot cause the verifier to try another v2 key. If a
stripped proof reaches the legacy path, it is verified only with the existing
historical key and normally fails cryptographically; authenticated requests
that negotiated a binding must reject the missing selector before proof
verification. No new binding changes the deterministic legacy map.

An existing byte-frozen source may later be described by a new v2 source record
under a new entry version, provided the adoption record pins the already
committed closure and contract without changing them and names the v1
predecessor. That is an additive description for selector-bearing proofs, not a
conversion of the v1 entry. The v1 entry and its historical key remain
independently resolvable forever.

### D5. Extend the artifact manifest and immutability gates without weakening v1

The current artifact manifest is keyed by one circuit name and cannot represent
several builds of the same source. A future implementation will add a
versioned manifest form in which a v2 artifact record is keyed by the full
predicate-entry/binding tuple (or its collision-resistant canonical key), not
by a globally preferred circuit name. Artifact paths must include the binding
identity so publishing a new build cannot overwrite old ACIR or VK bytes.

`registry/validate.py` must reject at least:

- unsupported or cross-wired entry/binding schema versions;
- a binding whose parent tuple or `sourceId` does not match its entry;
- duplicate binding identities or manifest keys;
- incomplete, escaping, or symlinked source/dependency closures;
- source, encoder, sidecar, or binding-schema digest mismatches;
- incomplete or non-integrity-pinned toolchain provenance;
- artifact hashes or paths that disagree with the generated and committed
  manifests;
- activation without eligible source and binding review evidence; and
- any exclusivity, canonical, mandatory, or default-preference field.

`registry/check_immutability.py` must retain every v1 check and additionally
prevent deletion or mutation of the immutable portion of any committed v2
source entry, source/dependency byte, contract byte, binding document, or
binding artifact. It may permit only the explicitly modeled review,
activation, supersession, and deprecation transitions. Adding a binding is
allowed only as a previously unreferenced file with previously unreferenced
artifact paths.

## Rationale

The normalized model makes the registry reflect the actual review boundary.
Predicate meaning is determined by source plus the public-input contract;
compiler and backend versions determine a reproducible artifact realization of
that meaning. Keeping both immutable but independently versioned avoids
mislabeling toolchain churn as a new predicate statement.

Separate binding documents are preferable to a `bindings` array inside the
entry. An array would either require mutating committed identity to append a
binding or republishing a new entry that copies the unchanged source record.
Append-only child records preserve a stable source identity and give each
binding its own evidence and activation lifecycle.

Exact selectors preserve determinism without creating a registry preference.
They also make downgrade and cross-wiring failures crisp: the verifier performs
one locally authorized lookup and one exact-key verification, or rejects.

## Consequences

### Positive

- A toolchain-only rebuild no longer requires copied Noir source, copied
  encoders, a new proof type, or semantic holder/verifier mapping churn.
- Source review remains attached to the complete bytes and public-input
  contract actually reviewed.
- Every generated ACIR/VK pair retains separate, inspectable provenance,
  review, activation, and deprecation history.
- Existing proof types, envelopes, public inputs, and verification keys retain
  their exact current interpretation.
- Implementations can support overlapping active toolchains without a
  registry-defined default.

### Negative

- Registry consumers need a second resolution dimension and must persist the
  exact binding selector in proof, audit, and diagnostic records.
- Adopting a committed v1 lineage requires one additive v2 entry version and
  equivalence record, although its proof types and semantics do not change.
- The artifact manifest, holder, verifier, aggregation mapping, admission
  validator, history checker, schemas, and tests all need coordinated additive
  support before v2 bindings are usable.
- Review policy becomes explicitly two-dimensional; user interfaces must not
  collapse source review and artifact reproduction into one misleading badge.

### Neutral

- Toolchain changes may still reveal bugs or alter constraint behavior. If
  review finds a source or public-input-contract change is required, that work
  remains a semantic source successor rather than a binding-only update.
- Publication remains distinct from review and activation.
- The registry remains advisory and non-exclusive; local policy remains the
  trust boundary.

## Alternatives Considered

### Keep predicate-entry v1 and publish full successors

This remains the required path until v2 is implemented and is safe, but it
creates false semantic versioning and repeated source, encoder, proof-type, and
mapping churn for every toolchain bump.

### Repin the v1 circuit block in place

Rejected. It destroys historical verification-key determinism, invalidates
review evidence, and bypasses the registry's core immutability guarantee.

### Put a mutable `bindings` array in predicate-entry v1 or v2

Rejected. Appending output would mutate a committed identity or force copied
source entries. It also makes per-binding lifecycle transitions harder to
history-gate precisely.

### Select the newest or most recently activated binding

Rejected. "Newest" is not a security policy, produces time- and
registry-view-dependent verification, and creates a de facto canonical
toolchain contrary to Freedom Safeguard 1.

### Try every verification key until one succeeds

Rejected. It hides ambiguous or malicious selectors, creates avoidable denial
of service, complicates audit evidence, and makes policy enforcement depend on
key iteration order.

### Encode the toolchain generation in each proof type

Rejected for v2 because toolchain identity is not predicate semantics. This is
the safe v1 fallback, but it is the churn this decision is intended to remove.

## Implementation and verification requirements

This ADR is a design decision, not authorization to implement or activate the
new schemas. A separate implementation requirement must cover the registry,
artifact pipeline, holder, verifier, request, aggregation, and conformance
changes together. It must demonstrate:

1. byte-for-byte unchanged v1 schema validation, history protection, runtime
   maps, and historical proof verification;
2. two or more artifact bindings for one source identity and proof type,
   selected deterministically by exact selector;
3. rejection of missing negotiated selectors and unknown, malformed,
   cross-wired, inactive, deprecated, disallowed, or ambiguous bindings;
4. independent source and binding review-policy enforcement and per-binding
   lifecycle transitions;
5. generated/committed manifest agreement and artifact drift detection for
   every binding;
6. deletion and mutation resistance for v1 and v2 records and all transitively
   protected bytes;
7. no new proof-type, proof-domain, public-input, claim-binding, or
   presentation-binding value for a binding-only toolchain change;
8. exact binding/VK evidence in verification and audit outputs, including
   aggregation cross-checks; and
9. a v1-to-v2 adoption fixture proving complete source/contract equivalence,
   selector-bearing reuse of the proof type, and unchanged selector-free v1
   resolution.

The beta.25 successor requirement remains governed by predicate-entry v1 and
its additive-copy rules unless and until the complete v2 implementation is
separately authorized, merged, and activated. This ADR does not retroactively
change that requirement or authorize overwriting any artifact.

## References

- `registry/schema/predicate-entry.schema.json`
- `registry/validate.py`
- `registry/check_immutability.py`
- `registry/README.md`
- `docs/zkc_predicate_registry_governance.md`
- `schemas/compliance-proof-v1.schema.json`
- `schemas/compliance-proof-v2.schema.json`
- `python/zkc_holder/registry.py`
- `python/zkc_verifier/vk_store.py`

# ZKC Issuer-Authoritative Selective Disclosure

**Status:** normative reference profile

**Credential:** `zkc:cred:attribute-set:v1`

**Proof entry:** `zkc:proof:selective_disclosure:v1`

**Circuit:** `zkc_selective_disclosure_v1`
**Envelope:** `zkc:proof:v2`

## Ownership boundary

ZKC owns credential issuance, issuer signatures, revocation, disclosure policy, and proof verification. ZKA bundles and AFP `afp.disclose.response` messages MAY carry the versioned ZKC envelope, but MUST treat it as opaque and delegate proof verification to a conforming ZKC verifier. They MUST NOT duplicate or weaken issuer-signature, accumulator, attribute-position, or transcript checks.

## Credential statement

An attribute-set credential contains an issuer-signed `attributeCount` in the range 1 through 8 and exactly eight circuit slots. The issuer API accepts `attributeCount` active values and canonicalizes the remaining slots to zero. The signed digest is:

```text
acc = H4(DOMAIN_ZKC_CLAIM, TYPE("zkc:cred:attribute-set:v1"),
         attributeCount, holderCommitment)
for position in 0..7:
    acc = H3(acc, position, attributes[position])
credentialDigest = H3(acc, credentialId, expiresAt)
```

The circuit verifies the issuer's secp256k1 signature over this digest and a fresh membership witness against the issuer's non-revocation accumulator. Consequently, a prover cannot substitute self-chosen values, counts, or padding.

## Attribute layouts and legacy signing keys

An attribute layout defines the meaning and field encoding of each position. An issuer and verifier MUST agree on that definition before a verifier requests any of its positions. A `layoutId` is exactly `0x` followed by 64 lowercase hexadecimal digits representing a nonzero BN254 scalar field element. Within an issuer's namespace, a layout ID MUST keep the same meaning for the lifetime of its credentials. A changed order, meaning, or encoding requires a new ID.

Proof v1 and its v2 toolchain republication use the legacy attribute-set credential. That signature binds values to positions. The layout comes from the issuer key's issuance policy. An issuer MUST use each exact public signing key for at most one legacy layout, across all operators and deployments that use the key, and MUST declare it as `signingKeys[].attributeLayoutId` in issuer metadata. The issuer MUST check the authoritative provider declaration against that pin before signing or renewing a credential. The issued credential carries an auxiliary `attributeLayoutId` beside `claims` so the holder can retain it from authenticated issuer delivery. Holders MUST compare the request's `layoutId` with that retained value or an independently provisioned layout for the credential. A verifier MUST pin `attributeLayoutId` on its own trust entry for the exact key and compare the request's `layoutId` against that pin. The same key MUST resolve to a single consistent pin across all entries that accept legacy proofs. Missing or conflicting declarations or trust pins MUST fail closed.

The legacy digest does not authenticate this auxiliary field. Holders and verifiers MUST establish legacy layout provenance independently of the party requesting or presenting the proof. A revocation announcement authenticates the accumulator state. Its signature does not authenticate other metadata fields. Before pinning a key that already issued legacy credentials, establish that it was used for the same layout throughout their lifetimes. If that history is uncertain or the key served multiple layouts, use fresh key material and reissue under a single pinned layout or under the signed-layout successor. Historical credentials without verified layout provenance MUST be refused.

## Layout-bound successor

Draft `zkc:proof:selective_disclosure:v3` consumes `zkc:cred:attribute-set:v2`. The issuer takes `claims.layoutId` from the authoritative attestation source. It includes the layout field in the signature digest below. Here `layoutId` denotes the scalar parsed from its canonical wire spelling.

```text
acc = H4(DOMAIN_ZKC_CLAIM, TYPE("zkc:cred:attribute-set:v2"),
         attributeCount, holderCommitment)
acc = H2(acc, layoutId)
for position in 0..7:
    acc = H3(acc, position, attributes[position])
credentialDigest = H3(acc, credentialId, expiresAt)
```

Proof v3 adds the nonzero public `layout_id` immediately before `credential_attribute_count`. The circuit uses that same field in the credential digest and in the disclosure transcript. The latter uses `TYPE("zkc:proof:selective_disclosure:v3")` in the header and folds `acc = H2(acc, layoutId)` before processing the disclosed positions. Verifiers MUST match that public field to the canonical `layoutId` in the request. Holders MUST select a v2 credential with the requested layout before proving. An issuer can sign several v2 layouts with the same key because the statement authenticates each credential's layout.

The draft proof-entry schema `schemas/selective-disclosure-proof-v3.schema.json` and encoder `schemas/public-inputs/zkc_selective_disclosure_v3.json` define the successor's wire shape. Holders must explicitly allow draft proving. Verifiers must explicitly trust the issuer for v3 and satisfy any configured review-status policy. Default profile resolution continues to use the legacy identity with the key policy above.

## Disclosure statement

The public disclosure surface has eight fixed positions:

- `credential_attribute_count`: issuer-signed active position count.
- `disclosure_count`: number of true flags; it MUST be non-zero.
- `disclosed_flags[8]`: explicit public mask; its array index is the position.
- `disclosed_attributes[8]`: value at a disclosed position, canonical zero at a hidden position.

For every true flag the circuit proves equality between the public value and the corresponding issuer-signed private attribute. A flag beyond `credential_attribute_count` rejects. A false flag requires a zero public value.

This representation makes a disclosed zero `(true, 0)` distinct from a hidden slot `(false, 0)`; neither mask semantics nor position is inferred from a value.

## Typed transcript and replay protection

The transcript uses the AFP-KDC v1.0.3 current registry's `zkc/claim` operational domain (`0x0b9294…c9d4`) followed immediately by the proof-type field for `zkc:proof:selective_disclosure:v1`. The domain field and Poseidon2 profile remain the immutable AFP-KDC v1.0.2 crypto evidence:

```text
acc = H4(DOMAIN_ZKC_CLAIM, TYPE("zkc:proof:selective_disclosure:v1"),
         credentialAttributeCount, disclosureCount)
for position in 0..7:
    acc = H4(acc, position, disclosedFlags[position],
             disclosedAttributes[position])
claimBinding = H3(acc, proofContext, timestamp)
```

The registered domain, explicit type field, fixed positional folds, and final context/timestamp fold separate this transcript from ZKA note commitments, Merkle nodes, ZKC aggregation, and other claim shapes. Replaying it under a different AFP session or ZKA interaction context changes `proofContext` and invalidates the proof.

## Public-input order

The canonical ABI is published at `schemas/public-inputs/zkc_selective_disclosure_v1.json`; the type-specific proof entry schema is `schemas/selective-disclosure-proof-v1.schema.json`. Public inputs are, in order:

1. presentation pseudonym and scope;
2. typed claim binding and proof context;
3. issuer accumulator root/epochs and proof timestamp;
4. issuer public key coordinates;
5. credential attribute count, disclosure count, eight flags, and eight values.

Holder commitment, binding key, full attribute vector, credential identifier, expiry, issuer signature, and accumulator path remain private. Anonymous presentations expose no stable holder handle; scoped presentations expose only the scope-derived pseudonym requested through the authenticated presentation flow.

## Verification

A verifier MUST:

1. validate `zkc:proof:v2`, require `principalConsent = true`, and enforce the type-specific proof-entry shape with no additional fields;
2. verify the matching manifest-bound proof for the requested identity;
3. apply its local issuer trust policy and require the claimed epoch/root to exactly match an authenticated issuer accumulator root (an empty root view is a rejection, never a wildcard);
4. require `disclosedPositions` to equal the public flag positions exactly and check `layoutId` against the trusted key pin (v1/v2) or the signed public field (v3);
5. recompute the typed claim binding from the public values, context, and timestamp; and
6. reject unknown proof/envelope versions, malformed counts or arrays, stale issuer state, and context mismatch.

The legacy KAT and negative cases are in `tests/vectors/zkc_core_vectors.json`. The successor KAT is in `tests/vectors/selective_disclosure_v3.json`. Noir and Python tests cover layout substitution, issued-value substitution, position alteration, hidden-zero ambiguity, wrong issuer state, signed-APR parameter substitution, malformed proof entries, and cross-context replay.

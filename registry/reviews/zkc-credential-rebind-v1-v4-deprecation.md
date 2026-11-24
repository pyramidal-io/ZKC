# Deprecation record — `zkc-credential-rebind` 1.0.0 through 4.0.0

| | |
|---|---|
| **Affected entries** | `registry/predicates/zkc-credential-rebind/{1.0.0,2.0.0,3.0.0,4.0.0}/entry.json` |
| **Proof types** | `zkc:proof:credential_rebind:v1`, `zkc:proof:rebind:v2`, `zkc:proof:credential_rebind:v2`, `zkc:proof:rebind:v3` |
| **Status** | All four entries are `deprecated`; their identity-bearing metadata, source packages, encoders, binding sidecars, and artifacts remain published and byte-frozen. |
| **Severity** | Soundness: a valid proof under any of these identities is not evidence of an issuer-created, non-revoked credential. |
| **Independent review** | None claimed by this maintainer-authored record. |
| **Record authored** | 2026-09-06 |

## Findings

Every circuit in the lineage (`zkc_credential_rebind`, `zkc_credential_rebind_v2`,
`zkc_credential_rebind_binding_v2`, `zkc_credential_rebind_v2_binding_v2`)
constrains only that the prover knows the credential binding keys behind the
public old and new holder handles, that the two handles differ, and that the
public claim binding was computed over the public values. The credential the
statement claims to migrate is represented entirely by unconstrained private
witnesses — `credential_holder_commitment`, `credential_issuer_id_hash`,
`credential_schema_id_hash`, `credential_valid_from`, `credential_valid_until` —
and every equality the circuit asserts over them compares a prover-chosen value
with another prover-chosen value. No issuer signature is verified and no
accumulator membership is proven.

Consequently a prover with no credential at all can produce a cryptographically
valid proof for any `credential_id`, any `issuer_id_hash`, any `schema_id_hash`,
and any validity window, and the reference verifier reported such a proof as
credential continuity. Request-pinned `issuerIdHash` / `schemaIdHash` values
compare a verifier expectation to a prover-chosen public input and never
authenticated anything. The 2.0.0 (scoped) and 3.0.0/4.0.0 (binding-contract-v2)
successors re-key or domain-separate the same unauthenticated statement; none
of them added authentication.

## Disposition

The four entries are deprecated (flagged, never deleted): their pinned
`sourceSha256`, `acirHash`, `vkHash`, `vkSha256`, encoders, and sidecars are
unchanged and remain resolvable so historical proofs and audits can be
interpreted for what they actually established (holder-key continuity only).

The reference holder SDK never selects, generates, or negotiates any of the
four identities (`UnauthenticatedProofTypeError`), and the reference verifier
rejects every envelope or request naming one of them with
`UNAUTHENTICATED_CREDENTIAL` at both entry points, independent of trust policy,
request pins, or request authentication. There is **no downgrade path**: a
request MUST name a successor identity explicitly, and no implementation may
map a deprecated identity to a successor or a successor to a deprecated
identity. Historical verification under an explicit verifier trust decision is
NOT offered for this lineage, because unlike a deprecated-but-sound predicate
these statements never authenticated the fact they were used to assert.

The additive issuer-authenticated successors — the linkable
`zkc:proof:credential_rebind:v3` (`zkc_credential_rebind_auth`) and the scoped
`zkc:proof:rebind:v4` (`zkc_credential_rebind_auth_v2`) — verify an issuer
signature over the `zkc:attestation:credential-rebind:v1` transcript recomputed
in-circuit from constrained fields and prove fresh accumulator membership for the
same credential identifier (specification §7.4, ADR 0004). Per the registry's
same-lineage rule the formal chain continues `... -> 4.0.0 -> 5.0.0 -> 6.0.0`
while the profile ancestry (1.0.0/3.0.0 linkable, 2.0.0/4.0.0 scoped) is recorded
in the successor titles and review records.

# Self-attested review record — `zkc-remaining-predicates` 6.0.0

## Scope

This entry is the hardened anonymous/scoped successor of the
published v4 profile. It retains the v4 presentation public-input ABI and
`flagRequired` claim-binding semantics while rejecting raw source/tax code `0`
before sparse-Merkle membership and requiring adjacent sanctions-neighbour leaf
indices.

## Published pins

The entry pins the v6 source SHA-256, ACIR bytecode SHA-256, UltraHonk
verification-key field hash, and verification-key file SHA-256 produced by the
repository-pinned Nargo beta.21 and Barretenberg nightly-20260324 toolchain.
The matching source package, encoder, binding sidecar, manifest record,
canonical ACIR, and verification key are committed with the entry.

## Validation performed

- Nargo beta.21 format/check and all 35 v6 Noir tests passed.
- Real sparse-padding witnesses establish the exploit precondition before the
  circuit rejects source/tax code zero; a nonzero full-field code `70000`
  remains accepted.
- Valid non-adjacent sanctions memberships are rejected, while adjacent
  canonical neighbours and anonymous/scoped presentation bindings remain valid.
- Artifact regeneration, committed-artifact comparison, registry validation,
  public-input encoder validation, and the v3/v4 immutability comparison pass.

This is maintainer self-attestation. No independent review is claimed.

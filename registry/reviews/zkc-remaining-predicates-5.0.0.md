# Self-attested review record — `zkc-remaining-predicates` 5.0.0

## Scope

This entry is the hardened linkable successor of the published v3
profile. It retains the v3 public-input ABI and `flagRequired` claim-binding
semantics while rejecting raw source/tax code `0` before sparse-Merkle
membership and requiring adjacent sanctions-neighbour leaf indices.

## Published pins

The entry pins the v5 source SHA-256, ACIR bytecode SHA-256, UltraHonk
verification-key field hash, and verification-key file SHA-256 produced by the
repository-pinned Nargo beta.21 and Barretenberg nightly-20260324 toolchain.
The matching source package, encoder, binding sidecar, manifest record,
canonical ACIR, and verification key are committed with the entry.

## Validation performed

- Nargo beta.21 format/check and all 31 v5 Noir tests passed.
- Real sparse-padding witnesses establish the exploit precondition before the
  circuit rejects source/tax code zero; a nonzero full-field code `70000`
  remains accepted.
- Valid non-adjacent sanctions memberships are rejected, while adjacent
  canonical neighbours remain accepted.
- Artifact regeneration, committed-artifact comparison, registry validation,
  public-input encoder validation, and the v3/v4 immutability comparison pass.

This is maintainer self-attestation. No independent review is claimed.

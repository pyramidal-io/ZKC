# Self-attested review record — `zkc-remaining-predicates` 7.0.0

## Scope

This additive linkable successor combines the remaining-predicate safety
requirements without changing any published v1–v6 identity. It retains the
linkable public-input ABI and four-slot `flagRequired` request binding, rejects
raw source/tax code `0`, requires exact sanctions-neighbour adjacency, and
uses the v2 profile digest that authenticates both `validFrom` and `validUntil`.

## Published identity

The entry binds the new `zkc_remaining_predicates_v7` package, its distinct v7
proof types, encoder, and binding sidecar. Its ACIR and verification-key pins
are populated from the reproducible pinned-toolchain artifact manifest before
publication; v1–v6 source, encoder, sidecar, artifact, and key bytes remain
unchanged.

## Verification evidence

- Noir positive and negative tests cover raw-code rejection, exact sanctions
  adjacency, and the validity-bound credential digest.
- Python holder/verifier and conformance regressions cover v7 selection,
  request binding, and the historical v1–v6 compatibility boundary.
- Registry validation, immutable-history comparison, public-input encoder and
  binding-sidecar checks, and reproducible artifact checks are required before
  activation.

This is maintainer self-attestation. No independent review is claimed.

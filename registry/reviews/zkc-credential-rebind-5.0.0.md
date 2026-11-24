# Self-attested review record — `zkc-credential-rebind` 5.0.0

## Scope

This additive linkable successor is the first credential-rebind statement that
authenticates the credential it migrates. The published 1.0.0–4.0.0 identities
constrain only holder-key continuity: their credential holder commitment,
identifier, issuer and schema hashes, and validity bounds are unconstrained
prover witnesses, and they verify no issuer signature and no accumulator
membership (`registry/reviews/zkc-credential-rebind-v1-v4-deprecation.md`).

`zkc_credential_rebind_auth` verifies an issuer ECDSA signature over the
`zkc:attestation:credential-rebind:v1` transcript **recomputed in-circuit** from
constrained fields — there is no digest input, so a prover-supplied digest
cannot be accepted — and proves accumulator membership for the same
authenticated credential identifier under the in-circuit epoch-freshness bound.
Specification section 7.4.2; design rationale in ADR 0004.

## Published identity

The entry binds the new `zkc_credential_rebind_auth` package (with its
`zkc_rebind_auth`, `zkc_issuer_sig`, `zkc_nonrevocation` and `zkc_lib`
dependency closure), the fresh `zkc:proof:credential_rebind:v3` proof type, its
public-input encoder, and its binding sidecar. ACIR and verification-key pins
come from the reproducible pinned-toolchain artifact manifest. Every
1.0.0–4.0.0 source, encoder, sidecar, artifact, and key byte remains unchanged;
this entry supersedes 4.0.0 in the lineage chain while the profile ancestry
(linkable: 1.0.0/3.0.0) is recorded here and in the entry title.

## Verification evidence

- Noir tests (22 in this package, plus 3 shared-gadget tests) cover the
  positive statement and reject a zero or tampered signature, a changed
  credential identifier, issuer, schema, or either validity bound, a transcript
  signed for a different holder, revoked membership, stale and future
  accumulator epochs, expired and not-yet-valid credentials, a zero timestamp
  or proof context, and claim-binding tampering.
- The in-circuit attestation digest, statement domain, and claim binding are
  cross-pinned against the Python reference and
  `tests/vectors/zkc_core_vectors.json` (`credential_rebind_attestation_v1`).
- Python holder tests cover the witness builder's fail-closed refusals
  (missing, zero, malformed, mismatched, expired, stale material) and the
  constraint mirror; verifier tests cover exact issuer-key trust, issuer
  identity agreement, authenticated-announcement-chain revocation state,
  envelope binding, entry-point parity, and downgrade/relabelling attempts.
- Registry validation, immutable-history comparison, encoder and sidecar
  checks, and reproducible artifact checks run in CI.

**Independent review: none.** This is maintainer self-attestation. The
statement's soundness rests on the issuer signature and accumulator membership
described above; no third-party cryptographic audit of this circuit exists.

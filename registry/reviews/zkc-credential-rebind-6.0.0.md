# Self-attested review record — `zkc-credential-rebind` 6.0.0

## Scope

This additive scoped successor is the pseudonym-keyed form of
`zkc-credential-rebind` 5.0.0 and shares its authenticated core. The published
1.0.0–4.0.0 identities authenticate no credential at all
(`registry/reviews/zkc-credential-rebind-v1-v4-deprecation.md`).

`zkc_credential_rebind_auth_v2` verifies an issuer ECDSA signature over the
`zkc:attestation:credential-rebind:v1` transcript **recomputed in-circuit** from
constrained fields — over the now-private old holder commitment — and proves
accumulator membership for the same authenticated credential identifier. Public
inputs 0/1 are the old and new presentation pseudonyms sharing one non-zero
`scope_id`: rebind is verifier-facing continuity, so the anonymous sentinel is
rejected. Specification section 7.4.3; design rationale in ADR 0004.

## Published identity

The entry binds the new `zkc_credential_rebind_auth_v2` package (with its
`zkc_rebind_auth`, `zkc_issuer_sig`, `zkc_nonrevocation` and `zkc_lib`
dependency closure), the fresh `zkc:proof:rebind:v4` proof type, its
public-input encoder, and its binding sidecar. ACIR and verification-key pins
come from the reproducible pinned-toolchain artifact manifest. Every
1.0.0–4.0.0 source, encoder, sidecar, artifact, and key byte remains unchanged;
this entry supersedes 5.0.0 in the lineage chain while the profile ancestry
(scoped: 2.0.0/4.0.0) is recorded here and in the entry title.

## Verification evidence

- Noir tests (21 in this package, plus 3 shared-gadget tests) cover the
  positive statement and reject a zero or tampered signature, a changed
  credential identifier, issuer, schema, or either validity bound, a transcript
  signed for a different holder, revoked membership, stale and future
  accumulator epochs, expired and not-yet-valid credentials, the anonymous
  sentinel scope, a wrong scope for the old pseudonym, a new pseudonym derived
  from the wrong key, an unchanged holder, and claim-binding tampering.
- The in-circuit attestation digest, statement domain, scoped pseudonyms, and
  claim binding are cross-pinned against the Python reference and
  `tests/vectors/zkc_core_vectors.json` (`credential_rebind_attestation_v1`).
- Python holder tests cover the scoped witness builder's fail-closed refusals
  and the constraint mirror; verifier tests cover exact issuer-key trust,
  issuer identity agreement, authenticated-announcement-chain revocation state,
  scoped envelope binding (pseudonym and scope), entry-point parity, and
  downgrade/relabelling attempts.
- Registry validation, immutable-history comparison, encoder and sidecar
  checks, and reproducible artifact checks run in CI.

**Independent review: none.** This is maintainer self-attestation. The
statement's soundness rests on the issuer signature and accumulator membership
described above; no third-party cryptographic audit of this circuit exists.

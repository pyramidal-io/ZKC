# Review evidence — `zkc-remaining-predicates` 1.0.0

| | |
|---|---|
| **Entry** | `registry/predicates/zkc-remaining-predicates/1.0.0/entry.json` |
| **Proof types** | `zkc:proof:accreditation:v1`, `zkc:proof:source:v1`, `zkc:proof:tax:v1`, `zkc:proof:sanctions:v1` |
| **Circuit** | `noir/zkc_remaining_predicates/src/main.nr` (UltraHonk) |
| **Self-verification date** | 2026-06-11 |
| **Reviewer** | ZKC reference-implementation maintainer (also the author of the change under review), with automated code-review tooling (CodeRabbit AI reviewer) |
| **Independent review** | **None** — see below |
| **Registry status** | `deprecated` (credential-integrity and sanctions-soundness defects discovered 2026-08-27) |
| **Record authored** | 2026-07-31 |

## Independent review: none

No independent third-party review, cryptographic audit, or external sign-off has been performed on this predicate or its circuit. The changes that introduced the artifacts below were authored, approved, and merged by the same maintainer; the only non-author commentary came from automated code-review tooling. Nothing in this record should be read as an independent assessment of the circuit's soundness.

## Scope

Constraint completeness and public-input identity of the shared `zkc_remaining_predicates` circuit across its four predicate branches (accreditation, source-of-funds, tax residency, sanctions clearance): that each branch's requirement is decided from issuer-signed credential data rather than from prover-supplied assertions, that the shared profile envelope (issuer signature, holder binding, claim binding, validity window, accumulator freshness) is enforced on every branch, and that the circuit's public inputs are pinned in a machine-readable, independently re-derivable form.

Explicitly **out of scope**: cryptographic soundness of the underlying proof system, Poseidon parameter selection, and the surrounding SDK/transport behaviour.

## Artifacts examined

- `noir/zkc_remaining_predicates/src/main.nr` — circuit source, hash-pinned by `circuit.sourceSha256` in the entry
- `schemas/public-inputs/zkc_remaining_predicates.json` — public-input encoder, conforming to `schemas/public-input-encoder-v1.schema.json`
- `tests/vectors/validate_public_input_encoders.py` — encoder cross-validator

## Verification performed

All of the following are enforced in continuous integration and are re-runnable by any reader from this repository alone.

1. **Source pinning.** `registry/validate.py` recomputes the SHA-256 of the committed circuit source and fails if it differs from `circuit.sourceSha256`, so a changed circuit cannot inherit this entry's review status.
2. **Public-input identity, cross-validated two independent ways.** `tests/vectors/validate_public_input_encoders.py` parses the `pub` parameters of `main()` directly from the Noir source and asserts an exact match against the committed encoder; the artifact-manifest build independently cross-checks the same encoder against the compiled circuit ABI. Both must agree.
3. **Artifact pinning.** `circuit.acirHash`, `circuit.vkHash`, and `circuit.vkSha256` are cross-checked by `registry/validate.py --manifest` against a reproducibly generated circuit-artifact manifest (format: `artifacts/manifest.schema.json`), built under the toolchain versions pinned in `.noir-version`.
4. **Negative tests.** The circuit carries 25 in-circuit tests, 15 of them negative (`#[test(should_fail_with = ...)]`), spanning both the shared profile envelope (tampered issuer signature, wrong issuer, tampered credential claims, wrong claim binding, wrong holder, expired credential, stale accumulator epoch) and each branch's own requirement (old tax year, unaccepted tax jurisdiction, sanctioned subject, insufficient accreditation level, missing institutional flag, unacceptable source-of-funds code).

## Findings

The review history now contains four substantive findings. The third and
fourth, discovered by later adversarial review, require deprecation of this
immutable identity.

### Finding 1 — accreditation institutional flag was not bound to signed data (critical) — **remediated**

The automated review pass identified that the accreditation branch decided institutional status from a prover-supplied `flag_actual` input that appeared in neither the issuer-signed profile digest nor the claim binding. A prover could therefore satisfy an institutional-accreditation requirement independently of what the issuer had actually signed — a soundness defect, not a style issue.

**Disposition: fixed.** A follow-up change removed the self-asserted input and bound institutional status to the issuer-signed `claim_1`. The pinned circuit source in this entry includes that fix; the negative test `test_accreditation_rejects_missing_institutional_flag` now exercises the bound behaviour, asserting that a holder of a non-institutional credential cannot satisfy an institutional requirement regardless of request inputs.

### Finding 2 — sanctions negative test may pass for the wrong reason (major) — **open**

The automated review pass identified that `test_sanctions_rejects_sanctioned_subject` replaces the blocked-set Merkle root with a subject-only tree while retaining the predecessor/successor witness derived from the original two-neighbour tree. The test's expected failure can therefore be produced by root/witness inconsistency rather than by the sanctions predicate's own logic, which weakens the assurance the test claims to provide. The recommendation was to construct a consistent blocked-set root and matching witnesses that include the subject and its neighbours.

**Disposition: not remediated.** As of this record, the test in the pinned circuit source is unchanged from the form the finding was raised against. This is a test-assurance gap rather than a demonstrated circuit defect: it means the sanctioned-subject rejection path is not conclusively covered, not that the path is known to be wrong. It is recorded here as open rather than closed.

### Finding 3 — sorted-neighbour sanctions clearance accepts non-adjacent members (critical) — **unfixed in this identity**

The sanctions branch proves that two blocked-set members bracket the subject value, but does not prove that their tree indices are adjacent. For the authentic blocked set `{100,150,200}`, subject `150` can therefore obtain false clearance with the valid membership witnesses for `100@0` and `200@2`. Canonical-root derivation alone does not prevent this witness substitution.

This committed circuit identity is immutable, so the defect is not patched in place. The whole entry is deprecated because one verification key serves all four proof types. The validFrom-bound, adjacency-safe v7/v8 successor identities replace it.

### Finding 4 — `validFrom` is not authenticated by the issuer signature (major) — **unfixed in this identity**

The profile credential digest authenticates `validUntil` but omits the private
`validFrom` claim later used by the circuit's validity check. A credential
holder can therefore move only `validFrom` earlier, retain the issuer's valid
signature, and prove eligibility before the issuer-authorized start time.

This committed identity and its digest are immutable. The additive v7/v8
circuits use `compute_profile_digest_v2`, which authenticates both validity
bounds. Existing profile v1 credentials require reissuance before they can be
used with those successors.

## Disposition

The historical mechanical checks above pass, but they did not cover consistent non-adjacent outer-member witnesses. The entry was activated on 2026-06-11 and is deprecated as of 2026-08-27.

**Historical status: `self_attested` (2026-07-31 to 2026-08-27).** Before deprecation, the entry accurately recorded author verification without independent review. `docs/zkc_predicate_registry_governance.md` §2 defines review as an *open, public* pull-request review by someone other than the author; this entry's verification met none of that. No independent review, cryptographic audit, or external sign-off exists, and `review.reviewedAt` remains `null`. Finding 2 was already open when this status applied.

The source, hashes, encoder, and verification key remain available for
historical proof resolution. New proof generation must use the v7/v8 successor
identities and v2 profile credentials.

# Review evidence — `zkc-jurisdiction` 1.0.0

| | |
|---|---|
| **Entry** | `registry/predicates/zkc-jurisdiction/1.0.0/entry.json` |
| **Proof types** | `zkc:proof:jurisdiction:v1` |
| **Circuit** | `noir/zkc_jurisdiction/src/main.nr` (UltraHonk) |
| **Self-verification date** | 2026-06-11 |
| **Reviewer** | ZKC reference-implementation maintainer (also the author of the change under review), with automated code-review tooling (CodeRabbit AI reviewer) |
| **Independent review** | **None** — see below |
| **Registry status** | `deprecated` (critical exclusion-soundness defect discovered 2026-08-27) |
| **Record authored** | 2026-07-31 |

## Independent review: none

No independent third-party review, cryptographic audit, or external sign-off has been performed on this predicate or its circuit. The change that introduced the artifacts below was authored, approved, and merged by the same maintainer; the only non-author commentary came from automated code-review tooling. Nothing in this record should be read as an independent assessment of the circuit's soundness.

## Scope

Constraint completeness and public-input identity of the `zkc_jurisdiction` circuit: that jurisdiction membership is proved against the verifier's stated set rather than self-asserted, that blocked jurisdictions are rejected, that non-membership cannot be passed off as membership, and that the credential's issuer signature, claim type, holder binding, claim binding, validity window, and revocation-accumulator freshness are each enforced.

Explicitly **out of scope**: cryptographic soundness of the underlying proof system, Poseidon parameter selection, the privacy properties of the jurisdiction set itself (set membership reveals set-level information by construction), and the surrounding SDK/transport behaviour.

## Artifacts examined

- `noir/zkc_jurisdiction/src/main.nr` — circuit source, hash-pinned by `circuit.sourceSha256` in the entry
- `schemas/public-inputs/zkc_jurisdiction.json` — public-input encoder, conforming to `schemas/public-input-encoder-v1.schema.json`
- `tests/vectors/validate_public_input_encoders.py` — encoder cross-validator

## Verification performed

All of the following are enforced in continuous integration and are re-runnable by any reader from this repository alone.

1. **Source pinning.** `registry/validate.py` recomputes the SHA-256 of the committed circuit source and fails if it differs from `circuit.sourceSha256`, so a changed circuit cannot inherit this entry's review status.
2. **Public-input identity, cross-validated two independent ways.** `tests/vectors/validate_public_input_encoders.py` parses the `pub` parameters of `main()` directly from the Noir source and asserts an exact match against the committed encoder; the artifact-manifest build independently cross-checks the same encoder against the compiled circuit ABI. Both must agree.
3. **Artifact pinning.** `circuit.acirHash`, `circuit.vkHash`, and `circuit.vkSha256` are cross-checked by `registry/validate.py --manifest` against a reproducibly generated circuit-artifact manifest (format: `artifacts/manifest.schema.json`), built under the toolchain versions pinned in `.noir-version`.
4. **Negative tests.** The circuit carries 13 in-circuit tests, 10 of them negative (`#[test(should_fail_with = ...)]`), each mutating exactly one input of a shared valid fixture: blocked jurisdiction, non-member claimed as included, tampered issuer signature, wrong issuer, tampered credential claims, wrong claim binding, wrong holder, claim-type mismatch, stale accumulator epoch, and expired credential.

## Findings

The automated review pass over the change that introduced these artifacts raised no correctness or soundness findings against `noir/zkc_jurisdiction/src/main.nr`. A later adversarial review on 2026-08-27 found the critical issue below.

**No finding means "nothing was reported", not "nothing is there."** The review depth here is that of an automated pass plus the mechanical checks in the previous section — see "Independent review: none" above.

### Finding — sorted-neighbour exclusion accepts non-adjacent members (critical) — **unfixed in this identity**

The exclusion branch proves that two set members bracket the subject value, but does not prove that their tree indices are adjacent. For the authentic blocked set `{100,150,200}`, subject `150` can therefore be falsely excluded with the valid membership witnesses for `100@0` and `200@2`. Canonical-root derivation alone does not prevent this witness substitution.

This committed circuit identity is immutable, so the defect is not patched in place. The entry is deprecated and replaced by the adjacency-safe `zkc:proof:jurisdiction:v3` and `zkc:proof:jurisdiction:v4` identities.

## Disposition

The historical mechanical checks above pass, but they did not cover non-adjacent outer-member witnesses. The entry was activated on 2026-06-11 and is deprecated as of 2026-08-27.

**Historical status: `self_attested` (2026-07-31 to 2026-08-27).** Before deprecation, the entry accurately recorded author verification without independent review. `docs/zkc_predicate_registry_governance.md` §2 defines review as an *open, public* pull-request review by someone other than the author; this entry's verification met none of that. No independent review, cryptographic audit, or external sign-off exists, and `review.reviewedAt` remains `null`.

The source, hashes, encoder, and verification key remain available for historical proof resolution. New proof generation must use the v3/v4 successor identities.

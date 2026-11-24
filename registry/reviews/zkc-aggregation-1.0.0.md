# Review evidence — `zkc-aggregation` 1.0.0

| | |
|---|---|
| **Entry** | `registry/predicates/zkc-aggregation/1.0.0/entry.json` |
| **Proof types** | `zkc:proof:aggregation:v1` |
| **Circuit** | `noir/zkc_aggregation/src/main.nr` (UltraHonk) |
| **Self-verification date** | 2026-06-11 |
| **Reviewer** | ZKC reference-implementation maintainer (also the author of the change under review), with automated code-review tooling (CodeRabbit AI reviewer) |
| **Independent review** | **None** — see below |
| **Registry status** | `self_attested` (was `reviewed` until 2026-07-31 — see Disposition) |
| **Record authored** | 2026-07-31 |

## Independent review: none

No independent third-party review, cryptographic audit, or external sign-off has been performed on this predicate or its circuit. The change that introduced the artifacts below was authored, approved, and merged by the same maintainer; the only non-author commentary came from automated code-review tooling. Nothing in this record should be read as an independent assessment of the circuit's soundness.

## Scope

Commitment constraints and public-input identity of the `zkc_aggregation` circuit. The circuit hashes the supplied representations of each component's verification key, proof, and public inputs. It checks equality of the separately supplied holder witnesses, the active consent flags, the aggregation commitment, the aggregated claim binding, and the proof context. It also rejects zero components, nonzero commitments in inactive slots, and zero context.

The equality check compares a private per-slot holder witness to the aggregate holder commitment. The circuit has no constraint connecting that witness to the component public inputs, and it performs no recursive proof verification. For a v1 envelope, the verifier MUST verify every covered component individually and recompute the envelope commitments over the verified entries. The reference verifier ignores the carried aggregate proof bytes (spec §7.3). Poseidon parameter selection and the surrounding SDK/transport behaviour were outside the review scope.

## Artifacts examined

- `noir/zkc_aggregation/src/main.nr` — circuit source, hash-pinned by `circuit.sourceSha256` in the entry
- `schemas/public-inputs/zkc_aggregation.json` — public-input encoder, conforming to `schemas/public-input-encoder-v1.schema.json`
- `tests/vectors/validate_public_input_encoders.py` — encoder cross-validator

## Verification performed

All of the following are enforced in continuous integration and are re-runnable by any reader from this repository alone.

1. **Source pinning.** `registry/validate.py` recomputes the SHA-256 of the committed circuit source and fails if it differs from `circuit.sourceSha256`, so a changed circuit cannot inherit this entry's review status.
2. **Public-input identity, cross-validated two independent ways.** `tests/vectors/validate_public_input_encoders.py` parses the `pub` parameters of `main()` directly from the Noir source and asserts an exact match against the committed encoder; the artifact-manifest build independently cross-checks the same encoder against the compiled circuit ABI. Both must agree.
3. **Artifact pinning.** `circuit.acirHash`, `circuit.vkHash`, and `circuit.vkSha256` are cross-checked by `registry/validate.py --manifest` against a reproducibly generated circuit-artifact manifest (format: `artifacts/manifest.schema.json`), built under the toolchain versions pinned in `.noir-version`.
4. **Negative tests.** The circuit carries 13 in-circuit tests, 10 of them negative (`#[test(should_fail_with = ...)]`), each mutating exactly one input of a shared valid fixture: changed proof, verification-key, or public-input fields under an unchanged commitment, a mismatched private holder witness, missing consent, wrong aggregation commitment, wrong aggregated claim binding, nonzero commitment in an inactive slot, zero proofs, and zero context.

## Findings

The automated review pass over the change that introduced these artifacts raised no correctness or soundness findings against `noir/zkc_aggregation/src/main.nr`. (The same change also touched `noir/zkc_remaining_predicates/src/main.nr`, against which a finding *was* raised — see `registry/reviews/zkc-remaining-predicates-1.0.0.md`.)

**No finding means "nothing was reported", not "nothing is there."** The review depth here is that of an automated pass plus the mechanical checks in the previous section — see "Independent review: none" above.

## Disposition

The mechanical checks above pass and the negative-test suite is present and green. The entry is activated (2026-06-11) and recorded as `self_attested`.

**Status: `self_attested` (resolved 2026-07-31).** The open governance question this record raised has been decided. `docs/zkc_predicate_registry_governance.md` §2 defines review as an *open, public* pull-request review by someone other than the author; this entry's verification met none of that. It took place in a non-public development repository, with no independent reviewer, before this registry existed, and the only non-author commentary came from automated tooling. Rather than keep a `reviewed` label the evidence does not support, the entry now carries **`self_attested`**: the author verified their own work and published this record of it; **no independent review, cryptographic audit, or external sign-off exists.** `review.reviewedAt` is `null` accordingly.

The entry stays `self_attested` until an independent review is performed and publicly recorded (governance doc, "Path from `self_attested` to `reviewed`"). Nothing about the circuit, its pinned hashes, or the verification described above changed in this relabelling — only the claim made about it.

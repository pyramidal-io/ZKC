# Review evidence — `zkc-credential-rebind` 1.0.0

| | |
|---|---|
| **Entry** | `registry/predicates/zkc-credential-rebind/1.0.0/entry.json` |
| **Proof types** | `zkc:proof:credential_rebind:v1` |
| **Circuit** | `noir/zkc_credential_rebind/src/main.nr` (UltraHonk) |
| **Self-verification date** | 2026-06-11 |
| **Reviewer** | ZKC reference-implementation maintainer (also the author of the change under review), with automated code-review tooling (CodeRabbit AI reviewer) |
| **Independent review** | **None** — see below |
| **Registry status** | `self_attested` (was `reviewed` until 2026-07-31 — see Disposition) |
| **Record authored** | 2026-07-31 |

## Independent review: none

No independent third-party review, cryptographic audit, or external sign-off has been performed on this predicate or its circuit. The change that introduced the artifacts below was authored, approved, and merged by the same maintainer; the only non-author commentary came from automated code-review tooling. Nothing in this record should be read as an independent assessment of the circuit's soundness.

## Scope

Constraint completeness and public-input identity of the `zkc_credential_rebind` circuit: that rebinding a credential from an old holder commitment to a new one is constrained on both endpoints — the old holder must be the one the credential was actually issued to, the new holder must be the one claimed, the commitment must actually change, and the issuer, schema, validity window, claim binding, and proof context must all be enforced rather than assumed.

Explicitly **out of scope**: cryptographic soundness of the underlying proof system, Poseidon parameter selection, unlinkability of a rebind event across presentations, and the surrounding SDK/transport behaviour.

## Artifacts examined

- `noir/zkc_credential_rebind/src/main.nr` — circuit source, hash-pinned by `circuit.sourceSha256` in the entry
- `schemas/public-inputs/zkc_credential_rebind.json` — public-input encoder (8 field elements), conforming to `schemas/public-input-encoder-v1.schema.json`
- `tests/vectors/validate_public_input_encoders.py` — encoder cross-validator

## Verification performed

All of the following are enforced in continuous integration and are re-runnable by any reader from this repository alone.

1. **Source pinning.** `registry/validate.py` recomputes the SHA-256 of the committed circuit source and fails if it differs from `circuit.sourceSha256`, so a changed circuit cannot inherit this entry's review status.
2. **Public-input identity, cross-validated two independent ways.** `tests/vectors/validate_public_input_encoders.py` parses the `pub` parameters of `main()` directly from the Noir source and asserts an exact match against the committed encoder; the artifact-manifest build independently cross-checks the same encoder against the compiled circuit ABI. Both must agree.
3. **Artifact pinning.** `circuit.acirHash`, `circuit.vkHash`, and `circuit.vkSha256` are cross-checked by `registry/validate.py --manifest` against a reproducibly generated circuit-artifact manifest (format: `artifacts/manifest.schema.json`), built under the toolchain versions pinned in `.noir-version`.
4. **Negative tests.** The circuit carries 13 in-circuit tests, 10 of them negative (`#[test(should_fail_with = ...)]`), each mutating exactly one input of a shared valid fixture: wrong old holder, wrong new holder, unchanged holder commitment, credential bound to another holder, issuer mismatch, schema mismatch, expired credential, not-yet-valid credential, wrong claim binding, and zero proof context.

## Findings

The automated review pass over this change raised no correctness or soundness findings against `noir/zkc_credential_rebind/src/main.nr`. Its actionable findings were directed at build/CI configuration (dependency pinning and artifact integrity checking), outside the scope of this entry; its remaining comments were maintainability nitpicks.

**No finding means "nothing was reported", not "nothing is there."** The review depth here is that of an automated pass plus the mechanical checks in the previous section — see "Independent review: none" above.

## Security finding (2026-09-06): the statement is unauthenticated

**This record's scope statement above was wrong in one load-bearing respect.** It describes the circuit as enforcing that "the old holder must be the one the credential was actually issued to" and that "the issuer, schema, validity window ... [are] enforced rather than assumed". They are not. The circuit's `credential_holder_commitment`, `credential_issuer_id_hash`, `credential_schema_id_hash`, `credential_valid_from`, and `credential_valid_until` inputs are unconstrained private witnesses: the prover chooses both sides of every equality the circuit asserts over them, and the circuit verifies no issuer signature and no accumulator membership. The only facts a valid proof establishes are that the prover knows the binding keys behind the public old and new holder handles and that the public claim binding was computed over the public values.

Consequences, recorded here so a reader relying on this record is not misled:

- A valid `zkc:proof:credential_rebind:v1` proof is **not** evidence of credential ownership, issuance, or live (non-revoked) continuity. The same finding applies to the lineage's 2.0.0, 3.0.0, and 4.0.0 entries (`zkc:proof:rebind:v2`, `zkc:proof:credential_rebind:v2`, `zkc:proof:rebind:v3`), whose circuits re-key or domain-separate the same unauthenticated statement.
- The 13 in-circuit tests listed above remain green and remain accurate for what they test (self-consistency of a prover-supplied witness). They never tested authentication, because the statement contains none.
- The pinned source, ACIR, verification key, and encoder are unchanged by this finding and stay byte-frozen; the reference holder SDK no longer generates this identity and the reference verifier rejects it unconditionally with `UNAUTHENTICATED_CREDENTIAL` (spec §4.5). Additive issuer-authenticated successor entries are specified and published separately.

## Disposition

The mechanical checks above pass and the negative-test suite is present and green. The entry is activated (2026-06-11) and recorded as `self_attested`. **Per the security finding above, `self_attested` here attests only to the mechanical checks listed; it does not and never did attest that the statement authenticates a credential.**

**Status: `self_attested` (resolved 2026-07-31).** The open governance question this record raised has been decided. `docs/zkc_predicate_registry_governance.md` §2 defines review as an *open, public* pull-request review by someone other than the author; this entry's verification met none of that. It took place in a non-public development repository, with no independent reviewer, before this registry existed, and the only non-author commentary came from automated tooling. Rather than keep a `reviewed` label the evidence does not support, the entry now carries **`self_attested`**: the author verified their own work and published this record of it; **no independent review, cryptographic audit, or external sign-off exists.** `review.reviewedAt` is `null` accordingly.

The entry stays `self_attested` until an independent review is performed and publicly recorded (governance doc, "Path from `self_attested` to `reviewed`"). Nothing about the circuit, its pinned hashes, or the verification described above changed in this relabelling — only the claim made about it.

# Review evidence — `community-kyc` 1.0.0

| | |
|---|---|
| **Entry** | `registry/predicates/community-kyc/1.0.0/entry.json` |
| **Proof types** | `zkc:proof:kyc:v1` |
| **Circuit** | `noir/zkc_kyc/src/main.nr` (UltraHonk) |
| **Self-verification date** | 2026-06-11 |
| **Reviewer** | ZKC reference-implementation maintainer (also the author of the change under review), with automated code-review tooling (CodeRabbit AI reviewer) |
| **Independent review** | **None** — see below |
| **Registry status** | `self_attested` (was `reviewed` until 2026-07-31 — see Disposition) |
| **Record authored** | 2026-07-31 |

## What this entry is

`community-kyc` is a **second registry listing for the same proof type** (`zkc:proof:kyc:v1`) as `zkc-kyc`, seeded so that the registry's pluralism guarantee is executable rather than aspirational: lookups must return every matching entry, never a blessed one, and that property is only testable when more than one entry exists. This is stated in `docs/zkc_predicate_registry_governance.md` §4.

**It is not a third-party listing.** This entry was authored in this repository by the same maintainer as `zkc-kyc`, and it pins the *identical* circuit — same `sourcePath`, same `sourceSha256`, same ACIR and verification-key hashes, same public-input encoder. A reader should treat it as a structural placeholder demonstrating that independent lineages *can* coexist, not as evidence that an independent party has listed or reviewed this predicate. As of 2026-07-31 the entry's own `author.name` and `title` say this outright; earlier revisions read "ZKC community (independent example listing)" and "independent community listing", which they were not.

## Independent review: none

No independent third-party review, cryptographic audit, or external sign-off has been performed on this listing or on the circuit it pins. No review was performed on this entry separately from `zkc-kyc`.

## Scope

None specific to this entry. Because this listing pins the byte-identical circuit and encoder as `zkc-kyc` 1.0.0, the scope, artifacts, verification, and findings that apply to it are exactly those recorded in `registry/reviews/zkc-kyc-1.0.0.md`. That record is the substantive evidence; this one exists so that a reader following `review.evidence` from this entry is told plainly that no separate review stands behind it.

## Verification performed

The same continuous-integration checks apply to this entry as to `zkc-kyc` 1.0.0, and are re-runnable from this repository alone:

1. **Source pinning** — `registry/validate.py` recomputes the SHA-256 of `noir/zkc_kyc/src/main.nr` and fails on any divergence from `circuit.sourceSha256`.
2. **Public-input identity** — `schemas/public-inputs/zkc_kyc.json` cross-validated against the circuit source by `tests/vectors/validate_public_input_encoders.py` and, independently, against the compiled circuit ABI by the artifact-manifest build.
3. **Artifact pinning** — ACIR and verification-key hashes cross-checked by `registry/validate.py --manifest` against a reproducibly generated manifest (format: `artifacts/manifest.schema.json`), under the toolchain pinned in `.noir-version`.
4. **Negative tests** — the 9 negative tests in `noir/zkc_kyc/src/main.nr`, enumerated in `registry/reviews/zkc-kyc-1.0.0.md`.

## Findings

None specific to this entry. See `registry/reviews/zkc-kyc-1.0.0.md`.

## Disposition

The mechanical checks above pass. The entry is activated (2026-06-11) and recorded as `self_attested`.

**Status: `self_attested` (resolved 2026-07-31).** The open governance question this record raised has been decided. Two defects stood behind the former `reviewed` label, and both are now stated on the record rather than papered over:

1. The verification it inherited from `zkc-kyc` 1.0.0 was conducted in a non-public repository, with no independent reviewer, before this registry existed — the only non-author commentary came from automated tooling.
2. Even that inherited verification was never directed at *this* listing. Its status was derived entirely from a different entry that happens to pin the same circuit.

The entry now carries **`self_attested`**: the author verified their own work (via `zkc-kyc`) and published these records of it; **no independent review, cryptographic audit, or external sign-off exists**, and none was ever aimed at this listing as such. `review.reviewedAt` is `null` accordingly.

The entry stays `self_attested` until an independent review is performed and publicly recorded (governance doc, "Path from `self_attested` to `reviewed`"). Nothing about the circuit or its pinned hashes changed in this relabelling — only the claim made about it and the entry's misleading attribution.

# ZKC Predicate Registry Governance

**Status:** Living document (normative anchor: spec §1.4 Safeguards 1 & 4, §4.2a)
**Scope:** `registry/` (predicate entries, issuer documents, published verifier policies)

The ZKC registry exists so that holders and verifiers can **find compatible, inspectable predicates and counterparties** — and for nothing else. It is an
**advisory cache, not a policy chokepoint**: every governance rule below is designed so the registry can inform decisions without ever making them.

---

## 1. What the registry is

| Surface | Contents | Guarantee |
|---|---|---|
| `registry/predicates/<predicateId>/<entryVersion>/entry.json` | Versioned predicate entries. V1 is the frozen combined source/artifact record; v2 is a hash-pinned source and public-input-contract identity. | Inspectability and review transparency (Safeguard 4) |
| `registry/predicates/<predicateId>/<entryVersion>/bindings/<binding-digest>.json` | Entry-v2 artifact bindings with exact toolchain provenance, ACIR/VK pins, independent review, and lifecycle state. | Reproducible source-to-artifact association without redefining source identity. |
| `registry/issuers/<name>.json` | Issuer metadata documents | Discovery of issuers by schema/capability |
| `registry/verifiers/<name>.json` | Published verifier trust policies | Discovery of verifiers accepting a credential |

All of it is **plain, versioned, in-repo data**. A filesystem copy of `registry/` is fully functional: every lookup in the reference SDKs works from a local copy with **no network dependency** (enforced by tests — see `tests/python/test_registry_governance_safeguards.py`).

## 2. How entries are added and changed: PR review IS the open review process

- Anyone adds or changes an entry by **pull request** against this repository. The public PR review — diffable circuit source, pinned hashes, CI validation — is the "public review period" Safeguard 4 requires. There is no other gate, committee, or approval authority. **Merging an entry to the public default branch makes it published as a public, reviewable record, regardless of `review.status` or activation state.** It does not make the entry active or trusted.
- `registry/validate.py` runs in CI on every PR and enforces the rules below; the artifacts job additionally cross-checks pinned ACIR/VK hashes against the reproducibly generated artifact manifest.
- `review.status` records the assurance an entry claims. `self_attested`, `reviewed`, and `deprecated` entries MUST carry **public** `review.evidence`.

### Review statuses

| Status | What it asserts | What it does NOT assert |
|---|---|---|
| `draft` | The publicly committed entry is still being worked on. | Anything about assurance or activation. |
| `in_review` | The publicly committed entry is under review. | That review concluded, or that the entry is active. |
| `self_attested` | The **author** published the entry with a hash-pinned, inspectable circuit and a **public record of the author's own verification** — what was checked, how, and what was explicitly not checked. | **That anyone other than the author looked at it.** No independent review, cryptographic audit, or external sign-off. No claim of soundness. |
| `reviewed` | All of the above **plus** a review by someone **other than the entry's author**, publicly recorded (§2 evidence forms). | That the reviewer audited the proof system, or that the predicate is correct — only that independent review happened and its substance is public. |
| `deprecated` | The version is superseded or withdrawn; its pinned identity is retained. | Anything about its assurance. |

`self_attested` exists because the alternative was a lie. Every 1.0.0 entry in this repository was labelled `reviewed` on the strength of self-authored, self-merged pull requests whose only non-author commentary came from automated tooling; no independent review of any predicate in this repository has ever occurred. Rather than keep a status the evidence does not support, or drop the entries to `draft` and pretend nothing was verified, the registry now names what actually happened. **`self_attested` is a floor, not a milestone** — it is the weakest status that still carries a public evidence obligation, and it is where an entry stays until real independent review arrives.

`review.reviewedAt` is the completion date of **independent** review, so it is `null` for `self_attested` entries (the validator enforces this); the author's own verification dates live in the evidence record.

### Path from `self_attested` to `reviewed`

1. Someone **other than the entry's author** reviews the pinned circuit source and the entry's claims. Automated review tooling does not qualify: it is named as tooling in the record, never as an independent assessor.
2. That review is recorded publicly in one of the two §2 evidence forms — a public pull-request review in this repository, or a committed review record under `registry/reviews/` naming the reviewer and the substance of the review.
3. The entry is updated by pull request: `review.status` → `reviewed`, `review.reviewedAt` set to the review's completion date, and the new evidence appended to `review.evidence` (existing self-attestation evidence is kept — it is still true).

Nothing about the circuit changes in that transition, so no new `<entryVersion>` is required; only the assurance claim moves.

### Activation

`activation.activatedAt` records when an already publicly committed entry version was **activated (published for use)**. It is **not** the entry's first-publication date: merger to the public default branch is publication/reviewability regardless of `draft`, `in_review`, or any other status. It requires a status whose assurance level is publicly documented (`self_attested`, `reviewed`, or `deprecated`) — `draft` and `in_review` entries are never activated. **Activation is not an assurance claim** and in particular does not imply independent review. Assurance gating is done where it belongs: by the holder default and by verifier policy, below.

### Accepted forms of `review.evidence`

Evidence MUST be publicly resolvable by any reader of this repository. Two forms satisfy that requirement:

1. **A public pull-request URL** in this repository — the ordinary case, and the expected form going forward. Reviews now happen in the open here, so a reviewed entry cites the public PR that reviewed it, and a reader follows the link to the diff, the review comments, and the CI results.
2. **A committed public review record** in this repository, under `registry/reviews/<predicateId>-<entryVersion>.md`, referenced by its repo-relative path. A record states the review's scope, the artifacts examined, the verification performed, the findings and their disposition, and — explicitly — what review did *not* occur. See `registry/reviews/README.md`.

Form 2 exists because a link is not the point: **public inspectability is**. A committed record travels with the repository, cannot rot into a dead link, and can be diffed and re-verified from a local copy with no network access — the same property the rest of the registry already guarantees. It is the required form for any review whose original discussion is not publicly resolvable (for example, review that predates this repository being public): the substance is extracted into a record and committed, rather than cited through a URL that no reader can open.

**This widens the accepted form of evidence, not the standard.** Both forms carry the identical Safeguard 4 obligation: the review must be real, its substance must be publicly inspectable, and the evidence must let a reader independently judge how much assurance the entry actually carries. A record that overstates what was reviewed fails this rule exactly as a dead URL does. Where a record shows that an entry's evidence does not support its `review.status`, that discrepancy is resolved by changing the status or obtaining the missing review — never by softening the record.

**That rule has already been applied to this registry.** The committed records under `registry/reviews/` showed that the six 1.0.0 entries' evidence did not support a `reviewed` status. On 2026-07-31 the discrepancy was resolved the way this section requires — by changing the status. All six moved from `reviewed` to `self_attested`; the records were not softened.

### Review-status semantics (what SDKs do with them)

- **Holder SDK (default-deny):** predicates that resolve to no entry, or to an entry whose status is outside the holder's accepted set, are **refused by default**. The gate applies to every proof type the holder emits, on the v1 path and on the anonymous and scoped (`zkc:proof:v2`) presentation paths alike: a v2 presentation sibling is its own entry and never inherits the status of its v1 family. The default set is `zkc_holder.registry.DEFAULT_ACCEPTED_STATUSES` = `("reviewed", "self_attested")` — exactly the two statuses that are *required* to publish review evidence, so a holder can read how much assurance an entry claims before using it. `draft`, `in_review`, and `deprecated` are refused. Overriding requires the explicit `allow_opaque` opt-in, which is logged and recorded (`HolderClient.override_log`); use of a `self_attested` entry is additionally logged at INFO. A holder that requires independent review passes `accepted_review_statuses=("reviewed",)` to `HolderClient` (or `ProofPlanner`), which refuses every entry in this registry today.
- **Verifier (verifier-local):** a verifier MAY require review statuses via `accepted_review_statuses` / `requiredReviewStatuses` in its policy. An empty requirement means the verifier imposes none. There is **no global default** beyond refusing unknown proof types. Matching is **exact**: a policy listing only `reviewed` rejects a `self_attested` entry, because self-attestation is not independent review. **A verifier with real exposure SHOULD require `["reviewed"]`.**
- **Assurance follows the verified artifact.** On both verifier entry points, a nonempty source-review policy must accept every admitted source identity publishing the selected manifest VK, including v1 entries under other proof labels and v2 parents of matching child bindings. The independent binding-review policy must likewise accept every matching binding's status; a deprecated binding cannot be hidden behind a legacy label. This is conservative policy aggregation, not a registry ranking or a review upgrade. An unbound v2 source publishes no artifact, and source or encoder equality does not identify a VK: another toolchain build with a different key is assessed separately. Empty source-review policy still imposes no source-review requirement. Exact selector, activation and binding-id allowlist checks remain in force for a selected v2 binding. In particular, `zkc-kyc@3.0.0` and the `zkc-kyc@4.0.0/successor` binding publish the same ACIR/VK; a policy accepting only `reviewed` and `self_attested` refuses both labels because the former source remains `draft`. No published identity or review claim changes.
- **Why the shipped example policy is more permissive.** `registry/verifiers/example-exchange.json` lists `["reviewed", "self_attested"]`. That is not a recommendation — it is a consequence of the registry's actual contents: nothing here has been independently reviewed, so a `["reviewed"]`-only example policy would refuse the reference registry on first run and teach nothing. The permissive example keeps the reference stack runnable end to end while the strict behaviour stays exercised: `tests/python/test_predicate_registry.py` asserts that a `("reviewed",)` policy **rejects** every KYC entry in this repository. When a predicate is genuinely independently reviewed, the honest move is to tighten the example, not to relabel the entry.

## 3. Immutability, evolution, and deprecation

### 3.1 Public commitment and immutable identity

Once an entry is merged to the **public default branch**, its immutable identity is committed, whether its `review.status` is `draft`, `in_review`, `self_attested`, `reviewed`, or `deprecated`, and whether `activation.activatedAt` is null or set. The immutable identity fields are exactly:

- `predicateId`;
- `entryVersion`;
- `proofTypes`;
- the complete `circuit` block; and
- `publicInputEncoder`.

The bytes of every circuit source package referenced by the complete `circuit` block of any committed entry are also immutable. In this reference registry's Noir profile, `circuit.name = <name>` is bound to the regular, non-symlinked `noir/<name>/src/main.nr` source of the matching workspace `bin` package. Admission parses that package and its recursively resolved repository-local dependencies, rejects missing, escaping, or symlinked closure paths, validates the public-input encoder, and binds the encoder path to the generated artifact manifest. The committed byte identity then includes each package's `Nargo.toml`, all files below every closure root, and the referenced encoder. In particular, a source-hash match is not permission to rewrite historical source, dependency, manifest, or encoder bytes: every committed entry that references them must remain reproducible and inspectable forever.

The verifier-contract sidecar associated with a committed encoder is immutable too. Entry v1 predates sidecars, so the history gate derives the association without rewriting published entries: `schemas/public-inputs/<name>.json` selects `schemas/public-input-bindings/<name>.json`. Once that sidecar exists in the public base tree, the gate byte-protects its complete contents and the exact canonical schema selected by its version/`$schema` pair. Admission supports only (`zkc:public-input-bindings:v1`, `https://zkc.dev/schemas/public-input-binding-v1.schema.json`) and (`zkc:public-input-bindings:v2`, `https://zkc.dev/schemas/public-input-binding-v2.schema.json`); a mixed, mismatched, or unknown selector fails closed. V2 adds structured `pinnedBy` conditional request pins while v1 remains byte-identical and does not interpret that field. This protection covers `class`, `source`, `check`, `group`, `from`, `pinnedBy`, `note`, `justification`, `predicateTypes`, and future semantic fields—not merely the golden class table. No in-place transition is permitted, including an apparent `free` → `bound` tightening or adding a v2 rule to a v1 sidecar: it would reinterpret historical proofs and is not a mechanically sufficient security ordering over the complete contract.

Review evidence and `review.status`/`review.reviewedAt`, activation metadata, and deprecation metadata MAY transition by a later public-default-branch merge, provided they do not change immutable identity. These transitions record assurance, use, and lifecycle facts; they do not republish or replace the committed identity.

### 3.2 Strictly additive circuit evolution

A circuit evolution is strictly additive. It MUST add all of the following, while retaining every older entry and every source package already referenced by a committed entry:

1. A **previously unreferenced** workspace circuit source package with a safe, complete local-dependency closure; existing referenced source bytes MUST NOT be edited or repointed.
2. Generated artifacts for that new package, with new pinned hashes.
3. A committed public-input encoder for that package.
4. A matching committed public-input binding sidecar using one exact supported canonical selector pair (currently v1 or v2). A future binding-schema version is not admitted merely by adding a file: schema dispatch, canonical selector validation, and history protection for that version MUST be implemented and reviewed first, while every older schema remains byte-identical and available.
5. A new `<entryVersion>` directory, with `activation.supersedes` pointing to the immediate prior version in that lineage.
6. A **distinct proof type** for a same-lineage replacement until the protocol defines explicit entry-version selection.

A version bump alone is insufficient: it cannot authorize reuse or mutation of a source package, artifacts, encoder, binding contract, binding schema, or proof type that would make an old proof ambiguous. Until explicit entry-version or binding-contract selection exists, same-lineage replacements therefore use distinct proof types; old sources, encoders, sidecars, schemas, artifacts, and entries remain available for historical proof verification and audit.

### 3.3 Deprecation

- **Deprecation only flags.** A deprecated entry keeps its complete immutable identity and is never deleted — proofs and audits can always resolve what an old version meant.
- `supersedes` MUST reference an existing, strictly older version of the same lineage.

### 3.3a Entry v2 source and artifact identities

Entry v2 is additive; the v1 schema and all v1 documents retain their original
meaning. A v2 source identity is the SHA-256 identifier of the canonical JSON
object containing exactly `source` and `publicInputContract`. Its source file
list is sorted and covers the complete repository-local dependency closure.
Each file, encoder, binding sidecar, and selected binding schema carries its own
SHA-256 pin. Changing any of those bytes requires a new source identity and a
new entry version; metadata or formatting outside the identity object does not.

An artifact binding is a child of one exact `(predicateId, entryVersion,
sourceId)` parent. Its binding identity covers the parent, circuit and scheme,
exact Nargo/noirc/Barretenberg versions, hash-pinned provenance record, build
profile, unique manifest key, artifact paths, and ACIR/VK identities. A binding
document is stored under `<bindingId without sha256:>.json`; committed binding
identity fields, artifacts, and provenance bytes are immutable. A source review
does not review a build, and a build review does not review a source.

Lifecycle transitions are monotonic and independent. New bindings may be added
without changing the source. An inactive binding has `activatedAt: null` and is
not selected unless local policy explicitly permits it. Deprecation preserves
the entire record and artifact closure. A successor binding names the prior
binding id but does not delete it. Rollback therefore means local policy selects
an already admitted prior active binding; operators never edit an identifier,
try keys until one verifies, or rely on an ambient compiler default.

V1 adoption is explicit through `adoptsV1`. The validator requires the named v1
entry to exist and to publish an overlapping proof type. Adoption adds v2
selection capability without mutating, auto-upgrading, or deprecating v1.

### 3.4 Safe entry checklist

Before merging a new entry or a permitted lifecycle transition to the public default branch:

1. For a new identity, create a new `<predicateId>/<entryVersion>/` directory. Do not alter an already committed identity field, referenced circuit source package, encoder-associated binding sidecar, or binding schema.
2. For circuit evolution, satisfy every additive requirement in §3.2, including a matching new binding sidecar and a distinct proof type for a same-lineage replacement until explicit entry-version selection exists. Retain the old source package, artifacts, encoder, sidecar, schemas, and entry.
3. Pin the candidate entry from its current bytes and generated artifacts:

   ```sh
   python3 registry/pin_entry.py \
     --predicate-id <predicateId> \
     --entry-version <entryVersion> \
     --circuit <circuitName> \
     --source-path <repo-relative-source-path> \
     --public-input-encoder <repo-relative-encoder-path> \
     --manifest artifacts/build/manifest.json
   ```

   For an existing lineage, copy the report's `requiredActivationSupersedes` value into `activation.supersedes`; the history gate requires that immediate-predecessor link.

4. Validate the working tree and artifact pins:

   ```sh
   python3 tests/vectors/validate_public_input_encoders.py
   python3 registry/validate.py --manifest artifacts/build/manifest.json
   ```

5. Check the proposed history transition against the public default branch before merge:

   ```sh
   python3 registry/check_immutability.py --base-ref <ci-base-sha>
   ```

6. For a review, activation, or deprecation transition, verify that the diff changes only its permitted metadata and that the public evidence is resolvable. Merge only after the history checker and CI succeed.

## 4. Predicate pluralism (Safeguard 1)

- **Independent predicate lineages coexist, including where proof types overlap.** `predicateId` identifies an *author's lineage*, not the proof type: independent authors may register and retain independent lineages for the same `proofTypes`, serving local trust decisions without registry-side consolidation. The repo seeds two listings for `zkc:proof:kyc:v1` (`zkc-kyc`, `community-kyc`) to keep this executable. **`community-kyc` is a seed, not a third-party listing:** it is authored by the same party as `zkc-kyc` and pins the identical circuit. It demonstrates that the *mechanism* admits parallel lineages without blessing either; it is not evidence that an independent author has actually shown up. Its entry says so in its own `author.name`.
- **Lookups return ALL matches, never a blessed one.** `resolve_all()`, `lookup_issuers()`, and `find_accepting_verifiers()` return every match in deterministic sorted order. Single-entry selection (`resolve()`) is a documented **holder-local** preference (explicit `preferred_predicate_id`, else strongest-assurance-first — `reviewed` before `self_attested` — with a sorted tie-break) — never registry-side ranking. It fails closed: when no entry has an accepted status it returns nothing, unless the caller explicitly passes `allow_unaccepted=True` to inspect the entry.
- The entry schema has **no field** that could mark an entry canonical, default, official, mandatory, or preferred, and the validator rejects any such key anywhere in an entry, schema, or discovery document.

## 5. What the registry does NOT do

- **It does not bless issuers or predicates.** Registry membership confers nothing. The conformance suite contains a seeded negative (`safeguard-1-registry-membership-not-trust` + `adapters/seeded_registry_trust.py`): an implementation that treats registry membership as trust **fails ZKC-Core conformance**.
- **It does not gate verification.** A verifier whose local policy pins predicates directly (committed encoders + circuit/VK hashes) and issuers by key verifies proofs with **no registry present at all** — registry absence is never a verification failure. The one exception is a selector-free proof whose manifest-pinned artifact is also an entry-v2 binding artifact: without the binding record its review and lifecycle gates cannot be checked, so it fails closed (spec §4.2a).
- **It does not own revocation.** Revocation stays per-issuer (accumulators, §2.4 of the spec); the registry stores no revocation state and cannot revoke anything.
- **It does not define a mandatory predicate set** and is not the only registry: any party can publish their own registry of entries for their own predicates; verifier policies may reference predicates and issuers that appear in no registry.

## 6. Enforcement map

| Rule | Enforced by |
|---|---|
| V1/v2 entry structure, exact v2 source closure and canonical identities, binding parent/provenance/artifact pins, independent review/lifecycle, non-exclusivity | `registry/validate.py` + `registry/noir_package.py` (CI: check/artifact jobs) |
| Immutable committed v1/v2 identity and transitive bytes; immutable binding artifacts/provenance; monotonic source and binding lifecycle; additive evolution | `registry/check_immutability.py --base-ref <ci-base-sha>` (merge base on PR/merge queue; `--exact-base` with the event before-SHA on default-branch push) |
| Candidate identity/artifact pin construction | `registry/pin_entry.py --predicate-id … --entry-version … --circuit … --source-path … --public-input-encoder … --manifest …` (author workflow; inspect its read-only JSON report before validation and history CI) |
| `self_attested` and `reviewed` entries carry public evidence | `registry/validate.py` (CI: check job) |
| `self_attested` entries carry no review-completion date | `registry/validate.py` (CI: check job) |
| ACIR/VK hash pinning | `registry/validate.py --manifest` (CI: artifacts job) |
| Holder default refusal + logged overrides | `tests/python/test_predicate_registry.py` |
| No entry claims `reviewed` without independent review | `tests/python/test_predicate_registry.py::test_shipped_entries_claim_no_independent_review` |
| A `["reviewed"]` policy rejects this registry's self-attested entries | `tests/python/test_predicate_registry.py::test_policy_requiring_reviewed_rejects_self_attested_repo_predicate` |
| Discovery never confers trust | `conformance/check_discovery_safeguards.py` (CI) |
| Membership-as-trust fails conformance | `safeguard-1-registry-membership-not-trust` + seeded adapters (CI) |
| Pluralism + chokepoint resistance (local copy, registry absence) | `tests/python/test_registry_governance_safeguards.py` |

The `Check & Test` context MUST be required for pull requests and merge groups in the repository ruleset. Because a repository-local workflow cannot defend itself against a change that rewrites both the workflow and its checker, deployments requiring adversarial protection MUST additionally use an organization/ruleset-managed required workflow (or equivalent trusted control) for this history comparison. The default-branch `push` run is a detection backstop, not permission to bypass pre-merge enforcement.

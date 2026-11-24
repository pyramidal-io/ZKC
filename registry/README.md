# ZKC Registry

Versioned, in-repo registry data for the ZKC ecosystem. The registry is
**advisory and non-exclusive**: it exists for discovery and review transparency, never as a trust anchor or policy chokepoint.

- Registry presence **never confers trust** (Freedom Safeguard 1). Verifier trust policies are verifier-local and may reference predicates and issuers that are not in any registry.
- There is **no canonical, default, official, or mandatory** entry of any kind; multiple entries from independent authors may serve the same proof type, and the validator rejects any field that asserts exclusivity.
- Registry presence is **not an assurance signal** either. Read each entry's `review.status` and follow its `review.evidence` before relying on it.

## Layout

```
registry/
  schema/predicate-entry.schema.json   # frozen predicate entry v1 schema
  schema/predicate-entry-v2.schema.json # source-identity entry schema
  schema/artifact-binding-v1.schema.json # independently governed build binding
  schema/verifier-policy.schema.json   # published verifier policy schema
  predicates/<predicateId>/<entryVersion>/entry.json
  predicates/<predicateId>/<entryVersion>/bindings/<binding-digest>.json
  toolchains/<provenance>.json         # hash-pinned build provenance
  reviews/<predicateId>-<entryVersion>.md  # committed review-evidence records
  issuers/<name>.json                  # issuer metadata documents (discovery)
  verifiers/<name>.json                # published verifier trust policies
  validate.py                          # current-tree governance validator (CI-enforced)
  noir_package.py                     # safe workspace package/dependency inspection
  pin_entry.py                         # candidate identity/artifact pinning helper
  check_immutability.py                # committed-identity history checker (CI-enforced)
```

## Discovery registry (`issuers/`, `verifiers/`)

- `issuers/*.json` are issuer metadata documents (`schemas/issuer-metadata.schema.json`). Listing an issuer here is **discovery only** — it grants the issuer nothing, and no verifier is ever required to trust it.
- `verifiers/*.json` are **published** verifier trust policies (`schema/verifier-policy.schema.json`): what proof types a verifier accepts, which review statuses it requires, and its key-exact issuer allowlist. Publication is informational; the verifier enforces its policy locally and may change it at will.
- Policies reference issuers **by key, never by registry membership** — a policy may trust issuers that appear in no registry (`acceptsOutOfRegistryIssuers`), and an empty allowlist trusts nobody.
- Python API: `python/zkc_registry` — `lookup_issuers(...)`, `find_accepting_verifiers(...)`, `to_holder_trust_policy(...)`, `to_verifier_trust_policy(...)`. Executable safeguard checks: `conformance/check_discovery_safeguards.py`.

## Governance rules

- **Open review and publication:** entries are added and changed via pull request — the PR review *is* the public review process (Freedom Safeguard 4). Merging to the public default branch publishes an entry as a reviewable record regardless of `draft`, `in_review`, or any other `review.status`; it does not activate or trust the entry. `self_attested`, `reviewed`, and `deprecated` entries must carry public review evidence: either a public pull-request URL in this repository, or a committed review record under `reviews/` (see `reviews/README.md`). The public snapshot also supplies explicitly labelled public status/evidence dispositions where a local evidence path would otherwise be unavailable. A disposition reports only the published metadata and public inspection surface; it does not claim newly performed verification or independent review, and does not upgrade the entry's recorded status.
- **Honest statuses:** `self_attested` means the author published evidence of their **own** verification and **no independent review exists**; `reviewed` additionally requires a publicly recorded review by someone other than the author. **Nothing in this registry is `reviewed` today.** The `zkc-remaining-predicates` 1.0.0–4.0.0 entries are deprecated for raw-code-padding and sorted-neighbour findings; the 5.0.0/6.0.0 entries are also deprecated because their issuer credential digest omits `validFrom` (`reviews/zkc-remaining-predicates-v5-v6-deprecation.md`). All six remain historical compatibility records and require an explicit deprecated-identity verifier opt-in. The additive, fully pinned 7.0.0 (linkable) and 8.0.0 (anonymous/scoped) entries are the self-attested combined successors. The `zkc-credential-rebind` 1.0.0–4.0.0 entries are deprecated because their statements authenticate no credential (`reviews/zkc-credential-rebind-v1-v4-deprecation.md`); unlike the other deprecations there is no historical-verification exception — the reference holder never generates them and the reference verifier rejects them unconditionally. Their issuer-authenticated successors are specified in the ZKC specification §7.4 and published as additive 5.0.0 (linkable) / 6.0.0 (scoped) entries. Status definitions and the path from `self_attested` to `reviewed`: `docs/zkc_predicate_registry_governance.md` §2.
- **Committed identity:** once merged to the public default branch, `predicateId`, `entryVersion`, `proofTypes`, the complete `circuit` block, and `publicInputEncoder` are immutable. Admission binds `circuit.name` to the matching `noir/<name>/src/main.nr` workspace bin package, rejects unsafe or incomplete local-dependency closures, validates the encoder shape, and cross-checks its path against the generated artifact manifest. The history gate then byte-protects the direct package, every recursively referenced repository-local dependency package, the encoder, its same-filename `schemas/public-input-bindings/` verifier-contract sidecar, and the exact canonical schema selected by that sidecar. Admission supports only the exact v1 (`zkc:public-input-bindings:v1`, `https://zkc.dev/schemas/public-input-binding-v1.schema.json`) and v2 (`zkc:public-input-bindings:v2`, `https://zkc.dev/schemas/public-input-binding-v2.schema.json`) `version`/`$schema` pairs; future versions require explicit validator and history-gate support. Entry v1 needs no migration field because the association is derived from the immutable encoder path. Review evidence/status, activation, and deprecation metadata may transition without changing identity.
- **Strictly additive evolution:** a circuit replacement adds a previously unreferenced source package, its generated artifacts, a public-input encoder and matching binding sidecar, a new `<entryVersion>` whose `activation.supersedes` names the immediate predecessor, and (until explicit entry-version or binding-contract selection exists) a distinct proof type for the same lineage. A version bump alone is insufficient; retain all old sources, artifacts, encoders, sidecars, binding schemas, and entries. No committed sidecar field may change in place, including an apparent `free` → `bound` tightening.
- **Activation and deprecation:** `activation.activatedAt` means activated/published-for-use, not first publication. Deprecated entries keep their full pinned identity and are never deleted.
- **Artifact pinning:** ACIR/VK hashes are cross-checked against the generated artifact manifest in CI (`--manifest artifacts/build/manifest.json`). The COMMITTED artifact set (`artifacts/manifest.json` plus per-circuit ACIR/vk files, maintained by `scripts/publish_artifacts.py`) is additionally drift-gated in CI against a fresh pinned-toolchain build (`scripts/publish_artifacts.py --check`) and cross-checked against every entry, so a fresh checkout resolves manifest-pinned verification keys that provably match the committed circuit identities.
- **Entry v2 separates source from builds:** `zkc:registry:predicate-entry:v2` commits the exact transitive source-file manifest and public-input contract as `sourceId = sha256(JCS({source, publicInputContract}))`. Each `zkc:registry:artifact-binding:v1` child independently commits its parent tuple, source id, proof system, exact compiler/backend provenance, build profile, artifact paths, and ACIR/VK hashes as `bindingId = sha256(JCS(immutableBindingFields))`. The filename is the binding digest. Source and binding review, activation, supersession, and deprecation are independent; neither can silently confer assurance on the other.
- **Unique selector-free encoder identity:** independent registry listings may share the same frozen encoder and circuit. Two encoder documents declaring the same proof type (including across predicate lineages or a copied encoder naming the same circuit) are rejected by both registry and encoder validation. The holder and verifier omit ambiguous types from selector-free resolution; a holder-local predicate preference cannot override a collision. Different selector-free statements require distinct proof types. Exact v2 artifact selection remains independent of this guard and never falls back through the legacy map. Historical credential-authentication containment exceptions additionally pin the exact circuit, proof types, and source digest in `python/zkc_registry/containment.py`; copying a historical label cannot grant a new statement that exception.
- **Exact selection, no ambient fallback:** a v2 proof selects the complete `(predicateId, entryVersion, bindingId)` tuple. The selector is committed by the authenticated request extension `zkc:request:binding-selectors:v1`, copied unchanged into the proof entry, resolved by exact manifest key, and retained in verifier audit evidence. Unknown, malformed, inactive, deprecated, disallowed, or cross-wired selectors fail closed. Selector-free requests retain their v1 proof type, circuit, encoder, and VK. If the VK pins on that circuit's manifest row uniquely identify the same artifact as a v2 binding, the verifier also applies that exact binding's review, lifecycle, and local-allowlist gates and labels the policy alias in audit evidence. Ambiguous, partial, or cross-wired aliases fail closed. No selector-free request chooses a different artifact by recency, iteration order, ambient toolchain, or key trial.

The reference adoption fixture is `zkc-kyc@4.0.0`. It declares `adoptsV1:
"zkc-kyc@2.0.0"` and binds the same source/contract to two simultaneously
active artifacts: `historical` (Noir beta.21) and `successor` (Noir beta.25).
This is an adoption marker, not a rewrite or deprecation of the v1 entry.

Use `predicateId` and `entryVersion` to identify a registry entry and
`circuit.name` to identify its Noir package. A pinned source header can retain
the predecessor's version label when the source is reused. For example,
`zkc-jurisdiction@5.0.0` pins package `zkc_jurisdiction_v5`, whose source header
still says v4 because the two packages share identical `src/main.nr` bytes.
Source headers are part of the pinned bytes.

Run locally:

```
python3 registry/validate.py
```

For a safe new identity or lifecycle transition:

```sh
python3 registry/pin_entry.py \
  --predicate-id <predicateId> \
  --entry-version <entryVersion> \
  --circuit <circuitName> \
  --source-path <repo-relative-source-path> \
  --public-input-encoder <repo-relative-encoder-path> \
  --manifest artifacts/build/manifest.json
python3 registry/validate.py --manifest artifacts/build/manifest.json
python3 registry/check_immutability.py --base-ref <ci-base-sha>
```

`pin_entry.py` emits a read-only JSON report for the candidate identity and artifact pins; for a successor, its `requiredActivationSupersedes` value is the required immediate-predecessor link. Inspect the report before validation and CI. The history checker rejects changed committed identity fields, direct/local-dependency package bytes, encoder bytes, binding-sidecar bytes, and binding-schema bytes. It compares the merge base for pull requests and merge groups, and the exact event `before` tree for default-branch push audits so a force rewrite cannot hide a deletion behind an older merge base. Require registry validation, pinned artifact cross-checks, and the history checker for the exact pull-request head in the repository's protected CI path. Configure that enforcement on the hosting provider; a repository-local workflow cannot protect itself from a coordinated rewrite. A workflow declaration alone does not establish that a particular host has enabled branch protection. For circuit evolution, add the complete replacement set described above; for review, activation, or deprecation, change only permitted metadata.

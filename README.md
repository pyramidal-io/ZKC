# ZKC — Zero-Knowledge Compliance

This is the public snapshot of the **ZKC protocol specification**, its
**Noir/BN254 reference circuits**, and the stdlib-only Python reference
implementation.

ZKC is a draft standard for proving compliance properties while minimizing
credential disclosure. The repository contains research and reference code;
it has not been independently audited and is not production certified.

## Repository contents

| Path | Contents |
|------|----------|
| [`docs/zkc_specification.md`](docs/zkc_specification.md) | Canonical protocol specification (`0.4.1-draft`) |
| [`noir/`](noir/) | Noir/BN254 reference circuit workspace |
| [`python/`](python/) | Stdlib-only Python reference packages |
| [`conformance/`](conformance/) | Reference conformance runners and vectors |
| [`registry/`](registry/) | Predicate, issuer, verifier, and review registry |
| [`PUBLIC_ALLOWLIST`](PUBLIC_ALLOWLIST) | Exact-file source publication policy |
| [`PUBLIC_SURFACE`](PUBLIC_SURFACE) | Exact public-only overlay manifest |
| [`docs/public-snapshot-provenance.md`](docs/public-snapshot-provenance.md) | Snapshot origin and verification boundary |

This repository is generated as a fresh-history snapshot. Its root commit has
no private ancestry, and its tracked tree is exactly the reviewed union of
`PUBLIC_ALLOWLIST` and `PUBLIC_SURFACE`.

### Protocol-family provenance

The epoch identifier and SHA-256 digests are the verifiable contract in a
clean public checkout. The lock's commit identifies the upstream development
epoch merge. Public history lacks that commit. The `protocols.*.owner` values
name private development repositories. The public ZKC repository is
`pyramidal-io/ZKC`. Its private development repository is
`pyramidal-io/ZKC.dev`.

The snapshot preserves the exact upstream bytes, including these reviewed
provenance references:

- [`protocol-family/snapshot-lock.json`](protocol-family/snapshot-lock.json)
  carries `canonical_repository` and `canonical_commit`.
- [`protocol-family/interface-manifest-v1.json`](protocol-family/interface-manifest-v1.json)
  carries `authority.repository`, `protocols.*.owner`, and three authority
  paths. `authority.manifest_path` is `protocol-family/interface-manifest-v1.json`,
  `authority.vector_path` is `protocol-family/golden-vectors-v1.json`, and
  `authority.matrix_path` is `protocol-family/compatibility-matrix.md`.
- [`protocol-family/interface-manifest-v1.schema.json`](protocol-family/interface-manifest-v1.schema.json)
  pins `properties.authority.properties.repository.const` and carries the public
  `$schema` URI `https://json-schema.org/draft/2020-12/schema` and `$id`
  `https://zka.dev/protocol-family/interface-manifest-v1.schema.json`.
- [`scripts/validate_protocol_family.py`](scripts/validate_protocol_family.py)
  contains two `pyramidal-io/ZKA.dev` literals, in the predecessor check and the
  snapshot lock check.

The manifest also retains the following repository-relative paths in sibling
`projections.*.assertions[].path` fields. ZKC's local validation needs only the
ZKC projection and the vendored inputs.

| Projection | Paths |
|----------|-------|
| AFP | `docs/afp_presentation_public_input_classification_v1.json`, `docs/afp_specification.md`, `docs/kdc_v1_0_3_domain_registry.json`, `docs/payment_venue_v2_conformance.json`, `protocol-family/afp-interface-surface-v1.json` |
| ZKA | `.noir-version`, `contracts/ethereum/ZKMAtomicSettlement.sol`, `docs/ZKA_ZKC_AFP_MIGRATION.md`, `docs/zka_specification.md`, `schemas/compliance-bundle-v1.schema.json`, `schemas/public-inputs/zka_transfer_binding_v2.json`, `src/zka-sdk/src/zkm/mod.rs`, `tests/vectors/crypto/zkc_presentation_binding.json` |
| ZKM | `.noir-version`, `docs/zkm_specification.md`, `protocol-family/zkm-statement-registry-v1.json`, `tests/vectors/afp_kdc_v1_0_2_conformance.json` |

## Reference checks

Run the stdlib-only Python suite from the repository root:

```bash
python3 -m unittest discover -s tests/python -t tests/python -v
python3 scripts/validate_protocol_family.py validate --repo zkc --root .
python3 conformance/run_zkc_core.py
```

Reference conformance and delegated viewing exercise the published Jurisdiction
[v3](registry/predicates/zkc-jurisdiction/3.0.0/entry.json) and
[v4](registry/predicates/zkc-jurisdiction/4.0.0/entry.json) identities. The
[v5](registry/predicates/zkc-jurisdiction/5.0.0/entry.json) entry is a draft fixture used by the Python tests. Its activation date is unset.

Live-proof tests report `pinned historical nargo/bb toolchain not on PATH` when
the pinned historical pair is unavailable, and `beta.25 nargo / bb 5.0.0 not
available` when that successor pair is unavailable. The generated-manifest
cross-check reports `artifact manifest not generated locally` until
`artifacts/build/manifest.json` has been built.

Install both Nargo versions pinned in [`.noir-version`](.noir-version), then
run the circuit checks from the repository root with explicit binary paths:

```bash
python3 scripts/noir_toolchains.py \
  --nargo historical=/path/to/beta.21/nargo \
  --nargo successor=/path/to/beta.25/nargo
python3 registry/validate.py --manifest artifacts/manifest.json
```

The checker verifies both compiler versions, uses the historical formatter,
and checks and tests each public circuit in every lane listed for it in
[`noir/toolchains.json`](noir/toolchains.json). It checks the fetched
Poseidon dependency against the committed source digest.

## Contributing, security, and license

- Contribution model and DCO requirements: [CONTRIBUTING.md](CONTRIBUTING.md)
- Private vulnerability reporting: [SECURITY.md](SECURITY.md)
- Apache License 2.0: [LICENSE](LICENSE) and [NOTICE](NOTICE)

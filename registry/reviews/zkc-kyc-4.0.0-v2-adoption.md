# zkc-kyc 4.0.0 source and artifact-binding review record

This record self-attests the additive predicate-entry v2 adoption of the
frozen `zkc-kyc@2.0.0` source and public-input contract. It does not claim an
independent audit. The source entry inventories the complete direct Noir
package and recursive repository-local dependency closure, the exact encoder,
binding sidecar, and selected binding schema. Its `sourceId` is computed over
that canonical manifest.

The two child bindings independently associate that source identity with the
pinned historical beta.21/nightly Barretenberg output and the beta.25/
Barretenberg 5.0.0 rebuild. Each binding has its own content identity, review,
activation, artifact paths, and manifest key. The generated manifest rebuilds
`zkc_kyc_v2` in both configured lanes and rejects any ACIR, VK, ABI,
provenance, or registry-pin disagreement.

Verification covers exact selector resolution, authenticated APR extension
binding, conjunctive source/binding review policy, local binding allowlists,
inactive/deprecated/cross-wired/malformed rejection, aggregation VK binding,
manifest drift, history immutability, and unchanged selector-free v1 lookup.

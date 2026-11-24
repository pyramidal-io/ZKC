# Deprecation record — `zkc-remaining-predicates` 1.0.0 through 4.0.0

| | |
|---|---|
| **Affected entries** | `registry/predicates/zkc-remaining-predicates/{1.0.0,2.0.0,3.0.0,4.0.0}/entry.json` |
| **Status** | All four entries are `deprecated`; their identity-bearing metadata, source packages, encoders, and artifacts remain published. |
| **Independent review** | None claimed by this maintainer-authored record. |

## Findings

The source-of-funds and tax-residency branches in versions 1 through 4 pass a
raw credential code to sparse-Merkle membership. A raw code of `0` aliases an
empty padding leaf, so a witness for a real empty position can satisfy the
membership statement. The sanctions branch also accepts two proven members
that merely bracket the subject numerically; without consecutive leaf indices,
non-adjacent outer members can conceal a blocked member between them.

## Disposition

The v5 entry is the hardened linkable-profile successor of the v3 profile;
the v6 entry is the hardened anonymous/scoped successor of the v4 profile.
Both reserve raw source/tax code `0` and require adjacent sanctions neighbours.
The registry's same-lineage rule requires immediate `activation.supersedes`
links, therefore the formal chain is `... -> 4.0.0 -> 5.0.0 -> 6.0.0` while
the profile ancestry is recorded in the v5/v6 titles and review records.

Deprecation changes only permitted entry metadata. Historical verification may
continue only under an explicit verifier trust decision; new proof generation
must use the fully pinned v5/v6 identities.

# Deprecation record — `zkc-remaining-predicates` 5.0.0 and 6.0.0

| | |
|---|---|
| **Affected entries** | `registry/predicates/zkc-remaining-predicates/{5.0.0,6.0.0}/entry.json` |
| **Status** | Both entries are `deprecated`; their identity-bearing metadata, source packages, encoders, and artifacts remain published. |
| **Independent review** | None claimed by this maintainer-authored record. |
| **Source** | ZKC protocol review 2026-10-04 (finding R1.4). |

## Findings

The v5 (linkable) and v6 (anonymous/scoped) circuits close the raw-code and
sanctions-adjacency defects of versions 1 through 4, but the issuer credential
digest they verify does not cover `validFrom`. A holder can therefore supply a
forged `validFrom` and present a credential before the issuer made it valid:
the review reproduced a not-yet-valid credential proving under v5 and v6, and
the same credential rejected by v8, whose v2 profile digest authenticates both
`validFrom` and `validUntil`.

## Disposition

The v7 entry is the validity-bound linkable successor of v5, and the v8 entry
is the validity-bound anonymous/scoped successor of v6. New proof generation
already resolves to v7/v8 (spec §7.2a); this record makes the registry status
agree with that rule. The deprecation reasons of 3.0.0 and 4.0.0 now point to
v7/v8 as well, since their previously named v5/v6 successors are themselves
deprecated.

Deprecation changes only permitted entry metadata. A verifier accepts a
deprecated identity only under an explicit trust decision: its policy MUST list
`deprecated` in `accepted_review_statuses`, otherwise authenticated verification rejects the proof with
`DEPRECATED_PROOF_TYPE`, independently of registry absence or additional
current-status aliases. Unauthenticated historical proofs retain their
`UNSIGNED_REQUEST` refusal (spec
§6.2, §7.2a).

# Registry review evidence records

Committed review-evidence records for predicate registry entries. A `self_attested`, `reviewed`, or `deprecated` entry carries `review.evidence` pointing either at a public pull request in this repository or at a record in this directory (see `docs/zkc_predicate_registry_governance.md` §2).

```
registry/reviews/<predicateId>-<entryVersion>.md
```

Each record states, for one entry version: the scope of what was examined, the artifacts examined, the verification actually performed, the findings raised and their disposition, and — explicitly — what review did **not** happen.

## Honesty rules for these records

These records are evidence, not endorsement. They are written to be falsifiable by a reader with only this repository:

- **Cite committed artifacts, not history.** A record cites repo-relative paths and the hashes pinned in the entry, so a reader can re-run the same checks. It does not depend on any commit or pull-request identifier resolving.
- **Name the reviewer accurately.** A record states who or what performed the review. Automated review tooling is named as automated tooling; it is never described as independent assessment.
- **State the absence of review as plainly as its presence.** If no independent human review, cryptographic audit, or external sign-off has occurred, the record says so in its own section. Silence is not permitted to imply assurance.
- **Record unresolved findings.** A finding that was raised and not remediated stays in the record, marked open.

## Relationship to review status

A record documents evidence; it does not by itself justify a `review.status` of `reviewed`. Where the evidence in a record does not support that status, the record says so, and resolving the discrepancy is a governance decision — not something the record silently absorbs.

**This has already happened once.** Every record in this directory documented verification performed by the entry's own author, with no independent review. On 2026-07-31 the six 1.0.0 entries were therefore moved from `reviewed` to **`self_attested`** — the status that says exactly that. The records were not changed to fit the old status; the status was changed to fit the records.

A record that supports `self_attested` and nothing more is a complete, correct record. Upgrading an entry to `reviewed` requires *new* evidence: a review performed by someone other than the author, publicly recorded (see the governance doc's "Path from `self_attested` to `reviewed`").

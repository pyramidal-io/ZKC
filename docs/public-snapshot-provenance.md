# Public snapshot provenance

This repository is generated rather than developed in place. Canonical ZKC
development occurs in a private repository; a reviewed exporter constructs
this public snapshot from one immutable private revision.

## Exact published tree

The tracked tree is exactly the disjoint union of:

- the canonical source files named in [`PUBLIC_ALLOWLIST`](../PUBLIC_ALLOWLIST);
  and
- the public-only destination files named in
  [`PUBLIC_SURFACE`](../PUBLIC_SURFACE).

Both policies are exact-file, default-deny inventories. Directory rules,
globs, implicit copying, symlinks, submodules, duplicate destinations, policy
overlap, and unlisted tracked files fail closed. Public CI revalidates this
tree and requires every workflow action to use an immutable forty-hex commit
reference.

## History boundary

The initial public commit is built in a fresh Git object database and has zero
parents. It contains no private refs, commits, tags, alternates, commit
messages, or ancestry. Approved source blobs may retain their content-derived
object IDs; this does not import private history.

An unpublished or staging candidate whose source is later found unsafe is
invalidated rather than advanced. Its target is never reused: the replacement
uses bootstrap mode against a different, verified-empty target and creates a
new zero-parent root from the final fixed source. Only after a reviewed public
root has actually been released may later snapshots extend that generated
public history. They never replay the private repository's commit graph.

## Provenance evidence

Generated public commits include publication schema/mode metadata plus policy
and inventory digest trailers. They never include the private source commit
SHA. The source revision, deterministic-export comparison, tree and commit
identities, ancestry checks, and scanner results are retained only in private,
redacted publication reports for review and audit.

The public repository can independently verify its checked-out tree with:

```bash
.github/scripts/check-public-surface.sh
python3 scripts/validate_public_allowlist.py --revision "$(git rev-parse HEAD)"
```

Regenerating the snapshot requires access to the private repository, the
reviewed overlay map, and the exporter. None of those private inputs is part of
the public tree.

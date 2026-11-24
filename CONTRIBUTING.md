# Contributing to ZKC

Thank you for your interest in ZKC. This repository is a generated public
snapshot of the specification and reference implementation. Canonical
development happens in a private repository and reaches this repository only
through a reviewed, allowlisted export. See
[the provenance document](docs/public-snapshot-provenance.md).

## Contributions

- Open an issue for specification ambiguities, interoperability problems, or
  documentation defects.
- Report suspected vulnerabilities privately as described in
  [SECURITY.md](SECURITY.md); do not open a public security issue.
- Focus pull requests on the published surface. Accepted changes may be ported
  to the canonical repository and appear in a later generated snapshot rather
  than being merged here directly.

## Developer Certificate of Origin

Every commit must carry a sign-off certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):

```bash
git commit -s
```

The sign-off must match the commit author. By signing off, you certify that you
have the right to submit the contribution under this repository's licenses and
that it may be redistributed under them.

## Public checks

Pull requests run read-only public CI. The gate verifies that the tracked tree
is exactly `PUBLIC_ALLOWLIST` plus `PUBLIC_SURFACE`, all tracked objects have
reviewed regular-file modes, workflow actions are immutable SHA references,
the source inventory validates at the checked-out commit, and the committed
tree passes the pinned secret scanner.

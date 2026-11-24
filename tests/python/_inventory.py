"""Expected test inventories for private source and its exact public snapshot.

A snapshot is identified by the public overlay manifest. Expected subsets come
from PUBLIC_ALLOWLIST, never from the files that happen to survive an export.
Missing allowlisted files therefore remain test failures.
"""

from _path import REPO_ROOT

IS_PUBLIC_SNAPSHOT = (REPO_ROOT / "PUBLIC_SURFACE").is_file()


def expected_public_paths(prefix: str, suffix: str) -> set[str]:
    return {
        line.strip()
        for line in (REPO_ROOT / "PUBLIC_ALLOWLIST").read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
        and line.strip().startswith(prefix) and line.strip().endswith(suffix)
    }


def expected_circuits(all_circuits: set[str]) -> set[str]:
    if not IS_PUBLIC_SNAPSHOT:
        return all_circuits
    return {
        path.rsplit("/", 1)[1][:-5]
        for path in expected_public_paths("schemas/public-input-bindings/", ".json")
    }


def expected_entries(all_entries: set[str]) -> set[str]:
    if not IS_PUBLIC_SNAPSHOT:
        return all_entries
    published = {
        "@".join(path.split("/")[2:4])
        for path in expected_public_paths("registry/predicates/", "/entry.json")
    }
    return all_entries & published


# Exact runtime-only contracts whose encoders are outside the reviewed public
# inventory. Deleting an exported encoder cannot increase this exclusion set.
_UNPUBLISHED_REQUEST_VERSIONS = {
    'accreditation': (9, 10, 12, 13),
    'community_kyc': (2, 3),
    'credential_rebind': (4,),
    'jurisdiction': (6, 7, 8),
    'kyc': (4,),
    'rebind': (5, 6),
    'sanctions': (9, 10, 11, 12, 13, 14),
    'selective_disclosure': (2, 3, 4),
    'source': (9, 10, 11, 12, 13, 14),
    'tax': (9, 10, 11, 12, 13, 14),
}
UNPUBLISHED_REQUEST_PROOF_TYPES = frozenset(
    f"zkc:proof:{family}:v{version}"
    for family, versions in _UNPUBLISHED_REQUEST_VERSIONS.items()
    for version in versions
)

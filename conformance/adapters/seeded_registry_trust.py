#!/usr/bin/env python3
"""Deliberately NON-CONFORMANT adapter: registry membership as trust.

Isolates RegistryMembershipTrustingVerifierAdapter (see seeded_negatives.py)
so the suite's teeth against THIS violation are provable without the
canonical-issuer violation also being in play. The conformance suite MUST
fail it on safeguard-1-registry-membership-not-trust.

DO NOT use this as a starting point for an implementation.
"""

from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
for path in (str(REPO_ROOT / "python"), str(REPO_ROOT / "conformance")):
    if path not in sys.path:
        sys.path.insert(0, path)

from adapters.reference import ReferenceHolderAdapter  # noqa: E402
from adapters.seeded_negatives import (  # noqa: E402
    RegistryMembershipTrustingVerifierAdapter,
)


def make_holder_adapter():
    return ReferenceHolderAdapter()


def make_verifier_adapter():
    return RegistryMembershipTrustingVerifierAdapter()

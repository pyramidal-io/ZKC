#!/usr/bin/env python3
"""Deliberately NON-CONFORMANT adapter: a new random receipt key for every receipt, linkable ones included.

Isolates UnstableReceiptKeyHolderAdapter (see seeded_negatives.py). The holder echoes its own key as
receiptHolderKey, so only the runner's receipt key-scope probes (spec 5.6.1)
can catch it. The conformance suite MUST fail it on safeguard-6-receipt-*.

DO NOT use this as a starting point for an implementation.
"""

from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
for path in (str(REPO_ROOT / "python"), str(REPO_ROOT / "conformance")):
    if path not in sys.path:
        sys.path.insert(0, path)

from adapters.reference import ReferenceVerifierAdapter  # noqa: E402
from adapters.seeded_negatives import UnstableReceiptKeyHolderAdapter  # noqa: E402


def make_holder_adapter():
    return UnstableReceiptKeyHolderAdapter()


def make_verifier_adapter():
    return ReferenceVerifierAdapter()

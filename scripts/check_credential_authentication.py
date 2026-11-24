#!/usr/bin/env python3
"""Fail closed when a credential-derived circuit is not actually authenticated.

The credential-rebind lineage shipped four proof identities that *described*
credential continuity while constraining only holder-key continuity: their
credential fields were unconstrained prover witnesses and no issuer signature
or accumulator membership was ever verified. Nothing mechanical caught that —
the circuits compiled, their tests passed, the encoders validated, and the
verifier had a handler for them.

This gate is that missing check. For every circuit a committed public-input
encoder declares, it requires one of exactly two dispositions, and rejects
anything in between:

  AUTHENTICATED  main unconditionally asserts reviewed issuer authentication
                 AND accumulator membership against public key/root/epoch inputs;
                 it publishes a binding
                 sidecar; every proof type it serves has a verifier
                 request-binding contract; and it carries adversarial
                 main-driven negative tests executed by pinned Nargo, with
                 honest, main-execution and constraint-removal controls.

  CONTAINED      the circuit lacks supported authentication evidence, and EVERY proof type
                 it serves is rejected unconditionally by the verifier (the
                 credential-rebind containment) or requires a literal signed
                 APR authorization (the historical predicate identities).

A credential-derived circuit that is neither — one that asserts things about a
credential without authenticating it, yet is semantically acceptable to the
verifier — fails this check. So does an authenticated circuit that loses its
issuer signature, its revocation proof, its sidecar, its verifier contract, or
its negative tests.

The bounded analyzer in credential_authentication.py rejects unsupported call
shapes. Reviewed gadget body/manifest pins establish assertion semantics; lexical
reachability alone never does. It does not prove arbitrary predicate semantics.
Tests run in disposable source copies, leaving frozen packages untouched.
Both pinned Nargo binaries must be available through ZKC_HISTORICAL_NARGO and
ZKC_SUCCESSOR_NARGO (or an exactly matching nargo on PATH).

Envelope-level aggregation circuits commit to supplied component proof data.
The v1 block is checked as an envelope commitment, and v2 blocks are refused.
These circuit identities are listed explicitly outside the per-proof chokepoint.

Usage: python3 scripts/check_credential_authentication.py [--json]
Standard library only.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ENCODER_DIR = ROOT / "schemas" / "public-inputs"
BINDING_DIR = ROOT / "schemas" / "public-input-bindings"
NOIR_DIR = ROOT / "noir"

sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "scripts"))

from credential_authentication import AuthenticationError, analyze, execute
from zkc_registry.containment import matches_containment_identity
from zkc_registry.encoder_resolution import encoder_circuits

# Envelope-level statements bind component proofs rather than credentials.
NON_CREDENTIAL_CIRCUITS = frozenset(
    {"zkc_aggregation", "zkc_aggregation_v2", "zkc_aggregation_v3"}
)


def verifier_dispositions() -> tuple[set, set, set]:
    """(bound proof types, unconditionally rejected, APR-only) per the verifier."""
    from zkc_verifier import verifier as module

    return (
        set(module._REQUEST_BINDINGS),
        set(module._UNAUTHENTICATED_REBIND_PROOF_TYPES),
        set(module._AUTHENTICATED_HISTORICAL_PROOF_TYPES),
    )


def report() -> tuple[list[str], list[dict]]:
    findings: list[str] = []
    receipts: list[dict] = []
    bound, contained, apr_only = verifier_dispositions()
    _, collisions = encoder_circuits(ROOT)
    findings.extend(collisions)
    encoders = sorted(ENCODER_DIR.glob("*.json"))
    if not encoders:
        findings.append("no public-input encoders found; no circuit was checked")
    authenticated = []
    for encoder_path in encoders:
        encoder = json.loads(encoder_path.read_text(encoding="utf-8"))
        circuit = encoder["circuit"]
        proof_types = list(encoder["proofTypes"])
        where = encoder_path.relative_to(ROOT)
        if not (BINDING_DIR / f"{circuit}.json").is_file():
            findings.append(f"{where}: {circuit} publishes no binding classification sidecar")
        if circuit in NON_CREDENTIAL_CIRCUITS:
            continue
        rejected = [pt for pt in proof_types
                    if (pt in contained or pt in apr_only)
                    and matches_containment_identity(ROOT, circuit, pt)]
        try:
            evidence = analyze(NOIR_DIR, circuit)
        except (AuthenticationError, OSError, ValueError) as exc:
            missing = [pt for pt in proof_types if pt not in rejected]
            if missing:
                findings.append(
                    f"{where}: {circuit} has no supported main credential-authentication "
                    f"evidence ({exc}); {', '.join(sorted(missing))} has "
                    "no exact frozen circuit containment disposition. Either authenticate "
                    "the statement or contain the identity."
                )
            continue
        for proof_type in proof_types:
            if proof_type not in bound:
                findings.append(
                    f"{where}: {proof_type} has no verifier request-binding contract; "
                    "an authenticated credential statement must declare how it binds to the request"
                )
        authenticated.append(evidence)
    # Do not spend compiler time on a tree already rejected by the static gates.
    # There is no public success/skip-execution mode.
    if not findings:
        for evidence in authenticated:
            try:
                receipts.extend(execute(ROOT, evidence))
            except (AuthenticationError, OSError, ValueError, subprocess.SubprocessError) as exc:
                findings.append(f"noir/{evidence.circuit}: main test evidence failed: {exc}")
    return findings, receipts


def check() -> list[str]:
    return report()[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit a machine-readable report")
    arguments = parser.parse_args()

    findings, receipts = report()
    if arguments.json:
        print(json.dumps({"findings": findings, "ok": not findings, "main_test_evidence": receipts}, indent=2))
    elif findings:
        for finding in findings:
            print(f"error: {finding}", file=sys.stderr)
    else:
        encoders = len(list(ENCODER_DIR.glob("*.json")))
        print(
            f"credential authentication check passed: {encoders} circuits are each "
            "authenticated-and-bound or explicitly contained"
        )
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""ZKC-Core conformance runner.

Runs the machine-readable vectors in conformance/vectors/ against an adapter
(default: the bundled reference implementation) and reports deterministic
per-case PASS/FAIL plus a summary. Exit code 0 only when every case passes.

Usage:
    python3 conformance/run_zkc_core.py
    python3 conformance/run_zkc_core.py --adapter adapters.reference
    python3 conformance/run_zkc_core.py --holder-adapter X --verifier-adapter Y
    python3 conformance/run_zkc_core.py --json
    python3 conformance/run_zkc_core.py --profile core

Adapter contract: see conformance/README.md. Profiles other than "core" are
expansion hooks (Standard/Full/Agent) and report as not yet published.

Standard library only.
"""

from __future__ import annotations

import argparse
import copy
import importlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
for path in (str(ROOT / "conformance"), str(ROOT / "python"), str(ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

KNOWN_PROFILES = ("core", "standard", "full", "agent")


class CaseFailure(Exception):
    pass


def apply_mutations(envelope: dict, mutations: list) -> dict:
    mutated = copy.deepcopy(envelope)
    for mutation in mutations:
        parts = mutation["path"].split("/")
        target = mutated
        for part in parts[:-1]:
            target = target[int(part)] if isinstance(target, list) else target[part]
        last = parts[-1]
        key = int(last) if isinstance(target, list) else last
        if mutation["op"] == "set":
            target[key] = mutation["value"]
        elif mutation["op"] == "delete":
            del target[key]
        else:
            raise CaseFailure(f"unknown mutation op: {mutation['op']}")
    return mutated


# TEST-ONLY scalars for the runner's own receipt-anchoring probes (spec 5.6.1).
_FOREIGN_HOLDER_SCALAR = 0xF0E1
_ATTACKER_HOLDER_SCALAR = 0x5EC12E7


def check_receipt_anchoring(verifier, receipt: dict, anchor) -> None:
    """A receipt's carried holder key is self-asserted (spec 5.6.1).

    Independently of the case's own expectation, the verifier adapter MUST
    reject the holder's genuine receipt without an expected holder key and
    under a foreign expected key, and MUST reject the same receipt re-signed
    under an attacker key when anchored to the holder's out-of-band key."""
    from zkc_crypto import holder_public_key, sign_receipt

    if verifier.verify_receipt(receipt, expected_holder_key=None).get("valid"):
        raise CaseFailure(
            "verifier accepted a receipt with no expected holder key "
            "(the carried holderKey is self-asserted)"
        )
    foreign = holder_public_key(_FOREIGN_HOLDER_SCALAR)
    if foreign != anchor and verifier.verify_receipt(
        receipt, expected_holder_key=foreign
    ).get("valid"):
        raise CaseFailure("verifier accepted a receipt under a foreign expected holder key")
    if anchor is not None:
        unsigned = {key: value for key, value in receipt.items() if key != "holderSignature"}
        forged = sign_receipt(unsigned, _ATTACKER_HOLDER_SCALAR)
        if verifier.verify_receipt(forged, expected_holder_key=anchor).get("valid"):
            raise CaseFailure(
                "verifier accepted a receipt re-signed under a non-holder key "
                "against the holder's anchored key"
            )


_OTHER_VERIFIER_SCALAR = 0x0C0FFEE5


def _carried_key(generated: dict):
    try:
        return generated["receipt"]["holderSignature"]["holderKey"]
    except (KeyError, TypeError) as exc:
        raise CaseFailure("holder receipt carries no holderSignature.holderKey") from exc


def check_receipt_key_scope(holder, request, apr, credentials, master_seed, first: dict) -> None:
    """Black-box receipt key scope checks (spec 5.6.1, 5.9.3).

    The profile is read from the receipt response: a linkable receipt names
    holderCommitment, a scoped one scopeId, an anonymous one neither.
    (a) Two answers to the same APR: linkable and scoped keys MUST be equal
        (and so must receiptHolderKey), anonymous keys MUST differ.
    (b) A linkable answer to the same request signed by another TEST-ONLY
        verifier key (another verifier identity) MUST carry a different key.
    A holder that echoes an honest, correctly scoped key is indistinguishable
    from an honest holder; these checks catch unstable and global keys."""
    from zkc_crypto import sign_apr

    second = holder.generate_authenticated(request, apr, credentials, master_seed)
    if "receipt" not in second:
        raise CaseFailure(f"holder refused a repeated answer: {second.get('refusal')}")
    response = first["receipt"].get("response") or {}
    stable = "holderCommitment" in response or "scopeId" in response
    same_key = _carried_key(first) == _carried_key(second)
    if stable and not same_key:
        raise CaseFailure(
            "linkable/scoped receipt key is not stable across answers to the same APR "
            "(no relying party can anchor it)"
        )
    if stable and first.get("receiptHolderKey") != second.get("receiptHolderKey"):
        raise CaseFailure("receiptHolderKey is not stable across answers to the same APR")
    if not stable and same_key:
        raise CaseFailure("two anonymous receipts carry the same holder key (linking handle)")
    if "holderCommitment" not in response:
        return
    unsigned = {key: value for key, value in apr.items() if key != "signature"}
    other_apr = sign_apr(unsigned, _OTHER_VERIFIER_SCALAR)
    other = holder.generate_authenticated(request, other_apr, credentials, master_seed)
    if "receipt" not in other:
        raise CaseFailure(
            f"holder refused the same request from another verifier key: {other.get('refusal')}"
        )
    if _carried_key(other) == _carried_key(first):
        raise CaseFailure(
            "linkable receipts to two verifier identities carry the same holder key "
            "(cross-verifier linking handle)"
        )


def check_expect(expect: dict, valid: bool, codes: list) -> None:
    if "valid" in expect:
        if bool(expect["valid"]) != valid:
            raise CaseFailure(f"expected valid={expect['valid']}, got valid={valid} codes={codes}")
    if "anyCode" in expect:
        if not set(expect["anyCode"]) & set(codes):
            raise CaseFailure(f"expected one of {expect['anyCode']}, got {codes}")


def run_case(case: dict, vectors: dict, holder, verifier) -> None:
    kind = case["kind"]
    # Some kinds (e.g. apr_purpose_mismatch) carry gen/verify requests instead
    # of a single "request"; resolve the common one only when present.
    request = vectors["requests"][case["request"]] if "request" in case else None
    credentials = [vectors["credentials"][name] for name in case.get("credentials", [])]
    master_seed = vectors["masterSeed"]
    expect = case["expect"]

    if kind == "roundtrip":
        generated = holder.generate(request, credentials, master_seed)
        if "envelope" not in generated:
            raise CaseFailure(f"holder refused unexpectedly: {generated.get('refusal')}")
        outcome = verifier.verify(generated["envelope"], request)
        check_expect(expect, bool(outcome.get("valid")), list(outcome.get("codes", [])))
    elif kind == "holder_refusal":
        generated = holder.generate(request, credentials, master_seed)
        if "refusal" not in generated:
            raise CaseFailure("holder generated an envelope but a refusal was required")
        check_expect(expect, False, [generated["refusal"].get("code", "")])
    elif kind == "verifier_mutation":
        generated = holder.generate(request, credentials, master_seed)
        if "envelope" not in generated:
            raise CaseFailure(f"holder refused unexpectedly: {generated.get('refusal')}")
        envelope = apply_mutations(generated["envelope"], case.get("mutations", []))
        verify_request = vectors["requests"][case.get("verifyRequest", case["request"])]
        outcome = verifier.verify(envelope, verify_request)
        check_expect(expect, bool(outcome.get("valid")), list(outcome.get("codes", [])))
    elif kind == "verifier_static":
        outcome = verifier.verify(case["envelope"], request)
        check_expect(expect, bool(outcome.get("valid")), list(outcome.get("codes", [])))
    elif kind == "apr_roundtrip":
        apr = vectors["aprs"][case["apr"]]
        generated = holder.generate_authenticated(request, apr, credentials, master_seed)
        if "envelope" not in generated:
            raise CaseFailure(f"holder refused unexpectedly: {generated.get('refusal')}")
        outcome = verifier.verify_authenticated(generated["envelope"], request, apr)
        check_expect(expect, bool(outcome.get("valid")), list(outcome.get("codes", [])))
    elif kind == "apr_generation_refusal":
        apr = vectors["aprs"][case["apr"]]
        generated = holder.generate_authenticated(request, apr, credentials, master_seed)
        if "refusal" not in generated:
            raise CaseFailure("holder answered an unauthenticated request but a refusal was required")
        check_expect(expect, False, [generated["refusal"].get("code", "")])
    elif kind == "apr_purpose_mismatch":
        gen_request = vectors["requests"][case["genRequest"]]
        gen_apr = vectors["aprs"][case["genApr"]]
        generated = holder.generate_authenticated(gen_request, gen_apr, credentials, master_seed)
        if "envelope" not in generated:
            raise CaseFailure(f"holder refused unexpectedly: {generated.get('refusal')}")
        verify_request = vectors["requests"][case["verifyRequest"]]
        verify_apr = vectors["aprs"][case["verifyApr"]]
        outcome = verifier.verify_authenticated(generated["envelope"], verify_request, verify_apr)
        check_expect(expect, bool(outcome.get("valid")), list(outcome.get("codes", [])))
    elif kind == "apr_receipt_roundtrip":
        apr = vectors["aprs"][case["apr"]]
        generated = holder.generate_authenticated(request, apr, credentials, master_seed)
        if "receipt" not in generated:
            raise CaseFailure(f"holder produced no receipt: {generated.get('refusal')}")
        check_receipt_anchoring(verifier, generated["receipt"], generated.get("receiptHolderKey"))
        check_receipt_key_scope(holder, request, apr, credentials, master_seed, generated)
        receipt = apply_mutations(generated["receipt"], case.get("mutations", []))
        # The relying party anchors the holder key out of band (spec 5.6.1):
        # the holder adapter supplies it, the receipt never does.
        outcome = verifier.verify_receipt(
            receipt, expected_holder_key=generated.get("receiptHolderKey")
        )
        expected = bool(expect.get("receiptValid"))
        if bool(outcome.get("valid")) != expected:
            raise CaseFailure(
                f"expected receiptValid={expected}, got {outcome}"
            )
    elif kind == "hosted_retention_refusal":
        apr = vectors["aprs"][case["apr"]]
        outcome = holder.answer_hosted(request, apr, credentials, master_seed)
        expected = bool(expect.get("retained"))
        if bool(outcome.get("retained")) != expected:
            raise CaseFailure(
                f"hosted SDK retained={outcome.get('retained')}, expected {expected}"
            )
        if outcome.get("custody") != "holder":
            raise CaseFailure(
                f"hosted SDK must leave receipts in holder custody, got custody={outcome.get('custody')}"
            )
    else:
        raise CaseFailure(f"unknown case kind: {kind}")


def load_adapter(module_name: str):
    return importlib.import_module(module_name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", default="adapters.reference",
                        help="module providing make_holder_adapter and make_verifier_adapter")
    parser.add_argument("--holder-adapter", default=None,
                        help="module for make_holder_adapter (overrides --adapter)")
    parser.add_argument("--verifier-adapter", default=None,
                        help="module for make_verifier_adapter (overrides --adapter)")
    parser.add_argument("--profile", default="core", choices=KNOWN_PROFILES)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--case", default=None, help="run a single case id")
    args = parser.parse_args()

    vectors_path = ROOT / "conformance" / "vectors" / f"zkc_{args.profile}.json"
    if not vectors_path.is_file():
        message = (
            f"profile '{args.profile}' has no published vectors yet "
            f"(expansion hook: add {vectors_path.relative_to(ROOT)} using the core case schema)"
        )
        if args.json:
            print(json.dumps({"profile": args.profile, "status": "not_published",
                              "message": message}))
        else:
            print(message)
        return 2

    vectors = json.loads(vectors_path.read_text())
    holder = load_adapter(args.holder_adapter or args.adapter).make_holder_adapter()
    verifier = load_adapter(args.verifier_adapter or args.adapter).make_verifier_adapter()

    cases = vectors["cases"]
    if args.case is not None:
        cases = [case for case in cases if case["id"] == args.case]
        if not cases:
            print(f"no case with id {args.case}", file=sys.stderr)
            return 2

    results = []
    for case in cases:
        try:
            run_case(case, vectors, holder, verifier)
            results.append({"id": case["id"], "status": "PASS"})
        except CaseFailure as exc:
            results.append({"id": case["id"], "status": "FAIL", "reason": str(exc)})
        except Exception as exc:  # adapter crash = failure, never a pass
            results.append({
                "id": case["id"],
                "status": "FAIL",
                "reason": f"adapter raised {type(exc).__name__}: {exc}",
            })

    failed = [r for r in results if r["status"] == "FAIL"]
    if args.json:
        print(json.dumps({
            "profile": vectors["profile"],
            "total": len(results),
            "passed": len(results) - len(failed),
            "failed": len(failed),
            "results": results,
        }, indent=2))
    else:
        for r in results:
            line = f"[{r['status']}] {r['id']}"
            if r["status"] == "FAIL":
                line += f" — {r['reason']}"
            print(line)
        print(f"\n{len(results) - len(failed)}/{len(results)} cases passed "
              f"(profile: {vectors['profile']})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

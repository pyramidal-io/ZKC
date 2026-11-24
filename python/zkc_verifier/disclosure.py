"""Verifier-side disclosure hygiene against the verifier's OWN published policy.

A verifier that publishes a trust policy (registry/verifiers/) commits to
minimums. This module lets the verifier audit a concrete interaction against
that commitment:

- OVERBROAD_REQUEST: the request it issued asks for more than its published
  policy needs (a compliance/privacy bug on the verifier's side), or asks for
  a set predicate over a set so narrow that the proof nearly identifies the
  holder's code (``zkc_holder.ceilings.NARROW_SET_THRESHOLD``), or ships
  inclusion-path material that would fix the holder's witness;
- OVER_DISCLOSURE: the incoming envelope discloses proofs beyond what the
  request asked for (the verifier must flag, not silently absorb, the extra
  disclosure).

Warnings only: none of this affects cryptographic validity.
"""

from __future__ import annotations

from zkc_holder.ceilings import SET_DETERMINED, set_disclosure
from zkc_holder.planner import parameter_excesses

from .errors import VerificationWarning
from .errors import VerificationWarningCode as WarningCode

__all__ = ["disclosure_warnings"]


def disclosure_warnings(request, policy, envelope=None) -> list:
    """Audit a request (and optionally a received envelope) against the
    verifier's own published policy document.

    `policy` is duck-typed (``zkc_registry.VerifierPolicyDocument``): it must
    expose ``accepted_proof_types`` and ``proof_requirements()``.
    """
    warnings = []
    accepted = tuple(policy.accepted_proof_types)
    requirements = dict(policy.proof_requirements())

    for proof_type in request.proof_types:
        if proof_type not in accepted:
            warnings.append(
                VerificationWarning(
                    code=WarningCode.OVERBROAD_REQUEST,
                    message=(
                        f"request asks for {proof_type}, which the published policy "
                        "does not accept"
                    ),
                    proof_type=proof_type,
                )
            )
            continue
        notes, outcome = set_disclosure(proof_type, request.parameters.get(proof_type, {}))
        for note in notes:
            if note["kind"] == "verifier_inclusion_path":
                message = (
                    f"request for {proof_type} ships inclusion-path material "
                    f"({', '.join(note['keys'])}): a holder proving along a verifier-fixed "
                    "path discloses its exact code"
                )
            elif note["kind"] == "narrow_set" and outcome == SET_DETERMINED:
                message = (
                    f"request for {proof_type} uses a {note['mode']} set that leaves "
                    f"{note['anonymitySetSize']} possible code(s) (narrow below "
                    f"{note['threshold']}): the proof nearly identifies the holder's code"
                )
            else:
                continue
            warnings.append(
                VerificationWarning(
                    code=WarningCode.OVERBROAD_REQUEST, message=message, proof_type=proof_type
                )
            )
        if not requirements:
            continue
        minimum = requirements.get(proof_type)
        if minimum is None:
            warnings.append(
                VerificationWarning(
                    code=WarningCode.OVERBROAD_REQUEST,
                    message=(
                        f"request asks for {proof_type}, which the published policy "
                        "does not list as required"
                    ),
                    proof_type=proof_type,
                )
            )
            continue
        for excess in parameter_excesses(
            proof_type, dict(request.parameters.get(proof_type, {})), minimum
        ):
            if excess["kind"] == "unknown_parameter" and excess["element"] == "proofType":
                message = (
                    f"no typed disclosure comparator governs {proof_type}, so the request "
                    "cannot be audited against the published policy"
                )
            elif excess["kind"] == "unknown_parameter":
                message = (
                    f"request element {excess['element']} for {proof_type} is not "
                    "governed by the proof type's typed disclosure comparator"
                )
            else:
                message = (
                    f"request element {excess['element']} for {proof_type} exceeds or "
                    f"differs from the published policy minimum "
                    f"(requested {excess['requested']!r}, policy {excess['permitted']!r})"
                )
            warnings.append(
                VerificationWarning(
                    code=WarningCode.OVERBROAD_REQUEST, message=message, proof_type=proof_type
                )
            )

    if envelope is not None:
        requested = set(request.proof_types)
        for proof_entry in envelope.get("proofs", []):
            proof_type = proof_entry.get("proofType", "")
            if proof_type not in requested:
                warnings.append(
                    VerificationWarning(
                        code=WarningCode.OVER_DISCLOSURE,
                        message=(
                            f"envelope discloses {proof_type}, which this request "
                            "did not ask for"
                        ),
                        proof_type=proof_type,
                    )
                )
    return warnings

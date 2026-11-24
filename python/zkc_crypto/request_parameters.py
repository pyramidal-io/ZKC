"""Closed request-parameter vocabulary per proof type (spec section 6.2.1).

A proof request carries one parameter object per proof type. The verifier
reads named keys from that object and applies a default when a key is
absent, so a misspelled key (``flagrequired`` for ``flagRequired``) used to
drop the requirement it was meant to state: the request verified, and the
signed APR carried the misspelling. Both holder and verifier therefore admit
a parameter object only when every key belongs to the proof type's closed
set:

* every request parameter that the circuit's public-input binding sidecar
  (``schemas/public-input-bindings/<circuit>.json``) structurally references
  with ``param:``. This part is derived, never transcribed, so a new
  successor identity gets its keys from its own sidecar; and
* the documented request-only keys of :data:`REQUEST_ONLY_PARAMETERS`: keys
  a verifier or holder reads that are not circuit public inputs.

Request-only keys fall into three kinds, each documented normatively in the
specification:

* canonical code sets (``canonicalSet`` for sanctions,
  ``jurisdictionCanonicalSet`` for jurisdiction), from which both parties
  derive the bound root;
* fail-closed or frozen filters that the verifier reads but the circuit does
  not bind (legacy accreditation ``flagRequired``; the frozen
  ``issuerIdHash``/``schemaIdHash`` filters of the contained rebind
  statements); and
* holder inputs that state no verifier requirement (Merkle-path witness
  hints, and the authenticated rebind's ``credentialId``). The verifier never
  reads these keys, so it cannot drop a requirement through them.

The table is keyed by circuit family (the circuit name without its trailing
``_vN`` generation) and, for a circuit whose sidecar multiplexes several
meanings through ``predicateTypes``, by the proof-type meaning
(``zkc:proof:<meaning>:vN``). A family or meaning absent from the table has
no request-only keys: its closed set is its sidecar's references alone.
Standard library only.
"""

from __future__ import annotations

import pathlib
import re

from .canonical_set import CANONICAL_SET_PARAM, JURISDICTION_CANONICAL_SET_PARAM
from .code_spaces import CODE_SPACE_PROOF_TO_KIND
from .credential_id_successors import NONZERO_CREDENTIAL_CIRCUIT_PREDECESSORS
from .encoders import PublicInputBindings

__all__ = [
    "EXCLUSION_NEIGHBOUR_HINTS",
    "INCLUSION_PATH_HINTS",
    "JURISDICTION_INCLUSION_PATH_HINTS",
    "REQUEST_ONLY_PARAMETERS",
    "circuit_family",
    "proof_type_meaning",
    "request_only_parameters",
    "request_parameter_contracts",
    "unknown_request_parameters",
]

# Holder witness hints: Merkle-path material a request MAY carry for the
# holder. They state no requirement; the verifier never reads them, and a
# holder that receives a canonical code set derives its own path instead.
INCLUSION_PATH_HINTS = ("pathIndex", "siblings")
JURISDICTION_INCLUSION_PATH_HINTS = ("membershipPathIndex", "membershipSiblings")
EXCLUSION_NEIGHBOUR_HINTS = (
    "predecessorCode",
    "predecessorPathIndex",
    "predecessorSiblings",
    "successorCode",
    "successorPathIndex",
    "successorSiblings",
)

# Meaning key for circuit families whose request vocabulary does not depend
# on the proof-type meaning.
ANY_MEANING = "*"

REQUEST_ONLY_PARAMETERS = {
    "zkc_kyc": {ANY_MEANING: ()},
    "zkc_community_kyc": {ANY_MEANING: ()},
    # The frozen statements check the layout against an issuer key pin.
    # The successor additionally binds layoutId through its sidecar.
    "zkc_selective_disclosure": {ANY_MEANING: ("layoutId",)},
    "zkc_jurisdiction": {
        ANY_MEANING: (JURISDICTION_CANONICAL_SET_PARAM,)
        + JURISDICTION_INCLUSION_PATH_HINTS
        + EXCLUSION_NEIGHBOUR_HINTS,
    },
    "zkc_remaining_predicates": {
        # v1/v2 do not bind flagRequired; the verifier reads it only to
        # refuse exact true and non-boolean values. v3+ sidecars bind it.
        "accreditation": ("flagRequired",),
        "source": INCLUSION_PATH_HINTS,
        "tax": INCLUSION_PATH_HINTS,
        "sanctions": (CANONICAL_SET_PARAM,) + EXCLUSION_NEIGHBOUR_HINTS,
    },
    # Contained historical rebind statements (v1 linkable, v2 scoped): frozen,
    # unreachable issuer/schema equality filters their sidecars never declared.
    "zkc_credential_rebind": {ANY_MEANING: ("issuerIdHash", "schemaIdHash")},
    # Binding-v2 rebind successors: every key is a sidecar ``pinnedBy`` pin.
    "zkc_credential_rebind_binding": {ANY_MEANING: ()},
    "zkc_credential_rebind_v2_binding": {ANY_MEANING: ()},
    # Issuer-authenticated rebind: the holder-side selector of the credential
    # to migrate. Never a secret; the new binding key never travels in a
    # request (spec section 7.4.4).
    "zkc_credential_rebind_auth": {ANY_MEANING: ("credentialId",)},
    # Aggregation identities are envelope-level blocks, never requested proof
    # entries; they accept no request parameters at all.
    "zkc_aggregation": {ANY_MEANING: ()},
}

_GENERATION_SUFFIX = re.compile(r"_v[0-9]+$")
_PROOF_TYPE = re.compile(r"zkc:proof:([a-z][a-z0-9_]*):v[0-9]+")


def circuit_family(circuit: str) -> str:
    """``zkc_remaining_predicates_v9`` -> ``zkc_remaining_predicates``."""
    circuit = NONZERO_CREDENTIAL_CIRCUIT_PREDECESSORS.get(circuit, circuit)
    return _GENERATION_SUFFIX.sub("", circuit)


def proof_type_meaning(proof_type: str):
    """``zkc:proof:accreditation:v8`` -> ``accreditation``; else ``None``."""
    match = _PROOF_TYPE.fullmatch(proof_type) if isinstance(proof_type, str) else None
    return match.group(1) if match else None


def request_only_parameters(circuit: str, proof_type: str, *, multiplexed: bool) -> frozenset:
    """Documented request-only keys for one proof type of ``circuit``.

    ``multiplexed`` is true when the circuit's sidecar publishes a
    ``predicateTypes`` map, so the vocabulary is selected by meaning."""
    if proof_type in CODE_SPACE_PROOF_TO_KIND:
        set_key = (
            JURISDICTION_CANONICAL_SET_PARAM
            if CODE_SPACE_PROOF_TO_KIND[proof_type] == "jurisdiction"
            else CANONICAL_SET_PARAM
        )
        return frozenset({set_key})
    by_meaning = REQUEST_ONLY_PARAMETERS.get(circuit_family(circuit), {})
    key = proof_type_meaning(proof_type) if multiplexed else ANY_MEANING
    return frozenset(by_meaning.get(key, ()))


def request_parameter_contracts(repo_root, circuit_by_proof_type) -> tuple[dict, dict]:
    """Derive ``proofType -> frozenset`` closed key sets for every proof type.

    ``circuit_by_proof_type`` is the caller's selector-free encoder map. A
    proof type whose sidecar is missing or malformed is reported in the
    second mapping (``proofType -> reason``) and never given a set: callers
    MUST refuse it instead of treating an absent contract as "anything goes".
    """
    root = pathlib.Path(repo_root)
    contracts = {}
    errors = {}
    loaded = {}
    for proof_type, circuit in sorted(circuit_by_proof_type.items()):
        try:
            if circuit not in loaded:
                bindings = PublicInputBindings.for_circuit(root, circuit)
                loaded[circuit] = (bindings.request_parameters(), bool(bindings.predicate_types))
            sidecar_keys, multiplexed = loaded[circuit]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors[proof_type] = f"{circuit}: {exc}"
            continue
        contracts[proof_type] = sidecar_keys | request_only_parameters(
            circuit, proof_type, multiplexed=multiplexed
        )
    return contracts, errors


def unknown_request_parameters(accepted, parameters) -> tuple:
    """Sorted keys of ``parameters`` outside ``accepted`` (``repr`` for non-str)."""
    return tuple(
        sorted(
            (key if isinstance(key, str) else repr(key))
            for key in parameters
            if key not in accepted
        )
    )

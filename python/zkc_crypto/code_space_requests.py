"""Verifier and holder construction of code-space-bound canonical sets."""

from dataclasses import dataclass

from .canonical_set import (
    CANONICAL_SET_EXCLUSION,
    CANONICAL_SET_INCLUSION,
    CANONICAL_SET_MAX_REQUEST_CODES,
    CANONICAL_SET_PARAM,
    CANONICAL_SET_PARAM_KEYS,
    JURISDICTION_CANONICAL_SET_PARAM,
    CanonicalCodeSet,
)
from .code_spaces import (
    CODE_SPACE_PROOF_TO_KIND,
    CodeSpace,
    get_code_space,
    validate_claim_type,
    validate_verification_method,
)
from .code_space_transcripts import code_space_leaf
from .field import FIELD_MODULUS

CODE_SPACE_ID_PARAM = "codeSpaceId"
REQUIRED_VERIFICATION_METHOD_PARAM = "requiredVerificationMethod"


def build_code_space_set(proof_type, code_space_id, codes, *, membership_type=None, claim_type=None):
    """Build a public set from codes assigned by the exact approved registry."""
    kind = CODE_SPACE_PROOF_TO_KIND.get(proof_type)
    if kind is None:
        raise ValueError("proof type has no code-space-bound set")
    space = get_code_space(code_space_id, kind)
    if not isinstance(codes, list) or len(codes) > CANONICAL_SET_MAX_REQUEST_CODES:
        raise ValueError("canonical codes must be a bounded JSON array")
    for code in codes:
        space.validate_code(code)
    if kind == "jurisdiction":
        if type(membership_type) is not int or membership_type not in (0, 1):
            raise ValueError("membershipType must select inclusion or exclusion")
        validate_claim_type(claim_type)
        exclusion = membership_type == 1
    else:
        if membership_type is not None or claim_type is not None:
            raise ValueError("only jurisdiction sets take membershipType and requiredClaimType")
        exclusion = kind == "sanctions"
    return CanonicalCodeSet(
        codes,
        lambda code: code_space_leaf(kind, space.field_id, code, claim_type),
        CANONICAL_SET_EXCLUSION if exclusion else CANONICAL_SET_INCLUSION,
    )


@dataclass(frozen=True)
class CodeSpaceRequest:
    space: CodeSpace
    code_set: CanonicalCodeSet
    root: int
    required_verification_method: int
    minimum_tax_year: int


def resolve_code_space_request(proof_type, parameters) -> CodeSpaceRequest:
    """Require the authenticated parameters to state exactly the derived root."""
    if not isinstance(parameters, dict):
        raise ValueError("code-space parameters must be a JSON object")
    kind = CODE_SPACE_PROOF_TO_KIND[proof_type]
    space = get_code_space(parameters.get(CODE_SPACE_ID_PARAM), kind)
    jurisdiction = kind == "jurisdiction"
    codes_key = JURISDICTION_CANONICAL_SET_PARAM if jurisdiction else CANONICAL_SET_PARAM
    root_key = "jurisdictionSetRoot" if jurisdiction else "setRoot"
    if any(key != codes_key and key in parameters for key in CANONICAL_SET_PARAM_KEYS):
        raise ValueError("canonical set parameter belongs to a different predicate")
    root = parameters.get(root_key)
    if type(root) is not int or not 0 <= root < FIELD_MODULUS:
        raise ValueError(f"{root_key} must be an exact field integer")

    method = 0
    year = 0
    if jurisdiction:
        if REQUIRED_VERIFICATION_METHOD_PARAM in parameters:
            method = validate_verification_method(parameters[REQUIRED_VERIFICATION_METHOD_PARAM])
    else:
        required0 = parameters.get("required0", 0)
        required1 = parameters.get("required1", 0)
        if type(required0) is not int or required0 != 0 or parameters.get("flagRequired", False) is not False:
            raise ValueError("required0 and flagRequired must be zero and false")
        if type(required1) is not int or not 0 <= required1 < 1 << 64:
            raise ValueError("required1 must be an exact u64 integer")
        if kind != "tax" and required1 != 0:
            raise ValueError("required1 is reserved outside tax residency")
        year = required1
    code_set = build_code_space_set(
        proof_type,
        space.id,
        parameters.get(codes_key),
        membership_type=parameters.get("membershipType") if jurisdiction else None,
        claim_type=parameters.get("requiredClaimType") if jurisdiction else None,
    )
    if code_set.root() != root:
        raise ValueError(f"{root_key} differs from the code-space-bound canonical set root")
    return CodeSpaceRequest(space, code_set, root, method, year)

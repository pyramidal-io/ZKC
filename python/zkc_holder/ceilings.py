"""Typed disclosure comparators for consent ceilings and published minimums.

A holder-side disclosure ceiling (the planner's ``consent_scope``, which the
agent fills from ``AgentCompliancePolicy.disclosure_ceiling``) and a verifier's
published ``proofRequirements`` minimum are both parameter objects for one
proof type. Comparing a request with either needs to know, per parameter, in
which direction a value discloses more about the holder. Key presence is not
enough: a ceiling ``required0 = 100000`` must refuse a request for
``required0 = 10000000000``, and a ceiling must govern accreditation, source,
tax, sanctions and jurisdiction, not only KYC (security review 2026-10-04,
R3.6).

Each parameter has one rule kind:

* ``threshold`` - an exact integer in the circuit's unsigned domain (``bits``)
  where a LARGER value discloses more (the circuit proves ``credential value
  >= requested value``, so a higher request shrinks the set of holders who
  satisfy it). A value outside the domain on either side is refused: the
  circuit casts it, so ``-253`` would be compared as ``3``.
* ``flag`` - an exact boolean where ``true`` adds a requirement and so
  discloses more.
* ``flag_vector`` - a fixed-length boolean vector, each ``true`` entry adding
  one requirement.
* ``subset`` - a list of distinct integer positions; every position reveals
  one more attribute value, so a superset discloses more.
* ``pinned`` - a value with no disclosure order (set roots, mode codes, claim
  types, dead transcript slots, fixed-false flags, schema and credential
  selectors). The request MUST equal the bound exactly (an absent key takes
  the documented default on both sides).
* ``canonical_set`` - a canonical code list from which both parties derive a
  set root and from which the holder derives its OWN Merkle witness. Against
  a ceiling, a requested list MUST equal the ceiling's list as a set. Against
  a published minimum, the lists are compared only when both state one (the
  pinned root governs, and the holder checks that the list derives it).
* ``witness_path`` - a verifier-supplied Merkle path or neighbour material.
  It is not compared value by value, but it is NOT inert: when the holder
  has no canonical list from which to derive its own witness, it proves
  membership along this path. With the path index and siblings fixed, only
  one leaf hashes to the root, so the proof (or the holder's refusal) is an
  equality test on the holder's exact code. :func:`set_disclosure` therefore
  reports such a request as an exact-member disclosure, and a ceiling refuses
  it unless the principal opts in with :data:`EXACT_MEMBER_OPT_IN`.

An absent key takes the rule's ``default`` on both sides. For a threshold or
flag that is the verifier's own default when it has one (KYC ``requiredLevel``
defaults to level 1, not 0) and otherwise the least-disclosing value.

The table is keyed like :data:`zkc_crypto.request_parameters.REQUEST_ONLY_PARAMETERS`:
by circuit family (circuit name without its ``_vN`` generation) and, for the
multiplexed remaining-predicates circuit, by proof-type meaning. Families in
:data:`REFUSED_UNDER_CEILING` have no comparator by design; a proof type with
no comparator is refused under a ceiling (fail closed). The cross-check test
``tests/python/test_disclosure_ceilings.py`` derives every proof type from the
repository's encoders and requires each one to be covered here, with a rule
for every key of its closed request-parameter set.

Standard library only.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace

from zkc_crypto.canonical_set import (
    CANONICAL_CODE_MAX,
    CANONICAL_CODE_MIN,
    CANONICAL_SET_EXCLUSION,
    CANONICAL_SET_INCLUSION,
    CANONICAL_SET_MAX_REQUEST_CODES,
    CANONICAL_SET_PARAM,
    JURISDICTION_CANONICAL_SET_PARAM,
)
from zkc_crypto.request_parameters import (
    EXCLUSION_NEIGHBOUR_HINTS,
    INCLUSION_PATH_HINTS,
    JURISDICTION_INCLUSION_PATH_HINTS,
    circuit_family,
    proof_type_meaning,
)
from zkc_crypto.code_spaces import CODE_SPACE_PROOF_TO_KIND, get_code_space

__all__ = [
    "ANY_MEANING",
    "BOUND_CEILING",
    "BOUND_MINIMUM",
    "CANONICAL_SET",
    "CEILING_COMPARATORS",
    "EXACT_MEMBER",
    "EXACT_MEMBER_OPT_IN",
    "FLAG",
    "FLAG_VECTOR",
    "INCLUSION_PATH_KEYS",
    "NARROW_SET_THRESHOLD",
    "PINNED",
    "REFUSED_UNDER_CEILING",
    "SET_DETERMINED",
    "SET_UNKNOWN",
    "SUBSET",
    "THRESHOLD",
    "WITNESS_PATH",
    "CeilingComparator",
    "ParameterRule",
    "SetSemantics",
    "check_bound_value",
    "comparator_for",
    "compare_parameters",
    "exact_member_opted_in",
    "narrow_parameters",
    "set_disclosure",
]

THRESHOLD = "threshold"
FLAG = "flag"
FLAG_VECTOR = "flag_vector"
SUBSET = "subset"
PINNED = "pinned"
CANONICAL_SET = "canonical_set"
WITNESS_PATH = "witness_path"

# Which bound a comparison is against. A ceiling is the principal's consent;
# a minimum is the verifier's published need.
BOUND_CEILING = "ceiling"
BOUND_MINIMUM = "minimum"

# Rule kinds whose excess the planner may narrow toward a published minimum.
# Pinned and canonical-set mismatches have no "narrower" value: substituting
# the published value would plan a statement the ceiling check never saw.
_NARROWABLE = (THRESHOLD, FLAG, FLAG_VECTOR, SUBSET)

ANY_MEANING = "*"

# Ceiling-only key (never a request parameter; the closed request vocabulary
# rejects it in a request): the principal's explicit, per-proof-type consent
# to an exact-member inclusion proof along a verifier-fixed path. Only the
# exact JSON value ``true`` opts in.
EXACT_MEMBER_OPT_IN = "allowExactMemberDisclosure"

# An anonymity set (the codes a set-predicate proof leaves possible) smaller
# than this is "narrow": the proof nearly identifies the holder's code. A
# singleton inclusion set reveals the exact jurisdiction; a 2-4 code set
# still narrows it to a handful. Five is the documented reference threshold.
#
# Known limitation: the repository defines no assigned-code domain per
# predicate (security review R5.2), so sizes count every code in the u16
# canonical domain. An inclusion set padded with unassigned codes is
# over-counted, and an exclusion set can only be measured against the whole
# domain minus at most CANONICAL_SET_MAX_REQUEST_CODES blocked codes, so a
# narrow EXCLUSION set is never detected.
NARROW_SET_THRESHOLD = 5

# set_disclosure() outcomes.
SET_DETERMINED = "determined"  # the holder derives its own witness from a known list
EXACT_MEMBER = "exact_member"  # the witness is fixed by the request: anonymity set 1
SET_UNKNOWN = "unknown"  # the size or the mode cannot be determined

# membershipType codes of the jurisdiction circuits
# (zkc_holder.predicates.MEMBERSHIP_TYPE_INCLUSION / _EXCLUSION).
_MEMBERSHIP_MODES = {0: CANONICAL_SET_INCLUSION, 1: CANONICAL_SET_EXCLUSION}

_CODE_DOMAIN_SIZE = CANONICAL_CODE_MAX - CANONICAL_CODE_MIN + 1

# Inclusion-path keys: a request carrying one ships a verifier-chosen path.
INCLUSION_PATH_KEYS = INCLUSION_PATH_HINTS + JURISDICTION_INCLUSION_PATH_HINTS


@dataclass(frozen=True)
class ParameterRule:
    """How one request parameter compares with a ceiling or minimum."""

    kind: str
    # Value an absent key takes on either side. For a threshold or flag: the
    # verifier's default when it has one, else the least-disclosing value.
    # ``None`` means "no default": absent equals only absent.
    default: object = None
    # threshold: unsigned bit width of the circuit type the value is cast to.
    bits: int = 0
    # flag_vector length.
    length: int = 0
    # Narrowed plans always state this key (the historical KYC plan shape).
    emit: bool = False
    why: str = ""


@dataclass(frozen=True)
class SetSemantics:
    """Where a set predicate's mode, list and witness come from."""

    # Fixed mode, or None when ``mode_key`` selects it.
    mode: str = None
    mode_key: str = None
    # Request key carrying the canonical code list; None when the protocol
    # has no canonical construction for this predicate (the holder can never
    # derive its own witness, so every inclusion proof is exact-member).
    canonical_key: str = None
    # Verifier-supplied inclusion path keys for this predicate.
    path_keys: tuple = ()


@dataclass(frozen=True)
class CeilingComparator:
    family: str
    meaning: str
    rules: Mapping = field(default_factory=dict)  # key -> ParameterRule
    set_semantics: SetSemantics = None


def _paths(keys, why):
    return {key: ParameterRule(WITNESS_PATH, why=why) for key in keys}


_KYC_RULES = {
    "requiredLevel": ParameterRule(
        THRESHOLD, default=1, bits=8, emit=True,
        why="circuit proves kycLevel >= requiredLevel (u8); a higher level admits fewer holders",
    ),
    "requiredAttributes": ParameterRule(
        FLAG_VECTOR, default=(False,) * 5, length=5, emit=True,
        why="each true flag proves one more verified attribute",
    ),
}

_DEAD_SLOT = "circuit-dead claim-binding slot for this predicate; pinned (default 0)"
_FIXED_FALSE_FLAG = "contract requires false for this predicate; pinned (default false)"
_INCLUSION_PATH = (
    "verifier-supplied inclusion path; without a canonical list the holder proves "
    "along it, which fixes the provable leaf (exact-member disclosure)"
)
_NEIGHBOUR_PATH = (
    "verifier-supplied exclusion neighbours; the holder re-derives them from the "
    "canonical list, which exclusion requires"
)

_JURISDICTION = CeilingComparator(
    family="zkc_jurisdiction",
    meaning=ANY_MEANING,
    rules={
        "membershipType": ParameterRule(
            PINNED, why="inclusion/exclusion mode code; modes are not ordered"
        ),
        "requiredClaimType": ParameterRule(
            PINNED, why="which jurisdiction claim is proved; claim types are not ordered"
        ),
        "jurisdictionSetRoot": ParameterRule(
            PINNED, why="set root; roots of different sets are not comparable"
        ),
        JURISDICTION_CANONICAL_SET_PARAM: ParameterRule(
            CANONICAL_SET, why="canonical code list deriving the root; equal as a set"
        ),
        **_paths(JURISDICTION_INCLUSION_PATH_HINTS, _INCLUSION_PATH),
        **_paths(EXCLUSION_NEIGHBOUR_HINTS, _NEIGHBOUR_PATH),
    },
    set_semantics=SetSemantics(
        mode_key="membershipType",
        canonical_key=JURISDICTION_CANONICAL_SET_PARAM,
        path_keys=JURISDICTION_INCLUSION_PATH_HINTS,
    ),
)

_ACCREDITATION = CeilingComparator(
    family="zkc_remaining_predicates",
    meaning="accreditation",
    rules={
        "required0": ParameterRule(
            THRESHOLD, default=0, bits=8,
            why="circuit proves accreditationLevel >= required0 (u8); higher discloses more",
        ),
        "required1": ParameterRule(PINNED, default=0, why=_DEAD_SLOT),
        "flagRequired": ParameterRule(
            FLAG, default=False,
            why="true additionally proves institutional status (issuer-signed claim_1)",
        ),
        "setRoot": ParameterRule(
            PINNED, default=0, why="unconstrained on this branch; contract requires 0"
        ),
    },
)

_SOURCE = CeilingComparator(
    family="zkc_remaining_predicates",
    meaning="source",
    rules={
        "required0": ParameterRule(PINNED, default=0, why=_DEAD_SLOT),
        "required1": ParameterRule(PINNED, default=0, why=_DEAD_SLOT),
        "flagRequired": ParameterRule(PINNED, default=False, why=_FIXED_FALSE_FLAG),
        "setRoot": ParameterRule(
            PINNED, why="accepted-source set root; roots are not comparable"
        ),
        **_paths(INCLUSION_PATH_HINTS, _INCLUSION_PATH),
    },
    # Full-Field source codes have no canonical-set construction (spec
    # section 7.2c.5): the holder always proves along the request's path, so
    # every proof is an exact-member disclosure.
    set_semantics=SetSemantics(mode=CANONICAL_SET_INCLUSION, path_keys=INCLUSION_PATH_HINTS),
)

_TAX = CeilingComparator(
    family="zkc_remaining_predicates",
    meaning="tax",
    rules={
        "required0": ParameterRule(PINNED, default=0, why=_DEAD_SLOT),
        "required1": ParameterRule(
            THRESHOLD, default=0, bits=64,
            why="circuit proves taxYear >= required1 (u64); a later minimum year discloses more",
        ),
        "flagRequired": ParameterRule(PINNED, default=False, why=_FIXED_FALSE_FLAG),
        "setRoot": ParameterRule(
            PINNED, why="accepted tax-jurisdiction set root; roots are not comparable"
        ),
        **_paths(INCLUSION_PATH_HINTS, _INCLUSION_PATH),
    },
    set_semantics=SetSemantics(mode=CANONICAL_SET_INCLUSION, path_keys=INCLUSION_PATH_HINTS),
)

_SANCTIONS = CeilingComparator(
    family="zkc_remaining_predicates",
    meaning="sanctions",
    rules={
        "required0": ParameterRule(PINNED, default=0, why=_DEAD_SLOT),
        "required1": ParameterRule(PINNED, default=0, why=_DEAD_SLOT),
        "flagRequired": ParameterRule(PINNED, default=False, why=_FIXED_FALSE_FLAG),
        "setRoot": ParameterRule(
            PINNED, why="blocked-set root; roots are not comparable"
        ),
        CANONICAL_SET_PARAM: ParameterRule(
            CANONICAL_SET, why="canonical blocked-code list deriving the root; equal as a set"
        ),
        **_paths(EXCLUSION_NEIGHBOUR_HINTS, _NEIGHBOUR_PATH),
    },
    set_semantics=SetSemantics(mode=CANONICAL_SET_EXCLUSION, canonical_key=CANONICAL_SET_PARAM),
)

_REBIND_AUTH = CeilingComparator(
    "zkc_credential_rebind_auth",
    ANY_MEANING,
    {
        "credentialId": ParameterRule(
            PINNED, why="selects the credential whose public credential_id is revealed"
        ),
        "schemaIdHash": ParameterRule(PINNED, why="schema equality pin"),
    },
)

CEILING_COMPARATORS = {
    "zkc_kyc": {
        ANY_MEANING: CeilingComparator("zkc_kyc", ANY_MEANING, _KYC_RULES),
    },
    "zkc_community_kyc": {
        ANY_MEANING: CeilingComparator("zkc_community_kyc", ANY_MEANING, _KYC_RULES),
    },
    "zkc_selective_disclosure": {
        ANY_MEANING: CeilingComparator(
            "zkc_selective_disclosure",
            ANY_MEANING,
            {
                "layoutId": ParameterRule(
                    PINNED, why="selects the attribute layout that gives positions their meaning",
                ),
                "disclosedPositions": ParameterRule(
                    SUBSET, default=(),
                    why="each position reveals one attribute value; a superset discloses more",
                ),
            },
        ),
    },
    "zkc_jurisdiction": {ANY_MEANING: _JURISDICTION},
    "zkc_remaining_predicates": {
        "accreditation": _ACCREDITATION,
        "source": _SOURCE,
        "tax": _TAX,
        "sanctions": _SANCTIONS,
    },
    "zkc_credential_rebind_auth": {ANY_MEANING: _REBIND_AUTH},
}

# Families with no comparator by design. Under a ceiling they are refused.
REFUSED_UNDER_CEILING = {
    "zkc_aggregation": (
        "envelope-level aggregation block, never an individually requested proof "
        "(spec section 6.2.1)"
    ),
    "zkc_credential_rebind": (
        "unauthenticated rebind statement; verifiers reject it unconditionally "
        "(spec section 4.5)"
    ),
    "zkc_credential_rebind_binding": (
        "unauthenticated rebind statement; verifiers reject it unconditionally "
        "(spec section 4.5)"
    ),
    "zkc_credential_rebind_v2_binding": (
        "unauthenticated rebind statement; verifiers reject it unconditionally "
        "(spec section 4.5)"
    ),
}

# The proof-type meanings each circuit family may serve. A registry-resolved
# circuit selects a comparator only for these meanings (fail closed on a
# meaning/circuit disagreement).
_FAMILY_MEANINGS = {
    "zkc_kyc": ("kyc",),
    "zkc_community_kyc": ("community_kyc",),
    "zkc_selective_disclosure": ("selective_disclosure",),
    "zkc_jurisdiction": ("jurisdiction",),
    "zkc_remaining_predicates": ("accreditation", "source", "tax", "sanctions"),
    "zkc_credential_rebind_auth": ("credential_rebind", "rebind"),
}

# Meaning -> family for callers that know only the proof type (the verifier's
# own disclosure audit, counter-offer evaluation).
_MEANING_FAMILIES = {
    meaning: family
    for family, meanings in _FAMILY_MEANINGS.items()
    if family != "zkc_credential_rebind_auth"
    for meaning in meanings
}

# Rebind meanings name both authenticated and unauthenticated generations, so
# without a circuit the family is unknown. The meaning-level comparator pins
# every key any rebind generation accepts; it has no ordered key, so it can
# only ever match a minimum exactly. It is never used under a ceiling (the
# planner always passes the registry circuit, and unauthenticated families
# have no comparator there).
_REBIND_MEANING = CeilingComparator(
    "rebind (meaning-level)",
    ANY_MEANING,
    {
        "credentialId": ParameterRule(PINNED, why="credential selector"),
        "schemaIdHash": ParameterRule(PINNED, why="schema equality pin"),
        "issuerIdHash": ParameterRule(PINNED, why="historical issuer equality filter"),
    },
)
_REBIND_MEANINGS = ("credential_rebind", "rebind")


def _code_space_comparator(comparator):
    semantics = comparator.set_semantics
    codes_key = semantics.canonical_key or CANONICAL_SET_PARAM
    rules = {key: rule for key, rule in comparator.rules.items() if rule.kind != WITNESS_PATH}
    rules["codeSpaceId"] = ParameterRule(PINNED, why="registry identity is an exact parameter")
    rules[codes_key] = ParameterRule(CANONICAL_SET, why="canonical code-space member list")
    if comparator.family == "zkc_jurisdiction":
        rules["requiredVerificationMethod"] = ParameterRule(PINNED, why="exact issuer-attested method")
    return replace(comparator, rules=rules, set_semantics=replace(semantics, canonical_key=codes_key, path_keys=()))


_CODE_SPACE_COMPARATORS = {
    kind: _code_space_comparator(comparator)
    for kind, comparator in (
        ("jurisdiction", _JURISDICTION), ("source", _SOURCE), ("tax", _TAX), ("sanctions", _SANCTIONS),
    )
}


def comparator_for(proof_type: str, circuit: str = None):
    """The :class:`CeilingComparator` for ``proof_type``, or ``None``.

    ``circuit`` is the registry-resolved circuit when the caller has it; its
    family must serve the proof type's meaning, or the result is ``None``
    (fail closed). Without a circuit the family comes from the meaning."""
    meaning = proof_type_meaning(proof_type)
    if meaning is None:
        return None
    if proof_type in CODE_SPACE_PROOF_TO_KIND:
        comparator = _CODE_SPACE_COMPARATORS[CODE_SPACE_PROOF_TO_KIND[proof_type]]
        return comparator if not circuit or circuit_family(circuit) == comparator.family else None
    if isinstance(circuit, str) and circuit:
        family = circuit_family(circuit)
        if meaning not in _FAMILY_MEANINGS.get(family, ()):
            return None
    elif meaning in _REBIND_MEANINGS:
        return _REBIND_MEANING
    else:
        family = _MEANING_FAMILIES.get(meaning)
    by_meaning = CEILING_COMPARATORS.get(family)
    if by_meaning is None:
        return None
    if ANY_MEANING in by_meaning:
        return by_meaning[ANY_MEANING]
    return by_meaning.get(meaning)


def exact_member_opted_in(ceiling) -> bool:
    """True only for a ceiling whose opt-in key is the exact JSON ``true``."""
    return isinstance(ceiling, Mapping) and ceiling.get(EXACT_MEMBER_OPT_IN) is True


# ---------------------------------------------------------------------------
# value checks (type-strict: JSON integers are not booleans, and vice versa)
# ---------------------------------------------------------------------------


def _is_int(value) -> bool:
    return type(value) is int


def _is_bool(value) -> bool:
    return type(value) is bool


def _in_domain(value, bits) -> bool:
    return _is_int(value) and 0 <= value < (1 << bits)


def _bool_vector(value, length):
    if isinstance(value, (list, tuple)) and len(value) == length and all(map(_is_bool, value)):
        return list(value)
    return None


def _positions(value):
    if isinstance(value, (list, tuple)) and all(_is_int(item) and item >= 0 for item in value):
        if len(set(value)) == len(value):
            return list(value)
    return None


def _code_set(value):
    if (
        isinstance(value, (list, tuple))
        and len(value) <= CANONICAL_SET_MAX_REQUEST_CODES
        and all(_is_int(code) for code in value)
    ):
        return frozenset(value)
    return None


def check_bound_value(rule: ParameterRule, value) -> bool:
    """True when ``value`` is a well-formed bound for ``rule``.

    Used to validate published minimums; a witness path is never a valid
    bound (it states no requirement)."""
    if rule.kind == THRESHOLD:
        return _in_domain(value, rule.bits)
    if rule.kind == FLAG:
        return _is_bool(value)
    if rule.kind == FLAG_VECTOR:
        return _bool_vector(value, rule.length) is not None
    if rule.kind == SUBSET:
        return _positions(value) is not None
    if rule.kind == CANONICAL_SET:
        return _code_set(value) is not None
    if rule.kind == PINNED:
        return True
    return False


def _strict_equal(left, right) -> bool:
    if type(left) is not type(right):
        # A tuple default and a JSON list of the same items are equal.
        if isinstance(left, (list, tuple)) and isinstance(right, (list, tuple)):
            return len(left) == len(right) and all(map(_strict_equal, left, right))
        return False
    if isinstance(left, (list, tuple)):
        return len(left) == len(right) and all(map(_strict_equal, left, right))
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_strict_equal(left[k], right[k]) for k in left)
    return left == right


def _element(proof_type, key, requested, permitted, kind):
    return {
        "proofType": proof_type,
        "element": key,
        "requested": requested,
        "permitted": permitted,
        "kind": kind,
    }


def _plain(value):
    return list(value) if isinstance(value, tuple) else value


def compare_parameters(
    proof_type: str,
    requested,
    bound,
    *,
    circuit: str = None,
    kind: str = "parameter_exceeds_policy",
    role: str = BOUND_MINIMUM,
) -> tuple[list, list]:
    """Compare ``requested`` with ``bound`` (a ceiling or a published minimum).

    Returns ``(narrowable, hard)`` lists of overbroad elements. Narrowable
    elements are well-formed threshold/flag/subset excesses that a counter-offer
    can reduce to the bound. Hard elements are everything else: a pinned or
    canonical-set mismatch, a malformed or out-of-domain value on either side,
    a key with no rule, or a proof type with no comparator. Every element
    carries ``kind`` (unknown keys and a missing comparator use
    ``unknown_parameter``; callers checking a consent ceiling relabel all
    elements ``beyond_consent``). ``role`` selects the canonical-set rule:
    against a ceiling a requested list must equal the ceiling's; against a
    minimum lists are compared only when both sides state one. Witness paths
    are never compared here; :func:`set_disclosure` governs them."""
    comparator = comparator_for(proof_type, circuit)
    if comparator is None:
        return [], [_element(proof_type, "proofType", proof_type, None, "unknown_parameter")]
    if not isinstance(requested, Mapping):
        return [], [_element(proof_type, "parameters", None, None, kind)]
    if not isinstance(bound, Mapping):
        return [], [_element(proof_type, "parameters", None, None, kind)]
    narrowable, hard = [], []
    for key, rule in comparator.rules.items():
        if rule.kind == WITNESS_PATH:
            continue
        asked = requested.get(key, rule.default)
        limit = bound.get(key, rule.default)
        if rule.kind == THRESHOLD:
            if not (_in_domain(asked, rule.bits) and _in_domain(limit, rule.bits)):
                hard.append(_element(proof_type, key, asked, limit, kind))
            elif asked > limit:
                narrowable.append(_element(proof_type, key, asked, limit, kind))
        elif rule.kind == FLAG:
            if not (_is_bool(asked) and _is_bool(limit)):
                hard.append(_element(proof_type, key, asked, limit, kind))
            elif asked and not limit:
                narrowable.append(_element(proof_type, key, asked, limit, kind))
        elif rule.kind == FLAG_VECTOR:
            asked_vector = _bool_vector(asked, rule.length)
            limit_vector = _bool_vector(limit, rule.length)
            if asked_vector is None or limit_vector is None:
                hard.append(_element(proof_type, key, _plain(asked), _plain(limit), kind))
                continue
            extra = [i for i, (a, b) in enumerate(zip(asked_vector, limit_vector)) if a and not b]
            if extra:
                narrowable.append(
                    _element(
                        proof_type, key, extra, [i for i, b in enumerate(limit_vector) if b], kind
                    )
                )
        elif rule.kind == SUBSET:
            asked_positions = _positions(asked)
            limit_positions = _positions(limit)
            if asked_positions is None or limit_positions is None:
                hard.append(_element(proof_type, key, _plain(asked), _plain(limit), kind))
                continue
            extra = sorted(set(asked_positions) - set(limit_positions))
            if extra:
                narrowable.append(
                    _element(proof_type, key, extra, sorted(limit_positions), kind)
                )
        elif rule.kind == PINNED:
            if not _strict_equal(asked, limit):
                hard.append(_element(proof_type, key, _plain(asked), _plain(limit), kind))
        elif rule.kind == CANONICAL_SET:
            if key not in requested:
                continue  # the pinned root governs
            if role == BOUND_MINIMUM and key not in bound:
                continue  # the published root governs; the holder checks derivation
            asked_codes = _code_set(asked)
            limit_codes = _code_set(limit) if key in bound else None
            if asked_codes is None or limit_codes is None or asked_codes != limit_codes:
                hard.append(
                    _element(
                        proof_type,
                        key,
                        sorted(asked_codes) if asked_codes is not None else _plain(asked),
                        sorted(limit_codes) if limit_codes is not None else _plain(limit),
                        kind,
                    )
                )
        else:  # pragma: no cover - table invariant, pinned by tests
            hard.append(_element(proof_type, key, asked, limit, kind))
    for key in requested:
        if key not in comparator.rules:
            hard.append(
                _element(
                    proof_type,
                    key if isinstance(key, str) else repr(key),
                    requested[key],
                    None,
                    "unknown_parameter",
                )
            )
    return narrowable, hard


def narrow_parameters(proof_type: str, requested: Mapping, minimum: Mapping, *, circuit=None) -> dict:
    """Element-wise narrowest parameters within the published ``minimum``.

    Keeps the predicate's own parameters (pinned values, canonical sets and
    witness paths unchanged) and lowers only the ordered ones. Call it only
    when :func:`compare_parameters` reports no hard element."""
    comparator = comparator_for(proof_type, circuit)
    if comparator is None:
        raise ValueError(f"no disclosure comparator for {proof_type}")
    narrowed = dict(requested)
    for key, rule in comparator.rules.items():
        if rule.kind not in _NARROWABLE or not (key in requested or rule.emit):
            continue
        asked = requested.get(key, rule.default)
        limit = minimum.get(key, rule.default)
        if rule.kind == THRESHOLD:
            narrowed[key] = min(asked, limit)
        elif rule.kind == FLAG:
            narrowed[key] = asked and limit
        elif rule.kind == FLAG_VECTOR:
            narrowed[key] = [a and b for a, b in zip(asked, limit)]
        elif rule.kind == SUBSET:
            allowed = set(limit)
            narrowed[key] = [position for position in asked if position in allowed]
    return narrowed


def set_disclosure(proof_type: str, parameters, *, circuit=None):
    """Narrow-set analysis for one set-predicate request.

    Returns ``(warnings, outcome)``. The size is taken ONLY from what
    constrains the holder's witness, never from a ceiling's list:

    * the holder derives its own witness from the request's canonical code
      list (jurisdiction with ``jurisdictionCanonicalSet``, sanctions with
      ``canonicalSet``): the anonymity set is the number of distinct listed
      codes for inclusion, or the u16 code domain minus the blocked codes for
      exclusion (``SET_DETERMINED``);
    * an inclusion request without such a list (jurisdiction inclusion with a
      bare root; source of funds and tax residency always) makes the holder
      prove along the request's path, or along the default path when none is
      supplied. Only one leaf hashes to the root along a fixed path, so the
      anonymity set is 1 (``EXACT_MEMBER``);
    * otherwise (unknown mode, malformed list, exclusion without a list) the
      size cannot be determined (``SET_UNKNOWN``).

    Warnings (holder-local overbreadth notes for the principal):
    ``narrow_set`` when the anonymity set is below :data:`NARROW_SET_THRESHOLD`
    (``anonymitySetSize: 1`` for exact-member), ``verifier_inclusion_path``
    when the request ships inclusion-path material, ``set_size_unknown``."""
    comparator = comparator_for(proof_type, circuit)
    semantics = comparator.set_semantics if comparator is not None else None
    if semantics is None or not isinstance(parameters, Mapping):
        return [], SET_DETERMINED

    warnings = []
    shipped_paths = sorted(key for key in semantics.path_keys if key in parameters)
    if shipped_paths:
        warnings.append(
            {
                "proofType": proof_type,
                "element": shipped_paths[0],
                "kind": "verifier_inclusion_path",
                "keys": shipped_paths,
            }
        )

    def unknown(element, reason):
        warnings.append(
            {
                "proofType": proof_type,
                "element": element,
                "kind": "set_size_unknown",
                "reason": reason,
            }
        )
        return warnings, SET_UNKNOWN

    def narrow(element, mode, size, outcome):
        if size < NARROW_SET_THRESHOLD:
            warnings.append(
                {
                    "proofType": proof_type,
                    "element": element,
                    "kind": "narrow_set",
                    "mode": mode,
                    "anonymitySetSize": size,
                    "threshold": NARROW_SET_THRESHOLD,
                }
            )
        return warnings, outcome

    mode = semantics.mode
    if semantics.mode_key is not None:
        code = parameters.get(semantics.mode_key)
        mode = _MEMBERSHIP_MODES.get(code) if _is_int(code) else None
        if mode is None:
            return unknown(semantics.mode_key, "membership mode is missing or unknown")
    if semantics.canonical_key is None or semantics.canonical_key not in parameters:
        if mode == CANONICAL_SET_INCLUSION:
            # The holder proves along the request's (or the default) path.
            element = shipped_paths[0] if shipped_paths else (semantics.canonical_key or "setRoot")
            return narrow(element, mode, 1, EXACT_MEMBER)
        return unknown(semantics.canonical_key, "no canonical code list in the request")
    codes = _code_set(parameters[semantics.canonical_key])
    if codes is None or any(
        code < CANONICAL_CODE_MIN or code > CANONICAL_CODE_MAX for code in codes
    ):
        return unknown(semantics.canonical_key, "the canonical code list is malformed")
    kind = CODE_SPACE_PROOF_TO_KIND.get(proof_type)
    domain_size = _CODE_DOMAIN_SIZE
    if kind is not None:
        try:
            space = get_code_space(parameters.get("codeSpaceId"), kind)
            for code in codes:
                space.validate_code(code)
        except ValueError:
            return unknown(semantics.canonical_key, "no valid code-space member list")
        domain_size = len(space.codes)
    size = len(codes) if mode == CANONICAL_SET_INCLUSION else domain_size - len(codes)
    outcome = EXACT_MEMBER if kind is not None and size == 1 else SET_DETERMINED
    return narrow(semantics.canonical_key, mode, size, outcome)

"""Canonical code-set trees for ZKC jurisdiction and sanctions predicates.

Jurisdiction exclusion and sanctions clearance prove non-membership by
exhibiting two set members that bracket the subject. That argument is sound
only when the verifier owns a canonical tree: member codes are unique, sorted,
and placed at consecutive indices, and exclusion sets are bracketed by reserved
minimum and maximum sentinels. A bare Merkle root does not attest any of those
properties, so :class:`CanonicalCodeSet` is the construction the verifier uses
before it publishes a root and the holder uses before it builds a witness.

The set mode is mandatory. Exclusion sets carry sentinels so every in-domain
non-member has two neighbours. Inclusion sets do not: the circuits treat every
leaf as an ordinary member, so adding sentinels would make codes 0 and 65535
provable members. Sanctions clearance is always exclusion; jurisdiction takes
its mode from the request's mandatory ``membershipType``. Consequently,
jurisdiction inclusion and exclusion over the same member codes intentionally
produce different roots.

The legacy source-of-funds and tax-residency profiles use full ``Field`` codes
and need a different tree construction. In remaining-predicate v1-v4, the
raw-code inclusion leaf 0 aliases the padding leaf at every empty index.
Remaining-predicate v5-v10 reject that code in-circuit while retaining the
full field domain. The code-space-bound successors use this tree construction
with the typed leaf encoders in ``code_space_transcripts``.

Padding follows :class:`merkle.SparseMerkleAccumulator`: an absent subtree of
height ``k`` contributes ``zero_subtree_root(k)``, not a literal zero except at
height 0. In the unbound code spaces, jurisdiction leaves are
``poseidon2(code, claim_type)`` and sanctions leaves are the raw u16 code.

Jurisdiction v3-v6 and the remaining-predicate v5-v11 sanctions branches
enforce index adjacency. These branches also require canonical construction
and authenticated verifier-derived roots. Jurisdiction v1/v2 and the
remaining-predicate v1-v4 sanctions branches lack the adjacency constraint, so
those identities cannot establish non-membership even with a canonical root.
"""

from __future__ import annotations

from .digests import compute_jurisdiction_leaf
from .field import FIELD_MODULUS
from .merkle import MERKLE_DEPTH, SparseMerkleAccumulator, compute_merkle_root

__all__ = [
    "CANONICAL_CODE_MAX",
    "CANONICAL_CODE_MIN",
    "CANONICAL_SET_EXCLUSION",
    "CANONICAL_SET_INCLUSION",
    "CANONICAL_SET_MAX_MEMBERS",
    "CANONICAL_SET_MAX_REQUEST_CODES",
    "CANONICAL_SET_MODES",
    "CANONICAL_SENTINEL_MAX",
    "CANONICAL_SENTINEL_MIN",
    "CANONICAL_SET_PARAM",
    "CANONICAL_SET_PARAM_KEYS",
    "JURISDICTION_CANONICAL_SET_PARAM",
    "CanonicalCodeSet",
    "CanonicalSetError",
    "MembershipWitness",
    "NonMembershipWitness",
    "jurisdiction_leaf_encoder",
    "raw_code_leaf",
]

# --- request-parameter key names (verifier <-> holder protocol shape, D4/D6) -
#
# ``zkc_verifier.verifier`` (derive-and-compare) and ``zkc_holder.client``
# (fail-fast reconciliation) each key a proof/verification request's
# ``parameters[proofType]`` dict by these names when the caller supplies a
# canonical code set instead of (or alongside) a bare root. Defined once here
# so the two sides can never drift on the string literal.
#
# Value shape: a JSON array of integer codes (pre-dedup/pre-sort;
# ``CanonicalCodeSet`` canonicalizes on construction). ``JURISDICTION_CANONICAL_SET_PARAM``
# is scoped by the jurisdiction predicate's existing mandatory ``requiredClaimType``
# parameter (folded into every leaf via ``jurisdiction_leaf_encoder``);
# ``CANONICAL_SET_PARAM`` serves sanctions-clearance, whose circuit uses
# ``raw_code_leaf``. The legacy source-of-funds and tax-residency profiles use
# a separate full-field construction. The code-space-bound profiles use the
# request contract in ``code_space_requests``.
# Accreditation has no Merkle set at all (the circuit leaves ``set_root``
# unconstrained on that branch) and is never a target of either key.
CANONICAL_SET_PARAM = "canonicalSet"
JURISDICTION_CANONICAL_SET_PARAM = "jurisdictionCanonicalSet"

# Every canonical-set request key, so both sides can detect a MIS-KEYED set
# (``canonicalSet`` on jurisdiction, ``jurisdictionCanonicalSet`` on a raw-code
# predicate). Such a request must be REJECTED, not ignored: silently ignoring
# it downgrades the request to the legacy bare-root path with no signal, and
# the holder's fail-fast reconciliation becomes a complete no-op.
CANONICAL_SET_PARAM_KEYS = (CANONICAL_SET_PARAM, JURISDICTION_CANONICAL_SET_PARAM)

# --- set mode (REQUIRED; see the module docstring) ---------------------------
#
# The mode decides whether the set is sentinel-bracketed. It is never defaulted:
# an inclusion set that is bracketed makes the sentinels provable members, and
# an exclusion set that is not bracketed cannot bracket edge subjects at all.
CANONICAL_SET_INCLUSION = "inclusion"
CANONICAL_SET_EXCLUSION = "exclusion"
CANONICAL_SET_MODES = (CANONICAL_SET_INCLUSION, CANONICAL_SET_EXCLUSION)

# Reserved u16 endpoint codes bracket each canonical exclusion set. Member
# and subject codes are 1..65534 in both inclusion and exclusion sets.
CANONICAL_SENTINEL_MIN = 0
CANONICAL_SENTINEL_MAX = (1 << 16) - 1

CANONICAL_CODE_MIN = CANONICAL_SENTINEL_MIN + 1
CANONICAL_CODE_MAX = CANONICAL_SENTINEL_MAX - 1

# Bounded by the u16 code domain long before the depth-32 tree runs out of
# leaves; both bounds are checked so the limit stays honest if the domain widens.
CANONICAL_SET_MAX_MEMBERS = min(
    CANONICAL_CODE_MAX - CANONICAL_CODE_MIN + 1,
    (1 << MERKLE_DEPTH) - 2,
)

# Online holder/verifier request processing has a tighter resource budget than
# offline tree construction.  A validly signed APR is still attacker-controlled
# input, and deriving a full-domain tree in the stdlib Poseidon reference would
# monopolize a process for seconds.  Both request boundaries enforce this
# pre-deduplication cap before copying or hashing any code list; the builder's
# mathematical/domain maximum above remains available for offline tooling.
CANONICAL_SET_MAX_REQUEST_CODES = 4096


class CanonicalSetError(ValueError):
    """A canonical set was mis-built, or a witness was requested that cannot exist."""


def raw_code_leaf(code: int) -> int:
    """Unbound sanctions leaf encoding, using the u16 code as a field element.

    The circuit hashes nothing: the leaf is ``predecessor_code as Field`` (or
    the corresponding successor). The code-space-bound profiles use typed
    leaves instead.
    """
    return int(code) % FIELD_MODULUS


def jurisdiction_leaf_encoder(claim_type: int):
    """Leaf encoder for jurisdiction sets: `poseidon2(code, claim_type)`.

    `claim_type` is folded into every leaf, sentinels included, so a set is
    scoped to one claim type. Returns a one-argument encoder.
    """
    if type(claim_type) is not int:
        raise CanonicalSetError("claim type must be an int")
    if not 0 <= claim_type < (1 << 8):
        raise CanonicalSetError("claim type must fit in u8")

    def encode(code: int) -> int:
        return compute_jurisdiction_leaf(int(code), claim_type)

    return encode


class MembershipWitness:
    """Witness that `code` is a member: feeds the circuit's membership branch."""

    __slots__ = ("code", "leaf", "path_index", "siblings")

    def __init__(self, code: int, leaf: int, path_index: int, siblings):
        self.code = code
        self.leaf = leaf
        self.path_index = path_index
        self.siblings = tuple(siblings)

    def root(self) -> int:
        """Re-derive the set root from this witness alone."""
        return compute_merkle_root(self.leaf, self.path_index, self.siblings)

    def __repr__(self) -> str:
        return f"MembershipWitness(code={self.code}, path_index={self.path_index})"


class NonMembershipWitness:
    """Sorted-neighbour witness that `subject_code` is absent.

    `predecessor_path_index + 1 == successor_path_index` holds by construction.
    """

    __slots__ = (
        "subject_code",
        "predecessor_code",
        "predecessor_leaf",
        "predecessor_path_index",
        "predecessor_siblings",
        "successor_code",
        "successor_leaf",
        "successor_path_index",
        "successor_siblings",
    )

    def __init__(self, subject_code: int, predecessor: MembershipWitness, successor: MembershipWitness):
        self.subject_code = subject_code
        self.predecessor_code = predecessor.code
        self.predecessor_leaf = predecessor.leaf
        self.predecessor_path_index = predecessor.path_index
        self.predecessor_siblings = predecessor.siblings
        self.successor_code = successor.code
        self.successor_leaf = successor.leaf
        self.successor_path_index = successor.path_index
        self.successor_siblings = successor.siblings

    @property
    def is_adjacent(self) -> bool:
        """True when the neighbours occupy consecutive leaf indices."""
        return self.successor_path_index == self.predecessor_path_index + 1

    def predecessor_witness(self) -> MembershipWitness:
        return MembershipWitness(
            self.predecessor_code,
            self.predecessor_leaf,
            self.predecessor_path_index,
            self.predecessor_siblings,
        )

    def successor_witness(self) -> MembershipWitness:
        return MembershipWitness(
            self.successor_code,
            self.successor_leaf,
            self.successor_path_index,
            self.successor_siblings,
        )

    def __repr__(self) -> str:
        return (
            f"NonMembershipWitness(subject={self.subject_code}, "
            f"predecessor={self.predecessor_code}@{self.predecessor_path_index}, "
            f"successor={self.successor_code}@{self.successor_path_index})"
        )


def _check_code(code, what: str = "code") -> int:
    """Domain check for a MEMBER code, applied in BOTH modes.

    The sentinel values stay reserved even in an inclusion set (which holds no
    sentinel leaves): reserving them keeps one code domain across the two modes,
    and it stops a verifier DECLARING code 0 as an accepted member — the value
    that collides with the raw-code padding leaf (see the module docstring's
    residual-gap note). It cannot stop a prover CLAIMING code 0; only a circuit
    constraint can.
    """
    if isinstance(code, bool) or not isinstance(code, int):
        raise CanonicalSetError(f"{what} must be an int, got {type(code).__name__}")
    if code in (CANONICAL_SENTINEL_MIN, CANONICAL_SENTINEL_MAX):
        raise CanonicalSetError(
            f"{what} {code} is a reserved canonical-set sentinel; "
            f"member codes are {CANONICAL_CODE_MIN}..{CANONICAL_CODE_MAX}"
        )
    if not CANONICAL_CODE_MIN <= code <= CANONICAL_CODE_MAX:
        raise CanonicalSetError(
            f"{what} {code} outside the canonical domain "
            f"{CANONICAL_CODE_MIN}..{CANONICAL_CODE_MAX}"
        )
    return code


class CanonicalCodeSet:
    """A verifier's published code set as a canonical depth-32 Poseidon2 tree.

    Construction: deduplicate, sort ascending, place at consecutive leaf indices
    starting at 0, pad the rest of the tree with zero subtrees. An EXCLUSION set
    is additionally bracketed with the reserved MIN and MAX sentinels (MIN at
    index 0, MAX at the last occupied index); an INCLUSION set is NOT — see the
    module docstring for why bracketing an inclusion set is unsound.

    ``mode`` is REQUIRED (``CANONICAL_SET_INCLUSION`` / ``CANONICAL_SET_EXCLUSION``).
    Prefer the per-predicate classmethods, which fix the predicate's encoding:
    :meth:`for_sanctions` (raw-code exclusion) and :meth:`for_jurisdiction`
    (claim-type-scoped leaves and a mode from the request's mandatory
    ``membershipType``).
    """

    def __init__(self, codes, leaf_encoder, mode):
        if mode not in CANONICAL_SET_MODES:
            raise CanonicalSetError(
                f"canonical set mode must be one of {CANONICAL_SET_MODES}, got {mode!r}; "
                "the mode is mandatory because it decides sentinel bracketing"
            )
        if not isinstance(codes, list):
            raise CanonicalSetError(
                "canonical set codes must be a list representing a JSON array"
            )
        # Bound the input cardinality before deduplication. Otherwise an
        # authenticated APR containing millions of copies of one valid code
        # would pass the distinct-member bound while consuming unbounded holder
        # and verifier work.
        unique_members = set()
        entry_count = 0
        for code in codes:
            entry_count += 1
            if entry_count > CANONICAL_SET_MAX_MEMBERS:
                raise CanonicalSetError(
                    f"canonical set input has more than "
                    f"{CANONICAL_SET_MAX_MEMBERS} entries before deduplication"
                )
            unique_members.add(_check_code(code))

        members = sorted(unique_members)
        if len(members) > CANONICAL_SET_MAX_MEMBERS:  # defensive; raw cap implies this
            raise CanonicalSetError(
                f"{len(members)} members exceeds the canonical maximum "
                f"{CANONICAL_SET_MAX_MEMBERS}"
            )
        self._members = tuple(members)
        self._mode = mode
        # Sentinels ONLY for exclusion. Bracketing an inclusion set would make
        # codes 0 and 65535 provable members of it, since the circuits' inclusion
        # branches are bare Merkle membership checks with no domain constraint.
        if mode == CANONICAL_SET_EXCLUSION:
            self._leaf_codes = (CANONICAL_SENTINEL_MIN, *members, CANONICAL_SENTINEL_MAX)
        else:
            self._leaf_codes = tuple(members)
        self._leaf_encoder = leaf_encoder
        self._leaves = tuple(leaf_encoder(code) % FIELD_MODULUS for code in self._leaf_codes)
        self._index = {code: i for i, code in enumerate(self._leaf_codes)}
        self._tree = SparseMerkleAccumulator(self._leaves)
        self._root = None

    # --- constructors per predicate ------------------------------------------

    @classmethod
    def for_jurisdiction(cls, codes, claim_type: int, mode: str) -> "CanonicalCodeSet":
        """Jurisdiction set: leaves are `poseidon2(code, claim_type)`.

        BOTH modes exist for this predicate and are selected by the request's
        mandatory ``membershipType`` parameter, so ``mode`` is required here and
        the caller must pass the mode that request states. The exclusion set and
        the inclusion set over the same codes have DIFFERENT roots (see the
        module docstring) — that is intended, not a bug.
        """
        return cls(codes, jurisdiction_leaf_encoder(claim_type), mode)

    @classmethod
    def for_sanctions(cls, codes) -> "CanonicalCodeSet":
        """Sanctions blocked-screening-code set: raw-code leaves, EXCLUSION.

        Sanctions clearance is always a non-membership proof, so this set is
        always sentinel-bracketed.
        """
        return cls(codes, raw_code_leaf, CANONICAL_SET_EXCLUSION)

    # --- shape ---------------------------------------------------------------

    @property
    def mode(self) -> str:
        """``CANONICAL_SET_INCLUSION`` or ``CANONICAL_SET_EXCLUSION``."""
        return self._mode

    @property
    def is_bracketed(self) -> bool:
        """True when the set carries the reserved MIN/MAX sentinel leaves."""
        return self._mode == CANONICAL_SET_EXCLUSION

    @property
    def members(self) -> tuple:
        """The member codes, deduplicated and sorted, without sentinels."""
        return self._members

    @property
    def leaf_codes(self) -> tuple:
        """Every leaf's code in index order, sentinels included."""
        return self._leaf_codes

    @property
    def leaves(self) -> tuple:
        """Every encoded leaf in index order."""
        return self._leaves

    def __len__(self) -> int:
        return len(self._leaf_codes)

    def __contains__(self, code) -> bool:
        return self.contains(code)

    def contains(self, code) -> bool:
        """True when `code` is a member (sentinels are not members)."""
        try:
            _check_code(code, "lookup code")
        except CanonicalSetError:
            return False
        return code in self._index and code not in (
            CANONICAL_SENTINEL_MIN,
            CANONICAL_SENTINEL_MAX,
        )

    def index_of(self, code) -> int:
        """Leaf index of `code`. In an exclusion set the sentinels resolve to
        0 and len-1; an inclusion set holds no sentinels at all."""
        if type(code) is not int or code not in (
            CANONICAL_SENTINEL_MIN,
            CANONICAL_SENTINEL_MAX,
        ):
            _check_code(code, "lookup code")
        try:
            return self._index[code]
        except KeyError:
            raise CanonicalSetError(f"code {code} is not in the set") from None

    def root(self) -> int:
        """The canonical set root, as published by the verifier."""
        if self._root is None:
            self._root = self._tree.root()
        return self._root

    # --- witnesses -----------------------------------------------------------

    def _witness_at(self, index: int) -> MembershipWitness:
        path_index, siblings = self._tree.witness(index)
        return MembershipWitness(
            self._leaf_codes[index], self._leaves[index], path_index, siblings
        )

    def membership_witness(self, code) -> MembershipWitness:
        """Witness that `code` is a member of this set."""
        _check_code(code, "subject code")
        if not self.contains(code):
            raise CanonicalSetError(
                f"code {code} is not a member; a membership witness cannot exist"
            )
        return self._witness_at(self.index_of(code))

    def non_membership_witness(self, code) -> NonMembershipWitness:
        """Sorted-neighbour witness that `code` is absent from this set.

        The sentinels guarantee a subject below the smallest member or above the
        largest still gets two real neighbours, so every in-domain non-member is
        provable. The returned neighbours are adjacent by construction.

        Only an EXCLUSION set can answer this: an inclusion set is deliberately
        unbracketed, so edge subjects have no bracketing neighbours and the
        argument does not exist. Refusing is the fail-closed answer — silently
        returning a witness that only works for interior subjects would make the
        set's mode invisible at the call site.
        """
        if self._mode != CANONICAL_SET_EXCLUSION:
            raise CanonicalSetError(
                "non-membership witnesses require an EXCLUSION set; this set was "
                f"built for {self._mode} and carries no sentinel bracket"
            )
        _check_code(code, "subject code")
        if self.contains(code):
            raise CanonicalSetError(
                f"code {code} IS a member of this set; a non-membership witness "
                f"cannot exist (refusing to emit an unprovable witness)"
            )
        # bisect over the sentinel-bracketed codes: strictly-less predecessor at
        # `position - 1`, strictly-greater successor at `position`.
        lo, hi = 0, len(self._leaf_codes)
        while lo < hi:
            mid = (lo + hi) // 2
            if self._leaf_codes[mid] < code:
                lo = mid + 1
            else:
                hi = mid
        predecessor_index = lo - 1
        successor_index = lo
        if predecessor_index < 0 or successor_index >= len(self._leaf_codes):
            raise CanonicalSetError(
                f"code {code} has no bracketing neighbours; the set is not "
                f"sentinel-bracketed"
            )
        witness = NonMembershipWitness(
            code,
            self._witness_at(predecessor_index),
            self._witness_at(successor_index),
        )
        if not witness.is_adjacent:
            raise CanonicalSetError("internal error: neighbours are not index-adjacent")
        return witness

    def __repr__(self) -> str:
        return (
            f"CanonicalCodeSet({len(self._members)} members, mode={self._mode}, "
            f"root=0x{self.root():064x})"
        )

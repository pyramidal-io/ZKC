"""Depth-32 Poseidon2 Merkle trees matching noir/zkc_lib path semantics.

`compute_merkle_root` mirrors zkc_lib::compute_merkle_root: the path index is
decomposed into 32 bits big-endian and consumed least-significant-bit first
(bit i of the index selects left/right at tree level i, leaf level = 0).

`SparseMerkleAccumulator` is the reference non-revocation accumulator: leaves
are active credential IDs, empty subtrees hash up from the zero leaf.
"""

from __future__ import annotations

from .poseidon2 import FIELD_MODULUS, poseidon2

__all__ = [
    "MERKLE_DEPTH",
    "compute_merkle_root",
    "SparseMerkleAccumulator",
    "zero_subtree_root",
]

MERKLE_DEPTH = 32

# zero_subtree[k] = root of an empty subtree of height k (zero leaves).
_ZERO_SUBTREE = [0]
for _ in range(MERKLE_DEPTH):
    _ZERO_SUBTREE.append(poseidon2(_ZERO_SUBTREE[-1], _ZERO_SUBTREE[-1]))


def zero_subtree_root(height: int) -> int:
    """Root of an empty subtree of `height` levels (0 <= height <= 32).

    This is the padding convention of the reference trees: the sibling standing
    in for an absent subtree at height k is `zero_subtree_root(k)`, never a
    literal 0 (which is only the correct value at height 0). Exposed because
    implementers must reproduce it to rebuild a canonical set root.
    """
    if not 0 <= height <= MERKLE_DEPTH:
        raise ValueError("zero-subtree height out of range for a depth-32 tree")
    return _ZERO_SUBTREE[height]


def compute_merkle_root(leaf: int, path_index: int, siblings) -> int:
    """zkc_lib::compute_merkle_root for a depth-32 path."""
    if not 0 <= path_index < (1 << MERKLE_DEPTH):
        raise ValueError("path index out of range for depth-32 tree")
    siblings = list(siblings)
    if len(siblings) != MERKLE_DEPTH:
        raise ValueError("expected exactly 32 siblings")
    current = leaf % FIELD_MODULUS
    for level in range(MERKLE_DEPTH):
        is_right = (path_index >> level) & 1
        if is_right:
            current = poseidon2(siblings[level], current)
        else:
            current = poseidon2(current, siblings[level])
    return current


class SparseMerkleAccumulator:
    """Append/remove accumulator over a depth-32 sparse Poseidon2 Merkle tree.

    Leaves are field elements (credential IDs) at consecutive indices; index
    slots may be zeroed (revocation). Empty regions use the zero-subtree cache,
    so the full 2^32-leaf tree is never materialized.
    """

    def __init__(self, leaves=None):
        self._leaves: list = list(leaves or [])

    def add(self, leaf: int) -> int:
        """Append a leaf; returns its index."""
        if leaf % FIELD_MODULUS == 0:
            raise ValueError("zero is not a valid accumulator leaf")
        self._leaves.append(leaf % FIELD_MODULUS)
        return len(self._leaves) - 1

    def remove(self, index: int) -> None:
        """Zero out a leaf slot (revoke)."""
        self._leaves[index] = 0

    def leaves(self) -> list:
        """Snapshot of the current leaf slots (zeroed slots included)."""
        return list(self._leaves)

    def index_of(self, leaf: int) -> int:
        target = leaf % FIELD_MODULUS
        for i, current in enumerate(self._leaves):
            if current == target:
                return i
        raise KeyError("leaf not present in accumulator")

    def _levels(self) -> list:
        levels = [list(self._leaves)]
        for height in range(MERKLE_DEPTH):
            below = levels[-1]
            above = []
            for i in range(0, len(below), 2):
                left = below[i]
                right = below[i + 1] if i + 1 < len(below) else _ZERO_SUBTREE[height]
                above.append(poseidon2(left, right))
            levels.append(above)
        return levels

    def root(self) -> int:
        if not self._leaves:
            return _ZERO_SUBTREE[MERKLE_DEPTH]
        return self._levels()[MERKLE_DEPTH][0]

    def witness(self, index: int):
        """(path_index, siblings) proving membership of the leaf at `index`."""
        if not 0 <= index < len(self._leaves):
            raise IndexError("leaf index out of range")
        levels = self._levels()
        siblings = []
        position = index
        for height in range(MERKLE_DEPTH):
            sibling_position = position ^ 1
            level = levels[height]
            if sibling_position < len(level):
                siblings.append(level[sibling_position])
            else:
                siblings.append(_ZERO_SUBTREE[height])
            position >>= 1
        return index, siblings

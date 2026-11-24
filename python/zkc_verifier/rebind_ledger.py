"""Verifier state rules for accepted credential-continuity claims (spec 7.4.7).

An issuer-authenticated rebind proves one thing: whoever holds the key the
issuer bound credential C to ALSO knows a new key. That is a continuity claim
at this verifier, not a migration of C. The credential digest stays bound to
the old holder commitment, so the new key can neither present C's predicates
nor rebind C again, while the old key keeps full power. Nothing in the
statement is exclusive or one-time: one old key yields valid rebinds to any
number of new keys, and a thief holding the old key can race the owner.

A verifier that treats an accepted rebind as an account move must therefore
keep state. :class:`RebindLedger` is the reference implementation of the
normative rules:

1. **One-time per credential at this verifier.** At most one continuity
   claim is honoured per ``(issuer, credential)``, across both statements and
   every scope (a presenter must not pick a fresh scope or the other statement
   to dodge a conflict). An identical replay is idempotent.
2. **Retire the old handle.** Once ``old -> new`` is accepted for C, ``old``
   no longer represents C's holder at this verifier.
3. **Conflict freezes.** A second, different claim for the same credential --
   fan-out, or a race under a compromised old key -- freezes C at this
   verifier: neither claimant's continuity is honoured until the issuer
   revokes C and re-issues it to the intended holder commitment. The verifier
   cannot tell the owner from a thief; the issuer can.

Only claims the verifier itself checked may be recorded: entries answering a
proof type of the request it verified, in an envelope it accepted. An
unrequested entry is skipped by verification (OVER_DISCLOSURE warning only),
so recording it would let a presenter attach a forged claim to any valid
envelope. The ledger adds state, never authentication.
"""

from __future__ import annotations

from dataclasses import dataclass

from zkc_crypto import hex_to_field

from .errors import VerificationResult
from .verifier import (
    REBIND_AUTH_PROOF_TYPE,
    REBIND_AUTH_V2_PROOF_TYPE,
    REBIND_AUTH_V3_PROOF_TYPE,
    VerificationRequest,
)

__all__ = [
    "RebindClaim",
    "RebindLedger",
    "RebindOutcome",
    "rebind_claims",
]

_LINKABLE_REBIND_AUTH = REBIND_AUTH_PROOF_TYPE
_SCOPED_REBIND_AUTH = frozenset((REBIND_AUTH_V2_PROOF_TYPE, REBIND_AUTH_V3_PROOF_TYPE))


class RebindOutcome:
    ACCEPTED = "accepted"
    REPLAYED = "replayed"
    CONFLICT = "conflict"


@dataclass(frozen=True)
class RebindClaim:
    """The continuity a verified rebind proof asserts, by public input."""

    proof_type: str
    issuer_id_hash: int
    credential_id: int
    scope_id: int  # 0 for the linkable statement
    old_handle: int
    new_handle: int

    @property
    def credential_key(self) -> tuple:
        return (self.issuer_id_hash, self.credential_id)

    @classmethod
    def from_proof_entry(cls, entry: dict) -> "RebindClaim":
        proof_type = entry["proofType"]
        inputs = entry["publicInputs"]
        if proof_type == _LINKABLE_REBIND_AUTH:
            old_name, new_name, scope_id = "old_holder_commitment", "new_holder_commitment", 0
        elif proof_type in _SCOPED_REBIND_AUTH:
            old_name, new_name = "old_presentation_pseudonym", "new_presentation_pseudonym"
            scope_id = hex_to_field(inputs["scope_id"])
        else:
            raise ValueError(f"{proof_type} is not an authenticated rebind statement")
        return cls(
            proof_type=proof_type,
            issuer_id_hash=hex_to_field(inputs["issuer_id_hash"]),
            credential_id=hex_to_field(inputs["credential_id"]),
            scope_id=scope_id,
            old_handle=hex_to_field(inputs[old_name]),
            new_handle=hex_to_field(inputs[new_name]),
        )


def rebind_claims(envelope: dict, request: VerificationRequest) -> tuple:
    """The authenticated rebind claims the verifier checked, in proof order.

    Only entries answering a proof type of ``request`` are verified (an
    unrequested entry is skipped with OVER_DISCLOSURE), so only those are
    claims; unrequested entries are ignored without being parsed."""
    requested = set(request.proof_types)
    return tuple(
        RebindClaim.from_proof_entry(entry)
        for entry in envelope.get("proofs", [])
        if entry.get("proofType") in requested
        and (
            entry.get("proofType") == _LINKABLE_REBIND_AUTH
            or entry.get("proofType") in _SCOPED_REBIND_AUTH
        )
    )


class RebindLedger:
    """Reference verifier-local continuity state (spec 7.4.7 rules 1-3)."""

    def __init__(self):
        self._accepted = {}  # credential_key -> the honoured RebindClaim
        self._frozen = set()  # credential_keys under conflict
        self._retired = set()  # (credential_key, handle)

    def apply(
        self, envelope: dict, request: VerificationRequest, result: VerificationResult
    ) -> tuple:
        """Record the claims this verifier checked when it accepted ``envelope``
        against ``request`` (the same pair passed to verify/verify_authenticated).

        Returns ``((claim, outcome), ...)``. Refuses an unaccepted envelope:
        recording must never stand in for verification."""
        if not isinstance(result, VerificationResult) or not result.valid:
            raise ValueError("only the claims of an accepted (valid) envelope may be recorded")
        if not isinstance(request, VerificationRequest):
            raise ValueError("the VerificationRequest the envelope was verified against is required")
        return tuple(
            (claim, self.record(claim)) for claim in rebind_claims(envelope, request)
        )

    def record(self, claim: RebindClaim) -> str:
        key = claim.credential_key
        if key in self._frozen:
            return RebindOutcome.CONFLICT
        prior = self._accepted.get(key)
        if prior is None:
            self._accepted[key] = claim
            self._retired.add((key, claim.old_handle))
            return RebindOutcome.ACCEPTED
        if prior == claim:
            return RebindOutcome.REPLAYED
        # Fan-out, a race, or the same credential under another scope or
        # statement: the verifier cannot tell owner from thief.
        self._frozen.add(key)
        return RebindOutcome.CONFLICT

    def accepted_claim(self, issuer_id_hash: int, credential_id: int):
        """The honoured claim for a credential, or None (none / frozen)."""
        key = (issuer_id_hash, credential_id)
        if key in self._frozen:
            return None
        return self._accepted.get(key)

    def holder_for(self, issuer_id_hash: int, credential_id: int):
        """The handle continuity currently points to, or None (none / frozen)."""
        claim = self.accepted_claim(issuer_id_hash, credential_id)
        return None if claim is None else claim.new_handle

    def is_frozen(self, issuer_id_hash: int, credential_id: int) -> bool:
        return (issuer_id_hash, credential_id) in self._frozen

    def is_retired(self, issuer_id_hash: int, credential_id: int, handle: int) -> bool:
        """True when ``handle`` was moved away from for this credential."""
        return ((issuer_id_hash, credential_id), handle) in self._retired

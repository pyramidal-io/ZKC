"""Agent compliance policy (spec §5.4 AgentCompliancePolicy).

DENY BY DEFAULT: an agent without a policy responds to nothing, an untrusted
verifier gets nothing, and a (proof type, verifier) pair without an explicit
rule is blocked. Auto-response is something the holder/principal OPTS INTO
per proof type — never an SDK default (non-goal: no autonomous disclosure
without holder/principal policy).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from zkc_holder.ceilings import EXACT_MEMBER_OPT_IN

from .errors import PolicyConfigurationError

__all__ = [
    "ACTION_AUTO_APPROVE",
    "ACTION_REQUIRE_PRINCIPAL_APPROVAL",
    "ACTION_BLOCK",
    "ACTIONS",
    "AgentCompliancePolicy",
]

ACTION_AUTO_APPROVE = "auto_approve"
ACTION_REQUIRE_PRINCIPAL_APPROVAL = "require_principal_approval"
ACTION_BLOCK = "block"
ACTIONS = (ACTION_AUTO_APPROVE, ACTION_REQUIRE_PRINCIPAL_APPROVAL, ACTION_BLOCK)


@dataclass(frozen=True)
class AgentCompliancePolicy:
    """Principal-authored automation policy for an agent holder.

    - `disclosure_ceiling`: proof type → maximum parameters the agent may
      ever disclose, in that proof type's own request vocabulary (KYC
      {"requiredLevel": int, "requiredAttributes": [bool]}, accreditation
      {"required0": int, "flagRequired": bool, ...}, jurisdiction
      {"membershipType", "requiredClaimType", "jurisdictionSetRoot",
      "jurisdictionCanonicalSet"}, ...). This doubles as the planner consent
      scope and is compared with typed per-predicate comparators
      (``zkc_holder.ceilings``): thresholds and flags in the direction that
      discloses more, set roots, modes and other unordered values pinned.
      Any request beyond the ceiling is refused, whatever the action says. A
      proof type absent from the ceiling, or with no comparator, can never be
      auto-disclosed. An inclusion proof whose witness the request fixes
      (source of funds, tax residency, jurisdiction inclusion without a
      canonical list) discloses the holder's exact code; it is refused unless
      that proof type's ceiling sets ``"allowExactMemberDisclosure": True``.
    - `trusted_verifiers`: verifier ids the agent may respond to at all.
      Unknown verifiers are blocked before any other rule is consulted.
    - `verifier_signing_keys`: verifier id → tuple of compressed SEC1 public
      keys from trusted local configuration. Empty pins refuse all signed APRs.
    - `actions`: proof type → tri-state action (auto_approve /
      require_principal_approval / block).
    - `verifier_overrides`: verifier id → {proof type → action}, taking
      precedence over `actions` for that verifier (e.g. auto-approve KYC
      generally but require approval for one specific exchange).

    Resolution order: untrusted verifier → block; verifier override →
    proof-type action → BLOCK (deny by default).
    """

    disclosure_ceiling: dict = field(default_factory=dict)
    trusted_verifiers: tuple = ()
    actions: dict = field(default_factory=dict)
    verifier_overrides: dict = field(default_factory=dict)
    # Trusted local configuration; never populate pins from a received APR.
    verifier_signing_keys: dict = field(default_factory=dict)

    def __post_init__(self):
        for verifier_id, keys in self.verifier_signing_keys.items():
            if verifier_id not in self.trusted_verifiers or not isinstance(keys, tuple):
                raise PolicyConfigurationError("signing keys require a trusted verifier and a tuple of pins")
            if any(type(key) is not bytes or len(key) != 33 or key[0] not in (2, 3) for key in keys):
                raise PolicyConfigurationError("verifier signing pins must be compressed SEC1 public keys")
        for proof_type, action in self.actions.items():
            if action not in ACTIONS:
                raise PolicyConfigurationError(
                    f"unknown action {action!r} for {proof_type} (one of {ACTIONS})"
                )
        for verifier_id, overrides in self.verifier_overrides.items():
            if verifier_id not in self.trusted_verifiers:
                raise PolicyConfigurationError(
                    f"verifier override for {verifier_id!r}, which is not a trusted verifier"
                )
            for proof_type, action in overrides.items():
                if action not in ACTIONS:
                    raise PolicyConfigurationError(
                        f"unknown action {action!r} for {proof_type} @ {verifier_id}"
                    )
        for proof_type, ceiling in self.disclosure_ceiling.items():
            if not isinstance(ceiling, dict):
                raise PolicyConfigurationError(
                    f"disclosure ceiling for {proof_type} must be a parameter object"
                )
            if EXACT_MEMBER_OPT_IN in ceiling and type(ceiling[EXACT_MEMBER_OPT_IN]) is not bool:
                raise PolicyConfigurationError(
                    f"disclosure ceiling {EXACT_MEMBER_OPT_IN} for {proof_type} must be "
                    "exactly true or false"
                )

    def trusts_verifier(self, verifier_id: str) -> bool:
        return verifier_id in self.trusted_verifiers

    def action_for(self, proof_type: str, verifier_id: str) -> str:
        """Tri-state action for one (proof type, verifier) pair — deny by
        default at every level."""
        if not self.trusts_verifier(verifier_id):
            return ACTION_BLOCK
        override = self.verifier_overrides.get(verifier_id, {})
        if proof_type in override:
            return override[proof_type]
        if proof_type in self.actions:
            return self.actions[proof_type]
        return ACTION_BLOCK

    def decision_for(self, proof_types, verifier_id: str) -> str:
        """Combined action for a multi-predicate request: any block blocks
        the whole request; otherwise any approval requirement queues it;
        only all-auto auto-responds."""
        actions = [self.action_for(proof_type, verifier_id) for proof_type in proof_types]
        if not actions or ACTION_BLOCK in actions:
            return ACTION_BLOCK
        if ACTION_REQUIRE_PRINCIPAL_APPROVAL in actions:
            return ACTION_REQUIRE_PRINCIPAL_APPROVAL
        return ACTION_AUTO_APPROVE

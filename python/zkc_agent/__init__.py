"""ZKC reference agent compliance API (stdlib-only Python, spec §5.4).

Automated, policy-bounded proof-request handling for agent holders:
compliance policy configuration (deny-by-default tri-state per proof type ×
verifier), handle_proof_request auto-response through the minimal-disclosure
planner, principal approval queue + notification hooks, precomputed proof
warm path, counterparty verification via the reference verifier, replay /
wrong-verifier protection, and a redacting JSONL audit log.

Non-goals by construction: no autonomous disclosure without holder/principal
policy, and no custody of spending authority.
"""

from .agent import (  # noqa: F401
    BLOCK_UNAUTHENTICATED_REQUEST,
    BLOCK_CONTEXT_MISMATCH,
    BLOCK_GENERATION_FAILED,
    BLOCK_NO_POLICY,
    BLOCK_NO_PUBLISHED_POLICY,
    BLOCK_PLANNING_REFUSED,
    BLOCK_POLICY,
    BLOCK_PRINCIPAL_DENIED,
    BLOCK_REPLAYED_REQUEST,
    BLOCK_UNTRUSTED_VERIFIER,
    AgentDecision,
    ApprovalRequest,
    DelegatedProver,
    DelegationToken,
    ViewingScope,
    ZKCAgentClient,
)
from .audit import FORBIDDEN_LOG_KEYS, REDACTED, AuditLog, redact  # noqa: F401
from .errors import (  # noqa: F401
    AgentError,
    ApprovalNotFoundError,
    PolicyConfigurationError,
)
from .policy import (  # noqa: F401
    ACTION_AUTO_APPROVE,
    ACTION_BLOCK,
    ACTION_REQUIRE_PRINCIPAL_APPROVAL,
    ACTIONS,
    AgentCompliancePolicy,
)

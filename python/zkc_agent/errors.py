"""Structured, fail-closed errors for the ZKC agent compliance API.

Messages never contain secret material (seeds, binding keys, credential
claims, proof payloads).
"""

from __future__ import annotations

__all__ = [
    "AgentError",
    "PolicyConfigurationError",
    "ApprovalNotFoundError",
]


class AgentError(Exception):
    """Base class; subclasses define a stable `code`."""

    code = "AGENT_ERROR"

    def __init__(self, message: str):
        super().__init__(f"[{self.code}] {message}")
        self.message = message


class PolicyConfigurationError(AgentError):
    code = "POLICY_CONFIGURATION_ERROR"


class ApprovalNotFoundError(AgentError):
    code = "APPROVAL_NOT_FOUND"

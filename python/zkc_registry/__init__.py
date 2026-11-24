"""ZKC discovery registry (stdlib-only Python).

Loads and validates the in-repo discovery data — issuer metadata documents
(``registry/issuers/``) and PUBLISHED verifier trust policies
(``registry/verifiers/``) — and answers discovery queries:

* ``lookup_issuers``: which issuers support a schema / credential type /
  proof type;
* ``find_accepting_verifiers``: which verifiers accept a holder's credential
  or proof type.

The registry provides DISCOVERY ONLY (Freedom Safeguard 1):

* registry membership NEVER confers trust — a verifier trusts exactly the
  key-exact allowlist in its own policy, and an empty policy trusts nobody;
* policies are first-class for issuers that appear in NO registry — trust is
  by key, not by membership;
* there is no canonical issuer, no default credential type, and no ranking:
  every lookup returns ALL matches in a deterministic order.
"""

from .store import (  # noqa: F401
    DiscoveryRegistry,
    DuplicateRegistryIdError,
    IssuerDocument,
    RegistryError,
    RegistryValidationError,
    VerifierPolicyDocument,
    to_holder_trust_policy,
    to_verifier_trust_policy,
)

__all__ = [
    "DiscoveryRegistry",
    "DuplicateRegistryIdError",
    "IssuerDocument",
    "RegistryError",
    "RegistryValidationError",
    "VerifierPolicyDocument",
    "to_holder_trust_policy",
    "to_verifier_trust_policy",
]

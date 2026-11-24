"""ZKC reference verifier library (stdlib-only Python).

Implements spec §6: zkc:proof:v1 parsing, freshness, context binding, holder
binding, verification-key lookup (artifact manifest), accumulator epoch
freshness, issuer trust policy checks, type-specific requirement checks, and
structured verification errors.

No canonical issuers and no policy recommendations: every trusted issuer is
explicit verifier-local configuration. See python/README.md.
"""

from .backends import BBVerifyBackend, StubVerifyBackend, VerifyBackend  # noqa: F401
from .disclosure import disclosure_warnings  # noqa: F401
from .errors import (  # noqa: F401
    VerificationError,
    VerificationErrorCode,
    VerificationResult,
    VerificationWarning,
    VerificationWarningCode,
)
from .trust_policy import (  # noqa: F401
    IssuerAccumulatorState,
    TrustedIssuer,
    VerifierTrustPolicy,
)
from .rebind_ledger import (  # noqa: F401
    RebindClaim,
    RebindLedger,
    RebindOutcome,
    rebind_claims,
)
from .verifier import VerificationRequest, ZKCVerifier  # noqa: F401
from .vk_store import VerificationKeyStore  # noqa: F401

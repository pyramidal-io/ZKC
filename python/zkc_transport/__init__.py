"""ZKC HTTP transport for the in-process issuer + revocation services (stdlib-only).

The server and client forward the reference services' JSON wire shapes.

* ``RevocationServer`` / ``IssuerServer`` — stdlib ``http.server`` servers that
  forward to a ``RevocationAccumulatorService`` / ``IssuerAdapter`` unchanged.
* ``RevocationServiceClient`` / ``IssuerServiceClient`` — ``urllib`` clients
  speaking the same wire shapes.
* ``HTTPWitnessUpdateProvider`` — per-credential HTTP refresh using signed
  epoch announcements and a locally pinned accumulator and issuer keys.
* ``zkc_revocation.PrivateWitnessProvider`` — credential-anonymous refresh
  when paired with a ``RevocationServiceClient`` and local trust policy.
* ``TransportError`` — structured client-side failure carrying the protocol
  error ``code`` when the server returned one.

Operator mutations (revoke, renew) never share the holder-facing listener:
``IssuerAdminServer`` serves them on a separate socket and admits only
requests signed by a pinned operator key (``OperatorKey`` /
``OperatorAuthenticator``, see ``operator_auth``); ``IssuerAdminClient``
signs them. A credential id is public and never authorizes anything.

NOT a production deployment: no TLS, and the holder-facing listeners
authenticate no caller. A real gateway sits in front and reuses the identical
wire shapes. The business logic stays in zkc_revocation / zkc_issuer — this
layer only moves bytes.
"""

from .client import (  # noqa: F401
    HTTPWitnessUpdateProvider,
    IssuerAdminClient,
    IssuerServiceClient,
    RevocationServiceClient,
    TransportError,
)
from .operator_auth import OperatorAuthenticator, OperatorKey  # noqa: F401
from .server import (  # noqa: F401
    ADMIN_RENEW_PATH,
    ADMIN_REVOKE_PATH,
    ISSUER_WELL_KNOWN_PATH,
    REVOCATION_ANNOUNCEMENT_PATH,
    REVOCATION_UPDATES_PATH,
    IssuerAdminServer,
    IssuerServer,
    RevocationServer,
)

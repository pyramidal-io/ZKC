"""Make the repo's python/ packages importable from the test suite."""

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
PYTHON_DIR = REPO_ROOT / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))


# The bundled sandbox signing key is a public test key whose default validity
# window ends on a fixed date. Tests that build ``SandboxIssuerAdapter()`` issue
# on the real clock, so once that clock reaches the end of the window the
# adapter can no longer sign genesis or credentials (EXPIRED_ISSUER_KEY).
# Production key windows are not touched: this wraps only the test-issuer
# constructor, only inside the test suite, and only when the caller did not pin
# a window and the default window has run out. Fixed historical test
# timestamps stay inside the window because ``not_before`` never moves.
_SANDBOX_WINDOW_RENEWAL_SECONDS = 365 * 86_400


def _renew_expired_default_sandbox_window() -> None:
    import datetime
    import time

    from zkc_issuer.keys import IssuerSigningKey, _parse_rfc3339

    constructor = IssuerSigningKey.__dict__["test_issuer"]
    if getattr(constructor.__func__, "_zkc_window_renewal", False):
        return
    default_not_after = _parse_rfc3339(IssuerSigningKey.__dataclass_fields__["not_after"].default)
    original = constructor.__func__

    def test_issuer(cls, key_id: str = "sandbox-2026-01", **kwargs):
        now = int(time.time())
        if "not_after" not in kwargs and now + 86_400 >= default_not_after:
            renewed = now + _SANDBOX_WINDOW_RENEWAL_SECONDS
            kwargs["not_after"] = datetime.datetime.fromtimestamp(
                renewed, datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
        return original(cls, key_id, **kwargs)

    test_issuer._zkc_window_renewal = True
    IssuerSigningKey.test_issuer = classmethod(test_issuer)


_renew_expired_default_sandbox_window()

"""Stdlib HTTP client SDKs for the ZKC revocation + issuer transports.

These speak the exact JSON wire shapes the in-process services define, so the
only difference from the in-process path is the transport: a ``urllib`` POST/GET
to a ``RevocationServer`` / ``IssuerServer`` instead of a direct method call.

* ``RevocationServiceClient`` — raw transport over the witness-update /
  epoch-delta / announcement wire shapes, mirroring
  ``RevocationAccumulatorService``'s server-side surface.
* ``HTTPWitnessUpdateProvider`` — per-credential witness refresh using the same
  pinned-key and signed-chain checks as the in-process provider. For
  credential-anonymous refresh, use ``zkc_revocation.PrivateWitnessProvider``
  with a revocation client, a locally pinned accumulator id, and a separate
  trusted announcement publication source.
* ``IssuerServiceClient`` — the four adapter stages + issuer surfaces over HTTP.

Stdlib-only (``urllib`` + ``json``). A non-2xx response carrying the server's
``{"error": {...}}`` body is raised as ``TransportError`` (with the adapter
error ``code`` when present), so callers see structured failures, not raw HTTP.

Responses are bounded before they are parsed: a body larger than the
client's ``max_response_bytes`` (default ``DEFAULT_MAX_RESPONSE_BYTES``), a
body that is not received within ``timeout`` seconds in total, and JSON the
server parser would refuse (``NaN``/``Infinity``, duplicate keys, excessive
nesting) each raise ``TransportError``.
"""

from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from zkc_crypto import field_to_hex
from zkc_revocation.provider import WitnessUpdateProvider
from zkc_revocation.service import (
    EPOCH_DELTA_REQUEST,
    WITNESS_UPDATE_REQUEST,
)

from .server import (
    ADMIN_RENEW_PATH,
    ADMIN_REVOKE_PATH,
    ISSUER_WELL_KNOWN_PATH,
    REVOCATION_ANNOUNCEMENT_PATH,
    REVOCATION_UPDATES_PATH,
    loads_strict_json,
)

__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "TransportError",
    "RevocationServiceClient",
    "HTTPWitnessUpdateProvider",
    "IssuerServiceClient",
    "IssuerAdminClient",
]


class TransportError(RuntimeError):
    """A transport-level failure (non-2xx response or unreachable server).

    ``code`` carries the server's structured adapter error code when the
    response body included one; ``status`` is the HTTP status (or None)."""

    def __init__(self, message: str, code: str = None, status: int = None):
        super().__init__(message)
        self.code = code
        self.status = status


# 16 MiB: a full epoch-state response of about 230,000 leaves. Pass a larger
# max_response_bytes for a larger accumulator.
DEFAULT_MAX_RESPONSE_BYTES = 1 << 24
# Error bodies carry only {"error": {"code", "message"}}.
_MAX_ERROR_BODY_BYTES = 1 << 16
_READ_CHUNK_BYTES = 1 << 16


def _read_bounded(response, limit: int, deadline: float) -> bytes:
    """Read at most ``limit`` bytes before ``deadline``; refuse anything more.

    A declared ``Content-Length`` above the limit is refused before any read.
    Each chunk waits at most the socket timeout, and the deadline is checked
    between chunks, so a server that sends slowly cannot hold the client.
    """
    declared = response.headers.get("Content-Length") if response.headers else None
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise TransportError(f"response body exceeds {limit} bytes")
    chunks = []
    size = 0
    while True:
        if time.monotonic() > deadline:
            raise TransportError("response body was not received in time")
        chunk = response.read1(_READ_CHUNK_BYTES)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > limit:
            raise TransportError(f"response body exceeds {limit} bytes")
        chunks.append(chunk)


def _request(method: str, url: str, body: dict = None, timeout: float = 10.0,
             extra_headers: dict = None,
             max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES) -> dict:
    """``body`` is a JSON-able dict, or exact bytes when they are signed."""
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    deadline = time.monotonic() + timeout
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = _read_bounded(response, max_response_bytes, deadline)
    except urllib.error.HTTPError as exc:
        with exc:
            try:
                detail = _read_bounded(exc, _MAX_ERROR_BODY_BYTES, deadline)
            except (TransportError, OSError, http.client.HTTPException):
                detail = b""
        code = None
        message = f"HTTP {exc.code}"
        try:
            parsed = loads_strict_json(detail)
            error = parsed.get("error", {})
            code = error.get("code")
            message = error.get("message", message)
        except (ValueError, AttributeError):
            pass
        raise TransportError(message, code=code, status=exc.code) from exc
    except urllib.error.URLError as exc:
        raise TransportError(f"transport unreachable: {exc.reason}") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise TransportError("transport failed while reading the response") from exc
    if not payload:
        return {}
    try:
        return loads_strict_json(payload)
    except ValueError as exc:
        raise TransportError("response body is not valid JSON") from exc


class RevocationServiceClient:
    """Raw HTTP client for a ``RevocationServer``."""

    def __init__(self, base_url: str, timeout: float = 10.0,
                 max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES):
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._max_response_bytes = max_response_bytes

    def _post(self, path: str, body: dict) -> dict:
        return _request("POST", self._base + path, body, self._timeout,
                        max_response_bytes=self._max_response_bytes)

    def _get(self, path: str) -> dict:
        return _request("GET", self._base + path, None, self._timeout,
                        max_response_bytes=self._max_response_bytes)

    def handle_request(self, request: dict) -> dict:
        """Send a revocation update request using the server's wire shape."""
        return self._post(REVOCATION_UPDATES_PATH, request)

    def witness_update(self, accumulator_id: str, credential_id: int, from_epoch: int = None) -> dict:
        """Witness-update request (``zkc:witness-update-request:v1``)."""
        request = {
            "type": WITNESS_UPDATE_REQUEST,
            "accumulatorId": accumulator_id,
            "credentialId": field_to_hex(credential_id),
        }
        if from_epoch is not None:
            request["fromEpoch"] = int(from_epoch)
        return self.handle_request(request)

    def epoch_delta(self, accumulator_id: str, from_epoch: int = None) -> dict:
        """Raw leaf fetch. Supplying ``from_epoch`` reveals the client's delta base."""
        request = {"type": EPOCH_DELTA_REQUEST, "accumulatorId": accumulator_id}
        if from_epoch is not None:
            request["fromEpoch"] = int(from_epoch)
        return self.handle_request(request)

    def current_announcement(self) -> dict:
        return self._get(REVOCATION_ANNOUNCEMENT_PATH)

    def announcement_for_epoch(self, epoch: int) -> dict:
        return self._get(f"{REVOCATION_ANNOUNCEMENT_PATH}/{int(epoch)}")


class HTTPWitnessUpdateProvider(WitnessUpdateProvider):
    """Per-credential HTTP refresh with a pinned accumulator and issuer keys."""

    def __init__(self, services: dict, issuer_keys: dict, **policy):
        """Map issuer ids to (client or base URL, pinned accumulator id).

        The issuer key map and checkpoint policy match WitnessUpdateProvider.
        """
        clients = {}
        for issuer_id, (target, accumulator_id) in services.items():
            client = RevocationServiceClient(target) if isinstance(target, str) else target
            clients[issuer_id] = (client, accumulator_id)
        super().__init__(clients, issuer_keys, **policy)


class IssuerServiceClient:
    """HTTP client for the four issuer adapter stages + issuer surfaces.

    Mirrors ``zkc_issuer.IssuerAdapter``: each stage takes/returns a JSON-able
    dict; a structured adapter failure on the server becomes a ``TransportError``
    carrying the protocol error ``code``.
    """

    def __init__(self, base_url: str, timeout: float = 10.0,
                 max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES):
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._max_response_bytes = max_response_bytes

    def _post(self, path: str, body: dict) -> dict:
        return _request("POST", self._base + path, body, self._timeout,
                        max_response_bytes=self._max_response_bytes)

    def verify_subject(self, payload: dict) -> dict:
        return self._post("/v1/issuer/verify-subject", payload)

    def request_binding_challenge(self, payload: dict) -> dict:
        return self._post("/v1/issuer/binding-challenge", payload)

    def bind_holder_commitment(self, payload: dict) -> dict:
        return self._post("/v1/issuer/bind-holder", payload)

    def issue_credential(self, payload: dict) -> dict:
        return self._post("/v1/issuer/issue-credential", payload)

    def publish_revocation_handle(self, payload: dict) -> dict:
        return self._post("/v1/issuer/publish-revocation-handle", payload)

    def issuer_metadata(self) -> dict:
        return _request("GET", self._base + ISSUER_WELL_KNOWN_PATH, None, self._timeout,
                        max_response_bytes=self._max_response_bytes)


class IssuerAdminClient:
    """Operator client for an ``IssuerAdminServer``; signs every request.

    Revocation and renewal are not holder operations and are not served by
    ``IssuerServer``. ``operator_key`` is a ``zkc_transport.OperatorKey`` (or
    any object with the same ``sign_request``) whose public key the server
    pins; ``issuer_id`` is the audience the signature binds. Each request
    gets a fresh timestamp and nonce, and the signature covers the exact
    body bytes sent.
    """

    def __init__(self, base_url: str, operator_key, issuer_id: str,
                 timeout: float = 10.0, clock=time.time,
                 max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES):
        self._base = base_url.rstrip("/")
        self._target_prefix = urllib.parse.urlsplit(self._base).path
        self._key = operator_key
        self._issuer_id = issuer_id
        self._max_response_bytes = max_response_bytes
        self._timeout = timeout
        self._clock = clock

    def _post(self, path: str, body: dict) -> dict:
        raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
        headers = self._key.sign_request(
            issuer_id=self._issuer_id,
            method="POST",
            request_target=self._target_prefix + path,
            body=raw,
            timestamp=int(self._clock()),
        )
        return _request("POST", self._base + path, raw, self._timeout, headers,
                        self._max_response_bytes)

    def revoke_credential(self, credential_id: int) -> dict:
        return self._post(ADMIN_REVOKE_PATH, {"credentialId": field_to_hex(credential_id)})

    def renew_credential(self, payload: dict) -> dict:
        return self._post(ADMIN_RENEW_PATH, payload)

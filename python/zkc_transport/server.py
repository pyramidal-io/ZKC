"""Stdlib HTTP servers for the in-process ZKC issuer + revocation services.

The reference revocation (``zkc_revocation.RevocationAccumulatorService``) and
issuer (``zkc_issuer.IssuerAdapter``) services are in-process: every operation
is a plain ``handle_request(dict) -> dict`` / stage ``(payload) -> dict`` call
over JSON-able wire shapes. This module is the thin
``POST body -> handler -> response`` translation the service docstrings
describe — no business logic lives here, so the wire shapes stay the single
source of truth.

Stdlib-only (``http.server`` + ``json``), matching the rest of the reference
stack. NOT a production server: no TLS, and the holder-facing listeners
authenticate no caller (the adapter's trusted session callback stands in for
a gateway). Only the operator listener checks a principal. Threaded by default
(pass ``threaded=False`` for ``HTTPServer``). Accumulator transitions and reads
are serialized by the accumulator service. Production
deployments put their own gateway in front and keep the same wire shapes.

Routes
------
Revocation (``RevocationServer``):

* ``POST /v1/revocation/updates``        — witness-update / epoch-delta request
  (the request body's ``type`` selects which; see service docstring)
* ``GET  /v1/revocation/announcement``   — current signed epoch announcement
* ``GET  /v1/revocation/announcement/{epoch}`` — historical announcement

Issuer (``IssuerServer``), the holder-facing listener: the 4 adapter stages
plus the public metadata document. It routes no operator mutation.

* ``POST /v1/issuer/verify-subject``
* ``POST /v1/issuer/binding-challenge``
* ``POST /v1/issuer/bind-holder``
* ``POST /v1/issuer/issue-credential``
* ``POST /v1/issuer/publish-revocation-handle`` — public status oracle, see below
* ``GET  /.well-known/zkc-issuer.json``  — issuer metadata document

Issuer operator (``IssuerAdminServer``), a SEPARATE listener for mutations
that need an operator principal. Every request must carry a signature by a
pinned operator key (``zkc_transport.operator_auth``); anything else is
refused with HTTP 401 before the body is parsed:

* ``POST /v1/admin/revoke`` — body exactly ``{"credentialId": "0x…"}``
* ``POST /v1/admin/renew``  — body ``{"credentialId": "0x…", "expiresAt"?}``
  (the adapter still applies its own owning-session rule)

A credential id is public: every active one is a published accumulator leaf
(the epoch-delta full mode lists them all), so neither listener treats
knowledge of an id as authorization. Stage 4 therefore answers status and a
membership witness for any id; that is data the leaf set already publishes,
and the adapter rate-limits it (docs/zkc_metadata_leakage_threat_model.md
section 1.10).

Error mapping (fail closed): a ``zkc_issuer.AdapterError`` becomes HTTP 422
with body ``{"error": {"code", "message"}}`` (the protocol's closed code set);
malformed JSON / unknown route / wrong method become 400 / 404 / 405; a
missing or invalid operator signature becomes 401; any other exception
becomes 500 with a generic message (never leaks internals).
The metadata document takes no request input, so every failure to build it
is an issuer-state fault: HTTP 503 with a generic message, plus the adapter
error code when there is one (for example ``EXPIRED_ISSUER_KEY``). The
revocation routes follow the same rule: the service reports every request
fault as an ``AdapterError``, so any other failure there is a 503, and the
current-announcement GET, which takes no input, is a 503 in every case.

Request bounds (every listener, before any handler runs):

* ``Content-Length`` is exactly one header of ASCII decimal digits and at
  most ``MAX_REQUEST_BODY_BYTES``; ``Transfer-Encoding`` is refused. Each
  violation is a structured 400.
* The body is UTF-8 JSON with an object at the top level, no duplicate
  keys, no ``NaN``/``Infinity``, no non-finite number, and at most 64
  nested objects or arrays, counting the root. Each violation is a 400.
* The whole request (line, headers and body) must arrive within
  ``request_timeout`` seconds. A slow body gets 408; a slow request line
  or header block is dropped.
* At most ``max_concurrent_requests`` connections are served at once; a
  connection beyond that gets 503 at once, without a handler thread.
* Every error, including the ones ``http.server`` raises itself (bad
  request line, oversized headers, unsupported method), has the JSON body
  ``{"error": {"message": ...}}``.
"""

from __future__ import annotations

import io
import json
import logging
import math
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

from zkc_crypto import canonical_hex_to_field, field_to_hex
from zkc_issuer.errors import AdapterError

from .operator_auth import OperatorAuthenticator

__all__ = [
    "RevocationServer",
    "IssuerServer",
    "IssuerAdminServer",
    "REVOCATION_UPDATES_PATH",
    "REVOCATION_ANNOUNCEMENT_PATH",
    "ISSUER_WELL_KNOWN_PATH",
    "ISSUER_HOLDER_POST_PATHS",
    "ADMIN_REVOKE_PATH",
    "ADMIN_RENEW_PATH",
    "DEFAULT_MAX_CONCURRENT_REQUESTS",
    "DEFAULT_REQUEST_TIMEOUT_SECONDS",
    "MAX_REQUEST_BODY_BYTES",
]

logger = logging.getLogger("zkc.transport")

REVOCATION_UPDATES_PATH = "/v1/revocation/updates"
REVOCATION_ANNOUNCEMENT_PATH = "/v1/revocation/announcement"
ISSUER_WELL_KNOWN_PATH = "/.well-known/zkc-issuer.json"
ADMIN_REVOKE_PATH = "/v1/admin/revoke"
ADMIN_RENEW_PATH = "/v1/admin/renew"
# The only POST routes the holder-facing issuer listener serves.
ISSUER_HOLDER_POST_PATHS = (
    "/v1/issuer/verify-subject",
    "/v1/issuer/binding-challenge",
    "/v1/issuer/bind-holder",
    "/v1/issuer/issue-credential",
    "/v1/issuer/publish-revocation-handle",
)

MAX_REQUEST_BODY_BYTES = 1 << 20  # 1 MiB; reference scale, fail closed beyond this.
# Time allowed to receive one whole request (line, headers and body).
DEFAULT_REQUEST_TIMEOUT_SECONDS = 10.0
# Connections served at once by a threaded listener; more get 503.
DEFAULT_MAX_CONCURRENT_REQUESTS = 32
# Enough digits for MAX_REQUEST_BODY_BYTES; int() alone would also accept
# whitespace, a sign, "_" separators and non-ASCII digits.
_CONTENT_LENGTH = re.compile(r"[0-9]{1,7}")
# A u64 epoch in canonical decimal: no sign, no leading zero, no whitespace.
_EPOCH_SEGMENT = re.compile(r"0|[1-9][0-9]{0,19}")
_U64_LIMIT = 1 << 64
_MAX_JSON_DEPTH = 64
# Match escapes as a unit so an escaped quote cannot end a string.
_JSON_STRUCTURE = re.compile(r'\\.|["{}\[\]]', re.DOTALL)
_BUSY_BODY = json.dumps({"error": {"message": "server is at its connection limit"}}).encode()
_BUSY_RESPONSE = (
    b"HTTP/1.0 503 Service Unavailable\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: " + str(len(_BUSY_BODY)).encode() + b"\r\n"
    b"Connection: close\r\n\r\n" + _BUSY_BODY
)


class _IssuerStateFault(Exception):
    """The server cannot produce a response because of its own state (5xx)."""

    def __init__(self, message: str, code: str = None):
        super().__init__(message)
        self.message = message
        self.code = code


class _RequestError(Exception):
    """A request input the transport itself rejects (HTTP 400)."""


def _reject_constant(name: str):
    raise ValueError(f"JSON constant {name} is not allowed")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("JSON number is not finite")
    return value


def _unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON object has a duplicate key")
        result[key] = value
    return result


def loads_strict_json(raw: bytes):
    """Decode UTF-8 JSON as a closed wire format; raise ``ValueError``.

    Refuses what ``json.loads`` accepts by default but no ZKC wire shape
    uses: ``NaN``/``Infinity``, numbers that overflow to infinity, duplicate
    object keys, and more than 64 nested containers. Check depth before
    decoding so the wire limit is independent of the available parser stack.
    """
    text = raw.decode("utf-8")
    depth = 0
    in_string = False
    for match in _JSON_STRUCTURE.finditer(text):
        token = match[0]
        if token == '"':
            in_string = not in_string
        elif in_string:
            continue
        elif token in ("{", "["):
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                raise ValueError(f"JSON nesting exceeds {_MAX_JSON_DEPTH} containers")
        elif token in ("}", "]"):
            depth -= 1

    try:
        return json.loads(
            text,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
            object_pairs_hook=_unique_object,
        )
    except RecursionError:
        raise ValueError("JSON nesting is too deep") from None


class _DeadlineSocketReader(io.RawIOBase):
    """Raw socket reader with one deadline for the whole request.

    A per-read socket timeout alone lets a client keep a handler thread by
    sending one byte just before each timeout. Each read here waits at most
    until the request's deadline and raises ``TimeoutError`` after it.
    """

    def __init__(self, sock, deadline: float):
        super().__init__()
        self._sock = sock
        self._deadline = deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request was not received before its deadline")
        self._sock.settimeout(remaining)
        return self._sock.recv_into(buffer)


class _JSONRequestHandler(BaseHTTPRequestHandler):
    """Routes via the server's ``dispatch`` table; never logs request bodies."""

    error_content_type = "application/json"

    # Quiet by default: the access log would otherwise spam test output.
    def log_message(self, format, *args):  # noqa: A002 (stdlib signature)
        logger.debug("%s - %s", self.address_string(), format % args)

    def setup(self):
        super().setup()
        timeout = self.server.request_timeout
        # One deadline covers the request line, the headers and the body.
        buffered = self.rfile
        self.rfile = io.BufferedReader(
            _DeadlineSocketReader(self.connection, time.monotonic() + timeout)
        )
        buffered.close()

    def send_error(self, code, message=None, explain=None):
        """JSON for the errors ``http.server`` raises itself (bad line, 414, 431, 501)."""
        self.close_connection = True
        reason = message or self.responses.get(code, ("error",))[0]
        self._send_error(int(code), str(reason))

    # --- body / response helpers -------------------------------------------------

    def _read_raw_body(self):
        lengths = self.headers.get_all("Content-Length") or []
        if self.headers.get("Transfer-Encoding") is not None:
            self._refuse(400, "Transfer-Encoding is not supported; send Content-Length")
            return None
        if len(lengths) > 1:
            self._refuse(400, "request has more than one Content-Length header")
            return None
        text = lengths[0] if lengths else "0"
        if _CONTENT_LENGTH.fullmatch(text) is None:
            self._refuse(400, "Content-Length must be ASCII decimal digits")
            return None
        length = int(text)
        if length > MAX_REQUEST_BODY_BYTES:
            self._refuse(400, "request body too large or malformed")
            return None
        if not length:
            return b""
        try:
            raw = self.rfile.read(length)
        except TimeoutError:
            self._refuse(408, "request body was not received in time")
            return None
        if len(raw) != length:
            self._refuse(400, "request body is shorter than Content-Length")
            return None
        return raw

    def _refuse(self, status: int, message: str) -> None:
        # The unread rest of the request makes this connection unusable.
        self.close_connection = True
        self._send_error(status, message)

    def _read_json_body(self):
        raw = self._read_raw_body()
        if raw is None:
            return None
        return self._parse_json_body(raw)

    def _parse_json_body(self, raw: bytes):
        if not raw:
            return {}
        try:
            body = loads_strict_json(raw)
        except ValueError:  # UnicodeDecodeError is a ValueError
            self._send_error(400, "request body is not valid JSON")
            return None
        if not isinstance(body, dict):
            self._send_error(400, "request body must be a JSON object")
            return None
        return body

    def _send_json(self, status: int, payload: dict) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        # Reads may have shortened the socket timeout to the request deadline.
        self.connection.settimeout(self.server.request_timeout)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(encoded)

    def _send_error(self, status: int, message: str, code: str = None) -> None:
        error = {"message": message}
        if code is not None:
            error["code"] = code
        self._send_json(status, {"error": error})

    # --- dispatch ----------------------------------------------------------------

    def do_GET(self):  # noqa: N802 (stdlib signature)
        handler = self.server.dispatch_get(self.path)
        if handler is None:
            self._send_error(404, "unknown route")
            return
        self._invoke(handler, None)

    def do_POST(self):  # noqa: N802 (stdlib signature)
        handler = self.server.dispatch_post(self.path)
        if handler is None:
            self._send_error(404, "unknown route")
            return
        body = self._read_json_body()
        if body is None:
            return  # _read_json_body already sent the error
        self._invoke(handler, body)

    def _invoke(self, handler, body) -> None:
        try:
            response = handler(body) if body is not None else handler()
        except _IssuerStateFault as exc:
            self._send_error(503, exc.message, exc.code)
            return
        except AdapterError as exc:
            self._send_json(422, {"error": exc.to_dict()})
            return
        except _RequestError as exc:
            self._send_error(400, str(exc))
            return
        except (KeyError, ValueError) as exc:
            if body is None:
                # A GET carries no input past routing, so this is a server fault.
                logger.warning("server fault serving %s: %s", self.path, type(exc).__name__)
                self._send_error(500, "internal server error")
                return
            # Structured client error (bad/missing fields). Message is a stable
            # description, never secret material.
            self._send_error(400, f"invalid request: {type(exc).__name__}")
            return
        except Exception:  # pragma: no cover - defensive; fail closed, no leak
            logger.exception("unhandled error serving %s", self.path)
            self._send_error(500, "internal server error")
            return
        self._send_json(200, response)


class _OperatorRequestHandler(_JSONRequestHandler):
    """Admits a POST only after its operator signature verifies.

    The signature covers the raw body bytes, so authentication runs on those
    bytes before any JSON parsing. Every refusal has one shape (HTTP 401).
    """

    def do_POST(self):  # noqa: N802 (stdlib signature)
        handler = self.server.dispatch_post(self.path)
        if handler is None:
            self._send_error(404, "unknown route")
            return
        raw = self._read_raw_body()
        if raw is None:
            return
        principal = self.server.authenticate_operator("POST", self.path, self.headers, raw)
        if principal is None:
            logger.info("operator authentication refused for %s", self.path.split("?", 1)[0])
            self._send_error(401, "operator authentication required")
            return
        body = self._parse_json_body(raw)
        if body is None:
            return
        self._invoke(lambda payload: handler(payload, principal), body)


class _BaseRouterServer:
    """Mixin holding the route tables + threaded start/stop helpers."""

    def __init__(self):
        self._get_routes = {}
        self._post_routes = {}
        self._get_prefix_routes = []  # (prefix, handler) for path params
        self._thread = None

    def add_get(self, path: str, handler):
        self._get_routes[path] = handler

    def add_get_prefix(self, prefix: str, handler):
        self._get_prefix_routes.append((prefix, handler))

    def add_post(self, path: str, handler):
        self._post_routes[path] = handler

    def dispatch_get(self, path: str):
        path = path.split("?", 1)[0]
        if path in self._get_routes:
            return self._get_routes[path]
        for prefix, handler in self._get_prefix_routes:
            if path.startswith(prefix):
                suffix = path[len(prefix):]
                return lambda _suffix=suffix, _handler=handler: _handler(_suffix)
        return None

    def dispatch_post(self, path: str):
        return self._post_routes.get(path.split("?", 1)[0])

    def handle_error(self, request, client_address):
        """Log instead of printing a traceback to stderr.

        Handlers map every exception they raise, so what reaches here is
        socket I/O: a client that closed or reset its connection early.
        """
        error = sys.exc_info()[1]
        if isinstance(error, OSError):
            logger.debug("connection closed early: %s", type(error).__name__)
        else:  # pragma: no cover - defensive
            logger.error("unhandled transport error", exc_info=True)

    # --- lifecycle ----------------------------------------------------------------

    @property
    def base_url(self) -> str:
        host, port = self.server_address[:2]
        if ":" in str(host):  # IPv6 literal
            host = f"[{host}]"
        return f"http://{host}:{port}"

    def start_background(self) -> str:
        """Serve in a daemon thread; returns the base URL. Idempotent-safe to
        call once per server instance."""
        if self._thread is not None:
            raise RuntimeError("server already started")
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


class _BoundedThreadsMixin:
    """Serve at most ``max_concurrent_requests`` connections at once.

    ``ThreadingHTTPServer`` starts one thread per connection without a
    limit. Here a connection beyond the limit gets a fixed 503 from the
    accepting thread and is closed; no handler thread is started for it.
    """

    def _init_slots(self, max_concurrent_requests: int) -> None:
        self._slots = threading.BoundedSemaphore(max_concurrent_requests)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self._refuse_busy(request)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    @staticmethod
    def _refuse_busy(request) -> None:
        try:
            request.settimeout(1.0)
            request.sendall(_BUSY_RESPONSE)
        except OSError:
            pass


def _positive_number(value, name: str):
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a positive finite number")
    return value


def _make_server_class(threaded: bool):
    bases = (_BoundedThreadsMixin, ThreadingHTTPServer) if threaded else (HTTPServer,)

    class _Server(_BaseRouterServer, *bases):
        def __init__(
            self,
            server_address,
            handler_class,
            request_timeout: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
            max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
        ):
            self.request_timeout = _positive_number(request_timeout, "request_timeout")
            if type(max_concurrent_requests) is not int or max_concurrent_requests < 1:
                raise ValueError("max_concurrent_requests must be a positive integer")
            if threaded:
                self._init_slots(max_concurrent_requests)
            bases[-1].__init__(self, server_address, handler_class)
            _BaseRouterServer.__init__(self)

    return _Server


class RevocationServer:
    """HTTP transport in front of a ``RevocationAccumulatorService``.

    Wraps the service's ``handle_request`` (witness-update + epoch-delta) and
    announcement accessors. Bind to ``("127.0.0.1", 0)`` for an ephemeral port;
    read the chosen URL from ``base_url`` after construction.
    """

    def __init__(
        self,
        service,
        host: str = "127.0.0.1",
        port: int = 0,
        threaded: bool = True,
        *,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
    ):
        self._service = service
        server_class = _make_server_class(threaded)
        self._http = server_class(
            (host, port), _JSONRequestHandler, request_timeout, max_concurrent_requests
        )
        self._http.add_post(REVOCATION_UPDATES_PATH, self._handle_updates)
        self._http.add_get(REVOCATION_ANNOUNCEMENT_PATH, self._handle_current_announcement)
        self._http.add_get_prefix(
            REVOCATION_ANNOUNCEMENT_PATH + "/", self._handle_announcement_for_epoch
        )

    # --- handlers ------------------------------------------------------------------

    @staticmethod
    def _service_call(call, *args):
        """Run a service read; a failure that is not an ``AdapterError`` is a 503.

        The service reports every request fault as an ``AdapterError`` (422),
        so any other exception comes from the service's own state.
        """
        try:
            return call(*args)
        except AdapterError:
            raise
        except (KeyError, IndexError, TypeError, ValueError, OverflowError) as exc:
            logger.warning("revocation service fault: %s", type(exc).__name__)
            raise _IssuerStateFault("revocation service is unavailable") from exc

    def _handle_updates(self, body: dict) -> dict:
        # handle_request dispatches witness-update vs epoch-delta by body["type"].
        return self._service_call(self._service.handle_request, body)

    def _handle_current_announcement(self) -> dict:
        # No request input reaches this read, so every failure is a 503.
        try:
            return self._service_call(self._service.current_announcement)
        except AdapterError as exc:
            raise _IssuerStateFault("current announcement is unavailable", exc.code) from exc

    def _handle_announcement_for_epoch(self, suffix: str) -> dict:
        if _EPOCH_SEGMENT.fullmatch(suffix) is None or int(suffix) >= _U64_LIMIT:
            raise _RequestError("epoch path segment must be a canonical u64 decimal")
        return self._service_call(self._service.announcement_for_epoch, int(suffix))

    # --- lifecycle -----------------------------------------------------------------

    @property
    def base_url(self) -> str:
        return self._http.base_url

    def start_background(self) -> str:
        return self._http.start_background()

    def serve_forever(self):
        self._http.serve_forever()

    def stop(self) -> None:
        self._http.stop()

    def __enter__(self):
        self.start_background()
        return self

    def __exit__(self, *exc):
        self.stop()
        return False


class IssuerServer:
    """Holder-facing HTTP transport in front of a ``zkc_issuer.IssuerAdapter``.

    Maps the four adapter stages and the metadata document onto HTTP routes.
    Each stage already takes/returns JSON-able dicts, rejects privacy-boundary
    material and authorizes through the adapter's trusted session callback,
    so this server adds no policy: it only moves bytes. It routes no operator
    mutation; revocation and renewal live on ``IssuerAdminServer``.
    """

    def __init__(
        self,
        adapter,
        host: str = "127.0.0.1",
        port: int = 0,
        threaded: bool = True,
        *,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
    ):
        self._adapter = adapter
        server_class = _make_server_class(threaded)
        self._http = server_class(
            (host, port), _JSONRequestHandler, request_timeout, max_concurrent_requests
        )
        handlers = (
            adapter.verify_subject,
            adapter.request_binding_challenge,
            adapter.bind_holder_commitment,
            adapter.issue_credential,
            adapter.publish_revocation_handle,
        )
        for path, handler in zip(ISSUER_HOLDER_POST_PATHS, handlers):
            self._http.add_post(path, handler)
        self._http.add_get(ISSUER_WELL_KNOWN_PATH, self._handle_metadata)

    def _handle_metadata(self) -> dict:
        # No client input reaches metadata generation, so no failure is a 4xx.
        try:
            return self._adapter.issuer_metadata()
        except AdapterError as exc:
            raise _IssuerStateFault("issuer metadata is unavailable", exc.code) from exc
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("issuer metadata unavailable: %s", type(exc).__name__)
            raise _IssuerStateFault("issuer metadata is unavailable") from exc

    # --- lifecycle -----------------------------------------------------------------

    @property
    def base_url(self) -> str:
        return self._http.base_url

    def start_background(self) -> str:
        return self._http.start_background()

    def serve_forever(self):
        self._http.serve_forever()

    def stop(self) -> None:
        self._http.stop()

    def __enter__(self):
        self.start_background()
        return self

    def __exit__(self, *exc):
        self.stop()
        return False


class IssuerAdminServer:
    """Operator-only HTTP listener for issuer mutations (revoke, renew).

    Runs on its own socket, never on the holder-facing ``IssuerServer``
    listener, so a gateway that admits holders to the stage routes admits
    nobody here. Every request must carry a signature by one of the pinned
    ``operator_keys`` (key id -> ``0x`` + x||y secp256k1 public key hex),
    bound to this issuer, the method, the exact request target, a timestamp
    within ``max_clock_skew_seconds`` and a single-use nonce (see
    ``zkc_transport.operator_auth``). The accepted key id is the operator
    principal; handlers receive it.

    Bind the listener to an operator-only interface; the signature is the
    authorization, not transport secrecy (this reference server has no TLS).
    """

    def __init__(
        self,
        adapter,
        operator_keys,
        host: str = "127.0.0.1",
        port: int = 0,
        threaded: bool = True,
        clock=time.time,
        max_clock_skew_seconds: int = 60,
        *,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS,
    ):
        self._adapter = adapter
        # Validates the pinned keys before any socket is opened.
        self._authenticator = OperatorAuthenticator(
            adapter.issuer_id,
            operator_keys,
            clock=clock,
            max_clock_skew_seconds=max_clock_skew_seconds,
        )
        server_class = _make_server_class(threaded)
        self._http = server_class(
            (host, port), _OperatorRequestHandler, request_timeout, max_concurrent_requests
        )
        self._http.authenticate_operator = self._authenticator.authenticate
        self._http.add_post(ADMIN_REVOKE_PATH, self._handle_revoke)
        if callable(getattr(adapter, "renew_credential", None)):
            self._http.add_post(ADMIN_RENEW_PATH, self._handle_renew)

    def _handle_revoke(self, body: dict, principal: str) -> dict:
        if set(body) != {"credentialId"}:
            raise ValueError("revoke requests name only credentialId")
        credential_id = canonical_hex_to_field(body["credentialId"])
        logger.info("operator %s revokes a credential", principal)
        result = self._adapter.revoke_credential(credential_id)
        # Echo the canonical credential id so the client can confirm.
        result.setdefault("credentialId", field_to_hex(credential_id))
        return result

    def _handle_renew(self, body: dict, principal: str) -> dict:
        logger.info("operator %s renews a credential", principal)
        return self._adapter.renew_credential(body)

    # --- lifecycle -----------------------------------------------------------------

    @property
    def base_url(self) -> str:
        return self._http.base_url

    def start_background(self) -> str:
        return self._http.start_background()

    def serve_forever(self):
        self._http.serve_forever()

    def stop(self) -> None:
        self._http.stop()

    def __enter__(self):
        self.start_background()
        return self

    def __exit__(self, *exc):
        self.stop()
        return False

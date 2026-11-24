"""Reviewed request commitments and durable holder-side delegation budgets."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
import sqlite3
import stat

from zkc_crypto import FIELD_MODULUS, ProofContext
from zkc_crypto.delegation import DelegationError, ViewingScope, validate_scope_identifiers

from .credential import ProofRequest, TrustedIssuer, TrustPolicy


def _json_copy(value, depth=0):
    if depth > 32:
        raise DelegationError("delegation request nesting is excessive")
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is list:
        return [_json_copy(item, depth + 1) for item in value]
    if type(value) is dict and all(type(key) is str for key in value):
        return {key: _json_copy(item, depth + 1) for key, item in value.items()}
    raise DelegationError("delegation request must contain only JSON values")


def _snapshot_requests(requests):
    """Detach every mutable field before hashing or using reviewed requests."""
    if type(requests) not in (list, tuple) or not requests:
        raise DelegationError("delegation requires a nonempty request sequence")
    # New request fields must explicitly join the snapshot contract, rather
    # than retaining a new mutable alias after their digest was checked.
    if {field.name for field in dataclasses.fields(ProofRequest)} != {
        "proof_types", "parameters", "context", "trust_policy", "max_proof_age",
        "current_epochs", "binding_selectors", "presentation_profile",
        "allow_protocol_scope", "allow_unlinked_composite", "rebind_secret",
    }:
        raise DelegationError("unsupported delegation request fields")
    snapshots = []
    for request in requests:
        if type(request) is ProofRequest and request.rebind_secret is not None:
            raise DelegationError("holder-local rebind secrets cannot be delegated")
        if (
            type(request) is not ProofRequest
            or type(request.context) is not ProofContext
            or type(request.trust_policy) is not TrustPolicy
            or type(request.trust_policy.issuers) is not tuple
            or type(request.proof_types) is not list
            or not request.proof_types
            or any(type(item) is not str or not item for item in request.proof_types)
            or len(set(request.proof_types)) != len(request.proof_types)
            or type(request.parameters) is not dict
            or type(request.current_epochs) is not dict
            or type(request.binding_selectors) is not dict
            or type(request.presentation_profile) is not str
            or type(request.max_proof_age) is not int
            or request.max_proof_age < 0
            or type(request.allow_protocol_scope) is not bool
            or type(request.allow_unlinked_composite) is not bool
        ):
            raise DelegationError("invalid delegation request representation")
        issuers = []
        for issuer in request.trust_policy.issuers:
            if (
                type(issuer) is not TrustedIssuer
                or type(issuer.issuer_id) is not str
                or type(issuer.proof_types) is not tuple
                or any(type(item) is not str for item in issuer.proof_types)
                or any(type(key) is not bytes or len(key) != 32
                       for key in (issuer.public_key_x, issuer.public_key_y))
            ):
                raise DelegationError("invalid delegation issuer trust")
            issuers.append(dataclasses.replace(issuer))
        context = dataclasses.replace(request.context)
        if any(type(value) not in (int, str) for value in dataclasses.asdict(context).values()):
            raise DelegationError("invalid delegation context")
        snapshots.append(dataclasses.replace(
            request,
            proof_types=list(request.proof_types),
            parameters=_json_copy(request.parameters),
            current_epochs=_json_copy(request.current_epochs),
            binding_selectors=_json_copy(request.binding_selectors),
            context=context,
            trust_policy=TrustPolicy(issuers=tuple(issuers)),
        ))
    return snapshots


def _snapshot_consents(consents, requests):
    if consents is None:
        return {}
    proof_types = {proof_type for request in requests for proof_type in request.proof_types}
    if (
        type(consents) is not dict
        or any(type(key) is not str or key not in proof_types or type(value) is not bool
               for key, value in consents.items())
    ):
        raise DelegationError("invalid reviewed delegation consents")
    return dict(consents)


def delegation_request_digest(requests, *, consents=None) -> bytes:
    """Commit to every field of the exact reviewed request batch.

    Request order is significant. Issuer keys are encoded only after checking
    their exact byte representation; parameter values cannot contain bytes.
    """
    snapshots = _snapshot_requests(requests)
    reviewed_consents = _snapshot_consents(consents, snapshots)
    try:
        documents = [dataclasses.asdict(request) for request in snapshots]
        for document in documents:
            # An absent local secret must not change existing signed digests.
            document.pop("rebind_secret")
            for issuer in document["trust_policy"]["issuers"]:
                for key in ("public_key_x", "public_key_y"):
                    issuer[key] = issuer[key].hex()
        encoded = json.dumps(
            {"requests": documents, "consents": reviewed_consents},
            sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise DelegationError("invalid delegation request encoding") from exc
    return hashlib.sha256(b"zkc/delegation-reviewed-requests:v1\0" + encoded).digest()


def _scoped_requests(requests, scope):
    if (
        type(scope) is not ViewingScope
        or type(scope.verifier_id) is not str or not scope.verifier_id
        or type(scope.context_value) is not int or not 0 < scope.context_value < FIELD_MODULUS
        or type(scope.proof_types) is not tuple or not scope.proof_types
        or any(type(item) is not str for item in scope.proof_types)
    ):
        raise DelegationError("invalid delegation scope")
    validate_scope_identifiers(scope)
    snapshots = _snapshot_requests(requests)
    for request in snapshots:
        try:
            context_matches = (
                request.context.value == scope.context_value
                and request.context.verifier_id == scope.verifier_id
                and request.context.reconstructs()
            )
        except (TypeError, ValueError, OverflowError):
            context_matches = False
        if not context_matches:
            raise DelegationError("request context or verifier is outside the delegated scope")
        if any(proof_type not in scope.proof_types for proof_type in request.proof_types):
            raise DelegationError("request proof type is outside the delegated scope")
    return snapshots


class SQLiteDelegationUseStore:
    """Atomic durable budgets; put the database in a private holder-owned dir.

    Only token hashes and counts are persisted. All holder processes must use
    the same protected database; deleting, restoring or replacing it resets
    replay protection. Reservations are committed before proving and never
    refunded, including after tool failure or a lost response.
    """

    def __init__(self, path):
        if str(path) == ":memory:" or str(path).startswith("file:"):
            raise DelegationError("delegation usage requires durable storage")
        self._path = pathlib.Path(path).absolute()
        try:
            parent = self._path.parent.stat()
            if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
                raise DelegationError("delegation usage directory must be private")
            try:
                fd = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                fd = os.open(self._path, os.O_RDWR | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
                    raise DelegationError("delegation usage file must be private and regular")
            finally:
                os.close(fd)
            connection = self._connect()
            try:
                with connection:
                    connection.execute(
                        "CREATE TABLE IF NOT EXISTS delegation_uses ("
                        "token_id BLOB PRIMARY KEY, token_digest BLOB NOT NULL, "
                        "uses INTEGER NOT NULL CHECK(uses >= 0))"
                    )
                    connection.execute(
                        "CREATE TABLE IF NOT EXISTS delegation_authorizations ("
                        "token_id BLOB NOT NULL, authorization_nonce BLOB NOT NULL, "
                        "PRIMARY KEY(token_id, authorization_nonce))"
                    )
            finally:
                connection.close()
        except (OSError, sqlite3.Error) as exc:
            raise DelegationError("could not initialize durable delegation usage") from exc

    def _connect(self):
        # A lost database must fail closed rather than silently reset budgets.
        connection = sqlite3.connect(self._path.as_uri() + "?mode=rw", uri=True, timeout=30)
        try:
            connection.execute("PRAGMA synchronous=FULL")
        except sqlite3.Error:
            connection.close()
            raise
        return connection

    def reserve(
        self, token_id: bytes, token_digest: bytes, count: int, max_uses: int,
        authorization_nonce: bytes,
    ) -> None:
        """Consume a request batch once, across concurrent clients/processes."""
        connection = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT token_digest, uses FROM delegation_uses WHERE token_id = ?", (token_id,)
            ).fetchone()
            uses = 0 if row is None else row[1]
            if type(uses) is not int or uses < 0:
                raise DelegationError("invalid durable delegation usage state")
            if row is not None and row[0] != token_digest:
                raise DelegationError("delegation nonce was already bound to another token")
            if count < 1 or uses + count > max_uses:
                raise DelegationError("delegation token use budget exhausted")
            previous = connection.execute(
                "SELECT 1 FROM delegation_authorizations "
                "WHERE token_id = ? AND authorization_nonce = ?",
                (token_id, authorization_nonce),
            ).fetchone()
            if previous is not None:
                raise DelegationError("delegation principal authorization was already used")
            connection.execute(
                "INSERT INTO delegation_uses(token_id, token_digest, uses) VALUES (?, ?, ?) "
                "ON CONFLICT(token_id) DO UPDATE SET uses = excluded.uses",
                (token_id, token_digest, uses + count),
            )
            connection.execute(
                "INSERT INTO delegation_authorizations(token_id, authorization_nonce) VALUES (?, ?)",
                (token_id, authorization_nonce),
            )
            connection.commit()
        except sqlite3.Error as exc:
            raise DelegationError("could not reserve durable delegation usage") from exc
        finally:
            if connection is not None:
                connection.close()

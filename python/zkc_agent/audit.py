"""Audit-safe event logging for agent compliance decisions.

Every disclosure decision (auto-response, queue, block, approval, denial,
counterparty verification) is recorded as a structured JSONL event. The log
is REDACTING BY CONSTRUCTION: secret material is stripped recursively before
an event is serialized, so no code path can log a credential payload, seed,
witness, signature, or proof body even by accident.
"""

from __future__ import annotations

import json
import pathlib
import time

from zkc_holder.rebind_secret import is_secret_key

__all__ = ["REDACTED", "FORBIDDEN_LOG_KEYS", "redact", "AuditLog"]

REDACTED = "[REDACTED]"

# Keys whose values are secret/private material and must never reach a log.
# Matching is case-insensitive on the lowercased key.
FORBIDDEN_LOG_KEYS = frozenset(
    {
        "proof",
        "proofs",
        "publicinputs",
        "claims",
        "signature",
        "witness",
        "seed",
        "masterseed",
        "master_seed",
        "bindingkey",
        "binding_key",
        "credential",
        "credentials",
        "privatekey",
        "private_key",
        "envelope",
        "passphrase",
        "secret",
        "token",
    }
)


def _is_forbidden(key) -> bool:
    """Exact forbidden names, plus any spelling of holder secret material
    (``newMasterSeed``, ``old_credential_binding_key``, ...)."""
    return str(key).lower() in FORBIDDEN_LOG_KEYS or is_secret_key(key)


def redact(node):
    """Recursively strip forbidden keys from a JSON-shaped structure."""
    if isinstance(node, dict):
        return {
            key: REDACTED if _is_forbidden(key) else redact(value)
            for key, value in node.items()
        }
    if isinstance(node, (list, tuple)):
        return [redact(item) for item in node]
    return node


class AuditLog:
    """Structured JSONL audit log with mandatory redaction.

    With a `path`, events are appended as one JSON object per line; without
    one, events accumulate in memory (`.events`). Either way every event
    passes through :func:`redact` first.
    """

    def __init__(self, path=None, clock=time.time):
        self._path = pathlib.Path(path) if path is not None else None
        self._clock = clock
        self.events = []

    def record(self, event: str, **fields) -> dict:
        entry = {"ts": int(self._clock()), "event": event}
        entry.update(redact(fields))
        # Defense in depth: refuse to write an entry that somehow still
        # contains an un-redacted forbidden key at any depth.
        self._assert_redacted(entry)
        self.events.append(entry)
        if self._path is not None:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    @staticmethod
    def _assert_redacted(node) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if _is_forbidden(key) and value != REDACTED:
                    raise ValueError(f"audit event leaked forbidden key {key!r}")
                AuditLog._assert_redacted(value)
        elif isinstance(node, (list, tuple)):
            for item in node:
                AuditLog._assert_redacted(item)

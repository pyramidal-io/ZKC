"""Holder-local custody of a credential rebind's NEW secret (spec section 7.4.4).

An authenticated rebind proves continuity from the holder's current binding
key to a NEW one. That new key (or the master seed it derives from) is the
holder's next root secret: whoever learns it computes the holder's pseudonyms
at every verifier, signs receipts as the holder, and uses re-issued
credentials. It therefore travels only through :class:`RebindSecret`, a
holder-local value the SDK never serializes, logs, or places in a request.

A request is verifier-controlled and, on the authenticated path, MUST equal
the verifier-signed APR, so a secret carried in request parameters would sit
inside a document the verifier signs, receives, and keeps -- and a malicious
verifier could choose it. The SDK refuses any request, APR, negotiation
request, or verifier policy that names a secret parameter before proving
(:class:`SecretInRequestError`, code ``SECRET_IN_REQUEST``).
"""

from __future__ import annotations

from zkc_crypto import FIELD_MODULUS, derive_credential_binding_key

from .errors import SecretInRequestError

__all__ = [
    "REBIND_SECRET_PARAMETER_KEYS",
    "RebindSecret",
    "is_secret_key",
    "refuse_secret_parameters",
]

# The request-parameter spellings earlier SDK versions read the new secret
# from. They are named here only so they can be refused.
REBIND_SECRET_PARAMETER_KEYS = ("newMasterSeed", "newCredentialBindingKey")

# A key whose normalized spelling (lowercase; "_", "-", ".", whitespace
# removed) contains one of these names holder secret material, whatever its
# casing, separators, or old/new prefix: newSeed, seed_phrase, holderSecret,
# privKey, NEW_CREDENTIAL_BINDING_KEY, "new master seed", ...
_SECRET_KEY_MARKERS = (
    "seed",
    "secret",
    "mnemonic",
    "passphrase",
    "bindingkey",
    "privatekey",
    "privkey",
)

REDACTED = "[REDACTED]"


def _normalize(key) -> str:
    return "".join(
        character
        for character in str(key).lower()
        if character not in "_-." and not character.isspace()
    )


def is_secret_key(key) -> bool:
    """True when ``key`` names holder secret material (case/separator-blind).

    Key names only: a scan cannot recognise a secret hidden under a neutral
    key name (``{"name": "seed", "value": ...}``). It is defense in depth;
    the SDK itself never reads a secret from a request."""
    normalized = _normalize(key)
    return any(marker in normalized for marker in _SECRET_KEY_MARKERS)


def refuse_secret_parameters(node, where: str) -> None:
    """Refuse secret-named fields, including nested request extensions.

    Diagnostics are value-free and omit attacker-controlled key paths too.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if is_secret_key(key):
                raise SecretInRequestError(
                    f"{where} names holder secret material; use the holder-local RebindSecret channel"
                )
            refuse_secret_parameters(value, where)
    elif isinstance(node, (list, tuple)):
        for item in node:
            refuse_secret_parameters(item, where)


def redact_secret_parameters(node):
    """A copy of ``node`` with every secret-named value replaced (for repr)."""
    if isinstance(node, dict):
        return {
            key: REDACTED if is_secret_key(key) else redact_secret_parameters(value)
            for key, value in node.items()
        }
    if isinstance(node, (list, tuple)):
        return type(node)(redact_secret_parameters(item) for item in node)
    return node


class RebindSecret:
    """The holder-chosen NEW identity of an authenticated credential rebind.

    Construct it locally from a fresh master seed (preferred) or an explicit
    credential binding key and pass it as ``ProofRequest.rebind_secret``. It
    is never part of a request's ``parameters``, never serialized, and its
    ``repr``/``str`` reveal nothing."""

    __slots__ = ("_binding_key",)

    def __init__(self, credential_binding_key: int):
        if (
            isinstance(credential_binding_key, bool)
            or not isinstance(credential_binding_key, int)
            or not 0 < credential_binding_key < FIELD_MODULUS
        ):
            # Deliberately value-free: the argument is the secret.
            raise ValueError("rebind secret must be a non-zero canonical field element")
        object.__setattr__(self, "_binding_key", credential_binding_key)

    @classmethod
    def from_master_seed(cls, master_seed) -> "RebindSecret":
        """Derive the new binding key from a fresh holder master seed (KDC A.6)."""
        try:
            key = derive_credential_binding_key(master_seed)
        except (TypeError, ValueError):
            raise ValueError("rebind master seed is malformed") from None
        return cls(key)

    @property
    def credential_binding_key(self) -> int:
        return self._binding_key

    def __setattr__(self, name, value):
        raise AttributeError("RebindSecret is immutable")

    def __repr__(self) -> str:
        return f"RebindSecret({REDACTED})"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("RebindSecret is holder-local and cannot be serialized")

    # Immutable: an in-process copy is the same value (and never a pickle).
    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self

    def __eq__(self, other):
        return NotImplemented

    __hash__ = None

"""Structured issuer adapter errors and the ZKC privacy boundary.

Error codes are the closed set from docs/zkc_issuer_adapter_protocol_v1.md.
Error messages MUST NOT include provider secrets, raw identity documents, or
wallet identifiers; `reject_forbidden` reports offending *key names* only,
never values.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping

__all__ = [
    "ADAPTER_ERROR_CODES",
    "FORBIDDEN_FIELDS",
    "HUMAN_PRIVACY_PROFILE",
    "MACHINE_PRIVACY_PROFILE",
    "KNOWN_PRIVACY_PROFILES",
    "MACHINE_SUBJECT_FORBIDDEN_FIELDS",
    "MACHINE_SUBJECT_FORBIDDEN_SUFFIXES",
    "AdapterError",
    "reject_forbidden",
]

# Closed enumeration — mirrors the "Error Semantics" section of the adapter
# protocol doc and schemas/issuer-adapter.schema.json.
ADAPTER_ERROR_CODES = (
    "UNSUPPORTED_SCHEMA",
    "INVALID_HOLDER_CHALLENGE",
    "UNTRUSTED_ISSUER_KEY",
    "EXPIRED_ISSUER_KEY",
    "REVOCATION_METADATA_UNAVAILABLE",
    "STALE_ACCUMULATOR_WITNESS",
    "PROVIDER_VERIFICATION_FAILED",
    "RATE_LIMITED",
)

# Privacy boundary (adapter protocol doc): material a conforming issuer
# adapter MUST NOT receive. Scanned recursively over every stage payload.
FORBIDDEN_FIELDS = frozenset(
    {
        "masterSeed",
        "spendingKey",
        "proofKey",
        "credentialBindingKey",
        "zkaAddress",
        "notePlaintext",
        "nullifier",
        "nullifiers",
        "noteCommitment",
        "noteCommitments",
        "paymentHistory",
        "transactionGraph",
        "walletTransactions",
    }
)

HUMAN_PRIVACY_PROFILE = "human"
MACHINE_PRIVACY_PROFILE = "machine"
KNOWN_PRIVACY_PROFILES = frozenset({HUMAN_PRIVACY_PROFILE, MACHINE_PRIVACY_PROFILE})

# Machine-subject material that must remain inside the provider boundary.
# Values are intentionally not inspected: these are semantic field names only.
MACHINE_SUBJECT_FORBIDDEN_FIELDS = frozenset(
    {
        "rawevidence", "rawprovenance", "provenancestatement",
        "transparencyinclusionproof", "inclusionpath", "logentry", "leafbytes",
        "teequote", "teereport", "rawquote", "attestationreport",
        "rawattestationreport", "rawteereport", "certificatechain",
        "endorsementchain", "endorsementartifact", "collateral",
        "runtimemeasurement", "reportdata", "hostserial", "hostserialnumber",
        "platformserial", "systemserial", "chipid", "chipidentifier", "hostuuid",
        "hardwareuuid", "hostid", "hardwareid", "machineid", "cloudinstanceid",
        "hostinstanceid", "vmid", "buildpath", "sourcepath", "workspacepath",
        "checkoutpath", "builddirectory", "sourcedirectory", "workingdirectory",
        "environmentvariables", "envvars", "buildparameters", "buildinvocationid",
    }
)
MACHINE_SUBJECT_FORBIDDEN_SUFFIXES = frozenset(
    {
        ("build", "path"),
        ("source", "path"),
        ("workspace", "path"),
        ("checkout", "path"),
        ("provenance", "build", "path"),
        ("build", "components", "path"),
        ("host", "serial"),
        ("host", "serialnumber"),
        ("platform", "serial"),
        ("chip", "id"),
        ("build", "builderidentity"),
    }
)
_MACHINE_PRIVACY_ERROR = "request includes forbidden privacy-boundary material"
_MAX_MACHINE_CONTAINER_DEPTH = 32
_MAX_MACHINE_VALUE_NODES = 4096
_MAX_MACHINE_KEY_UTF8_BYTES = 4096


def _normalized_name(name: str) -> str:
    return name.lower().replace("_", "").replace("-", "")


# Every forbidden name in its normalized form. A key path matches when the
# concatenation of any trailing run of its normalized segments equals one of
# these names, whether the segments came from literal dots in one key or from
# nested objects. Suffix rules therefore also match their concatenated forms.
_HUMAN_FORBIDDEN_NAMES = frozenset(_normalized_name(name) for name in FORBIDDEN_FIELDS)
_MACHINE_FORBIDDEN_NAMES = frozenset(MACHINE_SUBJECT_FORBIDDEN_FIELDS) | frozenset(
    "".join(suffix) for suffix in MACHINE_SUBJECT_FORBIDDEN_SUFFIXES
)
# Each retained segment is non-empty, so no forbidden name spans more trailing
# segments than it has characters.
_MAX_FORBIDDEN_NAME_LENGTH = max(
    len(name) for name in _HUMAN_FORBIDDEN_NAMES | _MACHINE_FORBIDDEN_NAMES
)


def _path_matches(path: tuple[str, ...], names: frozenset[str]) -> bool:
    """True when a trailing run of normalized segments spells a forbidden name."""
    joined = ""
    for segment in reversed(path):
        joined = segment + joined
        if len(joined) > _MAX_FORBIDDEN_NAME_LENGTH:
            return False
        if joined in names:
            return True
    return False


class AdapterError(ValueError):
    """A structured issuer adapter failure with a stable error code."""

    def __init__(self, code: str, message: str):
        if code not in ADAPTER_ERROR_CODES:
            raise ValueError(f"unknown adapter error code: {code}")
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message}


def _normalized_human_key_segments(key) -> tuple[str, ...]:
    # Human keys are not restricted to ASCII, so fold compatibility forms and
    # case before removing the separators the machine profile also ignores.
    text = unicodedata.normalize("NFKC", key if type(key) is str else str(key)).casefold()
    segments = []
    for segment in text.split("."):
        normalized = "".join(
            character for character in segment
            if character not in "_-" and not character.isspace()
        )
        if normalized:
            segments.append(normalized)
    return tuple(segments)


def _scan(value, path: str, segments: tuple[str, ...], hits: list) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            child_segments = (segments + _normalized_human_key_segments(key))[
                -_MAX_FORBIDDEN_NAME_LENGTH:
            ]
            if _path_matches(child_segments, _HUMAN_FORBIDDEN_NAMES):
                hits.append(child_path)
            _scan(child, child_path, child_segments, hits)
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _scan(child, f"{path}[{index}]", segments, hits)


def _reject_machine_subject_material() -> None:
    raise AdapterError("INVALID_HOLDER_CHALLENGE", _MACHINE_PRIVACY_ERROR) from None


def _normalized_machine_key_segments(key) -> tuple[str, ...]:
    if type(key) is not str or not key:
        _reject_machine_subject_material()
    # Machine keys must be ASCII, so their character and UTF-8 byte lengths
    # are identical. Bound the exact string before any encoding allocation.
    if len(key) > _MAX_MACHINE_KEY_UTF8_BYTES or not key.isascii():
        _reject_machine_subject_material()
    normalized = []
    for segment in key.split("."):
        if not segment or not segment[0].isalnum() or not segment[0].isascii():
            _reject_machine_subject_material()
        if any(
            not (character.isascii() and (character.isalnum() or character in "_-"))
            for character in segment[1:]
        ):
            _reject_machine_subject_material()
        normalized.append(_normalized_name(segment))
    return tuple(normalized)


def _scan_machine_subject(value, enforce_human_fields: bool) -> None:
    """Walk exact builtin containers without examining any scalar value."""
    worklist = [(value, (), 0)]
    seen_containers: set[int] = set()
    scheduled_nodes = 1
    forbidden_names = _MACHINE_FORBIDDEN_NAMES
    if enforce_human_fields:
        forbidden_names = forbidden_names | _HUMAN_FORBIDDEN_NAMES

    while worklist:
        current, path, container_depth = worklist.pop()

        current_type = type(current)
        if current_type is dict:
            if id(current) in seen_containers:
                _reject_machine_subject_material()
            seen_containers.add(id(current))
            depth = container_depth + 1
            if depth > _MAX_MACHINE_CONTAINER_DEPTH:
                _reject_machine_subject_material()
            for key, child in current.items():
                segments = _normalized_machine_key_segments(key)
                child_path = (path + segments)[-_MAX_FORBIDDEN_NAME_LENGTH:]
                if _path_matches(child_path, forbidden_names):
                    _reject_machine_subject_material()
                scheduled_nodes += 1
                if scheduled_nodes > _MAX_MACHINE_VALUE_NODES:
                    _reject_machine_subject_material()
                worklist.append((child, child_path, depth))
        elif current_type is list or current_type is tuple:
            if id(current) in seen_containers:
                _reject_machine_subject_material()
            seen_containers.add(id(current))
            depth = container_depth + 1
            if depth > _MAX_MACHINE_CONTAINER_DEPTH:
                _reject_machine_subject_material()
            for child in current:
                scheduled_nodes += 1
                if scheduled_nodes > _MAX_MACHINE_VALUE_NODES:
                    _reject_machine_subject_material()
                worklist.append((child, path, depth))
        elif isinstance(current, Mapping) or isinstance(current, (list, tuple)):
            _reject_machine_subject_material()


def reject_forbidden(payload, profiles=frozenset({"human"})) -> None:
    """Reject forbidden holder or machine-boundary material (fail closed).

    Human-profile errors name offending keys but never values. Machine-profile
    errors use one fixed, detail-free public message.
    """
    scanner_failed = False
    try:
        active_profiles = frozenset(profiles)
        if not active_profiles.issubset(KNOWN_PRIVACY_PROFILES):
            _reject_machine_subject_material()
        if MACHINE_PRIVACY_PROFILE in active_profiles:
            _scan_machine_subject(
                payload,
                enforce_human_fields=HUMAN_PRIVACY_PROFILE in active_profiles,
            )
        elif active_profiles == frozenset({HUMAN_PRIVACY_PROFILE}):
            hits: list = []
            _scan(payload, "", (), hits)
            if hits:
                raise AdapterError(
                    "INVALID_HOLDER_CHALLENGE",
                    "request includes forbidden holder material: " + ", ".join(sorted(hits)),
                )
    except AdapterError:
        raise
    except Exception:
        # Leave the exception handler before building the public error so its
        # context cannot retain an implementation detail or caller value.
        scanner_failed = True
    if scanner_failed:
        _reject_machine_subject_material()

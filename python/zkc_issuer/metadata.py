"""Issuer metadata (/.well-known/zkc-issuer.json) generation.

Builds the non-exclusive registry document defined by
``schemas/issuer-metadata.schema.json``. Verifiers decide which issuers,
schemas, keys, and accumulator states they trust — publishing metadata grants
no authority (Freedom Safeguard 1).
"""

from __future__ import annotations

import json
import pathlib
import re

from zkc_crypto import parse_attribute_layout_id
from zkc_crypto.code_spaces import CODE_SPACE_CREDENTIAL_TO_KIND, get_code_space

from .schemas import ATTRIBUTE_SET_V1_SCHEMA_ID

__all__ = [
    "METADATA_VERSION",
    "AUTHENTICATED_METADATA_VERSION",
    "WELL_KNOWN_PATH",
    "DEFAULT_SERVICE_LEVELS",
    "build_issuer_metadata",
    "write_well_known",
]

METADATA_VERSION = "zkc:issuer-metadata:v1"
AUTHENTICATED_METADATA_VERSION = "zkc:issuer-metadata:v2"
WELL_KNOWN_PATH = ".well-known/zkc-issuer.json"

_ISSUER_ID_PATTERN = re.compile(r"^zkc:issuer:[a-z0-9._-]+$")

DEFAULT_SERVICE_LEVELS = {
    "maxRevocationPropagationSeconds": 3600,
    "expectedIssuanceLatencySeconds": 30,
    "metadataCacheSeconds": 300,
}

_ADAPTER_STAGES = (
    ("verifySubjectEndpoint", "verify_subject"),
    ("bindHolderCommitmentEndpoint", "bind_holder_commitment"),
    ("issueCredentialEndpoint", "issue_credential"),
    ("publishRevocationHandleEndpoint", "publish_revocation_handle"),
)


def _check_published_liveness(liveness, announcement: dict, public_keys: list) -> None:
    """Refuse a ``currentLiveness`` the document could not authenticate.

    The statement must name the published announcement by its complete
    hash and be signed by a published ECDSA key valid at ``issuedAt``. As
    for the announcement, the published key is discovery data only;
    consumers authenticate it against their own pins.
    """
    from zkc_revocation.service import announcement_hash, verify_epoch_liveness

    if type(liveness) is not dict:
        raise ValueError("revocation liveness must be an object")
    if (
        type(liveness.get("accumulatorId")) is not str
        or liveness.get("accumulatorId") != announcement.get("accumulatorId")
        # Type-strict: Python equates True with 1.
        or type(liveness.get("epoch")) is not int
        or liveness.get("epoch") != announcement.get("epoch")
        or liveness.get("headHash") != announcement_hash(announcement)
    ):
        raise ValueError("revocation liveness does not name the current announcement")
    liveness_key = next(
        (key for key in public_keys if key.key_id == liveness.get("signingKeyId")),
        None,
    )
    if liveness_key is None:
        raise ValueError("revocation liveness signing key is not published")
    if liveness_key.scheme != "ECDSA_SECP256K1":
        raise ValueError("revocation liveness key uses an unsupported scheme")
    issued_at = liveness.get("issuedAt")
    if type(issued_at) is not int or not liveness_key.is_valid_at(issued_at):
        raise ValueError("revocation liveness signing key is not valid at issuedAt")
    key_x, key_y = liveness_key.public_key_coordinates()
    if not verify_epoch_liveness(
        liveness, key_x, key_y, expected_signing_key_id=liveness_key.key_id
    ):
        raise ValueError("revocation liveness signature is invalid")


def build_issuer_metadata(
    issuer_id: str,
    display_name: str,
    signing_keys,
    schemas,
    accumulator,
    base_url: str,
    service_levels: dict = None,
    schema_code_space_ids=None,
) -> dict:
    """Assemble schema-conforming issuer metadata (public material only)."""
    if not _ISSUER_ID_PATTERN.fullmatch(issuer_id):
        raise ValueError(f"issuerId does not match the required pattern: {issuer_id}")
    if not display_name:
        raise ValueError("displayName must be non-empty")
    if not base_url.startswith("https://"):
        raise ValueError("adapter endpoints must be https")
    public_keys = list(signing_keys or ())
    public_schemas = list(schemas or ())
    if not public_keys:
        raise ValueError("at least one signing key is required")
    if not public_schemas:
        raise ValueError("at least one supported schema is required")
    key_entries = [key.metadata_entry() for key in public_keys]
    schema_entries = [schema.metadata_entry() for schema in public_schemas]
    declared_spaces = schema_code_space_ids or {}
    bound_schemas = {
        entry["schemaId"] for entry in schema_entries
        if entry["schemaId"] in CODE_SPACE_CREDENTIAL_TO_KIND
    }
    if set(declared_spaces) != bound_schemas:
        raise ValueError("code-space declarations must cover exactly the supported code-space schemas")
    if sum(entry["schemaId"] in bound_schemas for entry in schema_entries) != len(bound_schemas):
        raise ValueError("duplicate code-space schema declaration")
    for entry in schema_entries:
        schema_id = entry["schemaId"]
        if schema_id not in bound_schemas:
            continue
        ids = declared_spaces[schema_id]
        if not isinstance(ids, (list, tuple, frozenset)) or not ids:
            raise ValueError("codeSpaceIds must be a nonempty closed list without duplicates")
        for code_space_id in ids:
            get_code_space(code_space_id, CODE_SPACE_CREDENTIAL_TO_KIND[schema_id])
        if len(set(ids)) != len(ids):
            raise ValueError("codeSpaceIds must be a nonempty closed list without duplicates")
        entry["codeSpaceIds"] = sorted(ids)
    key_layouts = {}
    for entry in key_entries:
        if "attributeLayoutId" not in entry:
            continue
        layout_id = entry["attributeLayoutId"]
        parse_attribute_layout_id(layout_id)
        identity = (entry["scheme"], entry["publicKey"])
        if key_layouts.setdefault(identity, layout_id) != layout_id:
            raise ValueError("a legacy attribute-set signing key cannot bind multiple layouts")
    if not key_layouts and any(
        entry["schemaId"] == ATTRIBUTE_SET_V1_SCHEMA_ID for entry in schema_entries
    ):
        raise ValueError("legacy attribute-set support requires a signing key with an attribute layout")
    revocation = accumulator.metadata()
    authenticated = "currentAnnouncement" in revocation
    if authenticated:
        announcement = revocation["currentAnnouncement"]
        announcement_key = next(
            (
                key
                for key in public_keys
                if key.key_id == announcement.get("signingKeyId")
            ),
            None,
        )
        if announcement_key is None:
            raise ValueError("revocation announcement signing key is not published")
        if announcement_key.scheme != "ECDSA_SECP256K1":
            raise ValueError("revocation announcement key uses an unsupported scheme")
        announced_at = announcement.get("announcedAt")
        if type(announced_at) is not int or not announcement_key.is_valid_at(announced_at):
            raise ValueError("revocation announcement signing key is not valid at announcedAt")
        for metadata_name, announcement_name in (
            ("accumulatorId", "accumulatorId"),
            ("currentRoot", "root"),
            ("currentEpoch", "epoch"),
            ("maxEpochLag", "maxEpochLag"),
        ):
            value, signed = revocation.get(metadata_name), announcement.get(announcement_name)
            # Type-strict: Python equates True with 1 and 10.0 with 10.
            if type(value) is not type(signed) or value != signed:
                raise ValueError("revocation metadata does not match its signed announcement")
        from zkc_revocation.service import verify_epoch_announcement

        key_x, key_y = announcement_key.public_key_coordinates()
        if not verify_epoch_announcement(
            announcement,
            key_x,
            key_y,
            expected_signing_key_id=announcement_key.key_id,
        ):
            raise ValueError("revocation announcement signature is invalid")
        if "currentLiveness" in revocation:
            _check_published_liveness(revocation["currentLiveness"], announcement, public_keys)
    elif "currentLiveness" in revocation:
        raise ValueError("revocation liveness requires an authenticated announcement")
    base = base_url.rstrip("/")
    return {
        "version": AUTHENTICATED_METADATA_VERSION if authenticated else METADATA_VERSION,
        "issuerId": issuer_id,
        "displayName": display_name,
        "signingKeys": key_entries,
        "supportedSchemas": schema_entries,
        "adapter": {name: f"{base}/v1/{stage}" for name, stage in _ADAPTER_STAGES},
        "revocation": revocation,
        "serviceLevels": dict(service_levels or DEFAULT_SERVICE_LEVELS),
    }


def write_well_known(directory, metadata: dict) -> pathlib.Path:
    """Write `<directory>/.well-known/zkc-issuer.json`; returns the path."""
    target = pathlib.Path(directory) / WELL_KNOWN_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(metadata, indent=2) + "\n")
    return target

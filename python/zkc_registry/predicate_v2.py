"""Shared predicate-entry v2 identity and selector primitives.

The registry validator, holder, verifier, and artifact publisher all use this
module so canonical identity calculation cannot drift between producers and
consumers.  Only the Python standard library is used.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
from typing import Iterable


ENTRY_VERSION = "zkc:registry:predicate-entry:v2"
BINDING_VERSION = "zkc:registry:artifact-binding:v1"
MANIFEST_VERSION = "zkc:artifacts:v2"
REQUEST_EXTENSION = "zkc:request:binding-selectors:v1"

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
VK_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
PREDICATE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")

SOURCE_ID_FIELDS = ("source", "publicInputContract")
BINDING_ID_FIELDS = (
    "predicateId",
    "entryVersion",
    "sourceId",
    "circuit",
    "scheme",
    "toolchain",
    "buildProfile",
    "artifactManifestKey",
    "artifacts",
    "acirHash",
    "vkHash",
    "vkSha256",
)


def canonical_json(value) -> bytes:
    """RFC-8785-compatible subset used by ZKC identity documents.

    Identity inputs are strings, integers, arrays, and objects only, so sorted
    keys plus compact UTF-8 JSON is unambiguous and independent of formatting.
    """

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_id(value) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def source_identity_document(entry: dict) -> dict:
    return {field: entry[field] for field in SOURCE_ID_FIELDS}


def source_id(entry: dict) -> str:
    return sha256_id(source_identity_document(entry))


def binding_identity_document(binding: dict) -> dict:
    return {field: binding[field] for field in BINDING_ID_FIELDS}


def binding_id(binding: dict) -> str:
    return sha256_id(binding_identity_document(binding))


def selector_key(selector: dict) -> tuple[str, str, str]:
    """Validate and normalize an exact untrusted binding selector."""

    if not isinstance(selector, dict) or set(selector) != {
        "predicateId",
        "entryVersion",
        "bindingId",
    }:
        raise ValueError(
            "binding selector must contain exactly predicateId, entryVersion, and bindingId"
        )
    predicate_id = selector["predicateId"]
    entry_version = selector["entryVersion"]
    selected_binding_id = selector["bindingId"]
    if not isinstance(predicate_id, str) or not PREDICATE_ID_RE.fullmatch(predicate_id):
        raise ValueError("binding selector predicateId is malformed")
    if not isinstance(entry_version, str) or not SEMVER_RE.fullmatch(entry_version):
        raise ValueError("binding selector entryVersion is malformed")
    if not isinstance(selected_binding_id, str) or not SHA256_RE.fullmatch(
        selected_binding_id
    ):
        raise ValueError("binding selector bindingId is malformed")
    return predicate_id, entry_version, selected_binding_id


def selector_for_binding(binding: dict) -> dict:
    return {
        "predicateId": binding["predicateId"],
        "entryVersion": binding["entryVersion"],
        "bindingId": binding["bindingId"],
    }


def parse_request_selectors(extensions, proof_types: Iterable[str]) -> dict[str, dict]:
    """Return proofType -> selector from the authenticated v1 extension.

    Unknown extensions are retained by the APR digest but ignored here.  The
    binding-selector extension itself is closed and exact so duplicate,
    missing, or extra proof-type selectors cannot become ambiguous.
    """

    if extensions is None:
        return {}
    if not isinstance(extensions, dict):
        raise ValueError("request extensions must be an object")
    block = extensions.get(REQUEST_EXTENSION)
    if block is None:
        return {}
    if not isinstance(block, dict) or set(block) != {"selectors"}:
        raise ValueError(f"{REQUEST_EXTENSION} must contain exactly selectors")
    selectors = block["selectors"]
    if not isinstance(selectors, list) or not selectors:
        raise ValueError(f"{REQUEST_EXTENSION}.selectors must be a non-empty array")
    allowed = set(proof_types)
    result = {}
    for item in selectors:
        if not isinstance(item, dict) or set(item) != {
            "proofType",
            "predicateId",
            "entryVersion",
            "bindingId",
        }:
            raise ValueError(
                "request binding selector must contain exactly proofType, predicateId, "
                "entryVersion, and bindingId"
            )
        proof_type = item["proofType"]
        if proof_type not in allowed:
            raise ValueError(f"binding selector names unrequested proof type {proof_type!r}")
        if proof_type in result:
            raise ValueError(f"duplicate binding selector for proof type {proof_type!r}")
        selector_key({key: item[key] for key in ("predicateId", "entryVersion", "bindingId")})
        result[proof_type] = {
            key: item[key] for key in ("predicateId", "entryVersion", "bindingId")
        }
    return result


def request_extension(selectors: dict[str, dict]) -> dict:
    """Canonical wire block for a local proofType -> selector mapping."""

    items = []
    for proof_type, selector in sorted(selectors.items()):
        selector_key(selector)
        items.append({"proofType": proof_type, **selector})
    return {REQUEST_EXTENSION: {"selectors": items}} if items else {}


def normalized_repo_path(value: str) -> pathlib.PurePosixPath:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
        or any(part in ("", ".", "..") for part in value.split("/"))
    ):
        raise ValueError("path must be normalized and repository-relative")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute():
        raise ValueError("path must be repository-relative")
    return path

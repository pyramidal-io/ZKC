#!/usr/bin/env python3
"""ZKC registry validator (Freedom Safeguards 1 and 4).

Validates every entry under registry/predicates/ against the entry schema and
the governance rules:

  * structural validity (registry/schema/predicate-entry.schema.json semantics,
    enforced dependency-free);
  * path consistency: registry/predicates/<predicateId>/<entryVersion>/entry.json;
  * inspectability: the pinned circuit source exists and its SHA-256 matches;
    once an entry reaches the public default branch, its immutable identity,
    source-package/local-dependency bytes, and encoder bytes are protected
    separately by check_immutability.py;
  * the public-input encoder exists, names the same circuit, and publishes
    every proof type the entry claims;
  * review/activation rules: 'self_attested', 'reviewed', and 'deprecated'
    entries carry public review evidence; a 'self_attested' entry MUST NOT
    carry a review.reviewedAt date, because no independent review happened;
    activated entries have a review status that permits activation; successors
    point to the immediate prior version of the same lineage;
    deprecation only flags (a deprecated entry keeps its full pinned identity);
  * additive same-lineage evolution: later versions use a new circuit name,
    source package, public-input encoder, and proof type until explicit
    entry-version selection exists. Independent predicate lineages may still
    serve overlapping proof types;
  * NON-EXCLUSIVITY (Freedom Safeguard 1): no entry — and no schema — may
    declare itself canonical, default, official, mandatory, blessed, exclusive,
    or preferred. Multiple entries serving the same proof type are explicitly
    allowed and never an error;
  * optional artifact cross-check: with --manifest (or when
    artifacts/build/manifest.json exists), acirHash/vkHash/vkSha256 must match
    the generated artifact manifest.

Also validates the DISCOVERY registry (registry/issuers/ + registry/verifiers/)
via python/zkc_registry: schema semantics, duplicate-id detection, and the
same non-exclusivity scan. Discovery documents are advisory: registry
membership never confers trust, and verifier policies may reference issuers
that appear in no registry.

Standard library only. Exit code 0 only when every check passes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from noir_package import NoirPackageError, inspect_circuit_package

PYTHON_DIR = pathlib.Path(__file__).resolve().parents[1] / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

from zkc_registry.encoder_resolution import encoder_circuits  # noqa: E402
from zkc_registry.predicate_v2 import (  # noqa: E402
    BINDING_ID_FIELDS,
    BINDING_VERSION,
    ENTRY_VERSION as ENTRY_V2,
    binding_id as compute_binding_id,
    source_id as compute_source_id,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
PREDICATES_DIR = ROOT / "registry" / "predicates"
SCHEMA_PATH = ROOT / "registry" / "schema" / "predicate-entry.schema.json"
SCHEMA_V2_PATH = ROOT / "registry" / "schema" / "predicate-entry-v2.schema.json"
BINDING_SCHEMA_PATH = ROOT / "registry" / "schema" / "artifact-binding-v1.schema.json"

REVIEW_STATUSES = ("draft", "in_review", "self_attested", "reviewed", "deprecated")
# Statuses that must publish review evidence. 'self_attested' is included
# deliberately: an entry may only claim self-verification if that verification
# is written down publicly and can be checked against by any reader.
EVIDENCE_REQUIRED_STATUSES = ("self_attested", "reviewed", "deprecated")
# Activation requires a status whose assurance level is publicly documented.
# It does NOT require independent review: 'self_attested' entries are published
# for use with their (lack of) review stated on the record. Assurance gating is
# the job of the holder default and of verifier policy, not of activation.
ACTIVATABLE_STATUSES = ("self_attested", "reviewed", "deprecated")

# Freedom Safeguard 1: key names that would assert exclusivity. None of these
# may appear anywhere in an entry document or in the entry schema itself.
FORBIDDEN_KEYS = (
    "canonical",
    "default",
    "official",
    "mandatory",
    "blessed",
    "exclusive",
    "preferred",
    "recommended",
)

SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
PREDICATE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
PROOF_TYPE_RE = re.compile(r"^zkc:proof:[a-z0-9._-]+:v[0-9]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PREFIXED_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
VK_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
SUPERSEDES_RE = re.compile(r"^([a-z0-9][a-z0-9._-]*)@([0-9]+\.[0-9]+\.[0-9]+)$")
DATE_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")

# Fields compared byte-for-byte (after JSON decoding) by
# registry/check_immutability.py once an entry is committed to the public
# default branch. Keeping the contract here makes validator diagnostics and
# history enforcement use the same vocabulary.
IMMUTABLE_IDENTITY_FIELDS = (
    "predicateId",
    "entryVersion",
    "proofTypes",
    "circuit",
    "publicInputEncoder",
)


class Findings:
    def __init__(self):
        self.errors = []

    def error(self, where: str, message: str) -> None:
        self.errors.append(f"{where}: {message}")


def semver_key(version: str) -> tuple:
    return tuple(int(part) for part in version.split("."))


def resolve_repo_file(
    repo_root: pathlib.Path,
    value: str,
    label: str,
    where: str,
    findings: Findings,
) -> pathlib.Path | None:
    """Resolve a non-symlinked repository-relative path, or report why not."""
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
    ):
        findings.error(where, f"{label} must be a normalized repository-relative path")
        return None
    relative = pathlib.PurePosixPath(value)
    if relative.is_absolute():
        findings.error(where, f"{label} must be repository-relative, not absolute")
        return None
    if any(part in ("", ".", "..") for part in value.split("/")):
        findings.error(where, f"{label} must be a normalized repository-relative path")
        return None

    candidate = repo_root.joinpath(*relative.parts)
    cursor = repo_root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            findings.error(where, f"{label} must not traverse a symlink: {value}")
            return None
    try:
        candidate.resolve(strict=False).relative_to(repo_root.resolve())
    except (OSError, ValueError):
        findings.error(where, f"{label} escapes the repository: {value}")
        return None
    return candidate


def source_package_reference(repo_root: pathlib.Path, source_path: str) -> str:
    """Identify the nearest Noir package, or fall back to the source file."""
    relative = pathlib.PurePosixPath(source_path)
    for parent in relative.parents:
        if parent == pathlib.PurePosixPath("."):
            break
        if repo_root.joinpath(*parent.parts, "Nargo.toml").is_file():
            return parent.as_posix()
    return relative.as_posix()


def scan_forbidden_keys(node, where: str, findings: Findings, path: str = "") -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key.lower() in FORBIDDEN_KEYS:
                findings.error(
                    where,
                    f"forbidden exclusivity key '{path}{key}' (Freedom Safeguard 1: "
                    "registry entries are non-exclusive)",
                )
            scan_forbidden_keys(value, where, findings, f"{path}{key}.")
    elif isinstance(node, list):
        for index, item in enumerate(node):
            scan_forbidden_keys(item, where, findings, f"{path}{index}.")


def _sha256_file(path: pathlib.Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _review_structure(value, where: str, findings: Findings) -> bool:
    if not isinstance(value, dict) or set(value) != {"status", "evidence", "reviewedAt"}:
        findings.error(where, "review must contain exactly status, evidence, and reviewedAt")
        return False
    status = value.get("status")
    evidence = value.get("evidence")
    reviewed_at = value.get("reviewedAt")
    ok = True
    if status not in REVIEW_STATUSES:
        findings.error(where, f"review.status must be one of {REVIEW_STATUSES}")
        ok = False
    if not isinstance(evidence, list) or not all(isinstance(item, str) and item for item in evidence):
        findings.error(where, "review.evidence must be an array of non-empty strings")
        ok = False
    if reviewed_at is not None and not DATE_TIME_RE.fullmatch(str(reviewed_at)):
        findings.error(where, "review.reviewedAt must be RFC 3339 or null")
        ok = False
    return ok


def _check_review_governance(record: dict, where: str, findings: Findings) -> None:
    review = record["review"]
    status = review["status"]
    if status in EVIDENCE_REQUIRED_STATUSES and not review["evidence"]:
        findings.error(where, f"status '{status}' requires public review evidence")
    if status == "self_attested" and review.get("reviewedAt") is not None:
        findings.error(where, "self_attested review.reviewedAt must be null")
    if status == "deprecated" and "deprecation" not in record:
        findings.error(where, "deprecated records must carry deprecation metadata")
    if status != "deprecated" and "deprecation" in record:
        findings.error(where, "deprecation metadata requires review.status deprecated")


def _file_pin(
    repo_root: pathlib.Path,
    value,
    label: str,
    where: str,
    findings: Findings,
) -> pathlib.Path | None:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        findings.error(where, f"{label} must contain exactly path and sha256")
        return None
    if not PREFIXED_SHA256_RE.fullmatch(str(value.get("sha256"))):
        findings.error(where, f"{label}.sha256 must match sha256:<hex>")
        return None
    path = resolve_repo_file(repo_root, value.get("path"), f"{label}.path", where, findings)
    if path is None:
        return None
    if not path.is_file():
        findings.error(where, f"{label} is missing: {value['path']}")
        return None
    actual = _sha256_file(path)
    if actual != value["sha256"]:
        findings.error(where, f"{label} digest mismatch ({actual} != {value['sha256']})")
    return path


def _source_manifest_files(repo_root: pathlib.Path, inspection) -> tuple[str, ...]:
    """Canonical complete source inventory for a direct package closure."""
    files = []
    for package_root in inspection.closure:
        package_dir = repo_root / package_root
        for child in sorted(package_dir.rglob("*")):
            relative_to_package = child.relative_to(package_dir)
            if "target" in relative_to_package.parts or child.name in {
                "Prover.toml", "Verifier.toml", ".DS_Store"
            }:
                continue
            if child.is_file():
                files.append(child.relative_to(repo_root).as_posix())
    return tuple(sorted(files))


def check_structure_v2(entry: dict, where: str, findings: Findings) -> bool:
    if not isinstance(entry, dict):
        findings.error(where, "entry is not a JSON object")
        return False
    required = {
        "version", "predicateId", "entryVersion", "title", "author", "proofTypes",
        "sourceId", "source", "publicInputContract", "review", "supersedes", "adoptsV1",
    }
    allowed = required | {"deprecation"}
    unknown = set(entry) - allowed
    missing = required - set(entry)
    for key in sorted(unknown):
        findings.error(where, f"unknown v2 top-level field '{key}'")
    for key in sorted(missing):
        findings.error(where, f"missing required v2 field '{key}'")
    if unknown or missing:
        return False
    ok = True
    if entry["version"] != ENTRY_V2:
        findings.error(where, f"unsupported entry version {entry['version']!r}")
        ok = False
    if not PREDICATE_ID_RE.fullmatch(str(entry["predicateId"])):
        findings.error(where, "invalid predicateId")
        ok = False
    if not SEMVER_RE.fullmatch(str(entry["entryVersion"])):
        findings.error(where, "invalid entryVersion")
        ok = False
    if not isinstance(entry["title"], str) or not entry["title"]:
        findings.error(where, "title must be non-empty")
        ok = False
    author = entry["author"]
    if not isinstance(author, dict) or not author.get("name") or set(author) - {"name", "url"}:
        findings.error(where, "author must contain name and optional url")
        ok = False
    proof_types = entry["proofTypes"]
    if (
        not isinstance(proof_types, list)
        or not proof_types
        or len(set(item for item in proof_types if isinstance(item, str))) != len(proof_types)
        or not all(isinstance(item, str) and PROOF_TYPE_RE.fullmatch(item) for item in proof_types)
    ):
        findings.error(where, "proofTypes must be a non-empty unique array of proof type IDs")
        ok = False
    if not PREFIXED_SHA256_RE.fullmatch(str(entry["sourceId"])):
        findings.error(where, "sourceId must match sha256:<hex>")
        ok = False
    source = entry["source"]
    if not isinstance(source, dict) or set(source) != {"circuit", "packageRoot", "files"}:
        findings.error(where, "source must contain exactly circuit, packageRoot, and files")
        ok = False
    elif (
        not re.fullmatch(r"zkc_[a-z0-9_]+", str(source["circuit"]))
        or source["packageRoot"] != f"noir/{source['circuit']}"
        or not isinstance(source["files"], list)
        or not source["files"]
    ):
        findings.error(where, "source circuit/packageRoot/files are malformed")
        ok = False
    contract = entry["publicInputContract"]
    if not isinstance(contract, dict) or set(contract) != {
        "encoder", "bindingSidecar", "bindingSchema"
    }:
        findings.error(where, "publicInputContract must contain encoder, bindingSidecar, bindingSchema")
        ok = False
    if not _review_structure(entry["review"], where, findings):
        ok = False
    for field in ("supersedes", "adoptsV1"):
        value = entry[field]
        if value is not None and not SUPERSEDES_RE.fullmatch(str(value)):
            findings.error(where, f"{field} must match predicateId@version or null")
            ok = False
    return ok


def check_binding_structure(binding: dict, where: str, findings: Findings) -> bool:
    required = set(BINDING_ID_FIELDS) | {"version", "bindingId", "review", "activation"}
    allowed = required | {"deprecation"}
    if not isinstance(binding, dict):
        findings.error(where, "artifact binding is not a JSON object")
        return False
    if set(binding) - allowed or required - set(binding):
        findings.error(where, "artifact binding has missing or unknown fields")
        return False
    ok = True
    if binding["version"] != BINDING_VERSION:
        findings.error(where, f"unsupported binding version {binding['version']!r}")
        ok = False
    for key in ("sourceId", "bindingId", "acirHash", "vkSha256"):
        if not PREFIXED_SHA256_RE.fullmatch(str(binding[key])):
            findings.error(where, f"{key} must match sha256:<hex>")
            ok = False
    if not VK_HASH_RE.fullmatch(str(binding["vkHash"])):
        findings.error(where, "vkHash must match 0x<hex>")
        ok = False
    if binding["scheme"] != "ultra_honk":
        findings.error(where, "scheme must be ultra_honk")
        ok = False
    toolchain = binding["toolchain"]
    if not isinstance(toolchain, dict) or set(toolchain) != {
        "id", "nargo", "noirc", "bb", "provenance"
    } or not all(isinstance(toolchain.get(key), str) and toolchain[key] for key in ("id", "nargo", "noirc", "bb")):
        findings.error(where, "toolchain must contain exact id/nargo/noirc/bb/provenance")
        ok = False
    artifacts = binding["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != {"acir", "vk"}:
        findings.error(where, "artifacts must contain exactly acir and vk")
        ok = False
    activation = binding["activation"]
    if not isinstance(activation, dict) or set(activation) != {"activatedAt", "supersedes"}:
        findings.error(where, "activation must contain exactly activatedAt and supersedes")
        ok = False
    elif (
        activation["activatedAt"] is not None
        and not DATE_TIME_RE.fullmatch(str(activation["activatedAt"]))
    ):
        findings.error(where, "activation.activatedAt must be RFC 3339 or null")
        ok = False
    elif activation["supersedes"] is not None and not PREFIXED_SHA256_RE.fullmatch(
        str(activation["supersedes"])
    ):
        findings.error(where, "activation.supersedes must be a bindingId or null")
        ok = False
    if not _review_structure(binding["review"], where, findings):
        ok = False
    return ok


def check_structure(entry: dict, where: str, findings: Findings) -> bool:
    """Dependency-free enforcement of predicate-entry.schema.json. Returns
    False when the entry is too malformed for further checks."""
    ok = True

    def err(message):
        nonlocal ok
        findings.error(where, message)
        ok = False

    if not isinstance(entry, dict):
        err("entry is not a JSON object")
        return False

    allowed_top = {
        "version", "predicateId", "entryVersion", "title", "author",
        "proofTypes", "circuit", "publicInputEncoder", "review",
        "activation", "deprecation",
    }
    for key in entry:
        if key not in allowed_top:
            err(f"unknown top-level field '{key}' (additionalProperties: false)")
    required_top = allowed_top - {"title", "deprecation"}
    for key in sorted(required_top):
        if key not in entry:
            err(f"missing required field '{key}'")
    if not ok:
        return False

    if entry["version"] != "zkc:registry:predicate-entry:v1":
        err(f"unsupported entry version '{entry['version']}'")
    if not PREDICATE_ID_RE.fullmatch(str(entry["predicateId"])):
        err(f"invalid predicateId '{entry['predicateId']}'")
    if not SEMVER_RE.fullmatch(str(entry["entryVersion"])):
        err(f"invalid entryVersion '{entry['entryVersion']}'")

    author = entry["author"]
    if not isinstance(author, dict) or not author.get("name"):
        err("author must be an object with a non-empty 'name'")
    elif set(author) - {"name", "url"}:
        err(f"unknown author fields: {sorted(set(author) - {'name', 'url'})}")

    proof_types = entry["proofTypes"]
    if not isinstance(proof_types, list) or not proof_types:
        err("proofTypes must be a non-empty array")
    else:
        valid_proof_types = []
        for proof_type in proof_types:
            if not isinstance(proof_type, str) or not PROOF_TYPE_RE.fullmatch(proof_type):
                err(f"invalid proof type '{proof_type}'")
            else:
                valid_proof_types.append(proof_type)
        if len(valid_proof_types) == len(proof_types) and len(
            set(valid_proof_types)
        ) != len(valid_proof_types):
            err("duplicate proof types within entry")

    circuit = entry["circuit"]
    if not isinstance(circuit, dict):
        err("circuit must be an object")
        return ok
    circuit_fields = {
        "name", "scheme", "sourcePath", "sourceSha256", "acirHash", "vkHash", "vkSha256",
    }
    for key in sorted(circuit_fields - set(circuit)):
        err(f"circuit missing required field '{key}'")
    for key in sorted(set(circuit) - circuit_fields):
        err(f"circuit has unknown field '{key}'")
    if not ok:
        return ok
    if not re.fullmatch(r"zkc_[a-z0-9_]+", str(circuit["name"])):
        err(f"invalid circuit name '{circuit['name']}'")
    if circuit["scheme"] != "ultra_honk":
        err(f"unsupported scheme '{circuit['scheme']}'")
    if not isinstance(circuit["sourcePath"], str) or not circuit["sourcePath"]:
        err("circuit.sourcePath must be a non-empty string")
    if not SHA256_RE.fullmatch(str(circuit["sourceSha256"])):
        err("circuit.sourceSha256 must be a bare hex SHA-256")
    if not PREFIXED_SHA256_RE.fullmatch(str(circuit["acirHash"])):
        err("circuit.acirHash must match sha256:<hex>")
    if not VK_HASH_RE.fullmatch(str(circuit["vkHash"])):
        err("circuit.vkHash must match 0x<hex>")
    if not PREFIXED_SHA256_RE.fullmatch(str(circuit["vkSha256"])):
        err("circuit.vkSha256 must match sha256:<hex>")
    if not isinstance(entry["publicInputEncoder"], str) or not entry["publicInputEncoder"]:
        err("publicInputEncoder must be a non-empty string")

    review = entry["review"]
    if not isinstance(review, dict) or review.get("status") not in REVIEW_STATUSES:
        err(f"review.status must be one of {REVIEW_STATUSES}")
    else:
        if set(review) - {"status", "evidence", "reviewedAt"}:
            err("review has unknown fields")
        evidence = review.get("evidence")
        if not isinstance(evidence, list) or not all(
            isinstance(item, str) and item for item in evidence
        ):
            err("review.evidence must be an array of non-empty strings")
        reviewed_at = review.get("reviewedAt")
        if reviewed_at is not None and not DATE_TIME_RE.fullmatch(str(reviewed_at)):
            err("review.reviewedAt must be RFC 3339 or null")

    activation = entry["activation"]
    if not isinstance(activation, dict) or set(activation) != {"activatedAt", "supersedes"}:
        err("activation must have exactly activatedAt and supersedes")
    else:
        activated_at = activation["activatedAt"]
        if activated_at is not None and not DATE_TIME_RE.fullmatch(str(activated_at)):
            err("activation.activatedAt must be RFC 3339 or null")
        supersedes = activation["supersedes"]
        if supersedes is not None and not SUPERSEDES_RE.fullmatch(str(supersedes)):
            err("activation.supersedes must match predicateId@version or null")

    if "deprecation" in entry:
        deprecation = entry["deprecation"]
        if not isinstance(deprecation, dict) or not deprecation.get("reason"):
            err("deprecation must carry a non-empty reason")
        elif set(deprecation) - {"reason", "deprecatedAt"}:
            err("deprecation has unknown fields")

    return ok


def check_governance(
    entry: dict,
    predicate_id: str,
    version: str,
    where: str,
    findings: Findings,
    all_versions: dict,
    repo_root: pathlib.Path,
    manifest_circuits: dict,
) -> None:
    if entry["predicateId"] != predicate_id:
        findings.error(
            where, f"predicateId '{entry['predicateId']}' does not match directory '{predicate_id}'"
        )
    if entry["entryVersion"] != version:
        findings.error(
            where, f"entryVersion '{entry['entryVersion']}' does not match directory '{version}'"
        )

    # Inspectability: the proposed tree must match its pin. Historical
    # immutability (including coordinated source + pin edits) is enforced by
    # registry/check_immutability.py against the merge base.
    circuit = entry["circuit"]
    source_path = resolve_repo_file(
        repo_root, circuit["sourcePath"], "circuit.sourcePath", where, findings
    )
    if source_path is None:
        pass
    elif not source_path.is_file():
        findings.error(where, f"circuit source missing: {circuit['sourcePath']}")
    else:
        actual = hashlib.sha256(source_path.read_bytes()).hexdigest()
        if actual != circuit["sourceSha256"]:
            findings.error(
                where,
                "circuit source hash mismatch — committed circuit identity is immutable; "
                "restore the pinned source, or add a new source package, encoder, entry "
                "version, and proof type and compute its pins with registry/pin_entry.py "
                f"({circuit['sourcePath']})",
            )
        try:
            inspect_circuit_package(repo_root, circuit["name"], circuit["sourcePath"])
        except NoirPackageError as exc:
            findings.error(where, f"invalid circuit package: {exc}")

    # Encoder consistency.
    encoder_path = resolve_repo_file(
        repo_root,
        entry["publicInputEncoder"],
        "publicInputEncoder",
        where,
        findings,
    )
    if encoder_path is None:
        pass
    elif not encoder_path.is_file():
        findings.error(where, f"public-input encoder missing: {entry['publicInputEncoder']}")
    else:
        try:
            encoder = json.loads(encoder_path.read_text(encoding="utf-8"))
            encoder_parsed = True
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            findings.error(where, f"public-input encoder is not valid JSON: {exc}")
            encoder = None
            encoder_parsed = False
        if encoder_parsed and not isinstance(encoder, dict):
            findings.error(where, "public-input encoder must contain a JSON object")
        elif isinstance(encoder, dict):
            if encoder.get("circuit") != circuit["name"]:
                findings.error(
                    where,
                    f"encoder circuit '{encoder.get('circuit')}' != entry circuit '{circuit['name']}'",
                )
            if encoder.get("version") != "zkc:public-inputs:v1":
                findings.error(where, "public-input encoder has an unsupported or missing version")
            if encoder.get("proofSystem") != circuit["scheme"]:
                findings.error(
                    where,
                    "public-input encoder proofSystem does not match circuit.scheme",
                )
            if encoder.get("curve") != "BN254":
                findings.error(where, "public-input encoder curve must be 'BN254'")
            encoding = encoder.get("encoding")
            encoding_keys = ("fieldElement", "order", "booleans", "integers", "byteArrays")
            if not isinstance(encoding, dict) or not all(
                isinstance(encoding.get(key), str) and encoding[key]
                for key in encoding_keys
            ):
                findings.error(where, "public-input encoder encoding profile is incomplete")
            published_values = encoder.get("proofTypes")
            if not isinstance(published_values, list) or not published_values or not all(
                isinstance(item, str) and PROOF_TYPE_RE.fullmatch(item)
                for item in published_values
            ):
                findings.error(
                    where,
                    "public-input encoder proofTypes must be a non-empty array of valid strings",
                )
                published = set()
            else:
                published = set(published_values)
                if len(published) != len(published_values):
                    findings.error(where, "public-input encoder proofTypes contain duplicates")
            unpublished = [pt for pt in entry["proofTypes"] if pt not in published]
            if unpublished and published_values is not None:
                findings.error(
                    where, f"proof types not published by the encoder: {unpublished}"
                )
            public_inputs = encoder.get("publicInputs")
            if not isinstance(public_inputs, list) or not public_inputs:
                findings.error(
                    where, "public-input encoder publicInputs must be a non-empty array"
                )
            else:
                next_offset = 0
                for index, item in enumerate(public_inputs):
                    if not isinstance(item, dict):
                        findings.error(
                            where, f"public-input encoder publicInputs[{index}] must be an object"
                        )
                        continue
                    if not isinstance(item.get("index"), int) or isinstance(
                        item.get("index"), bool
                    ) or item["index"] != index:
                        findings.error(
                            where,
                            f"public-input encoder publicInputs[{index}].index must equal {index}",
                        )
                    if not isinstance(item.get("offset"), int) or isinstance(
                        item.get("offset"), bool
                    ) or item["offset"] != next_offset:
                        findings.error(
                            where,
                            f"public-input encoder publicInputs[{index}].offset must equal "
                            f"{next_offset}",
                        )
                    if not isinstance(item.get("name"), str) or not re.fullmatch(
                        r"[a-z][a-z0-9_]*", item["name"]
                    ):
                        findings.error(
                            where,
                            f"public-input encoder publicInputs[{index}].name is invalid",
                        )
                    if not isinstance(item.get("abiType"), str) or not item["abiType"]:
                        findings.error(
                            where,
                            f"public-input encoder publicInputs[{index}].abiType must be a string",
                        )
                    field_elements = item.get("fieldElements")
                    if (
                        not isinstance(field_elements, int)
                        or isinstance(field_elements, bool)
                        or field_elements < 1
                    ):
                        findings.error(
                            where,
                            f"public-input encoder publicInputs[{index}].fieldElements "
                            "must be a positive integer",
                        )
                    else:
                        next_offset += field_elements
                    if not isinstance(item.get("description"), str):
                        findings.error(
                            where,
                            f"public-input encoder publicInputs[{index}].description "
                            "must be a string",
                        )
                total = encoder.get("totalFieldElements")
                if (
                    not isinstance(total, int)
                    or isinstance(total, bool)
                    or total != next_offset
                ):
                    findings.error(
                        where,
                        "public-input encoder totalFieldElements must equal the flattened "
                        f"public input size {next_offset}",
                    )

    # Review / activation rules.
    review = entry["review"]
    status = review["status"]
    if status in EVIDENCE_REQUIRED_STATUSES and not review["evidence"]:
        findings.error(
            where,
            f"status '{status}' requires public review evidence (open review, Safeguard 4)",
        )
    # 'self_attested' means no independent review took place, so there is no
    # review completion date to record. A date here would read as one.
    if status == "self_attested" and review.get("reviewedAt") is not None:
        findings.error(
            where,
            "status 'self_attested' asserts that NO independent review occurred, so "
            "review.reviewedAt must be null (record the author's own verification "
            "dates in the review evidence record instead)",
        )
    activated_at = entry["activation"]["activatedAt"]
    if activated_at is not None and status not in ACTIVATABLE_STATUSES:
        findings.error(
            where,
            f"entry is activated but review status is '{status}' — activation requires "
            "a status whose assurance level is publicly documented "
            f"({', '.join(ACTIVATABLE_STATUSES)})",
        )
    if status == "deprecated" and "deprecation" not in entry:
        findings.error(where, "deprecated entries must carry a deprecation block (flag, not delete)")
    if status != "deprecated" and "deprecation" in entry:
        findings.error(where, "deprecation block present but status is not 'deprecated'")

    # Supersedes: must reference an existing, strictly older version.
    supersedes = entry["activation"]["supersedes"]
    if supersedes is not None:
        match = SUPERSEDES_RE.fullmatch(supersedes)
        target_id, target_version = match.group(1), match.group(2)
        if target_id != predicate_id:
            findings.error(
                where,
                f"supersedes must reference the same predicate lineage '{predicate_id}': "
                f"{supersedes}",
            )
        elif target_version not in all_versions.get(target_id, {}):
            findings.error(where, f"supersedes target does not exist: {supersedes}")
        elif semver_key(target_version) >= semver_key(version):
            findings.error(
                where, f"supersedes must reference an older version of the lineage: {supersedes}"
            )

    # Optional artifact manifest cross-check.
    if manifest_circuits is not None:
        manifest_entry = manifest_circuits.get(circuit["name"])
        if manifest_entry is None:
            findings.error(
                where, f"circuit '{circuit['name']}' is not in the artifact manifest"
            )
        else:
            if manifest_entry.get("scheme") != circuit["scheme"]:
                findings.error(
                    where,
                    "circuit scheme does not match the artifact manifest "
                    f"({circuit['scheme']} != {manifest_entry.get('scheme')})",
                )
            if manifest_entry.get("publicInputEncoder") != entry["publicInputEncoder"]:
                findings.error(
                    where,
                    "publicInputEncoder does not match the artifact manifest "
                    f"({entry['publicInputEncoder']} != "
                    f"{manifest_entry.get('publicInputEncoder')})",
                )
            for entry_key, manifest_key in (
                ("acirHash", "acirHash"),
                ("vkHash", "vkHash"),
                ("vkSha256", "vkSha256"),
            ):
                if circuit[entry_key] != manifest_entry.get(manifest_key):
                    findings.error(
                        where,
                        f"{entry_key} does not match the artifact manifest "
                        f"({circuit[entry_key]} != {manifest_entry.get(manifest_key)})",
                    )


def check_v2_governance(
    entry: dict,
    predicate_id: str,
    version: str,
    where: str,
    findings: Findings,
    all_entries: dict,
    repo_root: pathlib.Path,
) -> None:
    if entry["predicateId"] != predicate_id or entry["entryVersion"] != version:
        findings.error(where, "v2 parent tuple does not match its registry path")
    _check_review_governance(entry, where, findings)

    source = entry["source"]
    try:
        inspection = inspect_circuit_package(
            repo_root, source["circuit"], f"{source['packageRoot']}/src/main.nr"
        )
    except NoirPackageError as exc:
        findings.error(where, f"invalid v2 source package: {exc}")
        inspection = None

    declared_files = source.get("files", [])
    declared_paths = []
    if isinstance(declared_files, list):
        for index, pin in enumerate(declared_files):
            path = _file_pin(repo_root, pin, f"source.files[{index}]", where, findings)
            if path is not None:
                declared_paths.append(pin["path"])
    if len(declared_paths) != len(set(declared_paths)):
        findings.error(where, "source manifest contains duplicate paths")
    if declared_paths != sorted(declared_paths):
        findings.error(where, "source manifest paths must be sorted canonically")
    if inspection is not None:
        actual_paths = _source_manifest_files(repo_root, inspection)
        if tuple(declared_paths) != actual_paths:
            missing = sorted(set(actual_paths) - set(declared_paths))
            extra = sorted(set(declared_paths) - set(actual_paths))
            findings.error(
                where,
                f"source manifest does not exactly cover the package closure; "
                f"missing={missing}, extra={extra}",
            )

    contract = entry["publicInputContract"]
    contract_paths = {}
    for label in ("encoder", "bindingSidecar", "bindingSchema"):
        contract_paths[label] = _file_pin(repo_root, contract.get(label), label, where, findings)
    encoder_path = contract_paths.get("encoder")
    sidecar_path = contract_paths.get("bindingSidecar")
    schema_path = contract_paths.get("bindingSchema")
    expected_encoder = f"schemas/public-inputs/{source['circuit']}.json"
    expected_sidecar = f"schemas/public-input-bindings/{source['circuit']}.json"
    if contract.get("encoder", {}).get("path") != expected_encoder:
        findings.error(where, f"encoder must be {expected_encoder}")
    if contract.get("bindingSidecar", {}).get("path") != expected_sidecar:
        findings.error(where, f"binding sidecar must be {expected_sidecar}")
    if encoder_path is not None:
        try:
            encoder = json.loads(encoder_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            findings.error(where, f"encoder is not valid JSON: {exc}")
            encoder = None
        if isinstance(encoder, dict):
            if encoder.get("circuit") != source["circuit"]:
                findings.error(where, "encoder circuit does not match v2 source circuit")
            published_types = encoder.get("proofTypes")
            if not isinstance(published_types, list) or not all(
                isinstance(item, str) for item in published_types
            ):
                findings.error(where, "encoder proofTypes must be an array of strings")
            else:
                unpublished = sorted(set(entry["proofTypes"]) - set(published_types))
                if unpublished:
                    findings.error(where, f"encoder does not publish proof types {unpublished}")
    if sidecar_path is not None and schema_path is not None:
        try:
            sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            findings.error(where, f"binding sidecar is not valid JSON: {exc}")
            sidecar = None
        if isinstance(sidecar, dict) and sidecar.get("$schema") != (
            "https://zkc.dev/" + contract["bindingSchema"]["path"]
        ):
            findings.error(where, "binding sidecar does not select the pinned binding schema")

    actual_source_id = compute_source_id(entry)
    if entry["sourceId"] != actual_source_id:
        findings.error(
            where,
            f"sourceId does not match canonical source-and-contract manifest "
            f"({entry['sourceId']} != {actual_source_id})",
        )

    for field in ("supersedes", "adoptsV1"):
        target = entry[field]
        if target is None:
            continue
        target_id, target_version = target.split("@", 1)
        target_entry = all_entries.get((target_id, target_version))
        if target_id != predicate_id or target_entry is None:
            findings.error(where, f"{field} target does not exist in the same lineage: {target}")
        elif semver_key(target_version) >= semver_key(version):
            findings.error(where, f"{field} must reference an older entry version")
        elif field == "adoptsV1" and target_entry.get("version") != "zkc:registry:predicate-entry:v1":
            findings.error(where, "adoptsV1 must name an exact predicate-entry v1 predecessor")

    if entry["adoptsV1"] is not None:
        adopted = all_entries.get(tuple(entry["adoptsV1"].split("@", 1)))
        if isinstance(adopted, dict):
            if entry["proofTypes"] != adopted.get("proofTypes"):
                findings.error(where, "v1 adoption must reuse the predecessor proofTypes exactly")
            adopted_source = adopted.get("circuit", {}).get("sourcePath")
            if adopted_source not in declared_paths:
                findings.error(where, "v1 adoption manifest must include the exact predecessor source")
            adopted_encoder = adopted.get("publicInputEncoder")
            if contract.get("encoder", {}).get("path") != adopted_encoder:
                findings.error(where, "v1 adoption must reuse the exact predecessor encoder")


def check_binding_governance(
    binding: dict,
    entry: dict,
    where: str,
    findings: Findings,
    repo_root: pathlib.Path,
    manifest_bindings: dict | None,
    known_binding_ids: set,
) -> None:
    parent = (entry["predicateId"], entry["entryVersion"])
    observed = (binding["predicateId"], binding["entryVersion"])
    if observed != parent or binding["sourceId"] != entry["sourceId"]:
        findings.error(where, "binding parent tuple/sourceId is cross-wired")
    if binding["circuit"] != entry["source"]["circuit"]:
        findings.error(where, "binding circuit does not match parent source circuit")
    actual_binding_id = compute_binding_id(binding)
    if binding["bindingId"] != actual_binding_id:
        findings.error(
            where,
            f"bindingId does not match canonical immutable binding "
            f"({binding['bindingId']} != {actual_binding_id})",
        )
    _check_review_governance(binding, where, findings)
    status = binding["review"]["status"]
    source_status = entry["review"]["status"]
    activated = binding["activation"]["activatedAt"]
    if activated is not None and (
        status not in ("self_attested", "reviewed")
        or source_status not in ("self_attested", "reviewed")
    ):
        findings.error(
            where,
            "binding activation requires independently eligible source and binding review states",
        )
    if status == "deprecated" and activated is None:
        findings.error(where, "a deprecated binding must retain its historical activation timestamp")
    supersedes = binding["activation"]["supersedes"]
    if supersedes is not None and supersedes not in known_binding_ids:
        findings.error(where, f"binding supersedes target does not exist: {supersedes}")

    provenance = binding["toolchain"].get("provenance")
    _file_pin(repo_root, provenance, "toolchain.provenance", where, findings)
    for artifact_name in ("acir", "vk"):
        path = resolve_repo_file(
            repo_root,
            binding["artifacts"].get(artifact_name),
            f"artifacts.{artifact_name}",
            where,
            findings,
        )
        if path is not None and not path.is_file():
            findings.error(where, f"binding artifact is missing: {binding['artifacts'][artifact_name]}")
    vk_path = resolve_repo_file(repo_root, binding["artifacts"].get("vk"), "artifacts.vk", where, findings)
    if vk_path is not None and vk_path.is_file() and _sha256_file(vk_path) != binding["vkSha256"]:
        findings.error(where, "binding vk bytes do not match vkSha256")

    if manifest_bindings is not None:
        manifest = manifest_bindings.get(binding["artifactManifestKey"])
        if manifest is None:
            findings.error(where, "binding artifactManifestKey is absent from the artifact manifest")
        else:
            for field in (
                "predicateId", "entryVersion", "sourceId", "bindingId", "circuit", "scheme",
                "toolchain", "buildProfile", "artifactManifestKey", "artifacts", "acirHash",
                "vkHash", "vkSha256",
            ):
                if field == "artifacts":
                    circuit = binding["circuit"]
                    toolchain_id = binding["toolchain"]["id"]
                    accepted_build_paths = (
                        {
                            "acir": f"artifacts/build/{circuit}/{circuit}.json",
                            "vk": f"artifacts/build/{circuit}/vk",
                        },
                        {
                            "acir": f"artifacts/build/bindings/{circuit}/{toolchain_id}/{circuit}.json",
                            "vk": f"artifacts/build/bindings/{circuit}/{toolchain_id}/vk",
                        },
                    )
                    agrees = (
                        manifest.get(field) == binding.get(field)
                        or manifest.get(field) in accepted_build_paths
                    )
                else:
                    agrees = manifest.get(field) == binding.get(field)
                if not agrees:
                    findings.error(where, f"binding {field} disagrees with the artifact manifest")


def validate_discovery(repo_root: pathlib.Path, findings: Findings) -> None:
    """Validate registry/issuers + registry/verifiers via python/zkc_registry
    (single source of truth for discovery document semantics)."""
    python_dir = str(repo_root / "python")
    if python_dir not in sys.path:
        sys.path.insert(0, python_dir)
    try:
        from zkc_registry import DiscoveryRegistry, RegistryError
    except ImportError as exc:
        findings.error("registry discovery", f"cannot import zkc_registry: {exc}")
        return
    try:
        registry = DiscoveryRegistry.from_repo(repo_root)
    except RegistryError as exc:
        findings.error("registry discovery", str(exc))
        return
    # The verifier-policy schema itself must not define exclusivity fields.
    policy_schema = repo_root / "registry" / "schema" / "verifier-policy.schema.json"
    if policy_schema.is_file():
        scan_forbidden_keys(
            json.loads(policy_schema.read_text()).get("properties", {}),
            str(policy_schema.relative_to(repo_root)),
            findings,
        )
    # Referential sanity (advisory data may reference out-of-registry issuers
    # by design — only structural problems are errors, never absence).
    for policy in registry.verifier_policies():
        if not policy.accepted_proof_types:
            findings.error(policy.source_path, "policy accepts no proof types")


def check_lineage_evolution(
    valid_entries: list, findings: Findings, repo_root: pathlib.Path, all_versions: dict
) -> None:
    """Reject version-ambiguous replacements within one predicate lineage.

    The reference holder/verifier APIs select by proof type and do not yet
    negotiate ``entryVersion``. A later version in the same author-controlled
    lineage must therefore be a fully additive circuit package with a distinct
    proof type. Reuse across *independent* predicateIds remains valid and is
    intentionally outside this check (Freedom Safeguard 1).
    """
    by_lineage = {}
    for predicate_id, version, where, entry in valid_entries:
        by_lineage.setdefault(predicate_id, []).append((version, where, entry))

    for predicate_id, lineage_entries in sorted(by_lineage.items()):
        seen_proof_types = {}
        seen_circuit_names = {}
        seen_source_packages = {}
        seen_encoders = {}
        # Supersession follows the full lineage, including intervening v2
        # source entries. The selector-free uniqueness checks below compare v1 entries.
        versions = sorted(
            (version for version in all_versions[predicate_id] if SEMVER_RE.fullmatch(version)),
            key=semver_key,
        )
        predecessors = dict(zip(versions[1:], versions[:-1]))
        for version, where, entry in sorted(
            lineage_entries, key=lambda item: semver_key(item[0])
        ):
            previous_version = predecessors.get(version)
            if previous_version is not None:
                expected = f"{predicate_id}@{previous_version}"
                actual = entry["activation"]["supersedes"]
                if actual != expected:
                    findings.error(
                        where,
                        "same-lineage successor must set activation.supersedes "
                        f"to its immediate predecessor '{expected}' (observed {actual!r})",
                    )

            for proof_type in entry["proofTypes"]:
                previous = seen_proof_types.get(proof_type)
                if previous is not None:
                    findings.error(
                        where,
                        f"same-lineage proof type '{proof_type}' is already used by "
                        f"{predicate_id}@{previous}; circuit successors require a "
                        "distinct proof type until entry-version selection is supported",
                    )
                else:
                    seen_proof_types[proof_type] = version

            source_package = source_package_reference(
                repo_root, entry["circuit"]["sourcePath"]
            )
            for label, value, seen in (
                ("circuit.name", entry["circuit"]["name"], seen_circuit_names),
                ("circuit source package", source_package, seen_source_packages),
                ("publicInputEncoder", entry["publicInputEncoder"], seen_encoders),
            ):
                previous = seen.get(value)
                if previous is not None:
                    findings.error(
                        where,
                        f"same-lineage {label} '{value}' is already used by "
                        f"{predicate_id}@{previous}; circuit successors must use a new "
                        "source package, generated artifact identity, and encoder",
                    )
                else:
                    seen[value] = version


def validate_registry(
    repo_root: pathlib.Path = ROOT, manifest_path: pathlib.Path = None
) -> Findings:
    findings = Findings()
    _, encoder_errors = encoder_circuits(repo_root)
    for error in encoder_errors:
        findings.error("schemas/public-inputs", error)
    predicates_dir = repo_root / "registry" / "predicates"
    schema_path = repo_root / "registry" / "schema" / "predicate-entry.schema.json"

    # The schema itself must not define exclusivity fields (Safeguard 1).
    for required_schema in (
        schema_path,
        repo_root / "registry" / "schema" / "predicate-entry-v2.schema.json",
        repo_root / "registry" / "schema" / "artifact-binding-v1.schema.json",
    ):
        if required_schema.is_file():
            scan_forbidden_keys(
                json.loads(required_schema.read_text()).get("properties", {}),
                str(required_schema.relative_to(repo_root)),
                findings,
            )
        else:
            findings.error("registry/schema", f"{required_schema.name} missing")

    manifest_circuits = None
    manifest_bindings = None
    if manifest_path is not None:
        if not manifest_path.is_file():
            findings.error("manifest", f"artifact manifest not found: {manifest_path}")
        else:
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest_parsed = True
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                findings.error("manifest", f"artifact manifest is not valid JSON: {exc}")
                manifest = None
                manifest_parsed = False
            circuits = manifest.get("circuits") if isinstance(manifest, dict) else None
            if manifest_parsed and not isinstance(manifest, dict):
                findings.error("manifest", "artifact manifest must contain a JSON object")
            elif isinstance(manifest, dict) and not isinstance(circuits, list):
                findings.error("manifest", "artifact manifest must contain a circuits array")
            elif isinstance(circuits, list):
                manifest_circuits = {}
                if not circuits:
                    findings.error("manifest", "artifact manifest circuits array must not be empty")
                for index, circuit in enumerate(circuits):
                    if not isinstance(circuit, dict) or not isinstance(
                        circuit.get("name"), str
                    ):
                        findings.error(
                            "manifest", f"circuits[{index}] must be a named object"
                        )
                        continue
                    name = circuit["name"]
                    if name in manifest_circuits:
                        findings.error("manifest", f"duplicate circuit name {name!r}")
                    else:
                        manifest_circuits[name] = circuit
                bindings = manifest.get("bindings", [])
                if bindings is not None and not isinstance(bindings, list):
                    findings.error("manifest", "artifact manifest bindings must be an array")
                elif isinstance(bindings, list):
                    manifest_bindings = {}
                    for index, binding in enumerate(bindings):
                        key = binding.get("artifactManifestKey") if isinstance(binding, dict) else None
                        if not isinstance(key, str):
                            findings.error("manifest", f"bindings[{index}] must have artifactManifestKey")
                        elif key in manifest_bindings:
                            findings.error("manifest", f"duplicate artifactManifestKey {key!r}")
                        else:
                            manifest_bindings[key] = binding

    if not predicates_dir.is_dir():
        findings.error("registry/predicates", "directory missing")
        return findings

    # Discover all versions first (supersedes resolution), then validate.
    all_versions = {}
    all_entries = {}
    entry_paths = []
    for entry_path in sorted(predicates_dir.glob("*/*/entry.json")):
        predicate_id = entry_path.parent.parent.name
        version = entry_path.parent.name
        all_versions.setdefault(predicate_id, {})[version] = entry_path
        entry_paths.append((predicate_id, version, entry_path))
        try:
            document = json.loads(entry_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            document = None
        if isinstance(document, dict):
            all_entries[(predicate_id, version)] = document

    if not entry_paths:
        findings.error("registry/predicates", "registry has no entries")

    # Binding child records are the only files permitted beneath a version.
    for stray in sorted(predicates_dir.rglob("*")):
        is_binding = (
            stray.is_file()
            and stray.parent.name == "bindings"
            and stray.suffix == ".json"
            and len(stray.relative_to(predicates_dir).parts) == 4
        )
        if stray.is_file() and stray.name != "entry.json" and not is_binding:
            findings.error(
                str(stray.relative_to(repo_root)),
                "unexpected file (only entry.json and bindings/<bindingId>.json are allowed)",
            )

    valid_entries = []
    for predicate_id, version, entry_path in entry_paths:
        where = str(entry_path.relative_to(repo_root))
        safe_entry_path = resolve_repo_file(
            repo_root, where, "registry entry path", where, findings
        )
        if safe_entry_path is None or not safe_entry_path.is_file():
            if safe_entry_path is not None:
                findings.error(where, "registry entry path is not a regular file")
            continue
        if not SEMVER_RE.fullmatch(version):
            findings.error(where, f"version directory '{version}' is not semver")
            continue
        try:
            entry = json.loads(safe_entry_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            findings.error(where, f"invalid JSON: {exc}")
            continue
        scan_forbidden_keys(entry, where, findings)
        if entry.get("version") == ENTRY_V2:
            if not check_structure_v2(entry, where, findings):
                continue
            check_v2_governance(
                entry, predicate_id, version, where, findings, all_entries, repo_root
            )
            binding_paths = sorted(entry_path.parent.glob("bindings/*.json"))
            if not binding_paths:
                findings.error(where, "v2 source entry must publish at least one artifact binding")
                continue
            loaded_bindings = []
            for binding_path in binding_paths:
                binding_where = str(binding_path.relative_to(repo_root))
                try:
                    binding = json.loads(binding_path.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    findings.error(binding_where, f"invalid binding JSON: {exc}")
                    continue
                scan_forbidden_keys(binding, binding_where, findings)
                if check_binding_structure(binding, binding_where, findings):
                    loaded_bindings.append((binding_where, binding))
            known_ids = {binding["bindingId"] for _, binding in loaded_bindings}
            manifest_keys = [binding["artifactManifestKey"] for _, binding in loaded_bindings]
            if len(manifest_keys) != len(set(manifest_keys)):
                findings.error(where, "v2 entry has duplicate artifactManifestKey values")
            if len(known_ids) != len(loaded_bindings):
                findings.error(where, "v2 entry has duplicate bindingId values")
            for binding_where, binding in loaded_bindings:
                expected_filename = binding["bindingId"].removeprefix("sha256:") + ".json"
                if pathlib.PurePosixPath(binding_where).name != expected_filename:
                    findings.error(binding_where, "binding filename must be its bare bindingId digest")
                check_binding_governance(
                    binding, entry, binding_where, findings, repo_root,
                    manifest_bindings, known_ids,
                )
        else:
            if not check_structure(entry, where, findings):
                continue
            valid_entries.append((predicate_id, version, where, entry))
            check_governance(
                entry, predicate_id, version, where, findings, all_versions,
                repo_root, manifest_circuits,
            )

    check_lineage_evolution(valid_entries, findings, repo_root, all_versions)

    validate_discovery(repo_root, findings)
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        default=None,
        help="artifact manifest to cross-check ACIR/VK hashes against "
        "(defaults to artifacts/build/manifest.json when present)",
    )
    parser.add_argument("--root", default=str(ROOT), help=argparse.SUPPRESS)
    args = parser.parse_args()

    repo_root = pathlib.Path(args.root)
    manifest_path = None
    if args.manifest is not None:
        manifest_path = pathlib.Path(args.manifest)
    else:
        default_manifest = repo_root / "artifacts" / "build" / "manifest.json"
        if default_manifest.is_file():
            manifest_path = default_manifest

    findings = validate_registry(repo_root, manifest_path)
    for error in findings.errors:
        print(f"ERROR {error}", file=sys.stderr)
    entries = len(list((repo_root / "registry" / "predicates").glob("*/*/entry.json")))
    issuers = len(list((repo_root / "registry" / "issuers").glob("*.json")))
    verifiers = len(list((repo_root / "registry" / "verifiers").glob("*.json")))
    if findings.errors:
        print(f"\nregistry INVALID: {len(findings.errors)} error(s)", file=sys.stderr)
        return 1
    cross_check = f", artifact manifest cross-checked ({manifest_path})" if manifest_path else ""
    print(
        f"registry valid: {entries} predicate entr(y/ies), {issuers} issuer(s), "
        f"{verifiers} verifier polic(y/ies){cross_check}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

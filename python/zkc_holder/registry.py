"""Predicate registry (Freedom Safeguard 4).

A predicate is OPAQUE when it cannot be resolved to an inspectable registry
entry — a versioned circuit with committed source and a published
public-input encoder. Inspectable is necessary but not sufficient: the SDK
additionally refuses, by default, entries whose governance review status
does not appear in :data:`DEFAULT_ACCEPTED_STATUSES`, and overriding either
refusal requires an explicit, logged opt-in (see the HolderClient
``allow_opaque`` keyword).

Two statuses are accepted by default — ``reviewed`` and ``self_attested`` —
because both are required by ``registry/validate.py`` to carry PUBLIC review
evidence, so a holder can read exactly how much assurance the entry claims
before using it. They are not equivalent: ``self_attested`` says the author
verified their own entry and that NO independent review occurred, while
``reviewed`` says a non-author review is publicly recorded. A party that
requires independent review says so explicitly — a holder by passing
``accepted_review_statuses=("reviewed",)`` to :class:`HolderClient`, a
verifier by setting ``requiredReviewStatuses: ["reviewed"]`` in its policy,
which a ``self_attested`` entry fails. ``draft``, ``in_review``, and
``deprecated`` entries are always refused by default.

The governed registry is versioned in-repo data:
``registry/predicates/<predicateId>/<entryVersion>/entry.json`` (see
registry/validate.py for the governance rules). When that directory is
absent, the loader falls back to the legacy encoder scan
(``schemas/public-inputs/*.json`` + ``noir/<circuit>/src/main.nr``).

There is no canonical predicate set (Freedom Safeguard 1): registries are
holder-local, any party can publish entries for their own reviewed
predicates, and multiple entries from independent authors may serve the same
proof type. When several entries match, selection is a HOLDER-LOCAL
preference over listings of the same encoder — never a registry-side
blessing. Conflicting encoder/circuit claims fail closed; different statements
need distinct selector-free proof types. Exact v2 binding selection is separate.
"""

from __future__ import annotations

import hashlib
import json
import logging
import pathlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Optional

from zkc_crypto.canonical_set import CANONICAL_SET_PARAM_KEYS
from zkc_crypto.request_parameters import (
    request_parameter_contracts,
    unknown_request_parameters,
)
from zkc_registry.encoder_resolution import encoder_circuits
from zkc_registry.predicate_v2 import (
    BINDING_VERSION,
    ENTRY_VERSION as ENTRY_V2,
    binding_id as compute_binding_id,
    selector_for_binding,
    selector_key,
    source_id as compute_source_id,
)

from .errors import CanonicalSetMismatchError, ConstraintViolationError

__all__ = [
    "PredicateEntry",
    "ArtifactBinding",
    "ResolvedPredicateBinding",
    "BindingResolutionError",
    "PredicateRegistry",
    "REVIEW_STATUSES",
    "DEFAULT_ACCEPTED_STATUSES",
]

logger = logging.getLogger("zkc.holder")

REVIEW_STATUSES = ("draft", "in_review", "self_attested", "reviewed", "deprecated")

# Statuses the SDK will use WITHOUT an explicit opt-in (see module docstring).
# Ordered strongest first: this is also the holder-local resolve() preference.
DEFAULT_ACCEPTED_STATUSES = ("reviewed", "self_attested")

# python/zkc_holder/registry.py -> repository root. Used only for the
# request-parameter vocabulary of a registry constructed without a repo root,
# so in-memory registries built inside this checkout (tests, tooling) keep
# their vocabulary. This is safe only because derivation fails closed: in an
# installed or vendored layout this path holds no encoders or sidecars, every
# non-empty parameter block is then refused, and a deployment must pass
# repo_root (PredicateRegistry.from_repo does) to answer requests at all.
_REFERENCE_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class PredicateEntry:
    proof_type: str
    circuit: str
    encoder_path: str
    source_path: str
    source_sha256: str
    public_inputs: tuple  # ordered (name, abi_type, field_elements)
    # Manifest-pinned UltraHonk vk hash ("0x" + 64 hex chars) for the circuit,
    # or "" when no well-formed pin is available. Aggregation REQUIRES a pin
    # and fails closed on "" — individual proofs do not need it.
    vk_hash: str = ""
    # Governance metadata (registry entries; legacy scan entries use defaults).
    predicate_id: str = ""
    entry_version: str = ""
    author: str = ""
    # Fail closed: an entry constructed without governance metadata claims the
    # weakest status, so it is refused by default rather than assumed sound.
    review_status: str = "draft"
    review_evidence: tuple = ()
    registry_version: str = "zkc:registry:predicate-entry:v1"
    source_id: str = ""
    # Exact VK-byte identity; individual verification need not supply the
    # UltraHonk aggregation hash when it supplies a sha256-pinned key.
    vk_sha256: str = ""

    @property
    def inspectable(self) -> bool:
        """True when the entry pins committed, hash-verified circuit source."""
        return bool(self.source_path and self.source_sha256)

    @property
    def reviewed(self) -> bool:
        """True only for INDEPENDENTLY reviewed entries.

        ``self_attested`` is deliberately False here: the author verifying
        their own entry is not review.
        """
        return self.review_status == "reviewed"

    @property
    def self_attested(self) -> bool:
        """True when the author published evidence of their own verification
        and no independent review has occurred."""
        return self.review_status == "self_attested"

    @property
    def usable_by_default(self) -> bool:
        """True when the SDK will use this entry without an explicit opt-in."""
        return self.review_status in DEFAULT_ACCEPTED_STATUSES


@dataclass(frozen=True)
class ArtifactBinding:
    predicate_id: str
    entry_version: str
    source_id: str
    binding_id: str
    circuit: str
    manifest_key: str
    artifacts: dict
    vk_hash: str
    vk_sha256: str
    acir_hash: str
    toolchain: dict
    build_profile: str
    review_status: str
    review_evidence: tuple
    activated_at: Optional[str]
    supersedes: Optional[str]

    @property
    def selector(self) -> dict:
        return selector_for_binding(
            {
                "predicateId": self.predicate_id,
                "entryVersion": self.entry_version,
                "bindingId": self.binding_id,
            }
        )


@dataclass(frozen=True)
class ResolvedPredicateBinding:
    source: PredicateEntry
    binding: ArtifactBinding


class BindingResolutionError(ValueError):
    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def _well_formed_vk_hash(value) -> str:
    """``value`` when it is a well-formed 0x-prefixed 32-byte hex pin, else ""."""
    if (
        isinstance(value, str)
        and len(value) == 66
        and value.startswith("0x")
        and all(character in "0123456789abcdef" for character in value[2:])
    ):
        return value
    return ""


def _well_formed_sha256(value) -> str:
    if (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    ):
        return value
    return ""


def _manifest_vk_identities(root: pathlib.Path) -> dict:
    """Circuit name -> (UltraHonk hash, byte SHA256) from the committed manifest.

    Empty when the committed manifest is absent or unreadable — affected
    entries then carry no vk pin and aggregation fails closed.
    """
    manifest_path = root / "artifacts" / "manifest.json"
    if not manifest_path.is_file():
        return {}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        logger.warning("unreadable artifact manifest %s; entries carry no vk pin", manifest_path)
        return {}
    vk_hashes = {}
    circuits = manifest.get("circuits") if isinstance(manifest, dict) else None
    for item in circuits if isinstance(circuits, list) else []:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            vk_hash = _well_formed_vk_hash(item.get("vkHash"))
            vk_sha256 = _well_formed_sha256(item.get("vkSha256"))
            if vk_hash or vk_sha256:
                vk_hashes[item["name"]] = (vk_hash, vk_sha256)
    return vk_hashes


def _encoder_public_inputs(encoder) -> Optional[tuple]:
    """Return the holder-facing encoder shape, or None when malformed."""
    if not isinstance(encoder, dict):
        return None
    public_inputs = encoder.get("publicInputs")
    if not isinstance(public_inputs, list) or not public_inputs:
        return None
    normalized = []
    next_offset = 0
    for index, item in enumerate(public_inputs):
        if not isinstance(item, dict):
            return None
        name = item.get("name")
        abi_type = item.get("abiType")
        field_elements = item.get("fieldElements")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(abi_type, str)
            or not abi_type
            or not isinstance(field_elements, int)
            or isinstance(field_elements, bool)
            or field_elements < 1
            or not isinstance(item.get("index"), int)
            or isinstance(item.get("index"), bool)
            or item.get("index") != index
            or not isinstance(item.get("offset"), int)
            or isinstance(item.get("offset"), bool)
            or item.get("offset") != next_offset
            or not isinstance(item.get("description"), str)
        ):
            return None
        normalized.append((name, abi_type, field_elements))
        next_offset += field_elements
    total = encoder.get("totalFieldElements")
    if not isinstance(total, int) or isinstance(total, bool) or total != next_offset:
        return None
    return tuple(normalized)


def _repo_file(root: pathlib.Path, value) -> Optional[pathlib.Path]:
    """Resolve one normalized, non-symlinked path inside ``root``."""
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
        or any(part in ("", ".", "..") for part in value.split("/"))
    ):
        return None
    relative = pathlib.PurePosixPath(value)
    if relative.is_absolute():
        return None
    candidate = root.joinpath(*relative.parts)
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            return None
    try:
        candidate.resolve(strict=False).relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    return candidate


class PredicateRegistry:
    def __init__(
        self, entries, bindings=(), *, circuit_map=None,
        declared_bindings=None, declared_v2_types=(), repo_root=None,
    ):
        self._circuit_map = circuit_map
        # Repository whose binding sidecars define the closed request-parameter
        # vocabulary. A registry built in memory without one uses the
        # reference repository these packages ship in.
        self._repo_root = (
            pathlib.Path(repo_root) if repo_root is not None else _REFERENCE_REPO_ROOT
        )
        self._request_parameter_contracts = None
        self._request_parameter_contract_failure = None
        self._by_proof_type = {}
        self._v2_sources = {}
        for entry in entries:
            if entry.registry_version == ENTRY_V2:
                self._v2_sources[(entry.predicate_id, entry.entry_version, entry.proof_type)] = entry
            else:
                self._by_proof_type.setdefault(entry.proof_type, []).append(entry)
        self._bindings_by_selector = {
            (binding.predicate_id, binding.entry_version, binding.binding_id): binding
            for binding in bindings
        }
        # Keep declarations separately from admitted bindings. The loader may
        # exclude a binding whose manifest row is missing; its declared VK
        # still prevents a verifier from treating that artifact as pure v1.
        if declared_bindings is None:
            declared_bindings = (
                {
                    "predicateId": binding.predicate_id,
                    "entryVersion": binding.entry_version,
                    "sourceId": binding.source_id,
                    "bindingId": binding.binding_id,
                    "circuit": binding.circuit,
                    "acirHash": binding.acir_hash,
                    "vkSha256": binding.vk_sha256,
                    "vkHash": binding.vk_hash,
                }
                for binding in bindings
            )
        self._declared_binding_rows = tuple(declared_bindings)
        self._declared_v2_types = frozenset(declared_v2_types)
        # Deterministic, holder-local ordering — NOT a registry ranking.
        for candidates in self._by_proof_type.values():
            candidates.sort(key=lambda e: (e.predicate_id, e.entry_version, e.circuit))

    @classmethod
    def from_repo(cls, repo_root) -> "PredicateRegistry":
        """Load the governed registry when present, else the legacy scan."""
        root = pathlib.Path(repo_root)
        if (root / "registry" / "predicates").is_dir():
            return cls.from_registry_dir(root)
        return cls._from_encoder_scan(root)

    @classmethod
    def from_registry_dir(cls, repo_root) -> "PredicateRegistry":
        """Load entries from registry/predicates/<id>/<version>/entry.json.

        Fail closed: entries whose pinned source is missing or whose source
        hash no longer matches the committed circuit are EXCLUDED (their proof
        types stay opaque unless another entry covers them).
        """
        root = pathlib.Path(repo_root)
        predicates_dir = root / "registry" / "predicates"
        if not predicates_dir.is_dir():
            raise FileNotFoundError(f"no predicate registry at {predicates_dir}")
        entries = []
        bindings = []
        declared_bindings = []
        declared_v2_types = set()
        for entry_path in sorted(predicates_dir.glob("*/*/entry.json")):
            safe_entry_path = _repo_file(root, entry_path.relative_to(root).as_posix())
            if safe_entry_path is None:
                logger.warning("skipping registry entry with unsafe path %s", entry_path)
                continue
            try:
                document = json.loads(safe_entry_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                logger.warning("skipping unparseable registry entry %s", entry_path)
                continue
            if not isinstance(document, dict):
                logger.warning("skipping non-object registry entry %s", entry_path)
                continue
            if document.get("version") == ENTRY_V2:
                raw_types = document.get("proofTypes")
                if isinstance(raw_types, list):
                    declared_v2_types.update(
                        proof_type for proof_type in raw_types
                        if isinstance(proof_type, str)
                    )
                for path in sorted(safe_entry_path.parent.glob("bindings/*.json")):
                    safe_path = _repo_file(root, path.relative_to(root).as_posix())
                    if safe_path is None:
                        continue
                    try:
                        declared = json.loads(safe_path.read_text(encoding="utf-8"))
                    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if isinstance(declared, dict):
                        declared_bindings.append(declared)
                loaded_entries, loaded_bindings = cls._load_v2_source(root, safe_entry_path, document)
                entries.extend(loaded_entries)
                bindings.extend(loaded_bindings)
                continue
            circuit = document.get("circuit")
            if not isinstance(circuit, dict) or not isinstance(circuit.get("name"), str):
                logger.warning("skipping registry entry %s: malformed circuit", entry_path)
                continue
            source_path = _repo_file(root, circuit.get("sourcePath"))
            if source_path is None:
                logger.warning(
                    "skipping registry entry %s: circuit source path is unsafe "
                    "(must be repository-relative and non-symlinked)",
                    entry_path,
                )
                continue
            if not source_path.is_file():
                logger.warning(
                    "skipping registry entry %s: circuit source missing (not inspectable)",
                    entry_path,
                )
                continue
            actual_hash = hashlib.sha256(source_path.read_bytes()).hexdigest()
            if actual_hash != circuit.get("sourceSha256"):
                logger.warning(
                    "skipping registry entry %s: circuit source hash mismatch "
                    "(committed identity and referenced source bytes are immutable; "
                    "restore them or publish an additive circuit package)",
                    entry_path,
                )
                continue
            encoder_path = _repo_file(root, document.get("publicInputEncoder"))
            if encoder_path is None:
                logger.warning(
                    "skipping registry entry %s: public-input encoder path is unsafe "
                    "(must be repository-relative and non-symlinked)",
                    entry_path,
                )
                continue
            if not encoder_path.is_file():
                logger.warning(
                    "skipping registry entry %s: public-input encoder missing", entry_path
                )
                continue
            try:
                encoder = json.loads(encoder_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                logger.warning(
                    "skipping registry entry %s: public-input encoder is not valid JSON",
                    entry_path,
                )
                continue
            proof_types = document.get("proofTypes")
            encoder_proof_types = encoder.get("proofTypes") if isinstance(encoder, dict) else None
            public_inputs = _encoder_public_inputs(encoder)
            predicate_id = document.get("predicateId")
            entry_version = document.get("entryVersion")
            author = document.get("author")
            review = document.get("review")
            evidence = review.get("evidence") if isinstance(review, dict) else None
            if (
                not isinstance(proof_types, list)
                or not proof_types
                or not all(isinstance(item, str) for item in proof_types)
                or not isinstance(predicate_id, str)
                or not predicate_id
                or not isinstance(entry_version, str)
                or not entry_version
                or not isinstance(author, dict)
                or not isinstance(author.get("name"), str)
                or not author["name"]
                or not isinstance(review, dict)
                or not isinstance(evidence, list)
                or not all(isinstance(item, str) and item for item in evidence)
                or not isinstance(encoder, dict)
                or encoder.get("version") != "zkc:public-inputs:v1"
                or encoder.get("circuit") != circuit["name"]
                or encoder.get("proofSystem") != circuit.get("scheme")
                or encoder.get("curve") != "BN254"
                or not isinstance(encoder_proof_types, list)
                or not all(isinstance(item, str) for item in encoder_proof_types)
                or not all(item in encoder_proof_types for item in proof_types)
                or public_inputs is None
            ):
                logger.warning(
                    "skipping registry entry %s: malformed registry metadata or "
                    "inconsistent public-input encoder",
                    entry_path,
                )
                continue
            status = review.get("status", "")
            if status not in REVIEW_STATUSES:
                logger.warning(
                    "skipping registry entry %s: unknown review status %r", entry_path, status
                )
                continue
            for proof_type in proof_types:
                entries.append(
                    PredicateEntry(
                        proof_type=proof_type,
                        circuit=circuit["name"],
                        encoder_path=str(encoder_path.relative_to(root)),
                        source_path=str(source_path.relative_to(root)),
                        source_sha256=actual_hash,
                        vk_hash=_well_formed_vk_hash(circuit.get("vkHash")),
                        vk_sha256=_well_formed_sha256(circuit.get("vkSha256")),
                        public_inputs=public_inputs,
                        predicate_id=predicate_id,
                        entry_version=entry_version,
                        author=author["name"],
                        review_status=status,
                        review_evidence=tuple(evidence),
                    )
                )
        return cls(
            entries, bindings,
            circuit_map=encoder_circuits(root)[0],
            declared_bindings=declared_bindings,
            declared_v2_types=declared_v2_types,
            repo_root=root,
        )

    @classmethod
    def _load_v2_source(cls, root, entry_path, document):
        """Load one normalized v2 source and its immutable child bindings."""
        try:
            source = document["source"]
            contract = document["publicInputContract"]
            if compute_source_id(document) != document["sourceId"]:
                raise ValueError("sourceId mismatch")
            if set(source) != {"circuit", "packageRoot", "files"}:
                raise ValueError("malformed source manifest")
            for pin in [*source["files"], *contract.values()]:
                path = _repo_file(root, pin["path"])
                if path is None or not path.is_file():
                    raise ValueError(f"missing or unsafe pinned file {pin.get('path')}")
                actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
                if actual != pin["sha256"]:
                    raise ValueError(f"pinned file digest mismatch {pin['path']}")
            encoder_path = _repo_file(root, contract["encoder"]["path"])
            encoder = json.loads(encoder_path.read_text(encoding="utf-8"))
            public_inputs = _encoder_public_inputs(encoder)
            proof_types = document["proofTypes"]
            if (
                public_inputs is None
                or encoder.get("circuit") != source["circuit"]
                or not all(proof_type in encoder.get("proofTypes", []) for proof_type in proof_types)
            ):
                raise ValueError("v2 public-input contract is inconsistent")
            review = document["review"]
            source_entries = [
                PredicateEntry(
                    proof_type=proof_type,
                    circuit=source["circuit"],
                    encoder_path=contract["encoder"]["path"],
                    source_path=f"{source['packageRoot']}/src/main.nr",
                    source_sha256=next(
                        pin["sha256"].removeprefix("sha256:")
                        for pin in source["files"]
                        if pin["path"] == f"{source['packageRoot']}/src/main.nr"
                    ),
                    public_inputs=public_inputs,
                    predicate_id=document["predicateId"],
                    entry_version=document["entryVersion"],
                    author=document["author"]["name"],
                    review_status=review["status"],
                    review_evidence=tuple(review["evidence"]),
                    registry_version=ENTRY_V2,
                    source_id=document["sourceId"],
                )
                for proof_type in proof_types
            ]
        except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as exc:
            logger.warning("skipping malformed v2 registry source %s: %s", entry_path, exc)
            return [], []

        manifest_bindings = {}
        manifest_path = root / "artifacts" / "manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest_bindings = {
                item["artifactManifestKey"]: item
                for item in manifest.get("bindings", [])
                if isinstance(item, dict) and isinstance(item.get("artifactManifestKey"), str)
            }
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            pass

        bindings = []
        for path in sorted(entry_path.parent.glob("bindings/*.json")):
            try:
                binding = json.loads(path.read_text(encoding="utf-8"))
                if binding.get("version") != BINDING_VERSION:
                    raise ValueError("unsupported binding version")
                if compute_binding_id(binding) != binding["bindingId"]:
                    raise ValueError("bindingId mismatch")
                if (
                    (binding["predicateId"], binding["entryVersion"])
                    != (document["predicateId"], document["entryVersion"])
                    or binding["sourceId"] != document["sourceId"]
                    or binding["circuit"] != source["circuit"]
                ):
                    raise ValueError("cross-wired binding parent")
                manifest_binding = manifest_bindings.get(binding["artifactManifestKey"])
                if manifest_binding is None:
                    raise ValueError("binding absent from artifact manifest")
                for field in (
                    "predicateId", "entryVersion", "sourceId", "bindingId", "circuit",
                    "scheme", "toolchain", "buildProfile", "artifactManifestKey", "artifacts",
                    "acirHash", "vkHash", "vkSha256",
                ):
                    if manifest_binding.get(field) != binding[field]:
                        raise ValueError(f"artifact manifest disagrees on {field}")
                review = binding["review"]
                activation = binding["activation"]
                bindings.append(
                    ArtifactBinding(
                        predicate_id=binding["predicateId"],
                        entry_version=binding["entryVersion"],
                        source_id=binding["sourceId"],
                        binding_id=binding["bindingId"],
                        circuit=binding["circuit"],
                        manifest_key=binding["artifactManifestKey"],
                        artifacts=dict(binding["artifacts"]),
                        vk_hash=_well_formed_vk_hash(binding["vkHash"]),
                        vk_sha256=binding["vkSha256"],
                        acir_hash=binding["acirHash"],
                        toolchain=dict(binding["toolchain"]),
                        build_profile=binding["buildProfile"],
                        review_status=review["status"],
                        review_evidence=tuple(review["evidence"]),
                        activated_at=activation["activatedAt"],
                        supersedes=activation["supersedes"],
                    )
                )
            except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as exc:
                logger.warning("skipping malformed v2 binding %s: %s", path, exc)
        return source_entries, bindings

    @classmethod
    def _from_encoder_scan(cls, root: pathlib.Path) -> "PredicateRegistry":
        encoder_dir = root / "schemas" / "public-inputs"
        if not encoder_dir.is_dir():
            raise FileNotFoundError(f"no public-input encoders at {encoder_dir}")
        vk_hashes = _manifest_vk_identities(root)
        entries = []
        for encoder_path in sorted(encoder_dir.glob("*.json")):
            try:
                encoder = json.loads(encoder_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            public_inputs = _encoder_public_inputs(encoder)
            if (
                not isinstance(encoder, dict)
                or not isinstance(encoder.get("circuit"), str)
                or not isinstance(encoder.get("proofTypes"), list)
                or not all(isinstance(item, str) for item in encoder["proofTypes"])
                or public_inputs is None
            ):
                continue
            circuit = encoder["circuit"]
            source_path = root / "noir" / circuit / "src" / "main.nr"
            if not source_path.is_file():
                # An encoder without inspectable source is not reviewable;
                # skip it (fail closed: its proof types stay opaque).
                continue
            source_sha256 = hashlib.sha256(source_path.read_bytes()).hexdigest()
            for proof_type in encoder["proofTypes"]:
                entries.append(
                    PredicateEntry(
                        proof_type=proof_type,
                        circuit=circuit,
                        encoder_path=str(encoder_path.relative_to(root)),
                        source_path=str(source_path.relative_to(root)),
                        source_sha256=source_sha256,
                        vk_hash=vk_hashes.get(circuit, ("", ""))[0],
                        vk_sha256=vk_hashes.get(circuit, ("", ""))[1],
                        public_inputs=public_inputs,
                        # The legacy scan only admits inspectable, hash-pinned
                        # in-repo circuits. Nothing about that is review, by
                        # anyone — so these entries are self-attested, never
                        # 'reviewed'.
                        review_status="self_attested",
                    )
                )
        return cls(entries, circuit_map=encoder_circuits(root)[0], repo_root=root)

    # ------------------------------------------------------------------

    def resolve(
        self,
        proof_type: str,
        preferred_predicate_id: str = None,
        *,
        accepted_statuses: tuple = DEFAULT_ACCEPTED_STATUSES,
        allow_unaccepted: bool = False,
    ) -> Optional[PredicateEntry]:
        """Pick ONE entry for a proof type — a holder-local choice.

        Ambiguous circuit/encoder identities always return None, including
        when a preferred predicateId is supplied. Among listings of the same
        identity, preference order is an explicit predicateId, then the
        strongest accepted assurance status (``reviewed`` before
        ``self_attested``, per :data:`DEFAULT_ACCEPTED_STATUSES`, then any
        other status in ``accepted_statuses``), with a deterministic
        tie-break. The registry itself never ranks or blesses entries
        (Safeguard 1) — this ordering is the holder's own, and any entry can
        be selected explicitly.

        Fail closed (Safeguard 4): when no entry has an accepted status this
        returns ``None``, never a silent fallback to a ``draft`` /
        ``in_review`` / ``deprecated`` entry. ``allow_unaccepted=True``
        returns the deterministic first entry instead; it is for callers
        that inspect the status or apply their own explicit, logged override.
        """
        candidates = self._by_proof_type.get(proof_type, [])
        if not candidates:
            return None
        # Discovery preferences can choose assurance metadata, never a different
        # circuit behind the same selector-free wire identity.
        circuits = {entry.circuit for entry in candidates}
        if len(circuits) != 1:
            return None
        if self._circuit_map is not None and self._circuit_map.get(proof_type) not in circuits:
            return None
        if preferred_predicate_id is not None:
            for entry in candidates:
                if entry.predicate_id == preferred_predicate_id:
                    return entry
            return None
        accepted = tuple(accepted_statuses)
        ladder = tuple(s for s in DEFAULT_ACCEPTED_STATUSES if s in accepted) + tuple(
            s for s in accepted if s not in DEFAULT_ACCEPTED_STATUSES
        )
        for status in ladder:
            for entry in candidates:
                if entry.review_status == status:
                    return entry
        return candidates[0] if allow_unaccepted else None

    def resolve_all(self, proof_type: str) -> tuple:
        """ALL entries serving a proof type (predicate pluralism): callers
        choose; the registry never returns a single blessed entry."""
        return tuple(self._by_proof_type.get(proof_type, []))

    def has_v2_source(self, proof_type: str) -> bool:
        """Whether a loaded or declared entry-v2 source publishes this type."""
        return proof_type in self._declared_v2_types or any(
            key[2] == proof_type for key in self._v2_sources
        )

    def declared_binding_vk_candidates(self, vk_sha256, vk_hash) -> tuple:
        """Raw governed declarations sharing a present VK pin, admitted or not."""
        return tuple(
            entry
            for entry in self._declared_binding_rows
            if (vk_sha256 is not None and entry.get("vkSha256") == vk_sha256)
            or (vk_hash is not None and entry.get("vkHash") == vk_hash)
        )

    def binding_vk_candidates(self, vk_sha256, vk_hash) -> tuple:
        """All binding records sharing a present legacy VK pin, across proof types.

        The caller must require one exact match before applying policy. A
        partial match is retained so inconsistent metadata cannot be ignored.
        """
        return tuple(
            binding
            for binding in self._bindings_by_selector.values()
            if (vk_sha256 is not None and binding.vk_sha256 == vk_sha256)
            or (vk_hash is not None and binding.vk_hash == vk_hash)
        )

    def binding_proof_types(self, selector: dict) -> tuple:
        """Proof types whose exact v2 source publishes this binding."""
        try:
            key = selector_key(selector)
        except ValueError:
            return ()
        binding = self._bindings_by_selector.get(key)
        if binding is None:
            return ()
        return tuple(sorted(
            proof_type
            for (predicate_id, entry_version, proof_type), source in self._v2_sources.items()
            if (predicate_id, entry_version) == key[:2]
            and source.source_id == binding.source_id
            and source.circuit == binding.circuit
        ))

    def binding_source(self, proof_type: str, selector: dict) -> Optional[PredicateEntry]:
        """The exact v2 source publishing one binding and proof type, if any."""
        try:
            key = selector_key(selector)
        except ValueError:
            return None
        binding = self._bindings_by_selector.get(key)
        source = self._v2_sources.get((*key[:2], proof_type))
        if (
            binding is None
            or source is None
            or binding.source_id != source.source_id
            or binding.circuit != source.circuit
        ):
            return None
        return source

    def resolve_binding(
        self,
        proof_type: str,
        selector: dict,
        *,
        accepted_source_statuses=DEFAULT_ACCEPTED_STATUSES,
        accepted_binding_statuses=DEFAULT_ACCEPTED_STATUSES,
        allowed_binding_ids=(),
        allow_inactive: bool = False,
    ) -> ResolvedPredicateBinding:
        """Resolve one exact v2 tuple in O(1), with no fallback or key trial."""
        try:
            key = selector_key(selector)
        except ValueError as exc:
            raise BindingResolutionError("malformed", str(exc)) from exc
        binding = self._bindings_by_selector.get(key)
        if binding is None:
            raise BindingResolutionError("unknown", "binding selector is not registered")
        source = self._v2_sources.get((binding.predicate_id, binding.entry_version, proof_type))
        if source is None:
            raise BindingResolutionError(
                "cross_wired", "selected binding does not publish the requested proof type"
            )
        if binding.source_id != source.source_id or binding.circuit != source.circuit:
            raise BindingResolutionError("cross_wired", "binding source identity is cross-wired")
        if source.review_status == "deprecated" or binding.review_status == "deprecated":
            raise BindingResolutionError("deprecated", "selected source or binding is deprecated")
        if accepted_source_statuses and source.review_status not in tuple(accepted_source_statuses):
            raise BindingResolutionError(
                "source_review",
                f"source review status {source.review_status!r} is not accepted",
            )
        if accepted_binding_statuses and binding.review_status not in tuple(accepted_binding_statuses):
            raise BindingResolutionError(
                "binding_review",
                f"binding review status {binding.review_status!r} is not accepted",
            )
        if not allow_inactive and binding.activated_at is None:
            raise BindingResolutionError("inactive", "selected binding is inactive")
        if allowed_binding_ids and binding.binding_id not in set(allowed_binding_ids):
            raise BindingResolutionError("disallowed", "selected binding is not locally allowed")
        return ResolvedPredicateBinding(source=source, binding=binding)

    def bindings_for(self, predicate_id: str, entry_version: str, proof_type: str) -> tuple:
        """Return exact local candidates; caller policy decides lifecycle acceptance."""
        source = self._v2_sources.get((predicate_id, entry_version, proof_type))
        if source is None:
            return ()
        return tuple(
            binding
            for key, binding in self._bindings_by_selector.items()
            if key[:2] == (predicate_id, entry_version)
            and binding.source_id == source.source_id
        )

    def artifact_review_statuses(self, vk_hash: str = "", *, vk_sha256: str = "") -> tuple:
        """Source and build statuses of ALL admitted identities publishing a VK.

        A v1 entry publishes its own key; a v2 source publishes keys only
        through its exact child bindings. Source/encoder equality alone is
        insufficient: different toolchain builds can have different keys.
        This is an inventory, not a ranking or a policy decision.
        """
        key_hash = _well_formed_vk_hash(vk_hash)
        byte_hash = _well_formed_sha256(vk_sha256)
        if not key_hash and not byte_hash:
            return (), ()

        def publishes_key(identity):
            return bool(
                (key_hash and identity.vk_hash == key_hash)
                or (byte_hash and identity.vk_sha256 == byte_hash)
            )

        source_statuses = {
            entry.review_status
            for entries in self._by_proof_type.values()
            for entry in entries
            if publishes_key(entry)
        }
        binding_statuses = set()
        for binding in self._bindings_by_selector.values():
            if not publishes_key(binding):
                continue
            sources = [
                source for source in self._v2_sources.values()
                if (source.predicate_id, source.entry_version, source.source_id, source.circuit)
                == (binding.predicate_id, binding.entry_version, binding.source_id, binding.circuit)
            ]
            if sources:
                source_statuses.update(source.review_status for source in sources)
                binding_statuses.add(binding.review_status)
        return tuple(sorted(source_statuses)), tuple(sorted(binding_statuses))

    def statuses(self, proof_type: str) -> tuple:
        """Review statuses of every entry serving a proof type."""
        return tuple(entry.review_status for entry in self.resolve_all(proof_type))

    def inspectable(self, proof_type: str) -> bool:
        return any(entry.inspectable for entry in self.resolve_all(proof_type))

    def reviewed(self, proof_type: str) -> bool:
        """True when some entry serving this proof type is INDEPENDENTLY
        reviewed. Self-attested entries do not satisfy this."""
        return any(entry.reviewed for entry in self.resolve_all(proof_type))

    def usable_by_default(self, proof_type: str) -> bool:
        """True when some entry serving this proof type may be used without an
        explicit opt-in (see :data:`DEFAULT_ACCEPTED_STATUSES`)."""
        return any(entry.usable_by_default for entry in self.resolve_all(proof_type))

    def proof_types(self) -> list:
        return sorted(self._by_proof_type)

    def request_parameter_contracts(self) -> tuple[dict, dict]:
        """``(proofType -> closed key set, proofType -> contract error)``.

        Derived once from the repository's binding sidecars plus the
        documented request-only keys (``zkc_crypto.request_parameters``),
        for every proof type a selector-free encoder declares. Fail closed:
        if the repository has no encoders, or encoder resolution reports any
        error, no proof type gets a set. Callers must refuse a proof type
        with no set rather than treat it as unconstrained."""
        if self._request_parameter_contracts is None:
            derived_map, encoder_errors = encoder_circuits(self._repo_root)
            circuit_map = self._circuit_map if self._circuit_map is not None else derived_map
            contracts, errors = request_parameter_contracts(self._repo_root, circuit_map)
            failure = None
            if encoder_errors:
                failure = (
                    f"public-input encoder resolution under {self._repo_root} reported "
                    f"errors: {'; '.join(encoder_errors)}"
                )
            elif not circuit_map:
                failure = f"no public-input encoders under {self._repo_root}"
            if failure is not None:
                contracts = {}
            self._request_parameter_contract_failure = failure
            self._request_parameter_contracts = (contracts, errors)
        return self._request_parameter_contracts

    def _request_parameter_contract_error(self, proof_type: str) -> str:
        _contracts, errors = self.request_parameter_contracts()
        return (
            errors.get(proof_type)
            or self._request_parameter_contract_failure
            or f"no public-input encoder under {self._repo_root} declares it"
        )

    def refuse_unknown_request_parameters(
        self, proof_types, parameters, where: str = "proof request", resolve=None
    ) -> None:
        """Refuse a request whose parameter table is outside the closed
        vocabulary (spec section 6.2.1).

        * The table must be a mapping, and every key must be a proof type the
          request lists. A block for an unlisted proof type is never read, so
          a requirement stated there would be dropped.
        * Each requested block is checked against the closed set of every
          proof type ``resolve(proof_type)`` returns: the identity the holder
          will actually emit, whose vocabulary the verifier enforces. Without
          ``resolve`` the requested identity itself is used.
        * A non-empty block whose emitted identity has no derivable set is
          refused (fail closed). An absent or empty block names no key, so
          there is nothing to drop; the opaque/review gates still apply.
        * A non-mapping block is left to the existing shape checks.

        Callers run this AFTER ``refuse_secret_parameters`` so a
        secret-bearing request keeps its ``SECRET_IN_REQUEST`` refusal. A
        misplaced canonical-set key keeps ``CANONICAL_SET_MISMATCH``. The
        diagnostic names keys and proof types, never values."""
        if not isinstance(parameters, Mapping):
            raise ConstraintViolationError(f"{where}: request parameters must be a JSON object")
        requested = [
            item for item in (proof_types if isinstance(proof_types, (list, tuple)) else ())
            if isinstance(item, str)
        ]
        unrequested = sorted(repr(key) for key in parameters if key not in requested)
        if unrequested:
            raise ConstraintViolationError(
                f"{where} supplies parameters for proof type(s) it does not request: "
                f"{', '.join(unrequested)}"
            )
        contracts, _errors = self.request_parameter_contracts()
        for proof_type in dict.fromkeys(requested):
            block = parameters.get(proof_type)
            if not isinstance(block, Mapping) or not block:
                continue
            governing = tuple(resolve(proof_type)) if resolve is not None else (proof_type,)
            for contract_type in governing:
                accepted = contracts.get(contract_type)
                if accepted is None:
                    raise ConstraintViolationError(
                        f"{where}: the request-parameter contract for {contract_type} "
                        f"(requested as {proof_type}) is unavailable "
                        f"({self._request_parameter_contract_error(contract_type)}); "
                        "refusing to prove"
                    )
                unknown = unknown_request_parameters(accepted, block)
                # A reserved canonical-set key on a proof type that does not
                # read it keeps its established CANONICAL_SET_MISMATCH refusal,
                # the holder-side mirror of the verifier's ordering.
                misplaced = [key for key in CANONICAL_SET_PARAM_KEYS if key in unknown]
                if misplaced:
                    raise CanonicalSetMismatchError(
                        f"request supplies unsupported canonical-set parameter(s) "
                        f"{', '.join(repr(key) for key in misplaced)} for {proof_type}"
                    )
                if unknown:
                    alias = "" if contract_type == proof_type else f" (answered as {contract_type})"
                    raise ConstraintViolationError(
                        f"{where} supplies unknown parameter(s) "
                        f"{', '.join(repr(key) for key in unknown)} for {proof_type}{alias}; "
                        f"its request-binding contract accepts only "
                        f"{', '.join(repr(key) for key in sorted(accepted)) or 'no parameters'}"
                    )

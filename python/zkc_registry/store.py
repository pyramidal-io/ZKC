"""Discovery registry store: loading, validation, and lookup.

Fail closed: malformed documents and duplicate identifiers abort loading
with a structured error — a discovery registry that silently drops or
shadows documents could be used to steer holders, which is exactly the
chokepoint this registry must not become.
"""

from __future__ import annotations

import json
import pathlib
import re
from dataclasses import dataclass
from typing import Optional

from zkc_crypto.digests import LEGACY_SELECTIVE_DISCLOSURE_PROOF_TYPES, parse_attribute_layout_id
from zkc_crypto.code_spaces import CODE_SPACE_CREDENTIAL_TO_KIND, get_code_space

__all__ = [
    "RegistryError",
    "RegistryValidationError",
    "DuplicateRegistryIdError",
    "IssuerDocument",
    "VerifierPolicyDocument",
    "DiscoveryRegistry",
    "to_holder_trust_policy",
    "to_verifier_trust_policy",
]

ISSUER_ID_RE = re.compile(r"^zkc:issuer:[a-z0-9._-]+$")
VERIFIER_ID_RE = re.compile(r"^[a-z0-9:._-]+$")
PROOF_TYPE_RE = re.compile(r"^zkc:proof:[a-z0-9._-]+:v[0-9]+$")
KEY_COORD_RE = re.compile(r"^0x[0-9a-f]{64}$")
UNCOMPRESSED_KEY_RE = re.compile(r"^0x[0-9a-f]{128}$")
REVIEW_STATUSES = ("draft", "in_review", "self_attested", "reviewed", "deprecated")
PROTOCOL_MAX_EPOCH_LAG = 10

# Freedom Safeguard 1: no discovery document may assert exclusivity.
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


class RegistryError(Exception):
    """Base class for discovery registry errors."""


class RegistryValidationError(RegistryError):
    pass


class DuplicateRegistryIdError(RegistryError):
    pass


def _require(condition: bool, where: str, message: str) -> None:
    if not condition:
        raise RegistryValidationError(f"{where}: {message}")


def _scan_forbidden_keys(node, where: str, path: str = "") -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            _require(
                key.lower() not in FORBIDDEN_KEYS,
                where,
                f"forbidden exclusivity key '{path}{key}' (Freedom Safeguard 1)",
            )
            _scan_forbidden_keys(value, where, f"{path}{key}.")
    elif isinstance(node, list):
        for index, item in enumerate(node):
            _scan_forbidden_keys(item, where, f"{path}{index}.")


@dataclass(frozen=True)
class IssuerDocument:
    """A published issuer metadata document (discovery only — listing an
    issuer here grants it NOTHING; see schemas/issuer-metadata.schema.json)."""

    issuer_id: str
    display_name: str
    signing_keys: tuple  # of (key_id, scheme, public_key_hex)
    supported_schemas: tuple  # of (schema_id, credential_type, proof_type)
    source_path: str
    raw: dict = None

    def proof_types(self) -> tuple:
        return tuple(sorted({schema[2] for schema in self.supported_schemas}))

    def schema_ids(self) -> tuple:
        return tuple(sorted({schema[0] for schema in self.supported_schemas}))

    def credential_types(self) -> tuple:
        return tuple(sorted({schema[1] for schema in self.supported_schemas}))

    def public_keys(self) -> tuple:
        """(x_bytes, y_bytes) for each uncompressed secp256k1 signing key."""
        keys = []
        for _key_id, scheme, public_key in self.signing_keys:
            if scheme == "ECDSA_SECP256K1" and UNCOMPRESSED_KEY_RE.fullmatch(public_key):
                blob = bytes.fromhex(public_key.removeprefix("0x"))
                keys.append((blob[:32], blob[32:]))
        return tuple(keys)


@dataclass(frozen=True)
class TrustedIssuerRef:
    """A key-exact allowlist entry inside a published verifier policy. The
    issuer is referenced BY KEY: it does not have to exist in any registry."""

    issuer_id: str
    public_key_x: str
    public_key_y: str
    proof_types: tuple
    attribute_layout_id: Optional[str] = None


@dataclass(frozen=True)
class VerifierPolicyDocument:
    """A verifier's published trust policy (discovery only; the verifier
    enforces it locally — publication grants and removes nothing)."""

    verifier_id: str
    display_name: str
    accepted_proof_types: tuple
    required_review_statuses: tuple
    trusted_issuers: tuple  # of TrustedIssuerRef
    accepts_out_of_registry_issuers: bool
    required_context_profile: str
    max_epoch_lag: int
    source_path: str
    raw: dict = None

    def trusts_issuer_key(self, public_key_x: bytes, public_key_y: bytes, proof_type: str) -> bool:
        for ref in self.trusted_issuers:
            if (
                bytes.fromhex(ref.public_key_x.removeprefix("0x")) == public_key_x
                and bytes.fromhex(ref.public_key_y.removeprefix("0x")) == public_key_y
                and proof_type in ref.proof_types
            ):
                return True
        return False

    def trusts_issuer_id(self, issuer_id: str, proof_type: str) -> bool:
        return any(
            ref.issuer_id == issuer_id and proof_type in ref.proof_types
            for ref in self.trusted_issuers
        )

    def proof_requirements(self) -> dict:
        """Published per-predicate minimums (`proofRequirements`, optional).

        Maps proof type → its minimum parameters (e.g. {"requiredLevel": 1,
        "requiredAttributes": [...]}). When present, this is the COMPLETE
        statement of the verifier's need: holders plan minimal disclosure
        against it, and requests beyond it are overbroad. An absent section
        means the policy publishes no parameter minimums (nothing to narrow
        against). Discovery only — the verifier still enforces locally.
        """
        if not isinstance(self.raw, dict):
            return {}
        requirements = self.raw.get("proofRequirements") or {}
        return {proof_type: dict(minimum) for proof_type, minimum in requirements.items()}


def validate_issuer_document(document: dict, where: str) -> None:
    _require(isinstance(document, dict), where, "not a JSON object")
    _scan_forbidden_keys(document, where)
    _require(
        document.get("version") in {"zkc:issuer-metadata:v1", "zkc:issuer-metadata:v2"},
        where,
        "bad metadata version",
    )
    _require(
        ISSUER_ID_RE.fullmatch(str(document.get("issuerId", ""))) is not None,
        where,
        f"bad issuerId {document.get('issuerId')!r}",
    )
    _require(bool(document.get("displayName")), where, "missing displayName")
    keys = document.get("signingKeys")
    _require(isinstance(keys, list) and keys, where, "missing signing keys")
    layout_pins = {}
    for key in keys:
        _require(
            key.get("scheme") in {"ECDSA_SECP256K1", "BLS", "Schnorr"},
            where,
            "unsupported key scheme",
        )
        _require(bool(key.get("keyId")), where, "signing key missing keyId")
        _require(isinstance(key.get("publicKey"), str) and bool(key["publicKey"]), where,
                 "signing key missing publicKey")
        if "attributeLayoutId" in key:
            layout_id = key["attributeLayoutId"]
            try:
                parse_attribute_layout_id(layout_id)
            except ValueError as exc:
                _require(False, where, f"signing key attributeLayoutId is invalid: {exc}")
            identity = key["scheme"], key["publicKey"].lower()
            _require(layout_pins.setdefault(identity, layout_id) == layout_id, where,
                     "one issuer signing key declares conflicting attribute layouts")
    schemas = document.get("supportedSchemas")
    _require(isinstance(schemas, list) and schemas, where, "missing supportedSchemas")
    bound_schemas = set()
    for schema in schemas:
        _require(isinstance(schema, dict), where, "supportedSchemas entry must be an object")
        for field in ("schemaId", "credentialType", "proofType"):
            _require(isinstance(schema.get(field), str) and bool(schema[field]), where,
                     f"supportedSchemas entry missing {field}")
        if schema["credentialType"] == "zkc:cred:attribute-set:v1":
            _require(bool(layout_pins), where, "legacy attribute-set metadata requires a signing key layout")
        schema_id = schema["schemaId"]
        kind = CODE_SPACE_CREDENTIAL_TO_KIND.get(schema_id)
        if kind is None:
            _require("codeSpaceIds" not in schema, where, "codeSpaceIds requires a code-space schema")
            _require(schema["credentialType"] not in CODE_SPACE_CREDENTIAL_TO_KIND, where,
                     "code-space credentialType must match schemaId")
            continue
        _require(schema_id not in bound_schemas, where, "duplicate code-space schema declaration")
        bound_schemas.add(schema_id)
        proof_version = 6 if kind == "jurisdiction" else 11
        _require(schema["credentialType"] == schema_id, where,
                 "code-space credentialType must match schemaId")
        _require(schema["proofType"] == f"zkc:proof:{kind}:v{proof_version}", where,
                 "code-space schema has the wrong proofType")
        ids = schema.get("codeSpaceIds")
        _require(type(ids) is list and bool(ids), where, "codeSpaceIds must be a nonempty closed list")
        seen = set()
        for code_space_id in ids:
            try:
                get_code_space(code_space_id, kind)
            except (TypeError, ValueError) as exc:
                _require(False, where, f"invalid codeSpaceId: {exc}")
            _require(code_space_id not in seen, where, "duplicate codeSpaceId")
            seen.add(code_space_id)
    for section in ("adapter", "revocation", "serviceLevels"):
        _require(isinstance(document.get(section), dict), where, f"missing {section}")
    if document["version"] == "zkc:issuer-metadata:v2":
        _require(
            isinstance(document["revocation"].get("currentAnnouncement"), dict),
            where,
            "authenticated metadata is missing currentAnnouncement",
        )
    else:
        _require(
            "currentAnnouncement" not in document["revocation"],
            where,
            "legacy metadata cannot carry an authenticated announcement",
        )


def validate_verifier_policy(document: dict, where: str) -> None:
    _require(isinstance(document, dict), where, "not a JSON object")
    _scan_forbidden_keys(document, where)
    _require(
        document.get("version") == "zkc:registry:verifier-policy:v1",
        where,
        "bad policy version",
    )
    _require(
        VERIFIER_ID_RE.fullmatch(str(document.get("verifierId", ""))) is not None,
        where,
        f"bad verifierId {document.get('verifierId')!r}",
    )
    _require(bool(document.get("displayName")), where, "missing displayName")
    proof_types = document.get("acceptedProofTypes")
    _require(isinstance(proof_types, list) and proof_types, where, "missing acceptedProofTypes")
    for proof_type in proof_types:
        _require(
            PROOF_TYPE_RE.fullmatch(str(proof_type)) is not None,
            where,
            f"bad proof type {proof_type!r}",
        )
    statuses = document.get("requiredReviewStatuses")
    _require(isinstance(statuses, list), where, "requiredReviewStatuses must be an array")
    for status in statuses:
        _require(status in REVIEW_STATUSES, where, f"unknown review status {status!r}")
    issuers = document.get("trustedIssuers")
    _require(isinstance(issuers, list), where, "trustedIssuers must be an array (empty = trust nobody)")
    layout_pins = {}
    for issuer in issuers:
        _require(bool(issuer.get("issuerId")), where, "trusted issuer missing issuerId")
        for coordinate in ("publicKeyX", "publicKeyY"):
            _require(
                KEY_COORD_RE.fullmatch(str(issuer.get(coordinate, ""))) is not None,
                where,
                f"trusted issuer {issuer.get('issuerId')!r} has bad {coordinate}",
            )
        _require(
            isinstance(issuer.get("proofTypes"), list) and issuer["proofTypes"]
            and all(isinstance(proof_type, str) for proof_type in issuer["proofTypes"]),
            where,
            f"trusted issuer {issuer.get('issuerId')!r} must list proof types",
        )
        legacy = LEGACY_SELECTIVE_DISCLOSURE_PROOF_TYPES.intersection(issuer["proofTypes"])
        if "attributeLayoutId" in issuer or legacy:
            layout_id = issuer.get("attributeLayoutId")
            try:
                parse_attribute_layout_id(layout_id)
            except ValueError as exc:
                _require(False, where, f"trusted issuer attributeLayoutId is invalid: {exc}")
            if legacy:
                coordinates = issuer["publicKeyX"], issuer["publicKeyY"]
                _require(layout_pins.setdefault(coordinates, layout_id) == layout_id, where,
                         "one trusted issuer key has conflicting legacy attribute layouts")
    _require(
        isinstance(document.get("acceptsOutOfRegistryIssuers"), bool),
        where,
        "acceptsOutOfRegistryIssuers must be a boolean",
    )
    _require(
        isinstance(document.get("requiredContextProfile"), str),
        where,
        "requiredContextProfile must be a string",
    )
    lag = document.get("maxEpochLag")
    _require(
        isinstance(lag, int) and 0 <= lag <= PROTOCOL_MAX_EPOCH_LAG,
        where,
        f"maxEpochLag must be within [0, {PROTOCOL_MAX_EPOCH_LAG}]",
    )
    requirements = document.get("proofRequirements")
    if requirements is not None:
        _require(isinstance(requirements, dict), where, "proofRequirements must be an object")
        for required_type, minimum in requirements.items():
            _require(
                required_type in proof_types,
                where,
                f"proofRequirements lists {required_type!r}, which is not in acceptedProofTypes",
            )
            _require(
                isinstance(minimum, dict),
                where,
                f"proofRequirements[{required_type!r}] must be an object",
            )
            _validate_proof_requirement(required_type, minimum, where)
    _require(bool(document.get("updatedAt")), where, "missing updatedAt")


def _validate_proof_requirement(proof_type: str, minimum: dict, where: str) -> None:
    """A published minimum may state only keys its typed disclosure
    comparator governs, each well-formed for its rule (planner and
    counter-offer evaluator must read the same requirement)."""
    from zkc_holder.ceilings import WITNESS_PATH, check_bound_value, comparator_for

    comparator = comparator_for(proof_type)
    _require(
        comparator is not None,
        where,
        f"proofRequirements[{proof_type!r}]: no typed disclosure comparator governs this proof type",
    )
    for key, value in minimum.items():
        rule = comparator.rules.get(key)
        _require(
            rule is not None and rule.kind != WITNESS_PATH,
            where,
            f"proofRequirements[{proof_type!r}] states {key!r}, which its typed "
            "disclosure comparator does not govern",
        )
        _require(
            check_bound_value(rule, value),
            where,
            f"proofRequirements[{proof_type!r}].{key} is not a well-formed {rule.kind} value",
        )
        if key == "layoutId":
            try:
                parse_attribute_layout_id(value)
            except ValueError as exc:
                _require(False, where, f"proofRequirements[{proof_type!r}] has invalid layoutId: {exc}")
    if "requiredLevel" in minimum:
        _require(
            minimum["requiredLevel"] >= 1,
            where,
            f"proofRequirements[{proof_type!r}].requiredLevel must be a positive integer",
        )


def _issuer_from_document(document: dict, source_path: str) -> IssuerDocument:
    return IssuerDocument(
        issuer_id=document["issuerId"],
        display_name=document["displayName"],
        signing_keys=tuple(
            (key["keyId"], key["scheme"], key["publicKey"])
            for key in document["signingKeys"]
        ),
        supported_schemas=tuple(
            (schema["schemaId"], schema["credentialType"], schema["proofType"])
            for schema in document["supportedSchemas"]
        ),
        source_path=source_path,
        raw=document,
    )


def _policy_from_document(document: dict, source_path: str) -> VerifierPolicyDocument:
    return VerifierPolicyDocument(
        verifier_id=document["verifierId"],
        display_name=document["displayName"],
        accepted_proof_types=tuple(document["acceptedProofTypes"]),
        required_review_statuses=tuple(document["requiredReviewStatuses"]),
        trusted_issuers=tuple(
            TrustedIssuerRef(
                issuer_id=issuer["issuerId"],
                public_key_x=issuer["publicKeyX"],
                public_key_y=issuer["publicKeyY"],
                proof_types=tuple(issuer["proofTypes"]),
                attribute_layout_id=issuer.get("attributeLayoutId"),
            )
            for issuer in document["trustedIssuers"]
        ),
        accepts_out_of_registry_issuers=document["acceptsOutOfRegistryIssuers"],
        required_context_profile=document["requiredContextProfile"],
        max_epoch_lag=document["maxEpochLag"],
        source_path=source_path,
        raw=document,
    )


class DiscoveryRegistry:
    """A loaded, validated view of registry/issuers + registry/verifiers.

    Lookups return ALL matches in deterministic (sorted) order — never a
    single blessed result. There is deliberately NO method that turns
    registry membership into a trust policy: trust policies are built only
    from an explicit published policy document (or local configuration).
    """

    def __init__(self, issuers, verifier_policies):
        self._issuers = {}
        for issuer in issuers:
            if issuer.issuer_id in self._issuers:
                raise DuplicateRegistryIdError(
                    f"duplicate issuerId {issuer.issuer_id!r} "
                    f"({self._issuers[issuer.issuer_id].source_path} and {issuer.source_path})"
                )
            self._issuers[issuer.issuer_id] = issuer
        self._verifiers = {}
        for policy in verifier_policies:
            if policy.verifier_id in self._verifiers:
                raise DuplicateRegistryIdError(
                    f"duplicate verifierId {policy.verifier_id!r} "
                    f"({self._verifiers[policy.verifier_id].source_path} and {policy.source_path})"
                )
            self._verifiers[policy.verifier_id] = policy

    @classmethod
    def from_repo(cls, repo_root) -> "DiscoveryRegistry":
        """Load from a LOCAL copy of the registry tree. No network access:
        the registry is an advisory cache that works fully offline."""
        root = pathlib.Path(repo_root)
        issuers = []
        issuers_dir = root / "registry" / "issuers"
        if issuers_dir.is_dir():
            for path in sorted(issuers_dir.glob("*.json")):
                where = str(path.relative_to(root))
                try:
                    document = json.loads(path.read_text())
                except ValueError as exc:
                    raise RegistryValidationError(f"{where}: invalid JSON: {exc}") from exc
                validate_issuer_document(document, where)
                issuers.append(_issuer_from_document(document, where))
        policies = []
        verifiers_dir = root / "registry" / "verifiers"
        if verifiers_dir.is_dir():
            for path in sorted(verifiers_dir.glob("*.json")):
                where = str(path.relative_to(root))
                try:
                    document = json.loads(path.read_text())
                except ValueError as exc:
                    raise RegistryValidationError(f"{where}: invalid JSON: {exc}") from exc
                validate_verifier_policy(document, where)
                policies.append(_policy_from_document(document, where))
        return cls(issuers, policies)

    # --- discovery: issuers -------------------------------------------------

    def issuers(self) -> tuple:
        return tuple(self._issuers[key] for key in sorted(self._issuers))

    def issuer(self, issuer_id: str) -> Optional[IssuerDocument]:
        return self._issuers.get(issuer_id)

    def lookup_issuers(
        self,
        schema_id: str = None,
        credential_type: str = None,
        proof_type: str = None,
    ) -> tuple:
        """ALL issuers matching the filters, sorted by issuerId. Discovery
        only: appearing in this result confers no trust whatsoever."""
        matches = []
        for issuer in self.issuers():
            if schema_id is not None and schema_id not in issuer.schema_ids():
                continue
            if credential_type is not None and credential_type not in issuer.credential_types():
                continue
            if proof_type is not None and proof_type not in issuer.proof_types():
                continue
            matches.append(issuer)
        return tuple(matches)

    # --- discovery: verifiers -----------------------------------------------

    def verifier_policies(self) -> tuple:
        return tuple(self._verifiers[key] for key in sorted(self._verifiers))

    def verifier_policy(self, verifier_id: str) -> Optional[VerifierPolicyDocument]:
        return self._verifiers.get(verifier_id)

    def find_accepting_verifiers(
        self,
        proof_type: str,
        issuer_id: str = None,
        issuer_public_key: tuple = None,
        credential=None,
    ) -> tuple:
        """ALL published verifier policies that accept `proof_type` — and,
        when an issuer is given (by id, key, or a holder credential), whose
        key-exact allowlist trusts that issuer for it.

        Holders use this to find counterparties for their credentials. The
        result is discovery only: each verifier still verifies locally.
        """
        if credential is not None:
            issuer_id = getattr(credential, "issuer_id", issuer_id)
            proof_type = getattr(credential, "proof_type", proof_type)
        matches = []
        for policy in self.verifier_policies():
            if proof_type not in policy.accepted_proof_types:
                continue
            if issuer_public_key is not None and not policy.trusts_issuer_key(
                issuer_public_key[0], issuer_public_key[1], proof_type
            ):
                continue
            if issuer_id is not None and not policy.trusts_issuer_id(issuer_id, proof_type):
                continue
            matches.append(policy)
        return tuple(matches)


def to_holder_trust_policy(policy_document: VerifierPolicyDocument):
    """Build the holder-side TrustPolicy from a PUBLISHED verifier policy, so
    a holder can plan credential selection against it before contacting the
    verifier. Requires an explicit policy document — registry membership
    alone can never produce a trust policy."""
    from zkc_holder import TrustPolicy, TrustedIssuer

    return TrustPolicy(
        issuers=tuple(
            TrustedIssuer(
                issuer_id=ref.issuer_id,
                public_key_x=bytes.fromhex(ref.public_key_x.removeprefix("0x")),
                public_key_y=bytes.fromhex(ref.public_key_y.removeprefix("0x")),
                proof_types=ref.proof_types,
            )
            for ref in policy_document.trusted_issuers
        )
    )


def to_verifier_trust_policy(policy_document: VerifierPolicyDocument):
    """Build the runtime VerifierTrustPolicy from the verifier's own
    published policy document (the verifier remains the enforcement point).
    Requires an explicit policy document — never registry membership."""
    from zkc_verifier import TrustedIssuer, VerifierTrustPolicy

    return VerifierTrustPolicy(
        issuers=tuple(
            TrustedIssuer(
                issuer_id=ref.issuer_id,
                public_key_x=bytes.fromhex(ref.public_key_x.removeprefix("0x")),
                public_key_y=bytes.fromhex(ref.public_key_y.removeprefix("0x")),
                proof_types=ref.proof_types,
                attribute_layout_id=ref.attribute_layout_id,
            )
            for ref in policy_document.trusted_issuers
        ),
        max_epoch_lag=policy_document.max_epoch_lag,
        required_context_profile=policy_document.required_context_profile,
        accepted_review_statuses=policy_document.required_review_statuses,
    )

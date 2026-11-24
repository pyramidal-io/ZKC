"""Provider-neutral runtime attestation issuer reference fixtures.

``StaticPreverifiedRuntimeAttestationProviderClient`` is test/reference-only.
It structurally validates and binds caller-supplied preverified verdicts, but
does not cryptographically verify provenance signatures, transparency logs,
TEE reports, endorsements, or collateral. Production integrations implement
``ProviderClient.verify_subject`` inside their provider trust boundary and
return only ``ProviderDecision`` to the shared issuer-adapter stages.

The evidence store itself uses the ZKC runtime-attestation canonical JSON v1
profile: values are owned plain ``dict``/``list`` trees containing only UTF-8
string keys and values, booleans, null, and signed 64-bit integers. Object
keys are ordered by ascending Unicode scalar value. Encoding is compact UTF-8
JSON with literal Unicode. Floats, non-finite numbers, container subclasses,
and values outside the named depth, node, and byte limits are forbidden.

External artifacts (the signed provenance statement, transparency-log
checkpoint, TEE report, and endorsement/collateral bundle) are NOT canonical
JSON values. They are exact scheme-native signed bytes, carried in the store
as lowercase-hex strings, and their public digests use the ZKC
runtime-attestation external-artifact digest v2 profile: SHA-256 over the
AFP External Artifact v2 framing ``ASCII("AFP-External-Artifact-v2\\0") ||
u32be(len(kind)) || UTF8(kind) || u32be(len(scheme)) || UTF8(scheme) ||
u64be(len(signed_bytes)) || signed_bytes``. Re-encoding an external artifact
as JSON (the retired v1 canonical-JSON derivation) is forbidden and fails
closed; see ``compute_external_artifact_digest``.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from types import MappingProxyType

from zkc_crypto import derive_holder_commitment_from_seed, field_to_hex, hex_to_field

from .errors import HUMAN_PRIVACY_PROFILE, MACHINE_PRIVACY_PROFILE
from .external import ExternalProviderAdapter, ProviderClient, ProviderDecision
from .schemas import (
    RUNTIME_ATTESTATION_MAX_ROOT_AUTHORITY_IDENTIFIER_UTF8_BYTES,
    RUNTIME_ATTESTATION_SCHEMA_ID,
    get_schema,
)

__all__ = [
    "RUNTIME_ATTESTATION_VERIFICATION_CONTEXT",
    "RUNTIME_ATTESTATION_MAX_EVIDENCE_STORE_ENTRIES",
    "RUNTIME_ATTESTATION_MAX_CANONICAL_JSON_NODES",
    "RUNTIME_ATTESTATION_MAX_STRING_UTF8_BYTES",
    "RUNTIME_ATTESTATION_MAX_EVIDENCE_REF_UTF8_BYTES",
    "RUNTIME_ATTESTATION_MAX_ROOT_AUTHORITY_IDENTIFIER_UTF8_BYTES",
    "RUNTIME_ATTESTATION_EXTERNAL_ARTIFACT_DIGEST_PROFILE",
    "RUNTIME_ATTESTATION_MAX_EXTERNAL_ARTIFACT_SIGNED_BYTES",
    "RUNTIME_ATTESTATION_ARTIFACT_KIND_PROVENANCE_STATEMENT",
    "RUNTIME_ATTESTATION_ARTIFACT_KIND_TRANSPARENCY_CHECKPOINT",
    "RUNTIME_ATTESTATION_ARTIFACT_KIND_TEE_REPORT",
    "RUNTIME_ATTESTATION_ARTIFACT_KIND_TEE_ENDORSEMENT_COLLATERAL",
    "compute_external_artifact_digest",
    "StaticPreverifiedRuntimeAttestationProviderClient",
    "RuntimeAttestationAdapter",
    "reference_runtime_attestation_adapter",
]

RUNTIME_ATTESTATION_VERIFICATION_CONTEXT = "sha256:" + "a5" * 32
RUNTIME_ATTESTATION_MAX_EVIDENCE_STORE_ENTRIES = 256
RUNTIME_ATTESTATION_MAX_CANONICAL_JSON_NODES = 4096
RUNTIME_ATTESTATION_MAX_STRING_UTF8_BYTES = 4096
RUNTIME_ATTESTATION_MAX_EVIDENCE_REF_UTF8_BYTES = 256
RUNTIME_ATTESTATION_EXTERNAL_ARTIFACT_DIGEST_PROFILE = (
    "zkc:runtime-attestation:external-artifact-digest:v2"
)
RUNTIME_ATTESTATION_MAX_EXTERNAL_ARTIFACT_SIGNED_BYTES = 2048
RUNTIME_ATTESTATION_ARTIFACT_KIND_PROVENANCE_STATEMENT = "provenance-statement"
RUNTIME_ATTESTATION_ARTIFACT_KIND_TRANSPARENCY_CHECKPOINT = (
    "transparency-checkpoint"
)
RUNTIME_ATTESTATION_ARTIFACT_KIND_TEE_REPORT = "tee-report"
RUNTIME_ATTESTATION_ARTIFACT_KIND_TEE_ENDORSEMENT_COLLATERAL = (
    "tee-endorsement-collateral"
)
_SAFE_FAILURE = "runtime attestation evidence rejected"
_INVALID_STORE = "invalid runtime attestation evidence store"
_CANONICAL_JSON_ERROR = (
    "value is not valid ZKC runtime-attestation canonical JSON v1"
)
_EXTERNAL_ARTIFACT_ERROR = (
    "value is not a valid AFP External Artifact v2 digest input"
)
_CANONICAL_JSON_MAX_DEPTH = 32
_CANONICAL_JSON_MIN_INT = -(1 << 63)
_CANONICAL_JSON_MAX_INT = (1 << 63) - 1
_CANONICAL_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EXTERNAL_ARTIFACT_DOMAIN = b"AFP-External-Artifact-v2\x00"
_EXTERNAL_ARTIFACT_IDENTIFIER_RE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z"
)
_EXTERNAL_ARTIFACT_HEX_RE = re.compile(
    r"(?:[0-9a-f]{2}){1,%d}\Z"
    % RUNTIME_ATTESTATION_MAX_EXTERNAL_ARTIFACT_SIGNED_BYTES
)
_EXTERNAL_ARTIFACT_STORE_KEYS = frozenset(
    {"digestProfile", "kind", "scheme", "signedBytesHex"}
)


def _unicode_scalar_sort_key(value: str) -> tuple[int, ...]:
    return tuple(ord(character) for character in value)


def _utf8_length(value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeError:
        raise ValueError(_CANONICAL_JSON_ERROR) from None


def _is_canonical_nonzero_sha256(value) -> bool:
    return (
        type(value) is str
        and _CANONICAL_SHA256_RE.fullmatch(value) is not None
        and value != "sha256:" + "0" * 64
    )


def _normalize_canonical_json(value, depth: int = 0, node_count=None):
    """Validate the canonical JSON v1 profile and return an owned plain tree."""

    if node_count is None:
        node_count = [0]
    node_count[0] += 1
    if node_count[0] > RUNTIME_ATTESTATION_MAX_CANONICAL_JSON_NODES:
        raise ValueError(_CANONICAL_JSON_ERROR)

    if type(value) is dict:
        if depth >= _CANONICAL_JSON_MAX_DEPTH:
            raise ValueError(_CANONICAL_JSON_ERROR)
        normalized = {}
        if any(type(key) is not str for key in value):
            raise ValueError(_CANONICAL_JSON_ERROR)
        for key in sorted(value, key=_unicode_scalar_sort_key):
            if _utf8_length(key) > RUNTIME_ATTESTATION_MAX_STRING_UTF8_BYTES:
                raise ValueError(_CANONICAL_JSON_ERROR)
            normalized[key] = _normalize_canonical_json(
                value[key], depth + 1, node_count
            )
        return normalized
    if type(value) is list:
        if depth >= _CANONICAL_JSON_MAX_DEPTH:
            raise ValueError(_CANONICAL_JSON_ERROR)
        return [
            _normalize_canonical_json(child, depth + 1, node_count)
            for child in value
        ]
    if type(value) is str:
        if _utf8_length(value) > RUNTIME_ATTESTATION_MAX_STRING_UTF8_BYTES:
            raise ValueError(_CANONICAL_JSON_ERROR)
        return value
    if value is None or type(value) is bool:
        return value
    if type(value) is int and _CANONICAL_JSON_MIN_INT <= value <= _CANONICAL_JSON_MAX_INT:
        return value
    raise ValueError(_CANONICAL_JSON_ERROR)


def _canonical_json_bytes(value) -> bytes:
    normalized = _normalize_canonical_json(value)
    return json.dumps(
        normalized,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest_json(value) -> str:
    encoded = _canonical_json_bytes(value)
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def compute_external_artifact_digest(
    kind: str, scheme: str, signed_bytes: bytes
) -> str:
    """Digest an external artifact under the AFP External Artifact v2 framing.

    ``signed_bytes`` are the exact scheme-native signed bytes; they are never
    reconstructed, canonicalized, or re-encoded as JSON. ``kind`` and
    ``scheme`` are the nonempty ASCII identifiers fixed by the accepted
    verification policy. The digest is SHA-256 over
    ``ASCII("AFP-External-Artifact-v2\\0") || u32be(len(kind)) || UTF8(kind)
    || u32be(len(scheme)) || UTF8(scheme) || u64be(len(signed_bytes)) ||
    signed_bytes`` per AFP ``docs/afp_specification.md`` at ``7d10e0e``.
    """

    if (
        type(kind) is not str
        or _EXTERNAL_ARTIFACT_IDENTIFIER_RE.fullmatch(kind) is None
        or type(scheme) is not str
        or _EXTERNAL_ARTIFACT_IDENTIFIER_RE.fullmatch(scheme) is None
        or type(signed_bytes) is not bytes
        or not signed_bytes
    ):
        raise ValueError(_EXTERNAL_ARTIFACT_ERROR)
    kind_bytes = kind.encode("ascii")
    scheme_bytes = scheme.encode("ascii")
    framing = b"".join(
        (
            _EXTERNAL_ARTIFACT_DOMAIN,
            len(kind_bytes).to_bytes(4, "big"),
            kind_bytes,
            len(scheme_bytes).to_bytes(4, "big"),
            scheme_bytes,
            len(signed_bytes).to_bytes(8, "big"),
            signed_bytes,
        )
    )
    return "sha256:" + hashlib.sha256(framing).hexdigest()


def _external_artifact_digest_from_store(value, expected_kind: str):
    """Digest a store-carried external artifact, or None if it is invalid.

    Only the explicit v2 store shape is accepted. A legacy v1 entry that
    carries the artifact as a canonical-JSON tree has no ``digestProfile``,
    ``kind``, ``scheme``, or ``signedBytesHex`` and is rejected here, so
    canonical-JSON reference credentials fail closed instead of being
    silently reinterpreted under v2 digest semantics.
    """

    if type(value) is not dict or set(value) != _EXTERNAL_ARTIFACT_STORE_KEYS:
        return None
    if (
        value["digestProfile"]
        != RUNTIME_ATTESTATION_EXTERNAL_ARTIFACT_DIGEST_PROFILE
        or value["kind"] != expected_kind
    ):
        return None
    signed_bytes_hex = value["signedBytesHex"]
    if (
        type(signed_bytes_hex) is not str
        or _EXTERNAL_ARTIFACT_HEX_RE.fullmatch(signed_bytes_hex) is None
    ):
        return None
    try:
        return compute_external_artifact_digest(
            value["kind"], value["scheme"], bytes.fromhex(signed_bytes_hex)
        )
    except ValueError:
        return None


def _failed() -> ProviderDecision:
    return ProviderDecision(verified=False, failure_reason=_SAFE_FAILURE)


def _nonempty_artifact(value) -> bool:
    if isinstance(value, str):
        return bool(value)
    if isinstance(value, dict):
        return bool(value)
    if isinstance(value, list):
        return bool(value) and all(_nonempty_artifact(item) for item in value)
    return False


def _build_artifacts(entry: dict, root_material: dict, raw_evidence: dict):
    """Return (rootMaterialDigest, attestationEvidenceDigest) or None.

    Both digests use the external-artifact v2 profile: the root-material
    digest commits to the exact signed transparency-log checkpoint bytes and
    the evidence digest to the exact signed provenance-statement bytes. The
    inclusion path stays provider-side and is structurally required but never
    published or digested into a claim.
    """

    inclusion_path = root_material.get("inclusionPath")
    if not (
        root_material.get("checkpointAuthenticated") is True
        and root_material.get("inclusionVerified") is True
        and raw_evidence.get("signatureVerified") is True
        and raw_evidence.get("builderIdentityAccepted") is True
        and isinstance(inclusion_path, list)
        and _nonempty_artifact(inclusion_path)
    ):
        return None
    checkpoint_digest = _external_artifact_digest_from_store(
        root_material.get("checkpoint"),
        RUNTIME_ATTESTATION_ARTIFACT_KIND_TRANSPARENCY_CHECKPOINT,
    )
    statement_digest = _external_artifact_digest_from_store(
        raw_evidence.get("statement"),
        RUNTIME_ATTESTATION_ARTIFACT_KIND_PROVENANCE_STATEMENT,
    )
    if (
        checkpoint_digest is None
        or statement_digest is None
        or root_material.get("includedStatementDigest") != statement_digest
        or raw_evidence.get("artifactDigest")
        != entry.get("attestedManifestDigest")
    ):
        return None
    return (checkpoint_digest, statement_digest)


def _tee_artifacts(
    entry: dict,
    root_material: dict,
    raw_evidence: dict,
    verification_context_digest: str,
):
    """Return (rootMaterialDigest, attestationEvidenceDigest) or None.

    The root-material digest commits to the exact scheme-native
    endorsement/collateral bundle bytes and the evidence digest to the exact
    hardware attestation report bytes, both under the external-artifact v2
    profile. The manifest and verification-context bindings are
    provider-asserted fields of the preverified verdict, not values parsed
    out of the opaque report bytes.
    """

    if not (
        root_material.get("endorsementChainVerified") is True
        and root_material.get("revocationCurrent") is True
        and root_material.get("collateralFresh") is True
        and raw_evidence.get("reportAuthenticated") is True
        and raw_evidence.get("fresh") is True
        and raw_evidence.get("measurementAccepted") is True
        and raw_evidence.get("reportDataBound") is True
    ):
        return None
    collateral_digest = _external_artifact_digest_from_store(
        root_material.get("collateral"),
        RUNTIME_ATTESTATION_ARTIFACT_KIND_TEE_ENDORSEMENT_COLLATERAL,
    )
    report_digest = _external_artifact_digest_from_store(
        raw_evidence.get("report"),
        RUNTIME_ATTESTATION_ARTIFACT_KIND_TEE_REPORT,
    )
    if (
        collateral_digest is None
        or report_digest is None
        or raw_evidence.get("attestedManifestDigest")
        != entry.get("attestedManifestDigest")
        or raw_evidence.get("verificationContextDigest")
        != verification_context_digest
    ):
        return None
    return (collateral_digest, report_digest)


class StaticPreverifiedRuntimeAttestationProviderClient(ProviderClient):
    """Test-only binder for static, caller-supplied preverified verdicts.

    This fixture performs structural checks and digest binding only. It does
    not cryptographically verify any AFP, transparency-log, or TEE artifact.
    """

    def __init__(self, evidence_store: dict, verification_context_digest: str):
        try:
            normalized_store = _normalize_canonical_json(evidence_store)
            if (
                type(normalized_store) is not dict
                or len(normalized_store)
                > RUNTIME_ATTESTATION_MAX_EVIDENCE_STORE_ENTRIES
                or not _is_canonical_nonzero_sha256(verification_context_digest)
            ):
                raise ValueError(_INVALID_STORE)
        except Exception:
            raise ValueError(_INVALID_STORE) from None
        self._evidence_store = normalized_store
        self._provider_refs = {
            entry["subjectIdentity"]: secrets.token_hex(32)
            for entry in normalized_store.values()
            if type(entry) is dict and type(entry.get("subjectIdentity")) is str
        }
        self._verification_context_digest = verification_context_digest

    def verify_subject(self, schema_id: str, payload: dict, *, authenticated_session: str) -> ProviderDecision:
        try:
            if schema_id != RUNTIME_ATTESTATION_SCHEMA_ID or not isinstance(
                payload, dict
            ):
                return _failed()
            payload_context = payload.get("verificationContextDigest")
            if (
                not _is_canonical_nonzero_sha256(payload_context)
                or payload_context != self._verification_context_digest
            ):
                return _failed()
            evidence_ref = payload.get("evidenceRef")
            if (
                type(evidence_ref) is not str
                or not evidence_ref
                or _utf8_length(evidence_ref)
                > RUNTIME_ATTESTATION_MAX_EVIDENCE_REF_UTF8_BYTES
            ):
                return _failed()
            entry = self._evidence_store.get(evidence_ref)
            if not isinstance(entry, dict):
                return _failed()

            # Provider-private verdict binds the signed evidence to this holder.
            # The static fixture asserts this check; real providers must verify
            # authenticated report-data / provenance subject bytes themselves.
            holder = payload.get("holderCommitment")
            raw_binding = entry.get("rawEvidence", {})
            if (type(holder) is not str or hex_to_field(holder) == 0
                    or type(raw_binding) is not dict
                    or raw_binding.get("holderCommitment") != holder):
                return _failed()
            subject_identity = entry.get("subjectIdentity")
            if (type(subject_identity) is not str or not subject_identity
                    or _utf8_length(subject_identity) > 256):
                return _failed()
            root_class = entry.get("rootClass")
            root_material = entry.get("rootMaterial")
            raw_evidence = entry.get("rawEvidence")
            if not isinstance(root_material, dict) or not isinstance(raw_evidence, dict):
                return _failed()
            if (
                not isinstance(entry.get("attestedManifestDigest"), str)
                or type(entry.get("rootAuthorityIdentifier")) is not str
                or _utf8_length(entry["rootAuthorityIdentifier"])
                > RUNTIME_ATTESTATION_MAX_ROOT_AUTHORITY_IDENTIFIER_UTF8_BYTES
                or not isinstance(entry.get("verificationPolicyDigest"), str)
                or isinstance(entry.get("validFrom"), bool)
                or not isinstance(entry.get("validFrom"), int)
                or isinstance(entry.get("validUntil"), bool)
                or not isinstance(entry.get("validUntil"), int)
            ):
                return _failed()

            if root_class == "root:build-provenance":
                artifacts = _build_artifacts(entry, root_material, raw_evidence)
            elif root_class == "root:tee-attestation":
                artifacts = _tee_artifacts(
                    entry,
                    root_material,
                    raw_evidence,
                    self._verification_context_digest,
                )
            else:
                artifacts = None
            if artifacts is None:
                return _failed()
            root_material_digest, attestation_evidence_digest = artifacts
            claims = {
                "attestedManifestDigest": entry["attestedManifestDigest"],
                "rootClass": root_class,
                "rootAuthorityIdentifier": entry["rootAuthorityIdentifier"],
                "rootMaterialDigest": root_material_digest,
                "attestationEvidenceDigest": attestation_evidence_digest,
                "verificationPolicyDigest": entry["verificationPolicyDigest"],
                "validFrom": entry["validFrom"],
                "validUntil": entry["validUntil"],
            }
            normalized_claims = get_schema(schema_id).normalize_claims(claims)
            expires_at = entry["validUntil"]
        except Exception:
            return _failed()
        return ProviderDecision(
            verified=True,
            provider_ref=self._provider_refs[subject_identity],
            holder_commitment=holder,
            claims=normalized_claims,
            expires_at=expires_at,
            failure_reason=_SAFE_FAILURE,
        )


class RuntimeAttestationAdapter(ExternalProviderAdapter):
    """Issuer adapter whose production provider must verify runtime evidence.

    Stage 1 consumes the bounded public ``evidenceRef`` inside the provider
    boundary. The resulting ``providerRef`` is independently allocated in the
    private provider store and identifies the issuance lineage. ``subjectRef``
    is a separate random, expiring session continuation. The provider verifies
    that authenticated report-data/provenance binds the stage-1 commitment;
    stage 2 cannot substitute a different holder. Raw runtime, host, and build
    evidence remains in the provider store and is never public.
    """

    conformance_subject_payload = {
        "evidenceRef": "reference-build-provenance",
        "holderCommitment": field_to_hex(derive_holder_commitment_from_seed(31337)),
        "verificationContextDigest": RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
    }
    conformance_schema_id = RUNTIME_ATTESTATION_SCHEMA_ID
    supported_schema_ids = frozenset({RUNTIME_ATTESTATION_SCHEMA_ID})
    schema_required_privacy_profiles = MappingProxyType(
        {
            RUNTIME_ATTESTATION_SCHEMA_ID: frozenset(
                {HUMAN_PRIVACY_PROFILE, MACHINE_PRIVACY_PROFILE}
            )
        }
    )

    def __init__(self, provider_client: ProviderClient, **kwargs):
        kwargs.setdefault("issuer_id", "zkc:issuer:runtime-attestation-reference")
        kwargs.setdefault(
            "display_name", "ZKC Runtime Attestation Reference Issuer"
        )
        kwargs.setdefault(
            "base_url", "https://issuer.runtime-attestation.zkc.dev"
        )
        super().__init__(provider_client, **kwargs)


def _external_artifact(kind: str, scheme: str, signed_bytes: bytes) -> dict:
    """Return the v2 store carrier for one exact-byte external artifact."""

    return {
        "digestProfile": RUNTIME_ATTESTATION_EXTERNAL_ARTIFACT_DIGEST_PROFILE,
        "kind": kind,
        "scheme": scheme,
        "signedBytesHex": signed_bytes.hex(),
    }


_REFERENCE_STATEMENT_SCHEME = "in-toto-dsse:v1"
_REFERENCE_CHECKPOINT_SCHEME = "signed-note:v1"

# Exact scheme-native signed bytes. Deliberately NOT canonical JSON: the
# spacing below never survives a JSON re-encode, so any implementation that
# reconstructs the artifact from a parsed tree derives a different digest.
_REFERENCE_BUILD_STATEMENT_BYTES = (
    b'{"statementType": "https://in-toto.io/Statement/v1", '
    b'"artifactDigest": "sha256:' + b"51" * 32 + b'", '
    b'"builder": "https://builder.example/reference", '
    b'"marker": "raw-provenance-must-stay-provider-side"}'
)
_REFERENCE_CHECKPOINT_BYTES = (
    b"rekor.sigstore.dev - reference-log\n"
    b"42\n"
    b"raw-checkpoint-must-stay-provider-side\n"
)

_REFERENCE_EVIDENCE_STORE = {
    "reference-build-provenance": {
        "subjectIdentity": "reference-runtime-subject",
        "rootClass": "root:build-provenance",
        "rootAuthorityIdentifier": "sigstore:rekor:public-good:v1",
        "attestedManifestDigest": "sha256:" + "51" * 32,
        "verificationPolicyDigest": "sha256:" + "52" * 32,
        "validFrom": 1_769_999_940,
        "validUntil": 1_770_003_600,
        "rootMaterial": {
            "checkpointAuthenticated": True,
            "inclusionVerified": True,
            "checkpoint": _external_artifact(
                RUNTIME_ATTESTATION_ARTIFACT_KIND_TRANSPARENCY_CHECKPOINT,
                _REFERENCE_CHECKPOINT_SCHEME,
                _REFERENCE_CHECKPOINT_BYTES,
            ),
            "inclusionPath": ["sha256:" + "53" * 32],
            "includedStatementDigest": compute_external_artifact_digest(
                RUNTIME_ATTESTATION_ARTIFACT_KIND_PROVENANCE_STATEMENT,
                _REFERENCE_STATEMENT_SCHEME,
                _REFERENCE_BUILD_STATEMENT_BYTES,
            ),
        },
        "rawEvidence": {
            "holderCommitment": field_to_hex(derive_holder_commitment_from_seed(31337)),
            "signatureVerified": True,
            "builderIdentityAccepted": True,
            "artifactDigest": "sha256:" + "51" * 32,
            "statement": _external_artifact(
                RUNTIME_ATTESTATION_ARTIFACT_KIND_PROVENANCE_STATEMENT,
                _REFERENCE_STATEMENT_SCHEME,
                _REFERENCE_BUILD_STATEMENT_BYTES,
            ),
        },
    }
}


def reference_runtime_attestation_adapter(**kwargs) -> RuntimeAttestationAdapter:
    """Return a test-only adapter backed by static preverified verdicts."""

    from .adapter import _reference_session_identity
    kwargs.setdefault("clock", lambda: 1_770_000_000)
    kwargs.setdefault("session_identity", _reference_session_identity)
    client = StaticPreverifiedRuntimeAttestationProviderClient(
        _REFERENCE_EVIDENCE_STORE,
        RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
    )
    return RuntimeAttestationAdapter(client, **kwargs)

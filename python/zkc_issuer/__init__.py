"""ZKC reference issuer SDK and sandbox adapter (stdlib-only).

Implements the issuer side of docs/zkc_issuer_adapter_protocol_v1.md:

* ``IssuerSigningKey`` — secp256k1 key generation/loading + digest signing
  (shared ECDSA from zkc_crypto; same construction as tools/zkc_test_issuer.py).
* ``SUPPORTED_SCHEMAS`` — the sandbox's current circuit-exact schemas plus
  retained, non-issuable legacy profile schemas.  New profile issuance uses
  ``zkc:cred:{accreditation,source,tax,sanctions}:v2`` so both validity bounds
  are signed; v1 is available only for historical verification.
* ``BindingChallenge`` / ``compute_binding_response`` — beta holder-binding
  challenge over (holderCommitment, issuerId, schemaId, nonce, expiresAt).
* ``IssuerAccumulator`` — Poseidon2 Merkle active-set revocation state.
* ``SQLiteIssuanceLedgerStore`` — durable issuance/renewal ledger, so a
  restarted adapter keeps renewing pre-restart credentials.
* ``build_issuer_metadata`` — /.well-known/zkc-issuer.json generation.
* ``SandboxIssuerAdapter`` — the 4 adapter stages against sandbox fixtures.
* ``StaticPreverifiedRuntimeAttestationProviderClient`` — test-only structural
  binder for caller-supplied preverified runtime-attestation verdicts; it is
  not a cryptographic evidence verifier.
* ``IssuerAdapterAccumulatorProvider`` — holder-SDK witness-refresh bridge.

Privacy boundary: the issuer never receives (and every stage rejects) ZKA
addresses, master seeds, spending/binding keys, note plaintext, or payment
history. There are NO canonical issuers (Freedom Safeguard 1).
"""

from .errors import (  # noqa: F401
    ADAPTER_ERROR_CODES,
    FORBIDDEN_FIELDS,
    HUMAN_PRIVACY_PROFILE,
    MACHINE_PRIVACY_PROFILE,
    KNOWN_PRIVACY_PROFILES,
    MACHINE_SUBJECT_FORBIDDEN_FIELDS,
    MACHINE_SUBJECT_FORBIDDEN_SUFFIXES,
    AdapterError,
    reject_forbidden,
)
from .keys import IssuerSigningKey  # noqa: F401
from .schemas import (  # noqa: F401
    RUNTIME_ATTESTATION_MAX_ROOT_AUTHORITY_IDENTIFIER_UTF8_BYTES,
    RUNTIME_ATTESTATION_PROOF_TYPE,
    RUNTIME_ATTESTATION_SCHEMA_ID,
    SUPPORTED_SCHEMAS,
    CredentialSchema,
    get_schema,
)
from .binding import (  # noqa: F401
    BINDING_CHALLENGE_VERSION,
    BindingChallenge,
    compute_binding_response,
    holder_binding_response,
)
from .accumulator import ACCUMULATOR_TYPE, MAX_EPOCH_LAG, IssuerAccumulator  # noqa: F401
from .metadata import (  # noqa: F401
    AUTHENTICATED_METADATA_VERSION,
    METADATA_VERSION,
    WELL_KNOWN_PATH,
    build_issuer_metadata,
    write_well_known,
)
from .fixtures import SANDBOX_FIXTURES  # noqa: F401
from .ledger import (  # noqa: F401
    ISSUANCE_LEDGER_VERSION,
    InMemoryIssuanceLedgerStore,
    IssuanceLedgerError,
    IssuanceLedgerStore,
    SQLiteIssuanceLedgerStore,
)
from .contract import IssuerAdapter  # noqa: F401
from .adapter import (  # noqa: F401
    CREDENTIAL_ENVELOPE_VERSION,
    MANDATORY_SCHEMA_PRIVACY_PROFILES,
    BaseIssuerAdapter,
    SandboxIssuerAdapter,
    validate_adapter_capabilities,
)
from .external import (  # noqa: F401
    ExternalProviderAdapter,
    ProviderClient,
    ProviderDecision,
    StaticProviderClient,
    reference_external_adapter,
)
from .runtime_attestation import (  # noqa: F401
    RUNTIME_ATTESTATION_ARTIFACT_KIND_PROVENANCE_STATEMENT,
    RUNTIME_ATTESTATION_ARTIFACT_KIND_TEE_ENDORSEMENT_COLLATERAL,
    RUNTIME_ATTESTATION_ARTIFACT_KIND_TEE_REPORT,
    RUNTIME_ATTESTATION_ARTIFACT_KIND_TRANSPARENCY_CHECKPOINT,
    RUNTIME_ATTESTATION_EXTERNAL_ARTIFACT_DIGEST_PROFILE,
    RUNTIME_ATTESTATION_MAX_CANONICAL_JSON_NODES,
    RUNTIME_ATTESTATION_MAX_EVIDENCE_REF_UTF8_BYTES,
    RUNTIME_ATTESTATION_MAX_EVIDENCE_STORE_ENTRIES,
    RUNTIME_ATTESTATION_MAX_EXTERNAL_ARTIFACT_SIGNED_BYTES,
    RUNTIME_ATTESTATION_MAX_STRING_UTF8_BYTES,
    RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
    RuntimeAttestationAdapter,
    StaticPreverifiedRuntimeAttestationProviderClient,
    compute_external_artifact_digest,
    reference_runtime_attestation_adapter,
)
from .provider import IssuerAdapterAccumulatorProvider  # noqa: F401

"""ZKC reference holder SDK (stdlib-only Python).

Implements the spec §5 client interface for the ZKC-Core profile: credential
storage, selection by proof request and trust policy, witness refresh,
zkc:proof:v1 generation, an aggregation entry point, context binding, and
default refusal of opaque predicates (Freedom Safeguard 4).

Non-custodial: master seed and credential binding key never leave the client.
See python/README.md for layout and usage.
"""

from .accumulator import (  # noqa: F401
    MAX_EPOCH_LAG,
    AccumulatorProvider,
    LocalAccumulatorProvider,
)
from .audit_export import (  # noqa: F401
    AUDIT_BUNDLE_VERSION,
    AuditBundleError,
    AuditCheckResult,
    AuditExporter,
    reverify_bundle_proofs,
    scan_forbidden_material,
    verify_audit_bundle,
)
from .backend import (  # noqa: F401
    COMMUNITY_KYC_V2_CIRCUIT,
    COMMUNITY_KYC_V2_PROOF_TYPE,
    KYC_CIRCUIT,
    KYC_PROOF_TYPE,
    KYC_V3_CIRCUIT,
    KYC_V3_PROOF_TYPE,
    NargoBackend,
    ProofBackend,
    StubBackend,
    build_kyc_witness,
)
from .client import HolderClient  # noqa: F401
from .disclosure import (  # noqa: F401
    DISCLOSURE_CIRCUIT,
    DISCLOSURE_PROOF_TYPE,
    DISCLOSURE_V2_CIRCUIT,
    DISCLOSURE_V2_PROOF_TYPE,
    build_selective_disclosure_witness,
    selective_disclosure_public_inputs,
)
from .predicates import (  # noqa: F401
    JURISDICTION_CIRCUIT,
    JURISDICTION_V1_CIRCUIT,
    JURISDICTION_PROOF_TYPE,
    JURISDICTION_V1_PROOF_TYPE,
    JURISDICTION_V2_PROOF_TYPE,
    JURISDICTION_V3_PROOF_TYPE,
    JURISDICTION_V4_PROOF_TYPE,
    JURISDICTION_V5_PROOF_TYPE,
    JURISDICTION_V3_CIRCUIT,
    JURISDICTION_V4_CIRCUIT,
    JURISDICTION_V5_CIRCUIT,
    MEMBERSHIP_TYPE_EXCLUSION,
    MEMBERSHIP_TYPE_INCLUSION,
    PROFILE_PROOF_TYPES,
    REBIND_CIRCUIT,
    REBIND_PROOF_TYPE,
    REBIND_BINDING_V2_CIRCUIT,
    REBIND_BINDING_V2_PROOF_TYPE,
    REBIND_V2_CIRCUIT,
    REBIND_V2_BINDING_V2_CIRCUIT,
    REBIND_V2_BINDING_V2_PROOF_TYPE,
    UNAUTHENTICATED_REBIND_PROOF_TYPES,
    REMAINING_CIRCUIT,
    REMAINING_V3_CIRCUIT,
    REMAINING_V4_CIRCUIT,
    REMAINING_V5_CIRCUIT,
    REMAINING_V6_CIRCUIT,
    REMAINING_V7_CIRCUIT,
    REMAINING_V8_CIRCUIT,
    REMAINING_V9_CIRCUIT,
    REMAINING_V10_CIRCUIT,
    REBIND_AUTH_V3_CIRCUIT,
    REBIND_AUTH_V3_PROOF_TYPE,
    build_jurisdiction_witness,
    build_profile_witness,
    build_profile_witness_v3,
    build_profile_witness_v4,
    build_profile_witness_v5,
    build_profile_witness_v6,
    build_profile_witness_v7,
    build_profile_witness_v8,
    build_rebind_witness,
    check_jurisdiction_constraints_v3,
    check_jurisdiction_constraints_v4,
    check_profile_constraints_v3,
    check_profile_constraints_v4,
    check_profile_constraints_v5,
    check_profile_constraints_v6,
    check_profile_constraints_v7,
    check_profile_constraints_v8,
    resolve_presentation_proof_type_for_request,
    single_leaf_inclusion_witness,
    single_leaf_set_root,
)
from .credential import (  # noqa: F401
    AccumulatorWitness,
    Credential,
    RebindAttestation,
    ProofRequest,
    TrustPolicy,
    TrustedIssuer,
)
from .errors import (  # noqa: F401
    AmbiguousCredentialError,
    AnonymousCompositeRefusedError,
    BackendUnavailableError,
    CanonicalSetMismatchError,
    ConsentRequiredError,
    ConstraintViolationError,
    ContextError,
    ExactMemberConsentRequiredError,
    ForbiddenMaterialError,
    HolderError,
    NoMatchingCredentialError,
    OpaquePredicateError,
    OverbroadRequestError,
    SecretInRequestError,
    StaleCredentialError,
    StaleWitnessError,
    StorageError,
    UnauthenticatedProofTypeError,
    UnknownIssuerError,
)
from .rebind_secret import (  # noqa: F401
    REBIND_SECRET_PARAMETER_KEYS,
    RebindSecret,
    is_secret_key,
    refuse_secret_parameters,
)
from .lifecycle import (  # noqa: F401
    STATE_AGING,
    STATE_FRESH,
    STATE_STALE,
    STATE_UNUSABLE,
    CredentialHealth,
    LifecycleManager,
    RefreshPolicy,
    TickReport,
    assess_credential,
)
from .planner import (  # noqa: F401
    NEGOTIATION_VERSION,
    REFUSAL_MESSAGE,
    NegotiationCounterOffer,
    NegotiationDecision,
    NegotiationRequest,
    PlanItem,
    PlanReport,
    ProofPlanner,
    evaluate_counter_offer,
)
from .registry import (  # noqa: F401
    ArtifactBinding,
    BindingResolutionError,
    DEFAULT_ACCEPTED_STATUSES,
    REVIEW_STATUSES,
    PredicateEntry,
    PredicateRegistry,
    ResolvedPredicateBinding,
)
from .store import (  # noqa: F401
    CredentialStore,
    EncryptedFileCredentialStore,
    InMemoryCredentialStore,
    SQLiteCredentialStore,
)
from .delegation import SQLiteDelegationUseStore, delegation_request_digest  # noqa: F401

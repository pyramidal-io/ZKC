"""Shared ZKC cryptographic primitives (stdlib-only reference implementation).

Bit-compatible with the Noir circuits in noir/: Poseidon2 (BN254, t=4 sponge),
KDC §A.6 credential binding, claim bindings, credential digests, depth-32
Poseidon2 Merkle trees, secp256k1 ECDSA, proof-context construction, and
zkc:proof:v1 envelope validation.

Used by the reference holder SDK (zkc_holder), verifier (zkc_verifier), and
the conformance suite. All KAT-pinned against tests/vectors/zkc_core_vectors.json.
"""

from .field import (  # noqa: F401
    FIELD_MODULUS,
    canonical_hex_to_field,
    derive_domain,
    field_to_hex,
    hex_to_field,
    string_to_field,
)
from .master_seed import (  # noqa: F401
    MASTER_SEED_BYTES,
    MASTER_SEED_PROFILE,
    generate_master_seed,
    master_seed_to_bytes,
    master_seed_to_field,
    master_seed_to_hex,
)
from .poseidon2 import hash_fields, permutation, poseidon2, poseidon3, poseidon4  # noqa: F401
from .kdc import (  # noqa: F401
    DOMAIN_ZKC_BINDING,
    DOMAIN_ZKC_CLAIM,
    DOMAIN_ZKC_CREDENTIAL,
    compute_claim_binding_2,
    compute_claim_binding_3,
    compute_claim_binding_4,
    derive_credential_binding_key,
    derive_holder_commitment,
    derive_holder_commitment_from_seed,
)
from .presentation import (  # noqa: F401
    ANONYMOUS_PROFILE,
    DOMAIN_ZKC_PRESENTATION_SCOPE,
    DOMAIN_ZKC_SCOPE,
    DOMAIN_ZKC_VERIFIER_ID,
    LINKABLE_PROFILE,
    SCOPED_PROFILE,
    derive_presentation_pseudonym,
    derive_scope_id,
    derive_verifier_identity,
)
from .digests import (  # noqa: F401
    compute_attribute_flags_hash,
    compute_jurisdiction_credential_digest,
    compute_jurisdiction_leaf,
    compute_kyc_credential_digest,
    compute_profile_digest,
    compute_profile_digest_v2,
    compute_rebind_attestation_digest,
    REBIND_ATTESTATION_TYPE,
    REBIND_ATTESTATION_VERSION,
    compute_runtime_attestation_claim_commitment,
    compute_runtime_attestation_credential_digest,
    compute_selective_disclosure_binding,
    compute_selective_disclosure_binding_v3,
    compute_selective_disclosure_credential_digest,
    compute_selective_disclosure_credential_digest_v2,
    digest_to_message_bytes,
    parse_attribute_layout_id,
    LEGACY_SELECTIVE_DISCLOSURE_PROOF_TYPES,
    RUNTIME_ATTESTATION_ROOT_CLASS_CODES,
    RUNTIME_ATTESTATION_SCHEMA_ID,
    SELECTIVE_DISCLOSURE_MAX_ATTRIBUTES,
)
from .merkle import (  # noqa: F401
    MERKLE_DEPTH,
    SparseMerkleAccumulator,
    compute_merkle_root,
    zero_subtree_root,
)
from .canonical_set import (  # noqa: F401
    CANONICAL_CODE_MAX,
    CANONICAL_CODE_MIN,
    CANONICAL_SENTINEL_MAX,
    CANONICAL_SENTINEL_MIN,
    CANONICAL_SET_EXCLUSION,
    CANONICAL_SET_INCLUSION,
    CANONICAL_SET_MAX_MEMBERS,
    CANONICAL_SET_MAX_REQUEST_CODES,
    CANONICAL_SET_MODES,
    CANONICAL_SET_PARAM,
    CANONICAL_SET_PARAM_KEYS,
    JURISDICTION_CANONICAL_SET_PARAM,
    CanonicalCodeSet,
    CanonicalSetError,
    MembershipWitness,
    NonMembershipWitness,
    jurisdiction_leaf_encoder,
    raw_code_leaf,
)
from .context import (  # noqa: F401
    DOMAIN_ZKC_CONTEXT,
    DOMAIN_ZKC_PURPOSE,
    PURPOSE_BOUND_PROFILE,
    VERIFIER_SESSION_PROFILE,
    ProofContext,
    canonical_purpose,
    purpose_tag,
)
from .apr import (  # noqa: F401
    DOMAIN_ZKC_APR,
    DOMAIN_ZKC_RECEIPT,
    REFERENCE_SIGNATURE_SCHEME,
    SUPPORTED_SIGNATURE_SCHEMES,
    apr_digest_from_dict,
    apr_freshness,
    apr_signer_pubkey,
    context_value_from_fixture,
    recompute_purpose_bound_context,
    receipt_digest_from_dict,
    scope_from_apr_presentation,
    verification_context_extension,
    sign_apr,
    sign_receipt,
    verify_apr_signature,
    verify_receipt,
)
from .holder_keys import (  # noqa: F401
    derive_audit_authorization_key,
    derive_audit_authorization_root,
    derive_fresh_receipt_key,
    derive_linkable_receipt_key,
    derive_scoped_receipt_key,
    holder_key_matches,
    holder_public_key,
)
from .envelope import (  # noqa: F401
    EnvelopeError,
    validate_compliance_proof_v1,
    validate_compliance_proof_v2,
    validate_envelope,
)
from .encoders import PublicInputBindings, PublicInputEncoder  # noqa: F401
from .delegation import (  # noqa: F401
    DELEGATION_TOKEN_DIGEST_VERSION,
    DelegatedProver,
    DelegationError,
    DelegationToken,
    ViewingScope,
    derive_delegation_signing_key,
    delegation_authorization_digest,
    delegation_token_transcript_v2,
    mint_delegation_token,
    validate_delegation_identifier,
)

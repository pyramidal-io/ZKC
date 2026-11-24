"""Reference statements whose successors add the nonzero credential constraint.

The predecessor names select witness builders and request semantics only.
Proofs, issuer trust, and verification keys use the exact successor identity.
"""

from types import MappingProxyType

NONZERO_CREDENTIAL_CIRCUIT_PREDECESSORS = MappingProxyType({
    "zkc_community_kyc_v3": "zkc_community_kyc_v2",
    "zkc_kyc_v4": "zkc_kyc_v3",
    "zkc_jurisdiction_v7": "zkc_jurisdiction_v3",
    "zkc_jurisdiction_v8": "zkc_jurisdiction_v6",
    "zkc_remaining_predicates_v12": "zkc_remaining_predicates_v7",
    "zkc_remaining_predicates_v13": "zkc_remaining_predicates_v10",
    "zkc_remaining_predicates_v14": "zkc_remaining_predicates_v11",
    "zkc_credential_rebind_auth_linkable_v2": "zkc_credential_rebind_auth",
    "zkc_credential_rebind_auth_v4": "zkc_credential_rebind_auth_v3",
    "zkc_selective_disclosure_v4": "zkc_selective_disclosure_v3",
})

NONZERO_LINKABLE_PROOF_PREDECESSORS = MappingProxyType({
    "zkc:proof:community_kyc:v3": "zkc:proof:community_kyc:v2",
    "zkc:proof:jurisdiction:v7": "zkc:proof:jurisdiction:v3",
    "zkc:proof:accreditation:v12": "zkc:proof:accreditation:v7",
    "zkc:proof:source:v12": "zkc:proof:source:v7",
    "zkc:proof:tax:v12": "zkc:proof:tax:v7",
    "zkc:proof:sanctions:v12": "zkc:proof:sanctions:v7",
    "zkc:proof:credential_rebind:v4": "zkc:proof:credential_rebind:v3",
})

NONZERO_CREDENTIAL_PROOF_PREDECESSORS = MappingProxyType({
    **NONZERO_LINKABLE_PROOF_PREDECESSORS,
    "zkc:proof:kyc:v4": "zkc:proof:kyc:v3",
    "zkc:proof:jurisdiction:v8": "zkc:proof:jurisdiction:v6",
    "zkc:proof:accreditation:v13": "zkc:proof:accreditation:v10",
    "zkc:proof:source:v13": "zkc:proof:source:v10",
    "zkc:proof:tax:v13": "zkc:proof:tax:v10",
    "zkc:proof:sanctions:v13": "zkc:proof:sanctions:v10",
    "zkc:proof:source:v14": "zkc:proof:source:v11",
    "zkc:proof:tax:v14": "zkc:proof:tax:v11",
    "zkc:proof:sanctions:v14": "zkc:proof:sanctions:v11",
    "zkc:proof:rebind:v6": "zkc:proof:rebind:v5",
    "zkc:proof:selective_disclosure:v4": "zkc:proof:selective_disclosure:v3",
})

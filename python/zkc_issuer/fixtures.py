"""Sandbox subject fixtures for the mock issuer adapter.

Each fixture is a pre-verified sandbox subject with per-schema claims.
Fixtures are provider-shaped but provider-neutral: they stand in for the
outcome of provider-specific verification (KYC vendor, accreditation review,
sanctions screening, …) without integrating any provider. NO fixture carries
wallet material — claims contain only what the issuer legitimately attests.
"""

from __future__ import annotations

from zkc_crypto.code_spaces import (
    JURISDICTION_CODE_SPACE_ID,
    SCREENING_CODE_SPACE_ID,
    SOURCE_CODE_SPACE_ID,
    TAX_CODE_SPACE_ID,
)

__all__ = ["SANDBOX_FIXTURES"]

_FAR_FUTURE = 2_000_000_000
_PAST = 1_600_000_000
SANDBOX_ATTRIBUTE_LAYOUT_ID = "0x" + "0" * 63 + "1"

# fixture_id -> schema_id -> {"claims": ..., "expiresAt": ...}
SANDBOX_FIXTURES = {
    "sandbox-alice-basic": {
        "zkc:cred:kyc:v1": {
            "claims": {"level": 1, "verifiedAttributes": [True, True, False, True, True]},
            "expiresAt": _FAR_FUTURE,
        },
        "zkc:cred:jurisdiction:v1": {
            "claims": {
                "jurisdictionCode": 840,  # ISO 3166-1 numeric: US
                "claimType": 0,
                "verificationMethod": 1,
                "validFrom": _PAST,
                "validUntil": _FAR_FUTURE,
            },
            "expiresAt": _FAR_FUTURE,
        },
        "zkc:cred:attribute-set:v1": {
            "claims": {
                "attributeCount": 4,
                "attributes": [0, 11, 22, 33],
            },
            "expiresAt": _FAR_FUTURE,
            "attributeLayoutId": SANDBOX_ATTRIBUTE_LAYOUT_ID,
        },
        "zkc:cred:attribute-set:v2": {
            "claims": {
                "layoutId": SANDBOX_ATTRIBUTE_LAYOUT_ID,
                "attributeCount": 4,
                "attributes": [0, 11, 22, 33],
            },
            "expiresAt": _FAR_FUTURE,
        },
    },
    "sandbox-bob-enhanced": {
        "zkc:cred:kyc:v1": {
            "claims": {"level": 3, "verifiedAttributes": [True, True, True, True, True]},
            "expiresAt": _FAR_FUTURE,
        },
        "zkc:cred:tax:v2": {
            "claims": {
                "taxResidencyCode": 276,  # ISO 3166-1 numeric: DE
                "taxYear": 2025,
                "validFrom": _PAST,
                "validUntil": _FAR_FUTURE,
            },
            "expiresAt": _FAR_FUTURE,
        },
        "zkc:cred:source:v2": {
            "claims": {
                "sourceOfFundsCode": 7,  # issuer-local source taxonomy
                "validFrom": _PAST,
                "validUntil": _FAR_FUTURE,
            },
            "expiresAt": _FAR_FUTURE,
        },
    },
    "sandbox-carol-institutional": {
        "zkc:cred:accreditation:v2": {
            "claims": {
                "accreditationLevel": 3,
                "institutional": True,
                "validFrom": _PAST,
                "validUntil": _FAR_FUTURE,
            },
            "expiresAt": _FAR_FUTURE,
        },
        "zkc:cred:sanctions:v2": {
            "claims": {
                "screeningCode": 4242,  # issuer-local screening identifier
                "validFrom": _PAST,
                "validUntil": _FAR_FUTURE,
            },
            "expiresAt": _FAR_FUTURE,
        },
    },
}

# Explicit provider fixture provisioning for additive code-space schemas.
# The historical fixture claims above retain their original identities.
for _fixture_id, _old_schema, _new_schema, _code_space_id in (
    ("sandbox-alice-basic", "zkc:cred:jurisdiction:v1", "zkc:cred:jurisdiction:v2", JURISDICTION_CODE_SPACE_ID),
    ("sandbox-bob-enhanced", "zkc:cred:source:v2", "zkc:cred:source:v3", SOURCE_CODE_SPACE_ID),
    ("sandbox-bob-enhanced", "zkc:cred:tax:v2", "zkc:cred:tax:v3", TAX_CODE_SPACE_ID),
    ("sandbox-carol-institutional", "zkc:cred:sanctions:v2", "zkc:cred:sanctions:v3", SCREENING_CODE_SPACE_ID),
):
    _old_entry = SANDBOX_FIXTURES[_fixture_id][_old_schema]
    SANDBOX_FIXTURES[_fixture_id][_new_schema] = {
        "claims": {**_old_entry["claims"], "codeSpaceId": _code_space_id},
        "expiresAt": _old_entry["expiresAt"],
    }

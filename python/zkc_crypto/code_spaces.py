"""Pinned integer namespaces for code-space-bound predicate successors.

Country assignments are a static 2026-11-18 ISO 3166-1 numeric-3 snapshot:
248 ISO-alpha2 rows from the official UNSD M49 overview, plus TW=158 from
UN Population Division metadata. UN-only entries, reserved alpha-2 identifiers,
regions and historical assignments are excluded. No runtime network lookup.

The two sanctions registries are bounded synthetic test registries, NOT real
sanctions lists. Their code spaces enumerate both listed and unlisted subjects;
blocked-set assertions are separate from code-space identity and may change
without redefining the identity of a subject.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from .field import canonical_hex_to_field, field_to_hex, string_to_field

CODE_SPACE_DOMAIN = "zkc:code-space:v1:"
COUNTRY_SNAPSHOT_REVISION = "2026-11-18"
COUNTRY_SOURCE_URL = "https://unstats.un.org/unsd/methodology/m49/overview/"
COUNTRY_SOURCE_SHA256 = "b9048114f6e7f2abda83bf03d4263c9d7cd1bd7230e3d0461025ee7839a7a1fb"
TAIWAN_SOURCE_URL = "https://population.un.org/dataportal/data/indicators/19/locations/158/start/1980/end/2026/metadata/metadatalocations"

# Leading zeros in ISO numeric-3 are display syntax; field values are integers.
ISO_ALPHA2_TO_NUMERIC = MappingProxyType({
    "AD": 20,
    "AE": 784,
    "AF": 4,
    "AG": 28,
    "AI": 660,
    "AL": 8,
    "AM": 51,
    "AO": 24,
    "AQ": 10,
    "AR": 32,
    "AS": 16,
    "AT": 40,
    "AU": 36,
    "AW": 533,
    "AX": 248,
    "AZ": 31,
    "BA": 70,
    "BB": 52,
    "BD": 50,
    "BE": 56,
    "BF": 854,
    "BG": 100,
    "BH": 48,
    "BI": 108,
    "BJ": 204,
    "BL": 652,
    "BM": 60,
    "BN": 96,
    "BO": 68,
    "BQ": 535,
    "BR": 76,
    "BS": 44,
    "BT": 64,
    "BV": 74,
    "BW": 72,
    "BY": 112,
    "BZ": 84,
    "CA": 124,
    "CC": 166,
    "CD": 180,
    "CF": 140,
    "CG": 178,
    "CH": 756,
    "CI": 384,
    "CK": 184,
    "CL": 152,
    "CM": 120,
    "CN": 156,
    "CO": 170,
    "CR": 188,
    "CU": 192,
    "CV": 132,
    "CW": 531,
    "CX": 162,
    "CY": 196,
    "CZ": 203,
    "DE": 276,
    "DJ": 262,
    "DK": 208,
    "DM": 212,
    "DO": 214,
    "DZ": 12,
    "EC": 218,
    "EE": 233,
    "EG": 818,
    "EH": 732,
    "ER": 232,
    "ES": 724,
    "ET": 231,
    "FI": 246,
    "FJ": 242,
    "FK": 238,
    "FM": 583,
    "FO": 234,
    "FR": 250,
    "GA": 266,
    "GB": 826,
    "GD": 308,
    "GE": 268,
    "GF": 254,
    "GG": 831,
    "GH": 288,
    "GI": 292,
    "GL": 304,
    "GM": 270,
    "GN": 324,
    "GP": 312,
    "GQ": 226,
    "GR": 300,
    "GS": 239,
    "GT": 320,
    "GU": 316,
    "GW": 624,
    "GY": 328,
    "HK": 344,
    "HM": 334,
    "HN": 340,
    "HR": 191,
    "HT": 332,
    "HU": 348,
    "ID": 360,
    "IE": 372,
    "IL": 376,
    "IM": 833,
    "IN": 356,
    "IO": 86,
    "IQ": 368,
    "IR": 364,
    "IS": 352,
    "IT": 380,
    "JE": 832,
    "JM": 388,
    "JO": 400,
    "JP": 392,
    "KE": 404,
    "KG": 417,
    "KH": 116,
    "KI": 296,
    "KM": 174,
    "KN": 659,
    "KP": 408,
    "KR": 410,
    "KW": 414,
    "KY": 136,
    "KZ": 398,
    "LA": 418,
    "LB": 422,
    "LC": 662,
    "LI": 438,
    "LK": 144,
    "LR": 430,
    "LS": 426,
    "LT": 440,
    "LU": 442,
    "LV": 428,
    "LY": 434,
    "MA": 504,
    "MC": 492,
    "MD": 498,
    "ME": 499,
    "MF": 663,
    "MG": 450,
    "MH": 584,
    "MK": 807,
    "ML": 466,
    "MM": 104,
    "MN": 496,
    "MO": 446,
    "MP": 580,
    "MQ": 474,
    "MR": 478,
    "MS": 500,
    "MT": 470,
    "MU": 480,
    "MV": 462,
    "MW": 454,
    "MX": 484,
    "MY": 458,
    "MZ": 508,
    "NA": 516,
    "NC": 540,
    "NE": 562,
    "NF": 574,
    "NG": 566,
    "NI": 558,
    "NL": 528,
    "NO": 578,
    "NP": 524,
    "NR": 520,
    "NU": 570,
    "NZ": 554,
    "OM": 512,
    "PA": 591,
    "PE": 604,
    "PF": 258,
    "PG": 598,
    "PH": 608,
    "PK": 586,
    "PL": 616,
    "PM": 666,
    "PN": 612,
    "PR": 630,
    "PS": 275,
    "PT": 620,
    "PW": 585,
    "PY": 600,
    "QA": 634,
    "RE": 638,
    "RO": 642,
    "RS": 688,
    "RU": 643,
    "RW": 646,
    "SA": 682,
    "SB": 90,
    "SC": 690,
    "SD": 729,
    "SE": 752,
    "SG": 702,
    "SH": 654,
    "SI": 705,
    "SJ": 744,
    "SK": 703,
    "SL": 694,
    "SM": 674,
    "SN": 686,
    "SO": 706,
    "SR": 740,
    "SS": 728,
    "ST": 678,
    "SV": 222,
    "SX": 534,
    "SY": 760,
    "SZ": 748,
    "TC": 796,
    "TD": 148,
    "TF": 260,
    "TG": 768,
    "TH": 764,
    "TJ": 762,
    "TK": 772,
    "TL": 626,
    "TM": 795,
    "TN": 788,
    "TO": 776,
    "TR": 792,
    "TT": 780,
    "TV": 798,
    "TW": 158,
    "TZ": 834,
    "UA": 804,
    "UG": 800,
    "UM": 581,
    "US": 840,
    "UY": 858,
    "UZ": 860,
    "VA": 336,
    "VC": 670,
    "VE": 862,
    "VG": 92,
    "VI": 850,
    "VN": 704,
    "VU": 548,
    "WF": 876,
    "WS": 882,
    "YE": 887,
    "YT": 175,
    "ZA": 710,
    "ZM": 894,
    "ZW": 716,
})

CLAIM_TYPES = MappingProxyType({"residency": 0, "citizenship": 1, "tax_residency": 2})
VERIFICATION_METHODS = MappingProxyType({
    "government_id": 1, "utility_bill": 2, "tax_return": 3, "passport": 4,
})
SOURCE_OF_FUNDS_CODES = MappingProxyType({
    "employment_income": 1, "business_income": 2, "investment_returns": 3,
    "inheritance": 4, "gift": 5, "sale_of_assets": 6,
    "regulated_exchange": 7, "other_verified": 8,
})

CODE_SPACE_PROOF_TO_KIND = MappingProxyType({
    "zkc:proof:jurisdiction:v6": "jurisdiction",
    "zkc:proof:jurisdiction:v8": "jurisdiction",
    "zkc:proof:source:v11": "source",
    "zkc:proof:tax:v11": "tax",
    "zkc:proof:sanctions:v11": "sanctions",
    "zkc:proof:source:v14": "source",
    "zkc:proof:tax:v14": "tax",
    "zkc:proof:sanctions:v14": "sanctions",
})
CODE_SPACE_CREDENTIAL_TO_KIND = MappingProxyType({
    "zkc:cred:jurisdiction:v2": "jurisdiction",
    "zkc:cred:source:v3": "source",
    "zkc:cred:tax:v3": "tax",
    "zkc:cred:sanctions:v3": "sanctions",
})


def _plain_manifest(value):
    # Restricted JCS subset: printable ASCII strings, string object keys,
    # arrays, and exact small integers. No floats, booleans, null or Unicode.
    # ASCII key ordering equals UTF-16 ordering; json emits canonical integers.
    if isinstance(value, Mapping):
        if any(type(key) is not str or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", key)
               for key in value):
            raise ValueError("manifest keys must be ASCII identifiers")
        return {key: _plain_manifest(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_manifest(item) for item in value]
    if type(value) is str and all(32 <= ord(char) <= 126 for char in value):
        return value
    if type(value) is int and 0 <= value <= 65535:
        return value
    raise ValueError("manifest value is outside the restricted JCS subset")


def canonical_manifest_json(manifest: Mapping) -> str:
    """Return RFC 8785 JCS for the supported ASCII/small-integer subset."""
    if not isinstance(manifest, Mapping):
        raise ValueError("manifest must be an object")
    return json.dumps(_plain_manifest(manifest), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class CodeSpace:
    """An immutable, fully enumerated integer namespace, not a policy list."""

    id: str
    field_id: int
    kind: str
    manifest: Mapping
    codes: Mapping[str, int]

    def validate_code(self, code: int) -> int:
        if type(code) is not int or not 1 <= code <= 65534 or code not in self.codes.values():
            raise ValueError("code is not assigned in this code space")
        return code

    def parse_code(self, key: str) -> int:
        """Resolve an exact case-sensitive symbolic key, with no normalization."""
        if type(key) is not str or key not in self.codes:
            raise ValueError("unknown code-space key")
        return self.validate_code(self.codes[key])


def parse_country_code(alpha2: str) -> int:
    """Parse an exact, uppercase officially assigned ISO 3166-1 alpha-2 key."""
    if type(alpha2) is not str or alpha2 not in ISO_ALPHA2_TO_NUMERIC:
        raise ValueError("unknown officially assigned ISO alpha-2 code")
    return ISO_ALPHA2_TO_NUMERIC[alpha2]


def validate_claim_type(code: int) -> int:
    if type(code) is not int or code not in CLAIM_TYPES.values():
        raise ValueError("unassigned claimType")
    return code


def validate_verification_method(code: int) -> int:
    if type(code) is not int or code not in VERIFICATION_METHODS.values():
        raise ValueError("unassigned verificationMethod")
    return code


def _country_manifest(kind):
    manifest = {
        "format": "zkc-code-space-v1", "kind": kind,
        "authority": "ISO-3166-MA", "listId": "ISO-3166-1-numeric-3",
        "revision": COUNTRY_SNAPSHOT_REVISION,
        "source": COUNTRY_SOURCE_URL, "sourceSha256": COUNTRY_SOURCE_SHA256,
        "supplementSource": TAIWAN_SOURCE_URL,
        "matching": "exact-uppercase-ISO-alpha2-no-normalization",
        "scope": "officially-assigned-ISO-3166-1-only",
        "codes": dict(ISO_ALPHA2_TO_NUMERIC),
    }
    if kind == "jurisdiction":
        manifest["claimTypes"] = dict(CLAIM_TYPES)
    return manifest


def _screening_manifest(list_id, listed, unlisted):
    return {
        "format": "zkc-code-space-v1", "kind": "sanctions",
        "authority": "ZKC-synthetic-fixture-authority", "listId": list_id,
        "revision": "1", "scope": "bounded-synthetic-only-no-production-claims",
        "matching": "exact-ASCII-subject-key-no-normalization-no-name-matching",
        "codes": {"sandbox_listed": listed, "sandbox_unlisted": unlisted},
    }


def _space(manifest):
    canonical = canonical_manifest_json(manifest)
    field_id = string_to_field(CODE_SPACE_DOMAIN + canonical)
    if not field_id:
        raise ValueError("code-space ID must be nonzero")
    return CodeSpace(field_to_hex(field_id), field_id, manifest["kind"],
                     _freeze(manifest), MappingProxyType(dict(manifest["codes"])))


_BUILTINS = (
    _space(_country_manifest("jurisdiction")),
    _space({
        "format": "zkc-code-space-v1", "kind": "source", "authority": "ZKC",
        "listId": "source-of-funds-v1", "revision": "1",
        "matching": "exact-ASCII-enum-key-no-normalization",
        "codes": dict(SOURCE_OF_FUNDS_CODES),
        "verificationMethods": dict(VERIFICATION_METHODS),
    }),
    _space(_country_manifest("tax")),
    _space(_screening_manifest("zkc-synthetic-screening-alpha-v1", 4242, 4343)),
    _space(_screening_manifest("zkc-synthetic-screening-beta-v1", 5242, 5343)),
)
(JURISDICTION_CODE_SPACE_ID, SOURCE_CODE_SPACE_ID, TAX_CODE_SPACE_ID,
 SCREENING_CODE_SPACE_ID, SECOND_SCREENING_CODE_SPACE_ID) = (space.id for space in _BUILTINS)
CODE_SPACES = MappingProxyType({space.id: space for space in _BUILTINS})
CODE_SPACE_MANIFESTS = MappingProxyType({space.id: space.manifest for space in _BUILTINS})
# Example assertions for conformance only: these are intentionally not ID inputs.
SYNTHETIC_BLOCKED_CODES = MappingProxyType({
    SCREENING_CODE_SPACE_ID: (4242,), SECOND_SCREENING_CODE_SPACE_ID: (5242,),
})


def get_code_space(id: str, kind: str) -> CodeSpace:
    """Resolve a known canonical nonzero BN254 field hex ID for an exact kind."""
    if canonical_hex_to_field(id) == 0:
        raise ValueError("codeSpaceId must be a nonzero canonical field element")
    if type(kind) is not str or kind not in {"jurisdiction", "source", "tax", "sanctions"}:
        raise ValueError("unknown code-space kind")
    space = CODE_SPACES.get(id)
    if space is None or space.kind != kind:
        raise ValueError("unknown codeSpaceId or wrong code-space kind")
    return space

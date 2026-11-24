#!/usr/bin/env python3
"""Dependency-free issuer metadata conformance checks."""

from __future__ import annotations

import json
import hashlib
import pathlib
import re
import sys
from datetime import datetime


ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "issuer_adapter" / "valid_issuer_metadata.json"
VECTOR = ROOT / "tests" / "vectors" / "revocation_announcement_v3.json"
SPEC = ROOT / "docs" / "zkc_issuer_adapter_protocol_v1.md"
sys.path.insert(0, str(ROOT / "python"))

from zkc_crypto import digest_to_message_bytes, hex_to_field  # noqa: E402
from zkc_crypto.ecdsa_secp256k1 import verify as ecdsa_verify  # noqa: E402
from zkc_crypto.field import FIELD_MODULUS  # noqa: E402
from zkc_crypto.code_spaces import CODE_SPACE_CREDENTIAL_TO_KIND, get_code_space  # noqa: E402

ERROR_CODES = {
    "UNSUPPORTED_SCHEMA",
    "INVALID_HOLDER_CHALLENGE",
    "UNTRUSTED_ISSUER_KEY",
    "EXPIRED_ISSUER_KEY",
    "REVOCATION_METADATA_UNAVAILABLE",
    "STALE_ACCUMULATOR_WITNESS",
    "PROVIDER_VERIFICATION_FAILED",
    "RATE_LIMITED",
}


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _text(value: str) -> bytes:
    encoded = value.encode("utf-8")
    require(len(encoded) <= 0xFFFF, "announcement text field is too long")
    return len(encoded).to_bytes(2, "big") + encoded


def announcement_transcript(announcement: dict) -> bytes:
    """Independent mirror of the normative v3 binary signing transcript."""
    return b"".join(
        (
            b"ZKC-EPOCH-ANNOUNCEMENT\x00\x03",
            _text(announcement["version"]),
            _text(announcement["accumulatorId"]),
            bytes.fromhex(announcement["root"].removeprefix("0x")),
            int(announcement["epoch"]).to_bytes(8, "big"),
            int(announcement["announcedAt"]).to_bytes(8, "big"),
            int(announcement["maxEpochLag"]).to_bytes(8, "big"),
            _text(announcement["signingKeyId"]),
            bytes.fromhex(
                announcement["previousAnnouncementHash"].removeprefix("0x")
            ),
        )
    )


def complete_announcement_bytes(announcement: dict) -> bytes:
    transcript = announcement_transcript(announcement)
    signature = bytes.fromhex(announcement["signature"].removeprefix("0x"))
    return (
        b"ZKC-EPOCH-ANNOUNCEMENT-COMPLETE\x00\x03"
        + len(transcript).to_bytes(2, "big")
        + transcript
        + signature
    )


def validate_announcement(announcement: dict, signing_keys: list) -> None:
    require(
        set(announcement)
        == {
            "version",
            "accumulatorId",
            "root",
            "epoch",
            "announcedAt",
            "maxEpochLag",
            "signingKeyId",
            "previousAnnouncementHash",
            "signature",
        },
        "announcement fields must be the exact closed v3 set",
    )
    require(
        announcement["version"] == "zkc:epoch-announcement:v3",
        "announcement version mismatch",
    )
    require(
        re.fullmatch(r"0x[0-9a-f]{64}", announcement["root"]) is not None,
        "bad announcement root",
    )
    try:
        hex_to_field(announcement["root"])
    except ValueError:
        require(False, "announcement root is not a canonical field element")
    require(
        re.fullmatch(r"0x[0-9a-f]{64}", announcement["previousAnnouncementHash"])
        is not None,
        "bad predecessor hash",
    )
    require(
        re.fullmatch(r"0x[0-9a-f]{128}", announcement["signature"]) is not None,
        "bad announcement signature",
    )
    require(
        type(announcement["epoch"]) is int
        and 0 <= announcement["epoch"] < 1 << 64,
        "bad epoch",
    )
    require(
        type(announcement["announcedAt"]) is int
        and 0 < announcement["announcedAt"] < 1 << 64,
        "bad announcement time",
    )
    require(
        type(announcement["maxEpochLag"]) is int
        and 0 <= announcement["maxEpochLag"] <= 10,
        "bad announcement lag",
    )
    require(
        type(announcement["accumulatorId"]) is str
        and 0 < len(announcement["accumulatorId"].encode("utf-8")) <= 0xFFFF,
        "bad accumulator id",
    )
    require(
        type(announcement["signingKeyId"]) is str
        and 0 < len(announcement["signingKeyId"].encode("utf-8")) <= 0xFFFF,
        "bad signing key id",
    )
    key = next(
        (entry for entry in signing_keys if entry["keyId"] == announcement["signingKeyId"]),
        None,
    )
    require(key is not None, "announcement signingKeyId is absent from metadata")
    public_key = bytes.fromhex(key["publicKey"].removeprefix("0x"))
    require(len(public_key) == 64, "announcement key must contain x||y")
    digest = int.from_bytes(hashlib.sha256(announcement_transcript(announcement)).digest(), "big")
    digest %= FIELD_MODULUS
    signature = bytes.fromhex(announcement["signature"].removeprefix("0x"))
    require(
        ecdsa_verify(
            public_key[:32],
            public_key[32:],
            signature,
            digest_to_message_bytes(digest),
        ),
        "announcement signature does not verify over the v3 transcript",
    )


def liveness_transcript(liveness: dict) -> bytes:
    """Independent mirror of the normative zkc:epoch-liveness:v1 transcript."""
    return b"".join(
        (
            b"ZKC-EPOCH-LIVENESS\x00\x01",
            _text(liveness["version"]),
            _text(liveness["accumulatorId"]),
            int(liveness["epoch"]).to_bytes(8, "big"),
            bytes.fromhex(liveness["headHash"].removeprefix("0x")),
            int(liveness["issuedAt"]).to_bytes(8, "big"),
            _text(liveness["signingKeyId"]),
        )
    )


def validate_liveness(liveness: dict, announcement: dict, signing_keys: list) -> None:
    """Check a published head liveness statement against its announcement."""
    require(
        set(liveness)
        == {
            "version",
            "accumulatorId",
            "epoch",
            "headHash",
            "issuedAt",
            "signingKeyId",
            "signature",
        },
        "liveness fields must be the exact closed v1 set",
    )
    require(liveness["version"] == "zkc:epoch-liveness:v1", "liveness version mismatch")
    require(
        re.fullmatch(r"0x[0-9a-f]{64}", liveness["headHash"]) is not None,
        "bad liveness head hash",
    )
    require(
        re.fullmatch(r"0x[0-9a-f]{128}", liveness["signature"]) is not None,
        "bad liveness signature",
    )
    require(
        type(liveness["epoch"]) is int and 0 <= liveness["epoch"] < 1 << 64,
        "bad liveness epoch",
    )
    require(
        type(liveness["issuedAt"]) is int and 0 < liveness["issuedAt"] < 1 << 64,
        "bad liveness time",
    )
    for name in ("accumulatorId", "signingKeyId"):
        require(
            type(liveness[name]) is str
            and 0 < len(liveness[name].encode("utf-8")) <= 0xFFFF,
            f"bad liveness {name}",
        )
    require(
        liveness["accumulatorId"] == announcement["accumulatorId"]
        and liveness["epoch"] == announcement["epoch"]
        and liveness["headHash"]
        == "0x" + hashlib.sha256(complete_announcement_bytes(announcement)).hexdigest(),
        "liveness does not name the current announcement",
    )
    key = next(
        (entry for entry in signing_keys if entry["keyId"] == liveness["signingKeyId"]),
        None,
    )
    require(key is not None, "liveness signingKeyId is absent from metadata")
    require(
        parse_time(key["notBefore"]).timestamp()
        <= liveness["issuedAt"]
        < parse_time(key["notAfter"]).timestamp(),
        "liveness issuedAt is outside its key validity window",
    )
    public_key = bytes.fromhex(key["publicKey"].removeprefix("0x"))
    require(len(public_key) == 64, "liveness key must contain x||y")
    transcript = liveness_transcript(liveness)
    require(len(transcript) <= 0xFFFF, "liveness transcript exceeds 65535 bytes")
    digest = int.from_bytes(hashlib.sha256(transcript).digest(), "big")
    digest %= FIELD_MODULUS
    signature = bytes.fromhex(liveness["signature"].removeprefix("0x"))
    require(
        ecdsa_verify(
            public_key[:32],
            public_key[32:],
            signature,
            digest_to_message_bytes(digest),
        ),
        "liveness signature does not verify over the v1 transcript",
    )


def validate_metadata(metadata: dict, require_authenticated: bool = False) -> None:
    require(
        metadata["version"] in {"zkc:issuer-metadata:v1", "zkc:issuer-metadata:v2"},
        "metadata version mismatch",
    )
    require(re.fullmatch(r"zkc:issuer:[a-z0-9._-]+", metadata["issuerId"]) is not None, "bad issuerId")
    require(metadata["signingKeys"], "missing signing keys")
    for key in metadata["signingKeys"]:
        require(key["scheme"] in {"ECDSA_SECP256K1", "BLS", "Schnorr"}, "unsupported key scheme")
        require(parse_time(key["notBefore"]) < parse_time(key["notAfter"]), "invalid key validity window")

    require(metadata["supportedSchemas"], "missing schemas")
    bound_schemas = set()
    for schema in metadata["supportedSchemas"]:
        require(type(schema) is dict, "schema declaration must be an object")
        schema_id = schema.get("schemaId")
        require(type(schema_id) is str, "schemaId must be text")
        kind = CODE_SPACE_CREDENTIAL_TO_KIND.get(schema_id)
        if kind is None:
            require("codeSpaceIds" not in schema, "codeSpaceIds requires a code-space schema")
            credential_type = schema.get("credentialType")
            require(type(credential_type) is str, "credentialType must be text")
            require(credential_type not in CODE_SPACE_CREDENTIAL_TO_KIND,
                    "code-space credentialType must match schemaId")
            continue
        require(schema_id not in bound_schemas, "duplicate code-space schema declaration")
        bound_schemas.add(schema_id)
        require(schema.get("credentialType") == schema_id, "code-space credentialType must match schemaId")
        proof_version = 6 if kind == "jurisdiction" else 11
        require(schema.get("proofType") == f"zkc:proof:{kind}:v{proof_version}",
                "code-space schema has the wrong proofType")
        ids = schema.get("codeSpaceIds")
        require(type(ids) is list and bool(ids), "codeSpaceIds must be a nonempty closed list")
        seen = set()
        for code_space_id in ids:
            try:
                get_code_space(code_space_id, kind)
            except (TypeError, ValueError):
                require(False, "unknown or wrong-kind codeSpaceId")
            require(code_space_id not in seen, "duplicate codeSpaceId")
            seen.add(code_space_id)
    adapter = metadata["adapter"]
    for name in [
        "verifySubjectEndpoint",
        "bindHolderCommitmentEndpoint",
        "issueCredentialEndpoint",
        "publishRevocationHandleEndpoint",
    ]:
        require(adapter[name].startswith("https://"), f"{name} must be https")

    revocation = metadata["revocation"]
    require(revocation["type"] == "POSEIDON2_MERKLE_ACTIVE_SET", "bad accumulator type")
    require(re.fullmatch(r"0x[0-9a-f]{64}", revocation["currentRoot"]) is not None, "bad root")
    require(revocation["maxEpochLag"] >= 0, "negative maxEpochLag")
    require(revocation["updateEndpoint"].startswith("https://"), "revocation update endpoint must be https")
    levels = metadata["serviceLevels"]
    for name in [
        "maxRevocationPropagationSeconds",
        "expectedIssuanceLatencySeconds",
        "metadataCacheSeconds",
    ]:
        require(isinstance(levels[name], int) and levels[name] >= 0, f"bad service level {name}")
    if metadata["version"] == "zkc:issuer-metadata:v1":
        require(not require_authenticated, "legacy metadata does not authenticate revocation")
        require(
            "currentAnnouncement" not in revocation,
            "legacy metadata must not masquerade as authenticated v2",
        )
        require(
            "currentLiveness" not in revocation,
            "legacy metadata cannot carry a head liveness statement",
        )
        return
    announcement = revocation["currentAnnouncement"]
    validate_announcement(announcement, metadata["signingKeys"])
    for metadata_name, announcement_name in (
        ("accumulatorId", "accumulatorId"),
        ("currentRoot", "root"),
        ("currentEpoch", "epoch"),
        ("maxEpochLag", "maxEpochLag"),
    ):
        require(
            type(revocation[metadata_name]) is type(announcement[announcement_name])
            and revocation[metadata_name] == announcement[announcement_name],
            f"revocation {metadata_name} does not equal signed {announcement_name}",
        )
    if "currentLiveness" in revocation:
        validate_liveness(revocation["currentLiveness"], announcement, metadata["signingKeys"])


def main() -> int:
    metadata = json.loads(FIXTURE.read_text())
    validate_metadata(metadata, require_authenticated=True)
    vector = json.loads(VECTOR.read_text())
    announcement = vector["announcement"]
    validate_announcement(announcement, metadata["signingKeys"])
    transcript = announcement_transcript(announcement)
    digest = int.from_bytes(hashlib.sha256(transcript).digest(), "big") % FIELD_MODULUS
    require(vector["transcriptHex"] == "0x" + transcript.hex(), "v3 transcript vector mismatch")
    require(
        vector["signingDigest"] == "0x" + digest.to_bytes(32, "big").hex(),
        "v3 signing digest vector mismatch",
    )
    require(
        vector["announcementHash"]
        == "0x" + hashlib.sha256(complete_announcement_bytes(announcement)).hexdigest(),
        "complete predecessor-announcement hash vector mismatch",
    )
    require(metadata["revocation"]["currentAnnouncement"] == announcement, "fixture/vector drift")
    require(
        metadata["revocation"]["currentLiveness"]["headHash"] == vector["announcementHash"],
        "fixture liveness does not name the vector announcement",
    )
    spec = SPEC.read_text()
    for code in ERROR_CODES:
        require(code in spec, f"{code} missing from adapter protocol doc")
    for forbidden in ["masterSeed", "spending key", "ZKA address", "payment history"]:
        require(forbidden in spec, f"privacy boundary missing {forbidden}")
    print("issuer metadata fixture and protocol doc validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Dependency-free validation and executable revocation launch conformance."""

from __future__ import annotations

import copy
import contextlib
import hashlib
import json
import pathlib
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "tests" / "vectors" / "revocation_equivocation_v1.json"
FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
TRANSCRIPT_DOMAIN = b"ZKC-EPOCH-ANNOUNCEMENT\x00\x03"
COMPLETE_DOMAIN = b"ZKC-EPOCH-ANNOUNCEMENT-COMPLETE\x00\x03"
ANNOUNCEMENT_VERSION = "zkc:epoch-announcement:v3"
GENESIS_HASH = "0x" + "00" * 32
ANNOUNCEMENT_FIELDS = {
    "version",
    "accumulatorId",
    "root",
    "epoch",
    "announcedAt",
    "maxEpochLag",
    "signingKeyId",
    "previousAnnouncementHash",
    "signature",
}
LIVENESS_DOMAIN = b"ZKC-EPOCH-LIVENESS\x00\x01"
LIVENESS_VERSION = "zkc:epoch-liveness:v1"
LIVENESS_FIELDS = {
    "version",
    "accumulatorId",
    "epoch",
    "headHash",
    "issuedAt",
    "signingKeyId",
    "signature",
}
EXPECTED_CASE_IDS = [
    "canonical-transcript-stability",
    "signed-field-tamper-matrix",
    "metadata-bootstrap-and-rotation",
    "replay-gap-backfill-and-fork-evidence",
    "durable-restart-publication-head",
    "cold-start-local-checkpoint",
    "isolated-split-view-residual",
    "genesis-issuance-revocation-lifecycle",
    "signature-malleation-by-transcript",
    "announcement-key-validity-window",
    "quiet-issuer-liveness-and-time-bound",
]


class ConformanceFailure(AssertionError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConformanceFailure(message)


def load_vectors() -> dict:
    return json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


def _text(value, name: str) -> bytes:
    if type(value) is not str or not value:
        raise ValueError(f"{name} must be non-empty text")
    encoded = value.encode("utf-8")
    if len(encoded) > 0xFFFF:
        raise ValueError(f"{name} is too long")
    return len(encoded).to_bytes(2, "big") + encoded


def _u64(value, name: str, nonzero: bool = False) -> bytes:
    minimum = 1 if nonzero else 0
    if type(value) is not int or not minimum <= value < 1 << 64:
        raise ValueError(f"{name} is not a canonical u64")
    return value.to_bytes(8, "big")


def _hex(value, size: int, name: str) -> bytes:
    if type(value) is not str or not value.startswith("0x"):
        raise ValueError(f"{name} is not prefixed hex")
    encoded = value[2:]
    # Every character must be a lowercase hex digit: bytes.fromhex skips
    # whitespace, so a length check alone would accept a shorter value.
    if len(encoded) != size * 2 or any(char not in "0123456789abcdef" for char in encoded):
        raise ValueError(f"{name} is not canonical {size}-byte hex")
    return bytes.fromhex(encoded)


def independent_transcript(announcement: dict) -> bytes:
    """Serialize v3 without importing the production serializer."""
    if type(announcement) is not dict or set(announcement) != ANNOUNCEMENT_FIELDS:
        raise ValueError("announcement does not have the closed v3 shape")
    if announcement["version"] != ANNOUNCEMENT_VERSION:
        raise ValueError("unsupported announcement version")
    root = _hex(announcement["root"], 32, "root")
    if int.from_bytes(root, "big") >= FIELD_MODULUS:
        raise ValueError("root is outside the BN254 field")
    max_lag = announcement["maxEpochLag"]
    if type(max_lag) is not int or not 0 <= max_lag <= 10:
        raise ValueError("maxEpochLag is outside the launch range")
    return b"".join(
        (
            TRANSCRIPT_DOMAIN,
            _text(announcement["version"], "version"),
            _text(announcement["accumulatorId"], "accumulatorId"),
            root,
            _u64(announcement["epoch"], "epoch"),
            _u64(announcement["announcedAt"], "announcedAt", nonzero=True),
            _u64(max_lag, "maxEpochLag"),
            _text(announcement["signingKeyId"], "signingKeyId"),
            _hex(announcement["previousAnnouncementHash"], 32, "previousAnnouncementHash"),
        )
    )


def _complete_bytes(announcement: dict) -> bytes:
    transcript = independent_transcript(announcement)
    if len(transcript) > 0xFFFF:
        raise ValueError("transcript is too long")
    return (
        COMPLETE_DOMAIN
        + len(transcript).to_bytes(2, "big")
        + transcript
        + _hex(announcement["signature"], 64, "signature")
    )


def independent_digest_bytes(announcement: dict) -> bytes:
    digest = int.from_bytes(hashlib.sha256(independent_transcript(announcement)).digest(), "big")
    return (digest % FIELD_MODULUS).to_bytes(32, "big")


def independent_digest_hex(announcement: dict) -> str:
    return "0x" + independent_digest_bytes(announcement).hex()


def independent_announcement_hash(announcement: dict) -> str:
    return "0x" + hashlib.sha256(_complete_bytes(announcement)).hexdigest()


def _point_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % SECP_P == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, SECP_P) % SECP_P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, SECP_P) % SECP_P
    x3 = (slope * slope - x1 - x2) % SECP_P
    return x3, (slope * (x1 - x3) - y1) % SECP_P


def _point_mul(scalar: int, point):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def independent_verify(announcement: dict, public_key: str) -> bool:
    """Verify transcript and secp256k1 signature using only the stdlib."""
    try:
        digest = independent_digest_bytes(announcement)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False
    return _independent_signature_ok(digest, announcement.get("signature"), public_key)


def independent_liveness_transcript(statement: dict) -> bytes:
    """Serialize zkc:epoch-liveness:v1 without the production serializer."""
    if type(statement) is not dict or set(statement) != LIVENESS_FIELDS:
        raise ValueError("liveness statement does not have the closed v1 shape")
    if statement["version"] != LIVENESS_VERSION:
        raise ValueError("unsupported liveness statement version")
    transcript = b"".join(
        (
            LIVENESS_DOMAIN,
            _text(statement["version"], "version"),
            _text(statement["accumulatorId"], "accumulatorId"),
            _u64(statement["epoch"], "epoch"),
            _hex(statement["headHash"], 32, "headHash"),
            _u64(statement["issuedAt"], "issuedAt", nonzero=True),
            _text(statement["signingKeyId"], "signingKeyId"),
        )
    )
    if len(transcript) > 0xFFFF:
        raise ValueError("liveness transcript exceeds 65535 bytes")
    return transcript


def independent_liveness_digest_bytes(statement: dict) -> bytes:
    digest = int.from_bytes(
        hashlib.sha256(independent_liveness_transcript(statement)).digest(), "big"
    )
    return (digest % FIELD_MODULUS).to_bytes(32, "big")


def independent_verify_liveness(statement: dict, public_key: str) -> bool:
    try:
        digest = independent_liveness_digest_bytes(statement)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False
    return _independent_signature_ok(digest, statement.get("signature"), public_key)


def _independent_signature_ok(digest: bytes, signature_hex, public_key: str) -> bool:
    try:
        key = _hex(public_key, 64, "publicKey")
        signature = _hex(signature_hex, 64, "signature")
        x = int.from_bytes(key[:32], "big")
        y = int.from_bytes(key[32:], "big")
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        if x >= SECP_P or y >= SECP_P or (y * y - (x * x * x + 7)) % SECP_P:
            return False
        # Low-s only (spec section 2.4.1): the high-s twin (r, n - s) of a
        # valid signature is a keyless re-encoding and MUST be rejected.
        if not (1 <= r < SECP_N and 1 <= s <= SECP_N // 2):
            return False
        inverse = pow(s, -1, SECP_N)
        z = int.from_bytes(digest, "big")
        point = _point_add(
            _point_mul(z * inverse % SECP_N, SECP_G),
            _point_mul(r * inverse % SECP_N, (x, y)),
        )
        return point is not None and point[0] % SECP_N == r
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def validate_vector_document(vectors: dict) -> None:
    _require(vectors.get("version") == "zkc:revocation-equivocation-vectors:v1", "vector version")
    _require(vectors.get("accumulatorId") == "sandbox-active-credentials", "accumulator id")
    keys = vectors.get("keys")
    _require(type(keys) is dict and set(keys) == {"primary", "rotation"}, "public key set")
    for name, key in keys.items():
        _require(set(key) == {"keyId", "publicKey"}, f"{name} key leaks or omits fields")
        _hex(key["publicKey"], 64, f"{name}.publicKey")

    records = vectors.get("announcements")
    _require(type(records) is dict and len(records) >= 7, "announcement records")
    for name, record in records.items():
        _require(
            set(record) == {"key", "announcement", "transcriptHex", "signingDigest", "announcementHash"},
            f"{name} record shape",
        )
        announcement = record["announcement"]
        key = keys[record["key"]]
        _require(announcement["signingKeyId"] == key["keyId"], f"{name} key id")
        _require("0x" + independent_transcript(announcement).hex() == record["transcriptHex"], f"{name} transcript")
        _require(independent_digest_hex(announcement) == record["signingDigest"], f"{name} digest")
        _require(independent_announcement_hash(announcement) == record["announcementHash"], f"{name} complete hash")
        _require(independent_verify(announcement, key["publicKey"]), f"{name} signature")

    for chain_name, chain_names in vectors["chains"].items():
        chain = [records[name] for name in chain_names]
        _require(chain[0]["announcement"]["previousAnnouncementHash"] == GENESIS_HASH, f"{chain_name} genesis")
        for previous, current in zip(chain, chain[1:]):
            _require(current["announcement"]["epoch"] == previous["announcement"]["epoch"] + 1, f"{chain_name} epoch")
            _require(current["announcement"]["previousAnnouncementHash"] == previous["announcementHash"], f"{chain_name} predecessor")

    required_tampers = ANNOUNCEMENT_FIELDS
    tamper_cases = vectors.get("tamperCases")
    _require({case["field"] for case in tamper_cases} == required_tampers, "tamper matrix completeness")
    base = records["revocation"]["announcement"]
    primary_key = keys["primary"]["publicKey"]
    for case in tamper_cases:
        candidate = copy.deepcopy(base)
        candidate[case["field"]] = case["value"]
        _require(not independent_verify(candidate, primary_key), f"tamper accepted: {case['field']}")

    _validate_signature_malleation(vectors)
    _validate_liveness_vectors(vectors)

    cold = vectors.get("coldStart", {})
    _require(cold.get("acceptedAs") == "local-checkpoint-only", "cold-start semantics")
    _require(cold.get("globalConsistencyEstablished") is False, "cold-start global overclaim")
    residual = vectors.get("splitViewResidual", {})
    _require(residual.get("individuallyConsistent") is True, "split-view consistency")
    _require(residual.get("detectedOnlyAfterCheckpointComparison") is True, "split-view detection boundary")


def _validate_signature_malleation(vectors: dict) -> None:
    """Pin the high-s and same-transcript re-signature vectors independently."""
    malleation = vectors.get("signatureMalleation")
    _require(
        type(malleation) is dict
        and set(malleation)
        == {
            "base",
            "successor",
            "highS",
            "resignedSameTranscript",
            "expectedErrorCode",
            "retainsEvidence",
        },
        "signature malleation shape",
    )
    records = vectors["announcements"]
    base = records[malleation["base"]]
    _require(malleation["successor"] in records, "signature malleation successor")
    _require(
        malleation["expectedErrorCode"] == "ANNOUNCEMENT_AUTHENTICATION_FAILED",
        "same-transcript conflicts must be authentication failures",
    )
    _require(malleation["retainsEvidence"] is False, "same-transcript conflicts retain no evidence")
    public_key = vectors["keys"][base["key"]]["publicKey"]
    base_signature = _hex(base["announcement"]["signature"], 64, "signature")
    for name in ("highS", "resignedSameTranscript"):
        variant = malleation[name]
        _require(
            set(variant) == {"announcement", "transcriptHex", "announcementHash"},
            f"{name} record shape",
        )
        announcement = variant["announcement"]
        _require(
            {key: value for key, value in announcement.items() if key != "signature"}
            == {key: value for key, value in base["announcement"].items() if key != "signature"},
            f"{name} changes a signed field",
        )
        transcript = "0x" + independent_transcript(announcement).hex()
        _require(transcript == variant["transcriptHex"] == base["transcriptHex"], f"{name} transcript")
        complete_hash = independent_announcement_hash(announcement)
        _require(complete_hash == variant["announcementHash"], f"{name} complete hash")
        _require(complete_hash != base["announcementHash"], f"{name} complete hash is not distinct")
    high = _hex(malleation["highS"]["announcement"]["signature"], 64, "signature")
    base_s = int.from_bytes(base_signature[32:], "big")
    high_s = int.from_bytes(high[32:], "big")
    _require(
        high[:32] == base_signature[:32] and high_s == SECP_N - base_s and high_s > SECP_N // 2,
        "highS is not the (r, n - s) twin of the base signature",
    )
    _require(
        not independent_verify(malleation["highS"]["announcement"], public_key),
        "independent verifier accepted a high-s signature",
    )
    resigned = _hex(
        malleation["resignedSameTranscript"]["announcement"]["signature"], 64, "signature"
    )
    _require(
        resigned != base_signature and int.from_bytes(resigned[32:], "big") <= SECP_N // 2,
        "resignedSameTranscript is not a distinct low-s signature",
    )
    _require(
        independent_verify(malleation["resignedSameTranscript"]["announcement"], public_key),
        "resignedSameTranscript signature",
    )


def _validate_liveness_vectors(vectors: dict) -> None:
    """Pin the quiet-issuer liveness vectors independently (spec 2.4.2)."""
    liveness = vectors.get("liveness")
    _require(
        type(liveness) is dict
        and set(liveness)
        == {
            "head",
            "revokedBy",
            "observedAt",
            "refusalCheckedAt",
            "valid",
            "otherHead",
            "unpinnedSigner",
            "tamperCases",
            "policy",
            "expected",
        },
        "liveness vector shape",
    )
    records = vectors["announcements"]
    keys = vectors["keys"]
    head = records[liveness["head"]]
    revoked = records[liveness["revokedBy"]]
    for name in ("valid", "otherHead", "unpinnedSigner"):
        record = liveness[name]
        _require(
            set(record) == {"key", "statement", "transcriptHex", "signingDigest"},
            f"liveness {name} record shape",
        )
        statement = record["statement"]
        key = keys[record["key"]]
        _require(statement["signingKeyId"] == key["keyId"], f"liveness {name} key id")
        _require(
            "0x" + independent_liveness_transcript(statement).hex() == record["transcriptHex"],
            f"liveness {name} transcript",
        )
        _require(
            "0x" + independent_liveness_digest_bytes(statement).hex() == record["signingDigest"],
            f"liveness {name} digest",
        )
        _require(independent_verify_liveness(statement, key["publicKey"]), f"liveness {name} signature")
        _require(
            not independent_verify(statement, key["publicKey"]),
            f"liveness {name} verified as an announcement",
        )

    def names(statement, record):
        announcement = record["announcement"]
        return (
            statement["accumulatorId"] == announcement["accumulatorId"]
            and statement["epoch"] == announcement["epoch"]
            and statement["headHash"] == record["announcementHash"]
        )

    valid = liveness["valid"]["statement"]
    _require(liveness["valid"]["key"] == "primary", "valid liveness signer")
    _require(names(valid, head), "valid liveness does not name the head")
    _require(valid["issuedAt"] == liveness["observedAt"], "valid liveness time")
    _require(names(liveness["otherHead"]["statement"], revoked), "otherHead names the revoked head")
    _require(not names(liveness["otherHead"]["statement"], head), "otherHead names the head")
    _require(liveness["unpinnedSigner"]["key"] == "rotation", "unpinned liveness signer")
    _require(names(liveness["unpinnedSigner"]["statement"], head), "unpinned liveness head")

    tamper_cases = liveness["tamperCases"]
    _require({case["field"] for case in tamper_cases} == LIVENESS_FIELDS, "liveness tamper matrix")
    for case in tamper_cases:
        candidate = {**valid, case["field"]: case["value"]}
        _require(
            not independent_verify_liveness(candidate, keys["primary"]["publicKey"]),
            f"liveness tamper accepted: {case['field']}",
        )

    policy = liveness["policy"]
    age = policy["maxAnnouncementAgeSeconds"]
    skew = policy["maxClockSkewSeconds"]
    _require(policy["worstCaseRevocationLatencySeconds"] == age + skew, "worst-case latency")
    _require(
        liveness["observedAt"] - head["announcement"]["announcedAt"] > age,
        "liveness vectors must model a quiet head past the age limit",
    )
    _require(
        liveness["refusalCheckedAt"] - head["announcement"]["announcedAt"] <= age,
        "refusals are checked while the head is fresh on its own",
    )
    expected = liveness["expected"]
    _require(expected["otherHeadErrorCode"] == "LIVENESS_HEAD_MISMATCH", "otherHead code")
    _require(
        expected["unpinnedSignerErrorCode"] == "ANNOUNCEMENT_AUTHENTICATION_FAILED",
        "unpinned signer code",
    )
    _require(expected["changesCheckpoint"] is False, "liveness never changes the checkpoint")
    _require(expected["retainsEvidence"] is False, "liveness is never evidence")
    _require(expected["servedEpochs"] == [head["announcement"]["epoch"]], "served epochs")


def _coordinates(public_key: str):
    raw = bytes.fromhex(public_key.removeprefix("0x"))
    return raw[:32], raw[32:]


# Verifier-local validity windows for the vector keys. Pins are verifier
# trust policy (specification 2.4.1), so the runner states its own: the
# 2026 calendar year, which contains every vector announcedAt.
PIN_NOT_BEFORE = 1_767_225_600  # 2026-01-01T00:00:00Z
PIN_NOT_AFTER = 1_798_761_600  # 2027-01-01T00:00:00Z


def _pin(key: dict, *, not_before: int = PIN_NOT_BEFORE, not_after: int = PIN_NOT_AFTER,
         retire_after_epoch: int = None):
    from zkc_revocation import AnnouncementKeyPin

    x, y = _coordinates(key["publicKey"])
    return AnnouncementKeyPin(x, y, not_before, not_after, retire_after_epoch)


def _metadata(vectors: dict, name: str, *, version: str = "zkc:issuer-metadata:v2") -> dict:
    announcement = copy.deepcopy(vectors["announcements"][name]["announcement"])
    return {
        "version": version,
        "issuerId": vectors["issuerId"],
        "signingKeys": list(vectors["keys"].values()),
        "revocation": {
            "accumulatorId": announcement["accumulatorId"],
            "currentRoot": announcement["root"],
            "currentEpoch": announcement["epoch"],
            "maxEpochLag": announcement["maxEpochLag"],
            "currentAnnouncement": announcement,
        },
    }


def _case_canonical(vectors):
    validate_vector_document(vectors)


def _case_tamper(vectors):
    from zkc_revocation import verify_epoch_announcement

    base = vectors["announcements"]["revocation"]["announcement"]
    key = vectors["keys"]["primary"]
    x, y = _coordinates(key["publicKey"])
    _require(
        verify_epoch_announcement(base, x, y, key["keyId"]),
        "production verifier rejected the untampered announcement",
    )
    for case in vectors["tamperCases"]:
        candidate = copy.deepcopy(base)
        candidate[case["field"]] = case["value"]
        _require(not independent_verify(candidate, key["publicKey"]), f"independent tamper {case['field']}")
        _require(not verify_epoch_announcement(candidate, x, y, key["keyId"]), f"production tamper {case['field']}")


def _case_metadata_rotation(vectors):
    from zkc_revocation import (
        AnnouncementAuthenticationError,
        AnnouncementMetadataError,
        InMemoryVerifierCheckpointStore,
        VerifierAccumulatorCache,
    )

    issuer = vectors["issuerId"]
    accumulator = vectors["accumulatorId"]
    primary = vectors["keys"]["primary"]
    rotation = vectors["keys"]["rotation"]
    all_keys = {primary["keyId"]: _pin(primary), rotation["keyId"]: _pin(rotation)}
    cache = VerifierAccumulatorCache(
        {issuer: all_keys}, accumulator_ids={issuer: accumulator},
        checkpoint_store=InMemoryVerifierCheckpointStore(), clock=lambda: 1_770_000_000,
    )
    for name in ("genesis", "issuance", "revocation", "authorizedRotation"):
        cache.ingest_metadata(issuer, _metadata(vectors, name))
    _require(cache.state(issuer).current_epoch == 3, "pre-pinned rotation was not accepted")

    untrusted = VerifierAccumulatorCache(
        {issuer: {primary["keyId"]: _pin(primary)}},
        accumulator_ids={issuer: accumulator}, checkpoint_store=InMemoryVerifierCheckpointStore(),
        clock=lambda: 1_770_000_000,
    )
    for name in ("genesis", "issuance", "revocation"):
        untrusted.ingest_metadata(issuer, _metadata(vectors, name))
    try:
        untrusted.ingest_metadata(issuer, _metadata(vectors, "authorizedRotation"))
    except AnnouncementAuthenticationError:
        pass
    else:
        raise ConformanceFailure("same-document or unauthorized rotation was accepted")
    mismatched = _metadata(vectors, "revocation")
    mismatched["revocation"]["currentRoot"] = "0x" + "00" * 32
    try:
        VerifierAccumulatorCache(
            {issuer: {primary["keyId"]: _pin(primary)}},
            accumulator_ids={issuer: accumulator}, checkpoint_store=InMemoryVerifierCheckpointStore(),
            clock=lambda: 1_770_000_000,
        ).ingest_metadata(issuer, mismatched)
    except AnnouncementMetadataError:
        pass
    else:
        raise ConformanceFailure("metadata/announcement mismatch was accepted")
    try:
        untrusted.ingest_metadata(issuer, _metadata(vectors, "revocation", version="zkc:issuer-metadata:v1"))
    except AnnouncementMetadataError:
        pass
    else:
        raise ConformanceFailure("metadata downgrade was accepted")


def _case_replay_gap_fork(vectors):
    from zkc_revocation import (
        AnnouncementChain,
        AnnouncementMetadataError,
        AnnouncementReplayError,
        ChainLinkageError,
        EpochGapError,
        InMemoryVerifierCheckpointStore,
        VerifierAccumulatorCache,
    )

    primary = vectors["keys"]["primary"]
    keys = {primary["keyId"]: _pin(primary)}
    records = vectors["announcements"]
    chain = AnnouncementChain(trusted_keys=keys)
    chain.ingest(records["genesis"]["announcement"])
    chain.ingest(records["issuance"]["announcement"])
    try:
        chain.ingest(records["genesis"]["announcement"])
    except AnnouncementReplayError:
        pass
    else:
        raise ConformanceFailure("replay was accepted")
    gap_chain = AnnouncementChain(trusted_keys=keys, checkpoint=records["genesis"]["announcement"])
    try:
        gap_chain.ingest(records["revocation"]["announcement"])
    except EpochGapError as error:
        _require(error.missing_epochs == [1], "missing epoch report")
    else:
        raise ConformanceFailure("epoch gap was accepted")

    issuer = vectors["issuerId"]
    accumulator = vectors["accumulatorId"]
    store = InMemoryVerifierCheckpointStore()
    cache = VerifierAccumulatorCache(
        {issuer: keys}, accumulator_ids={issuer: accumulator}, checkpoint_store=store,
        clock=lambda: 1_770_000_000,
    )
    cache.ingest_metadata(issuer, _metadata(vectors, "genesis"))
    try:
        cache.ingest_metadata(
            issuer, _metadata(vectors, "revocation"), history_loader=lambda _a, _b: [],
        )
    except AnnouncementMetadataError:
        pass
    else:
        raise ConformanceFailure("unavailable backfill was accepted")
    cache.ingest_metadata(issuer, _metadata(vectors, "issuance"))
    cache.ingest_metadata(issuer, _metadata(vectors, "revocation"))
    try:
        cache.ingest_metadata(issuer, _metadata(vectors, "forkB"))
    except ChainLinkageError as error:
        _require(error.code == "CHAIN_FORKED", "fork error code")
    else:
        raise ConformanceFailure("signed fork was accepted")
    evidence = store.evidence(issuer, accumulator)
    _require(len(evidence) == 1 and evidence[0]["candidate"] == records["forkB"]["announcement"], "fork evidence")


def _case_durable_restart(vectors):
    from zkc_issuer import IssuerSigningKey
    from zkc_revocation import (
        DurableRevocationAccumulatorService,
        SQLiteAccumulatorStateStore,
        SQLiteVerifierCheckpointStore,
        VerifierAccumulatorCache,
    )

    issuer = vectors["issuerId"]
    accumulator = vectors["accumulatorId"]
    primary = vectors["keys"]["primary"]
    keys = {primary["keyId"]: _pin(primary)}
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / "revocation.sqlite3"
        with contextlib.closing(SQLiteVerifierCheckpointStore(path)) as first_store:
            first = VerifierAccumulatorCache(
                {issuer: keys},
                accumulator_ids={issuer: accumulator},
                checkpoint_store=first_store,
                clock=lambda: 1_770_000_000,
            )
            for name in ("genesis", "issuance", "revocation"):
                first.ingest_metadata(issuer, _metadata(vectors, name))
            expected_hash = first.state(issuer).checkpoint_hash
        with contextlib.closing(SQLiteVerifierCheckpointStore(path)) as second_store:
            second = VerifierAccumulatorCache(
                {issuer: keys},
                accumulator_ids={issuer: accumulator},
                checkpoint_store=second_store,
                clock=lambda: 1_770_000_000,
            )
            recovered = second.state(issuer, accumulator)
            _require(recovered.current_epoch == 2, "restart epoch")
            _require(
                recovered.checkpoint_hash == expected_hash,
                "restart publication head",
            )

        issuer_path = pathlib.Path(directory) / "issuer.sqlite3"
        signing_key = IssuerSigningKey.test_issuer()
        with contextlib.closing(
            SQLiteAccumulatorStateStore(issuer_path, accumulator)
        ) as issuer_store:
            first_issuer = DurableRevocationAccumulatorService.open(
                accumulator,
                "https://issuer.sandbox.zkc.dev/v1/revocation/updates",
                signing_key,
                issuer_store,
                clock=lambda: 1_770_000_000,
            )
            first_issuer.register(404)
            first_issuer.revoke(404)
            expected_head = first_issuer.current_announcement()
            expected_history = [
                first_issuer.announcement_for_epoch(epoch) for epoch in range(3)
            ]

        with contextlib.closing(
            SQLiteAccumulatorStateStore(issuer_path, accumulator)
        ) as reopened_store:
            recovered_issuer = DurableRevocationAccumulatorService.open(
                accumulator,
                "https://issuer.sandbox.zkc.dev/v1/revocation/updates",
                signing_key,
                reopened_store,
                clock=lambda: 1_770_000_000,
            )
            _require(
                recovered_issuer.current_announcement() == expected_head,
                "issuer restart changed the publication head",
            )
            _require(
                [
                    recovered_issuer.announcement_for_epoch(epoch)
                    for epoch in range(3)
                ]
                == expected_history,
                "issuer restart changed the accepted publication chain",
            )


def _case_cold_start(vectors):
    from zkc_revocation import AnnouncementAuthenticationError, AnnouncementChain

    records = vectors["announcements"]
    primary = vectors["keys"]["primary"]
    rotation = vectors["keys"]["rotation"]
    candidate = records[vectors["coldStart"]["candidate"]]["announcement"]
    chain = AnnouncementChain(trusted_keys={primary["keyId"]: _pin(primary)})
    chain.ingest(candidate)
    _require(chain.last_epoch == candidate["epoch"], "cold-start checkpoint")
    for bad_keys, bad_candidate in (
        ({rotation["keyId"]: _pin(rotation)}, candidate),
        ({primary["keyId"]: _pin(primary)}, {**candidate, "signature": "0x" + "00" * 64}),
    ):
        try:
            AnnouncementChain(trusted_keys=bad_keys).ingest(bad_candidate)
        except AnnouncementAuthenticationError:
            pass
        else:
            raise ConformanceFailure("untrusted or malformed first announcement accepted")
    _require(vectors["coldStart"]["globalConsistencyEstablished"] is False, "cold-start overclaim")


def _case_split_view(vectors):
    from zkc_revocation import AnnouncementChain, ChainLinkageError

    primary = vectors["keys"]["primary"]
    keys = {primary["keyId"]: _pin(primary)}
    records = vectors["announcements"]
    heads = []
    for view in ("isolatedViewA", "isolatedViewB"):
        chain = AnnouncementChain(trusted_keys=keys)
        for name in vectors["chains"][view]:
            chain.ingest(records[name]["announcement"])
        heads.append(chain.last_hash)
    _require(heads[0] != heads[1], "isolated views did not diverge")
    compared = AnnouncementChain(trusted_keys=keys)
    for name in ("genesis", "issuance", "revocation"):
        compared.ingest(records[name]["announcement"])
    try:
        compared.ingest(records["forkB"]["announcement"])
    except ChainLinkageError as error:
        _require(error.code == vectors["splitViewResidual"]["expectedErrorCode"], "comparison fork code")
    else:
        raise ConformanceFailure("checkpoint comparison did not expose the split view")


def _case_lifecycle(vectors):
    records = vectors["announcements"]
    names = vectors["chains"]["lifecycle"][:3]
    epochs = [records[name]["announcement"]["epoch"] for name in names]
    roots = [records[name]["announcement"]["root"] for name in names]
    _require(epochs == [0, 1, 2], "genesis/issuance/revocation epochs")
    _require(roots[0] != roots[1], "issuance did not change the genesis root")
    _require(roots[1] != roots[2], "revocation did not change the issued root")
    validate_vector_document(vectors)


def _case_signature_malleation(vectors):
    """High-s is rejected; a same-transcript conflict is never a fork."""
    from zkc_revocation import (
        AnnouncementAuthenticationError,
        AnnouncementChain,
        ChainLinkageError,
        InMemoryVerifierCheckpointStore,
        VerifierAccumulatorCache,
        verify_epoch_announcement,
    )

    _validate_signature_malleation(vectors)
    malleation = vectors["signatureMalleation"]
    records = vectors["announcements"]
    base = records[malleation["base"]]["announcement"]
    successor = records[malleation["successor"]]["announcement"]
    primary = vectors["keys"]["primary"]
    x, y = _coordinates(primary["publicKey"])
    keys = {primary["keyId"]: _pin(primary)}
    high_s = malleation["highS"]["announcement"]
    resigned = malleation["resignedSameTranscript"]["announcement"]

    _require(not independent_verify(high_s, primary["publicKey"]), "independent high-s accepted")
    _require(
        not verify_epoch_announcement(high_s, x, y, primary["keyId"]),
        "production verifier accepted a high-s signature",
    )
    _require(
        verify_epoch_announcement(resigned, x, y, primary["keyId"]),
        "production verifier rejected a valid low-s re-signature",
    )

    for name, candidate in (("highS", high_s), ("resignedSameTranscript", resigned)):
        chain = AnnouncementChain(trusted_keys=keys, checkpoint=base)
        try:
            chain.ingest(candidate)
        except ChainLinkageError as error:
            raise ConformanceFailure(f"{name} classified as {error.code}") from error
        except AnnouncementAuthenticationError as error:
            _require(error.code == malleation["expectedErrorCode"], f"{name} error code")
        else:
            raise ConformanceFailure(f"{name} was accepted at the checkpoint epoch")

    issuer = vectors["issuerId"]
    accumulator = vectors["accumulatorId"]
    store = InMemoryVerifierCheckpointStore()
    cache = VerifierAccumulatorCache(
        {issuer: keys}, accumulator_ids={issuer: accumulator}, checkpoint_store=store,
        clock=lambda: 1_770_000_000,
    )
    for name in ("genesis", "issuance", malleation["base"]):
        cache.ingest_metadata(issuer, _metadata(vectors, name))
    for name, candidate in (("highS", high_s), ("resignedSameTranscript", resigned)):
        metadata = _metadata(vectors, malleation["base"])
        metadata["revocation"]["currentAnnouncement"] = copy.deepcopy(candidate)
        try:
            cache.ingest_metadata(issuer, metadata)
        except AnnouncementAuthenticationError as error:
            _require(error.code == malleation["expectedErrorCode"], f"cache {name} error code")
        else:
            raise ConformanceFailure(f"cache accepted {name}")
    _require(store.evidence(issuer, accumulator) == [], "same-transcript conflict retained as evidence")
    cache.ingest_metadata(issuer, _metadata(vectors, malleation["successor"]))
    _require(
        cache.state(issuer).current_epoch == successor["epoch"],
        "honest successor did not advance after a rejected malleation",
    )


def _case_key_validity_window(vectors):
    from zkc_revocation import (
        AnnouncementChain,
        AnnouncementKeyWindowError,
        InMemoryVerifierCheckpointStore,
        VerifierAccumulatorCache,
    )

    issuer = vectors["issuerId"]
    accumulator = vectors["accumulatorId"]
    primary = vectors["keys"]["primary"]
    records = vectors["announcements"]
    genesis = records["genesis"]["announcement"]
    issuance = records["issuance"]["announcement"]
    signed_at = genesis["announcedAt"]

    # A bare (x, y) pin has no window and must fail closed.
    try:
        AnnouncementChain(trusted_keys={primary["keyId"]: _coordinates(primary["publicKey"])})
    except ValueError:
        pass
    else:
        raise ConformanceFailure("a bare (x, y) announcement key pin was accepted")

    # The window is half-open: notBefore <= announcedAt < notAfter.
    for label, pin in (
        ("expired", _pin(primary, not_before=signed_at - 86_400, not_after=signed_at)),
        ("not yet valid", _pin(primary, not_before=signed_at + 1, not_after=signed_at + 86_400)),
    ):
        try:
            AnnouncementChain(trusted_keys={primary["keyId"]: pin}).ingest(genesis)
        except AnnouncementKeyWindowError as error:
            _require(error.code == "ANNOUNCEMENT_KEY_OUTSIDE_VALIDITY", f"{label} error code")
        else:
            raise ConformanceFailure(f"{label} key window was accepted")
    edge = _pin(primary, not_before=signed_at, not_after=signed_at + 1)
    AnnouncementChain(trusted_keys={primary["keyId"]: edge}).ingest(genesis)

    # retireAfterEpoch bounds the epochs a pinned key may sign.
    retired = AnnouncementChain(
        trusted_keys={primary["keyId"]: _pin(primary, retire_after_epoch=genesis["epoch"])}
    )
    retired.ingest(genesis)
    try:
        retired.ingest(issuance)
    except AnnouncementKeyWindowError:
        pass
    else:
        raise ConformanceFailure("an announcement after retireAfterEpoch was accepted")

    # The verifier cache rejects an expired head and changes no checkpoint.
    store = InMemoryVerifierCheckpointStore()
    cache = VerifierAccumulatorCache(
        {issuer: {primary["keyId"]: _pin(primary, not_after=signed_at)}},
        accumulator_ids={issuer: accumulator},
        checkpoint_store=store,
        clock=lambda: signed_at,
    )
    try:
        cache.ingest_metadata(issuer, _metadata(vectors, "genesis"))
    except AnnouncementKeyWindowError:
        pass
    else:
        raise ConformanceFailure("verifier cache accepted an announcement outside its key window")
    _require(store.load_checkpoint(issuer, accumulator) is None, "rejected head was persisted")


def _case_quiet_issuer_liveness(vectors):
    """A quiet head stays fresh by liveness; superseded roots expire in time."""
    from zkc_revocation import (
        AnnouncementAuthenticationError,
        AnnouncementFreshnessError,
        InMemoryVerifierCheckpointStore,
        LivenessHeadMismatchError,
        VerifierAccumulatorCache,
        liveness_transcript,
        verify_epoch_liveness,
    )

    _validate_liveness_vectors(vectors)
    liveness = vectors["liveness"]
    records = vectors["announcements"]
    primary = vectors["keys"]["primary"]
    x, y = _coordinates(primary["publicKey"])
    for name in ("valid", "otherHead"):
        statement = liveness[name]["statement"]
        _require(
            "0x" + liveness_transcript(statement).hex() == liveness[name]["transcriptHex"],
            f"production liveness transcript {name}",
        )
        _require(verify_epoch_liveness(statement, x, y, primary["keyId"]), f"production {name}")
    _require(
        not verify_epoch_liveness(liveness["unpinnedSigner"]["statement"], x, y),
        "production verifier accepted another key's liveness",
    )
    for case in liveness["tamperCases"]:
        candidate = {**liveness["valid"]["statement"], case["field"]: case["value"]}
        _require(not verify_epoch_liveness(candidate, x, y), f"production liveness tamper {case['field']}")

    issuer = vectors["issuerId"]
    accumulator = vectors["accumulatorId"]
    policy = liveness["policy"]
    clock = {"now": records["genesis"]["announcement"]["announcedAt"]}
    store = InMemoryVerifierCheckpointStore()
    cache = VerifierAccumulatorCache(
        {issuer: {primary["keyId"]: _pin(primary)}},
        accumulator_ids={issuer: accumulator},
        checkpoint_store=store,
        clock=lambda: clock["now"],
        max_announcement_age=policy["maxAnnouncementAgeSeconds"],
        max_clock_skew=policy["maxClockSkewSeconds"],
    )
    for name in vectors["chains"]["lifecycle"]:
        cache.ingest_metadata(issuer, _metadata(vectors, name))
    checkpoint = store.load_checkpoint(issuer, accumulator)

    def with_liveness(name):
        metadata = _metadata(vectors, liveness["head"])
        metadata["revocation"]["currentLiveness"] = copy.deepcopy(liveness[name]["statement"])
        return metadata

    clock["now"] = liveness["refusalCheckedAt"]
    for name, error, code in (
        ("otherHead", LivenessHeadMismatchError, liveness["expected"]["otherHeadErrorCode"]),
        (
            "unpinnedSigner",
            AnnouncementAuthenticationError,
            liveness["expected"]["unpinnedSignerErrorCode"],
        ),
    ):
        try:
            cache.ingest_metadata(issuer, with_liveness(name))
        except error as exc:
            _require(exc.code == code, f"{name} error code")
        else:
            raise ConformanceFailure(f"{name} liveness was accepted")

    clock["now"] = liveness["observedAt"]
    try:
        cache.state(issuer)
    except AnnouncementFreshnessError:
        pass
    else:
        raise ConformanceFailure("a quiet head stayed fresh without a liveness statement")
    for _ in range(2):  # re-polling unchanged metadata is a silent no-op
        cache.ingest_metadata(issuer, with_liveness("valid"))
    _require(store.load_checkpoint(issuer, accumulator) == checkpoint, "liveness changed the checkpoint")
    _require(store.evidence(issuer, accumulator) == [], "liveness was retained as evidence")
    state = cache.state(issuer)
    head = records[liveness["head"]]["announcement"]
    _require(state.current_epoch == head["epoch"], "quiet head epoch")
    _require(sorted(state.roots) == liveness["expected"]["servedEpochs"], "superseded roots outlived the age limit")
    revoked_by = records[liveness["revokedBy"]]["announcement"]
    for record in records.values():
        announcement = record["announcement"]
        if announcement["epoch"] < revoked_by["epoch"] and announcement["accumulatorId"] == accumulator:
            _require(
                int(announcement["root"], 16) not in state.roots.values(),
                "a pre-revocation root is still servable",
            )


_CASES = [
    _case_canonical,
    _case_tamper,
    _case_metadata_rotation,
    _case_replay_gap_fork,
    _case_durable_restart,
    _case_cold_start,
    _case_split_view,
    _case_lifecycle,
    _case_signature_malleation,
    _case_key_validity_window,
    _case_quiet_issuer_liveness,
]


def run_conformance() -> dict:
    vectors = load_vectors()
    results = []
    _require(
        len(EXPECTED_CASE_IDS) == len(_CASES),
        "case id list and case callable list diverged",
    )
    for case_id, case in zip(EXPECTED_CASE_IDS, _CASES, strict=True):
        try:
            case(vectors)
        except Exception as error:  # noqa: BLE001 - conformance must report stable failures
            results.append({"id": case_id, "status": "FAIL", "error": f"{type(error).__name__}: {error}"})
        else:
            results.append({"id": case_id, "status": "PASS"})
    passed = sum(result["status"] == "PASS" for result in results)
    return {"profile": "revocation-launch", "passed": passed, "failed": len(results) - passed, "allPassed": passed == len(results), "results": results}

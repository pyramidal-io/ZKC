#!/usr/bin/env python3
"""Generate deterministic public authenticated-revocation launch vectors."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

import hashlib  # noqa: E402

from zkc_crypto import digest_to_message_bytes, field_to_hex  # noqa: E402
from zkc_crypto.ecdsa_secp256k1 import GX, GY, HALF_N, N, _inv, _mul  # noqa: E402
from zkc_issuer import IssuerSigningKey  # noqa: E402
from zkc_revocation import (  # noqa: E402
    LIVENESS_VERSION,
    RevocationAccumulatorService,
    announcement_hash,
    announcement_transcript,
    compute_announcement_digest,
    compute_liveness_digest,
    liveness_transcript,
)


VECTOR_PATH = ROOT / "tests" / "vectors" / "revocation_equivocation_v1.json"
TIMESTAMP = 1_770_000_000
ACCUMULATOR_ID = "sandbox-active-credentials"
# Two quiet hours after the last mutation: past the default 3600 s age limit.
QUIET_OBSERVED_AT = TIMESTAMP + 7200
MAX_ANNOUNCEMENT_AGE = 3600
MAX_CLOCK_SKEW = 300


def _signed(announcement: dict, key: IssuerSigningKey) -> dict:
    candidate = dict(announcement)
    candidate["signature"] = "0x" + key.sign_digest(
        compute_announcement_digest(candidate)
    ).hex()
    return candidate


def _high_s(announcement: dict) -> dict:
    """The keyless high-s twin (r, n - s) of a signed announcement."""
    signature = bytes.fromhex(announcement["signature"].removeprefix("0x"))
    s = int.from_bytes(signature[32:], "big")
    return {
        **announcement,
        "signature": "0x" + (signature[:32] + (N - s).to_bytes(32, "big")).hex(),
    }


def _resigned_other_nonce(announcement: dict, key: IssuerSigningKey) -> dict:
    """A second valid low-s signature over the same transcript.

    Uses a fixed nonce other than the RFC 6979 one, so the signed statement
    is identical while the signature bytes and complete hash differ.
    """
    digest = digest_to_message_bytes(compute_announcement_digest(announcement))
    nonce = int.from_bytes(
        hashlib.sha256(b"zkc-revocation-vector-alternate-nonce-v1").digest(), "big"
    ) % N
    r = _mul(nonce, (GX, GY))[0] % N
    s = _inv(nonce, N) * (int.from_bytes(digest, "big") + r * key.private_key) % N
    if s > HALF_N:
        s = N - s
    return {
        **announcement,
        "signature": "0x" + (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex(),
    }


def _variant(announcement: dict) -> dict:
    return {
        "announcement": announcement,
        "transcriptHex": "0x" + announcement_transcript(announcement).hex(),
        "announcementHash": announcement_hash(announcement),
    }


def _record(announcement: dict, key_name: str) -> dict:
    return {
        "key": key_name,
        "announcement": announcement,
        "transcriptHex": "0x" + announcement_transcript(announcement).hex(),
        "signingDigest": f"0x{compute_announcement_digest(announcement):064x}",
        "announcementHash": announcement_hash(announcement),
    }


def _signed_liveness(statement: dict, key: IssuerSigningKey) -> dict:
    statement = dict(statement)
    statement["signature"] = "0x" + key.sign_digest(compute_liveness_digest(statement)).hex()
    return statement


def _liveness_record(statement: dict, key_name: str) -> dict:
    return {
        "key": key_name,
        "statement": statement,
        "transcriptHex": "0x" + liveness_transcript(statement).hex(),
        "signingDigest": f"0x{compute_liveness_digest(statement):064x}",
    }


def _liveness(head: dict, revoked: dict, primary, rotation) -> dict:
    """Quiet-issuer liveness vectors (specification section 2.4.2)."""

    def statement(announcement, key, issued_at):
        return _signed_liveness(
            {
                "version": LIVENESS_VERSION,
                "accumulatorId": announcement["accumulatorId"],
                "epoch": announcement["epoch"],
                "headHash": announcement_hash(announcement),
                "issuedAt": issued_at,
                "signingKeyId": key.key_id,
            },
            key,
        )

    valid = statement(head, primary, QUIET_OBSERVED_AT)
    tampered_signature = bytearray.fromhex(valid["signature"].removeprefix("0x"))
    tampered_signature[-1] ^= 1
    # Refusals are checked while the head is still fresh on its own, so a
    # statement that names another head reaches the binding check.
    refusal_at = TIMESTAMP + 60
    return {
        "head": "postRevocationIssuance",
        "revokedBy": "revocation",
        "observedAt": QUIET_OBSERVED_AT,
        "refusalCheckedAt": refusal_at,
        "valid": _liveness_record(valid, "primary"),
        "otherHead": _liveness_record(statement(revoked, primary, refusal_at), "primary"),
        "unpinnedSigner": _liveness_record(statement(head, rotation, refusal_at), "rotation"),
        "tamperCases": [
            {"field": "version", "value": "zkc:epoch-liveness:v2"},
            {"field": "accumulatorId", "value": "attacker-selected-accumulator"},
            {"field": "epoch", "value": valid["epoch"] + 1},
            {"field": "headHash", "value": announcement_hash(revoked)},
            {"field": "issuedAt", "value": QUIET_OBSERVED_AT + 1},
            {"field": "signingKeyId", "value": rotation.key_id},
            {"field": "signature", "value": "0x" + tampered_signature.hex()},
        ],
        "policy": {
            "maxAnnouncementAgeSeconds": MAX_ANNOUNCEMENT_AGE,
            "maxClockSkewSeconds": MAX_CLOCK_SKEW,
            "worstCaseRevocationLatencySeconds": MAX_ANNOUNCEMENT_AGE + MAX_CLOCK_SKEW,
        },
        "expected": {
            "staleWithoutLiveness": True,
            "servedEpochs": [valid["epoch"]],
            "otherHeadErrorCode": "LIVENESS_HEAD_MISMATCH",
            "unpinnedSignerErrorCode": "ANNOUNCEMENT_AUTHENTICATION_FAILED",
            "changesCheckpoint": False,
            "retainsEvidence": False,
        },
    }


def generate() -> dict:
    primary = IssuerSigningKey.test_issuer()
    rotation = IssuerSigningKey.from_seed(
        b"zkc-revocation-rotation-vector-v1",
        key_id="sandbox-2026-rotation",
    )
    service = RevocationAccumulatorService(
        ACCUMULATOR_ID,
        "https://issuer.sandbox.zkc.dev/v1/revocation/updates",
        primary,
        clock=lambda: TIMESTAMP,
    )
    genesis = service.current_announcement()
    service.register(101)
    issuance = service.current_announcement()
    service.revoke(101)
    revocation = service.current_announcement()
    service.register(202)
    post_revocation_issuance = service.current_announcement()

    fork_b = _signed(
        {
            **revocation,
            "root": field_to_hex(1),
            "signature": "0x" + "00" * 64,
        },
        primary,
    )
    fork_b_successor = _signed(
        {
            **post_revocation_issuance,
            "root": field_to_hex(2),
            "previousAnnouncementHash": announcement_hash(fork_b),
            "signature": "0x" + "00" * 64,
        },
        primary,
    )
    authorized_rotation = _signed(
        {
            **post_revocation_issuance,
            "root": field_to_hex(3),
            "signingKeyId": rotation.key_id,
            "signature": "0x" + "00" * 64,
        },
        rotation,
    )

    records = {
        "genesis": _record(genesis, "primary"),
        "issuance": _record(issuance, "primary"),
        "revocation": _record(revocation, "primary"),
        "postRevocationIssuance": _record(post_revocation_issuance, "primary"),
        "forkB": _record(fork_b, "primary"),
        "forkBSuccessor": _record(fork_b_successor, "primary"),
        "authorizedRotation": _record(authorized_rotation, "rotation"),
    }
    revocation_announcement = revocation
    tampered_signature = bytearray.fromhex(
        revocation_announcement["signature"].removeprefix("0x")
    )
    tampered_signature[-1] ^= 1
    tamper_cases = [
        {"field": "version", "value": "zkc:epoch-announcement:v2"},
        {"field": "accumulatorId", "value": "attacker-selected-accumulator"},
        {"field": "root", "value": field_to_hex(4)},
        {"field": "epoch", "value": revocation_announcement["epoch"] + 7},
        {"field": "announcedAt", "value": TIMESTAMP + 1},
        {"field": "maxEpochLag", "value": 9},
        {"field": "signingKeyId", "value": rotation.key_id},
        {"field": "previousAnnouncementHash", "value": "0x" + "11" * 32},
        {
            "field": "signature",
            "value": "0x" + tampered_signature.hex(),
        },
    ]
    return {
        "version": "zkc:revocation-equivocation-vectors:v1",
        "description": (
            "Deterministic public launch vectors for authenticated revocation, "
            "cold-start locality, durable continuity, and isolated split views."
        ),
        "issuerId": "zkc:issuer:sandbox",
        "accumulatorId": ACCUMULATOR_ID,
        "keys": {
            "primary": {
                "keyId": primary.key_id,
                "publicKey": primary.public_key_hex(),
            },
            "rotation": {
                "keyId": rotation.key_id,
                "publicKey": rotation.public_key_hex(),
            },
        },
        "announcements": records,
        "chains": {
            "lifecycle": [
                "genesis",
                "issuance",
                "revocation",
                "postRevocationIssuance",
            ],
            "isolatedViewA": [
                "genesis",
                "issuance",
                "revocation",
                "postRevocationIssuance",
            ],
            "isolatedViewB": [
                "genesis",
                "issuance",
                "forkB",
                "forkBSuccessor",
            ],
            "authorizedRotation": [
                "genesis",
                "issuance",
                "revocation",
                "authorizedRotation",
            ],
        },
        "metadata": {
            "version": "zkc:issuer-metadata:v2",
            "head": "revocation",
            "signedEqualityFields": {
                "accumulatorId": "accumulatorId",
                "currentRoot": "root",
                "currentEpoch": "epoch",
                "maxEpochLag": "maxEpochLag",
            },
        },
        "coldStart": {
            "candidate": "issuance",
            "acceptedAs": "local-checkpoint-only",
            "globalConsistencyEstablished": False,
        },
        "splitViewResidual": {
            "viewA": "isolatedViewA",
            "viewB": "isolatedViewB",
            "individuallyConsistent": True,
            "detectedOnlyAfterCheckpointComparison": True,
            "expectedErrorCode": "CHAIN_FORKED",
        },
        "rotation": {
            "candidate": "authorizedRotation",
            "acceptedPinnedKeys": [primary.key_id, rotation.key_id],
            "rejectedPinnedKeys": [primary.key_id],
        },
        "tamperCases": tamper_cases,
        "signatureMalleation": {
            "base": "revocation",
            "successor": "postRevocationIssuance",
            "highS": _variant(_high_s(revocation)),
            "resignedSameTranscript": _variant(
                _resigned_other_nonce(revocation, primary)
            ),
            "expectedErrorCode": "ANNOUNCEMENT_AUTHENTICATION_FAILED",
            "retainsEvidence": False,
        },
        "liveness": _liveness(post_revocation_issuance, revocation, primary, rotation),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write == args.check:
        parser.error("choose exactly one of --write or --check")
    rendered = json.dumps(generate(), indent=2, sort_keys=False) + "\n"
    if args.write:
        VECTOR_PATH.write_text(rendered, encoding="utf-8")
        print(f"wrote {VECTOR_PATH.relative_to(ROOT)}")
        return 0
    if not VECTOR_PATH.exists() or VECTOR_PATH.read_text(encoding="utf-8") != rendered:
        print(f"{VECTOR_PATH.relative_to(ROOT)} is stale", file=sys.stderr)
        return 1
    print(f"validated generated {VECTOR_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

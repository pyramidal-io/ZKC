"""Structural validation tests for zkc:proof:v2 envelopes (design §3).

v2 replaces v1's global `holderBinding` with a `presentationBinding` block:
profile is one of {anonymous, scoped}; scoped carries `pseudonym` + `scopeId`,
anonymous carries neither; `holderBinding` is forbidden in v2. The v1 validator
and v1 envelopes stay byte-frozen — a known-good v1 envelope must still pass the
version-dispatching entrypoint unchanged.
"""

import json
import unittest

from _path import REPO_ROOT

from zkc_crypto import (
    ANONYMOUS_PROFILE,
    SCOPED_PROFILE,
    EnvelopeError,
    validate_compliance_proof_v1,
    validate_compliance_proof_v2,
    validate_envelope,
)


def _valid_v1_envelope():
    return {
        "version": "zkc:proof:v1",
        "metadata": {
            "generatedAt": "2026-06-10T00:00:00Z",
            "expiresAt": "2026-06-10T01:00:00Z",
            "context": {
                "profile": "zkc:context:verifier-session:v1",
                "value": "0x" + "11" * 32,
                "timestamp": 1700000000,
            },
        },
        "proofs": [
            {
                "proofType": "zkc:proof:kyc:v1",
                "proof": "0xabcd",
                "publicInputs": {},
                "principalConsent": True,
            }
        ],
        "holderBinding": {"commitment": "0x" + "22" * 32},
    }


def _valid_v2_scoped_envelope():
    return {
        "version": "zkc:proof:v2",
        "metadata": {
            "generatedAt": "2026-06-10T00:00:00Z",
            "expiresAt": "2026-06-10T01:00:00Z",
            "context": {
                "profile": "zkc:context:verifier-session:v1",
                "value": "0x" + "11" * 32,
                "timestamp": 1700000000,
            },
        },
        "proofs": [
            {
                "proofType": "zkc:proof:kyc:v2",
                "proof": "0xabcd",
                "publicInputs": {
                    "presentation_pseudonym": "0x" + "33" * 32,
                    "scope_id": "0x" + "44" * 32,
                    "claim_binding": "0x" + "55" * 32,
                    "proof_context": "0x" + "66" * 32,
                },
                "principalConsent": True,
            }
        ],
        "presentationBinding": {
            "profile": SCOPED_PROFILE,
            "pseudonym": "0x" + "33" * 32,
            "scopeId": "0x" + "44" * 32,
        },
    }


def _valid_v2_anonymous_envelope():
    env = _valid_v2_scoped_envelope()
    env["proofs"][0]["publicInputs"]["presentation_pseudonym"] = "0x" + "00" * 32
    env["proofs"][0]["publicInputs"]["scope_id"] = "0x" + "00" * 32
    env["presentationBinding"] = {"profile": ANONYMOUS_PROFILE}
    return env


class EnvelopeV2Tests(unittest.TestCase):
    # --- positive ---------------------------------------------------------

    def test_valid_scoped_v2_passes(self):
        validate_compliance_proof_v2(_valid_v2_scoped_envelope())
        validate_envelope(_valid_v2_scoped_envelope())

    def test_valid_anonymous_v2_passes(self):
        validate_compliance_proof_v2(_valid_v2_anonymous_envelope())
        validate_envelope(_valid_v2_anonymous_envelope())

    def test_known_good_v1_still_validates(self):
        # Regression: the v2 dispatcher must route v1 envelopes to the frozen
        # v1 validator, and the v1 validator itself is untouched.
        validate_compliance_proof_v1(_valid_v1_envelope())
        validate_envelope(_valid_v1_envelope())

    # --- negative ---------------------------------------------------------

    def test_holderbinding_in_v2_fails(self):
        env = _valid_v2_scoped_envelope()
        env["holderBinding"] = {"commitment": "0x" + "22" * 32}
        with self.assertRaises(EnvelopeError):
            validate_compliance_proof_v2(env)
        with self.assertRaises(EnvelopeError):
            validate_envelope(env)

    def test_anonymous_with_pseudonym_fails(self):
        env = _valid_v2_anonymous_envelope()
        env["presentationBinding"]["pseudonym"] = "0x" + "33" * 32
        with self.assertRaises(EnvelopeError):
            validate_compliance_proof_v2(env)

    def test_anonymous_with_scope_id_fails(self):
        env = _valid_v2_anonymous_envelope()
        env["presentationBinding"]["scopeId"] = "0x" + "44" * 32
        with self.assertRaises(EnvelopeError):
            validate_compliance_proof_v2(env)

    def test_scoped_without_pseudonym_fails(self):
        env = _valid_v2_scoped_envelope()
        del env["presentationBinding"]["pseudonym"]
        with self.assertRaises(EnvelopeError):
            validate_compliance_proof_v2(env)

    def test_scoped_without_scope_id_fails(self):
        env = _valid_v2_scoped_envelope()
        del env["presentationBinding"]["scopeId"]
        with self.assertRaises(EnvelopeError):
            validate_compliance_proof_v2(env)

    def test_v2_without_presentationbinding_fails(self):
        env = _valid_v2_scoped_envelope()
        del env["presentationBinding"]
        with self.assertRaises(EnvelopeError):
            validate_compliance_proof_v2(env)

    def test_unknown_profile_fails(self):
        env = _valid_v2_scoped_envelope()
        env["presentationBinding"]["profile"] = "zkc:presentation:linkable:v1"
        with self.assertRaises(EnvelopeError):
            validate_compliance_proof_v2(env)

    def test_bad_hex_pseudonym_fails(self):
        env = _valid_v2_scoped_envelope()
        env["presentationBinding"]["pseudonym"] = "0x1234"
        with self.assertRaises(EnvelopeError):
            validate_compliance_proof_v2(env)

    def test_wrong_version_rejected_by_v2_validator(self):
        env = _valid_v2_scoped_envelope()
        env["version"] = "zkc:proof:v1"
        with self.assertRaises(EnvelopeError):
            validate_compliance_proof_v2(env)

    def test_v1_validator_still_rejects_v2_version(self):
        # The frozen v1 validator must remain strictly v1-only.
        with self.assertRaises(EnvelopeError):
            validate_compliance_proof_v1(_valid_v2_scoped_envelope())

    def test_dispatch_rejects_unknown_version(self):
        env = _valid_v2_scoped_envelope()
        env["version"] = "zkc:proof:v3"
        with self.assertRaises(EnvelopeError):
            validate_envelope(env)

    # --- schema cross-check ----------------------------------------------

    def test_validator_covers_v2_schema_required_fields(self):
        # The stdlib v2 validator must not drift from the published schema.
        schema = json.loads(
            (REPO_ROOT / "schemas" / "compliance-proof-v2.schema.json").read_text()
        )
        for required in schema["required"]:
            env = _valid_v2_scoped_envelope()
            del env[required]
            with self.assertRaises(EnvelopeError, msg=f"missing {required} must fail"):
                validate_compliance_proof_v2(env)


class V1PresentationBindingRejectionTests(unittest.TestCase):
    """Symmetric strictness: v1 forbids the v2-only
    presentationBinding field, closing the misleading-metadata channel where a
    stray anonymous-looking binding could decorate a linkable v1 envelope."""

    def test_v1_envelope_with_stray_presentation_binding_is_rejected(self):
        envelope = _valid_v1_envelope()
        envelope["presentationBinding"] = {"profile": ANONYMOUS_PROFILE}
        with self.assertRaisesRegex(
            EnvelopeError, "presentationBinding is forbidden in a v1 envelope"
        ):
            validate_compliance_proof_v1(envelope)
        with self.assertRaisesRegex(
            EnvelopeError, "presentationBinding is forbidden in a v1 envelope"
        ):
            validate_envelope(envelope)

    def test_clean_v1_envelope_still_validates(self):
        validate_compliance_proof_v1(_valid_v1_envelope())


if __name__ == "__main__":
    unittest.main()

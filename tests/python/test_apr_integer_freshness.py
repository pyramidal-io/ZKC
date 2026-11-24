"""Canonical signed integers and independent APR expiry time (review R2.2)."""

import copy
import dataclasses
import json
import unittest
from unittest import mock

import _path  # noqa: F401
from _path import REPO_ROOT
from test_verifier_profiles import (
    APR_VERIFIER_PRIVATE_KEY,
    TIMESTAMP,
    ProfileVerifierBase,
)
from zkc_agent import ZKCAgentClient
from zkc_crypto import (
    FIELD_MODULUS,
    ProofContext,
    apr_freshness,
    derive_holder_commitment_from_seed,
    field_to_hex,
    sign_apr,
    verify_apr_signature,
    verify_receipt,
)
from zkc_crypto.delegation import DelegationError, ViewingScope, mint_delegation_token
from zkc_crypto.ecdsa_secp256k1 import public_key_bytes
from zkc_crypto.poseidon2 import hash_fields
from zkc_holder.errors import UnauthenticatedRequestError
from zkc_verifier import VerificationErrorCode as Code
from holder_fixtures import verify_receipt_as_holder

U64_LIMIT = 1 << 64


class IntegerAlias(int):
    pass


def invalid_integers(value, limit):
    return (-1, limit, limit + value, True, float(value), str(value), IntegerAlias(value))


class StrictSpongeTests(unittest.TestCase):
    def test_strict_rejects_aliases_but_retains_arithmetic_mode(self):
        for bad in invalid_integers(1, FIELD_MODULUS):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                hash_fields([bad], strict=True)
        self.assertEqual(hash_fields([FIELD_MODULUS + 1]), hash_fields([1]))
        self.assertEqual(hash_fields([-1]), hash_fields([FIELD_MODULUS - 1]))

    def test_all_existing_sponge_kats_match_in_strict_mode(self):
        package = json.loads((REPO_ROOT / "tests/vectors/crypto/afp_kdc_v1_0_2_conformance.json").read_text())
        for case in package["rawSponge"]:
            with self.subTest(case=case["name"]):
                inputs = [int(value, 16) for value in case["inputs"]]
                self.assertEqual(field_to_hex(hash_fields(inputs, strict=True)), case["output"])

    def test_strict_message_size_is_exact_and_bounded(self):
        for size in (-1, 2, True, 1.0, "1"):
            with self.subTest(size=size), self.assertRaises(ValueError):
                hash_fields([1], size, strict=True)


class AprIntegerFreshnessTests(ProfileVerifierBase):
    def assert_rejected_by_both(self, apr, *, now=TIMESTAMP):
        with mock.patch.object(self.holder, "_generate_envelope", side_effect=AssertionError("proof generated")):
            with self.assertRaises(UnauthenticatedRequestError):
                self.holder.generate_authenticated_proof(apr, self.make_request(), now=now)
        verifier = self.make_verifier()
        with mock.patch.object(verifier._backend, "verify", side_effect=AssertionError("backend reached")):
            result = verifier.verify_authenticated(apr, {}, self.make_verification_request(), now=now)
        self.assertEqual(result.codes(), [Code.UNSIGNED_REQUEST], result.to_dict())

    def test_modulus_expiry_alias_no_longer_authenticates_or_extends_freshness(self):
        apr = self.make_apr()
        forged = copy.deepcopy(apr)
        forged["expiresAt"] += FIELD_MODULUS
        self.assertTrue(verify_apr_signature(apr))
        self.assertFalse(verify_apr_signature(forged))
        self.assertFalse(apr_freshness(forged, TIMESTAMP + 10 * 365 * 86400, set())[0])
        self.assert_rejected_by_both(forged)

    def test_apr_time_fields_reject_every_numeric_alias(self):
        apr = self.make_apr()
        for field in ("issuedAt", "expiresAt"):
            for bad in invalid_integers(apr[field], U64_LIMIT) + (FIELD_MODULUS + apr[field],):
                with self.subTest(field=field, value=bad):
                    forged = copy.deepcopy(apr)
                    forged[field] = bad
                    with self.assertRaises(ValueError):
                        sign_apr(forged, APR_VERIFIER_PRIVATE_KEY)
                    self.assertFalse(verify_apr_signature(forged))
                    self.assertFalse(apr_freshness(forged, TIMESTAMP, set())[0])
                    self.assert_rejected_by_both(forged)

    def test_context_timestamp_and_session_aliases_rejected(self):
        apr = self.make_apr()
        cases = [("timestamp", bad) for bad in invalid_integers(TIMESTAMP, U64_LIMIT)]
        cases += [("sessionId", value) for value in (True, 555, 555.0, "555", hex(FIELD_MODULUS + 555))]
        for field, bad in cases:
            with self.subTest(field=field, value=bad):
                forged = copy.deepcopy(apr)
                forged["request"]["context"][field] = bad
                with self.assertRaises(ValueError):
                    sign_apr(forged, APR_VERIFIER_PRIVATE_KEY)
                self.assertFalse(verify_apr_signature(forged))
                self.assert_rejected_by_both(forged)

    def test_context_constructors_and_metadata_cannot_normalize_aliases(self):
        for bad in invalid_integers(TIMESTAMP, U64_LIMIT):
            with self.subTest(value=bad):
                for factory in (
                    lambda: ProofContext.verifier_session("verifier.example", 555, bad),
                    lambda: ProofContext.purpose_bound("verifier.example", 555, "access", bad),
                    lambda: ProofContext.from_metadata({**self.context.to_metadata(), "timestamp": bad}),
                    lambda: ProofContext("opaque", 1, bad),
                ):
                    with self.assertRaises(ValueError):
                        factory()
        for bad in invalid_integers(555, FIELD_MODULUS):
            with self.subTest(session=bad), self.assertRaises(ValueError):
                ProofContext.verifier_session("verifier.example", bad, TIMESTAMP)

    def test_u64_and_field_upper_bound_controls(self):
        context = ProofContext.verifier_session("verifier.example", FIELD_MODULUS - 1, U64_LIMIT - 1)
        self.assertTrue(context.reconstructs())
        apr = self.make_apr()
        apr["expiresAt"] = U64_LIMIT - 1
        apr = sign_apr(apr, APR_VERIFIER_PRIVATE_KEY)
        self.assertTrue(verify_apr_signature(apr))
        self.assertTrue(apr_freshness(apr, U64_LIMIT - 1, set())[0])

    def test_omitted_now_uses_wall_clock_for_holder_verifier_and_hosted(self):
        apr = self.make_apr()
        with mock.patch("zkc_crypto.apr.time.time", return_value=TIMESTAMP + 3601):
            self.assertFalse(apr_freshness(apr)[0])
            with self.assertRaises(UnauthenticatedRequestError):
                self.holder.generate_authenticated_proof(apr, self.make_request())
            with self.assertRaises(UnauthenticatedRequestError):
                self.holder.answer_as_hosted_service(apr, self.make_request())
            result = self.make_verifier().verify_authenticated(apr, {}, self.make_verification_request())
            self.assertEqual(result.codes(), [Code.UNSIGNED_REQUEST])

    def test_honest_current_default_clock_and_explicit_historical_time_work(self):
        apr = self.make_apr()
        with mock.patch("zkc_crypto.apr.time.time", return_value=TIMESTAMP):
            envelope = self.holder.generate_authenticated_proof(apr, self.make_request())["envelope"]
            result = self.make_verifier().verify_authenticated(apr, envelope, self.make_verification_request())
            self.assertTrue(result.valid, result.to_dict())
        with mock.patch("zkc_crypto.apr.time.time", return_value=TIMESTAMP + 3601):
            envelope = self.holder.generate_authenticated_proof(apr, self.make_request(), now=TIMESTAMP)["envelope"]
            result = self.make_verifier().verify_authenticated(apr, envelope, self.make_verification_request(), now=TIMESTAMP)
            self.assertTrue(result.valid, result.to_dict())

    def test_explicit_now_is_exact_u64(self):
        apr = self.make_apr()
        for bad in invalid_integers(TIMESTAMP, U64_LIMIT):
            with self.subTest(now=bad):
                self.assertFalse(apr_freshness(apr, bad, set())[0])
                self.assert_rejected_by_both(apr, now=bad)

    def test_receipt_rejects_aliased_demand_but_keeps_historical_verification(self):
        apr = self.make_apr()
        receipt = self.holder.generate_authenticated_proof(apr, self.make_request(), now=TIMESTAMP)["receipt"]
        with mock.patch("zkc_crypto.apr.time.time", return_value=TIMESTAMP + 10 * 365 * 86400):
            self.assertTrue(verify_receipt_as_holder(receipt)["valid"])
        forged = copy.deepcopy(receipt)
        forged["apr"]["expiresAt"] += FIELD_MODULUS
        result = verify_receipt(forged)
        self.assertFalse(result["aprValid"])
        self.assertFalse(result["holderValid"])
        self.assertFalse(result["valid"])


class DelegationIntegerTests(ProfileVerifierBase):
    def token(self, **changes):
        values = dict(master_seed=42, holder_commitment=derive_holder_commitment_from_seed(42),
                      principal_key_x=public_key_bytes(0xA11CE)[0], principal_key_y=public_key_bytes(0xA11CE)[1],
                      scope=ViewingScope(("zkc:proof:kyc:v1",), 123, "verifier.example", TIMESTAMP + 3600, 2),
                      issued_at=TIMESTAMP, nonce=7)
        values.update(changes)
        return mint_delegation_token(**values)

    def test_sha256_transcript_matches_v2_known_answer(self):
        # The v1 NUL-terminated transcript was retired (R3.8); the strict
        # integer checks apply unchanged to the length-prefixed v2 transcript.
        vectors = json.loads(
            (REPO_ROOT / "tests" / "vectors" / "delegation_token_digest_v2.json").read_text("utf-8")
        )
        expected = {case["name"]: case["digest"] for case in vectors["cases"]}
        self.assertEqual(self.token().digest().hex(), expected["apr-integer-freshness-inspection"])

    def test_mint_and_verify_reject_noncanonical_integer_fields(self):
        token = self.token()
        for field, limit in (("issued_at", U64_LIMIT), ("nonce", FIELD_MODULUS),
                             ("holder_commitment", FIELD_MODULUS)):
            for bad in invalid_integers(getattr(token, field), limit):
                with self.subTest(field=field, value=bad):
                    with self.assertRaises(DelegationError):
                        self.token(**{field: bad})
                    self.assertFalse(dataclasses.replace(token, **{field: bad}).verify_signature())
        for field, limit in (("context_value", FIELD_MODULUS), ("expires_at", U64_LIMIT), ("max_uses", 1 << 32)):
            for bad in invalid_integers(getattr(token.scope, field), limit):
                with self.subTest(field=field, value=bad):
                    scope = dataclasses.replace(token.scope, **{field: bad})
                    with self.assertRaises(DelegationError):
                        self.token(scope=scope)
                    self.assertFalse(dataclasses.replace(token, scope=scope).verify_signature())

    def test_agent_default_nonce_is_canonical_and_facades_do_not_coerce(self):
        scope = self.token().scope
        agent = ZKCAgentClient(self.holder, self.holder._registry)
        with mock.patch("zkc_agent.agent.secrets.randbelow", return_value=FIELD_MODULUS - 1) as rng:
            token = agent.delegateViewing(public_key_bytes(0xA11CE), scope, issued_at=TIMESTAMP)
        rng.assert_called_once_with(FIELD_MODULUS)
        self.assertEqual(token.nonce, FIELD_MODULUS - 1)
        self.assertTrue(token.verify_signature())
        for bad in (True, float(TIMESTAMP), str(TIMESTAMP), U64_LIMIT):
            with self.subTest(issued_at=bad), self.assertRaises(DelegationError):
                agent.delegateViewing(public_key_bytes(0xA11CE), scope, issued_at=bad, nonce=7)
        with self.assertRaises(DelegationError):
            self.holder.delegate_viewing(*public_key_bytes(0xA11CE), scope, issued_at=TIMESTAMP, nonce="7")


if __name__ == "__main__":
    unittest.main()

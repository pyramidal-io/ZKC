"""Regression coverage for the institutional-accreditation request bit."""

import copy
import unittest

import _path  # noqa: F401
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from holder_fixtures import apr_verifier_identity
from _path import REPO_ROOT

from holder_fixtures import (
    TEST_ISSUER_ID,
    TEST_ISSUER_KEY_X,
    TEST_ISSUER_KEY_Y,
)
from predicate_fixtures import issue_accreditation_credential, trusted_predicate_issuer

from zkc_crypto import (
    ANONYMOUS_PROFILE,
    ProofContext,
    SCOPED_PROFILE,
    apr_digest_from_dict,
    digest_to_message_bytes,
    field_to_hex,
    sign_apr,
)
from zkc_crypto.ecdsa_secp256k1 import public_key_bytes, sign as sign_digest
from zkc_holder import (
    ConstraintViolationError,
    HolderClient,
    HolderError,
    LocalAccumulatorProvider,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
)
from zkc_holder.client import _Presentation
from zkc_verifier import (
    IssuerAccumulatorState,
    StubVerifyBackend,
    VerificationErrorCode as Code,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)
from zkc_verifier import TrustedIssuer as VerifierTrustedIssuer


MASTER_SEED = 4242
TIMESTAMP = 1_700_000
CONTEXT_NONCE = 7_777
LINKABLE_TYPE = "zkc:proof:accreditation:v7"
PRESENTATION_TYPE = "zkc:proof:accreditation:v8"
HISTORICAL_LINKABLE_TYPE = "zkc:proof:accreditation:v3"
HISTORICAL_PRESENTATION_TYPE = "zkc:proof:accreditation:v4"
LEGACY_LINKABLE_TYPE = "zkc:proof:accreditation:v1"
LEGACY_PRESENTATION_TYPE = "zkc:proof:accreditation:v2"
APR_PRIVATE_KEY = 0xA9701


def _context():
    return ProofContext.verifier_session("flag-required.example", CONTEXT_NONCE, TIMESTAMP)


def _verifier():
    issuer = VerifierTrustedIssuer(
        issuer_id=TEST_ISSUER_ID,
        public_key_x=TEST_ISSUER_KEY_X,
        public_key_y=TEST_ISSUER_KEY_Y,
        proof_types=(
            LEGACY_LINKABLE_TYPE,
            LEGACY_PRESENTATION_TYPE,
            HISTORICAL_LINKABLE_TYPE,
            HISTORICAL_PRESENTATION_TYPE,
            LINKABLE_TYPE,
            PRESENTATION_TYPE,
        ),
    )
    return ZKCVerifier(
        REPO_ROOT,
        VerifierTrustPolicy(**apr_verifier_identity(0xA9701, "flag-required.example"), issuers=(issuer,)),
        StubVerifyBackend(),
    )


def _build(*, institutional, flag_marker, profile, credential_id):
    provider = LocalAccumulatorProvider()
    holder = HolderClient.from_seed(
        MASTER_SEED,
        PredicateRegistry.from_repo(REPO_ROOT),
        StubBackend(),
        accumulator_provider=provider,
    )
    credential = issue_accreditation_credential(
        master_seed=MASTER_SEED,
        credential_id=credential_id,
        accreditation_level=3,
        institutional=institutional,
    )
    provider.register(TEST_ISSUER_ID, credential.credential_id)
    holder.store_credential(credential)

    parameters = {"required0": 2, "required1": 0}
    if flag_marker is not _ABSENT:
        parameters["flagRequired"] = flag_marker
    request = ProofRequest(
        proof_types=[LINKABLE_TYPE],
        parameters={LINKABLE_TYPE: parameters},
        context=_context(),
        trust_policy=TrustPolicy(issuers=(trusted_predicate_issuer(),)),
        current_epochs={TEST_ISSUER_ID: provider.current_epoch(TEST_ISSUER_ID)},
    )
    if profile is None:
        envelope = generate_unauthenticated_linkable(holder, request)
        output_type = LINKABLE_TYPE
    else:
        scope_id = 0xFEED if profile == SCOPED_PROFILE else 0
        envelope = holder._generate_envelope(request, _Presentation(profile, scope_id))
        output_type = PRESENTATION_TYPE
    verification_request = VerificationRequest(
        proof_types=[output_type],
        parameters={output_type: copy.deepcopy(parameters)},
        context=_context(),
        accumulator_states={
            TEST_ISSUER_ID: IssuerAccumulatorState(
                current_epoch=provider.current_epoch(TEST_ISSUER_ID),
                roots=provider.roots(TEST_ISSUER_ID),
            )
        },
    )
    return envelope, verification_request, output_type


def _build_legacy_false(*, credential_id):
    provider = LocalAccumulatorProvider()
    holder = HolderClient.from_seed(
        MASTER_SEED,
        PredicateRegistry.from_repo(REPO_ROOT),
        StubBackend(),
        accumulator_provider=provider,
        accepted_review_statuses=("reviewed", "self_attested", "deprecated"),
    )
    credential = issue_accreditation_credential(
        master_seed=MASTER_SEED,
        credential_id=credential_id,
        accreditation_level=3,
        institutional=False,
    )
    provider.register(TEST_ISSUER_ID, credential.credential_id)
    holder.store_credential(credential)
    parameters = {"required0": 2, "required1": 0, "flagRequired": False}
    request = ProofRequest(
        proof_types=[LEGACY_LINKABLE_TYPE],
        parameters={LEGACY_LINKABLE_TYPE: copy.deepcopy(parameters)},
        context=_context(),
        trust_policy=TrustPolicy(issuers=(trusted_predicate_issuer(),)),
        current_epochs={TEST_ISSUER_ID: provider.current_epoch(TEST_ISSUER_ID)},
    )
    envelope = holder._generate_envelope(
        request, _Presentation(ANONYMOUS_PROFILE, 0)
    )
    verification_request = VerificationRequest(
        proof_types=[LEGACY_PRESENTATION_TYPE],
        parameters={LEGACY_PRESENTATION_TYPE: copy.deepcopy(parameters)},
        context=_context(),
        accumulator_states={
            TEST_ISSUER_ID: IssuerAccumulatorState(
                current_epoch=provider.current_epoch(TEST_ISSUER_ID),
                roots=provider.roots(TEST_ISSUER_ID),
            )
        },
    )
    return envelope, verification_request


def _unsigned_apr(*, proof_types, parameters, nonce):
    return {
        "request": {
            "proofTypes": list(proof_types),
            "parameters": copy.deepcopy(parameters),
            "context": {
                "profile": "zkc:context:verifier-session:v1",
                "verifierId": "flag-required.example",
                "sessionId": field_to_hex(CONTEXT_NONCE),
                "timestamp": TIMESTAMP,
            },
            "trustPolicy": {"issuers": []},
            "presentation": {"profile": ANONYMOUS_PROFILE},
        },
        "verifierId": "flag-required.example",
        "nonce": field_to_hex(nonce),
        "issuedAt": TIMESTAMP,
        "expiresAt": TIMESTAMP + 3600,
    }


def _sign_apr_without_shape_validation(unsigned):
    """Model a hostile signer without weakening the production sign helper."""
    digest = digest_to_message_bytes(apr_digest_from_dict(unsigned))
    value = sign_digest(digest, APR_PRIVATE_KEY)
    key_x, key_y = public_key_bytes(APR_PRIVATE_KEY)
    signed = copy.deepcopy(unsigned)
    signed["signature"] = {
        "scheme": "ECDSA_SECP256K1",
        "value": "0x" + value.hex(),
        "verifierKey": {"x": "0x" + key_x.hex(), "y": "0x" + key_y.hex()},
    }
    return signed


_ABSENT = object()
_PROFILES = (None, ANONYMOUS_PROFILE, SCOPED_PROFILE)


class SuccessorFlagRequiredTests(unittest.TestCase):
    def test_honest_true_and_false_or_absent_succeed(self):
        cases = ((True, True), (False, False), (False, _ABSENT))
        for profile in _PROFILES:
            for index, (institutional, flag) in enumerate(cases):
                with self.subTest(profile=profile, institutional=institutional, flag=flag):
                    envelope, request, _ = _build(
                        institutional=institutional,
                        flag_marker=flag,
                        profile=profile,
                        credential_id=3_000 + index + 10 * _PROFILES.index(profile),
                    )
                    result = _verifier().verify(envelope, request)
                    self.assertTrue(result.valid, result.to_dict())
                    self.assertEqual(result.codes(), [], result.to_dict())

    def test_false_bound_proof_cannot_satisfy_true_request(self):
        for index, profile in enumerate(_PROFILES):
            with self.subTest(profile=profile):
                envelope, request, proof_type = _build(
                    institutional=False,
                    flag_marker=False,
                    profile=profile,
                    credential_id=3_100 + index,
                )
                request.parameters[proof_type]["flagRequired"] = True
                result = _verifier().verify(envelope, request)
                self.assertFalse(result.valid, result.to_dict())
                self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())

    def test_signed_v7_apr_resolves_and_authenticates_v8(self):
        provider = LocalAccumulatorProvider()
        holder = HolderClient.from_seed(
            MASTER_SEED,
            PredicateRegistry.from_repo(REPO_ROOT),
            StubBackend(),
            accumulator_provider=provider,
        )
        credential = issue_accreditation_credential(
            master_seed=MASTER_SEED,
            credential_id=3_600,
            accreditation_level=3,
            institutional=True,
        )
        provider.register(TEST_ISSUER_ID, credential.credential_id)
        holder.store_credential(credential)
        parameters = {"required0": 2, "required1": 0, "flagRequired": True}
        context = _context()
        request = ProofRequest(
            proof_types=[LINKABLE_TYPE],
            parameters={LINKABLE_TYPE: copy.deepcopy(parameters)},
            context=context,
            trust_policy=TrustPolicy(issuers=(trusted_predicate_issuer(),)),
            current_epochs={TEST_ISSUER_ID: provider.current_epoch(TEST_ISSUER_ID)},
            presentation_profile=ANONYMOUS_PROFILE,
        )
        apr = sign_apr(
            {
                "request": {
                    "proofTypes": [LINKABLE_TYPE],
                    "parameters": {LINKABLE_TYPE: copy.deepcopy(parameters)},
                    "context": {
                        "profile": "zkc:context:verifier-session:v1",
                        "verifierId": "flag-required.example",
                        "sessionId": field_to_hex(CONTEXT_NONCE),
                        "timestamp": TIMESTAMP,
                    },
                    "trustPolicy": {"issuers": []},
                    "presentation": {"profile": ANONYMOUS_PROFILE},
                },
                "verifierId": "flag-required.example",
                "nonce": field_to_hex(0xA11CE),
                "issuedAt": TIMESTAMP,
                "expiresAt": TIMESTAMP + 3600,
            },
            0xA9701,
        )
        envelope = holder.generate_authenticated_proof(apr, request, now=request.context.timestamp)["envelope"]
        self.assertEqual(envelope["proofs"][0]["proofType"], PRESENTATION_TYPE)
        verification_request = VerificationRequest(
            proof_types=[PRESENTATION_TYPE],
            parameters={PRESENTATION_TYPE: copy.deepcopy(parameters)},
            context=context,
            accumulator_states={
                TEST_ISSUER_ID: IssuerAccumulatorState(
                    current_epoch=provider.current_epoch(TEST_ISSUER_ID),
                    roots=provider.roots(TEST_ISSUER_ID),
                )
            },
        )
        result = _verifier().verify_authenticated(apr, envelope, verification_request, now=verification_request.context.timestamp)
        self.assertTrue(result.valid, result.to_dict())
        self.assertEqual(result.codes(), [], result.to_dict())

    def test_apr_signer_rejects_ambiguous_parameter_tables(self):
        block = {"required0": 2, "required1": 0, "flagRequired": True}
        cases = (
            (
                [LINKABLE_TYPE],
                {LINKABLE_TYPE: block, PRESENTATION_TYPE: block},
                "exactly match",
            ),
            ([LINKABLE_TYPE], {}, "exactly match"),
            (
                [LINKABLE_TYPE, LINKABLE_TYPE],
                {LINKABLE_TYPE: block},
                "duplicates",
            ),
        )
        for index, (proof_types, parameters, message) in enumerate(cases):
            with self.subTest(proof_types=proof_types, parameters=parameters):
                with self.assertRaisesRegex(ValueError, message):
                    sign_apr(
                        _unsigned_apr(
                            proof_types=proof_types,
                            parameters=parameters,
                            nonce=0xA1200 + index,
                        ),
                        APR_PRIVATE_KEY,
                    )

    def test_authenticated_apr_rejects_unsigned_parameter_aliases(self):
        successor = _build(
            institutional=False,
            flag_marker=False,
            profile=ANONYMOUS_PROFILE,
            credential_id=3_601,
        )[:2]
        legacy = _build_legacy_false(credential_id=3_602)
        cases = (
            (LINKABLE_TYPE, PRESENTATION_TYPE, successor),
            (LEGACY_LINKABLE_TYPE, LEGACY_PRESENTATION_TYPE, legacy),
        )
        for index, (linkable_type, presentation_type, built) in enumerate(cases):
            with self.subTest(linkable_type=linkable_type):
                envelope, verification_request = built
                false_block = copy.deepcopy(
                    verification_request.parameters[presentation_type]
                )
                true_block = copy.deepcopy(false_block)
                true_block["flagRequired"] = True
                apr = _sign_apr_without_shape_validation(
                    _unsigned_apr(
                        proof_types=[linkable_type],
                        parameters={
                            linkable_type: true_block,
                            presentation_type: false_block,
                        },
                        nonce=0xA1300 + index,
                    )
                )
                result = _verifier().verify_authenticated(
                    apr, envelope, verification_request,
                    now=verification_request.context.timestamp
                )
                self.assertFalse(result.valid, result.to_dict())
                self.assertEqual(
                    result.codes(), [Code.UNSIGNED_REQUEST], result.to_dict()
                )

    def test_authenticated_apr_rejects_resolved_destination_collision(self):
        envelope, verification_request, _ = _build(
            institutional=False,
            flag_marker=False,
            profile=ANONYMOUS_PROFILE,
            credential_id=3_603,
        )
        false_block = copy.deepcopy(
            verification_request.parameters[PRESENTATION_TYPE]
        )
        apr = sign_apr(
            _unsigned_apr(
                proof_types=[LINKABLE_TYPE, PRESENTATION_TYPE],
                parameters={
                    LINKABLE_TYPE: copy.deepcopy(false_block),
                    PRESENTATION_TYPE: copy.deepcopy(false_block),
                },
                nonce=0xA1400,
            ),
            APR_PRIVATE_KEY,
        )
        colliding_request = copy.deepcopy(verification_request)
        colliding_request.proof_types = [PRESENTATION_TYPE, PRESENTATION_TYPE]
        result = _verifier().verify_authenticated(
            apr, envelope, colliding_request,
            now=colliding_request.context.timestamp
        )
        self.assertFalse(result.valid, result.to_dict())
        self.assertEqual(result.codes(), [Code.UNSIGNED_REQUEST], result.to_dict())

    def test_true_bound_proof_cannot_satisfy_false_request(self):
        for index, profile in enumerate(_PROFILES):
            with self.subTest(profile=profile):
                envelope, request, proof_type = _build(
                    institutional=True,
                    flag_marker=True,
                    profile=profile,
                    credential_id=3_200 + index,
                )
                request.parameters[proof_type]["flagRequired"] = False
                result = _verifier().verify(envelope, request)
                self.assertFalse(result.valid, result.to_dict())
                self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())

    def test_noninstitutional_credential_cannot_prove_true(self):
        for index, profile in enumerate(_PROFILES):
            with self.subTest(profile=profile):
                with self.assertRaises(ConstraintViolationError):
                    _build(
                        institutional=False,
                        flag_marker=True,
                        profile=profile,
                        credential_id=3_300 + index,
                    )

    def test_boolean_aliases_fail_closed_at_holder_and_verifier(self):
        aliases = (0, 1, "true", None, [])
        for index, value in enumerate(aliases):
            with self.subTest(layer="holder", value=value):
                with self.assertRaises(HolderError):
                    _build(
                        institutional=True,
                        flag_marker=value,
                        profile=None,
                        credential_id=3_400 + index,
                    )

        envelope, request, proof_type = _build(
            institutional=False,
            flag_marker=False,
            profile=None,
            credential_id=3_500,
        )
        for value in aliases:
            with self.subTest(layer="verifier", value=value):
                malformed = copy.deepcopy(request)
                malformed.parameters[proof_type]["flagRequired"] = value
                result = _verifier().verify(envelope, malformed)
                self.assertFalse(result.valid, result.to_dict())
                self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())


if __name__ == "__main__":
    unittest.main()

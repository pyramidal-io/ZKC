"""APR-negotiated presentation profiles + holder-side negotiation (design
§5.1/§5.2).

The holder resolves the APR's optional ``request.presentation`` block into a
concrete presentation profile and — for scoped requests — derives the
``scope_id`` ITSELF from the *authenticated* APR signer key (never from a
verifier-supplied literal). Anonymous is the ambient default; continuity is
always an explicit, signed, purpose-bound request (design §5.2):

1. anonymous is the default when there is no ``presentation`` block;
2. a scoped request requires an authenticated APR;
3. the scope is derived from the APR signer, not accepted from the wire;
4. a ``protocol:`` scope needs distinct holder consent (allow_protocol_scope);
5. a verifier-supplied literal ``scopeId`` in the presentation block is a
   protocol error (the holder never accepts a pre-derived scope).
"""

import copy
import unittest

import _path  # noqa: F401  (sys.path side effect)

from holder_fixtures import (
    DRAFT_OPT_IN_REVIEW_STATUSES,
    KYC_PROOF_TYPE,
    issue_kyc_credential,
    trusted_test_issuer,
)
from zkc_crypto import (
    ProofContext,
    derive_credential_binding_key,
    field_to_hex,
    sign_apr,
    verify_apr_signature,
)
from zkc_crypto.ecdsa_secp256k1 import N, public_key_bytes
from zkc_crypto.presentation import (
    ANONYMOUS_PROFILE,
    SCOPED_PROFILE,
    derive_presentation_pseudonym,
    derive_scope_id,
    derive_verifier_identity,
)
from zkc_holder import (
    HolderClient,
    LocalAccumulatorProvider,
    PredicateRegistry,
    ProofRequest,
    TrustPolicy,
)
from zkc_holder.errors import HolderError, UnauthenticatedRequestError

from _path import REPO_ROOT

REGISTRY = PredicateRegistry.from_repo(REPO_ROOT)
MASTER_SEED = 42
SESSION_ID = 555
TIMESTAMP = 1_700_000_000
KYC_V2_PROOF_TYPE = "zkc:proof:kyc:v2"

# A well-known APR verifier signing key (TEST-ONLY, public material).
APR_VERIFIER_PRIVATE_KEY = 0xA9701 % N or 1
APR_VERIFIER_KEY_X, APR_VERIFIER_KEY_Y = public_key_bytes(APR_VERIFIER_PRIVATE_KEY)


def sec1_compressed(key_x: bytes, key_y: bytes) -> bytes:
    """SEC1 compressed encoding of a public key: 0x02/0x03 prefix + x."""
    prefix = 0x02 if (key_y[-1] & 1) == 0 else 0x03
    return bytes([prefix]) + key_x


APR_SIGNER_SEC1 = sec1_compressed(APR_VERIFIER_KEY_X, APR_VERIFIER_KEY_Y)


def verifier_session_context_fixture(verifier_id="verifier.example", session_id=SESSION_ID,
                                     timestamp=TIMESTAMP) -> dict:
    return {
        "profile": "zkc:context:verifier-session:v1",
        "verifierId": verifier_id,
        "sessionId": field_to_hex(session_id),
        "timestamp": timestamp,
    }


class NegotiationBase(unittest.TestCase):
    def setUp(self):
        self.provider = LocalAccumulatorProvider()
        self.credential = issue_kyc_credential(
            master_seed=MASTER_SEED,
            credential_id=7,
            provider=self.provider,
            expires_at=2_000_000_000,
        )
        self.holder = HolderClient.from_seed(
            MASTER_SEED,
            REGISTRY,
            self._backend(),
            accumulator_provider=self.provider,
            accepted_review_statuses=DRAFT_OPT_IN_REVIEW_STATUSES,
        )
        self.holder.store_credential(self.credential)
        self.cbk = derive_credential_binding_key(MASTER_SEED)

    @staticmethod
    def _backend():
        from zkc_holder import StubBackend

        return StubBackend()

    def make_request(self, *, presentation_profile=ANONYMOUS_PROFILE,
                     allow_protocol_scope=False):
        return ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters={
                KYC_PROOF_TYPE: {
                    "requiredLevel": 1,
                    "requiredAttributes": [True, False, True, False, False],
                }
            },
            context=ProofContext.verifier_session("verifier.example", SESSION_ID, TIMESTAMP),
            trust_policy=TrustPolicy(
                issuers=(trusted_test_issuer((KYC_V2_PROOF_TYPE,)),)
            ),
            presentation_profile=presentation_profile,
            allow_protocol_scope=allow_protocol_scope,
        )

    def make_apr(
        self, *, presentation=None, include_presentation=False, signed=True, nonce=0xABC123
    ):
        request = {
            "proofTypes": [KYC_PROOF_TYPE],
            "parameters": {
                KYC_PROOF_TYPE: {
                    "requiredLevel": 1,
                    "requiredAttributes": [True, False, True, False, False],
                }
            },
            "context": verifier_session_context_fixture(),
            "trustPolicy": {"issuers": []},
        }
        if include_presentation or presentation is not None:
            request["presentation"] = presentation
        unsigned = {
            "request": request,
            "verifierId": "verifier.example",
            "nonce": field_to_hex(nonce),
            "issuedAt": TIMESTAMP,
            "expiresAt": TIMESTAMP + 3600,
        }
        if signed:
            return sign_apr(unsigned, APR_VERIFIER_PRIVATE_KEY)
        # Structurally complete but UNSIGNED: a zero signature never verifies.
        unsigned["signature"] = {
            "scheme": "ECDSA_SECP256K1",
            "value": "0x" + "00" * 64,
            "verifierKey": {
                "x": "0x" + APR_VERIFIER_KEY_X.hex(),
                "y": "0x" + APR_VERIFIER_KEY_Y.hex(),
            },
        }
        return unsigned


class DefaultAnonymousTests(NegotiationBase):
    def test_default_is_anonymous(self):
        # An APR with no presentation block answers anonymously: a v2 envelope,
        # anonymous presentationBinding, no pseudonym/scopeId, every proof's
        # public inputs pinned to the anonymous sentinel, and no holderBinding.
        apr = self.make_apr(presentation=None)
        request = self.make_request(presentation_profile=ANONYMOUS_PROFILE)
        result = self.holder.generate_authenticated_proof(apr, request, now=request.context.timestamp)
        envelope = result["envelope"]

        self.assertEqual(envelope["version"], "zkc:proof:v2")
        self.assertNotIn("holderBinding", envelope)
        binding = envelope["presentationBinding"]
        self.assertEqual(binding["profile"], ANONYMOUS_PROFILE)
        self.assertNotIn("pseudonym", binding)
        self.assertNotIn("scopeId", binding)

        zero = field_to_hex(0)
        for proof in envelope["proofs"]:
            public = proof["publicInputs"]
            self.assertEqual(public["presentation_pseudonym"], zero)
            self.assertEqual(public["scope_id"], zero)
            self.assertNotIn("holder_commitment", public)


class PresentationValidationTests(NegotiationBase):
    def test_present_malformed_block_is_bound_and_rejected(self):
        # An explicit null is part of the signed request and, like every other
        # non-object presentation block, is rejected.
        request = self.make_request(presentation_profile=ANONYMOUS_PROFILE)
        for index, presentation in enumerate((None, [], "not-an-object")):
            with self.subTest(presentation=presentation):
                apr = self.make_apr(
                    presentation=presentation,
                    include_presentation=True,
                    nonce=0xABC130 + index,
                )
                self.assertTrue(verify_apr_signature(apr))

                without_block = copy.deepcopy(apr)
                del without_block["request"]["presentation"]
                self.assertFalse(verify_apr_signature(without_block))

                with self.assertRaisesRegex(HolderError, "presentation block must be an object"):
                    self.holder.generate_authenticated_proof(apr, request, now=request.context.timestamp)

    def test_present_unknown_profile_is_rejected(self):
        apr = self.make_apr(
            presentation={"profile": "zkc:presentation:unknown:v1"},
            nonce=0xABC133,
        )
        self.assertTrue(verify_apr_signature(apr))
        request = self.make_request(presentation_profile=ANONYMOUS_PROFILE)
        with self.assertRaisesRegex(HolderError, "unknown presentation profile"):
            self.holder.generate_authenticated_proof(apr, request, now=request.context.timestamp)


class ScopedAuthenticationTests(NegotiationBase):
    def test_scoped_requires_authenticated_apr(self):
        # A scoped presentation request on an UNSIGNED APR cannot establish a
        # verifier identity, so the holder refuses by default (§5.2 rule 1).
        apr = self.make_apr(
            presentation={"profile": SCOPED_PROFILE, "scopePolicy": "verifier",
                          "rotationEpochSeconds": 0},
            signed=False,
        )
        request = self.make_request(presentation_profile=SCOPED_PROFILE)
        with self.assertRaises(UnauthenticatedRequestError):
            self.holder.generate_authenticated_proof(apr, request, now=request.context.timestamp)

    def test_scoped_derives_scope_from_apr_signer(self):
        # A valid signed scoped APR: the envelope scopeId equals the holder's
        # OWN derivation from the APR signer key, and the pseudonym derives from
        # the credential binding key and that scope (§5.2 rules 2/3).
        apr = self.make_apr(
            presentation={"profile": SCOPED_PROFILE, "scopePolicy": "verifier",
                          "rotationEpochSeconds": 0},
            signed=True,
        )
        request = self.make_request(presentation_profile=SCOPED_PROFILE)
        result = self.holder.generate_authenticated_proof(apr, request, now=request.context.timestamp)
        envelope = result["envelope"]

        expected_scope = derive_scope_id(
            derive_verifier_identity(APR_SIGNER_SEC1), "verifier", 0
        )
        expected_pseudonym = derive_presentation_pseudonym(self.cbk, expected_scope)

        binding = envelope["presentationBinding"]
        self.assertEqual(binding["profile"], SCOPED_PROFILE)
        self.assertEqual(binding["scopeId"], field_to_hex(expected_scope))
        self.assertEqual(binding["pseudonym"], field_to_hex(expected_pseudonym))
        self.assertNotIn("holderBinding", envelope)
        for proof in envelope["proofs"]:
            public = proof["publicInputs"]
            self.assertEqual(public["scope_id"], field_to_hex(expected_scope))
            self.assertEqual(public["presentation_pseudonym"], field_to_hex(expected_pseudonym))


class ProtocolScopeConsentTests(NegotiationBase):
    def test_protocol_scope_requires_distinct_consent(self):
        # A "protocol:" scope is a separately consented broad scope: refused
        # without allow_protocol_scope, accepted with it (§5.2 rule 3).
        presentation = {"profile": SCOPED_PROFILE, "scopePolicy": "protocol:demo",
                        "rotationEpochSeconds": 0}
        apr = self.make_apr(presentation=presentation, signed=True)

        without = self.make_request(
            presentation_profile=SCOPED_PROFILE, allow_protocol_scope=False
        )
        with self.assertRaises(HolderError):
            self.holder.generate_authenticated_proof(apr, without, now=without.context.timestamp)

        with_consent = self.make_request(
            presentation_profile=SCOPED_PROFILE, allow_protocol_scope=True
        )
        result = self.holder.generate_authenticated_proof(apr, with_consent, now=with_consent.context.timestamp)
        expected_scope = derive_scope_id(
            derive_verifier_identity(APR_SIGNER_SEC1), "protocol:demo", 0
        )
        self.assertEqual(
            result["envelope"]["presentationBinding"]["scopeId"],
            field_to_hex(expected_scope),
        )


class VerifierSuppliedScopeTests(NegotiationBase):
    def test_verifier_supplied_scope_id_rejected(self):
        # A literal scopeId anywhere in the presentation block is a protocol
        # error: the holder always derives scope itself (§5.2 rule 2).
        apr = self.make_apr(
            presentation={
                "profile": SCOPED_PROFILE,
                "scopePolicy": "verifier",
                "rotationEpochSeconds": 0,
                "scopeId": field_to_hex(0x1234),
            },
            signed=True,
        )
        request = self.make_request(presentation_profile=SCOPED_PROFILE)
        with self.assertRaises(HolderError):
            self.holder.generate_authenticated_proof(apr, request, now=request.context.timestamp)


class DisclosureReceiptProfileTests(NegotiationBase):
    """The receipt ``response`` binds ONLY the active profile handle (design
    §5.3): the global ``holderCommitment`` never enters a v2 receipt, and a
    scoped receipt carries the presentation pseudonym/scope, not the global
    commitment."""

    def test_anonymous_receipt_binds_no_holder_handle(self):
        # An anonymous exchange: the receipt names WHAT was answered (context +
        # proof types) but no holder-derived handle at all.
        apr = self.make_apr(presentation=None)
        request = self.make_request(presentation_profile=ANONYMOUS_PROFILE)
        result = self.holder.generate_authenticated_proof(apr, request, now=request.context.timestamp)
        response = result["receipt"]["response"]

        self.assertIn("contextValue", response)
        self.assertIn("answeredProofTypes", response)
        self.assertEqual(
            response["answeredProofTypes"],
            [entry["proofType"] for entry in result["envelope"]["proofs"]],
        )
        # No holder-linkable handle under the anonymous profile.
        self.assertNotIn("holderCommitment", response)
        self.assertNotIn("presentationPseudonym", response)
        self.assertNotIn("scopeId", response)

    def test_scoped_receipt_binds_pseudonym_and_scope_only(self):
        # A scoped exchange: the receipt binds the presentation pseudonym +
        # scope (the active handle) but NEVER the global holderCommitment.
        apr = self.make_apr(
            presentation={"profile": SCOPED_PROFILE, "scopePolicy": "verifier",
                          "rotationEpochSeconds": 0},
            signed=True,
        )
        request = self.make_request(presentation_profile=SCOPED_PROFILE)
        result = self.holder.generate_authenticated_proof(apr, request, now=request.context.timestamp)
        response = result["receipt"]["response"]
        binding = result["envelope"]["presentationBinding"]

        self.assertIn("contextValue", response)
        self.assertIn("answeredProofTypes", response)
        self.assertEqual(response["presentationPseudonym"], binding["pseudonym"])
        self.assertEqual(response["scopeId"], binding["scopeId"])
        # The scoped handle replaces — never accompanies — the global commitment.
        self.assertNotIn("holderCommitment", response)


if __name__ == "__main__":
    unittest.main()

"""Holder-local custody of a rebind's NEW secret (security review 2026-10-04, R4.1).

The authenticated rebind witness builders used to read the new binding key or
master seed from request parameters. Safeguard 6 requires those parameters to
equal the verifier-signed APR, and rebind:v4's scoped profile is granted only
to an authenticated APR, so the holder's NEXT root secret had to sit inside a
verifier-signed document -- landing in the Disclosure Receipt, the verifier's
VerificationRequest and audit bundles, or letting a malicious verifier choose
the holder's new key.

These tests pin the closed behaviour:

* the new key comes only from ``ProofRequest.rebind_secret`` (a holder-local
  ``RebindSecret``), and both successors still round-trip through the public
  API under an APR carrying no secret;
* any APR, proof request, negotiation request or verifier policy naming a
  secret parameter is refused before proving (``SECRET_IN_REQUEST``);
* receipts, envelopes, audit bundles, agent logs, exception text and repr()
  never contain the secret (grep tests over every serialized surface).
"""

import copy
import json
import unittest

import _path  # noqa: F401  (sys.path side effect)
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from holder_fixtures import verify_receipt_as_holder  # noqa: E402
from _path import REPO_ROOT

from test_agent_compliance import (
    KYC_MINIMUM,
    AgentTestBase,
    make_context,
    make_policy_document,
    make_request as make_negotiation_request,
)
from test_audit_disclosure import AuditBundleTestBase
from test_rebind_auth_verifier import (
    CREDENTIAL_ID,
    ISSUER_ID,
    KEY_X,
    KEY_Y,
    MASTER_SEED,
    SESSION_ID,
    TIMESTAMP,
    RebindAuthVerifierBase,
)
from zkc_agent.audit import AuditLog
from zkc_registry import RegistryValidationError
from zkc_registry.store import _policy_from_document
from zkc_crypto import derive_credential_binding_key, field_to_hex, sign_apr
from zkc_crypto.presentation import LINKABLE_PROFILE, SCOPED_PROFILE
from zkc_holder import (
    HolderClient,
    PredicateRegistry,
    ProofPlanner,
    ProofRequest,
    RebindSecret,
    SecretInRequestError,
    StubBackend,
    TrustPolicy,
)
from zkc_holder import TrustedIssuer as HolderTrustedIssuer
from zkc_holder.errors import ForbiddenMaterialError, HolderError
from zkc_holder.predicates import REBIND_AUTH_PROOF_TYPE, REBIND_AUTH_V2_PROOF_TYPE
from zkc_verifier import VerificationRequest

REGISTRY = PredicateRegistry.from_repo(REPO_ROOT)
NEW_MASTER_SEED = 0x5EC12E7_5EED
APR_PRIVATE_KEY = 0xA9701
KYC_PROOF_TYPE = "zkc:proof:kyc:v1"


def _secret_forms(*values):
    """Every rendering of a secret an accidental serializer could produce."""
    forms = set()
    for value in values:
        forms.update({str(value), hex(value), field_to_hex(value), f"{value:x}"})
    return forms


class CountingBackend(StubBackend):
    """Records every proving call so a refusal can be shown to precede it."""

    def __init__(self):
        super().__init__()
        self.calls = 0

    def prove(self, circuit, witness):
        self.calls += 1
        return super().prove(circuit, witness)


class SecretKeyDetectionTests(unittest.TestCase):
    def test_common_secret_spellings_are_detected(self):
        from zkc_holder import is_secret_key

        for key in (
            "newMasterSeed", "new_master_seed", "NEW-CREDENTIAL-BINDING-KEY",
            "newSeed", "new_seed", "seedPhrase", "mnemonic", "holderSecret",
            "secretKey", "rebindSecret", "privKey", "private_key",
            "new.master.seed", "new master seed", "passphrase",
        ):
            with self.subTest(key=key):
                self.assertTrue(is_secret_key(key))

    def test_request_vocabulary_is_not_flagged(self):
        from zkc_holder import is_secret_key

        for key in (
            "credentialId", "requiredLevel", "requiredAttributes", "setRoot",
            "membershipType", "requiredClaimType", "jurisdictionCanonicalSet",
            "canonicalSet", "required0", "required1", "flagRequired",
            "issuerIdHash", "schemaIdHash", "disclosedPositions", "bindingSelector",
        ):
            with self.subTest(key=key):
                self.assertFalse(is_secret_key(key))


class RebindSecretValueTests(unittest.TestCase):
    def test_repr_str_and_errors_reveal_nothing(self):
        secret = RebindSecret.from_master_seed(NEW_MASTER_SEED)
        key = derive_credential_binding_key(NEW_MASTER_SEED)
        self.assertEqual(secret.credential_binding_key, key)
        for rendering in (repr(secret), str(secret), f"{secret}"):
            for form in _secret_forms(key, NEW_MASTER_SEED):
                self.assertNotIn(form, rendering)
        for bad in (0, -5, 2**300, True, "0x1234", 1.5):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as ctx:
                    RebindSecret(bad)
                self.assertNotIn(str(bad), str(ctx.exception))

    def test_secret_cannot_be_pickled_or_mutated(self):
        import pickle

        secret = RebindSecret.from_master_seed(NEW_MASTER_SEED)
        with self.assertRaises(TypeError):
            pickle.dumps(secret)
        with self.assertRaises(AttributeError):
            secret._binding_key = 1
        self.assertIs(copy.deepcopy(secret), secret)
        with self.assertRaises(TypeError):
            json.dumps({"secret": secret})

    def test_proof_request_repr_hides_the_secret_and_secret_parameters(self):
        key = derive_credential_binding_key(NEW_MASTER_SEED)
        request = ProofRequest(
            proof_types=[REBIND_AUTH_PROOF_TYPE],
            parameters={REBIND_AUTH_PROOF_TYPE: {"newCredentialBindingKey": key}},
            context=_context(),
            trust_policy=TrustPolicy(issuers=()),
            rebind_secret=RebindSecret(key),
        )
        rendering = repr(request)
        for form in _secret_forms(key):
            self.assertNotIn(form, rendering)
        self.assertIn("[REDACTED]", rendering)


def _context():
    from zkc_crypto import ProofContext

    return ProofContext.verifier_session("verifier.example", SESSION_ID, TIMESTAMP)


class HolderLocalChannelTests(RebindAuthVerifierBase):
    """Both successors round-trip under an APR carrying no secret."""

    def holder(self, backend=None):
        holder = HolderClient.from_seed(MASTER_SEED, REGISTRY, backend or StubBackend())
        holder.store_credential(self.credential)
        return holder

    def trust_policy(self):
        return TrustPolicy(
            issuers=(
                HolderTrustedIssuer(
                    issuer_id=ISSUER_ID,
                    public_key_x=KEY_X,
                    public_key_y=KEY_Y,
                    proof_types=(REBIND_AUTH_PROOF_TYPE, REBIND_AUTH_V2_PROOF_TYPE),
                ),
            )
        )

    def apr(self, proof_type, parameters, presentation):
        return sign_apr(
            {
                "request": {
                    "proofTypes": [proof_type],
                    "parameters": {proof_type: dict(parameters)},
                    "context": {
                        "profile": self.context.profile,
                        "verifierId": "verifier.example",
                        "sessionId": field_to_hex(SESSION_ID),
                        "timestamp": TIMESTAMP,
                    },
                    "trustPolicy": {"issuers": []},
                    "presentation": presentation,
                },
                "verifierId": "verifier.example",
                "nonce": field_to_hex(0xABC123),
                "issuedAt": TIMESTAMP,
                "expiresAt": TIMESTAMP + 3600,
            },
            APR_PRIVATE_KEY,
        )

    def proof_request(self, proof_type, parameters, profile, secret=True):
        return ProofRequest(
            proof_types=[proof_type],
            parameters={proof_type: dict(parameters)},
            context=self.context,
            trust_policy=self.trust_policy(),
            presentation_profile=profile,
            rebind_secret=RebindSecret(self.new_cbk) if secret else None,
        )

    CASES = (
        (
            REBIND_AUTH_V2_PROOF_TYPE,
            SCOPED_PROFILE,
            {"profile": SCOPED_PROFILE, "scopePolicy": "verifier", "rotationEpochSeconds": 0},
            "zkc:proof:v2",
        ),
        (REBIND_AUTH_PROOF_TYPE, LINKABLE_PROFILE, {"profile": LINKABLE_PROFILE}, "zkc:proof:v1"),
    )

    def test_successors_round_trip_without_any_secret_in_the_apr(self):
        parameters = {"credentialId": CREDENTIAL_ID}
        for proof_type, profile, presentation, version in self.CASES:
            with self.subTest(proof_type=proof_type):
                apr = self.apr(proof_type, parameters, presentation)
                result = self.holder().generate_authenticated_proof(
                    apr, self.proof_request(proof_type, parameters, profile), now=TIMESTAMP
                )
                envelope, receipt = result["envelope"], result["receipt"]
                self.assertEqual(envelope["version"], version)
                self.assertEqual(envelope["proofs"][0]["proofType"], proof_type)
                verification = self.verifier().verify_authenticated(
                    apr,
                    envelope,
                    VerificationRequest(
                        proof_types=[proof_type],
                        parameters={proof_type: dict(parameters)},
                        context=self.context,
                        max_proof_age=3600,
                        accumulator_states={ISSUER_ID: self.authenticated_state},
                    ),
                    now=TIMESTAMP,
                )
                self.assertTrue(verification.valid, verification.to_dict())
                from zkc_holder.audit_export import AuditExporter, verify_audit_bundle

                self.assertTrue(verify_receipt_as_holder(receipt)["valid"])
                exporter = AuditExporter(MASTER_SEED)
                auditor = "did:zkc:auditor:example#key-1"
                bundle = exporter.export(
                    [{"envelope": envelope, "verification": {
                        "proofTypes": [proof_type],
                        "parameters": {proof_type: dict(parameters)},
                        "context": self.context.to_metadata(),
                    }}],
                    auditor_key_id=auditor,
                    valid_from=TIMESTAMP, valid_until=TIMESTAMP + 3600, purpose="audit",
                )
                self.assertTrue(verify_audit_bundle(
                    bundle, now=TIMESTAMP,
                    expected_holder_key=exporter.authorization_public_key(auditor),
                ).valid)
                # Grep every normal exported surface after a successful rebind.
                rendered = json.dumps([apr, envelope, receipt, bundle], default=str)
                for form in _secret_forms(self.new_cbk):
                    self.assertNotIn(form, rendered)

    def test_fresh_seed_channel_binds_the_holder_chosen_new_identity(self):
        from zkc_crypto import derive_holder_commitment, hex_to_field
        from zkc_crypto.presentation import derive_presentation_pseudonym

        parameters = {"credentialId": CREDENTIAL_ID}
        new_key = derive_credential_binding_key(NEW_MASTER_SEED)
        for proof_type, profile, presentation, _ in self.CASES:
            with self.subTest(proof_type=proof_type):
                request = self.proof_request(proof_type, parameters, profile)
                request.rebind_secret = RebindSecret.from_master_seed(NEW_MASTER_SEED)
                result = self.holder().generate_authenticated_proof(
                    self.apr(proof_type, parameters, presentation), request, now=TIMESTAMP,
                )
                inputs = result["envelope"]["proofs"][0]["publicInputs"]
                if profile == LINKABLE_PROFILE:
                    expected = derive_holder_commitment(new_key)
                    actual = hex_to_field(inputs["new_holder_commitment"])
                else:
                    expected = derive_presentation_pseudonym(new_key, hex_to_field(inputs["scope_id"]))
                    actual = hex_to_field(inputs["new_presentation_pseudonym"])
                self.assertEqual(actual, expected)
                rendered = json.dumps(result)
                for form in _secret_forms(NEW_MASTER_SEED, new_key):
                    self.assertNotIn(form, rendered)

    def test_secret_in_apr_extension_or_refusal_receipt_is_refused(self):
        for key in ("newMasterSeed", "newCredentialBindingKey"):
            with self.subTest(key=key):
                apr = self.apr(REBIND_AUTH_PROOF_TYPE, {"credentialId": CREDENTIAL_ID},
                               {"profile": LINKABLE_PROFILE})
                apr["request"]["extensions"] = {"extra": [{key: NEW_MASTER_SEED}]}
                request = self.proof_request(REBIND_AUTH_PROOF_TYPE,
                                            {"credentialId": CREDENTIAL_ID}, LINKABLE_PROFILE)
                backend = CountingBackend()
                holder = self.holder(backend)
                for action in (
                    lambda: holder.generate_authenticated_proof(apr, request, allow_unauthenticated=True),
                    lambda: holder.answer_as_hosted_service(apr, request, allow_unauthenticated=True),
                    lambda: holder.refusal_receipt(apr, request),
                ):
                    with self.assertRaises(SecretInRequestError) as caught:
                        action()
                    self.assertNotIn(str(NEW_MASTER_SEED), str(caught.exception))
                self.assertEqual(backend.calls, 0)

    def test_rebind_without_a_holder_local_secret_is_refused(self):
        backend = CountingBackend()
        with self.assertRaises(HolderError) as ctx:
            generate_unauthenticated_linkable(
                self.holder(backend), self.proof_request(
                    REBIND_AUTH_PROOF_TYPE,
                    {"credentialId": CREDENTIAL_ID},
                    LINKABLE_PROFILE,
                    secret=False,
                )
            )
        self.assertIn("RebindSecret", str(ctx.exception))
        self.assertEqual(backend.calls, 0)

    def test_apr_naming_a_secret_parameter_is_refused_before_proving(self):
        seed_cbk = derive_credential_binding_key(NEW_MASTER_SEED)
        for key, value in (
            ("newMasterSeed", NEW_MASTER_SEED),
            ("newCredentialBindingKey", self.new_cbk),
            ("newCredentialBindingKey", field_to_hex(self.new_cbk)),  # once a ValueError echo
            ("new_master_seed", NEW_MASTER_SEED),
        ):
            for proof_type, profile, presentation, _ in self.CASES:
                with self.subTest(key=key, value_type=type(value).__name__, proof_type=proof_type):
                    parameters = {"credentialId": CREDENTIAL_ID, key: value}
                    backend = CountingBackend()
                    with self.assertRaises(SecretInRequestError) as ctx:
                        self.holder(backend).generate_authenticated_proof(
                            self.apr(proof_type, parameters, presentation),
                            self.proof_request(proof_type, parameters, profile),
                        )
                    self.assertEqual(ctx.exception.code, "SECRET_IN_REQUEST")
                    self.assertEqual(backend.calls, 0)
                    for form in _secret_forms(self.new_cbk, NEW_MASTER_SEED, seed_cbk):
                        self.assertNotIn(form, str(ctx.exception))

    def test_unauthenticated_request_naming_a_secret_is_refused(self):
        parameters = {"credentialId": CREDENTIAL_ID, "newMasterSeed": NEW_MASTER_SEED}
        backend = CountingBackend()
        with self.assertRaises(SecretInRequestError):
            generate_unauthenticated_linkable(
                self.holder(backend), self.proof_request(REBIND_AUTH_PROOF_TYPE, parameters, LINKABLE_PROFILE)
            )
        self.assertEqual(backend.calls, 0)


class NegotiationAndPolicyTests(AgentTestBase):
    """Negotiation requests and verifier policies are refused, constant-shape."""

    def test_negotiation_request_naming_a_secret_is_refused(self):
        request = make_negotiation_request(
            parameters={KYC_PROOF_TYPE: dict(KYC_MINIMUM, newMasterSeed=NEW_MASTER_SEED)}
        )
        planner = ProofPlanner(REGISTRY, make_policy_document())
        with self.assertRaises(SecretInRequestError) as ctx:
            planner.plan(request)
        self.assertNotIn(str(NEW_MASTER_SEED), str(ctx.exception))
        offer = planner.counter_offer(request)
        self.assertEqual(offer.status, "refusal")
        self.assertEqual(offer.refusal_code, "SECRET_IN_REQUEST")
        self.assertNotIn(str(NEW_MASTER_SEED), json.dumps(offer.to_dict()))

    def test_negotiation_repr_hides_secret_values(self):
        request = make_negotiation_request(
            parameters={KYC_PROOF_TYPE: {"newMasterSeed": NEW_MASTER_SEED}}
        )
        self.assertNotIn(str(NEW_MASTER_SEED), repr(request))

    def test_verifier_policy_naming_a_secret_is_refused(self):
        requirements = {
            KYC_PROOF_TYPE: dict(KYC_MINIMUM, newCredentialBindingKey=NEW_MASTER_SEED)
        }
        # Policy validation admits only keys the typed disclosure comparator
        # governs, so the published document is refused without echoing it.
        with self.assertRaises(RegistryValidationError) as ctx:
            make_policy_document(proof_requirements=requirements)
        self.assertNotIn(str(NEW_MASTER_SEED), str(ctx.exception))
        # A policy object that skipped validation still meets the planner's
        # own SECRET_IN_REQUEST refusal.
        document = dict(make_policy_document().raw, proofRequirements=requirements)
        policy = _policy_from_document(document, "<test>")
        with self.assertRaises(SecretInRequestError):
            ProofPlanner(REGISTRY, policy).plan(make_negotiation_request())

    def test_agent_blocks_and_logs_no_secret(self):
        decision = self.agent.handle_proof_request(
            make_negotiation_request(
                parameters={KYC_PROOF_TYPE: dict(KYC_MINIMUM, newMasterSeed=NEW_MASTER_SEED)}
            ),
            make_context(),
        )
        self.assertEqual(decision.status, "blocked")
        rendered = json.dumps(
            [self.agent.audit_log.events, self.notifications, repr(decision)], default=str
        )
        self.assertIn("SECRET_IN_REQUEST", rendered)
        self.assertNotIn(str(NEW_MASTER_SEED), rendered)


class SerializedSurfaceTests(AuditBundleTestBase):
    """Audit bundles and agent logs never carry the SDK's own secret fields."""

    def test_audit_bundle_refuses_rebind_secret_fields(self):
        for key in ("newMasterSeed", "newCredentialBindingKey", "old_credential_binding_key"):
            with self.subTest(key=key):
                record = copy.deepcopy(self.proof_record)
                record["verification"]["parameters"][KYC_PROOF_TYPE][key] = NEW_MASTER_SEED
                with self.assertRaises(ForbiddenMaterialError) as ctx:
                    self.exporter.export(
                        [record],
                        auditor_key_id="did:zkc:auditor:example#key-1",
                        valid_from=1,
                        valid_until=2,
                        purpose="audit",
                    )
                self.assertIn(key, str(ctx.exception))
                self.assertNotIn(str(NEW_MASTER_SEED), str(ctx.exception))

    def test_agent_log_redacts_rebind_secret_fields(self):
        log = AuditLog()
        entry = log.record(
            "proof_request",
            parameters={
                "newMasterSeed": NEW_MASTER_SEED,
                "nested": {"NEW_CREDENTIAL_BINDING_KEY": NEW_MASTER_SEED},
            },
        )
        self.assertNotIn(str(NEW_MASTER_SEED), json.dumps(entry))


class DelegationCompatibilityTests(unittest.TestCase):
    def test_existing_digest_bytes_are_preserved(self):
        import dataclasses
        import hashlib
        from test_delegation import _jurisdiction_request
        from zkc_holder import delegation_request_digest

        _, request, _ = _jurisdiction_request()
        document = dataclasses.asdict(request)
        document.pop("rebind_secret")
        for issuer in document["trust_policy"]["issuers"]:
            for key in ("public_key_x", "public_key_y"):
                issuer[key] = issuer[key].hex()
        old_bytes = json.dumps(
            {"requests": [document], "consents": {}},
            sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
        self.assertEqual(delegation_request_digest([request]),
                         hashlib.sha256(b"zkc/delegation-reviewed-requests:v1\0" + old_bytes).digest())

    def test_local_secret_cannot_enter_delegation_commitment(self):
        from test_delegation import _jurisdiction_request
        from zkc_crypto.delegation import DelegationError
        from zkc_holder import delegation_request_digest

        _, request, _ = _jurisdiction_request()
        request.rebind_secret = RebindSecret.from_master_seed(NEW_MASTER_SEED)
        with self.assertRaises(DelegationError) as caught:
            delegation_request_digest([request])
        self.assertNotIn(str(NEW_MASTER_SEED), str(caught.exception))


if __name__ == "__main__":
    unittest.main()

"""Non-custodial scoped proving delegation (spec §5.3–§5.4).

A holder delegates scoped proving to an agent/principal without surrendering the
master seed: ``agent.delegateViewing(principal, scope, requests=...)`` mints a
request-bound holder-signed DelegationToken, the holder pre-authorizes
viewing-limited material, and a
seedless DelegatedProver exercises it within scope — failing closed otherwise.
"""

import dataclasses
import inspect
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import _path  # noqa: F401
from _path import REPO_ROOT

from predicate_fixtures import (
    JURISDICTION_PROOF_TYPE,
    TEST_ISSUER_ID,
    TEST_ISSUER_KEY_X,
    TEST_ISSUER_KEY_Y,
    issue_jurisdiction_credential,
    trusted_predicate_issuer,
)
from zkc_crypto import (
    ANONYMOUS_PROFILE,
    FIELD_MODULUS,
    ProofContext,
    CANONICAL_SET_INCLUSION,
    CanonicalCodeSet,
    derive_holder_commitment_from_seed,
    delegation_authorization_digest,
)
from zkc_crypto.delegation import (
    DelegatedProver,
    DelegationError,
    DelegationToken,
    ViewingScope,
    derive_delegation_signing_key,
    mint_delegation_token,
)
from zkc_crypto.ecdsa_secp256k1 import public_key_bytes, sign
from zkc_holder import (
    HolderClient,
    LocalAccumulatorProvider,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
    SQLiteDelegationUseStore,
    delegation_request_digest,
)
from zkc_holder.predicates import (
    JURISDICTION_V4_PROOF_TYPE,
    MEMBERSHIP_TYPE_INCLUSION,
)
from zkc_agent import DelegatedProver as ReexportedDelegatedProver  # re-export smoke
from zkc_agent import ZKCAgentClient
from zkc_verifier import (
    IssuerAccumulatorState,
    StubVerifyBackend,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)
from zkc_verifier import TrustedIssuer as VerifierTrustedIssuer

MASTER_SEED = 4242
TIMESTAMP = 1_700_000
CONTEXT_NONCE = 555
VERIFIER_ID = "verifier.example"
DELEGATE_SK = 0xA11CE5EED  # delegate (principal) private key
ATTACKER_SEED = 999_999
AUTHORIZATION_NONCE = b"\x01" * 32


def _context() -> ProofContext:
    return ProofContext.verifier_session(VERIFIER_ID, CONTEXT_NONCE, TIMESTAMP)


def _scope() -> ViewingScope:
    ctx = _context()
    return ViewingScope(
        proof_types=(JURISDICTION_PROOF_TYPE,),
        context_value=ctx.value,
        verifier_id=VERIFIER_ID,
        expires_at=ctx.timestamp + 3600,
    )


def _resign_with_seed(token, master_seed):
    signing_key = derive_delegation_signing_key(master_seed)
    holder_key_x, holder_key_y = public_key_bytes(signing_key)
    token = dataclasses.replace(
        token,
        holder_key_x=holder_key_x,
        holder_key_y=holder_key_y,
    )
    return dataclasses.replace(token, signature=sign(token.digest(), signing_key))


def _holder(provider, *, delegation_use_store=None):
    return HolderClient.from_seed(
        MASTER_SEED,
        PredicateRegistry.from_repo(REPO_ROOT),
        StubBackend(),
        accumulator_provider=provider,
        delegation_use_store=delegation_use_store,
    )


def _verifier():
    return ZKCVerifier(
        REPO_ROOT,
        VerifierTrustPolicy(
            issuers=(
                VerifierTrustedIssuer(
                    issuer_id=TEST_ISSUER_ID,
                    public_key_x=TEST_ISSUER_KEY_X,
                    public_key_y=TEST_ISSUER_KEY_Y,
                    proof_types=(JURISDICTION_PROOF_TYPE, JURISDICTION_V4_PROOF_TYPE),
                ),
            )
        ),
        StubVerifyBackend(),
    )


def _jurisdiction_request():
    credential = issue_jurisdiction_credential(
        master_seed=MASTER_SEED, credential_id=31, jurisdiction_code=840, claim_type=1
    )
    codes = [826, 840]
    code_set = CanonicalCodeSet.for_jurisdiction(codes, 1, CANONICAL_SET_INCLUSION)
    witness = code_set.membership_witness(840)
    params = {
        "membershipType": MEMBERSHIP_TYPE_INCLUSION,
        "requiredClaimType": 1,
        "jurisdictionCanonicalSet": codes,
        "jurisdictionSetRoot": code_set.root(),
        "membershipPathIndex": witness.path_index,
        "membershipSiblings": list(witness.siblings),
    }
    request = ProofRequest(
        proof_types=[JURISDICTION_PROOF_TYPE],
        parameters={JURISDICTION_PROOF_TYPE: params},
        context=_context(),
        trust_policy=TrustPolicy(issuers=(trusted_predicate_issuer(),)),
    )
    return credential, request, params


class DelegatedViewingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zkc-delegation-test-")
        self.addCleanup(self.temp.cleanup)
        self.use_store = SQLiteDelegationUseStore(pathlib.Path(self.temp.name) / "uses.sqlite")

    def _holder(self, provider):
        return _holder(provider, delegation_use_store=self.use_store)

    @staticmethod
    def _principal_signature(token, requests, *, consents=None,
                             authorization_nonce=AUTHORIZATION_NONCE):
        try:
            digest = delegation_authorization_digest(
                token.digest(), delegation_request_digest(requests, consents=consents),
                authorization_nonce,
            )
        except (AttributeError, TypeError, ValueError, OverflowError):
            return b"\x00" * 64
        return sign(digest, DELEGATE_SK)

    def _assert_authorization_rejected_before_proof(self, holder, token):
        _, request, _ = _jurisdiction_request()
        with mock.patch.object(holder, "generate_proof") as generate_proof:
            with self.assertRaises(DelegationError):
                holder.authorize_delegated_material(
                    token, [request], now=TIMESTAMP,
                    principal_signature=self._principal_signature(token, [request]),
                    authorization_nonce=AUTHORIZATION_NONCE,
                    allow_unauthenticated=True,
                )
        generate_proof.assert_not_called()

    def _delegate(self):
        """Set up: holder stores a credential, agent delegates a scope, holder
        authorizes the in-scope material. Returns the pieces a delegate holds."""
        provider = LocalAccumulatorProvider()
        holder = self._holder(provider)
        credential, request, params = _jurisdiction_request()
        provider.register(TEST_ISSUER_ID, credential.credential_id)
        holder.store_credential(credential)
        agent = ZKCAgentClient(holder, PredicateRegistry.from_repo(REPO_ROOT))

        ctx = _context()
        principal = public_key_bytes(DELEGATE_SK)
        scope = _scope()
        token = agent.delegateViewing(
            principal, scope, issued_at=ctx.timestamp, nonce=1, requests=[request]
        )
        material = agent.authorize_delegated_material(
            token, [request], now=ctx.timestamp,
            principal_signature=self._principal_signature(token, [request]),
            authorization_nonce=AUTHORIZATION_NONCE,
            allow_unauthenticated=True,
        )
        return holder, agent, token, material, ctx, params, provider

    def test_attacker_signed_token_claiming_holder_commitment_is_rejected(self):
        holder = self._holder(LocalAccumulatorProvider())
        attacker_token = mint_delegation_token(
            master_seed=ATTACKER_SEED,
            holder_commitment=derive_holder_commitment_from_seed(ATTACKER_SEED),
            principal_key_x=public_key_bytes(DELEGATE_SK)[0],
            principal_key_y=public_key_bytes(DELEGATE_SK)[1],
            scope=_scope(),
            issued_at=TIMESTAMP,
            nonce=11,
            request_digest=delegation_request_digest([_jurisdiction_request()[1]]),
        )
        attacker_token = dataclasses.replace(
            attacker_token,
            holder_commitment=holder.get_binding_commitment(),
        )
        attacker_token = _resign_with_seed(attacker_token, ATTACKER_SEED)

        self.assertTrue(attacker_token.verify_signature())
        self._assert_authorization_rejected_before_proof(holder, attacker_token)

    def test_replaced_holder_coordinates_and_signature_are_rejected(self):
        holder = self._holder(LocalAccumulatorProvider())
        legitimate_token = holder.delegate_viewing(
            *public_key_bytes(DELEGATE_SK),
            _scope(),
            issued_at=TIMESTAMP,
            nonce=12,
            requests=[_jurisdiction_request()[1]],
        )
        attacker_token = _resign_with_seed(legitimate_token, ATTACKER_SEED)

        self.assertTrue(attacker_token.verify_signature())
        self._assert_authorization_rejected_before_proof(holder, attacker_token)

    def test_token_digest_override_cannot_widen_authorized_scope(self):
        holder = self._holder(LocalAccumulatorProvider())
        signed_scope = dataclasses.replace(
            _scope(),
            proof_types=("zkc:proof:kyc:v1",),
            context_value=_context().value + 1,
        )
        legitimate_token = mint_delegation_token(
            master_seed=MASTER_SEED,
            holder_commitment=holder.get_binding_commitment(),
            principal_key_x=public_key_bytes(DELEGATE_SK)[0],
            principal_key_y=public_key_bytes(DELEGATE_SK)[1],
            scope=signed_scope,
            issued_at=TIMESTAMP,
            nonce=16,
            request_digest=delegation_request_digest([_jurisdiction_request()[1]]),
        )
        digest_overriding_token = SimpleNamespace(
            principal_key_x=legitimate_token.principal_key_x,
            principal_key_y=legitimate_token.principal_key_y,
            scope=_scope(),
            holder_commitment=legitimate_token.holder_commitment,
            issued_at=legitimate_token.issued_at,
            nonce=legitimate_token.nonce,
            holder_key_x=legitimate_token.holder_key_x,
            holder_key_y=legitimate_token.holder_key_y,
            signature=legitimate_token.signature,
            request_digest=legitimate_token.request_digest,
            digest=legitimate_token.digest,
        )

        self._assert_authorization_rejected_before_proof(
            holder,
            digest_overriding_token,
        )

    def test_kdc_alias_seed_cannot_authorize_for_holder(self):
        holder = HolderClient.from_seed(
            0,
            PredicateRegistry.from_repo(REPO_ROOT),
            StubBackend(),
            delegation_use_store=self.use_store,
        )
        alias_token = mint_delegation_token(
            master_seed=FIELD_MODULUS,
            holder_commitment=derive_holder_commitment_from_seed(FIELD_MODULUS),
            principal_key_x=public_key_bytes(DELEGATE_SK)[0],
            principal_key_y=public_key_bytes(DELEGATE_SK)[1],
            scope=_scope(),
            issued_at=TIMESTAMP,
            nonce=13,
            request_digest=delegation_request_digest([_jurisdiction_request()[1]]),
        )

        self.assertEqual(alias_token.holder_commitment, holder.get_binding_commitment())
        self.assertTrue(alias_token.verify_signature())
        self._assert_authorization_rejected_before_proof(holder, alias_token)

    def test_malformed_holder_coordinates_are_rejected_before_proof(self):
        holder = self._holder(LocalAccumulatorProvider())
        token = holder.delegate_viewing(
            *public_key_bytes(DELEGATE_SK),
            _scope(),
            issued_at=TIMESTAMP,
            nonce=14,
            requests=[_jurisdiction_request()[1]],
        )
        malformed_coordinates = (
            {"holder_key_x": token.holder_key_x[:-1]},
            {"holder_key_y": token.holder_key_y + b"\x00"},
            {"holder_key_x": None},
        )

        for replacement in malformed_coordinates:
            with self.subTest(replacement=replacement):
                self._assert_authorization_rejected_before_proof(
                    holder,
                    dataclasses.replace(token, **replacement),
                )

    def test_invalid_holder_signature_is_rejected_before_proof(self):
        holder = self._holder(LocalAccumulatorProvider())
        token = holder.delegate_viewing(
            *public_key_bytes(DELEGATE_SK),
            _scope(),
            issued_at=TIMESTAMP,
            nonce=17,
            requests=[_jurisdiction_request()[1]],
        )
        invalid_signature = token.signature[:-1] + bytes([token.signature[-1] ^ 1])

        self._assert_authorization_rejected_before_proof(
            holder,
            dataclasses.replace(token, signature=invalid_signature),
        )

    def test_malformed_signed_fields_are_rejected_before_proof(self):
        holder = self._holder(LocalAccumulatorProvider())
        token = holder.delegate_viewing(
            *public_key_bytes(DELEGATE_SK),
            _scope(),
            issued_at=TIMESTAMP,
            nonce=19,
            requests=[_jurisdiction_request()[1]],
        )
        malformed_fields = (
            ("principal key x type", {"principal_key_x": None}),
            ("principal key y width", {"principal_key_y": token.principal_key_y[:-1]}),
            (
                "proof types container",
                {"scope": dataclasses.replace(token.scope, proof_types=[])},
            ),
            (
                "proof type element",
                {"scope": dataclasses.replace(token.scope, proof_types=([],))},
            ),
            (
                "verifier id type",
                {"scope": dataclasses.replace(token.scope, verifier_id=None)},
            ),
            (
                "verifier id encoding",
                {"scope": dataclasses.replace(token.scope, verifier_id="\ud800")},
            ),
            (
                "context value",
                {"scope": dataclasses.replace(token.scope, context_value=-1)},
            ),
            (
                "expiry width",
                {"scope": dataclasses.replace(token.scope, expires_at=1 << 64)},
            ),
            (
                "use budget",
                {"scope": dataclasses.replace(token.scope, max_uses=0)},
            ),
            ("holder commitment", {"holder_commitment": -1}),
            ("issued at type", {"issued_at": object()}),
            ("nonce width", {"nonce": 1 << 256}),
            ("signature type", {"signature": None}),
        )

        for field, replacement in malformed_fields:
            with self.subTest(field=field):
                self._assert_authorization_rejected_before_proof(
                    holder,
                    dataclasses.replace(token, **replacement),
                )

    def test_mint_rejects_seed_holder_commitment_mismatch(self):
        with self.assertRaises(DelegationError):
            mint_delegation_token(
                master_seed=MASTER_SEED,
                holder_commitment=derive_holder_commitment_from_seed(ATTACKER_SEED),
                principal_key_x=public_key_bytes(DELEGATE_SK)[0],
                principal_key_y=public_key_bytes(DELEGATE_SK)[1],
                scope=_scope(),
                issued_at=TIMESTAMP,
                nonce=15,
            )

    def test_mint_rejects_non_integer_holder_commitment(self):
        expected_holder_commitment = derive_holder_commitment_from_seed(MASTER_SEED)
        for holder_commitment in (
            str(expected_holder_commitment),
            float(expected_holder_commitment),
            True,
        ):
            with self.subTest(holder_commitment_type=type(holder_commitment).__name__):
                with self.assertRaisesRegex(
                    DelegationError,
                    "holder commitment must be an integer",
                ):
                    mint_delegation_token(
                        master_seed=MASTER_SEED,
                        holder_commitment=holder_commitment,
                        principal_key_x=public_key_bytes(DELEGATE_SK)[0],
                        principal_key_y=public_key_bytes(DELEGATE_SK)[1],
                        scope=_scope(),
                        issued_at=TIMESTAMP,
                        nonce=18,
                    )

    def test_end_to_end_delegated_proof_verifies(self):
        holder, agent, token, material, ctx, params, provider = self._delegate()
        self.assertTrue(token.verify_signature())

        prover = DelegatedProver(token, DELEGATE_SK, material)
        envelope = prover.prove(JURISDICTION_PROOF_TYPE, ctx.value, VERIFIER_ID, now=ctx.timestamp)
        # The reviewed request keeps the default anonymous profile, so the
        # delegated material is a v2 presentation, never a holderBinding. Spec
        # 5.3 properties 3 and 5: the consumer requests and trusts the
        # presentation-resolved sibling identity (jurisdiction:v4), not v3.
        self.assertEqual(envelope["version"], "zkc:proof:v2")
        self.assertNotIn("holderBinding", envelope)
        self.assertEqual(envelope["presentationBinding"], {"profile": ANONYMOUS_PROFILE})
        presented = envelope["proofs"][0]["proofType"]
        self.assertEqual(presented, JURISDICTION_V4_PROOF_TYPE)

        verifier = _verifier()
        vreq = VerificationRequest(
            proof_types=[presented],
            parameters={presented: params},
            context=_context(),
            accumulator_states={
                TEST_ISSUER_ID: IssuerAccumulatorState(
                    current_epoch=provider.current_epoch(TEST_ISSUER_ID),
                    roots=provider.roots(TEST_ISSUER_ID),
                )
            },
        )
        result = verifier.verify(envelope, vreq)
        self.assertTrue(result.valid, result.to_dict())

    def test_delegated_prover_is_seedless(self):
        _, _, token, material, _, _, _ = self._delegate()
        prover = DelegatedProver(token, DELEGATE_SK, material)
        for forbidden in ("_master_seed", "_holder", "_credential_binding_key", "_seed"):
            self.assertFalse(hasattr(prover, forbidden), forbidden)
        self.assertIs(DelegatedProver, ReexportedDelegatedProver)

    def test_out_of_scope_requests_fail_closed(self):
        _, _, token, material, ctx, _, _ = self._delegate()
        prover = DelegatedProver(token, DELEGATE_SK, material)
        # Out-of-scope proof type.
        with self.assertRaises(DelegationError):
            prover.prove("zkc:proof:kyc:v1", ctx.value, VERIFIER_ID, now=ctx.timestamp)
        # Wrong context value.
        with self.assertRaises(DelegationError):
            prover.prove(JURISDICTION_PROOF_TYPE, ctx.value + 1, VERIFIER_ID, now=ctx.timestamp)
        # Wrong predicate source / verifier.
        with self.assertRaises(DelegationError):
            prover.prove(JURISDICTION_PROOF_TYPE, ctx.value, "evil.example", now=ctx.timestamp)
        # Expired.
        with self.assertRaises(DelegationError):
            prover.prove(
                JURISDICTION_PROOF_TYPE, ctx.value, VERIFIER_ID, now=token.scope.expires_at + 1
            )

    def test_use_budget_enforced(self):
        _, _, token, material, ctx, _, _ = self._delegate()
        prover = DelegatedProver(token, DELEGATE_SK, material)
        prover.prove(JURISDICTION_PROOF_TYPE, ctx.value, VERIFIER_ID, now=ctx.timestamp)  # ok (1/1)
        with self.assertRaises(DelegationError):
            prover.prove(JURISDICTION_PROOF_TYPE, ctx.value, VERIFIER_ID, now=ctx.timestamp)

    def test_wrong_principal_rejected(self):
        _, _, token, material, _, _, _ = self._delegate()
        with self.assertRaises(DelegationError):
            DelegatedProver(token, DELEGATE_SK + 1, material)

    def test_tampered_token_rejected(self):
        _, _, token, material, _, _, _ = self._delegate()
        widened = dataclasses.replace(
            token,
            scope=dataclasses.replace(token.scope, expires_at=token.scope.expires_at + 10_000),
        )
        self.assertFalse(widened.verify_signature())
        with self.assertRaises(DelegationError):
            DelegatedProver(widened, DELEGATE_SK, material)

    def test_material_outside_scope_rejected(self):
        # Authorizing material for a proof type the token never scoped fails closed.
        provider = LocalAccumulatorProvider()
        holder = self._holder(provider)
        credential, request, _ = _jurisdiction_request()
        provider.register(TEST_ISSUER_ID, credential.credential_id)
        holder.store_credential(credential)
        agent = ZKCAgentClient(holder, PredicateRegistry.from_repo(REPO_ROOT))
        ctx = _context()
        scope = ViewingScope(
            proof_types=("zkc:proof:kyc:v1",),  # does NOT include jurisdiction
            context_value=ctx.value,
            verifier_id=VERIFIER_ID,
            expires_at=ctx.timestamp + 3600,
        )
        token = mint_delegation_token(
            master_seed=MASTER_SEED,
            holder_commitment=holder.get_binding_commitment(),
            principal_key_x=public_key_bytes(DELEGATE_SK)[0],
            principal_key_y=public_key_bytes(DELEGATE_SK)[1],
            scope=scope,
            issued_at=ctx.timestamp,
            nonce=2,
            request_digest=delegation_request_digest([request]),
        )
        with self.assertRaises(DelegationError):
            agent.authorize_delegated_material(
                token, [request], now=ctx.timestamp,
                principal_signature=self._principal_signature(token, [request]),
                authorization_nonce=AUTHORIZATION_NONCE,
                allow_unauthenticated=True,
            )

    def test_delegate_viewing_rejects_expired_scope(self):
        provider = LocalAccumulatorProvider()
        agent = ZKCAgentClient(self._holder(provider), PredicateRegistry.from_repo(REPO_ROOT))
        ctx = _context()
        bad_scope = ViewingScope(
            proof_types=(JURISDICTION_PROOF_TYPE,),
            context_value=ctx.value,
            verifier_id=VERIFIER_ID,
            expires_at=ctx.timestamp,  # not after issuance
        )
        with self.assertRaises(DelegationError):
            agent.delegateViewing(
                public_key_bytes(DELEGATE_SK), bad_scope, issued_at=ctx.timestamp, nonce=3
            )


class DelegationDocumentationContractTests(unittest.TestCase):
    def test_spec_pins_local_holder_key_and_same_seed_minting_invariants(self):
        spec = (REPO_ROOT / "docs" / "zkc_specification.md").read_text()
        start = spec.index("### 5.3 Delegated Proof Generation")
        end = spec.index("### 5.5 Authenticated Proof Request", start)
        section = " ".join(spec[start:end].split())

        self.assertIn(
            "MUST resolve the expected delegation verification key from "
            "authenticated local holder state",
            section,
        )
        self.assertIn(
            "MUST NOT use `holderKeyX`, `holderKeyY`, or any other "
            "token-carried key as the authorization trust anchor",
            section,
        )
        self.assertIn(
            "MUST NOT treat any of them as a substitute for the cryptographic "
            "holder-key anchor",
            section,
        )
        self.assertIn("KDC aliases with the same commitment", section)
        self.assertIn(
            "derive both the delegation signing key and `holderCommitment` "
            "from those same authenticated local seed bytes",
            section,
        )
        self.assertIn("changes the token wire format", section)

    def test_public_api_docs_separate_self_consistency_from_authorization(self):
        token_verification = inspect.getdoc(DelegationToken.verify_signature)
        holder_authorization = " ".join(
            inspect.getdoc(HolderClient.authorize_delegated_material).split()
        )
        agent_authorization = " ".join(
            inspect.getdoc(ZKCAgentClient.authorize_delegated_material).split()
        )

        self.assertIn("self-consistency", token_verification)
        self.assertIn("does not authenticate a holder", token_verification)
        self.assertIn("MUST NOT authorize", token_verification)
        self.assertIn("authenticated local seed", holder_authorization)
        self.assertIn("before proof generation", holder_authorization)
        self.assertIn("never trusts", agent_authorization)


if __name__ == "__main__":
    unittest.main()

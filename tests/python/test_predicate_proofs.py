"""Generate + verify the five non-KYC ZKC predicate proofs via the holder SDK
backend, plus direct constraint-mirror fail-closed coverage.

The StubBackend re-evaluates each circuit's constraints in Python before
emitting a deterministic (NON-production) stub payload, and StubVerifyBackend
recomputes that payload — so a full generate -> verify round trip exercises the
witness builders, the public-input extractors, and the constraint mirrors for
every predicate without the Noir toolchain. Live nargo+bb proving is covered by
test_live_predicate_proving.py (skips when the toolchain is absent).

Predicate-circuit coverage: zkc_jurisdiction_v3 (inclusion + exclusion),
zkc_remaining_predicates_v7 (accreditation, source-of-funds, tax, sanctions), and
zkc_credential_rebind. The four set-membership circuits run through the full
ZKCVerifier; credential-rebind (which has a distinct public-input shape with no
accumulator binding) is verified through the proof backend directly.
"""

import unittest

import _path  # noqa: F401
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from _path import REPO_ROOT

from predicate_fixtures import (
    ACCREDITATION_V7_PROOF_TYPE,
    JURISDICTION_PROOF_TYPE,
    REBIND_PROOF_TYPE,
    SANCTIONS_V7_PROOF_TYPE,
    SOURCE_V7_PROOF_TYPE,
    TAX_V7_PROOF_TYPE,
    TEST_ISSUER_ID,
    TEST_ISSUER_KEY_X,
    TEST_ISSUER_KEY_Y,
    issue_accreditation_credential,
    issue_jurisdiction_credential,
    issue_rebindable_credential,
    issue_sanctions_credential,
    issue_source_credential,
    issue_tax_credential,
    new_rebind_binding_key,
    trusted_predicate_issuer,
)

from zkc_crypto import (
    CANONICAL_SET_EXCLUSION,
    JURISDICTION_CANONICAL_SET_PARAM,
    CANONICAL_SET_PARAM,
    CanonicalCodeSet,
    ProofContext,
    compute_jurisdiction_leaf,
    validate_compliance_proof_v1,
)
from zkc_holder.rebind_secret import RebindSecret
from zkc_holder import (
    HolderClient,
    LocalAccumulatorProvider,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
)
from zkc_holder.errors import ConstraintViolationError
from zkc_holder.predicates import (
    MEMBERSHIP_TYPE_EXCLUSION,
    MEMBERSHIP_TYPE_INCLUSION,
    REBIND_BINDING_V2_CIRCUIT,
    REBIND_BINDING_V2_PROOF_TYPE,
    single_leaf_inclusion_witness,
    single_leaf_set_root,
)
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


def _context() -> ProofContext:
    return ProofContext.verifier_session("verifier.example", CONTEXT_NONCE, TIMESTAMP)


def _holder(provider):
    return HolderClient.from_seed(
        MASTER_SEED,
        PredicateRegistry.from_repo(REPO_ROOT),
        StubBackend(),
        accumulator_provider=provider,
    )


def _verifier(proof_types):
    return ZKCVerifier(
        REPO_ROOT,
        VerifierTrustPolicy(
            issuers=(
                VerifierTrustedIssuer(
                    issuer_id=TEST_ISSUER_ID,
                    public_key_x=TEST_ISSUER_KEY_X,
                    public_key_y=TEST_ISSUER_KEY_Y,
                    proof_types=tuple(proof_types),
                ),
            )
        ),
        StubVerifyBackend(),
    )


class PredicateRoundTripTests(unittest.TestCase):
    """Holder SDK generates a stub proof the reference verifier accepts."""

    def _round_trip(self, proof_type, credential, parameters):
        provider = LocalAccumulatorProvider()
        client = _holder(provider)
        provider.register(TEST_ISSUER_ID, credential.credential_id)
        client.store_credential(credential)
        request = ProofRequest(
            proof_types=[proof_type],
            parameters={proof_type: parameters},
            context=_context(),
            trust_policy=TrustPolicy(issuers=(trusted_predicate_issuer(),)),
        )
        exact_member_consents = {
            JURISDICTION_PROOF_TYPE: True,
            SOURCE_V7_PROOF_TYPE: True,
            TAX_V7_PROOF_TYPE: True,
        }
        envelope = generate_unauthenticated_linkable(
            client, request, exact_member_consents=exact_member_consents,
        )
        validate_compliance_proof_v1(envelope)
        self.assertEqual(envelope["proofs"][0]["proofType"], proof_type)

        verifier = _verifier([proof_type])
        verification_request = VerificationRequest(
            proof_types=[proof_type],
            parameters={proof_type: parameters},
            context=_context(),
            accumulator_states={
                TEST_ISSUER_ID: IssuerAccumulatorState(
                    current_epoch=provider.current_epoch(TEST_ISSUER_ID),
                    roots=provider.roots(TEST_ISSUER_ID),
                )
            },
        )
        result = verifier.verify(envelope, verification_request)
        self.assertTrue(result.valid, result.to_dict())
        return envelope, result

    def test_jurisdiction_inclusion(self):
        credential = issue_jurisdiction_credential(
            master_seed=MASTER_SEED, credential_id=11, jurisdiction_code=840, claim_type=1
        )
        leaf = compute_jurisdiction_leaf(840, 1)
        path_index, siblings = single_leaf_inclusion_witness()
        self._round_trip(
            JURISDICTION_PROOF_TYPE,
            credential,
            {
                "membershipType": MEMBERSHIP_TYPE_INCLUSION,
                "requiredClaimType": 1,
                "jurisdictionSetRoot": single_leaf_set_root(leaf),
                "membershipPathIndex": path_index,
                "membershipSiblings": siblings,
            },
        )

    def test_jurisdiction_exclusion(self):
        # Credential jurisdiction 150 proven NOT in a blocked set whose sorted
        # neighbors are 100 and 200.
        credential = issue_jurisdiction_credential(
            master_seed=MASTER_SEED, credential_id=12, jurisdiction_code=150, claim_type=1
        )
        blocked_codes = [100, 200]
        blocked_set = CanonicalCodeSet.for_jurisdiction(
            blocked_codes, claim_type=1, mode=CANONICAL_SET_EXCLUSION
        )
        self._round_trip(
            JURISDICTION_PROOF_TYPE,
            credential,
            {
                "membershipType": MEMBERSHIP_TYPE_EXCLUSION,
                "requiredClaimType": 1,
                JURISDICTION_CANONICAL_SET_PARAM: blocked_codes,
                "jurisdictionSetRoot": blocked_set.root(),
            },
        )

    def test_accreditation(self):
        credential = issue_accreditation_credential(
            master_seed=MASTER_SEED, credential_id=13, accreditation_level=3, institutional=True
        )
        self._round_trip(
            ACCREDITATION_V7_PROOF_TYPE,
            credential,
            {"required0": 2, "required1": 0, "flagRequired": True},
        )

    def test_source_of_funds(self):
        credential = issue_source_credential(
            master_seed=MASTER_SEED, credential_id=14, source_code=7
        )
        path_index, siblings = single_leaf_inclusion_witness()
        self._round_trip(
            SOURCE_V7_PROOF_TYPE,
            credential,
            {
                "required0": 0,
                "required1": 0,
                "setRoot": single_leaf_set_root(7),
                "pathIndex": path_index,
                "siblings": siblings,
            },
        )

    def test_tax_residency(self):
        credential = issue_tax_credential(
            master_seed=MASTER_SEED, credential_id=15, tax_code=840, tax_year=2026
        )
        path_index, siblings = single_leaf_inclusion_witness()
        self._round_trip(
            TAX_V7_PROOF_TYPE,
            credential,
            {
                "required0": 0,
                "required1": 2025,
                "setRoot": single_leaf_set_root(840),
                "pathIndex": path_index,
                "siblings": siblings,
            },
        )

    def test_sanctions_clearance(self):
        credential = issue_sanctions_credential(
            master_seed=MASTER_SEED, credential_id=16, screening_code=150
        )
        blocked_codes = [100, 200]
        blocked_set = CanonicalCodeSet.for_sanctions(blocked_codes)
        self._round_trip(
            SANCTIONS_V7_PROOF_TYPE,
            credential,
            {
                "required0": 0,
                "required1": 0,
                CANONICAL_SET_PARAM: blocked_codes,
                "setRoot": blocked_set.root(),
            },
        )


class CredentialRebindContainmentTests(unittest.TestCase):
    """Security containment: the holder SDK never generates a credential-rebind
    proof through any of the four published rebind identities, because none of
    their circuits authenticates the credential being migrated (spec section
    4.5). Exploit-shaped envelopes and the verifier-side gate are covered by
    test_rebind_containment.py; this class pins the holder-side refusals that
    replaced the former round-trip tests at this location.
    """

    def _client(self, **kwargs):
        client = HolderClient.from_seed(
            MASTER_SEED, PredicateRegistry.from_repo(REPO_ROOT), StubBackend(), **kwargs
        )
        client.store_credential(
            issue_rebindable_credential(
                master_seed=MASTER_SEED, credential_id=21, issuer_id_hash=1001, schema_id_hash=2002
            )
        )
        return client

    def _request(self, proof_type):
        return ProofRequest(
            proof_types=[proof_type],
            parameters={
                proof_type: {
                    "issuerIdHash": 1001,
                    "schemaIdHash": 2002,
                }
            },
            rebind_secret=RebindSecret(new_rebind_binding_key(99)),
            context=_context(),
            trust_policy=TrustPolicy(issuers=(trusted_predicate_issuer((proof_type,)),)),
        )

    def test_holder_refuses_every_linkable_rebind_identity(self):
        from zkc_holder.errors import UnauthenticatedProofTypeError

        for proof_type in (REBIND_PROOF_TYPE, REBIND_BINDING_V2_PROOF_TYPE):
            with self.subTest(proof_type=proof_type):
                client = self._client()
                with self.assertRaises(UnauthenticatedProofTypeError) as ctx:
                    generate_unauthenticated_linkable(client, self._request(proof_type))
                self.assertEqual(ctx.exception.code, "UNAUTHENTICATED_PROOF_TYPE")
                with self.assertRaises(UnauthenticatedProofTypeError):
                    client.select_credential(self._request(proof_type), proof_type)

    def test_review_status_override_does_not_reopen_the_rebind_path(self):
        """allow_opaque / draft acceptance are review-status overrides; they are
        not a bypass of the credential-authentication containment."""
        from zkc_holder.errors import UnauthenticatedProofTypeError

        client = self._client(accepted_review_statuses=("draft", "self_attested"))
        with self.assertRaises(UnauthenticatedProofTypeError):
            generate_unauthenticated_linkable(client, self._request(REBIND_BINDING_V2_PROOF_TYPE), allow_opaque=True)

    def test_frozen_builders_still_mirror_the_historical_circuits(self):
        """The retained witness builder and constraint mirror remain a faithful
        record of the byte-frozen legacy circuit; the stub backend proves the
        historical statement for cross-wire/VK-separation tests only, and the
        stub verify backend keeps circuit identity in its transcript."""
        from zkc_crypto import derive_credential_binding_key
        from zkc_holder.predicates import build_rebind_witness

        credential = issue_rebindable_credential(
            master_seed=MASTER_SEED, credential_id=21, issuer_id_hash=1001, schema_id_hash=2002
        )
        witness = build_rebind_witness(
            old_credential_binding_key=derive_credential_binding_key(MASTER_SEED),
            new_credential_binding_key=new_rebind_binding_key(99),
            credential=credential,
            issuer_id_hash=1001,
            schema_id_hash=2002,
            proof_context=_context().value,
            timestamp=TIMESTAMP,
        )
        backend = StubBackend()
        proof = backend.prove("zkc_credential_rebind", witness)
        public_inputs = backend.public_inputs("zkc_credential_rebind", witness)
        verify_backend = StubVerifyBackend()
        self.assertTrue(verify_backend.verify("zkc_credential_rebind", proof, public_inputs, None))
        self.assertFalse(
            verify_backend.verify(REBIND_BINDING_V2_CIRCUIT, proof, public_inputs, None)
        )


class PredicateConstraintMirrorTests(unittest.TestCase):
    """The Python constraint mirror fails closed exactly where the circuit
    would — so the stub backend can never emit a proof for a rejected witness.

    These build a witness via the holder path, then mutate it and re-run the
    circuit's constraint check, asserting the circuit's failure message.
    """

    def _jurisdiction_witness(self):
        from zkc_holder.predicates import build_jurisdiction_witness

        provider = LocalAccumulatorProvider()
        credential = issue_jurisdiction_credential(
            master_seed=MASTER_SEED, credential_id=31, jurisdiction_code=840, claim_type=1
        )
        provider.register(TEST_ISSUER_ID, credential.credential_id)
        witness = provider.witness(TEST_ISSUER_ID, credential.credential_id)
        leaf = compute_jurisdiction_leaf(840, 1)
        path_index, siblings = single_leaf_inclusion_witness()
        from zkc_crypto import derive_credential_binding_key

        return build_jurisdiction_witness(
            credential_binding_key=derive_credential_binding_key(MASTER_SEED),
            credential=credential,
            issuer=trusted_predicate_issuer(),
            witness=witness,
            membership_type=MEMBERSHIP_TYPE_INCLUSION,
            required_claim_type=1,
            jurisdiction_set_root=single_leaf_set_root(leaf),
            membership_path_index=path_index,
            membership_siblings=siblings,
            predecessor_code=0,
            predecessor_path_index=0,
            predecessor_siblings=[0] * 32,
            successor_code=0,
            successor_path_index=0,
            successor_siblings=[0] * 32,
            proof_context=12345,
            timestamp=TIMESTAMP,
            current_epoch=provider.current_epoch(TEST_ISSUER_ID),
        )

    def test_jurisdiction_valid_passes(self):
        from zkc_holder.predicates import check_jurisdiction_constraints

        check_jurisdiction_constraints(self._jurisdiction_witness())  # no raise

    def test_jurisdiction_rejects_non_member(self):
        from zkc_holder.predicates import check_jurisdiction_constraints

        witness = self._jurisdiction_witness()
        witness["jurisdiction_set_root"] = single_leaf_set_root(compute_jurisdiction_leaf(826, 1))
        with self.assertRaises(ConstraintViolationError) as ctx:
            check_jurisdiction_constraints(witness)
        self.assertIn("jurisdiction set proof failed", str(ctx.exception))

    def test_jurisdiction_rejects_tampered_signature(self):
        from zkc_holder.predicates import check_jurisdiction_constraints

        witness = self._jurisdiction_witness()
        witness["issuer_signature"][0] ^= 0x01
        with self.assertRaises(ConstraintViolationError) as ctx:
            check_jurisdiction_constraints(witness)
        self.assertIn("invalid issuer signature", str(ctx.exception))

    def test_jurisdiction_rejects_claim_type_mismatch(self):
        from zkc_holder.predicates import check_jurisdiction_constraints

        witness = self._jurisdiction_witness()
        witness["required_claim_type"] = 2
        with self.assertRaises(ConstraintViolationError) as ctx:
            check_jurisdiction_constraints(witness)
        self.assertIn("claim type", str(ctx.exception))

    def _profile_witness(self, predicate_type, claim0, claim1, **overrides):
        from zkc_holder.predicates import build_profile_witness
        from zkc_crypto import derive_credential_binding_key

        provider = LocalAccumulatorProvider()
        # A profile credential signed for the requested predicate slot.
        from predicate_fixtures import _issue_profile_credential

        credential = _issue_profile_credential(
            master_seed=MASTER_SEED,
            credential_id=overrides.get("credential_id", 32),
            proof_type="zkc:proof:accreditation:v1",
            credential_type="zkc:cred:accreditation:v1",
            predicate_type=predicate_type,
            claim0=claim0,
            claim1=claim1,
            valid_from=1000,
            valid_until=2_000_000_000,
            provider=provider,
            issuer_id=TEST_ISSUER_ID,
            legacy=True,
        )
        witness = provider.witness(TEST_ISSUER_ID, credential.credential_id)
        kwargs = dict(
            predicate_type=predicate_type,
            credential_binding_key=derive_credential_binding_key(MASTER_SEED),
            credential=credential,
            issuer=trusted_predicate_issuer(),
            witness=witness,
            required_0=overrides.get("required_0", 0),
            required_1=overrides.get("required_1", 0),
            flag_required=overrides.get("flag_required", False),
            set_root=overrides.get("set_root", 0),
            path_index=overrides.get("path_index", 0),
            siblings=overrides.get("siblings", [0] * 32),
            predecessor_code=overrides.get("predecessor_code", 0),
            predecessor_path_index=overrides.get("predecessor_path_index", 0),
            predecessor_siblings=overrides.get("predecessor_siblings", [0] * 32),
            successor_code=overrides.get("successor_code", 0),
            successor_path_index=overrides.get("successor_path_index", 0),
            successor_siblings=overrides.get("successor_siblings", [0] * 32),
            proof_context=12345,
            timestamp=TIMESTAMP,
            current_epoch=provider.current_epoch(TEST_ISSUER_ID),
        )
        return build_profile_witness(**kwargs)

    def test_accreditation_rejects_insufficient_level(self):
        from zkc_holder.predicates import (
            PREDICATE_ACCREDITATION,
            check_profile_constraints,
        )

        witness = self._profile_witness(PREDICATE_ACCREDITATION, 3, 1, required_0=2, flag_required=True)
        check_profile_constraints(witness)  # baseline valid
        witness["required_0"] = 4
        # recompute claim binding for the new request so we hit the predicate
        # check, not claim-binding mismatch.
        from zkc_crypto import compute_claim_binding_3

        witness["claim_binding"] = compute_claim_binding_3(
            witness["predicate_type"],
            witness["required_0"],
            witness["required_1"],
            witness["proof_context"],
            witness["timestamp"],
        )
        with self.assertRaises(ConstraintViolationError) as ctx:
            check_profile_constraints(witness)
        self.assertIn("predicate-specific requirement failed", str(ctx.exception))

    def test_accreditation_rejects_missing_institutional_flag(self):
        from zkc_holder.predicates import (
            PREDICATE_ACCREDITATION,
            check_profile_constraints,
        )

        # Issuer signed claim_1 = 0 (non-institutional); a flagRequired request
        # cannot be satisfied.
        witness = self._profile_witness(
            PREDICATE_ACCREDITATION, 3, 0, required_0=2, flag_required=True
        )
        with self.assertRaises(ConstraintViolationError) as ctx:
            check_profile_constraints(witness)
        self.assertIn("predicate-specific requirement failed", str(ctx.exception))

    def test_tax_rejects_old_year(self):
        from zkc_holder.predicates import (
            PREDICATE_TAX_RESIDENCY,
            check_profile_constraints,
        )
        from zkc_crypto import compute_claim_binding_3

        witness = self._profile_witness(
            PREDICATE_TAX_RESIDENCY,
            840,
            2026,
            required_1=2025,
            set_root=single_leaf_set_root(840),
        )
        check_profile_constraints(witness)  # baseline valid
        witness["required_1"] = 2027
        witness["claim_binding"] = compute_claim_binding_3(
            witness["predicate_type"],
            witness["required_0"],
            witness["required_1"],
            witness["proof_context"],
            witness["timestamp"],
        )
        with self.assertRaises(ConstraintViolationError) as ctx:
            check_profile_constraints(witness)
        self.assertIn("predicate-specific requirement failed", str(ctx.exception))

    def test_profile_rejects_tampered_signature(self):
        from zkc_holder.predicates import (
            PREDICATE_SOURCE_OF_FUNDS,
            check_profile_constraints,
        )

        witness = self._profile_witness(
            PREDICATE_SOURCE_OF_FUNDS, 7, 0, set_root=single_leaf_set_root(7)
        )
        witness["issuer_signature"][0] ^= 0x01
        with self.assertRaises(ConstraintViolationError) as ctx:
            check_profile_constraints(witness)
        self.assertIn("invalid issuer signature", str(ctx.exception))

    def _rebind_witness(self):
        from zkc_holder.predicates import build_rebind_witness
        from zkc_crypto import derive_credential_binding_key

        credential = issue_rebindable_credential(
            master_seed=MASTER_SEED, credential_id=41, issuer_id_hash=1001, schema_id_hash=2002
        )
        return build_rebind_witness(
            old_credential_binding_key=derive_credential_binding_key(MASTER_SEED),
            new_credential_binding_key=new_rebind_binding_key(99),
            credential=credential,
            issuer_id_hash=1001,
            schema_id_hash=2002,
            proof_context=12345,
            timestamp=TIMESTAMP,
        )

    def test_rebind_valid_passes(self):
        from zkc_holder.predicates import check_rebind_constraints

        check_rebind_constraints(self._rebind_witness())  # no raise

    def test_binding_v2_rebind_requires_its_exact_statement_domain(self):
        from zkc_holder.predicates import (
            REBIND_BINDING_V2_STATEMENT_DOMAIN,
            check_rebind_binding_v2_constraints,
        )

        witness = self._rebind_witness()
        self.assertNotIn("statement_domain", witness, "frozen builder output changed")
        with self.assertRaisesRegex(ConstraintViolationError, "statement domain mismatch"):
            check_rebind_binding_v2_constraints(witness)

        witness["statement_domain"] = REBIND_BINDING_V2_STATEMENT_DOMAIN
        check_rebind_binding_v2_constraints(witness)
        witness["statement_domain"] ^= 1
        with self.assertRaisesRegex(ConstraintViolationError, "statement domain mismatch"):
            check_rebind_binding_v2_constraints(witness)

    def test_rebind_rejects_unchanged_holder(self):
        from zkc_holder.predicates import check_rebind_constraints
        from zkc_crypto import derive_credential_binding_key, derive_holder_commitment

        witness = self._rebind_witness()
        same = derive_credential_binding_key(MASTER_SEED)
        witness["new_credential_binding_key"] = same
        witness["new_holder_commitment"] = derive_holder_commitment(same)
        with self.assertRaises(ConstraintViolationError) as ctx:
            check_rebind_constraints(witness)
        self.assertIn("rebind must change holder commitment", str(ctx.exception))

    def test_rebind_rejects_wrong_issuer(self):
        from zkc_holder.predicates import check_rebind_constraints

        witness = self._rebind_witness()
        witness["issuer_id_hash"] += 1
        with self.assertRaises(ConstraintViolationError) as ctx:
            check_rebind_constraints(witness)
        self.assertIn("issuer mismatch", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

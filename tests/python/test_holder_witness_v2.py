"""Holder v2 witness assembly + presentation-profile proof-type resolution.

Design §4. The v2 witness builders are ADDITIVE — the v1
build_*_witness functions and their byte-identical outputs are untouched.

v2 public-input shape (design §4.1/§4.2):
  * index 0 = presentation_pseudonym  (replaces holder_commitment)
  * index 1 = scope_id                (new)
  * holder_commitment moves OUT of the public inputs (private witness only)
  * anonymous (scope_id == 0)  -> presentation_pseudonym == 0
  * scoped   (scope_id != 0)   -> presentation_pseudonym ==
                                  derive_presentation_pseudonym(cbk, scope_id)
"""

import unittest

import _path  # noqa: F401  (sys.path side effect)

from zkc_crypto import derive_credential_binding_key, field_to_hex
from zkc_crypto.presentation import (
    ANONYMOUS_PROFILE,
    LINKABLE_PROFILE,
    SCOPED_PROFILE,
    derive_presentation_pseudonym,
    derive_scope_id,
    derive_verifier_identity,
)
from zkc_holder.backend import (
    KYC_V2_PUBLIC_INPUT_NAMES,
    build_kyc_witness_v2,
    kyc_public_inputs_v2,
)
from zkc_holder.errors import ConstraintViolationError
from zkc_holder.predicates import (
    JURISDICTION_V2_PUBLIC_INPUT_NAMES,
    PROFILE_V2_PUBLIC_INPUT_NAMES,
    REBIND_V2_PUBLIC_INPUT_NAMES,
    PREDICATE_ACCREDITATION,
    build_jurisdiction_witness_v2,
    build_profile_witness_v2,
    build_rebind_witness_v2,
    jurisdiction_public_inputs_v2,
    profile_public_inputs_v2,
    rebind_public_inputs_v2,
    REBIND_V2_BINDING_V2_STATEMENT_DOMAIN,
    UNAUTHENTICATED_REBIND_PROOF_TYPES,
    check_rebind_v2_binding_v2_constraints,
    resolve_presentation_proof_type,
    resolve_presentation_proof_type_for_request,
)
from zkc_holder.errors import UnauthenticatedProofTypeError
from zkc_holder.accumulator import LocalAccumulatorProvider

from holder_fixtures import (
    TEST_ISSUER_ID,
    issue_kyc_credential,
    trusted_test_issuer,
)
from predicate_fixtures import (
    TEST_ISSUER_ID as PRED_ISSUER_ID,
    issue_accreditation_credential,
    issue_jurisdiction_credential,
    issue_rebindable_credential,
    new_rebind_binding_key,
    trusted_predicate_issuer,
)
from zkc_crypto import compute_jurisdiction_leaf
from zkc_holder.predicates import (
    MEMBERSHIP_TYPE_INCLUSION,
    single_leaf_inclusion_witness,
    single_leaf_set_root,
)

MASTER_SEED = 42
PRED_MASTER_SEED = 4242
SCOPE_POLICY = "verifier"
# A well-known SEC1 compressed key just to derive a concrete scope_id.
VERIFIER_PUBKEY = bytes([0x02]) + bytes(range(1, 33))


def _scoped_scope_id() -> int:
    verifier_identity = derive_verifier_identity(VERIFIER_PUBKEY)
    return derive_scope_id(verifier_identity, SCOPE_POLICY, 0)


class KycWitnessV2Tests(unittest.TestCase):
    def setUp(self):
        self.provider = LocalAccumulatorProvider()
        self.cbk = derive_credential_binding_key(MASTER_SEED)
        self.credential = issue_kyc_credential(
            master_seed=MASTER_SEED, credential_id=7, provider=self.provider
        )
        self.witness = self.provider.witness(TEST_ISSUER_ID, 7)
        self.scope_id = _scoped_scope_id()

    def _build(self, scope_id):
        return build_kyc_witness_v2(
            credential_binding_key=self.cbk,
            credential=self.credential,
            issuer=trusted_test_issuer(),
            witness=self.witness,
            required_level=1,
            required_attributes=[False] * 5,
            proof_context=777,
            timestamp=12345,
            current_epoch=self.provider.current_epoch(TEST_ISSUER_ID),
            scope_id=scope_id,
        )

    def test_public_input_order_pseudonym_then_scope(self):
        self.assertEqual(KYC_V2_PUBLIC_INPUT_NAMES[0], "presentation_pseudonym")
        self.assertEqual(KYC_V2_PUBLIC_INPUT_NAMES[1], "scope_id")

    def test_holder_commitment_not_public(self):
        witness = self._build(self.scope_id)
        public = kyc_public_inputs_v2(witness)
        self.assertNotIn("holder_commitment", public)
        # ...but it must survive privately (constraint still binds it).
        self.assertEqual(witness["holder_commitment"], self.credential.holder_commitment)

    def test_anonymous_pseudonym_is_zero(self):
        witness = self._build(0)
        self.assertEqual(witness["presentation_pseudonym"], 0)
        self.assertEqual(witness["scope_id"], 0)
        public = kyc_public_inputs_v2(witness)
        self.assertEqual(public["presentation_pseudonym"], field_to_hex(0))
        self.assertEqual(public["scope_id"], field_to_hex(0))

    def test_scoped_pseudonym_matches_derivation(self):
        witness = self._build(self.scope_id)
        expected = derive_presentation_pseudonym(self.cbk, self.scope_id)
        self.assertEqual(witness["presentation_pseudonym"], expected)
        self.assertEqual(witness["scope_id"], self.scope_id)
        public = kyc_public_inputs_v2(witness)
        # index 0 is the pseudonym in the extracted (ordered) mapping
        self.assertEqual(list(public)[0], "presentation_pseudonym")
        self.assertEqual(list(public)[1], "scope_id")
        self.assertEqual(public["presentation_pseudonym"], field_to_hex(expected))


class JurisdictionWitnessV2Tests(unittest.TestCase):
    def setUp(self):
        self.provider = LocalAccumulatorProvider()
        self.cbk = derive_credential_binding_key(PRED_MASTER_SEED)
        self.credential = issue_jurisdiction_credential(
            master_seed=PRED_MASTER_SEED, credential_id=31, jurisdiction_code=840, claim_type=1
        )
        self.provider.register(PRED_ISSUER_ID, self.credential.credential_id)
        self.witness = self.provider.witness(PRED_ISSUER_ID, self.credential.credential_id)
        self.scope_id = _scoped_scope_id()

    def _build(self, scope_id):
        leaf = compute_jurisdiction_leaf(840, 1)
        path_index, siblings = single_leaf_inclusion_witness()
        return build_jurisdiction_witness_v2(
            credential_binding_key=self.cbk,
            credential=self.credential,
            issuer=trusted_predicate_issuer(),
            witness=self.witness,
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
            timestamp=1_500_000,
            current_epoch=self.provider.current_epoch(PRED_ISSUER_ID),
            scope_id=scope_id,
        )

    def test_public_input_order(self):
        self.assertEqual(JURISDICTION_V2_PUBLIC_INPUT_NAMES[0], "presentation_pseudonym")
        self.assertEqual(JURISDICTION_V2_PUBLIC_INPUT_NAMES[1], "scope_id")
        self.assertNotIn("holder_commitment", JURISDICTION_V2_PUBLIC_INPUT_NAMES)

    def test_holder_commitment_private_only(self):
        witness = self._build(self.scope_id)
        self.assertNotIn("holder_commitment", jurisdiction_public_inputs_v2(witness))
        self.assertEqual(witness["holder_commitment"], self.credential.holder_commitment)

    def test_anonymous_zero_pseudonym(self):
        witness = self._build(0)
        self.assertEqual(witness["presentation_pseudonym"], 0)

    def test_scoped_pseudonym(self):
        witness = self._build(self.scope_id)
        self.assertEqual(
            witness["presentation_pseudonym"],
            derive_presentation_pseudonym(self.cbk, self.scope_id),
        )


class ProfileWitnessV2Tests(unittest.TestCase):
    def setUp(self):
        self.provider = LocalAccumulatorProvider()
        self.cbk = derive_credential_binding_key(PRED_MASTER_SEED)
        self.credential = issue_accreditation_credential(
            master_seed=PRED_MASTER_SEED, credential_id=51
        )
        self.provider.register(PRED_ISSUER_ID, self.credential.credential_id)
        self.witness = self.provider.witness(PRED_ISSUER_ID, self.credential.credential_id)
        self.scope_id = _scoped_scope_id()

    def _build(self, scope_id):
        return build_profile_witness_v2(
            predicate_type=PREDICATE_ACCREDITATION,
            credential_binding_key=self.cbk,
            credential=self.credential,
            issuer=trusted_predicate_issuer(),
            witness=self.witness,
            required_0=1,
            required_1=0,
            flag_required=False,
            set_root=0,
            path_index=0,
            siblings=[0] * 32,
            predecessor_code=0,
            predecessor_path_index=0,
            predecessor_siblings=[0] * 32,
            successor_code=0,
            successor_path_index=0,
            successor_siblings=[0] * 32,
            proof_context=888,
            timestamp=1_500_000,
            current_epoch=self.provider.current_epoch(PRED_ISSUER_ID),
            scope_id=scope_id,
        )

    def test_public_input_order_and_predicate_slot(self):
        # design §4.1: remaining_predicates v2 reorders to set_root, predicate_type
        self.assertEqual(PROFILE_V2_PUBLIC_INPUT_NAMES[0], "presentation_pseudonym")
        self.assertEqual(PROFILE_V2_PUBLIC_INPUT_NAMES[1], "scope_id")
        self.assertEqual(PROFILE_V2_PUBLIC_INPUT_NAMES[4], "set_root")
        self.assertEqual(PROFILE_V2_PUBLIC_INPUT_NAMES[5], "predicate_type")
        self.assertNotIn("holder_commitment", PROFILE_V2_PUBLIC_INPUT_NAMES)

    def test_holder_commitment_private_only(self):
        witness = self._build(self.scope_id)
        self.assertNotIn("holder_commitment", profile_public_inputs_v2(witness))
        self.assertEqual(witness["holder_commitment"], self.credential.holder_commitment)

    def test_anonymous_zero_pseudonym(self):
        self.assertEqual(self._build(0)["presentation_pseudonym"], 0)

    def test_scoped_pseudonym(self):
        witness = self._build(self.scope_id)
        self.assertEqual(
            witness["presentation_pseudonym"],
            derive_presentation_pseudonym(self.cbk, self.scope_id),
        )


class RebindWitnessV2Tests(unittest.TestCase):
    def setUp(self):
        self.old_cbk = derive_credential_binding_key(PRED_MASTER_SEED)
        self.new_cbk = new_rebind_binding_key(PRED_MASTER_SEED + 1)
        self.credential = issue_rebindable_credential(
            master_seed=PRED_MASTER_SEED, credential_id=61
        )
        self.scope_id = _scoped_scope_id()

    def _build(self, scope_id):
        return build_rebind_witness_v2(
            old_credential_binding_key=self.old_cbk,
            new_credential_binding_key=self.new_cbk,
            credential=self.credential,
            issuer_id_hash=1001,
            schema_id_hash=2002,
            proof_context=999,
            timestamp=1_500_000,
            scope_id=scope_id,
        )

    def test_public_input_order(self):
        self.assertEqual(REBIND_V2_PUBLIC_INPUT_NAMES[0], "old_presentation_pseudonym")
        self.assertEqual(REBIND_V2_PUBLIC_INPUT_NAMES[1], "new_presentation_pseudonym")
        self.assertEqual(REBIND_V2_PUBLIC_INPUT_NAMES[2], "scope_id")
        self.assertNotIn("old_holder_commitment", REBIND_V2_PUBLIC_INPUT_NAMES)
        self.assertNotIn("new_holder_commitment", REBIND_V2_PUBLIC_INPUT_NAMES)

    def test_scoped_pseudonyms_and_claim_binding(self):
        witness = self._build(self.scope_id)
        old_p = derive_presentation_pseudonym(self.old_cbk, self.scope_id)
        new_p = derive_presentation_pseudonym(self.new_cbk, self.scope_id)
        self.assertEqual(witness["old_presentation_pseudonym"], old_p)
        self.assertEqual(witness["new_presentation_pseudonym"], new_p)
        self.assertNotEqual(old_p, new_p)
        # claim_binding v2 commits to the PSEUDONYMS, not the commitments (design §4.2)
        from zkc_crypto import compute_claim_binding_3

        expected = compute_claim_binding_3(
            old_p, new_p, self.credential.credential_id, 999, 1_500_000
        )
        self.assertEqual(witness["claim_binding"], expected)

    def test_holder_commitments_private_only(self):
        witness = self._build(self.scope_id)
        public = rebind_public_inputs_v2(witness)
        self.assertNotIn("old_holder_commitment", public)
        self.assertNotIn("new_holder_commitment", public)

    def test_rebind_requires_scope(self):
        # Rebind is verifier-facing continuity: no anonymous rebind (design §4.2).
        with self.assertRaises(ConstraintViolationError):
            self._build(0)

    def test_binding_v2_successor_requires_its_exact_statement_domain(self):
        witness = self._build(self.scope_id)
        self.assertNotIn("statement_domain", witness, "frozen v2 builder output changed")
        with self.assertRaisesRegex(ConstraintViolationError, "statement domain mismatch"):
            check_rebind_v2_binding_v2_constraints(witness)

        witness["statement_domain"] = REBIND_V2_BINDING_V2_STATEMENT_DOMAIN
        check_rebind_v2_binding_v2_constraints(witness)
        witness["statement_domain"] ^= 1
        with self.assertRaisesRegex(ConstraintViolationError, "statement domain mismatch"):
            check_rebind_v2_binding_v2_constraints(witness)


class ProofTypeResolutionTests(unittest.TestCase):
    def test_linkable_resolves_to_current_family_version(self):
        self.assertEqual(
            resolve_presentation_proof_type("kyc", LINKABLE_PROFILE), "zkc:proof:kyc:v1"
        )
        self.assertEqual(
            resolve_presentation_proof_type("accreditation", LINKABLE_PROFILE),
            "zkc:proof:accreditation:v7",
        )
        # Security containment: the rebind family has no authenticated
        # statement to resolve to under any profile (spec section 4.5).
        with self.assertRaises(UnauthenticatedProofTypeError):
            resolve_presentation_proof_type("rebind", LINKABLE_PROFILE)

    def test_anonymous_and_scoped_resolve_to_current_family_version(self):
        for profile in (ANONYMOUS_PROFILE, SCOPED_PROFILE):
            self.assertEqual(
                resolve_presentation_proof_type("kyc", profile), "zkc:proof:kyc:v2"
            )
            self.assertEqual(
                resolve_presentation_proof_type("jurisdiction", profile),
                "zkc:proof:jurisdiction:v4",
            )
            self.assertEqual(
                resolve_presentation_proof_type("sanctions", profile),
                "zkc:proof:sanctions:v8",
            )
            # Security containment: no profile resolves into a rebind identity.
            with self.assertRaises(UnauthenticatedProofTypeError):
                resolve_presentation_proof_type("rebind", profile)
            self.assertEqual(
                resolve_presentation_proof_type("aggregate", profile),
                "zkc:proof:aggregate:v2",
            )

    def test_every_rebind_family_is_contained_under_every_profile(self):
        """Neither the legacy family nor the binding-v2 family may resolve: all
        four historical identities are unauthenticated (spec section 4.5)."""
        for family in ("rebind", "rebind_binding_v2"):
            for profile in (LINKABLE_PROFILE, ANONYMOUS_PROFILE, SCOPED_PROFILE):
                with self.subTest(family=family, profile=profile):
                    with self.assertRaises(UnauthenticatedProofTypeError) as ctx:
                        resolve_presentation_proof_type(family, profile)
                    self.assertEqual(ctx.exception.code, "UNAUTHENTICATED_PROOF_TYPE")
        for proof_type in sorted(UNAUTHENTICATED_REBIND_PROOF_TYPES):
            for profile in (LINKABLE_PROFILE, ANONYMOUS_PROFILE, SCOPED_PROFILE):
                with self.subTest(proof_type=proof_type, profile=profile):
                    with self.assertRaises(UnauthenticatedProofTypeError):
                        resolve_presentation_proof_type_for_request(proof_type, profile)

    def test_unknown_family_raises(self):
        with self.assertRaises(ConstraintViolationError):
            resolve_presentation_proof_type("nonsense", ANONYMOUS_PROFILE)

    def test_unknown_profile_raises(self):
        with self.assertRaises(ConstraintViolationError):
            resolve_presentation_proof_type("kyc", "zkc:presentation:bogus:v1")


if __name__ == "__main__":
    unittest.main()

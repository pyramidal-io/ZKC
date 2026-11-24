"""Canonical jurisdiction/sanctions set construction and APR binding tests.

P5 applies only to jurisdiction and sanctions.  Jurisdiction has explicit
inclusion and exclusion modes; sanctions is exclusion-only.  Source-of-funds
and tax-residency deliberately retain their P1 direct-root binding and reject
the reserved canonical-set request keys.
"""

import copy
import unittest
from unittest import mock

import _path  # noqa: F401
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from holder_fixtures import apr_verifier_identity
from holder_fixtures import verify_receipt_as_holder  # noqa: E402
from _path import REPO_ROOT

from predicate_fixtures import (
    JURISDICTION_PROOF_TYPE,
    SANCTIONS_PROOF_TYPE,
    SOURCE_PROOF_TYPE,
    TAX_PROOF_TYPE,
    TEST_ISSUER_ID,
    TEST_ISSUER_KEY_X,
    TEST_ISSUER_KEY_Y,
    issue_jurisdiction_credential,
    issue_sanctions_credential,
    issue_source_credential,
    issue_tax_credential,
    trusted_predicate_issuer,
)
from zkc_crypto import (
    CANONICAL_SENTINEL_MAX,
    CANONICAL_SENTINEL_MIN,
    CANONICAL_SET_EXCLUSION,
    CANONICAL_SET_INCLUSION,
    CANONICAL_SET_MAX_MEMBERS,
    CANONICAL_SET_MAX_REQUEST_CODES,
    CANONICAL_SET_PARAM,
    FIELD_MODULUS,
    JURISDICTION_CANONICAL_SET_PARAM,
    CanonicalCodeSet,
    CanonicalSetError,
    ProofContext,
    compute_jurisdiction_leaf,
    field_to_hex,
    raw_code_leaf,
    sign_apr,
    validate_envelope,
    verify_apr_signature,
)
from zkc_crypto.merkle import SparseMerkleAccumulator, zero_subtree_root
from zkc_crypto.presentation import ANONYMOUS_PROFILE, LINKABLE_PROFILE, SCOPED_PROFILE
from zkc_holder import (
    HolderClient,
    LocalAccumulatorProvider,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
)
from zkc_holder.errors import (
    CanonicalSetMismatchError,
    ExactMemberConsentRequiredError,
    UnauthenticatedRequestError,
)
from zkc_holder.predicates import (
    JURISDICTION_V5_CIRCUIT,
    JURISDICTION_V5_PROOF_TYPE,
    MEMBERSHIP_TYPE_EXCLUSION,
    MEMBERSHIP_TYPE_INCLUSION,
    resolve_requested_presentation_proof_type,
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
from zkc_verifier.errors import VerificationErrorCode as Code


MASTER_SEED = 4242
TIMESTAMP = 1_700_000
CONTEXT_NONCE = 777
APR_VERIFIER_PRIVATE_KEY = 0xA9701

_V1_PROOF_TYPES = (
    JURISDICTION_PROOF_TYPE,
    SANCTIONS_PROOF_TYPE,
    SOURCE_PROOF_TYPE,
    TAX_PROOF_TYPE,
)
_V2_PROOF_TYPES = tuple(
    resolve_requested_presentation_proof_type(proof_type, ANONYMOUS_PROFILE)
    for proof_type in _V1_PROOF_TYPES
)
_WITNESS_PARAMETER_KEYS = {
    "membershipPathIndex",
    "membershipSiblings",
    "pathIndex",
    "siblings",
    "predecessorCode",
    "predecessorPathIndex",
    "predecessorSiblings",
    "successorCode",
    "successorPathIndex",
    "successorSiblings",
}


def _context() -> ProofContext:
    return ProofContext.verifier_session("verifier.example", CONTEXT_NONCE, TIMESTAMP)


def _context_fixture() -> dict:
    return {
        "profile": "zkc:context:verifier-session:v1",
        "verifierId": "verifier.example",
        "sessionId": field_to_hex(CONTEXT_NONCE),
        "timestamp": TIMESTAMP,
    }


def _holder(provider) -> HolderClient:
    return HolderClient.from_seed(
        MASTER_SEED,
        PredicateRegistry.from_repo(REPO_ROOT),
        StubBackend(),
        accumulator_provider=provider,
        # This module deliberately characterizes the frozen v1/v2 canonical-set
        # surfaces.  Deprecated proof generation is available only under an
        # explicit local policy; current callers resolve to v5/v6 instead.
        accepted_review_statuses=("reviewed", "self_attested", "deprecated"),
    )


def _effective_type(proof_type: str, version: str) -> str:
    if version == "v1":
        return proof_type
    if version == "v2":
        return resolve_requested_presentation_proof_type(proof_type, ANONYMOUS_PROFILE)
    raise ValueError(f"unknown proof version {version!r}")


def _verifier() -> ZKCVerifier:
    return ZKCVerifier(
        REPO_ROOT,
        VerifierTrustPolicy(
            **apr_verifier_identity(0xA9701),
            issuers=(
                VerifierTrustedIssuer(
                    issuer_id=TEST_ISSUER_ID,
                    public_key_x=TEST_ISSUER_KEY_X,
                    public_key_y=TEST_ISSUER_KEY_Y,
                    proof_types=_V1_PROOF_TYPES + _V2_PROOF_TYPES,
                ),
            )
        ),
        StubVerifyBackend(),
    )


def _supported_case(name: str, credential_id: int):
    if name == "sanctions":
        codes = [300, 100, 200]
        canonical = CanonicalCodeSet.for_sanctions(codes)
        credential = issue_sanctions_credential(
            master_seed=MASTER_SEED,
            credential_id=credential_id,
            screening_code=150,
        )
        params = {
            "required0": 0,
            "required1": 0,
            CANONICAL_SET_PARAM: codes,
            "setRoot": canonical.root(),
        }
        return SANCTIONS_PROOF_TYPE, credential, params, canonical

    if name in ("jurisdiction-inclusion", "jurisdiction-exclusion"):
        inclusion = name.endswith("inclusion")
        subject = 840 if inclusion else 150
        codes = [840, 826, 392] if inclusion else [300, 100, 200]
        mode = CANONICAL_SET_INCLUSION if inclusion else CANONICAL_SET_EXCLUSION
        membership_type = (
            MEMBERSHIP_TYPE_INCLUSION if inclusion else MEMBERSHIP_TYPE_EXCLUSION
        )
        canonical = CanonicalCodeSet.for_jurisdiction(codes, claim_type=1, mode=mode)
        credential = issue_jurisdiction_credential(
            master_seed=MASTER_SEED,
            credential_id=credential_id,
            jurisdiction_code=subject,
            claim_type=1,
        )
        params = {
            "membershipType": membership_type,
            "requiredClaimType": 1,
            JURISDICTION_CANONICAL_SET_PARAM: codes,
            "jurisdictionSetRoot": canonical.root(),
        }
        return JURISDICTION_PROOF_TYPE, credential, params, canonical

    raise ValueError(f"unknown supported case {name!r}")


def _legacy_case(name: str, credential_id: int):
    path_index, siblings = single_leaf_inclusion_witness()
    if name == "source":
        credential = issue_source_credential(
            master_seed=MASTER_SEED, credential_id=credential_id, source_code=7
        )
        params = {
            "required0": 0,
            "required1": 0,
            "setRoot": single_leaf_set_root(7),
            "pathIndex": path_index,
            "siblings": siblings,
        }
        return SOURCE_PROOF_TYPE, credential, params
    if name == "tax":
        credential = issue_tax_credential(
            master_seed=MASTER_SEED,
            credential_id=credential_id,
            tax_code=840,
            tax_year=2026,
        )
        params = {
            "required0": 0,
            "required1": 2025,
            "setRoot": single_leaf_set_root(840),
            "pathIndex": path_index,
            "siblings": siblings,
        }
        return TAX_PROOF_TYPE, credential, params
    if name == "jurisdiction-inclusion":
        credential = issue_jurisdiction_credential(
            master_seed=MASTER_SEED,
            credential_id=credential_id,
            jurisdiction_code=840,
            claim_type=1,
        )
        params = {
            "membershipType": MEMBERSHIP_TYPE_INCLUSION,
            "requiredClaimType": 1,
            "jurisdictionSetRoot": single_leaf_set_root(
                compute_jurisdiction_leaf(840, 1)
            ),
            "membershipPathIndex": path_index,
            "membershipSiblings": siblings,
        }
        return JURISDICTION_PROOF_TYPE, credential, params
    raise ValueError(f"unknown legacy case {name!r}")


def _proof_request(proof_type, params, *, profile=LINKABLE_PROFILE) -> ProofRequest:
    return ProofRequest(
        proof_types=[proof_type],
        parameters={proof_type: copy.deepcopy(params)},
        context=_context(),
        trust_policy=TrustPolicy(issuers=(trusted_predicate_issuer(),)),
        presentation_profile=profile,
    )


def _prepare_holder(credential):
    provider = LocalAccumulatorProvider()
    client = _holder(provider)
    provider.register(TEST_ISSUER_ID, credential.credential_id)
    client.store_credential(credential)
    return client, provider


def _verification_request(proof_type, version, params, provider) -> VerificationRequest:
    effective = _effective_type(proof_type, version)
    return VerificationRequest(
        proof_types=[effective],
        parameters={effective: copy.deepcopy(params)},
        context=_context(),
        accumulator_states={
            TEST_ISSUER_ID: IssuerAccumulatorState(
                current_epoch=provider.current_epoch(TEST_ISSUER_ID),
                roots=provider.roots(TEST_ISSUER_ID),
            )
        },
    )


def _generate_v1(proof_type, credential, params, **options):
    client, provider = _prepare_holder(credential)
    envelope = generate_unauthenticated_linkable(
        client, _proof_request(proof_type, params), **options
    )
    validate_envelope(envelope)
    return envelope, provider


def _apr(proof_type, params, profile, *, nonce=0xABC123):
    presentation = {"profile": profile}
    if profile == SCOPED_PROFILE:
        presentation["scopePolicy"] = "session"
    unsigned = {
        "request": {
            "proofTypes": [proof_type],
            "parameters": {proof_type: copy.deepcopy(params)},
            "context": _context_fixture(),
            "trustPolicy": {"issuers": []},
            "presentation": presentation,
        },
        "verifierId": "verifier.example",
        "nonce": field_to_hex(nonce),
        "issuedAt": TIMESTAMP,
        "expiresAt": TIMESTAMP + 3600,
    }
    return sign_apr(unsigned, APR_VERIFIER_PRIVATE_KEY)


def _authenticated_exchange(proof_type, credential, params, version, *, nonce=0xABC123, **options):
    profile = LINKABLE_PROFILE if version == "v1" else ANONYMOUS_PROFILE
    client, provider = _prepare_holder(credential)
    request = _proof_request(proof_type, params, profile=profile)
    apr = _apr(proof_type, params, profile, nonce=nonce)
    answer = client.generate_authenticated_proof(apr, request, now=TIMESTAMP, **options)
    envelope = answer["envelope"]
    validate_envelope(envelope)
    effective = _effective_type(proof_type, version)
    if envelope["proofs"][0]["proofType"] != effective:
        raise AssertionError("authenticated exchange produced the wrong presentation proof type")
    verification_request = _verification_request(proof_type, version, params, provider)
    result = _verifier().verify_authenticated(
        apr, envelope, verification_request, now=TIMESTAMP
    )
    return {
        "apr": apr,
        "client": client,
        "envelope": envelope,
        "provider": provider,
        "receipt": answer["receipt"],
        "request": request,
        "result": result,
        "verification_request": verification_request,
    }


def _envelope_for(proof_type, credential, params, version, *, nonce=0xABC123, **options):
    if version == "v1":
        envelope, provider = _generate_v1(proof_type, credential, params, **options)
        return envelope, provider
    exchange = _authenticated_exchange(
        proof_type, credential, params, version, nonce=nonce, **options
    )
    if not exchange["result"].valid:
        raise AssertionError(exchange["result"].to_dict())
    return exchange["envelope"], exchange["provider"]


class CanonicalCodeSetBuilderTests(unittest.TestCase):
    def test_sanctions_deduplicates_sorts_brackets_and_assigns_consecutive_indices(self):
        canonical = CanonicalCodeSet.for_sanctions([408, 364, 728, 364, 192])
        self.assertEqual(canonical.mode, CANONICAL_SET_EXCLUSION)
        self.assertEqual(canonical.members, (192, 364, 408, 728))
        self.assertEqual(canonical.leaf_codes, (0, 192, 364, 408, 728, 65535))
        for index, code in enumerate(canonical.leaf_codes):
            self.assertEqual(canonical.index_of(code), index)

    def test_lookup_rejects_numeric_aliases_without_losing_sentinel_indices(self):
        canonical = CanonicalCodeSet.for_sanctions([1, 200])

        for alias in (True, False, 1.0):
            with self.subTest(alias=alias):
                self.assertFalse(canonical.contains(alias))
                self.assertNotIn(alias, canonical)
                with self.assertRaises(CanonicalSetError):
                    canonical.index_of(alias)

        self.assertEqual(canonical.index_of(CANONICAL_SENTINEL_MIN), 0)
        self.assertEqual(
            canonical.index_of(CANONICAL_SENTINEL_MAX),
            len(canonical.leaf_codes) - 1,
        )
        self.assertFalse(canonical.contains(CANONICAL_SENTINEL_MIN))
        self.assertFalse(canonical.contains(CANONICAL_SENTINEL_MAX))

    def test_roots_are_order_and_duplicate_independent(self):
        a = CanonicalCodeSet.for_sanctions([200, 100, 150, 150]).root()
        b = CanonicalCodeSet.for_sanctions([100, 150, 200]).root()
        self.assertEqual(a, b)

    def test_membership_and_non_membership_witnesses_rederive_root(self):
        canonical = CanonicalCodeSet.for_sanctions([192, 364, 408, 728])
        member = canonical.membership_witness(408)
        self.assertEqual(member.root(), canonical.root())
        self.assertEqual(len(member.siblings), 32)
        for subject in (100, 500, 900):
            with self.subTest(subject=subject):
                witness = canonical.non_membership_witness(subject)
                self.assertTrue(witness.is_adjacent)
                self.assertLess(witness.predecessor_code, subject)
                self.assertLess(subject, witness.successor_code)
                self.assertEqual(witness.predecessor_witness().root(), canonical.root())
                self.assertEqual(witness.successor_witness().root(), canonical.root())

    def test_jurisdiction_mode_is_explicit_and_changes_tree_shape_and_root(self):
        codes = [840, 826, 392]
        inclusion = CanonicalCodeSet.for_jurisdiction(
            codes, claim_type=1, mode=CANONICAL_SET_INCLUSION
        )
        exclusion = CanonicalCodeSet.for_jurisdiction(
            codes, claim_type=1, mode=CANONICAL_SET_EXCLUSION
        )
        self.assertEqual(inclusion.leaf_codes, (392, 826, 840))
        self.assertEqual(exclusion.leaf_codes, (0, 392, 826, 840, 65535))
        self.assertNotEqual(inclusion.root(), exclusion.root())
        with self.assertRaises(TypeError):
            CanonicalCodeSet.for_jurisdiction(codes, claim_type=1)
        with self.assertRaises(CanonicalSetError):
            CanonicalCodeSet.for_jurisdiction(codes, claim_type=1, mode="default")

    def test_jurisdiction_leaf_encoding_scopes_roots_to_claim_type(self):
        codes = [840, 826, 392]
        claim_1 = CanonicalCodeSet.for_jurisdiction(
            codes, claim_type=1, mode=CANONICAL_SET_INCLUSION
        )
        claim_2 = CanonicalCodeSet.for_jurisdiction(
            codes, claim_type=2, mode=CANONICAL_SET_INCLUSION
        )
        self.assertNotEqual(claim_1.root(), claim_2.root())
        self.assertEqual(
            claim_1.membership_witness(840).leaf,
            compute_jurisdiction_leaf(840, 1),
        )

    def test_empty_exclusion_is_two_sentinels_and_proves_honest_absence(self):
        for canonical in (
            CanonicalCodeSet.for_sanctions([]),
            CanonicalCodeSet.for_jurisdiction(
                [], claim_type=1, mode=CANONICAL_SET_EXCLUSION
            ),
        ):
            with self.subTest(canonical=repr(canonical)):
                self.assertEqual(canonical.members, ())
                self.assertEqual(canonical.leaf_codes, (0, 65535))
                witness = canonical.non_membership_witness(150)
                self.assertEqual(witness.predecessor_code, 0)
                self.assertEqual(witness.successor_code, 65535)
                self.assertTrue(witness.is_adjacent)
                self.assertEqual(witness.predecessor_witness().root(), canonical.root())
                self.assertEqual(witness.successor_witness().root(), canonical.root())

    def test_empty_inclusion_is_zero_subtree_root_and_has_no_membership_witness(self):
        canonical = CanonicalCodeSet.for_jurisdiction(
            [], claim_type=1, mode=CANONICAL_SET_INCLUSION
        )
        self.assertEqual(canonical.members, ())
        self.assertEqual(canonical.leaf_codes, ())
        self.assertEqual(canonical.root(), zero_subtree_root(32))
        with self.assertRaises(CanonicalSetError):
            canonical.membership_witness(840)
        with self.assertRaises(CanonicalSetError):
            canonical.non_membership_witness(840)

    def test_padding_uses_zero_subtrees_not_literal_zero_siblings(self):
        canonical = CanonicalCodeSet.for_sanctions([7])
        self.assertNotEqual(canonical.root(), single_leaf_set_root(raw_code_leaf(7)))

    def test_sentinel_bracket_is_required_for_edge_non_membership(self):
        members = [100, 150, 200]
        sentinel_less = SparseMerkleAccumulator([raw_code_leaf(code) for code in members])
        canonical = CanonicalCodeSet.for_sanctions(members)
        self.assertNotEqual(sentinel_less.root(), canonical.root())
        self.assertEqual(canonical.non_membership_witness(50).predecessor_code, 0)
        self.assertEqual(canonical.non_membership_witness(250).successor_code, 65535)

    def test_outer_member_witness_is_refused(self):
        canonical = CanonicalCodeSet.for_sanctions([100, 150, 200])
        with self.assertRaises(CanonicalSetError):
            canonical.non_membership_witness(150)
        predecessor = canonical.membership_witness(100)
        successor = canonical.membership_witness(200)
        self.assertEqual(predecessor.root(), canonical.root())
        self.assertEqual(successor.root(), canonical.root())
        self.assertNotEqual(successor.path_index, predecessor.path_index + 1)

    def test_invalid_member_domains_and_input_cap_fail_closed(self):
        for bad in (0, 65535, 65536, -1, True, "7"):
            with self.subTest(bad=bad), self.assertRaises(CanonicalSetError):
                CanonicalCodeSet.for_sanctions([bad])
        with self.assertRaises(CanonicalSetError):
            CanonicalCodeSet.for_sanctions([1] * (CANONICAL_SET_MAX_MEMBERS + 1))
        for non_array in ((1, 2), {1, 2}, iter([1, 2]), {"1": 2}, "1,2"):
            with self.subTest(non_array=type(non_array).__name__), self.assertRaises(
                CanonicalSetError
            ):
                CanonicalCodeSet.for_sanctions(non_array)


class CanonicalSetIntegrationTests(unittest.TestCase):
    def test_supported_modes_derive_and_compare_for_v1_and_v2(self):
        case_id = 100
        for name in ("sanctions", "jurisdiction-inclusion", "jurisdiction-exclusion"):
            for version in ("v1", "v2"):
                case_id += 1
                with self.subTest(name=name, version=version):
                    proof_type, credential, params, _canonical = _supported_case(name, case_id)
                    if name == "jurisdiction-inclusion":
                        params.update(membershipPathIndex=31, membershipSiblings=[7] * 32)
                    envelope, provider = _envelope_for(
                        proof_type, credential, params, version, nonce=0xC000 + case_id
                    )
                    result = _verifier().verify(
                        envelope,
                        _verification_request(proof_type, version, params, provider),
                    )
                    self.assertTrue(result.valid, result.to_dict())
                    self.assertEqual(result.warning_codes(), [])

    def test_verifier_rejects_proof_against_a_different_coherent_derived_root(self):
        case_id = 200
        for name in ("sanctions", "jurisdiction-inclusion", "jurisdiction-exclusion"):
            for version in ("v1", "v2"):
                case_id += 1
                with self.subTest(name=name, version=version):
                    proof_type, credential, params, _canonical = _supported_case(name, case_id)
                    envelope, provider = _envelope_for(
                        proof_type, credential, params, version, nonce=0xC100 + case_id
                    )
                    other = copy.deepcopy(params)
                    if proof_type == SANCTIONS_PROOF_TYPE:
                        other[CANONICAL_SET_PARAM].append(444)
                        other["setRoot"] = CanonicalCodeSet.for_sanctions(
                            other[CANONICAL_SET_PARAM]
                        ).root()
                    else:
                        other[JURISDICTION_CANONICAL_SET_PARAM].append(444)
                        mode = (
                            CANONICAL_SET_INCLUSION
                            if other["membershipType"] == MEMBERSHIP_TYPE_INCLUSION
                            else CANONICAL_SET_EXCLUSION
                        )
                        other["jurisdictionSetRoot"] = CanonicalCodeSet.for_jurisdiction(
                            other[JURISDICTION_CANONICAL_SET_PARAM], 1, mode
                        ).root()
                    result = _verifier().verify(
                        envelope,
                        _verification_request(proof_type, version, other, provider),
                    )
                    self.assertFalse(result.valid)
                    self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes())

    def test_codes_and_root_disagreement_rejected_by_holder_and_verifier(self):
        case_id = 300
        for name in ("sanctions", "jurisdiction-inclusion", "jurisdiction-exclusion"):
            case_id += 1
            with self.subTest(name=name):
                proof_type, credential, params, _canonical = _supported_case(name, case_id)
                envelope, provider = _generate_v1(proof_type, credential, params)
                contradictory = copy.deepcopy(params)
                root_key = (
                    "setRoot" if proof_type == SANCTIONS_PROOF_TYPE else "jurisdictionSetRoot"
                )
                contradictory[root_key] += 1
                client, _unused = _prepare_holder(credential)
                with self.assertRaises(CanonicalSetMismatchError):
                    generate_unauthenticated_linkable(client, _proof_request(proof_type, contradictory))
                result = _verifier().verify(
                    envelope,
                    _verification_request(proof_type, "v1", contradictory, provider),
                )
                self.assertFalse(result.valid)
                self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes())

    def test_root_is_mandatory_and_strict_field_integer(self):
        proof_type, credential, params, _canonical = _supported_case("sanctions", 401)
        envelope, provider = _generate_v1(proof_type, credential, params)
        root_cases = (None, False, "0x01", -1, FIELD_MODULUS)
        for root in root_cases:
            with self.subTest(root=root):
                bad = copy.deepcopy(params)
                if root is None:
                    bad.pop("setRoot")
                else:
                    bad["setRoot"] = root
                client, _unused = _prepare_holder(credential)
                with self.assertRaises(CanonicalSetMismatchError):
                    generate_unauthenticated_linkable(client, _proof_request(proof_type, bad))
                result = _verifier().verify(
                    envelope,
                    _verification_request(proof_type, "v1", bad, provider),
                )
                self.assertFalse(result.valid)
                self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes())

    def test_exclusion_rejects_bare_root_fallback(self):
        case_id = 500
        for name in ("sanctions", "jurisdiction-exclusion"):
            for version in ("v1", "v2"):
                case_id += 1
                with self.subTest(name=name, version=version):
                    proof_type, credential, params, _canonical = _supported_case(name, case_id)
                    envelope, provider = _envelope_for(
                        proof_type, credential, params, version, nonce=0xC200 + case_id
                    )
                    bare = copy.deepcopy(params)
                    bare.pop(
                        CANONICAL_SET_PARAM
                        if proof_type == SANCTIONS_PROOF_TYPE
                        else JURISDICTION_CANONICAL_SET_PARAM
                    )
                    client, _unused = _prepare_holder(credential)
                    with self.assertRaises(CanonicalSetMismatchError):
                        generate_unauthenticated_linkable(client, _proof_request(proof_type, bare))
                    result = _verifier().verify(
                        envelope,
                        _verification_request(proof_type, version, bare, provider),
                    )
                    self.assertFalse(result.valid)
                    self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes())

    def test_jurisdiction_inclusion_bare_root_verifies_with_holder_consent(self):
        for version, credential_id in (("v1", 601), ("v2", 602)):
            with self.subTest(version=version):
                proof_type, credential, params = _legacy_case(
                    "jurisdiction-inclusion", credential_id
                )
                envelope, provider = _envelope_for(
                    proof_type, credential, params, version, nonce=0xC300 + credential_id,
                    exact_member_consents={proof_type: True},
                )
                result = _verifier().verify(
                    envelope,
                    _verification_request(proof_type, version, params, provider),
                )
                self.assertTrue(result.valid, result.to_dict())
                self.assertEqual(result.warning_codes(), [])

    def test_fixed_inclusion_paths_refuse_before_reading_credentials(self):
        for name in ("jurisdiction-inclusion", "source", "tax"):
            with self.subTest(name=name):
                proof_type, _credential, params = _legacy_case(name, 650)
                for key in ("membershipPathIndex", "membershipSiblings", "pathIndex", "siblings"):
                    params.pop(key, None)
                client = _holder(None)
                request = _proof_request(proof_type, params, profile=ANONYMOUS_PROFILE)
                apr = _apr(proof_type, params, ANONYMOUS_PROFILE)
                for consent in ({}, {proof_type: 1}, {"another-proof-type": True}):
                    with self.assertRaises(ExactMemberConsentRequiredError):
                        client.generate_proof(
                            request, allow_unauthenticated=True,
                            exact_member_consents=consent,
                        )
                    with self.assertRaises(ExactMemberConsentRequiredError):
                        client.generate_authenticated_proof(
                            apr, request, now=TIMESTAMP,
                            exact_member_consents=consent,
                        )
                self.assertEqual(client.override_log, [])

    def test_exact_member_opt_in_is_recorded_without_witness_data(self):
        proof_type, credential, params = _legacy_case("jurisdiction-inclusion", 651)
        exchange = _authenticated_exchange(
            proof_type, credential, params, "v2", exact_member_consents={proof_type: True},
        )
        self.assertEqual(exchange["client"].override_log, [{
            "proofType": proof_type,
            "kind": "EXACT_MEMBER",
            "reason": "holder consented to exact-code disclosure using a fixed inclusion path",
            "predicateId": "",
        }])

    def test_scoped_jurisdiction_v5_requires_consent_or_derives_its_path(self):
        _, credential, params, _ = _supported_case("jurisdiction-inclusion", 652)
        client, _ = _prepare_holder(credential)
        proof_type = JURISDICTION_V5_PROOF_TYPE
        params.update(membershipPathIndex=31, membershipSiblings=[7] * 32)
        bare = dict(params)
        bare.pop(JURISDICTION_CANONICAL_SET_PARAM)
        with self.assertRaises(ExactMemberConsentRequiredError):
            client.generate_authenticated_proof(
                _apr(proof_type, bare, SCOPED_PROFILE),
                _proof_request(proof_type, bare, profile=SCOPED_PROFILE),
                now=TIMESTAMP, allow_opaque=True,
            )
        self.assertEqual(client.override_log, [])
        request = _proof_request(proof_type, params, profile=SCOPED_PROFILE)
        request.trust_policy = TrustPolicy(issuers=(trusted_predicate_issuer((proof_type,)),))
        result = client.generate_authenticated_proof(
            _apr(proof_type, params, SCOPED_PROFILE),
            request,
            now=TIMESTAMP, allow_opaque=True,
        )
        self.assertEqual(result["envelope"]["proofs"][0]["proofType"], proof_type)
        self.assertNotIn("EXACT_MEMBER", [record["kind"] for record in client.override_log])

    def test_empty_exclusion_sets_prove_honest_non_membership_end_to_end(self):
        case_id = 700
        for name in ("sanctions", "jurisdiction-exclusion"):
            for version in ("v1", "v2"):
                case_id += 1
                with self.subTest(name=name, version=version):
                    proof_type, credential, params, _canonical = _supported_case(name, case_id)
                    codes_key = (
                        CANONICAL_SET_PARAM
                        if proof_type == SANCTIONS_PROOF_TYPE
                        else JURISDICTION_CANONICAL_SET_PARAM
                    )
                    root_key = (
                        "setRoot"
                        if proof_type == SANCTIONS_PROOF_TYPE
                        else "jurisdictionSetRoot"
                    )
                    params[codes_key] = []
                    canonical = (
                        CanonicalCodeSet.for_sanctions([])
                        if proof_type == SANCTIONS_PROOF_TYPE
                        else CanonicalCodeSet.for_jurisdiction(
                            [], 1, CANONICAL_SET_EXCLUSION
                        )
                    )
                    params[root_key] = canonical.root()
                    envelope, provider = _envelope_for(
                        proof_type, credential, params, version, nonce=0xC400 + case_id
                    )
                    result = _verifier().verify(
                        envelope,
                        _verification_request(proof_type, version, params, provider),
                    )
                    self.assertTrue(result.valid, result.to_dict())

    def test_empty_inclusion_set_fails_cleanly_when_holder_needs_membership(self):
        proof_type, credential, params, _canonical = _supported_case(
            "jurisdiction-inclusion", 801
        )
        params[JURISDICTION_CANONICAL_SET_PARAM] = []
        params["jurisdictionSetRoot"] = CanonicalCodeSet.for_jurisdiction(
            [], 1, CANONICAL_SET_INCLUSION
        ).root()
        client, _provider = _prepare_holder(credential)
        with self.assertRaises(CanonicalSetMismatchError):
            generate_unauthenticated_linkable(client, _proof_request(proof_type, params))

    def test_miskeyed_malformed_and_oversized_sets_fail_closed(self):
        proof_type, credential, params, _canonical = _supported_case("sanctions", 901)
        envelope, provider = _generate_v1(proof_type, credential, params)
        cases = []
        miskeyed = copy.deepcopy(params)
        miskeyed[JURISDICTION_CANONICAL_SET_PARAM] = [100, 200]
        cases.append(miskeyed)
        malformed = copy.deepcopy(params)
        malformed[CANONICAL_SET_PARAM] = "100,200"
        cases.append(malformed)
        tuple_alias = copy.deepcopy(params)
        tuple_alias[CANONICAL_SET_PARAM] = tuple(params[CANONICAL_SET_PARAM])
        cases.append(tuple_alias)
        non_integer = copy.deepcopy(params)
        non_integer[CANONICAL_SET_PARAM] = [100, True, 200]
        cases.append(non_integer)
        sentinel = copy.deepcopy(params)
        sentinel[CANONICAL_SET_PARAM] = [0, 100, 200]
        cases.append(sentinel)
        oversized = copy.deepcopy(params)
        oversized[CANONICAL_SET_PARAM] = [1] * (
            CANONICAL_SET_MAX_REQUEST_CODES + 1
        )
        cases.append(oversized)
        for bad in cases:
            with self.subTest(keys=tuple(bad)):
                client, _unused = _prepare_holder(credential)
                with self.assertRaises(CanonicalSetMismatchError):
                    generate_unauthenticated_linkable(client, _proof_request(proof_type, bad))
                result = _verifier().verify(
                    envelope,
                    _verification_request(proof_type, "v1", bad, provider),
                )
                self.assertFalse(result.valid)
                self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes())

    def test_holder_rejects_non_object_parameter_block(self):
        proof_type, credential, _params, _canonical = _supported_case("sanctions", 902)
        client, _provider = _prepare_holder(credential)
        request = ProofRequest(
            proof_types=[proof_type],
            parameters={proof_type: []},
            context=_context(),
            trust_policy=TrustPolicy(issuers=(trusted_predicate_issuer(),)),
        )
        with self.assertRaisesRegex(CanonicalSetMismatchError, "JSON object"):
            generate_unauthenticated_linkable(client, request)

    def test_online_request_code_budget_accepts_limit_and_rejects_next_entry(self):
        proof_type, credential, params, _canonical = _supported_case("sanctions", 904)
        at_limit = [100] * CANONICAL_SET_MAX_REQUEST_CODES
        params[CANONICAL_SET_PARAM] = at_limit
        params["setRoot"] = CanonicalCodeSet.for_sanctions(at_limit).root()
        envelope, provider = _generate_v1(proof_type, credential, params)
        accepted = _verifier().verify(
            envelope,
            _verification_request(proof_type, "v1", params, provider),
        )
        self.assertTrue(accepted.valid, accepted.to_dict())

        oversized = copy.deepcopy(params)
        oversized[CANONICAL_SET_PARAM] = at_limit + [100]
        client, _unused = _prepare_holder(credential)
        with self.assertRaises(CanonicalSetMismatchError):
            generate_unauthenticated_linkable(client, _proof_request(proof_type, oversized))
        rejected = _verifier().verify(
            envelope,
            _verification_request(proof_type, "v1", oversized, provider),
        )
        self.assertFalse(rejected.valid)
        self.assertIn(Code.REQUIREMENTS_NOT_MET, rejected.codes())

    def test_holder_refuses_a_credential_code_inside_an_exclusion_set(self):
        proof_type, credential, params, _canonical = _supported_case("sanctions", 903)
        params[CANONICAL_SET_PARAM] = [100, 150, 300]
        params["setRoot"] = CanonicalCodeSet.for_sanctions(
            params[CANONICAL_SET_PARAM]
        ).root()
        client, _provider = _prepare_holder(credential)
        with self.assertRaises(CanonicalSetMismatchError) as caught:
            generate_unauthenticated_linkable(client, _proof_request(proof_type, params))
        self.assertNotIn("150", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)


class ScopedJurisdictionV5ExclusionTests(unittest.TestCase):
    def setUp(self):
        _, self.credential, self.params, self.canonical = _supported_case(
            "jurisdiction-exclusion", 14001
        )
        self.holder, _ = _prepare_holder(self.credential)
        self.params.update(
            predecessorCode=CANONICAL_SENTINEL_MIN,
            predecessorPathIndex=0,
            predecessorSiblings=[0] * 32,
            successorCode=CANONICAL_SENTINEL_MAX,
            successorPathIndex=0,
            successorSiblings=[0] * 32,
        )

    def _answer(self):
        proof_type = JURISDICTION_V5_PROOF_TYPE
        request = _proof_request(proof_type, self.params, profile=SCOPED_PROFILE)
        request.trust_policy = TrustPolicy(issuers=(trusted_predicate_issuer((proof_type,)),))
        return self.holder.generate_authenticated_proof(
            _apr(proof_type, self.params, SCOPED_PROFILE),
            request,
            now=TIMESTAMP,
            allow_opaque=True,
        )

    def test_replaces_supplied_neighbours_with_canonical_witness(self):
        expected = self.canonical.non_membership_witness(
            self.credential.claims["jurisdictionCode"]
        )
        backend = self.holder._backend
        with mock.patch.object(backend, "prove", wraps=backend.prove) as prove:
            envelope = self._answer()["envelope"]

        prove.assert_called_once()
        circuit, witness = prove.call_args.args
        self.assertEqual(circuit, JURISDICTION_V5_CIRCUIT)
        self.assertEqual(envelope["proofs"][0]["proofType"], JURISDICTION_V5_PROOF_TYPE)
        self.assertEqual(envelope["presentationBinding"]["profile"], SCOPED_PROFILE)
        self.assertEqual(witness["predecessor_code"], expected.predecessor_code)
        self.assertEqual(witness["predecessor_path_index"], expected.predecessor_path_index)
        self.assertEqual(witness["predecessor_siblings"], list(expected.predecessor_siblings))
        self.assertEqual(witness["successor_code"], expected.successor_code)
        self.assertEqual(witness["successor_path_index"], expected.successor_path_index)
        self.assertEqual(witness["successor_siblings"], list(expected.successor_siblings))

    def test_refuses_root_only_exclusion_before_proving(self):
        self.params.pop(JURISDICTION_CANONICAL_SET_PARAM)
        with mock.patch.object(self.holder._backend, "prove") as prove:
            with self.assertRaisesRegex(CanonicalSetMismatchError, "jurisdictionCanonicalSet"):
                self._answer()
            prove.assert_not_called()


class AuthenticatedCanonicalSetTests(unittest.TestCase):
    def test_signed_apr_carries_codes_and_matching_root_for_v1_and_v2(self):
        case_id = 1000
        for name in ("sanctions", "jurisdiction-inclusion", "jurisdiction-exclusion"):
            for version in ("v1", "v2"):
                case_id += 1
                with self.subTest(name=name, version=version):
                    proof_type, credential, params, canonical = _supported_case(name, case_id)
                    exchange = _authenticated_exchange(
                        proof_type,
                        credential,
                        params,
                        version,
                        nonce=0xD000 + case_id,
                    )
                    self.assertTrue(verify_apr_signature(exchange["apr"]))
                    self.assertTrue(exchange["result"].valid, exchange["result"].to_dict())
                    self.assertEqual(exchange["result"].warning_codes(), [])
                    self.assertEqual(
                        verify_receipt_as_holder(exchange["receipt"]),
                        {
                            "aprValid": True,
                            "holderValid": True,
                            "holderKeyAnchored": True,
                            "contextBound": True,
                            "valid": True,
                        },
                    )
                    signed_params = exchange["apr"]["request"]["parameters"][proof_type]
                    codes_key = (
                        CANONICAL_SET_PARAM
                        if proof_type == SANCTIONS_PROOF_TYPE
                        else JURISDICTION_CANONICAL_SET_PARAM
                    )
                    root_key = (
                        "setRoot"
                        if proof_type == SANCTIONS_PROOF_TYPE
                        else "jurisdictionSetRoot"
                    )
                    public_root = (
                        "set_root"
                        if proof_type == SANCTIONS_PROOF_TYPE
                        else "jurisdiction_set_root"
                    )
                    self.assertEqual(signed_params[codes_key], params[codes_key])
                    self.assertEqual(signed_params[root_key], canonical.root())
                    self.assertFalse(_WITNESS_PARAMETER_KEYS.intersection(signed_params))
                    self.assertEqual(
                        exchange["envelope"]["proofs"][0]["publicInputs"][public_root],
                        field_to_hex(canonical.root()),
                    )

    def test_post_signature_root_tampering_is_unauthenticated(self):
        proof_type, credential, params, _canonical = _supported_case("sanctions", 1101)
        client, _provider = _prepare_holder(credential)
        request = _proof_request(proof_type, params, profile=LINKABLE_PROFILE)
        apr = _apr(proof_type, params, LINKABLE_PROFILE, nonce=0xD101)
        apr["request"]["parameters"][proof_type]["setRoot"] += 1
        self.assertFalse(verify_apr_signature(apr))
        with self.assertRaises(UnauthenticatedRequestError):
            client.generate_authenticated_proof(apr, request, now=TIMESTAMP)

    def test_validly_signed_inconsistent_root_is_rejected_before_proving(self):
        case_id = 1200
        for name in ("sanctions", "jurisdiction-inclusion", "jurisdiction-exclusion"):
            case_id += 1
            with self.subTest(name=name):
                proof_type, credential, params, _canonical = _supported_case(name, case_id)
                root_key = (
                    "setRoot" if proof_type == SANCTIONS_PROOF_TYPE else "jurisdictionSetRoot"
                )
                params[root_key] += 1
                client, _provider = _prepare_holder(credential)
                request = _proof_request(proof_type, params, profile=LINKABLE_PROFILE)
                apr = _apr(proof_type, params, LINKABLE_PROFILE, nonce=0xD200 + case_id)
                self.assertTrue(verify_apr_signature(apr))
                with self.assertRaises(CanonicalSetMismatchError):
                    client.generate_authenticated_proof(apr, request, now=TIMESTAMP)

    def test_verifier_rejects_coherent_request_not_covered_by_apr(self):
        proof_type, credential, params, _canonical = _supported_case("sanctions", 1301)
        exchange = _authenticated_exchange(
            proof_type, credential, params, "v2", nonce=0xD301
        )
        other = copy.deepcopy(params)
        other[CANONICAL_SET_PARAM].append(444)
        other["setRoot"] = CanonicalCodeSet.for_sanctions(
            other[CANONICAL_SET_PARAM]
        ).root()
        request = _verification_request(
            proof_type, "v2", other, exchange["provider"]
        )
        result = _verifier().verify_authenticated(
            exchange["apr"], exchange["envelope"], request, now=TIMESTAMP
        )
        self.assertEqual(result.codes(), [Code.UNSIGNED_REQUEST], result.to_dict())


class UnsupportedCanonicalSetTests(unittest.TestCase):
    def test_source_and_tax_direct_root_path_verifies_with_holder_consent(self):
        case_id = 1400
        for name in ("source", "tax"):
            for version in ("v1", "v2"):
                case_id += 1
                with self.subTest(name=name, version=version):
                    proof_type, credential, params = _legacy_case(name, case_id)
                    envelope, provider = _envelope_for(
                        proof_type, credential, params, version, nonce=0xE000 + case_id,
                        exact_member_consents={proof_type: True},
                    )
                    result = _verifier().verify(
                        envelope,
                        _verification_request(proof_type, version, params, provider),
                    )
                    self.assertTrue(result.valid, result.to_dict())
                    self.assertEqual(result.warning_codes(), [])

    def test_source_and_tax_reserved_keys_are_rejected_by_holder(self):
        case_id = 1500
        for name in ("source", "tax"):
            for reserved_key in (CANONICAL_SET_PARAM, JURISDICTION_CANONICAL_SET_PARAM):
                case_id += 1
                with self.subTest(name=name, reserved_key=reserved_key):
                    proof_type, credential, params = _legacy_case(name, case_id)
                    params[reserved_key] = [7]
                    client, _provider = _prepare_holder(credential)
                    with self.assertRaises(CanonicalSetMismatchError):
                        generate_unauthenticated_linkable(client, _proof_request(proof_type, params))

    def test_source_and_tax_reserved_keys_are_rejected_by_verifier_v1_and_v2(self):
        case_id = 1600
        for name in ("source", "tax"):
            for version in ("v1", "v2"):
                case_id += 1
                proof_type, credential, params = _legacy_case(name, case_id)
                envelope, provider = _envelope_for(
                    proof_type, credential, params, version, nonce=0xE100 + case_id,
                    exact_member_consents={proof_type: True},
                )
                for reserved_key in (
                    CANONICAL_SET_PARAM,
                    JURISDICTION_CANONICAL_SET_PARAM,
                ):
                    with self.subTest(
                        name=name, version=version, reserved_key=reserved_key
                    ):
                        bad = copy.deepcopy(params)
                        bad[reserved_key] = [7]
                        result = _verifier().verify(
                            envelope,
                            _verification_request(
                                proof_type, version, bad, provider
                            ),
                        )
                        self.assertFalse(result.valid)
                        self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes())


if __name__ == "__main__":
    unittest.main()

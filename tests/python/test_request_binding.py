"""Adversarial tests for the verifier's per-predicate request-binding registry
(spec §6.2 step 4e).

Before the request-binding registry existed, the verifier's per-predicate
requirement check ran ONLY for KYC, selective-disclosure, and rebind (v1/v2).
Five families — jurisdiction, accreditation, source-of-funds, tax-residency,
sanctions-clearance — verified cryptographically and then bound to NOTHING:

  * P1: a valid jurisdiction INCLUSION proof satisfied a request demanding
    EXCLUSION (and vice versa); any jurisdictionSetRoot/requiredClaimType the
    prover liked was accepted.
  * P2: one verification key covers all four `zkc_remaining_predicates`
    meanings (accreditation/source/tax/sanctions), so a proof of any one type
    relabelled as any other type verified as that other type's clearance.

This file proves both classes of bug are closed and characterizes the immutable
legacy response to ``flagRequired``: positive requests fail closed, while the
current v7/v8 profile circuits bind the exact boolean in their claim transcript.

Every rejection case asserts a SPECIFIC ``VerificationErrorCode`` — never
merely ``not result.valid`` — per the acceptance criteria. Every rejection
case also has an honest-control sibling proving the fixture itself is capable
of ACCEPTING when nothing is tampered with.
"""

import copy
import datetime
import json
import unittest
from unittest import mock

import _path  # noqa: F401  (sys.path side effect)
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from holder_fixtures import apr_verifier_identity
from _path import REPO_ROOT
from _inventory import (
    IS_PUBLIC_SNAPSHOT,
    UNPUBLISHED_REQUEST_PROOF_TYPES,
    expected_public_paths,
)

from holder_fixtures import (
    TEST_ISSUER_ID,
    TEST_ISSUER_KEY_X,
    TEST_ISSUER_KEY_Y,
    issue_kyc_credential,
    trusted_test_issuer,
)
from predicate_fixtures import (
    ACCREDITATION_PROOF_TYPE,
    JURISDICTION_PROOF_TYPE,
    SANCTIONS_PROOF_TYPE,
    SOURCE_PROOF_TYPE,
    TAX_PROOF_TYPE,
    issue_accreditation_credential,
    issue_jurisdiction_credential,
    issue_sanctions_credential,
    issue_source_credential,
    issue_tax_credential,
    trusted_predicate_issuer,
)

from zkc_crypto import (
    CANONICAL_SET_EXCLUSION,
    FIELD_MODULUS,
    CanonicalCodeSet,
    ProofContext,
    compute_jurisdiction_leaf,
    field_to_hex,
    sign_apr,
)
from zkc_crypto.ecdsa_secp256k1 import N, public_key_bytes
from zkc_crypto.presentation import ANONYMOUS_PROFILE, LINKABLE_PROFILE, SCOPED_PROFILE
from zkc_crypto.stub import stub_proof_payload
from zkc_holder import (
    HolderClient,
    LocalAccumulatorProvider,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
)
from zkc_holder.client import _Presentation
from zkc_holder.predicates import (
    MEMBERSHIP_TYPE_EXCLUSION,
    MEMBERSHIP_TYPE_INCLUSION,
    single_leaf_inclusion_witness,
    single_leaf_set_root,
)
from zkc_verifier import (
    IssuerAccumulatorState,
    StubVerifyBackend,
    VerificationErrorCode as Code,
    VerificationRequest,
    VerificationResult,
    VerifierTrustPolicy,
    ZKCVerifier,
)
from zkc_verifier import TrustedIssuer as VerifierTrustedIssuer
from zkc_verifier.verifier import _REQUEST_BINDINGS
from zkc_registry.predicate_v2 import request_extension

MASTER_SEED = 4242
TIMESTAMP = 1_700_000
CONTEXT_NONCE = 555
SCOPE_ID = 0xFEED  # fixed scope for every scoped-profile envelope in this file

KYC_PROOF_TYPE = "zkc:proof:kyc:v1"
KYC_V2_PROOF_TYPE = "zkc:proof:kyc:v2"

# Safe presentation siblings. Explicit historical v1--v6 compatibility
# coverage lives apart from this default request-binding matrix.
JURISDICTION_V4_PROOF_TYPE = "zkc:proof:jurisdiction:v4"
ACCREDITATION_V8_PROOF_TYPE = "zkc:proof:accreditation:v8"
SOURCE_V8_PROOF_TYPE = "zkc:proof:source:v8"
TAX_V8_PROOF_TYPE = "zkc:proof:tax:v8"
SANCTIONS_V8_PROOF_TYPE = "zkc:proof:sanctions:v8"
JURISDICTION_LEGACY_V1_PROOF_TYPE = "zkc:proof:jurisdiction:v1"
JURISDICTION_LEGACY_V2_PROOF_TYPE = "zkc:proof:jurisdiction:v2"

# Safe proof types by family, plus the circuit used by each envelope ABI
# (needed to re-stamp a mutated stub proof).  The v1/v2 keys below name the
# envelope shape, not the deprecated predicate-proof identities.
_V3_TYPE = {
    "jurisdiction": JURISDICTION_PROOF_TYPE,
    "accreditation": ACCREDITATION_PROOF_TYPE,
    "source": SOURCE_PROOF_TYPE,
    "tax": TAX_PROOF_TYPE,
    "sanctions": SANCTIONS_PROOF_TYPE,
}
_V4_TYPE = {
    "jurisdiction": JURISDICTION_V4_PROOF_TYPE,
    "accreditation": ACCREDITATION_V8_PROOF_TYPE,
    "source": SOURCE_V8_PROOF_TYPE,
    "tax": TAX_V8_PROOF_TYPE,
    "sanctions": SANCTIONS_V8_PROOF_TYPE,
}
_CIRCUIT = {
    "v1": {
        "jurisdiction": "zkc_jurisdiction_v3",
        "accreditation": "zkc_remaining_predicates_v7",
        "source": "zkc_remaining_predicates_v7",
        "tax": "zkc_remaining_predicates_v7",
        "sanctions": "zkc_remaining_predicates_v7",
    },
    "v2": {
        "jurisdiction": "zkc_jurisdiction_v4",
        "accreditation": "zkc_remaining_predicates_v8",
        "source": "zkc_remaining_predicates_v8",
        "tax": "zkc_remaining_predicates_v8",
        "sanctions": "zkc_remaining_predicates_v8",
    },
}
REMAINING_FAMILIES = ("accreditation", "source", "tax", "sanctions")
ALL_FAMILIES = ("jurisdiction", *REMAINING_FAMILIES)

# All ten predicate proof types this file exercises, trusted up front so no
# individual test needs to think about issuer trust.
_ALL_PREDICATE_TYPES = tuple(_V3_TYPE.values()) + tuple(_V4_TYPE.values())


def _context() -> ProofContext:
    return ProofContext.verifier_session("verifier.example", CONTEXT_NONCE, TIMESTAMP)


def _rfc3339(ts: int) -> str:
    return (
        datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _make_holder(provider) -> HolderClient:
    return HolderClient.from_seed(
        MASTER_SEED,
        PredicateRegistry.from_repo(REPO_ROOT),
        StubBackend(),
        accumulator_provider=provider,
        # This module characterizes immutable v1/v2 behavior explicitly. New
        # generation uses v7/v8; historical generation requires opt-in, and
        # the draft v2 presentation siblings need the Safeguard 4 opt-in.
        accepted_review_statuses=("reviewed", "self_attested", "draft", "deprecated"),
    )


# The explicit verifier opt-in for historical (deprecated) identities: the
# statuses a verifier accepts, plus "deprecated" (spec 7.2a).
_HISTORICAL_OPT_IN = ("reviewed", "self_attested", "draft", "deprecated")


def _verifier(proof_types=_ALL_PREDICATE_TYPES, **policy_kwargs) -> ZKCVerifier:
    return ZKCVerifier(
        REPO_ROOT,
        VerifierTrustPolicy(
            **apr_verifier_identity(),
            issuers=(
                VerifierTrustedIssuer(
                    issuer_id=TEST_ISSUER_ID,
                    public_key_x=TEST_ISSUER_KEY_X,
                    public_key_y=TEST_ISSUER_KEY_Y,
                    proof_types=tuple(proof_types),
                ),
            ),
            **policy_kwargs,
        ),
        StubVerifyBackend(),
    )


# ---------------------------------------------------------------------------
# Per-family honest fixtures: (credential, parameters). Parameter keys/shapes
# mirror tests/python/test_predicate_proofs.py exactly (the shape oracle).
# ---------------------------------------------------------------------------


def _jurisdiction_case(credential_id, *, jurisdiction_code=840, claim_type=1):
    credential = issue_jurisdiction_credential(
        master_seed=MASTER_SEED,
        credential_id=credential_id,
        jurisdiction_code=jurisdiction_code,
        claim_type=claim_type,
    )
    leaf = compute_jurisdiction_leaf(jurisdiction_code, claim_type)
    path_index, siblings = single_leaf_inclusion_witness()
    params = {
        "membershipType": MEMBERSHIP_TYPE_INCLUSION,
        "requiredClaimType": claim_type,
        "jurisdictionSetRoot": single_leaf_set_root(leaf),
        "membershipPathIndex": path_index,
        "membershipSiblings": siblings,
    }
    return credential, params


def _accreditation_case(credential_id):
    credential = issue_accreditation_credential(
        master_seed=MASTER_SEED, credential_id=credential_id, accreditation_level=3, institutional=True
    )
    # Legacy v1/v2 honest-control requests use the safe false value. Dedicated
    # tests below exercise positive fail-closed behavior; v3/v4 true controls
    # live in test_flag_required_binding.py.
    params = {"required0": 2, "required1": 0, "flagRequired": False}
    return credential, params


def _source_case(credential_id):
    credential = issue_source_credential(master_seed=MASTER_SEED, credential_id=credential_id, source_code=7)
    path_index, siblings = single_leaf_inclusion_witness()
    params = {
        "required0": 0,
        "required1": 0,
        "setRoot": single_leaf_set_root(7),
        "pathIndex": path_index,
        "siblings": siblings,
    }
    return credential, params


def _tax_case(credential_id):
    credential = issue_tax_credential(
        master_seed=MASTER_SEED, credential_id=credential_id, tax_code=840, tax_year=2026
    )
    path_index, siblings = single_leaf_inclusion_witness()
    params = {
        "required0": 0,
        "required1": 2025,
        "setRoot": single_leaf_set_root(840),
        "pathIndex": path_index,
        "siblings": siblings,
    }
    return credential, params


def _sanctions_case(credential_id):
    credential = issue_sanctions_credential(
        master_seed=MASTER_SEED, credential_id=credential_id, screening_code=150
    )
    # Sanctions is always an exclusion predicate.  P5 requires the signed
    # request to carry the canonical blocked set as well as its derived root;
    # HolderClient then derives the adjacent-neighbour witness from this set.
    blocked_codes = [100, 200]
    params = {
        "required0": 0,
        "required1": 0,
        "canonicalSet": blocked_codes,
        "setRoot": CanonicalCodeSet.for_sanctions(blocked_codes).root(),
    }
    return credential, params


_CASE_BUILDERS = {
    "jurisdiction": _jurisdiction_case,
    "accreditation": _accreditation_case,
    "source": _source_case,
    "tax": _tax_case,
    "sanctions": _sanctions_case,
}


def _build(
    family: str,
    version: str,
    *,
    credential_id: int,
    profile: str = None,
    lag: int = 0,
    requested_type: str = None,
):
    """Generate one honest envelope + matching VerificationRequest.

    ``version`` is the v1/v2 envelope ABI. The predicate proof types remain
    jurisdiction v3/v4 and remaining-predicate profile v7/v8 throughout; for
    the v2 envelope ABI, ``profile`` selects ANONYMOUS_PROFILE or SCOPED_PROFILE
    (defaults to anonymous). ``lag``
    declares a verifier "current epoch view" that is ``lag`` epochs AHEAD of
    the accumulator witness's own epoch (the accumulator-lag window, capped
    at MAX_EPOCH_LAG=10 both holder- and verifier-side) — the non-revocation
    witness itself is refreshed against the (unchanged) registration epoch,
    while ``request.current_epochs`` declares the verifier's later view, so
    the proof's own ``accumulator_epoch``/``current_epoch`` public inputs
    genuinely differ by ``lag``. Returns (envelope, verification_request,
    proof_type, params, provider) so callers can mutate/re-verify.
    """
    credential, params = _CASE_BUILDERS[family](credential_id)
    provider = LocalAccumulatorProvider()
    holder = _make_holder(provider)
    provider.register(TEST_ISSUER_ID, credential.credential_id)
    holder.store_credential(credential)
    registration_epoch = provider.current_epoch(TEST_ISSUER_ID)
    current_epoch_view = registration_epoch + lag

    linkable_type = requested_type or _V3_TYPE[family]
    issuer = trusted_predicate_issuer((requested_type,)) if requested_type else trusted_predicate_issuer()
    request = ProofRequest(
        proof_types=[linkable_type],
        parameters={linkable_type: params},
        context=_context(),
        trust_policy=TrustPolicy(issuers=(issuer,)),
        current_epochs={TEST_ISSUER_ID: current_epoch_view},
    )

    exact_member_consents = {linkable_type: True} if family in ("jurisdiction", "source", "tax") else {}
    if version == "v1":
        envelope = generate_unauthenticated_linkable(
            holder, request, exact_member_consents=exact_member_consents,
        )
        proof_type = linkable_type
    else:
        effective_profile = profile or ANONYMOUS_PROFILE
        presentation = _Presentation(effective_profile, SCOPE_ID if effective_profile == SCOPED_PROFILE else 0)
        envelope = holder._generate_envelope(
            request, presentation, exact_member_consents=exact_member_consents,
        )
        proof_type = requested_type or _V4_TYPE[family]

    verification_request = VerificationRequest(
        proof_types=[proof_type],
        parameters={proof_type: copy.deepcopy(params)},
        context=_context(),
        accumulator_states={
            TEST_ISSUER_ID: IssuerAccumulatorState(
                current_epoch=current_epoch_view, roots=provider.roots(TEST_ISSUER_ID)
            )
        },
    )
    return envelope, verification_request, proof_type, params, provider


def _reseal(entry: dict, circuit: str) -> dict:
    """Re-stamp a mutated stub proof entry so the backend digest still
    'verifies' — models a forged proof whose public inputs the circuit would
    reject but whose envelope the verifier must catch on its own. Mirrors
    tests/python/test_verifier_profiles.py:reseal_proof_entry."""
    entry["proof"] = stub_proof_payload(circuit, entry["publicInputs"])
    return entry


def _jurisdiction_exclusion_overrides(params: dict) -> dict:
    """Build a structurally valid P5 exclusion request from an inclusion one.

    The resulting request is intentionally paired with an inclusion proof in
    the membership-type substitution tests below.  Supplying the canonical
    blocked set and its matching root keeps those tests focused on that type
    mismatch rather than the P5 fail-closed missing-set rejection.
    """
    blocked_codes = [800]
    claim_type = params["requiredClaimType"]
    return {
        "membershipType": MEMBERSHIP_TYPE_EXCLUSION,
        "jurisdictionCanonicalSet": blocked_codes,
        "jurisdictionSetRoot": CanonicalCodeSet.for_jurisdiction(
            blocked_codes, claim_type, CANONICAL_SET_EXCLUSION
        ).root(),
    }


# ===========================================================================
# 1. HONEST CONTROL — fully matching proof + request ACCEPTS. Per profile
#    (anonymous/scoped) and across the accumulator lag window.
# ===========================================================================


class HonestControlTests(unittest.TestCase):
    def test_v1_all_families_accept(self):
        verifier = _verifier()
        for family in ALL_FAMILIES:
            with self.subTest(family=family):
                # Deterministic id (not hash(), which is PYTHONHASHSEED-salted
                # and would make this fixture's identity differ run to run).
                envelope, request, proof_type, _params, _provider = _build(
                    family, "v1", credential_id=100 + ALL_FAMILIES.index(family)
                )
                result = verifier.verify(envelope, request)
                self.assertEqual(result.codes(), [], result.to_dict())
                self.assertTrue(result.valid)

    def test_v2_all_families_accept_per_profile(self):
        verifier = _verifier()
        profiles = (ANONYMOUS_PROFILE, SCOPED_PROFILE)
        for family in ALL_FAMILIES:
            for profile in profiles:
                with self.subTest(family=family, profile=profile):
                    # Deterministic id -- see test_v1_all_families_accept.
                    envelope, request, proof_type, _params, _provider = _build(
                        family,
                        "v2",
                        credential_id=200
                        + ALL_FAMILIES.index(family) * len(profiles)
                        + profiles.index(profile),
                        profile=profile,
                    )
                    result = verifier.verify(envelope, request)
                    self.assertEqual(result.codes(), [], result.to_dict())
                    self.assertTrue(result.valid)

    def test_v1_accepts_across_accumulator_lag_window(self):
        # The accumulator witness is refreshed at registration epoch, while
        # the verifier's declared current-epoch view runs `lag` epochs ahead
        # of it (0..MAX_EPOCH_LAG=10) -- honest proofs must verify at every
        # point in that window, not merely at lag 0.
        verifier = _verifier()
        lags = (0, 5, 10)
        for family in ALL_FAMILIES:
            for lag in lags:
                with self.subTest(family=family, lag=lag):
                    # Deterministic id -- see test_v1_all_families_accept.
                    envelope, request, proof_type, _params, _provider = _build(
                        family,
                        "v1",
                        credential_id=300
                        + ALL_FAMILIES.index(family) * len(lags)
                        + lags.index(lag),
                        lag=lag,
                    )
                    result = verifier.verify(envelope, request)
                    self.assertEqual(result.codes(), [], result.to_dict())
                    self.assertTrue(result.valid)

    def test_v1_rejects_lag_beyond_verifiers_tightened_policy_bound(self):
        # The protocol-wide bound (MAX_EPOCH_LAG=10) is a hard cap both sides
        # enforce structurally, so lag=11 cannot even be constructed. A
        # verifier policy MAY only TIGHTEN the bound (never loosen it), so an
        # honest proof at the full protocol lag (10) must still be refused by
        # a verifier whose own policy caps it lower (5) -- proving the window
        # test above wasn't vacuously accepting everything.
        envelope, request, proof_type, _params, _provider = _build(
            "jurisdiction", "v1", credential_id=777, lag=10
        )
        tight_verifier = _verifier(max_epoch_lag=5)
        result = tight_verifier.verify(envelope, request)
        self.assertEqual(result.codes(), [Code.STALE_ACCUMULATOR], result.to_dict())
        self.assertFalse(result.valid)

    def test_v2_accepts_across_accumulator_lag_window(self):
        verifier = _verifier()
        profiles = (ANONYMOUS_PROFILE, SCOPED_PROFILE)
        lags = (0, 5, 10)
        for profile in profiles:
            for lag in lags:
                with self.subTest(profile=profile, lag=lag):
                    # Deterministic id -- see test_v1_all_families_accept.
                    envelope, request, proof_type, _params, _provider = _build(
                        "jurisdiction",
                        "v2",
                        credential_id=400
                        + profiles.index(profile) * len(lags)
                        + lags.index(lag),
                        profile=profile,
                        lag=lag,
                    )
                    result = verifier.verify(envelope, request)
                    self.assertEqual(result.codes(), [], result.to_dict())
                    self.assertTrue(result.valid)


# ===========================================================================
# 2 & 3. Jurisdiction substitution: inclusion-vs-exclusion (the reproduced
#    A1/A2 bug), wrong set root, wrong required claim type.
# ===========================================================================


class JurisdictionSubstitutionTests(unittest.TestCase):
    def _mismatched_request(self, request, proof_type, **overrides):
        mismatched = copy.deepcopy(request)
        mismatched.parameters[proof_type].update(overrides)
        return mismatched

    def test_v1_inclusion_proof_rejected_against_exclusion_request(self):
        verifier = _verifier()
        envelope, request, proof_type, _params, _provider = _build(
            "jurisdiction", "v1", credential_id=11
        )
        # Sanity: the honest pairing accepts.
        self.assertTrue(verifier.verify(envelope, request).valid)

        attack_request = self._mismatched_request(
            request,
            proof_type,
            **_jurisdiction_exclusion_overrides(request.parameters[proof_type]),
        )
        result = verifier.verify(envelope, attack_request)
        self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes())
        self.assertFalse(result.valid)
        # Require an error naming membership_type to exercise its direct
        # comparison; the v2 sibling explains why an unnamed rejection is insufficient.
        messages = [error.message for error in result.errors]
        self.assertTrue(
            any("membership_type" in message for message in messages),
            f"expected a rejection naming membership_type, got: {messages}",
        )

    def test_v2_inclusion_proof_rejected_against_exclusion_request(self):
        verifier = _verifier()
        profiles = (ANONYMOUS_PROFILE, SCOPED_PROFILE)
        for profile in profiles:
            with self.subTest(profile=profile):
                # Deterministic id -- see HonestControlTests.test_v1_all_families_accept.
                envelope, request, proof_type, _params, _provider = _build(
                    "jurisdiction", "v2", credential_id=1100 + profiles.index(profile), profile=profile
                )
                attack_request = self._mismatched_request(
                    request,
                    proof_type,
                    **_jurisdiction_exclusion_overrides(request.parameters[proof_type]),
                )
                result = verifier.verify(envelope, attack_request)
                self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes())
                self.assertFalse(result.valid)
                # Require an error naming membership_type, not merely any
                # REQUIREMENTS_NOT_MET result. Without the direct comparison,
                # claim-binding recomputation still rejects this request through
                # its jurisdiction_set_root, membershipType, or requiredClaimType
                # slots, so an unnamed rejection would not exercise this check.
                messages = [error.message for error in result.errors]
                self.assertTrue(
                    any("membership_type" in message for message in messages),
                    f"expected a rejection naming membership_type, got: {messages}",
                )

    def test_v1_wrong_jurisdiction_set_root_rejected(self):
        verifier = _verifier()
        envelope, request, proof_type, params, _provider = _build(
            "jurisdiction", "v1", credential_id=12
        )
        other_root = (params["jurisdictionSetRoot"] + 1) % (2**254)
        attack_request = self._mismatched_request(
            request, proof_type, jurisdictionSetRoot=other_root
        )
        result = verifier.verify(envelope, attack_request)
        self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes())
        self.assertFalse(result.valid)
        # Require an error naming jurisdiction_set_root to exercise its direct
        # comparison, as the remaining-predicate tests do for set_root.
        messages = [error.message for error in result.errors]
        self.assertTrue(
            any("jurisdiction_set_root" in message for message in messages),
            f"expected a rejection naming jurisdiction_set_root, got: {messages}",
        )

    def test_v1_wrong_required_claim_type_rejected(self):
        verifier = _verifier()
        envelope, request, proof_type, _params, _provider = _build(
            "jurisdiction", "v1", credential_id=13
        )
        attack_request = self._mismatched_request(request, proof_type, requiredClaimType=2)
        result = verifier.verify(envelope, attack_request)
        self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes())
        self.assertFalse(result.valid)

    def test_v2_wrong_jurisdiction_set_root_rejected(self):
        verifier = _verifier()
        envelope, request, proof_type, params, _provider = _build(
            "jurisdiction", "v2", credential_id=1200
        )
        other_root = (params["jurisdictionSetRoot"] + 1) % (2**254)
        attack_request = self._mismatched_request(
            request, proof_type, jurisdictionSetRoot=other_root
        )
        result = verifier.verify(envelope, attack_request)
        self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes())
        self.assertFalse(result.valid)
        # Require an error naming jurisdiction_set_root to exercise its direct comparison.
        messages = [error.message for error in result.errors]
        self.assertTrue(
            any("jurisdiction_set_root" in message for message in messages),
            f"expected a rejection naming jurisdiction_set_root, got: {messages}",
        )

    def test_v2_wrong_required_claim_type_rejected(self):
        verifier = _verifier()
        envelope, request, proof_type, _params, _provider = _build(
            "jurisdiction", "v2", credential_id=1300
        )
        attack_request = self._mismatched_request(request, proof_type, requiredClaimType=2)
        result = verifier.verify(envelope, attack_request)
        self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes())
        self.assertFalse(result.valid)


# ===========================================================================
# 4. Remaining-predicates set_root substitution: set_root is OUTSIDE the
#    claim_binding preimage, so it must be caught by the DIRECT comparison,
#    not incidentally by the claim-binding recompute. Forge the proof's own
#    set_root (prover-chosen root) and assert the claim binding check still
#    PASSES while the direct set_root compare is what fires.
# ===========================================================================


class SetRootDirectBindingTests(unittest.TestCase):
    def _forge_set_root(self, envelope, circuit, new_root_hex):
        forged = copy.deepcopy(envelope)
        entry = forged["proofs"][0]
        entry["publicInputs"]["set_root"] = new_root_hex
        self._reseal_entry(entry, circuit)
        return forged

    def _reseal_entry(self, entry, circuit):
        return _reseal(entry, circuit)

    def test_v1_source_prover_chosen_set_root_rejected_directly(self):
        verifier = _verifier()
        envelope, request, proof_type, params, _provider = _build("source", "v1", credential_id=14)
        forged_root = field_to_hex((params["setRoot"] + 1) % (2**254))
        forged = self._forge_set_root(envelope, _CIRCUIT["v1"]["source"], forged_root)

        result = verifier.verify(forged, request)
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
        self.assertFalse(result.valid)
        # Prove it is the DIRECT set_root comparison that fired, not the
        # claim-binding recompute (which does not cover set_root at all).
        self.assertIn("set_root", result.errors[0].message)
        self.assertNotIn("claim binding", result.errors[0].message)

    def test_v1_tax_prover_chosen_set_root_rejected_directly(self):
        verifier = _verifier()
        envelope, request, proof_type, params, _provider = _build("tax", "v1", credential_id=15)
        forged_root = field_to_hex((params["setRoot"] + 1) % (2**254))
        forged = self._forge_set_root(envelope, _CIRCUIT["v1"]["tax"], forged_root)

        result = verifier.verify(forged, request)
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
        self.assertFalse(result.valid)
        self.assertIn("set_root", result.errors[0].message)

    def test_v1_sanctions_prover_chosen_set_root_rejected_directly(self):
        verifier = _verifier()
        envelope, request, proof_type, params, _provider = _build(
            "sanctions", "v1", credential_id=16
        )
        forged_root = field_to_hex((params["setRoot"] + 1) % (2**254))
        forged = self._forge_set_root(envelope, _CIRCUIT["v1"]["sanctions"], forged_root)

        result = verifier.verify(forged, request)
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
        self.assertFalse(result.valid)
        self.assertIn("set_root", result.errors[0].message)

    def test_v2_source_prover_chosen_set_root_rejected_directly(self):
        verifier = _verifier()
        envelope, request, proof_type, params, _provider = _build(
            "source", "v2", credential_id=1400
        )
        forged_root = field_to_hex((params["setRoot"] + 1) % (2**254))
        forged = self._forge_set_root(envelope, _CIRCUIT["v2"]["source"], forged_root)

        result = verifier.verify(forged, request)
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
        self.assertFalse(result.valid)
        self.assertIn("set_root", result.errors[0].message)

    def test_v1_accreditation_omitted_set_root_rejected(self):
        # Accreditation's honest expected set_root is 0 (mirrors the holder
        # default). A prover supplying a non-zero set root must still be
        # caught by the direct comparison even though accreditation's own
        # request never asked for a real set.
        verifier = _verifier()
        envelope, request, proof_type, _params, _provider = _build(
            "accreditation", "v1", credential_id=17
        )
        forged = self._forge_set_root(
            envelope, _CIRCUIT["v1"]["accreditation"], field_to_hex(999999)
        )
        result = verifier.verify(forged, request)
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
        self.assertFalse(result.valid)
        self.assertIn("set_root", result.errors[0].message)

    def test_v1_accreditation_nonzero_request_set_root_rejected(self):
        # The converse of the previous test: it is the REQUEST, not the
        # proof, that asks for a non-zero setRoot. Accreditation's set_root
        # is a _FixedValue(0, "setRoot") -- the circuit never constrains this
        # input on this branch (main.nr:194-197), so a request asking for
        # anything else is asking for something the predicate structurally
        # cannot express. This exercises _resolve_binding_source's own
        # _FixedValue rejection, a distinct code path from the direct
        # public-input comparison the previous test exercises (that one
        # fires only once the FixedValue's OWN check already passed).
        verifier = _verifier()
        envelope, request, proof_type, _params, _provider = _build(
            "accreditation", "v1", credential_id=18
        )
        attack_request = copy.deepcopy(request)
        attack_request.parameters[proof_type]["setRoot"] = 999999
        result = verifier.verify(envelope, attack_request)
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
        self.assertFalse(result.valid)
        self.assertIn("setRoot", result.errors[0].message)
        self.assertIn("must be 0", result.errors[0].message)

    def test_v2_accreditation_nonzero_request_set_root_rejected(self):
        verifier = _verifier()
        envelope, request, proof_type, _params, _provider = _build(
            "accreditation", "v2", credential_id=1801
        )
        attack_request = copy.deepcopy(request)
        attack_request.parameters[proof_type]["setRoot"] = 123456
        result = verifier.verify(envelope, attack_request)
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
        self.assertFalse(result.valid)
        self.assertIn("setRoot", result.errors[0].message)
        self.assertIn("must be 0", result.errors[0].message)


# ===========================================================================
# 4b. Request-bound required slots. Claim-binding recomputation checks
#    ``required_0`` and ``required_1`` for the remaining-predicate families.
#    The verifier compares ``set_root`` and ``predicate_type`` directly.
#
#    Accreditation compares the minimum level in ``required_0`` and tax
#    compares the minimum year in ``required_1`` against the private witness.
#    Source and sanctions use zero in both slots. The test below checks that
#    those zeros still contribute to the claim binding.
#
#    Each rejection case pairs with an accepted request for the same proof
#    to confirm the fixture is valid.
# ===========================================================================


class RequiredValueClaimBindingTests(unittest.TestCase):
    def _mismatched_request(self, request, proof_type, **overrides):
        mismatched = copy.deepcopy(request)
        mismatched.parameters[proof_type].update(overrides)
        return mismatched

    def _assert_claim_binding_rejection(self, result, proof_type):
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
        self.assertFalse(result.valid)
        # Attribute the rejection to the claim-binding recompute specifically
        # (not merely "some REQUIREMENTS_NOT_MET fired") -- this is the exact
        # half SURVIVOR 1's mutation neuters for these four families.
        messages = [error.message for error in result.errors]
        self.assertTrue(
            any("claim binding" in message for message in messages),
            f"expected a rejection naming the claim binding, got: {messages}",
        )

    def test_v1_accreditation_wrong_required_level_rejected(self):
        # Honest proof attests a minimum level of 2 (_accreditation_case's
        # required0=2, accreditation_level=3 satisfies it). The verifier then
        # demands required0=3 -- a DIFFERENT minimum than the one the proof's
        # claim binding actually commits to.
        verifier = _verifier()
        envelope, request, proof_type, params, _provider = _build(
            "accreditation", "v1", credential_id=1950
        )
        self.assertEqual(params["required0"], 2)
        # Positive control: the matching (honest) required value accepts.
        self.assertTrue(verifier.verify(envelope, request).valid)

        attack_request = self._mismatched_request(request, proof_type, required0=3)
        result = verifier.verify(envelope, attack_request)
        self._assert_claim_binding_rejection(result, proof_type)

    def test_v2_accreditation_wrong_required_level_rejected(self):
        verifier = _verifier()
        envelope, request, proof_type, params, _provider = _build(
            "accreditation", "v2", credential_id=1951
        )
        self.assertEqual(params["required0"], 2)
        self.assertTrue(verifier.verify(envelope, request).valid)

        attack_request = self._mismatched_request(request, proof_type, required0=3)
        result = verifier.verify(envelope, attack_request)
        self._assert_claim_binding_rejection(result, proof_type)

    def test_v1_tax_wrong_required_year_rejected(self):
        # Honest proof attests a minimum tax year of 2025 (_tax_case's
        # required1=2025, tax_year=2026 satisfies it). The verifier then
        # demands required1=2026 -- a DIFFERENT minimum than the one the
        # proof's claim binding actually commits to.
        verifier = _verifier()
        envelope, request, proof_type, params, _provider = _build(
            "tax", "v1", credential_id=1952
        )
        self.assertEqual(params["required1"], 2025)
        self.assertTrue(verifier.verify(envelope, request).valid)

        attack_request = self._mismatched_request(request, proof_type, required1=2026)
        result = verifier.verify(envelope, attack_request)
        self._assert_claim_binding_rejection(result, proof_type)

    def test_v2_tax_wrong_required_year_rejected(self):
        verifier = _verifier()
        envelope, request, proof_type, params, _provider = _build(
            "tax", "v2", credential_id=1953
        )
        self.assertEqual(params["required1"], 2025)
        self.assertTrue(verifier.verify(envelope, request).valid)

        attack_request = self._mismatched_request(request, proof_type, required1=2026)
        result = verifier.verify(envelope, attack_request)
        self._assert_claim_binding_rejection(result, proof_type)

    def test_v1_source_wrong_required_value_rejected_binding_only(self):
        # BINDING-ONLY coverage, labelled honestly: source's required0/
        # required1 are both circuit-dead (the circuit never compares either
        # against a witness on this branch), so this is NOT a security
        # property the predicate enforces -- unlike the accreditation/tax
        # cases above. It still pins that the claim-binding recompute covers
        # required_0 for every zkc_remaining_predicates family, not only the
        # two with a live slot.
        verifier = _verifier()
        envelope, request, proof_type, params, _provider = _build(
            "source", "v1", credential_id=1954
        )
        self.assertEqual(params["required0"], 0)
        self.assertTrue(verifier.verify(envelope, request).valid)

        attack_request = self._mismatched_request(request, proof_type, required0=1)
        result = verifier.verify(envelope, attack_request)
        self._assert_claim_binding_rejection(result, proof_type)


# ===========================================================================
# 4b. CANONICAL NUMERIC DOMAIN — Poseidon/Noir field inputs are residues, but
#     verifier request parameters are exact JSON values.  An untouched proof
#     for x MUST NOT satisfy a request for x + FIELD_MODULUS merely because the
#     transcript reduces both to the same BN254 element.  Exercise the shared
#     resolver for every generic predicate family and both envelope versions.
# ===========================================================================


class CanonicalNumericParameterTests(unittest.TestCase):
    _PARAMETER_BY_FAMILY = {
        "jurisdiction": "requiredClaimType",
        "accreditation": "required0",
        "source": "required0",
        "tax": "required1",
        "sanctions": "required0",
    }

    def test_modulus_shifted_parameters_rejected_for_every_family_and_version(self):
        verifier = _verifier()
        credential_id = 1970
        for version in ("v1", "v2"):
            for family, parameter in self._PARAMETER_BY_FAMILY.items():
                with self.subTest(version=version, family=family, parameter=parameter):
                    envelope, request, proof_type, _params, _provider = _build(
                        family, version, credential_id=credential_id
                    )
                    credential_id += 1
                    self.assertTrue(verifier.verify(envelope, request).valid)

                    shifted = copy.deepcopy(request)
                    shifted.parameters[proof_type][parameter] += FIELD_MODULUS
                    result = verifier.verify(envelope, shifted)
                    self.assertEqual(
                        result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict()
                    )
                    self.assertFalse(result.valid)


# ===========================================================================
# 5. P2 CROSS-PREDICATE SUBSTITUTION MATRIX — every ordered pair (a, b) of
#    {accreditation, source, tax, sanctions}, a != b: relabel a valid proof
#    of type a as type b (no re-stamp needed: the digest covers only
#    (circuit, publicInputs), and all four types in a version share ONE
#    circuit). 12 ordered pairs for v1, 12 for v2.
# ===========================================================================


class CrossPredicateSubstitutionMatrixTests(unittest.TestCase):
    def _pairs(self):
        return [(a, b) for a in REMAINING_FAMILIES for b in REMAINING_FAMILIES if a != b]

    def _relabelled_envelope(self, envelope, new_proof_type):
        forged = copy.deepcopy(envelope)
        forged["proofs"][0]["proofType"] = new_proof_type
        return forged

    def test_v1_cross_predicate_substitution_matrix(self):
        verifier = _verifier()
        envelopes = {}
        requests = {}
        for family in REMAINING_FAMILIES:
            envelope, request, proof_type, _params, _provider = _build(
                family, "v1", credential_id=500 + REMAINING_FAMILIES.index(family)
            )
            envelopes[family] = envelope
            requests[family] = request
            # Sanity: each family's own honest pairing accepts.
            self.assertTrue(verifier.verify(envelope, request).valid, family)

        for a, b in self._pairs():
            with self.subTest(a=a, b=b):
                relabelled = self._relabelled_envelope(envelopes[a], _V3_TYPE[b])
                result = verifier.verify(relabelled, requests[b])
                self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes(), result.to_dict())
                self.assertFalse(result.valid)
                # Require a predicate_type-specific error. Each fixture carries
                # a distinct set_root, so its direct comparison alone would
                # satisfy a bare REQUIREMENTS_NOT_MET assertion and conceal a
                # broken predicate_type binding.
                messages = [error.message for error in result.errors]
                self.assertTrue(
                    any("predicate_type" in message for message in messages),
                    f"[{a}->{b}] expected a rejection naming predicate_type, got: {messages}",
                )

    def test_v2_cross_predicate_substitution_matrix(self):
        verifier = _verifier()
        envelopes = {}
        requests = {}
        for family in REMAINING_FAMILIES:
            envelope, request, proof_type, _params, _provider = _build(
                family, "v2", credential_id=600 + REMAINING_FAMILIES.index(family)
            )
            envelopes[family] = envelope
            requests[family] = request
            self.assertTrue(verifier.verify(envelope, request).valid, family)

        for a, b in self._pairs():
            with self.subTest(a=a, b=b):
                relabelled = self._relabelled_envelope(envelopes[a], _V4_TYPE[b])
                result = verifier.verify(relabelled, requests[b])
                self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes(), result.to_dict())
                self.assertFalse(result.valid)
                # Require a predicate_type-specific error; see the v1 sibling
                # test for why a bare rejection is insufficient.
                messages = [error.message for error in result.errors]
                self.assertTrue(
                    any("predicate_type" in message for message in messages),
                    f"[{a}->{b}] expected a rejection naming predicate_type, got: {messages}",
                )


# ===========================================================================
# 5b. PREDICATE_TYPE ISOLATED as the sole load-bearing rejection.
#
#    The matrix above proves the substitution is rejected, but every fixture
#    there also carries its own distinct set_root, so a direct comparison on
#    set_root alone is already sufficient to satisfy "REQUIREMENTS_NOT_MET is
#    somewhere in codes()" -- predicate_type is never actually exercised as
#    the thing standing between accept and reject.
#
#    This is the concrete attack a mutation (predicate_type sourced from the
#    proof's OWN public input instead of the P4 sidecar keyed by the
#    REQUESTED proof type) leaves open: build an honest SOURCE proof, forge
#    ONLY its set_root public input to equal the SANCTIONS request's own
#    setRoot (source's and sanctions' required0/required1 already agree --
#    both default to 0), relabel its proofType to sanctions, and verify
#    against the sanctions request. Nothing but predicate_type is left to
#    reject it.
# ===========================================================================


class PredicateTypeIsolationTests(unittest.TestCase):
    def _relabel_and_align_set_root(self, envelope, new_proof_type, circuit, new_root_hex):
        forged = copy.deepcopy(envelope)
        entry = forged["proofs"][0]
        entry["proofType"] = new_proof_type
        entry["publicInputs"]["set_root"] = new_root_hex
        _reseal(entry, circuit)
        return forged

    def test_v1_source_relabelled_as_sanctions_with_aligned_set_root_isolates_predicate_type(self):
        verifier = _verifier()
        source_envelope, _source_request, _source_type, source_params, _p1 = _build(
            "source", "v1", credential_id=901
        )
        _sanctions_envelope, sanctions_request, sanctions_type, sanctions_params, _p2 = _build(
            "sanctions", "v1", credential_id=902
        )
        # Sanity: source's own required0/required1 already agree with
        # sanctions' (both default to 0), so aligning set_root neutralises
        # every check EXCEPT predicate_type.
        self.assertEqual(source_params["required0"], sanctions_params["required0"])
        self.assertEqual(source_params["required1"], sanctions_params["required1"])
        self.assertNotEqual(source_params["setRoot"], sanctions_params["setRoot"])

        attack = self._relabel_and_align_set_root(
            source_envelope,
            sanctions_type,
            _CIRCUIT["v1"]["source"],
            field_to_hex(sanctions_params["setRoot"]),
        )
        # Sanity: relabelling+realigning alone (without the isolation this
        # test targets) would otherwise be indistinguishable from an honest
        # sanctions proof by set_root/required0/required1 alone.
        result = verifier.verify(attack, sanctions_request)
        self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes(), result.to_dict())
        self.assertFalse(result.valid)
        messages = [error.message for error in result.errors]
        self.assertTrue(
            any("predicate_type" in message for message in messages),
            f"ATTACK not caught by predicate_type: {messages}",
        )

    def test_v2_source_relabelled_as_sanctions_with_aligned_set_root_isolates_predicate_type(self):
        verifier = _verifier()
        source_envelope, _source_request, _source_type, source_params, _p1 = _build(
            "source", "v2", credential_id=1401
        )
        _sanctions_envelope, sanctions_request, sanctions_type, sanctions_params, _p2 = _build(
            "sanctions", "v2", credential_id=1402
        )
        self.assertEqual(source_params["required0"], sanctions_params["required0"])
        self.assertEqual(source_params["required1"], sanctions_params["required1"])
        self.assertNotEqual(source_params["setRoot"], sanctions_params["setRoot"])

        attack = self._relabel_and_align_set_root(
            source_envelope,
            sanctions_type,
            _CIRCUIT["v2"]["source"],
            field_to_hex(sanctions_params["setRoot"]),
        )
        result = verifier.verify(attack, sanctions_request)
        self.assertIn(Code.REQUIREMENTS_NOT_MET, result.codes(), result.to_dict())
        self.assertFalse(result.valid)
        messages = [error.message for error in result.errors]
        self.assertTrue(
            any("predicate_type" in message for message in messages),
            f"ATTACK not caught by predicate_type: {messages}",
        )


# ===========================================================================
# 5c. PUBLIC-INPUT REPRESENTATION — u8 selectors are exact JSON integers.
#     Field encoding maps "3" and 3.9 to the same field element as 3. Resealing
#     the stub proof
#     models a cryptographically valid proof over those byte-identical inputs;
#     the named binding boundary must still reject the malformed JSON shape.
# ===========================================================================


class PublicComparisonTypeStrictnessTests(unittest.TestCase):
    def test_predicate_type_aliases_rejected_for_v1_and_v2(self):
        verifier = _verifier()
        credential_id = 1490
        for version in ("v1", "v2"):
            for alias in ("3", 3.9):
                with self.subTest(version=version, alias=alias):
                    envelope, request, _proof_type, _params, _provider = _build(
                        "tax", version, credential_id=credential_id
                    )
                    credential_id += 1
                    attack = copy.deepcopy(envelope)
                    entry = attack["proofs"][0]
                    entry["publicInputs"]["predicate_type"] = alias
                    _reseal(entry, _CIRCUIT[version]["tax"])

                    result = verifier.verify(attack, request)
                    self.assertEqual(result.codes(), [Code.MALFORMED_PROOF], result.to_dict())
                    self.assertFalse(result.valid)


# ===========================================================================
# 6. Missing/empty parameters for each of the five predicate families ->
#    REQUIREMENTS_NOT_MET (fail-closed posture: no default acceptance).
# ===========================================================================


#    The first fail-closed parameter diagnostic each family's binding contract
#    reaches. Canonical-root derivation runs before the legacy
#    direct comparison for jurisdiction/sanctions: jurisdiction must resolve
#    membershipType to select a tree mode, while sanctions reports its missing
#    APR root before it can require/derive canonicalSet. The other families
#    retain their original mandatory-parameter order.
_FIRST_PARAMETER_FAILURE_BY_FAMILY = {
    "jurisdiction": "lacks required parameter 'membershipType'",
    "accreditation": "lacks required parameter 'required0'",
    "source": "lacks required parameter 'setRoot'",
    "tax": "lacks required parameter 'required1'",
    "sanctions": "lacks APR-distributed root parameter 'setRoot'",
}


class MissingParametersTests(unittest.TestCase):
    def test_v1_empty_parameters_rejected(self):
        verifier = _verifier()
        for family in ALL_FAMILIES:
            with self.subTest(family=family):
                envelope, request, proof_type, _params, _provider = _build(
                    family, "v1", credential_id=700 + ALL_FAMILIES.index(family)
                )
                empty_request = copy.deepcopy(request)
                empty_request.parameters[proof_type] = {}
                result = verifier.verify(envelope, empty_request)
                self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
                self.assertFalse(result.valid)
                # Assert the mandatory-parameter message specifically (not
                # merely that some REQUIREMENTS_NOT_MET happened to
                # fire). A mutation turning "_MANDATORY: raise" into
                # "_MANDATORY: return 0" never produces this message again --
                # for accreditation/source/sanctions the single-entry
                # assertion above would otherwise still pass, coincidentally,
                # via an unrelated claim-binding or set_root mismatch (their
                # honest fixtures happen to carry a non-zero/non-default
                # value there), silently losing MANDATORY enforcement.
                expected_failure = _FIRST_PARAMETER_FAILURE_BY_FAMILY[family]
                self.assertIn(
                    expected_failure,
                    result.errors[0].message,
                    result.to_dict(),
                )

    def test_v1_missing_parameters_key_rejected(self):
        # The request never mentions this proof type's parameters at all
        # (not even an empty dict). The shared dispatcher must distinguish
        # omission from an explicit object and fail before family dispatch.
        verifier = _verifier()
        for family in ALL_FAMILIES:
            with self.subTest(family=family):
                envelope, request, proof_type, _params, _provider = _build(
                    family, "v1", credential_id=800 + ALL_FAMILIES.index(family)
                )
                empty_request = copy.deepcopy(request)
                del empty_request.parameters[proof_type]
                result = verifier.verify(envelope, empty_request)
                self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
                self.assertFalse(result.valid)
                self.assertIn(
                    "lacks usable parameters",
                    result.errors[0].message,
                    result.to_dict(),
                )

    def test_v2_empty_parameters_rejected(self):
        verifier = _verifier()
        for family in ALL_FAMILIES:
            with self.subTest(family=family):
                envelope, request, proof_type, _params, _provider = _build(
                    family, "v2", credential_id=900 + ALL_FAMILIES.index(family)
                )
                empty_request = copy.deepcopy(request)
                empty_request.parameters[proof_type] = {}
                result = verifier.verify(envelope, empty_request)
                self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
                self.assertFalse(result.valid)
                # Match the v1 assertion for the first mandatory-parameter failure.
                expected_failure = _FIRST_PARAMETER_FAILURE_BY_FAMILY[family]
                self.assertIn(
                    expected_failure,
                    result.errors[0].message,
                    result.to_dict(),
                )

    def test_v2_missing_parameters_key_rejected(self):
        verifier = _verifier()
        for family in ALL_FAMILIES:
            with self.subTest(family=family):
                envelope, request, proof_type, _params, _provider = _build(
                    family, "v2", credential_id=950 + ALL_FAMILIES.index(family)
                )
                missing_request = copy.deepcopy(request)
                del missing_request.parameters[proof_type]
                result = verifier.verify(envelope, missing_request)
                self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
                self.assertFalse(result.valid)
                self.assertIn("lacks usable parameters", result.errors[0].message)


# ===========================================================================
# 6b. The generic request-binding path returns REQUIREMENTS_NOT_MET for
#    non-mapping parameter blocks, including None and lists.
# ===========================================================================


class NonMappingParametersTests(unittest.TestCase):
    def test_v1_none_parameters_rejected_not_crashed(self):
        verifier = _verifier()
        envelope, request, proof_type, _params, _provider = _build(
            "jurisdiction", "v1", credential_id=1901
        )
        attack_request = copy.deepcopy(request)
        attack_request.parameters[proof_type] = None
        result = verifier.verify(envelope, attack_request)  # must not raise
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
        self.assertFalse(result.valid)

    def test_v1_list_parameters_rejected_not_crashed(self):
        verifier = _verifier()
        envelope, request, proof_type, _params, _provider = _build(
            "sanctions", "v1", credential_id=1902
        )
        attack_request = copy.deepcopy(request)
        attack_request.parameters[proof_type] = ["not", "a", "mapping"]
        result = verifier.verify(envelope, attack_request)  # must not raise
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
        self.assertFalse(result.valid)

    def test_v2_none_parameters_rejected_not_crashed(self):
        verifier = _verifier()
        envelope, request, proof_type, _params, _provider = _build(
            "tax", "v2", credential_id=1903
        )
        attack_request = copy.deepcopy(request)
        attack_request.parameters[proof_type] = None
        result = verifier.verify(envelope, attack_request)  # must not raise
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
        self.assertFalse(result.valid)

    def test_v2_list_parameters_rejected_not_crashed(self):
        verifier = _verifier()
        envelope, request, proof_type, _params, _provider = _build(
            "accreditation", "v2", credential_id=1904
        )
        attack_request = copy.deepcopy(request)
        attack_request.parameters[proof_type] = [1, 2, 3]
        result = verifier.verify(envelope, attack_request)  # must not raise
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
        self.assertFalse(result.valid)


# ===========================================================================
# 6c. Legacy flagRequired mitigation. Immutable v1/v2 proofs cannot attest
#    this private bit, so positive and malformed requirements fail closed.
#    False/absent remains usable because it asks for no institutional property.
# ===========================================================================


class FlagRequiredCharacterizationTests(unittest.TestCase):
    def test_legacy_true_fails_closed(self):
        for index, version in enumerate(("v1", "v2")):
            with self.subTest(version=version):
                envelope, request, _proof_type, _params, _provider = _build(
                    "accreditation", version, credential_id=1905 + index
                )
                proof_type = request.proof_types[0]
                request.parameters[proof_type]["flagRequired"] = True
                result = _verifier().verify(envelope, request)
                self.assertFalse(result.valid, result.to_dict())
                self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
                self.assertEqual(result.warning_codes(), [], result.to_dict())

    def test_legacy_false_or_absent_remains_usable(self):
        for index, version in enumerate(("v1", "v2")):
            envelope, request, proof_type, _params, _provider = _build(
                "accreditation", version, credential_id=1910 + index
            )
            for marker in (False, None):
                with self.subTest(version=version, marker=marker):
                    safe_request = copy.deepcopy(request)
                    if marker is None:
                        safe_request.parameters[proof_type].pop("flagRequired")
                    else:
                        safe_request.parameters[proof_type]["flagRequired"] = marker
                    result = _verifier().verify(envelope, safe_request)
                    self.assertTrue(result.valid, result.to_dict())
                    self.assertEqual(result.codes(), [], result.to_dict())

    def test_legacy_non_boolean_aliases_fail_closed(self):
        for index, version in enumerate(("v1", "v2")):
            envelope, request, proof_type, _params, _provider = _build(
                "accreditation", version, credential_id=1920 + index
            )
            for value in (0, 1, "true", None, []):
                with self.subTest(version=version, value=value):
                    malformed = copy.deepcopy(request)
                    malformed.parameters[proof_type]["flagRequired"] = value
                    result = _verifier().verify(envelope, malformed)
                    self.assertFalse(result.valid, result.to_dict())
                    self.assertEqual(
                        result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict()
                    )


# ===========================================================================
# 7. UNBOUND_PROOF_TYPE: a proof type that resolves to a real circuit but has
#    NO entry in the request-binding registry must be rejected, not accepted.
#    The two aggregation proof types are exactly this case (they are
#    envelope-level and never legitimately appear as an individual proof
#    entry, so the registry deliberately omits them -- default-deny).
# ===========================================================================


class UnboundProofTypeTests(unittest.TestCase):
    def _v1_envelope(self, proof_type):
        context = _context()
        entry = {
            "proofType": proof_type,
            "proof": "zkc:stub:v1:0000000000000000000000000000000000000000000000000000000000000000",
            "publicInputs": {},
            "principalConsent": True,
        }
        return {
            "version": "zkc:proof:v1",
            "metadata": {
                "generatedAt": _rfc3339(TIMESTAMP - 10),
                "expiresAt": _rfc3339(TIMESTAMP + 3600),
                "context": context.to_metadata(),
            },
            "proofs": [entry],
            "holderBinding": {"commitment": field_to_hex(0xABCDEF)},
        }

    def _v2_envelope(self, proof_type):
        context = _context()
        entry = {
            "proofType": proof_type,
            "proof": "zkc:stub:v1:0000000000000000000000000000000000000000000000000000000000000000",
            "publicInputs": {},
            "principalConsent": True,
        }
        return {
            "version": "zkc:proof:v2",
            "metadata": {
                "generatedAt": _rfc3339(TIMESTAMP - 10),
                "expiresAt": _rfc3339(TIMESTAMP + 3600),
                "context": context.to_metadata(),
            },
            "proofs": [entry],
            "presentationBinding": {"profile": ANONYMOUS_PROFILE},
        }

    def test_v1_aggregation_proof_type_has_no_binding_contract(self):
        proof_type = "zkc:proof:aggregation:v1"
        envelope = self._v1_envelope(proof_type)
        request = VerificationRequest(
            proof_types=[proof_type], parameters={}, context=_context(),
        )
        result = _verifier().verify(envelope, request)
        self.assertEqual(result.codes(), [Code.UNBOUND_PROOF_TYPE], result.to_dict())
        self.assertFalse(result.valid)

    def test_aggregate_successor_proof_types_have_no_binding_contract(self):
        for proof_type in ("zkc:proof:aggregate:v2", "zkc:proof:aggregate:v3"):
            with self.subTest(proof_type=proof_type):
                envelope = self._v2_envelope(proof_type)
                request = VerificationRequest(
                    proof_types=[proof_type], parameters={}, context=_context(),
                )
                result = _verifier().verify(envelope, request)
                # aggregate:v3's encoder is unpublished; the public verifier
                # rejects it before the individual binding-contract gate.
                expected_code = (
                    Code.UNKNOWN_PROOF_TYPE
                    if IS_PUBLIC_SNAPSHOT and proof_type == "zkc:proof:aggregate:v3"
                    else Code.UNBOUND_PROOF_TYPE
                )
                self.assertEqual(result.codes(), [expected_code], result.to_dict())
                self.assertFalse(result.valid)


# ===========================================================================
# 7b. Exercise the request-binding check directly. Envelope verification
#    rejects unregistered proof types before reaching
#    ``_verify_type_specific_requirements``, which also rejects them.
# ===========================================================================


class ChokepointDirectDefaultDenyTests(unittest.TestCase):
    def test_type_specific_requirements_rejects_unregistered_proof_type_directly(self):
        verifier = _verifier()
        result = VerificationResult()
        # public_inputs/request/claim_binding/proof_context/timestamp are
        # never consulted on this path -- contract is None short-circuits
        # before any of them are touched -- so dummy values are safe here.
        verifier._verify_type_specific_requirements(
            "zkc:proof:not_a_registered_predicate:v1",
            {},
            None,
            0,
            0,
            TIMESTAMP,
            result,
        )
        self.assertEqual(result.codes(), [Code.UNBOUND_PROOF_TYPE], result.to_dict())
        self.assertFalse(result.valid)


# ===========================================================================
# 8. UNSIGNED_REQUEST (request-vs-APR disagreement): verify_authenticated
#    with an APR whose request.parameters/proofTypes disagree with the
#    caller's VerificationRequest -> REJECT. This reuses the spec's own
#    code for "Request differs from signed APR" (docs/zkc_specification.md
#    step 0) rather than a bespoke code. Includes the type-strictness case
#    ([True] vs [1]). The matching APR case still ACCEPTS.
# ===========================================================================

APR_VERIFIER_PRIVATE_KEY = 0xA9701 % N or 1
APR_VERIFIER_KEY_X, APR_VERIFIER_KEY_Y = public_key_bytes(APR_VERIFIER_PRIVATE_KEY)

KYC_PARAMS = {
    "requiredLevel": 1,
    "requiredAttributes": [True, False, True, False, False],
}


def _verifier_session_context_fixture() -> dict:
    return {
        "profile": "zkc:context:verifier-session:v1",
        "verifierId": "verifier.example",
        "sessionId": field_to_hex(CONTEXT_NONCE),
        "timestamp": TIMESTAMP,
    }


class AuthenticatedRequestBindingTests(unittest.TestCase):
    def setUp(self):
        self.provider = LocalAccumulatorProvider()
        self.holder = _make_holder(self.provider)
        self.credential = issue_kyc_credential(
            master_seed=MASTER_SEED, credential_id=99, provider=self.provider, expires_at=2_000_000_000
        )
        self.holder.store_credential(self.credential)
        self.context = _context()
        self.accumulator_states = {
            TEST_ISSUER_ID: IssuerAccumulatorState(
                current_epoch=self.provider.current_epoch(TEST_ISSUER_ID),
                roots=self.provider.roots(TEST_ISSUER_ID),
            )
        }

    def _apr(self, nonce=0xABC123, *, parameters=None):
        effective_parameters = KYC_PARAMS if parameters is None else parameters
        request_block = {
            "proofTypes": [KYC_PROOF_TYPE],
            "parameters": {KYC_PROOF_TYPE: copy.deepcopy(effective_parameters)},
            "context": _verifier_session_context_fixture(),
            "trustPolicy": {"issuers": []},
            # Explicit anonymous presentation so _apr_presentation_proof_types
            # translates kyc:v1 -> kyc:v2 for the comparison, exactly as the
            # holder itself resolves it below.
            "presentation": {"profile": ANONYMOUS_PROFILE},
        }
        unsigned = {
            "request": request_block,
            "verifierId": "verifier.example",
            "nonce": field_to_hex(nonce),
            "issuedAt": TIMESTAMP,
            "expiresAt": TIMESTAMP + 3600,
        }
        return sign_apr(unsigned, APR_VERIFIER_PRIVATE_KEY)

    def _holder_request(self):
        return ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters={KYC_PROOF_TYPE: copy.deepcopy(KYC_PARAMS)},
            context=self.context,
            trust_policy=TrustPolicy(
                issuers=(trusted_test_issuer((KYC_PROOF_TYPE, KYC_V2_PROOF_TYPE)),)
            ),
            presentation_profile=ANONYMOUS_PROFILE,
        )

    def _envelope(self, apr):
        request = self._holder_request()
        return self.holder.generate_authenticated_proof(apr, request, now=request.context.timestamp)["envelope"]

    def _verifier(self, **policy_kwargs):
        return ZKCVerifier(
            REPO_ROOT,
            VerifierTrustPolicy(
                **apr_verifier_identity(),
                issuers=(
                    VerifierTrustedIssuer(
                        issuer_id=TEST_ISSUER_ID,
                        public_key_x=TEST_ISSUER_KEY_X,
                        public_key_y=TEST_ISSUER_KEY_Y,
                        proof_types=(KYC_V2_PROOF_TYPE,),
                    ),
                ),
                **policy_kwargs,
            ),
            StubVerifyBackend(),
        )

    def _verification_request(self, parameters, proof_types=(KYC_V2_PROOF_TYPE,)):
        return VerificationRequest(
            proof_types=list(proof_types),
            parameters=parameters,
            context=self.context,
            accumulator_states=dict(self.accumulator_states),
        )

    def test_matching_apr_accepts(self):
        apr = self._apr()
        envelope = self._envelope(apr)
        request = self._verification_request({KYC_V2_PROOF_TYPE: copy.deepcopy(KYC_PARAMS)})
        result = self._verifier().verify_authenticated(apr, envelope, request, now=request.context.timestamp)
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertTrue(result.valid)

    def _binding_exchange(self):
        registry = PredicateRegistry.from_repo(REPO_ROOT)
        bindings = registry.bindings_for("zkc-kyc", "4.0.0", KYC_V2_PROOF_TYPE)
        selector = next(
            binding.selector for binding in bindings if binding.toolchain["id"] == "successor"
        )
        unsigned = copy.deepcopy(self._apr())
        unsigned.pop("signature")
        unsigned["request"]["extensions"] = request_extension({KYC_PROOF_TYPE: selector})
        apr = sign_apr(unsigned, APR_VERIFIER_PRIVATE_KEY)
        holder_request = self._holder_request()
        holder_request.binding_selectors = {KYC_PROOF_TYPE: selector}
        envelope = self.holder.generate_authenticated_proof(apr, holder_request, now=holder_request.context.timestamp)["envelope"]
        verifier_request = self._verification_request(
            {KYC_V2_PROOF_TYPE: copy.deepcopy(KYC_PARAMS)}
        )
        verifier_request.binding_selectors = {KYC_V2_PROOF_TYPE: selector}
        return apr, envelope, verifier_request, selector

    def test_authenticated_v2_binding_selector_is_exact_and_auditable(self):
        apr, envelope, request, selector = self._binding_exchange()
        self.assertEqual(envelope["proofs"][0]["bindingSelector"], selector)
        result = self._verifier().verify_authenticated(apr, envelope, request, now=request.context.timestamp)
        self.assertTrue(result.valid, result.to_dict())
        self.assertEqual(result.bindings[0]["bindingId"], selector["bindingId"])
        self.assertEqual(result.bindings[0]["toolchain"]["id"], "successor")

    def test_authenticated_v2_binding_selector_cannot_be_stripped(self):
        apr, envelope, request, _selector = self._binding_exchange()
        envelope["proofs"][0].pop("bindingSelector")
        result = self._verifier().verify_authenticated(apr, envelope, request, now=request.context.timestamp)
        self.assertEqual(result.codes(), [Code.MALFORMED_BINDING_SELECTOR], result.to_dict())

    def test_verifier_binding_allowlist_is_an_independent_gate(self):
        apr, envelope, request, _selector = self._binding_exchange()
        other = next(
            binding.binding_id
            for binding in PredicateRegistry.from_repo(REPO_ROOT).bindings_for(
                "zkc-kyc", "4.0.0", KYC_V2_PROOF_TYPE
            )
            if binding.toolchain["id"] == "historical"
        )
        result = self._verifier(accepted_binding_ids=(other,)).verify_authenticated(
            apr, envelope, request,
            now=request.context.timestamp
        )
        self.assertEqual(result.codes(), [Code.DISALLOWED_BINDING], result.to_dict())

    def test_weakened_required_attributes_rejected(self):
        apr = self._apr()
        envelope = self._envelope(apr)
        weakened = {"requiredLevel": 1, "requiredAttributes": [False, False, False, False, False]}
        request = self._verification_request({KYC_V2_PROOF_TYPE: weakened})
        result = self._verifier().verify_authenticated(apr, envelope, request, now=request.context.timestamp)
        self.assertEqual(result.codes(), [Code.UNSIGNED_REQUEST], result.to_dict())
        self.assertFalse(result.valid)

    def test_swapped_proof_types_rejected(self):
        apr = self._apr()
        envelope = self._envelope(apr)
        request = self._verification_request(
            {"zkc:proof:jurisdiction:v2": copy.deepcopy(KYC_PARAMS)},
            proof_types=("zkc:proof:jurisdiction:v2",),
        )
        # SECONDARY (mutation-testing follow-up): assert the APR-agreement
        # gate itself rejects this swap, not merely that SOME rejection fires
        # end-to-end. Without this, a mutation that widens
        # ``_apr_presentation_proof_types`` resolution so the gate wrongly
        # ACCEPTS the swapped proof type still passes this test -- it only
        # fails incidentally, downstream, because the (now-mismatched) KYC
        # parameters trip a DIFFERENT check
        # (``AssertionError: Lists differ: ['MISSING_PROOF'] != ['UNSIGNED_REQUEST']``).
        # Calling the gate directly makes the intent load-bearing.
        verifier = self._verifier()
        gate_result = VerificationResult()
        self.assertFalse(verifier._request_matches_apr(apr, request, gate_result))

        result = verifier.verify_authenticated(apr, envelope, request, now=request.context.timestamp)
        self.assertEqual(result.codes(), [Code.UNSIGNED_REQUEST], result.to_dict())
        self.assertFalse(result.valid)

    def test_type_strictness_true_vs_one_rejected(self):
        # The canonical-JSON comparison is deliberately type-strict: JSON
        # `true` is not `1`. A caller substituting integers for booleans must
        # be rejected even though the values are "equal" under Python's ==.
        apr = self._apr()
        envelope = self._envelope(apr)
        int_flags = {"requiredLevel": 1, "requiredAttributes": [1, 0, 1, 0, 0]}
        self.assertEqual(int_flags["requiredAttributes"], [True, False, True, False, False])  # Python ==
        request = self._verification_request({KYC_V2_PROOF_TYPE: int_flags})
        result = self._verifier().verify_authenticated(apr, envelope, request, now=request.context.timestamp)
        self.assertEqual(result.codes(), [Code.UNSIGNED_REQUEST], result.to_dict())
        self.assertFalse(result.valid)

    def test_signed_modulus_shifted_level_rejected_by_type_specific_gate(self):
        # The attacker signs the shifted value too, so APR agreement succeeds.
        # The untouched proof still attests canonical level 1 and must be
        # rejected by step 4e rather than treating 1 + r as the same residue.
        honest_apr = self._apr()
        envelope = self._envelope(honest_apr)
        shifted = {
            "requiredLevel": FIELD_MODULUS + 1,
            "requiredAttributes": [True, False, True, False, False],
        }
        attack_apr = self._apr(nonce=0xABC124, parameters=shifted)
        request = self._verification_request(
            {KYC_V2_PROOF_TYPE: copy.deepcopy(shifted)}
        )
        result = self._verifier().verify_authenticated(attack_apr, envelope, request, now=request.context.timestamp)
        self.assertEqual(result.codes(), [Code.REQUIREMENTS_NOT_MET], result.to_dict())
        self.assertFalse(result.valid)

    # -----------------------------------------------------------------
    # Check that the verifier accepts the proof types permitted by the
    # holder's presentation profile negotiation.
    # -----------------------------------------------------------------

    def _apr_with_presentation(self, presentation_block, *, omit_key=False, nonce=0xABC200):
        request_block = {
            "proofTypes": [KYC_PROOF_TYPE],
            "parameters": {KYC_PROOF_TYPE: copy.deepcopy(KYC_PARAMS)},
            "context": _verifier_session_context_fixture(),
            "trustPolicy": {"issuers": []},
        }
        if not omit_key:
            request_block["presentation"] = presentation_block
        unsigned = {
            "request": request_block,
            "verifierId": "verifier.example",
            "nonce": field_to_hex(nonce),
            "issuedAt": TIMESTAMP,
            "expiresAt": TIMESTAMP + 3600,
        }
        return sign_apr(unsigned, APR_VERIFIER_PRIVATE_KEY)

    def test_presentation_silent_apr_authenticated_exchange_accepts(self):
        # With the APR silent, the holder's ceiling determines the profile.
        # The verifier cannot observe that ceiling and accepts either proof
        # type allowed by the silent APR.
        apr = self._apr_with_presentation(None, omit_key=True, nonce=0xABC201)
        envelope = self._envelope(apr)
        self.assertEqual(envelope["proofs"][0]["proofType"], KYC_V2_PROOF_TYPE)
        request = self._verification_request({KYC_V2_PROOF_TYPE: copy.deepcopy(KYC_PARAMS)})
        result = self._verifier().verify_authenticated(apr, envelope, request, now=request.context.timestamp)
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertTrue(result.valid)

    def test_presentation_profile_less_block_authenticated_exchange_accepts(self):
        # The "presentation" block IS present but silent on "profile". Both
        # the holder (client.py:879, ``block.get("profile", ANONYMOUS_PROFILE)``)
        # and the verifier (_apr_presentation_proof_types) must default this
        # to ANONYMOUS the SAME way, not merely when a caller writes the
        # profile explicitly.
        apr = self._apr_with_presentation({}, nonce=0xABC202)
        envelope = self._envelope(apr)
        self.assertEqual(envelope["proofs"][0]["proofType"], KYC_V2_PROOF_TYPE)
        request = self._verification_request({KYC_V2_PROOF_TYPE: copy.deepcopy(KYC_PARAMS)})
        result = self._verifier().verify_authenticated(apr, envelope, request, now=request.context.timestamp)
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertTrue(result.valid)

    def test_non_object_or_unknown_presentation_rejected_before_request_comparison(self):
        # The holder refuses these profiles too.  In particular, an explicit
        # ``null`` is not the same wire representation as omitting the block:
        # only an absent block gets the legacy holder-ceiling compatibility
        # behaviour.  Check the request-agreement gate directly so an
        # unrelated downstream proof failure cannot mask a widened parser.
        envelope = self._envelope(self._apr(nonce=0xABC205))
        request = self._verification_request(
            {KYC_V2_PROOF_TYPE: copy.deepcopy(KYC_PARAMS)}
        )
        cases = (None, [], "not-an-object", {"profile": "zkc:profile:unknown:v1"})
        for index, presentation in enumerate(cases):
            with self.subTest(presentation=presentation):
                apr = self._apr_with_presentation(
                    presentation, nonce=0xABC206 + index
                )
                verifier = self._verifier()
                gate_result = VerificationResult()
                self.assertFalse(
                    verifier._request_matches_apr(apr, request, gate_result)
                )
                self.assertEqual(
                    gate_result.codes(), [Code.UNSIGNED_REQUEST], gate_result.to_dict()
                )

                result = verifier.verify_authenticated(apr, envelope, request, now=request.context.timestamp)
                self.assertEqual(result.codes(), [Code.UNSIGNED_REQUEST], result.to_dict())
                self.assertFalse(result.valid)

    def test_linkable_apr_with_downgrading_holder_authenticated_exchange_accepts(self):
        # The holder's ``_resolve_presentation`` caps the requested profile at
        # the holder's ceiling. A linkable APR can receive a valid v2 response
        # from a holder with an anonymous ceiling.
        apr = self._apr_with_presentation({"profile": LINKABLE_PROFILE}, nonce=0xABC203)
        envelope = self._envelope(apr)
        self.assertEqual(envelope["proofs"][0]["proofType"], KYC_V2_PROOF_TYPE)
        request = self._verification_request({KYC_V2_PROOF_TYPE: copy.deepcopy(KYC_PARAMS)})
        result = self._verifier().verify_authenticated(apr, envelope, request, now=request.context.timestamp)
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertTrue(result.valid)

    def test_anonymous_apr_v1_spelled_request_rejected(self):
        # An explicitly anonymous APR permits only the v2 proof type.
        # Reject a verifier request that names the linkable v1 type.
        apr = self._apr_with_presentation({"profile": ANONYMOUS_PROFILE}, nonce=0xABC204)
        envelope = self._envelope(apr)
        self.assertEqual(envelope["proofs"][0]["proofType"], KYC_V2_PROOF_TYPE)
        request = self._verification_request(
            {KYC_PROOF_TYPE: copy.deepcopy(KYC_PARAMS)}, proof_types=(KYC_PROOF_TYPE,)
        )
        result = self._verifier().verify_authenticated(apr, envelope, request, now=request.context.timestamp)
        self.assertEqual(result.codes(), [Code.UNSIGNED_REQUEST], result.to_dict())
        self.assertFalse(result.valid)

    def _jurisdiction_alias_apr(
        self,
        proof_types,
        parameters,
        nonce,
        profile=ANONYMOUS_PROFILE,
        *,
        include_presentation=True,
    ):
        request = {
            "proofTypes": list(proof_types),
            "parameters": copy.deepcopy(parameters),
            "context": _verifier_session_context_fixture(),
            "trustPolicy": {"issuers": []},
        }
        if include_presentation:
            request["presentation"] = {"profile": profile}
        return sign_apr(
            {
                "request": request,
                "verifierId": "verifier.example",
                "nonce": field_to_hex(nonce),
                "issuedAt": TIMESTAMP,
                "expiresAt": TIMESTAMP + 3600,
            },
            APR_VERIFIER_PRIVATE_KEY,
        )

    def _historical_jurisdiction_exchange(self, version, credential_id):
        """Build a static old-generation envelope without generating one anew."""
        envelope, safe_request, safe_type, params, _provider = _build(
            "jurisdiction", version, credential_id=credential_id
        )
        if version == "v1":
            legacy_type = JURISDICTION_LEGACY_V1_PROOF_TYPE
            legacy_circuit = "zkc_jurisdiction"
        else:
            legacy_type = JURISDICTION_LEGACY_V2_PROOF_TYPE
            legacy_circuit = "zkc_jurisdiction_v2"

        self.assertNotEqual(safe_type, legacy_type)
        entry = envelope["proofs"][0]
        entry["proofType"] = legacy_type
        _reseal(entry, legacy_circuit)
        request = VerificationRequest(
            proof_types=[legacy_type],
            parameters={legacy_type: copy.deepcopy(params)},
            context=safe_request.context,
            accumulator_states=safe_request.accumulator_states,
        )
        return envelope, request, legacy_type, params

    def _historical_profile_exchange(self, family, generation, credential_id):
        """Model an already-issued v3-v6 profile proof without minting one.

        Holder generation intentionally cannot produce these vulnerable
        identities. The verifier still needs an exact literal/trust-gated path
        for a proof that was created before the v7/v8 migration.
        """
        version = "v1" if generation % 2 else "v2"
        envelope, safe_request, safe_type, params, _provider = _build(
            family, version, credential_id=credential_id
        )
        legacy_type = f"zkc:proof:{family}:v{generation}"
        legacy_circuit = f"zkc_remaining_predicates_v{generation}"
        if generation % 2:
            profile = LINKABLE_PROFILE
        else:
            profile = ANONYMOUS_PROFILE

        self.assertNotEqual(safe_type, legacy_type)
        entry = envelope["proofs"][0]
        entry["proofType"] = legacy_type
        _reseal(entry, legacy_circuit)
        request = VerificationRequest(
            proof_types=[legacy_type],
            parameters={legacy_type: copy.deepcopy(params)},
            context=safe_request.context,
            accumulator_states=safe_request.accumulator_states,
        )
        return envelope, request, legacy_type, params, profile

    def test_explicit_matching_legacy_apr_needs_the_deprecated_opt_in(self):
        """A literal APR authorizes the REQUEST, not the forgeable statement: a
        fresh historical proof is accepted only when the verifier's own policy
        opts into deprecated identities (security review 2026-10-04, R1.4)."""
        cases = (
            ("v1", LINKABLE_PROFILE, 9914, 0xABC209),
            ("v2", ANONYMOUS_PROFILE, 9915, 0xABC20A),
        )
        for version, profile, credential_id, nonce in cases:
            with self.subTest(version=version, profile=profile):
                envelope, request, legacy_type, params = (
                    self._historical_jurisdiction_exchange(version, credential_id)
                )
                apr = self._jurisdiction_alias_apr(
                    (legacy_type,), {legacy_type: params}, nonce, profile=profile
                )
                verifier = _verifier(proof_types=(legacy_type,))

                gate_result = VerificationResult()
                self.assertTrue(verifier._request_matches_apr(apr, request, gate_result))
                self.assertEqual(gate_result.codes(), [], gate_result.to_dict())

                result = verifier.verify_authenticated(apr, envelope, request, now=request.context.timestamp)
                self.assertEqual(result.codes(), [Code.DEPRECATED_PROOF_TYPE], result.to_dict())

                opted_in = _verifier(
                    proof_types=(legacy_type,), accepted_review_statuses=_HISTORICAL_OPT_IN
                )
                result = opted_in.verify_authenticated(apr, envelope, request, now=request.context.timestamp)
                self.assertEqual(result.codes(), [], result.to_dict())
                self.assertTrue(result.valid)

    def test_raw_verifier_rejects_every_affected_historical_identity(self):
        cases = [
            self._historical_jurisdiction_exchange("v1", 99140),
            self._historical_jurisdiction_exchange("v2", 99141),
        ]
        for family_index, family in enumerate(REMAINING_FAMILIES):
            for generation in range(1, 7):
                envelope_version = "v1" if generation % 2 else "v2"
                envelope, safe_request, _safe_type, params, _provider = _build(
                    family,
                    envelope_version,
                    credential_id=99150 + family_index * 4 + generation,
                )
                historical_type = f"zkc:proof:{family}:v{generation}"
                envelope["proofs"][0]["proofType"] = historical_type
                request = VerificationRequest(
                    proof_types=[historical_type],
                    parameters={historical_type: copy.deepcopy(params)},
                    context=safe_request.context,
                    accumulator_states=safe_request.accumulator_states,
                )
                cases.append((envelope, request, historical_type, params))

        for envelope, request, historical_type, _params in cases:
            with self.subTest(proof_type=historical_type):
                result = _verifier(proof_types=(historical_type,)).verify(
                    envelope, request
                )
                self.assertFalse(result.valid, result.to_dict())
                self.assertEqual(
                    result.codes(), [Code.UNSIGNED_REQUEST], result.to_dict()
                )
                self.assertEqual(
                    result.errors[0].proof_type,
                    historical_type,
                    result.to_dict(),
                )

    def test_historical_envelopes_require_literal_explicit_legacy_authorization(self):
        historical_v1 = self._historical_jurisdiction_exchange("v1", 9916)
        historical_v2 = self._historical_jurisdiction_exchange("v2", 9917)
        cases = (
            # A current safe identity can never authorize a deprecated proof.
            (historical_v1, "zkc:proof:jurisdiction:v3", LINKABLE_PROFILE, True),
            (historical_v2, JURISDICTION_V4_PROOF_TYPE, ANONYMOUS_PROFILE, True),
            # A legacy spelling is valid only for its matching profile ABI.
            (historical_v1, JURISDICTION_LEGACY_V1_PROOF_TYPE, ANONYMOUS_PROFILE, True),
            (historical_v2, JURISDICTION_LEGACY_V2_PROOF_TYPE, LINKABLE_PROFILE, True),
            # The legacy opt-in must be explicit, never inferred from a missing block.
            (historical_v1, JURISDICTION_LEGACY_V1_PROOF_TYPE, LINKABLE_PROFILE, False),
        )
        for index, (historical, signed_type, profile, explicit) in enumerate(cases):
            envelope, request, legacy_type, params = historical
            with self.subTest(
                legacy_type=legacy_type,
                signed_type=signed_type,
                profile=profile,
                explicit=explicit,
            ):
                apr = self._jurisdiction_alias_apr(
                    (signed_type,),
                    {signed_type: params},
                    0xABC20B + index,
                    profile=profile,
                    include_presentation=explicit,
                )
                verifier = _verifier(proof_types=(legacy_type,))

                gate_result = VerificationResult()
                self.assertFalse(verifier._request_matches_apr(apr, request, gate_result))
                self.assertEqual(
                    gate_result.codes(), [Code.UNSIGNED_REQUEST], gate_result.to_dict()
                )

                result = verifier.verify_authenticated(apr, envelope, request, now=request.context.timestamp)
                self.assertEqual(result.codes(), [Code.UNSIGNED_REQUEST], result.to_dict())
                self.assertFalse(result.valid)

    def test_profile_v3_to_v6_historical_proofs_need_literal_apr_and_trust(self):
        for family_index, family in enumerate(REMAINING_FAMILIES):
            for generation in range(3, 7):
                with self.subTest(family=family, generation=generation):
                    envelope, request, legacy_type, params, profile = (
                        self._historical_profile_exchange(
                            family,
                            generation,
                            credential_id=9930 + family_index * 4 + generation,
                        )
                    )
                    apr = self._jurisdiction_alias_apr(
                        (legacy_type,),
                        {legacy_type: params},
                        0xABC250 + family_index * 4 + generation,
                        profile=profile,
                    )
                    default = _verifier(proof_types=(legacy_type,))
                    refused = default.verify_authenticated(apr, envelope, request, now=request.context.timestamp)
                    self.assertEqual(
                        refused.codes(), [Code.DEPRECATED_PROOF_TYPE], refused.to_dict()
                    )
                    trusted = _verifier(
                        proof_types=(legacy_type,), accepted_review_statuses=_HISTORICAL_OPT_IN
                    )
                    accepted = trusted.verify_authenticated(apr, envelope, request, now=request.context.timestamp)
                    self.assertTrue(accepted.valid, accepted.to_dict())

                    current_type = (
                        _V3_TYPE[family] if generation % 2 else _V4_TYPE[family]
                    )
                    current_apr = self._jurisdiction_alias_apr(
                        (current_type,),
                        {current_type: params},
                        0xABC280 + family_index * 4 + generation,
                        profile=profile,
                    )
                    rejected = trusted.verify_authenticated(current_apr, envelope, request, now=request.context.timestamp)
                    self.assertFalse(rejected.valid, rejected.to_dict())
                    self.assertEqual(
                        rejected.codes(), [Code.UNSIGNED_REQUEST], rejected.to_dict()
                    )

    def test_single_legacy_jurisdiction_alias_resolves_to_safe_v4(self):
        envelope, request, proof_type, params, _provider = _build(
            "jurisdiction", "v2", credential_id=9910
        )
        apr = self._jurisdiction_alias_apr(
            ("zkc:proof:jurisdiction:v1",),
            {"zkc:proof:jurisdiction:v1": params},
            0xABC205,
        )

        result = _verifier().verify_authenticated(apr, envelope, request, now=request.context.timestamp)
        self.assertEqual(proof_type, JURISDICTION_V4_PROOF_TYPE)
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertTrue(result.valid)

    def test_linkable_legacy_jurisdiction_alias_resolves_to_safe_v3(self):
        envelope, request, proof_type, params, _provider = _build(
            "jurisdiction", "v1", credential_id=9912
        )
        apr = self._jurisdiction_alias_apr(
            ("zkc:proof:jurisdiction:v1",),
            {"zkc:proof:jurisdiction:v1": params},
            0xABC207,
            profile=LINKABLE_PROFILE,
        )

        result = _verifier().verify_authenticated(apr, envelope, request, now=request.context.timestamp)
        self.assertEqual(proof_type, "zkc:proof:jurisdiction:v3")
        self.assertEqual(result.codes(), [], result.to_dict())
        self.assertTrue(result.valid)

    def test_repeated_legacy_and_safe_family_aliases_rejected(self):
        envelope, honest_request, proof_type, safe_params, _provider = _build(
            "jurisdiction", "v2", credential_id=9911
        )
        legacy_params = copy.deepcopy(safe_params)
        legacy_params["requiredClaimType"] += 1
        apr = self._jurisdiction_alias_apr(
            ("zkc:proof:jurisdiction:v1", "zkc:proof:jurisdiction:v3"),
            {
                "zkc:proof:jurisdiction:v1": legacy_params,
                "zkc:proof:jurisdiction:v3": safe_params,
            },
            0xABC206,
        )
        collapsed_request = VerificationRequest(
            proof_types=[proof_type, proof_type],
            parameters={proof_type: copy.deepcopy(safe_params)},
            context=honest_request.context,
            accumulator_states=honest_request.accumulator_states,
        )
        verifier = _verifier()

        gate_result = VerificationResult()
        self.assertFalse(verifier._request_matches_apr(apr, collapsed_request, gate_result))
        self.assertEqual(gate_result.codes(), [Code.UNSIGNED_REQUEST], gate_result.to_dict())
        self.assertIn("repeats predicate family", gate_result.errors[0].message)

        result = verifier.verify_authenticated(apr, envelope, collapsed_request, now=collapsed_request.context.timestamp)
        self.assertEqual(result.codes(), [Code.UNSIGNED_REQUEST], result.to_dict())
        self.assertFalse(result.valid)

    def test_repeated_family_aliases_rejected_when_effective_types_are_distinct(self):
        _envelope, honest_request, _proof_type, params, _provider = _build(
            "jurisdiction", "v1", credential_id=9913
        )
        v3_type = "zkc:proof:jurisdiction:v3"
        v4_type = JURISDICTION_V4_PROOF_TYPE
        apr = self._jurisdiction_alias_apr(
            (v3_type, v4_type),
            {v3_type: params, v4_type: params},
            0xABC208,
            profile=LINKABLE_PROFILE,
        )
        distinct_request = VerificationRequest(
            proof_types=[v3_type, v4_type],
            parameters={v3_type: copy.deepcopy(params), v4_type: copy.deepcopy(params)},
            context=honest_request.context,
            accumulator_states=honest_request.accumulator_states,
        )
        gate_result = VerificationResult()

        self.assertFalse(
            _verifier()._request_matches_apr(apr, distinct_request, gate_result)
        )
        self.assertEqual(gate_result.codes(), [Code.UNSIGNED_REQUEST], gate_result.to_dict())
        self.assertIn("repeats predicate family", gate_result.errors[0].message)

    def test_colliding_future_resolver_outputs_rejected_as_duplicate_identities(self):
        alias_a = "zkc:proof:future-a:v1"
        alias_b = "zkc:proof:future-b:v1"
        effective_type = "zkc:proof:shared-effective:v1"
        apr = self._jurisdiction_alias_apr(
            (alias_a, alias_b), {alias_a: {}, alias_b: {}}, 0xABC210
        )
        request = VerificationRequest(
            proof_types=[effective_type, effective_type],
            parameters={effective_type: {}},
            context=self.context,
            accumulator_states=self.accumulator_states,
        )
        gate_result = VerificationResult()

        # The published maps are collision-free today. Model a future resolver
        # collision directly so this final fail-closed guard remains load-bearing.
        with mock.patch(
            "zkc_verifier.verifier._apr_presentation_proof_types",
            return_value={
                alias_a: (effective_type,),
                alias_b: (effective_type,),
            },
        ):
            self.assertFalse(
                _verifier()._request_matches_apr(apr, request, gate_result)
            )

        self.assertEqual(gate_result.codes(), [Code.UNSIGNED_REQUEST], gate_result.to_dict())
        self.assertIn("collid", gate_result.errors[0].message)


# ===========================================================================
# 9. Registry completeness: every proof type the encoders declare must have a
#    _REQUEST_BINDINGS entry, except a narrow, explicitly-justified exclusion
#    set. This is the guard against "a predicate is added and the author
#    forgets to bind it" rotting back into a silent soundness hole -- without
#    it, the default-deny registry only protects proof types someone
#    remembered to list, which is exactly the failure mode P1/P2 exploited.
#
#    The expected set is built by reading schemas/public-inputs/*.json with
#    the SAME glob _load_circuit_map uses (so this test tracks the encoders
#    the verifier itself loads, not a hand-maintained list that can drift),
#    minus exactly the proof types PROVEN -- by reading _verify_v1/_verify_v2
#    below, not assumed -- to never reach _verify_individual/_verify_individual_v2.
# ===========================================================================


class RequestBindingRegistryCompletenessTests(unittest.TestCase):
    # Justified exclusion set. Each entry names the proof type and the exact
    # code-reading reason it cannot reach _verify_individual/_verify_individual_v2,
    # so a future reader cannot casually widen this set without also updating
    # the reasoning here.
    #
    #   * "zkc:proof:aggregation:v1", "zkc:proof:aggregate:v2", and
    #     "zkc:proof:aggregate:v3" -- these encoders
    #     exist for the AGGREGATION BLOCK, not for individual proof entries.
    #     _verify_v1/_verify_v2 (python/zkc_verifier/verifier.py) each dispatch
    #     the two loops separately: step 4 iterates ``envelope["proofs"]``,
    #     calling _verify_individual(_v2) once per entry's "proofType"; step 6
    #     is a SEPARATE, unconditional-on-proof-type check --
    #     checks the v1 block's commitments or rejects the block in v2. This
    #     step operates on ``envelope["aggregation"]`` and never consults
    #     "proofTypes" or _REQUEST_BINDINGS at all. A legitimately-constructed
    #     envelope therefore never presents an aggregation proof type as a
    #     "proofs" list entry, so step 4's chokepoint never sees one.
    #     This is not merely assumed: UnboundProofTypeTests
    #     (test_v1_aggregation_proof_type_has_no_binding_contract,
    #     test_aggregate_successor_proof_types_have_no_binding_contract, above)
    #     prove
    #     that if an adversarial envelope DOES smuggle one of these proof
    #     types into "proofs" anyway, it is rejected with UNBOUND_PROOF_TYPE
    #     rather than accepted silently -- so omitting them from
    #     _REQUEST_BINDINGS costs nothing: the only reachable outcome for them
    #     is already a rejection. NOTE, precisely: those two tests go through
    #     `verifier.verify(...)`, which reaches the EARLY default-deny gate in
    #     _verify_individual/_verify_individual_v2 (it checks
    #     ``proof_type not in _REQUEST_BINDINGS`` and returns before
    #     _verify_type_specific_requirements is ever called) -- NOT the
    #     separate gate inside _verify_type_specific_requirements itself,
    #     which the early gate's own
    #     early return makes unreachable from any envelope-level test. That
    #     second, chokepoint-local gate is exercised directly (bypassing the
    #     early gate) by
    #     ChokepointDirectDefaultDenyTests.test_type_specific_requirements_rejects_unregistered_proof_type_directly
    #     above.
    _EXCLUDED_PROOF_TYPES = frozenset(
        {
            "zkc:proof:aggregation:v1",
            "zkc:proof:aggregate:v2",
            "zkc:proof:aggregate:v3",
        }
    )

    def _encoder_declared_proof_types(self) -> set:
        """Every proofType across schemas/public-inputs/*.json.

        Mirrors ZKCVerifier._load_circuit_map's own glob exactly (same
        directory, same "*.json" pattern, same "proofTypes" field) so this
        test tracks what the verifier itself loads rather than a
        hand-maintained duplicate list that can silently drift from it.
        """
        declared = set()
        encoder_dir = REPO_ROOT / "schemas" / "public-inputs"
        paths = (
            [REPO_ROOT / path for path in sorted(expected_public_paths(
                "schemas/public-inputs/", ".json"
            ))]
            if IS_PUBLIC_SNAPSHOT else sorted(encoder_dir.glob("*.json"))
        )
        for path in paths:
            encoder = json.loads(path.read_text())
            declared.update(encoder["proofTypes"])
        return declared

    def test_every_non_aggregation_proof_type_has_a_binding(self):
        declared = self._encoder_declared_proof_types()
        expected = declared - self._EXCLUDED_PROOF_TYPES
        self.assertTrue(expected, "sanity: encoder glob found no bindable proof types")

        bound = set(_REQUEST_BINDINGS.keys())
        missing = expected - bound
        self.assertEqual(
            missing,
            set(),
            f"proof type(s) declared by an encoder but with NO "
            f"_REQUEST_BINDINGS entry -- these would reach "
            f"_verify_individual/_verify_individual_v2 and be REJECTED as "
            f"UNBOUND_PROOF_TYPE (fail-closed, not a silent accept), but any "
            f"newly added predicate must be given an explicit binding "
            f"contract rather than relying on default-deny: {sorted(missing)}",
        )

    def test_no_stale_or_excluded_proof_type_in_the_registry(self):
        # The converse direction: _REQUEST_BINDINGS should not carry an entry
        # for a proof type no encoder declares (dead/stale binding), and
        # should not carry an entry for a proof type this test's exclusion
        # set says can never reach the chokepoint (which would mean either
        # the exclusion reasoning above is wrong, or the entry is dead code).
        declared = self._encoder_declared_proof_types()
        bound = set(_REQUEST_BINDINGS.keys())

        stale = bound - declared
        # Public source omits unpublished encoders while retaining the complete
        # runtime binding table. Private source still requires every binding's
        # encoder to be present. Both directions remain exact assertions.
        expected_unpublished = (
            UNPUBLISHED_REQUEST_PROOF_TYPES if IS_PUBLIC_SNAPSHOT else set()
        )
        self.assertEqual(
            stale, expected_unpublished,
            f"unexpected binding/encoder inventory difference: {sorted(stale)}",
        )

        wrongly_bound_exclusions = bound & self._EXCLUDED_PROOF_TYPES
        self.assertEqual(
            wrongly_bound_exclusions,
            set(),
            f"proof type(s) both in the justified exclusion set AND in "
            f"_REQUEST_BINDINGS -- update this test's exclusion reasoning, "
            f"it no longer matches the implementation: {sorted(wrongly_bound_exclusions)}",
        )


if __name__ == "__main__":
    unittest.main()

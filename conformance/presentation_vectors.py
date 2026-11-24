#!/usr/bin/env python3
"""Presentation-profile conformance vectors (design §8 matrix).

Every vector here runs through the REAL holder→verifier pipeline — the bundled
reference holder SDK generates a v2 ``presentationBinding`` envelope and the
reference verifier verifies it — never a hand-assembled envelope. Scoped
vectors negotiate scope via an *authenticated* APR so the holder derives
``scope_id`` itself from the APR signer key; cross-scope / scope-mismatch use
two DISTINCT verifier identities (APR A and APR B).

The machine-readable declaration of the same vectors lives in
``conformance/vectors/zkc_presentation.json``; ``run_presentation.py`` is the
CLI runner and ``tests/python/test_conformance.py`` asserts every vector passes.

TEST-ONLY key material throughout. Standard library only.
"""

from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "python") not in sys.path:
    sys.path.insert(0, str(ROOT / "python"))

from zkc_crypto import (  # noqa: E402
    ProofContext,
    compute_kyc_credential_digest,
    compute_profile_digest_v2,
    derive_holder_commitment_from_seed,
    digest_to_message_bytes,
    field_to_hex,
    hex_to_field,
    sign_apr,
)
from zkc_crypto.ecdsa_secp256k1 import N, public_key_bytes, sign  # noqa: E402
from zkc_crypto.presentation import (  # noqa: E402
    ANONYMOUS_PROFILE,
    SCOPED_PROFILE,
)
from zkc_holder import (  # noqa: E402
    Credential,
    HolderClient,
    LocalAccumulatorProvider,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
    TrustedIssuer,
)
from zkc_holder.predicates import PREDICATE_ACCREDITATION  # noqa: E402
from zkc_verifier import (  # noqa: E402
    IssuerAccumulatorState,
    StubVerifyBackend,
    VerificationErrorCode as Code,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)
from zkc_verifier import TrustedIssuer as VerifierTrustedIssuer  # noqa: E402

VECTORS_PATH = ROOT / "conformance" / "vectors" / "zkc_presentation.json"

# --- pinned TEST-ONLY material ------------------------------------------------

MASTER_SEED = 42
KYC_PROOF_TYPE = "zkc:proof:kyc:v1"
KYC_V2_PROOF_TYPE = "zkc:proof:kyc:v2"

# Safeguard 4: the v2 presentation siblings (for example zkc:proof:kyc:v2)
# are `draft` registry entries, which a default holder refuses. These vectors
# test presentation behaviour, so the reference holder opts in to draft
# entries explicitly through its accepted-status policy.
DRAFT_OPT_IN_REVIEW_STATUSES = ("reviewed", "self_attested", "draft")

TEST_ISSUER_ID = "did:zkc:test-issuer"
TEST_ISSUER_PRIVATE_KEY = (
    int.from_bytes(hashlib.sha256(b"zkc-test-issuer-v1").digest(), "big") % N
)
TEST_ISSUER_KEY_X, TEST_ISSUER_KEY_Y = public_key_bytes(TEST_ISSUER_PRIVATE_KEY)

# Two DISTINCT verifier identities for cross-scope / scope-mismatch vectors.
APR_VERIFIER_A_PRIVATE_KEY = (
    int.from_bytes(hashlib.sha256(b"zkc-presentation-apr-verifier-A").digest(), "big") % N
    or 1
)
APR_VERIFIER_B_PRIVATE_KEY = (
    int.from_bytes(hashlib.sha256(b"zkc-presentation-apr-verifier-B").digest(), "big") % N
    or 2
)

KYC_PARAMETERS = {
    "requiredLevel": 1,
    "requiredAttributes": [True, False, True, False, False],
}

# Public inputs of a v2 KYC proof that are ecosystem-wide / issuer-scoped —
# equal across two presentations of the same credential BY DESIGN (they carry
# no per-holder linking beyond "same issuer / same accumulator epoch"). Every
# other public input must be either session-scoped (differs across sessions) or
# an anonymous sentinel (constant 0, carrying no holder information).
ECOSYSTEM_WIDE_INPUTS = (
    "accumulator_root",
    "accumulator_epoch",
    "current_epoch",
    "issuer_public_key_x",
    "issuer_public_key_y",
)
ANONYMOUS_SENTINEL_INPUTS = ("presentation_pseudonym", "scope_id")

# Composite (multi-predicate) presentations: a conjunctive request
# "KYC AND accreditation" answered by one holder, or pooled from two.
ACCREDITATION_PROOF_TYPE = "zkc:proof:accreditation:v7"
ACCREDITATION_V8_PROOF_TYPE = "zkc:proof:accreditation:v8"
ACCREDITATION_PARAMETERS = {"required0": 2, "required1": 0}
ALICE_SEED = 0xA11CE  # holds ONLY a KYC credential
BOB_SEED = 0xB0B  # holds ONLY an accreditation credential
CAROL_SEED = 0xCA201  # holds both


class VectorFailure(Exception):
    """A conformance vector's real-pipeline assertion did not hold."""


# --- pipeline construction (real holder + real verifier) ----------------------


def _trusted_issuer_holder(proof_types) -> TrustedIssuer:
    return TrustedIssuer(
        issuer_id=TEST_ISSUER_ID,
        public_key_x=TEST_ISSUER_KEY_X,
        public_key_y=TEST_ISSUER_KEY_Y,
        proof_types=tuple(proof_types),
    )


def _trusted_issuer_verifier(proof_types) -> VerifierTrustedIssuer:
    return VerifierTrustedIssuer(
        issuer_id=TEST_ISSUER_ID,
        public_key_x=TEST_ISSUER_KEY_X,
        public_key_y=TEST_ISSUER_KEY_Y,
        proof_types=tuple(proof_types),
    )


def _issue_kyc_credential(
    provider: LocalAccumulatorProvider, credential_id: int, master_seed: int = MASTER_SEED
) -> Credential:
    holder_commitment = derive_holder_commitment_from_seed(master_seed)
    level = 2
    verified_attributes = [True, True, True, False, True]
    expires_at = 2_000_000_000
    digest = compute_kyc_credential_digest(
        holder_commitment, credential_id, level, verified_attributes, expires_at
    )
    signature = sign(digest_to_message_bytes(digest), TEST_ISSUER_PRIVATE_KEY)
    provider.register(TEST_ISSUER_ID, credential_id)
    return Credential(
        credential_type="zkc:kyc:v1",
        proof_type=KYC_PROOF_TYPE,
        issuer_id=TEST_ISSUER_ID,
        holder_commitment=holder_commitment,
        credential_id=credential_id,
        claims={"level": level, "verifiedAttributes": list(verified_attributes)},
        expires_at=expires_at,
        signature=signature,
    )


def _issue_accreditation_credential(
    provider: LocalAccumulatorProvider, credential_id: int, master_seed: int
) -> Credential:
    holder_commitment = derive_holder_commitment_from_seed(master_seed)
    level, institutional, valid_from, valid_until = 3, 0, 1_000, 2_000_000_000
    digest = compute_profile_digest_v2(
        holder_commitment,
        credential_id,
        PREDICATE_ACCREDITATION,
        level,
        institutional,
        valid_from,
        valid_until,
    )
    signature = sign(digest_to_message_bytes(digest), TEST_ISSUER_PRIVATE_KEY)
    provider.register(TEST_ISSUER_ID, credential_id)
    return Credential(
        credential_type="zkc:cred:accreditation:v2",
        proof_type=ACCREDITATION_PROOF_TYPE,
        issuer_id=TEST_ISSUER_ID,
        holder_commitment=holder_commitment,
        credential_id=credential_id,
        claims={
            "claim0": level,
            "claim1": institutional,
            "validFrom": valid_from,
            "validUntil": valid_until,
        },
        expires_at=valid_until,
        signature=signature,
    )


class Pipeline:
    """A real holder + reference verifier over one shared credential.

    A single holder stores one KYC credential; every presentation in a vector
    is a fresh authenticated exchange with that same credential, so equality
    joins across envelopes are testing the SAME holder/credential — exactly the
    cross-presentation linkability question the vectors probe.
    """

    def __init__(self):
        self._registry = PredicateRegistry.from_repo(ROOT)
        self._provider = LocalAccumulatorProvider()
        self._credential = _issue_kyc_credential(self._provider, credential_id=7)
        self._holder = HolderClient.from_seed(
            MASTER_SEED,
            self._registry,
            StubBackend(),
            accumulator_provider=self._provider,
            accepted_review_statuses=DRAFT_OPT_IN_REVIEW_STATUSES,
        )
        self._holder.store_credential(self._credential)
        self._current_epoch = self._provider.current_epoch(TEST_ISSUER_ID)

    # -- requests / APRs -------------------------------------------------------

    def _context(self, session_id: int, timestamp: int) -> ProofContext:
        return ProofContext.verifier_session("verifier.example", session_id, timestamp)

    def request(self, *, presentation_profile, session_id, timestamp,
                allow_protocol_scope=False) -> ProofRequest:
        return ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters={KYC_PROOF_TYPE: copy.deepcopy(KYC_PARAMETERS)},
            context=self._context(session_id, timestamp),
            # Authenticated anonymous/scoped negotiation emits the v2
            # statement, so issuer authorization covers that effective proof
            # type. Credential selection then uses the explicit v2-to-v1
            # stored-credential compatibility mapping.
            trust_policy=TrustPolicy(issuers=(_trusted_issuer_holder([KYC_V2_PROOF_TYPE]),)),
            presentation_profile=presentation_profile,
            allow_protocol_scope=allow_protocol_scope,
        )

    def apr(self, *, private_key, session_id, timestamp, nonce, presentation=None) -> dict:
        request = {
            "proofTypes": [KYC_PROOF_TYPE],
            "parameters": {KYC_PROOF_TYPE: copy.deepcopy(KYC_PARAMETERS)},
            "context": {
                "profile": "zkc:context:verifier-session:v1",
                "verifierId": "verifier.example",
                "sessionId": field_to_hex(session_id),
                "timestamp": timestamp,
            },
            "trustPolicy": {"issuers": []},
        }
        if presentation is not None:
            request["presentation"] = presentation
        unsigned = {
            "request": request,
            "verifierId": "verifier.example",
            "nonce": field_to_hex(nonce),
            "issuedAt": timestamp,
            "expiresAt": timestamp + 3600,
        }
        return sign_apr(unsigned, private_key)

    # -- generation (real holder) ----------------------------------------------

    def generate_anonymous(self, *, session_id, timestamp, nonce) -> dict:
        apr = self.apr(
            private_key=APR_VERIFIER_A_PRIVATE_KEY,
            session_id=session_id, timestamp=timestamp, nonce=nonce, presentation=None,
        )
        request = self.request(
            presentation_profile=ANONYMOUS_PROFILE, session_id=session_id, timestamp=timestamp,
        )
        return self._holder.generate_authenticated_proof(apr, request, now=request.context.timestamp)["envelope"]

    def generate_scoped(self, *, private_key, session_id, timestamp, nonce,
                        scope_policy="verifier", rotation_epoch_seconds=0,
                        allow_protocol_scope=False) -> dict:
        apr = self.apr(
            private_key=private_key, session_id=session_id, timestamp=timestamp, nonce=nonce,
            presentation={
                "profile": SCOPED_PROFILE,
                "scopePolicy": scope_policy,
                "rotationEpochSeconds": rotation_epoch_seconds,
            },
        )
        request = self.request(
            presentation_profile=SCOPED_PROFILE, session_id=session_id, timestamp=timestamp,
            allow_protocol_scope=allow_protocol_scope,
        )
        return self._holder.generate_authenticated_proof(apr, request, now=request.context.timestamp)["envelope"]

    # -- verification (reference verifier) -------------------------------------

    def _verification_request(self, *, session_id, timestamp) -> VerificationRequest:
        return VerificationRequest(
            proof_types=[KYC_V2_PROOF_TYPE],
            parameters={KYC_V2_PROOF_TYPE: copy.deepcopy(KYC_PARAMETERS)},
            context=self._context(session_id, timestamp),
            max_proof_age=3600,
            accumulator_states={
                TEST_ISSUER_ID: IssuerAccumulatorState(
                    current_epoch=self._current_epoch,
                    roots=self._provider.roots(TEST_ISSUER_ID),
                )
            },
        )

    def _verifier(self, *, accepted_profiles=None,
                  private_key=APR_VERIFIER_A_PRIVATE_KEY) -> ZKCVerifier:
        key_x, key_y = public_key_bytes(private_key)
        policy = VerifierTrustPolicy(
            issuers=(_trusted_issuer_verifier([KYC_V2_PROOF_TYPE]),),
            accepted_profiles=accepted_profiles,
            verifier_id="verifier.example",
            verifier_signing_keys=(bytes([2 + (key_y[-1] & 1)]) + key_x,),
        )
        return ZKCVerifier(ROOT, policy, StubVerifyBackend())

    def verify(self, envelope, *, session_id, timestamp, accepted_profiles=None):
        verifier = self._verifier(accepted_profiles=accepted_profiles)
        return verifier.verify(
            envelope, self._verification_request(session_id=session_id, timestamp=timestamp)
        )

    def verify_authenticated(self, apr, envelope, *, session_id, timestamp,
                             private_key=APR_VERIFIER_A_PRIVATE_KEY):
        verifier = self._verifier(private_key=private_key)
        return verifier.verify_authenticated(
            apr, envelope, self._verification_request(session_id=session_id, timestamp=timestamp),
            now=timestamp
        )


class CompositePipeline:
    """Three real holders under ONE issuer accumulator, answering the
    conjunctive request "KYC(level>=1) AND accreditation(level>=2)".

    Alice holds only KYC, Bob only accreditation -- neither can answer alone --
    and Carol holds both. Every exchange is a real authenticated holder run.
    """

    TYPES = (KYC_PROOF_TYPE, ACCREDITATION_PROOF_TYPE)
    PARAMETERS = {
        KYC_PROOF_TYPE: KYC_PARAMETERS,
        ACCREDITATION_PROOF_TYPE: ACCREDITATION_PARAMETERS,
    }
    EFFECTIVE = {
        KYC_PROOF_TYPE: KYC_V2_PROOF_TYPE,
        ACCREDITATION_PROOF_TYPE: ACCREDITATION_V8_PROOF_TYPE,
    }

    def __init__(self):
        self._registry = PredicateRegistry.from_repo(ROOT)
        self._provider = LocalAccumulatorProvider()
        self.alice = self._holder(ALICE_SEED, [_issue_kyc_credential(self._provider, 11, ALICE_SEED)])
        self.bob = self._holder(
            BOB_SEED, [_issue_accreditation_credential(self._provider, 12, BOB_SEED)]
        )
        self.carol = self._holder(
            CAROL_SEED,
            [
                _issue_kyc_credential(self._provider, 13, CAROL_SEED),
                _issue_accreditation_credential(self._provider, 14, CAROL_SEED),
            ],
        )

    def _holder(self, seed, credentials) -> HolderClient:
        holder = HolderClient.from_seed(
            seed,
            self._registry,
            StubBackend(),
            accumulator_provider=self._provider,
            accepted_review_statuses=DRAFT_OPT_IN_REVIEW_STATUSES,
        )
        for credential in credentials:
            holder.store_credential(credential)
        return holder

    @staticmethod
    def context(session_id: int, timestamp: int) -> ProofContext:
        return ProofContext.verifier_session("verifier.example", session_id, timestamp)

    def apr(self, proof_types, *, session_id, timestamp, nonce, presentation,
            private_key=APR_VERIFIER_A_PRIVATE_KEY) -> dict:
        request = {
            "proofTypes": list(proof_types),
            "parameters": {pt: copy.deepcopy(self.PARAMETERS[pt]) for pt in proof_types},
            "context": {
                "profile": "zkc:context:verifier-session:v1",
                "verifierId": "verifier.example",
                "sessionId": field_to_hex(session_id),
                "timestamp": timestamp,
            },
            "trustPolicy": {"issuers": []},
            "presentation": presentation,
        }
        return sign_apr(
            {
                "request": request,
                "verifierId": "verifier.example",
                "nonce": field_to_hex(nonce),
                "issuedAt": timestamp,
                "expiresAt": timestamp + 3600,
            },
            private_key,
        )

    def proof_request(
        self, proof_types, *, session_id, timestamp, profile, allow_unlinked_composite=False
    ) -> ProofRequest:
        return ProofRequest(
            proof_types=list(proof_types),
            parameters={pt: copy.deepcopy(self.PARAMETERS[pt]) for pt in proof_types},
            context=self.context(session_id, timestamp),
            trust_policy=TrustPolicy(
                issuers=(_trusted_issuer_holder(list(self.EFFECTIVE.values())),)
            ),
            presentation_profile=profile,
            allow_unlinked_composite=allow_unlinked_composite,
        )

    def generate(
        self, holder, proof_types, *, presentation, session_id, timestamp, nonce,
        holder_profile=None, allow_unlinked_composite=False, consents=None,
        private_key=APR_VERIFIER_A_PRIVATE_KEY,
    ):
        """Answer the signed APR. The holder's ceiling defaults to the APR's
        profile; ``allow_unlinked_composite`` is the holder's explicit opt-in to
        answer several proofs anonymously (spec 5.9.2 rule 5), which the
        reference holder otherwise refuses before proving."""
        apr = self.apr(
            proof_types, session_id=session_id, timestamp=timestamp, nonce=nonce,
            presentation=presentation,
            private_key=private_key,
        )
        request = self.proof_request(
            proof_types, session_id=session_id, timestamp=timestamp,
            profile=presentation["profile"] if holder_profile is None else holder_profile,
            allow_unlinked_composite=allow_unlinked_composite,
        )
        if consents is None:
            consents = {pt: True for pt in proof_types}
        return holder.generate_authenticated_proof(apr, request, consents=consents, now=request.context.timestamp)["envelope"]

    def verification_request(self, *, session_id, timestamp) -> VerificationRequest:
        return VerificationRequest(
            proof_types=[self.EFFECTIVE[pt] for pt in self.TYPES],
            parameters={
                self.EFFECTIVE[pt]: copy.deepcopy(self.PARAMETERS[pt]) for pt in self.TYPES
            },
            context=self.context(session_id, timestamp),
            max_proof_age=3600,
            accumulator_states={
                TEST_ISSUER_ID: IssuerAccumulatorState(
                    current_epoch=self._provider.current_epoch(TEST_ISSUER_ID),
                    roots=self._provider.roots(TEST_ISSUER_ID),
                )
            },
        )

    @staticmethod
    def verifier(*, private_key=APR_VERIFIER_A_PRIVATE_KEY, **policy) -> ZKCVerifier:
        key_x, key_y = public_key_bytes(private_key)
        return ZKCVerifier(
            ROOT,
            VerifierTrustPolicy(
                verifier_id="verifier.example",
                verifier_signing_keys=(bytes([2 + (key_y[-1] & 1)]) + key_x,),
                issuers=(
                    _trusted_issuer_verifier(
                        [KYC_V2_PROOF_TYPE, ACCREDITATION_V8_PROOF_TYPE]
                    ),
                ),
                **policy,
            ),
            StubVerifyBackend(),
        )


def _splice(first: dict, second: dict) -> dict:
    merged = copy.deepcopy(first)
    merged["proofs"] = copy.deepcopy(first["proofs"]) + copy.deepcopy(second["proofs"])
    return merged


def _pseudonym(envelope: dict) -> int:
    return hex_to_field(envelope["presentationBinding"]["pseudonym"])


SESSION_SCOPED = {"profile": SCOPED_PROFILE, "scopePolicy": "session", "rotationEpochSeconds": 0}
ANONYMOUS = {"profile": ANONYMOUS_PROFILE}


# --- per-vector public-input helpers ------------------------------------------


def _kyc_public_inputs(envelope: dict) -> dict:
    proofs = [p for p in envelope["proofs"] if p["proofType"] == KYC_V2_PROOF_TYPE]
    if len(proofs) != 1:
        raise VectorFailure(f"expected exactly one {KYC_V2_PROOF_TYPE} proof, got {len(proofs)}")
    return proofs[0]["publicInputs"]


def _expect_valid(result, vector_id: str) -> None:
    if not result.valid:
        raise VectorFailure(f"{vector_id}: expected the envelope to VERIFY, got codes={result.codes()}")


def _expect_code(result, code: str, vector_id: str) -> None:
    if result.valid or code not in result.codes():
        raise VectorFailure(
            f"{vector_id}: expected rejection with {code}, got valid={result.valid} codes={result.codes()}"
        )


# --- the eight vectors --------------------------------------------------------


def vector_anonymous_unlinkable() -> None:
    """positive: two anonymous presentations share no holder-derived value."""
    pipe = Pipeline()
    env_a = pipe.generate_anonymous(session_id=101, timestamp=1_700_000_000, nonce=0xA1)
    env_b = pipe.generate_anonymous(session_id=202, timestamp=1_700_000_500, nonce=0xA2)

    _expect_valid(pipe.verify(env_a, session_id=101, timestamp=1_700_000_000), "presentation-anonymous-unlinkable")
    _expect_valid(pipe.verify(env_b, session_id=202, timestamp=1_700_000_500), "presentation-anonymous-unlinkable")

    pub_a = _kyc_public_inputs(env_a)
    pub_b = _kyc_public_inputs(env_b)
    zero = field_to_hex(0)

    # No holder-derived handle: both pseudonym and scope_id are the sentinel.
    for pub in (pub_a, pub_b):
        if pub["presentation_pseudonym"] != zero or pub["scope_id"] != zero:
            raise VectorFailure("anonymous presentation must carry the sentinel pseudonym/scope_id")
        if "holder_commitment" in pub:
            raise VectorFailure("v2 anonymous public inputs must not surface holder_commitment")

    # The two envelopes must NOT share any credential-derived public value. The
    # sentinels + ecosystem-wide inputs may (and must) repeat; nothing else may.
    allowed_equal = set(ANONYMOUS_SENTINEL_INPUTS) | set(ECOSYSTEM_WIDE_INPUTS)
    for name in pub_a:
        if pub_a[name] == pub_b[name] and name not in allowed_equal:
            raise VectorFailure(
                f"anonymous presentations unexpectedly share public input {name!r} "
                "(a repeated value here would be a cross-presentation linkability leak)"
            )


def vector_scoped_cross_scope() -> None:
    """negative: two DISTINCT scopes => different pseudonyms; join fails."""
    pipe = Pipeline()
    # Two distinct verifiers run two distinct sessions (distinct verifier
    # identity AND distinct session/timestamp — the real colluding-verifier
    # setting), so the ONLY thing linking the two envelopes would be a repeated
    # holder-derived value. There must be none.
    env_a = pipe.generate_scoped(
        private_key=APR_VERIFIER_A_PRIVATE_KEY, session_id=301, timestamp=1_700_000_000, nonce=0xB1,
    )
    env_b = pipe.generate_scoped(
        private_key=APR_VERIFIER_B_PRIVATE_KEY, session_id=302, timestamp=1_700_000_400, nonce=0xB2,
    )
    pub_a = _kyc_public_inputs(env_a)
    pub_b = _kyc_public_inputs(env_b)

    # The equality join a colluding pair of verifiers would attempt MUST fail.
    if pub_a["presentation_pseudonym"] == pub_b["presentation_pseudonym"]:
        raise VectorFailure(
            "cross-scope pseudonyms are EQUAL — the same credential is linkable across scopes"
        )
    if pub_a["scope_id"] == pub_b["scope_id"]:
        raise VectorFailure("distinct verifier scopes produced the same scope_id")
    # And no per-holder public value repeats across the two scoped envelopes:
    # only ecosystem-wide/issuer inputs (same issuer, same accumulator epoch)
    # may legitimately coincide.
    for name in pub_a:
        if pub_a[name] == pub_b[name] and name not in ECOSYSTEM_WIDE_INPUTS:
            raise VectorFailure(
                f"cross-scope presentations unexpectedly share public input {name!r}"
            )


def vector_scoped_within_scope() -> None:
    """positive: same scope, two sessions => same pseudonym (repeat recognition)."""
    pipe = Pipeline()
    env_1 = pipe.generate_scoped(
        private_key=APR_VERIFIER_A_PRIVATE_KEY, session_id=401, timestamp=1_700_000_000, nonce=0xC1,
    )
    env_2 = pipe.generate_scoped(
        private_key=APR_VERIFIER_A_PRIVATE_KEY, session_id=402, timestamp=1_700_000_900, nonce=0xC2,
    )
    _expect_valid(pipe.verify(env_1, session_id=401, timestamp=1_700_000_000), "presentation-scoped-within-scope")
    _expect_valid(pipe.verify(env_2, session_id=402, timestamp=1_700_000_900), "presentation-scoped-within-scope")

    pub_1 = _kyc_public_inputs(env_1)
    pub_2 = _kyc_public_inputs(env_2)
    # Same scope => same scope_id and same pseudonym (the verifier CAN recognize
    # the returning holder within its own scope — that is the point of scoped).
    if pub_1["scope_id"] != pub_2["scope_id"]:
        raise VectorFailure("same-scope presentations produced different scope_ids")
    if pub_1["presentation_pseudonym"] != pub_2["presentation_pseudonym"]:
        raise VectorFailure("same-scope presentations produced different pseudonyms")
    # But the sessions must still be distinct (claim_binding tracks the session).
    if pub_1["claim_binding"] == pub_2["claim_binding"]:
        raise VectorFailure("two sessions must not share a claim_binding")


def vector_scoped_rotation() -> None:
    """positive: two rotation epochs => different pseudonyms."""
    pipe = Pipeline()
    # rotation epoch = floor(timestamp / rotationEpochSeconds); two timestamps
    # straddling the rotation boundary land in different epochs.
    period = 1_000_000
    ts_epoch_1 = 1_700_000_000  # floor(1_700_000_000 / 1_000_000) = 1700
    ts_epoch_2 = 1_701_000_000  # floor(1_701_000_000 / 1_000_000) = 1701
    env_1 = pipe.generate_scoped(
        private_key=APR_VERIFIER_A_PRIVATE_KEY, session_id=501, timestamp=ts_epoch_1, nonce=0xD1,
        rotation_epoch_seconds=period,
    )
    env_2 = pipe.generate_scoped(
        private_key=APR_VERIFIER_A_PRIVATE_KEY, session_id=502, timestamp=ts_epoch_2, nonce=0xD2,
        rotation_epoch_seconds=period,
    )
    pub_1 = _kyc_public_inputs(env_1)
    pub_2 = _kyc_public_inputs(env_2)
    if pub_1["scope_id"] == pub_2["scope_id"]:
        raise VectorFailure("two rotation epochs produced the same scope_id")
    if pub_1["presentation_pseudonym"] == pub_2["presentation_pseudonym"]:
        raise VectorFailure(
            "two rotation epochs produced the same pseudonym — rotation did not unlink"
        )


def vector_profile_replay() -> None:
    """negative: scoped proof under anonymous binding => PROFILE_MISMATCH."""
    pipe = Pipeline()
    scoped = pipe.generate_scoped(
        private_key=APR_VERIFIER_A_PRIVATE_KEY, session_id=601, timestamp=1_700_000_000, nonce=0xE1,
    )
    anonymous = pipe.generate_anonymous(session_id=601, timestamp=1_700_000_000, nonce=0xE2)
    # Splice the scoped proof entries under the anonymous presentationBinding:
    # the profile (anonymous) no longer matches the proof shape (scoped).
    forged = copy.deepcopy(anonymous)
    forged["proofs"] = copy.deepcopy(scoped["proofs"])
    result = pipe.verify(forged, session_id=601, timestamp=1_700_000_000)
    _expect_code(result, Code.PROFILE_MISMATCH, "presentation-profile-replay")


def vector_scope_mismatch() -> None:
    """negative: scope-A proof to authenticated verifier B => SCOPE_MISMATCH."""
    pipe = Pipeline()
    apr_a = pipe.apr(
        private_key=APR_VERIFIER_A_PRIVATE_KEY, session_id=701, timestamp=1_700_000_000, nonce=0xF1,
        presentation={"profile": SCOPED_PROFILE, "scopePolicy": "verifier", "rotationEpochSeconds": 0},
    )
    request = pipe.request(
        presentation_profile=SCOPED_PROFILE, session_id=701, timestamp=1_700_000_000,
    )
    envelope = pipe._holder.generate_authenticated_proof(apr_a, request, now=request.context.timestamp)["envelope"]
    # Present the scope-A envelope under verifier B's own (validly signed) APR:
    # B recomputes scope_id from its OWN identity and gets a different value.
    apr_b = pipe.apr(
        private_key=APR_VERIFIER_B_PRIVATE_KEY, session_id=701, timestamp=1_700_000_000, nonce=0xF2,
        presentation={"profile": SCOPED_PROFILE, "scopePolicy": "verifier", "rotationEpochSeconds": 0},
    )
    result = pipe.verify_authenticated(apr_b, envelope, session_id=701, timestamp=1_700_000_000,
                                       private_key=APR_VERIFIER_B_PRIVATE_KEY)
    _expect_code(result, Code.SCOPE_MISMATCH, "presentation-scope-mismatch")


def vector_profile_not_accepted() -> None:
    """negative: v2 profile not in accepted_profiles => PROFILE_NOT_ACCEPTED."""
    pipe = Pipeline()
    scoped = pipe.generate_scoped(
        private_key=APR_VERIFIER_A_PRIVATE_KEY, session_id=801, timestamp=1_700_000_000, nonce=0x11,
    )
    # A verifier accepting ONLY the anonymous profile refuses a scoped envelope.
    result = pipe.verify(
        scoped, session_id=801, timestamp=1_700_000_000, accepted_profiles=(ANONYMOUS_PROFILE,),
    )
    _expect_code(result, Code.PROFILE_NOT_ACCEPTED, "presentation-profile-not-accepted")


def vector_determinism_invariant() -> None:
    """invariant: only ecosystem-wide + sentinel inputs repeat; claim_binding differs."""
    pipe = Pipeline()
    env_a = pipe.generate_anonymous(session_id=901, timestamp=1_700_000_000, nonce=0x21)
    env_b = pipe.generate_anonymous(session_id=902, timestamp=1_700_000_777, nonce=0x22)
    pub_a = _kyc_public_inputs(env_a)
    pub_b = _kyc_public_inputs(env_b)

    equal = {name for name in pub_a if pub_a[name] == pub_b[name]}
    differ = {name for name in pub_a if pub_a[name] != pub_b[name]}
    allowed_equal = set(ECOSYSTEM_WIDE_INPUTS) | set(ANONYMOUS_SENTINEL_INPUTS)

    unexpected_equal = equal - allowed_equal
    if unexpected_equal:
        raise VectorFailure(
            f"public inputs unexpectedly equal across sessions: {sorted(unexpected_equal)} "
            "(deterministic in credential-only material => a linkability leak)"
        )
    # The ecosystem-wide inputs and sentinels MUST actually be present + equal
    # (proving the invariant has teeth: it is not vacuously satisfied).
    for name in allowed_equal:
        if name not in equal:
            raise VectorFailure(
                f"expected ecosystem-wide/sentinel input {name!r} to be equal across sessions"
            )
    # claim_binding MUST differ: its preimage retains proof_context + timestamp,
    # which differ across sessions (the ADR determinism invariant, design §8).
    if "claim_binding" not in differ:
        raise VectorFailure(
            "claim_binding did not differ across sessions — its preimage must retain "
            "proof_context + timestamp so it is session-scoped, not credential-deterministic"
        )
    if pub_a["proof_context"] == pub_b["proof_context"] or pub_a["timestamp"] == pub_b["timestamp"]:
        raise VectorFailure("the two sessions must have distinct proof_context and timestamp")


def vector_anonymous_composite_pooling() -> None:
    """negative: two holders' anonymous proofs pooled into one conjunctive answer."""
    vector_id = "presentation-anonymous-composite-pooling"
    pipe = CompositePipeline()
    session, timestamp = 1001, 1_700_000_000
    alice = pipe.generate(
        pipe.alice, (KYC_PROOF_TYPE,), presentation=ANONYMOUS,
        session_id=session, timestamp=timestamp, nonce=0x31,
    )
    bob = pipe.generate(
        pipe.bob, (ACCREDITATION_PROOF_TYPE,), presentation=ANONYMOUS,
        session_id=session, timestamp=timestamp, nonce=0x32,
    )
    pooled = _splice(alice, bob)
    request = pipe.verification_request(session_id=session, timestamp=timestamp)
    _expect_code(pipe.verifier().verify(pooled, request), Code.UNBOUND_COMPOSITE, vector_id)
    apr = pipe.apr(
        pipe.TYPES, session_id=session, timestamp=timestamp, nonce=0x33, presentation=ANONYMOUS
    )
    _expect_code(
        pipe.verifier().verify_authenticated(apr, pooled, request, now=request.context.timestamp),
        Code.UNBOUND_COMPOSITE,
        vector_id,
    )


def vector_session_scoped_composite() -> None:
    """positive: one holder answers both conjuncts under one session-scoped pseudonym;
    the same pooling splice under that scope is PROFILE_MISMATCH."""
    vector_id = "presentation-session-scoped-composite"
    pipe = CompositePipeline()
    session, timestamp = 1101, 1_700_000_000
    carol = pipe.generate(
        pipe.carol, pipe.TYPES, presentation=SESSION_SCOPED,
        session_id=session, timestamp=timestamp, nonce=0x41,
    )
    apr = pipe.apr(
        pipe.TYPES, session_id=session, timestamp=timestamp, nonce=0x41,
        presentation=SESSION_SCOPED,
    )
    request = pipe.verification_request(session_id=session, timestamp=timestamp)
    _expect_valid(pipe.verifier().verify_authenticated(apr, carol, request, now=request.context.timestamp), vector_id)
    alice = pipe.generate(
        pipe.alice, (KYC_PROOF_TYPE,), presentation=SESSION_SCOPED,
        session_id=session, timestamp=timestamp, nonce=0x42,
    )
    bob = pipe.generate(
        pipe.bob, (ACCREDITATION_PROOF_TYPE,), presentation=SESSION_SCOPED,
        session_id=session, timestamp=timestamp, nonce=0x43,
    )
    _expect_code(
        pipe.verifier().verify_authenticated(apr, _splice(alice, bob), request, now=request.context.timestamp),
        Code.PROFILE_MISMATCH,
        vector_id,
    )


def vector_session_scope_unlinkable() -> None:
    """positive: the session scope gives two sessions of the same holder (and the
    same verifier) unrelated scopes and pseudonyms; both verify."""
    vector_id = "presentation-session-scope-unlinkable"
    pipe = CompositePipeline()
    envelopes = []
    for session, timestamp, nonce in ((1201, 1_700_000_000, 0x51), (1202, 1_700_000_600, 0x52)):
        envelope = pipe.generate(
            pipe.carol, pipe.TYPES, presentation=SESSION_SCOPED,
            session_id=session, timestamp=timestamp, nonce=nonce,
        )
        apr = pipe.apr(
            pipe.TYPES, session_id=session, timestamp=timestamp, nonce=nonce,
            presentation=SESSION_SCOPED,
        )
        _expect_valid(
            pipe.verifier().verify_authenticated(
                apr, envelope, pipe.verification_request(session_id=session, timestamp=timestamp),
                now=timestamp
            ),
            vector_id,
        )
        envelopes.append(envelope)
    # Same context under a different independently configured verifier key.
    session, timestamp, nonce = 1201, 1_700_000_000, 0x53
    foreign = pipe.generate(
        pipe.carol, pipe.TYPES, presentation=SESSION_SCOPED,
        session_id=session, timestamp=timestamp, nonce=nonce,
        private_key=APR_VERIFIER_B_PRIVATE_KEY,
    )
    apr = pipe.apr(
        pipe.TYPES, session_id=session, timestamp=timestamp, nonce=nonce,
        presentation=SESSION_SCOPED, private_key=APR_VERIFIER_B_PRIVATE_KEY,
    )
    _expect_valid(pipe.verifier(private_key=APR_VERIFIER_B_PRIVATE_KEY).verify_authenticated(
        apr, foreign, pipe.verification_request(session_id=session, timestamp=timestamp),
        now=timestamp), vector_id)
    envelopes.append(foreign)
    if len({item["presentationBinding"]["scopeId"] for item in envelopes}) != len(envelopes):
        raise VectorFailure(f"{vector_id}: sessions/verifiers derived the same scope")
    if len({_pseudonym(item) for item in envelopes}) != len(envelopes):
        raise VectorFailure(f"{vector_id}: sessions/verifiers share a pseudonym (linkable)")
    for envelope in envelopes:
        handles = {entry["publicInputs"]["presentation_pseudonym"] for entry in envelope["proofs"]}
        if len(handles) != 1:
            raise VectorFailure(f"{vector_id}: one session's answers carry different pseudonyms")


_VECTORS = {
    "presentation-anonymous-unlinkable": vector_anonymous_unlinkable,
    "presentation-scoped-cross-scope": vector_scoped_cross_scope,
    "presentation-scoped-within-scope": vector_scoped_within_scope,
    "presentation-scoped-rotation": vector_scoped_rotation,
    "presentation-profile-replay": vector_profile_replay,
    "presentation-scope-mismatch": vector_scope_mismatch,
    "presentation-profile-not-accepted": vector_profile_not_accepted,
    "presentation-determinism-invariant": vector_determinism_invariant,
    "presentation-anonymous-composite-pooling": vector_anonymous_composite_pooling,
    "presentation-session-scoped-composite": vector_session_scoped_composite,
    "presentation-session-scope-unlinkable": vector_session_scope_unlinkable,
}


def declared_vector_ids() -> list:
    """The vector ids declared in the machine-readable spec (source of truth)."""
    spec = json.loads(VECTORS_PATH.read_text())
    return [entry["id"] for entry in spec["vectors"]]


def run_all() -> list:
    """Run every declared vector through the real pipeline; structured results.

    The declared spec is the source of truth for the id set, so a spec/runner
    drift (a declared vector with no implementation, or vice versa) surfaces as
    a FAIL here rather than silently skipping.
    """
    declared = declared_vector_ids()
    results = []
    for vector_id in declared:
        runner = _VECTORS.get(vector_id)
        if runner is None:
            results.append({
                "id": vector_id, "status": "FAIL",
                "reason": "declared in zkc_presentation.json but no pipeline runner is implemented",
            })
            continue
        try:
            runner()
            results.append({"id": vector_id, "status": "PASS"})
        except VectorFailure as exc:
            results.append({"id": vector_id, "status": "FAIL", "reason": str(exc)})
        except Exception as exc:  # a pipeline crash is a failure, never a pass
            results.append({
                "id": vector_id, "status": "FAIL",
                "reason": f"pipeline raised {type(exc).__name__}: {exc}",
            })
    # Catch an implemented-but-undeclared runner too (drift the other way).
    for vector_id in _VECTORS:
        if vector_id not in declared:
            results.append({
                "id": vector_id, "status": "FAIL",
                "reason": "implemented pipeline runner is not declared in zkc_presentation.json",
            })
    return results

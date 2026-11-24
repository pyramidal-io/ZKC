"""Reference adapters: the bundled holder SDK + verifier library.

These adapters define the canonical mapping from conformance fixture formats
to implementation inputs; third-party adapters should mirror this mapping.
Deterministic (stub proof backends) so the suite runs without the Noir
toolchain.
"""

from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "python") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "python"))

from zkc_crypto import (  # noqa: E402
    LINKABLE_PROFILE,
    PURPOSE_BOUND_PROFILE,
    ProofContext,
    apr_signer_pubkey,
    derive_verifier_identity,
    hex_to_field,
    verify_receipt as crypto_verify_receipt,
)
from zkc_holder import (  # noqa: E402
    Credential,
    HolderClient,
    HolderError,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
    TrustedIssuer,
)
from zkc_verifier import (  # noqa: E402
    IssuerAccumulatorState,
    StubVerifyBackend,
    TrustedIssuer as VerifierTrustedIssuer,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)


def _context_from_fixture(fixture: dict) -> ProofContext:
    if fixture.get("profile") == PURPOSE_BOUND_PROFILE:
        return ProofContext.purpose_bound(
            fixture["verifierId"],
            hex_to_field(fixture["sessionId"]),
            fixture["purpose"],
            fixture["timestamp"],
        )
    return ProofContext.verifier_session(
        fixture["verifierId"],
        hex_to_field(fixture["sessionId"]),
        fixture["timestamp"],
    )


def _issuer_tuple(policy_fixture: dict, cls):
    return tuple(
        cls(
            issuer_id=entry["issuerId"],
            public_key_x=bytes.fromhex(entry["publicKeyX"].removeprefix("0x")),
            public_key_y=bytes.fromhex(entry["publicKeyY"].removeprefix("0x")),
            proof_types=tuple(entry["proofTypes"]),
        )
        for entry in policy_fixture["issuers"]
    )


def _proof_request(request: dict) -> ProofRequest:
    # The published ZKC-Core vectors exercise the frozen linkable
    # ``zkc:proof:v1`` envelope while using each predicate family's current
    # linkable proof type (including remaining-predicate v7). Anonymous/scoped
    # ``zkc:proof:v2`` presentationBinding flows carry their own
    # presentation vectors (design §8). The holder SDK default is anonymous.
    return ProofRequest(
        proof_types=list(request["proofTypes"]),
        parameters=request.get("parameters", {}),
        context=_context_from_fixture(request["context"]),
        trust_policy=TrustPolicy(issuers=_issuer_tuple(request["trustPolicy"], TrustedIssuer)),
        max_proof_age=int(request.get("maxProofAge", 3600)),
        current_epochs={
            issuer_id: int(state["currentEpoch"])
            for issuer_id, state in request.get("accumulatorStates", {}).items()
        },
        presentation_profile=LINKABLE_PROFILE,
    )


def _verification_request(request: dict) -> VerificationRequest:
    return VerificationRequest(
        proof_types=list(request["proofTypes"]),
        parameters=request.get("parameters", {}),
        context=_context_from_fixture(request["context"]),
        max_proof_age=int(request.get("maxProofAge", 3600)),
        accumulator_states={
            issuer_id: IssuerAccumulatorState.from_dict(state)
            for issuer_id, state in request.get("accumulatorStates", {}).items()
        },
    )


def _receipt_anchor(client: HolderClient, apr: dict, receipt: dict) -> dict:
    """The holder's out-of-band receipt-key anchor (spec 5.6.1).

    ``client`` answered exactly one request. If it answered through the
    logged unauthenticated override, the receipt has a fresh key whatever its
    response shape. Otherwise a scoped receipt's key derives from its scope
    and a linkable receipt's from the APR signer, both re-derived from the
    seed. A fresh key (anonymous or unauthenticated) can never be derived
    again; the only anchor is the holder's own assertion of the key in its
    receipt."""
    authenticated = not any(
        record.get("kind") == "UNAUTHENTICATED" for record in client.override_log
    )
    response = receipt.get("response") or {}
    if authenticated and "scopeId" in response:
        return client.receipt_public_key(scope_id=hex_to_field(response["scopeId"]))
    if authenticated and "holderCommitment" in response:
        return client.receipt_public_key(
            verifier_identity=derive_verifier_identity(apr_signer_pubkey(apr))
        )
    return dict(receipt["holderSignature"]["holderKey"])


class ReferenceHolderAdapter:
    def _client(self, credentials: list, master_seed: str) -> HolderClient:
        registry = PredicateRegistry.from_repo(REPO_ROOT)
        client = HolderClient.from_seed(hex_to_field(master_seed), registry, StubBackend())
        for fixture in credentials:
            client.store_credential(Credential.from_dict(fixture))
        return client

    def generate(self, request: dict, credentials: list, master_seed: str) -> dict:
        try:
            client = self._client(credentials, master_seed)
            # The ZKC-Core generation vectors carry no APR and exercise the
            # frozen linkable v1 envelope: the adapter (as the holder) gives
            # the explicit, logged Safeguard 6 opt-in and the explicit
            # linkable consent. Neither is the SDK default; the safeguard-6-*
            # cases cover the default refusal.
            return {
                "envelope": client.generate_proof(
                    _proof_request(request),
                    allow_unauthenticated=True,
                    allow_linkable=True,
                    exact_member_consents=request.get("holderExactMemberConsents"),
                )
            }
        except HolderError as exc:
            return {"refusal": {"code": exc.code, "message": exc.message}}

    def generate_authenticated(
        self, request: dict, apr: dict, credentials: list, master_seed: str
    ) -> dict:
        """Answer an Authenticated Proof Request (Safeguard 6, §5.5–§5.6)."""
        try:
            client = self._client(credentials, master_seed)
            proof_request = _proof_request(request)
            result = client.generate_authenticated_proof(
                apr, proof_request, now=proof_request.context.timestamp
            )
            result["receiptHolderKey"] = _receipt_anchor(client, apr, result["receipt"])
            return result
        except HolderError as exc:
            return {"refusal": {"code": exc.code, "message": exc.message}}

    def answer_hosted(
        self, request: dict, apr: dict, credentials: list, master_seed: str
    ) -> dict:
        """Hosted-SDK answer that retains nothing (Safeguard 6 non-custody)."""
        try:
            client = self._client(credentials, master_seed)
            proof_request = _proof_request(request)
            return client.answer_as_hosted_service(
                apr, proof_request, now=proof_request.context.timestamp
            )
        except HolderError as exc:
            return {
                "refusal": {"code": exc.code, "message": exc.message},
                "retained": False,
                "custody": "holder",
            }


class ReferenceVerifierAdapter:
    def __init__(self):
        self._seen_nonces = set()

    def _verifier(self, request: dict) -> ZKCVerifier:
        return ZKCVerifier(
            REPO_ROOT,
            VerifierTrustPolicy(
                issuers=_issuer_tuple(request["trustPolicy"], VerifierTrustedIssuer),
                verifier_id="verifier.example",
                # Independent public fixture pin, derived from the documented
                # zkc-conformance-apr-verifier-v1 TEST-ONLY key, never the APR.
                verifier_signing_keys=(bytes.fromhex(
                    "0353a91be6284a158b137f9b0cc0da67618955f91e05b3d65afa086330dac8028b"
                ),),
            ),
            StubVerifyBackend(),
        )

    def verify(self, envelope: dict, request: dict) -> dict:
        result = self._verifier(request).verify(envelope, _verification_request(request))
        return {"valid": result.valid, "codes": result.codes()}

    def verify_authenticated(self, envelope: dict, request: dict, apr: dict) -> dict:
        """Authenticated verification path (Safeguard 6, §6.2 step 0)."""
        result = self._verifier(request).verify_authenticated(
            apr, envelope, _verification_request(request), seen_nonces=self._seen_nonces,
            now=request["context"]["timestamp"]
        )
        return {"valid": result.valid, "codes": result.codes()}

    def verify_receipt(self, receipt: dict, *, expected_holder_key: dict = None) -> dict:
        """Third-party Disclosure Receipt verification (§5.6). No verifier
        state, no operator, no issuer — the signatures in the receipt plus
        the holder key the relying party anchors out of band (§5.6.1)."""
        return crypto_verify_receipt(receipt, expected_holder_key=expected_holder_key)


def make_holder_adapter():
    return ReferenceHolderAdapter()


def make_verifier_adapter():
    return ReferenceVerifierAdapter()

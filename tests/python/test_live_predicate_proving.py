"""Live predicate proving: holder SDK -> real nargo+bb proof -> bb verify.

Generates a REAL UltraHonk proof for each non-KYC predicate via NargoBackend
and verifies it with BBVerifyBackend against the compiled circuit. Requires the
pinned Noir toolchain (`nargo` + `bb`) on PATH and skips otherwise. The focused
independent dynamic re-verification case runs in the pinned-toolchain artifact
job; the Python job still exercises the remaining reference suite without the
toolchain.

This is the live counterpart to test_predicate_proofs.py (which uses the
deterministic stub backend). NO fabricated proof bytes: when bb is absent the
whole module skips rather than asserting against stand-in data.
"""

import pathlib
import unittest

import _path  # noqa: F401
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from holder_fixtures import apr_verifier_identity
from _path import REPO_ROOT
from _live_toolchain import historical_toolchain_available

from predicate_fixtures import (
    ACCREDITATION_V7_PROOF_TYPE,
    ACCREDITATION_V8_PROOF_TYPE,
    JURISDICTION_PROOF_TYPE,
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
    CANONICAL_SET_PARAM,
    JURISDICTION_CANONICAL_SET_PARAM,
    CanonicalCodeSet,
    ProofContext,
    compute_jurisdiction_leaf,
    derive_credential_binding_key,
    field_to_hex,
    sign_apr,
    validate_compliance_proof_v1,
    validate_compliance_proof_v2,
)
from zkc_crypto.presentation import ANONYMOUS_PROFILE
from zkc_holder import (
    HolderClient,
    LocalAccumulatorProvider,
    NargoBackend,
    PredicateRegistry,
    ProofRequest,
    TrustPolicy,
)
from zkc_holder.predicates import (
    MEMBERSHIP_TYPE_EXCLUSION,
    MEMBERSHIP_TYPE_INCLUSION,
    REBIND_BINDING_V2_CIRCUIT,
    REBIND_BINDING_V2_STATEMENT_DOMAIN,
    REBIND_CIRCUIT,
    REBIND_V2_BINDING_V2_CIRCUIT,
    REBIND_V2_BINDING_V2_STATEMENT_DOMAIN,
    REBIND_V2_CIRCUIT,
    build_rebind_witness,
    build_rebind_witness_v2,
    single_leaf_inclusion_witness,
    single_leaf_set_root,
)
from zkc_verifier import (
    BBVerifyBackend,
    IssuerAccumulatorState,
    VerificationErrorCode,
    VerificationRequest,
    VerifierTrustPolicy,
    VerificationKeyStore,
    ZKCVerifier,
)
from zkc_verifier import TrustedIssuer as VerifierTrustedIssuer

TOOLCHAIN = historical_toolchain_available()

MASTER_SEED = 4242
TIMESTAMP = 1_700_000
CONTEXT_NONCE = 555
APR_VERIFIER_PRIVATE_KEY = 0xA9701


def _write_vk(tmp_path: pathlib.Path, circuit: str) -> bytes:
    """Derive one verification key from the pinned-toolchain ACIR artifact."""
    import subprocess

    circuit_dir = tmp_path / "artifacts" / "build" / circuit
    circuit_dir.mkdir(parents=True, exist_ok=True)
    artifact = REPO_ROOT / "artifacts" / circuit / f"{circuit}.json"
    subprocess.run(
        ["bb", "write_vk", "-b", str(artifact), "-o", str(circuit_dir)],
        check=True,
        capture_output=True,
    )
    return (circuit_dir / "vk").read_bytes()


def _write_vk_manifest(tmp_path: pathlib.Path, circuit: str) -> pathlib.Path:
    """Build a manifest-backed VK store from a compiled circuit artifact."""
    import hashlib
    import json

    build = tmp_path / "artifacts" / "build"
    vk_bytes = _write_vk(tmp_path, circuit)
    manifest = {
        "circuits": [
            {
                "name": circuit,
                "vkSha256": "sha256:" + hashlib.sha256(vk_bytes).hexdigest(),
                "artifacts": {"vk": f"artifacts/build/{circuit}/vk"},
            }
        ]
    }
    manifest_path = build / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    return manifest_path


@unittest.skipUnless(TOOLCHAIN, "pinned historical nargo/bb toolchain not on PATH")
class LivePredicateProvingTests(unittest.TestCase):
    def _context(self) -> ProofContext:
        return ProofContext.verifier_session("verifier.example", CONTEXT_NONCE, TIMESTAMP)

    def _generate_and_verify(
        self,
        proof_type,
        circuit,
        credential,
        parameters,
        *,
        presentation_proof_type=None,
        rejected_parameters=None,
        relabelled_proof_type=None,
        relabelled_parameters=None,
    ):
        import tempfile

        provider = LocalAccumulatorProvider()
        client = HolderClient.from_seed(
            MASTER_SEED,
            PredicateRegistry.from_repo(REPO_ROOT),
            NargoBackend(REPO_ROOT),
            accumulator_provider=provider,
        )
        provider.register(TEST_ISSUER_ID, credential.credential_id)
        client.store_credential(credential)
        context = self._context()
        request = ProofRequest(
            proof_types=[proof_type],
            parameters={proof_type: parameters},
            context=context,
            trust_policy=TrustPolicy(issuers=(trusted_predicate_issuer(),)),
        )
        exact_member_consents = {
            JURISDICTION_PROOF_TYPE: True,
            SOURCE_V7_PROOF_TYPE: True,
            TAX_V7_PROOF_TYPE: True,
        }
        apr = None
        if presentation_proof_type is None:
            envelope = generate_unauthenticated_linkable(
                client, request, exact_member_consents=exact_member_consents,
            )
            validate_compliance_proof_v1(envelope)
            effective_proof_type = proof_type
        else:
            apr = sign_apr(
                {
                    "request": {
                        "proofTypes": [proof_type],
                        "parameters": {proof_type: parameters},
                        "context": {
                            "profile": "zkc:context:verifier-session:v1",
                            "verifierId": "verifier.example",
                            "sessionId": field_to_hex(CONTEXT_NONCE),
                            "timestamp": TIMESTAMP,
                        },
                        "trustPolicy": {"issuers": []},
                        "presentation": {"profile": ANONYMOUS_PROFILE},
                    },
                    "verifierId": "verifier.example",
                    "nonce": field_to_hex(0xA11CE),
                    "issuedAt": TIMESTAMP,
                    "expiresAt": TIMESTAMP + 3600,
                },
                APR_VERIFIER_PRIVATE_KEY,
            )
            envelope = client.generate_authenticated_proof(
                apr, request, now=TIMESTAMP, exact_member_consents=exact_member_consents,
            )["envelope"]
            validate_compliance_proof_v2(envelope)
            effective_proof_type = presentation_proof_type

        self.assertEqual(envelope["proofs"][0]["proofType"], effective_proof_type)
        proof_hex = envelope["proofs"][0]["proof"]
        self.assertTrue(proof_hex.startswith("0x"))
        self.assertGreater(len(proof_hex), 1000, "expected a real UltraHonk proof")

        with tempfile.TemporaryDirectory(prefix="zkc-live-pred-") as tmp:
            manifest_path = _write_vk_manifest(pathlib.Path(tmp), circuit)
            trusted_proof_types = [effective_proof_type]
            if relabelled_proof_type is not None:
                trusted_proof_types.append(relabelled_proof_type)
            verifier = ZKCVerifier(
                REPO_ROOT,
                VerifierTrustPolicy(
                    **apr_verifier_identity(0xA9701),
                    issuers=(
                        VerifierTrustedIssuer(
                            issuer_id=TEST_ISSUER_ID,
                            public_key_x=TEST_ISSUER_KEY_X,
                            public_key_y=TEST_ISSUER_KEY_Y,
                            proof_types=tuple(trusted_proof_types),
                        ),
                    )
                ),
                BBVerifyBackend(REPO_ROOT),
                vk_store=VerificationKeyStore(manifest_path),
            )
            verification_request = VerificationRequest(
                proof_types=[effective_proof_type],
                parameters={effective_proof_type: parameters},
                context=context,
                accumulator_states={
                    TEST_ISSUER_ID: IssuerAccumulatorState(
                        current_epoch=provider.current_epoch(TEST_ISSUER_ID),
                        roots=provider.roots(TEST_ISSUER_ID),
                    )
                },
            )
            if apr is None:
                result = verifier.verify(envelope, verification_request)
            else:
                result = verifier.verify_authenticated(
                    apr, envelope, verification_request, now=TIMESTAMP
                )
            self.assertTrue(result.valid, result.to_dict())

            if rejected_parameters is not None:
                # Keep the child proof and every public input byte-identical.
                # Only the verifier's internally valid request changes. This
                # distinguishes request-binding rejection from proof tampering
                # and from an implementation that rejects every proof.
                out_of_request = VerificationRequest(
                    proof_types=[effective_proof_type],
                    parameters={effective_proof_type: rejected_parameters},
                    context=context,
                    accumulator_states=verification_request.accumulator_states,
                )
                if apr is None:
                    rejected = verifier.verify(envelope, out_of_request)
                else:
                    rejected = verifier.verify_authenticated(
                        apr, envelope, out_of_request, now=TIMESTAMP
                    )
                self.assertFalse(rejected.valid, rejected.to_dict())
                self.assertEqual(
                    rejected.codes(),
                    [VerificationErrorCode.REQUIREMENTS_NOT_MET],
                    rejected.to_dict(),
                )

            if relabelled_proof_type is not None:
                import copy

                self.assertIsNotNone(relabelled_parameters)
                # The four remaining-predicate meanings share this exact
                # circuit and VK. Relabel only the envelope routing metadata;
                # the real proof and its public inputs stay byte-identical and
                # therefore remain valid child-circuit evidence.
                relabelled = copy.deepcopy(envelope)
                relabelled["proofs"][0]["proofType"] = relabelled_proof_type
                relabelled_request = VerificationRequest(
                    proof_types=[relabelled_proof_type],
                    parameters={relabelled_proof_type: relabelled_parameters},
                    context=context,
                    accumulator_states=verification_request.accumulator_states,
                )
                rejected = verifier.verify(relabelled, relabelled_request)
                self.assertFalse(rejected.valid, rejected.to_dict())
                self.assertTrue(rejected.codes(), rejected.to_dict())
                self.assertEqual(
                    set(rejected.codes()),
                    {VerificationErrorCode.REQUIREMENTS_NOT_MET},
                    rejected.to_dict(),
                )
                self.assertTrue(
                    any("predicate_type" in error.message for error in rejected.errors),
                    rejected.to_dict(),
                )

    def _assert_rebind_cross_wire_rejected(
        self, predecessor_circuit, successor_circuit, predecessor_witness, successor_witness
    ):
        """Real proof/VK cross-wire check for one additive statement pair.

        The successor's private statement domain must produce a different ACIR
        and verification key, even though its public input ABI intentionally
        remains compatible with the predecessor.  Checking both directions
        makes a copied package or an accidentally reused verification key fail
        under actual Barretenberg verification rather than only under the stub
        backend's circuit-name transcript.
        """
        import tempfile

        prover = NargoBackend(REPO_ROOT)
        verifier = BBVerifyBackend(REPO_ROOT)
        predecessor_proof = prover.prove(predecessor_circuit, predecessor_witness)
        predecessor_inputs = prover.public_inputs(predecessor_circuit, predecessor_witness)
        successor_proof = prover.prove(successor_circuit, successor_witness)
        successor_inputs = prover.public_inputs(successor_circuit, successor_witness)

        with tempfile.TemporaryDirectory(prefix="zkc-live-rebind-domain-") as tmp:
            scratch = pathlib.Path(tmp)
            predecessor_vk = _write_vk(scratch, predecessor_circuit)
            successor_vk = _write_vk(scratch, successor_circuit)
            self.assertTrue(
                verifier.verify(
                    predecessor_circuit, predecessor_proof, predecessor_inputs, predecessor_vk
                ),
                "predecessor proof must verify under its own verification key",
            )
            self.assertTrue(
                verifier.verify(
                    successor_circuit, successor_proof, successor_inputs, successor_vk
                ),
                "successor proof must verify under its own verification key",
            )
            self.assertFalse(
                verifier.verify(
                    successor_circuit, predecessor_proof, predecessor_inputs, successor_vk
                ),
                "predecessor proof verified under successor VK",
            )
            self.assertFalse(
                verifier.verify(
                    predecessor_circuit, successor_proof, successor_inputs, predecessor_vk
                ),
                "successor proof verified under predecessor VK",
            )

    def test_rebind_binding_contract_successor_proofs_do_not_cross_verify(self):
        """The linkable and scoped binding-v2 successors have independent
        cryptographic statement identities from their frozen predecessors."""
        credential = issue_rebindable_credential(
            master_seed=MASTER_SEED, credential_id=91, issuer_id_hash=1001, schema_id_hash=2002
        )
        old_key = derive_credential_binding_key(MASTER_SEED)
        new_key = new_rebind_binding_key(MASTER_SEED + 1)
        context = self._context()
        base = {
            "old_credential_binding_key": old_key,
            "new_credential_binding_key": new_key,
            "credential": credential,
            "issuer_id_hash": 1001,
            "schema_id_hash": 2002,
            "proof_context": context.value,
            "timestamp": context.timestamp,
        }
        with self.subTest(profile="linkable"):
            self._assert_rebind_cross_wire_rejected(
                REBIND_CIRCUIT,
                REBIND_BINDING_V2_CIRCUIT,
                build_rebind_witness(**base),
                build_rebind_witness(
                    **base, statement_domain=REBIND_BINDING_V2_STATEMENT_DOMAIN
                ),
            )
        with self.subTest(profile="scoped"):
            scoped = {**base, "scope_id": 0x5C0DE}
            self._assert_rebind_cross_wire_rejected(
                REBIND_V2_CIRCUIT,
                REBIND_V2_BINDING_V2_CIRCUIT,
                build_rebind_witness_v2(**scoped),
                build_rebind_witness_v2(
                    **scoped, statement_domain=REBIND_V2_BINDING_V2_STATEMENT_DOMAIN
                ),
            )

    def test_jurisdiction_inclusion(self):
        credential = issue_jurisdiction_credential(
            master_seed=MASTER_SEED, credential_id=11, jurisdiction_code=840, claim_type=1
        )
        leaf = compute_jurisdiction_leaf(840, 1)
        path_index, siblings = single_leaf_inclusion_witness()
        self._generate_and_verify(
            JURISDICTION_PROOF_TYPE,
            "zkc_jurisdiction_v3",
            credential,
            {
                "membershipType": MEMBERSHIP_TYPE_INCLUSION,
                "requiredClaimType": 1,
                "jurisdictionSetRoot": single_leaf_set_root(leaf),
                "membershipPathIndex": path_index,
                "membershipSiblings": siblings,
            },
        )

    def test_accreditation(self):
        credential = issue_accreditation_credential(
            master_seed=MASTER_SEED, credential_id=13, accreditation_level=3, institutional=True
        )
        self._generate_and_verify(
            ACCREDITATION_V7_PROOF_TYPE,
            "zkc_remaining_predicates_v7",
            credential,
            {"required0": 2, "required1": 0, "flagRequired": True},
            # The level-3 credential satisfies both requests, but the proof
            # attests the level-2 statement. The untouched real proof must not
            # satisfy this different parent request.
            rejected_parameters={"required0": 3, "required1": 0, "flagRequired": True},
        )

    def test_anonymous_accreditation_v8(self):
        credential = issue_accreditation_credential(
            master_seed=MASTER_SEED,
            credential_id=17,
            accreditation_level=3,
            institutional=True,
        )
        self._generate_and_verify(
            ACCREDITATION_V7_PROOF_TYPE,
            "zkc_remaining_predicates_v8",
            credential,
            {"required0": 2, "required1": 0, "flagRequired": True},
            presentation_proof_type=ACCREDITATION_V8_PROOF_TYPE,
        )

    def test_source_of_funds(self):
        credential = issue_source_credential(
            master_seed=MASTER_SEED, credential_id=14, source_code=7
        )
        path_index, siblings = single_leaf_inclusion_witness()
        sanctions_codes = [100, 200]
        self._generate_and_verify(
            SOURCE_V7_PROOF_TYPE,
            "zkc_remaining_predicates_v7",
            credential,
            {
                "setRoot": single_leaf_set_root(7),
                "pathIndex": path_index,
                "siblings": siblings,
            },
            relabelled_proof_type=SANCTIONS_V7_PROOF_TYPE,
            relabelled_parameters={
                CANONICAL_SET_PARAM: sanctions_codes,
                "setRoot": CanonicalCodeSet.for_sanctions(sanctions_codes).root(),
            },
        )

    def test_tax_residency(self):
        credential = issue_tax_credential(
            master_seed=MASTER_SEED, credential_id=15, tax_code=840, tax_year=2026
        )
        path_index, siblings = single_leaf_inclusion_witness()
        self._generate_and_verify(
            TAX_V7_PROOF_TYPE,
            "zkc_remaining_predicates_v7",
            credential,
            {
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
        self._generate_and_verify(
            SANCTIONS_V7_PROOF_TYPE,
            "zkc_remaining_predicates_v7",
            credential,
            {
                CANONICAL_SET_PARAM: blocked_codes,
                "setRoot": blocked_set.root(),
            },
        )

    def test_jurisdiction_exclusion(self):
        credential = issue_jurisdiction_credential(
            master_seed=MASTER_SEED, credential_id=12, jurisdiction_code=150, claim_type=1
        )
        blocked_codes = [100, 200]
        blocked_set = CanonicalCodeSet.for_jurisdiction(
            blocked_codes, claim_type=1, mode=CANONICAL_SET_EXCLUSION
        )
        self._generate_and_verify(
            JURISDICTION_PROOF_TYPE,
            "zkc_jurisdiction_v3",
            credential,
            {
                "membershipType": MEMBERSHIP_TYPE_EXCLUSION,
                "requiredClaimType": 1,
                JURISDICTION_CANONICAL_SET_PARAM: blocked_codes,
                "jurisdictionSetRoot": blocked_set.root(),
            },
        )


if __name__ == "__main__":
    unittest.main()

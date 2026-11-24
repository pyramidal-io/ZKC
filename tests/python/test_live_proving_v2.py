"""Live proving v2: real bb proofs under presentation profiles.

Requires the pinned toolchain (`nargo`, `bb`) on PATH; skips otherwise,
exactly like tests/python/test_live_proving.py (the CI python job runs without
the toolchain — the `artifacts` job covers circuit compilation, and this test
covers real v2 proof generation + verification when run locally).

CI execution parity (see .forgejo/workflows/protected-gates.yml): the Python job that
runs `unittest discover -s tests/python` installs neither `nargo` nor `bb`,
so `NargoBackend.available()` is False and every live class below skips there
— identically to the v1 live suite. This is *deliberate parity with v1*, not
an oversight: v2 is discovered by the same command and gated by the same
`skipUnless(TOOLCHAIN)` guard, so it is neither weaker nor stronger than v1's
CI treatment. Real-bb coverage is exercised locally and gated by the pinned
`.noir-version` toolchain; the `artifacts` job (which does install `bb`)
covers circuit compilation. Do not loosen the skip guard to "make it run in
CI" without also migrating v1 in the same way.

Task 1 (this file): the anonymous presentation profile round trip. A holder
generates a DEFAULT (anonymous) presentation as a real UltraHonk proof against
noir/zkc_kyc_v2, a fresh `bb write_vk`/`bb verify` accepts it, and ZKCVerifier
with the real bb backend verifies the envelope valid.
"""

import copy
import hashlib
import pathlib
import subprocess
import tempfile
import unittest

from _path import REPO_ROOT
from _live_toolchain import historical_toolchain_available
from holder_fixtures import apr_verifier_identity

from holder_fixtures import (
    TEST_ISSUER_ID,
    TEST_ISSUER_KEY_X,
    TEST_ISSUER_KEY_Y,
    issue_kyc_credential,
)
from zkc_crypto import (
    FIELD_MODULUS,
    ProofContext,
    PublicInputEncoder,
    apr_signer_pubkey,
    derive_credential_binding_key,
    derive_presentation_pseudonym,
    derive_scope_id,
    derive_verifier_identity,
    field_to_hex,
    hex_to_field,
    sign_apr,
)
from zkc_crypto.ecdsa_secp256k1 import N
from zkc_crypto.presentation import ANONYMOUS_PROFILE, SCOPED_PROFILE
from zkc_registry.predicate_v2 import request_extension
from zkc_holder import (
    HolderClient,
    LocalAccumulatorProvider,
    NargoBackend,
    PredicateRegistry,
    ProofRequest,
    TrustPolicy,
    TrustedIssuer,
)

TOOLCHAIN = historical_toolchain_available()

# v1 KYC proof type is what the holder REQUEST carries; the holder resolves the
# v1 family to its :v2 sibling internally when a v2 presentation is negotiated.
KYC_PROOF_TYPE = "zkc:proof:kyc:v1"
KYC_V2_PROOF_TYPE = "zkc:proof:kyc:v2"
KYC_V2_CIRCUIT = "zkc_kyc_v2"

# The selector-free v2 alias remains draft. These historical live tests instead
# authenticate the exact active, self-attested beta.21 binding; holder review
# defaults remain in force, and beta.25 cannot be selected accidentally.
HISTORICAL_BINDING_SELECTOR = {
    "predicateId": "zkc-kyc",
    "entryVersion": "4.0.0",
    "bindingId": "sha256:c70f1a6b29935f65b9ec21cdf654c170deaa4ac26f615f7bb8195625d9b0be49",
}
KYC_PARAMETERS = {
    "requiredLevel": 1,
    "requiredAttributes": [True, False, True, False, False],
}

# A single TEST-ONLY verifier identity that signs the anonymous APR. The APR is
# authenticated (so the exchange is a real presentation), but it carries NO
# presentation block, so the holder's own anonymous ceiling governs => the
# anonymous profile (scope_id == 0, presentation_pseudonym == 0).
APR_VERIFIER_PRIVATE_KEY = (
    int.from_bytes(hashlib.sha256(b"zkc-live-v2-apr-verifier").digest(), "big") % N or 1
)

SESSION_ID = 555
TIMESTAMP = 1_700_000
NONCE = 0xA1

# The holder seed reused across every live v2 test in this module (matching the
# anonymous class above): the credential-binding key is a deterministic function
# of it, so the expected scoped pseudonym can be recomputed independently.
HOLDER_SEED = 42
HOLDER_CREDENTIAL_ID = 42

# Two DISTINCT TEST-ONLY verifier identities (mirroring
# conformance/presentation_vectors.py's APR verifier A / B): verifier A signs the
# scoped APR the holder answers; verifier B signs a validly-signed-but-foreign
# APR that must recompute a different scope => SCOPE_MISMATCH.
APR_VERIFIER_A_PRIVATE_KEY = (
    int.from_bytes(hashlib.sha256(b"zkc-live-v2-apr-verifier-A").digest(), "big") % N or 1
)
APR_VERIFIER_B_PRIVATE_KEY = (
    int.from_bytes(hashlib.sha256(b"zkc-live-v2-apr-verifier-B").digest(), "big") % N or 2
)

SCOPE_POLICY = "verifier"
ROTATION_EPOCH_SECONDS = 0


def _binding_selectors(proof_type):
    return {proof_type: dict(HISTORICAL_BINDING_SELECTOR)}


def _write_vk_manifest_v2(tmp_path: pathlib.Path, circuit: str) -> pathlib.Path:
    """Build a minimal manifest-backed VK store from a compiled v2 circuit.

    Mirrors _write_vk_manifest in test_live_proving.py, parametrized on the
    circuit name so the v2 artifact (zkc_kyc_v2) is used.
    """
    import json

    build = tmp_path / "artifacts" / "build"
    circuit_dir = build / circuit
    circuit_dir.mkdir(parents=True)
    artifact = REPO_ROOT / "artifacts" / circuit / f"{circuit}.json"
    subprocess.run(
        ["bb", "write_vk", "-b", str(artifact), "-o", str(circuit_dir)],
        check=True, capture_output=True,
    )
    vk_bytes = (circuit_dir / "vk").read_bytes()
    manifest = {
        "circuits": [
            {
                "name": circuit,
                "vkSha256": "sha256:" + hashlib.sha256(vk_bytes).hexdigest(),
                "artifacts": {"vk": f"artifacts/build/{circuit}/vk"},
            }
        ]
    }
    # Preserve the governed binding identity while exercising a freshly
    # generated VK. A different compiled key must fail before verification.
    committed = json.loads((REPO_ROOT / "artifacts/manifest.json").read_text())
    binding = next(
        row for row in committed["bindings"]
        if all(row[key] == value for key, value in HISTORICAL_BINDING_SELECTOR.items())
    )
    if manifest["circuits"][0]["vkSha256"] != binding["vkSha256"]:
        raise AssertionError("live historical VK differs from its committed binding")
    manifest["bindings"] = [{
        **binding,
        "artifacts": {**binding["artifacts"], "vk": f"artifacts/build/{circuit}/vk"},
    }]
    manifest_path = build / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    return manifest_path


def _trusted_holder_issuer(proof_types) -> TrustedIssuer:
    return TrustedIssuer(
        issuer_id=TEST_ISSUER_ID,
        public_key_x=TEST_ISSUER_KEY_X,
        public_key_y=TEST_ISSUER_KEY_Y,
        proof_types=tuple(proof_types),
    )


def _anonymous_apr(*, session_id, timestamp, nonce) -> dict:
    """A signed APR with NO presentation block => the holder answers anonymously.

    Mirrors conformance/presentation_vectors.py::Pipeline.apr(presentation=None):
    the holder's anonymous ceiling governs a silent APR (design §5.2).
    """
    request = {
        "proofTypes": [KYC_PROOF_TYPE],
        "parameters": {KYC_PROOF_TYPE: dict(KYC_PARAMETERS)},
        "context": {
            "profile": "zkc:context:verifier-session:v1",
            "verifierId": "verifier.example",
            "sessionId": field_to_hex(session_id),
            "timestamp": timestamp,
        },
        "trustPolicy": {"issuers": []},
        "extensions": request_extension(_binding_selectors(KYC_PROOF_TYPE)),
    }
    unsigned = {
        "request": request,
        "verifierId": "verifier.example",
        "nonce": field_to_hex(nonce),
        "issuedAt": timestamp,
        "expiresAt": timestamp + 3600,
    }
    return sign_apr(unsigned, APR_VERIFIER_PRIVATE_KEY)


def _scoped_apr(*, private_key, session_id, timestamp, nonce) -> dict:
    """A signed APR carrying a SCOPED presentation block (design §5.2).

    Mirrors conformance/presentation_vectors.py::Pipeline.apr with a
    ``presentation`` block: {profile: scoped, scopePolicy: "verifier",
    rotationEpochSeconds: 0}. The holder derives scope_id from the APR SIGNER's
    key, so the scope is bound to whichever verifier signed the APR.
    """
    request = {
        "proofTypes": [KYC_PROOF_TYPE],
        "parameters": {KYC_PROOF_TYPE: dict(KYC_PARAMETERS)},
        "context": {
            "profile": "zkc:context:verifier-session:v1",
            "verifierId": "verifier.example",
            "sessionId": field_to_hex(session_id),
            "timestamp": timestamp,
        },
        "trustPolicy": {"issuers": []},
        "extensions": request_extension(_binding_selectors(KYC_PROOF_TYPE)),
        "presentation": {
            "profile": SCOPED_PROFILE,
            "scopePolicy": SCOPE_POLICY,
            "rotationEpochSeconds": ROTATION_EPOCH_SECONDS,
        },
    }
    unsigned = {
        "request": request,
        "verifierId": "verifier.example",
        "nonce": field_to_hex(nonce),
        "issuedAt": timestamp,
        "expiresAt": timestamp + 3600,
    }
    return sign_apr(unsigned, private_key)


@unittest.skipUnless(TOOLCHAIN, "pinned historical nargo/bb toolchain not on PATH")
class LiveAnonymousProvingTests(unittest.TestCase):
    """Anonymous-profile real-proof round trip against noir/zkc_kyc_v2.

    Proving is slow, so ONE real proof is generated in setUpClass and reused
    across the assertions (mirroring the per-class reuse the v1 live file uses).
    """

    @classmethod
    def setUpClass(cls):
        cls.provider = LocalAccumulatorProvider()
        client = HolderClient.from_seed(
            42,
            PredicateRegistry.from_repo(REPO_ROOT),
            NargoBackend(REPO_ROOT),
            accumulator_provider=cls.provider,
        )
        client.store_credential(
            issue_kyc_credential(master_seed=42, credential_id=42, provider=cls.provider)
        )
        cls.context = ProofContext.verifier_session("verifier.example", SESSION_ID, TIMESTAMP)
        request = ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            binding_selectors=_binding_selectors(KYC_PROOF_TYPE),
            parameters={KYC_PROOF_TYPE: dict(KYC_PARAMETERS)},
            context=cls.context,
            trust_policy=TrustPolicy(
                issuers=(_trusted_holder_issuer([KYC_V2_PROOF_TYPE]),)
            ),
            presentation_profile=ANONYMOUS_PROFILE,
        )
        apr = _anonymous_apr(session_id=SESSION_ID, timestamp=TIMESTAMP, nonce=NONCE)
        # The real presentation pipeline: authenticated APR + anonymous request
        # => a zkc:proof:v2 envelope carrying a REAL UltraHonk proof.
        cls.envelope = client.generate_authenticated_proof(apr, request, now=request.context.timestamp)["envelope"]

    def _kyc_v2_entry(self) -> dict:
        proofs = [p for p in self.envelope["proofs"] if p["proofType"] == KYC_V2_PROOF_TYPE]
        self.assertEqual(len(proofs), 1, "expected exactly one zkc:proof:kyc:v2 proof")
        self.assertEqual(proofs[0]["bindingSelector"], HISTORICAL_BINDING_SELECTOR)
        return proofs[0]

    def test_envelope_is_anonymous_v2(self):
        """The envelope is a v2 anonymous presentation with a real proof body."""
        self.assertEqual(self.envelope["version"], "zkc:proof:v2")
        # Anonymous binding: profile only, no holder-derived handles.
        binding = self.envelope["presentationBinding"]
        self.assertEqual(binding["profile"], ANONYMOUS_PROFILE)
        self.assertNotIn("pseudonym", binding)
        self.assertNotIn("scopeId", binding)
        # No v1 holderBinding on a v2 envelope.
        self.assertNotIn("holderBinding", self.envelope)

        entry = self._kyc_v2_entry()
        self.assertEqual(entry["proofType"], KYC_V2_PROOF_TYPE)
        # Anonymous sentinels: pseudonym and scope_id are both the field zero,
        # and the private holder_commitment is not surfaced.
        public_inputs = entry["publicInputs"]
        self.assertEqual(hex_to_field(public_inputs["presentation_pseudonym"]), 0)
        self.assertEqual(hex_to_field(public_inputs["scope_id"]), 0)
        self.assertNotIn("holder_commitment", public_inputs)
        # A real UltraHonk proof, not a stub payload.
        proof_hex = entry["proof"]
        self.assertTrue(proof_hex.startswith("0x"))
        self.assertGreater(len(proof_hex), 1000, "expected a real UltraHonk proof")

    def test_raw_bb_verify_accepts_the_real_proof(self):
        """A fresh `bb write_vk` VK + `bb verify` accepts the v2 proof."""
        entry = self._kyc_v2_entry()
        proof_hex = entry["proof"]
        encoder = PublicInputEncoder.load(
            REPO_ROOT / "schemas" / "public-inputs" / f"{KYC_V2_CIRCUIT}.json"
        )
        public_input_bytes = encoder.encode_bytes(entry["publicInputs"])
        with tempfile.TemporaryDirectory(prefix="zkc-live-verify-v2-") as tmp:
            tmp_path = pathlib.Path(tmp)
            artifact = REPO_ROOT / "artifacts" / KYC_V2_CIRCUIT / f"{KYC_V2_CIRCUIT}.json"
            self.assertTrue(
                artifact.is_file(), "committed zkc_kyc_v2 ACIR must exist"
            )
            subprocess.run(
                ["bb", "write_vk", "-b", str(artifact), "-o", str(tmp_path)],
                check=True, capture_output=True,
            )
            (tmp_path / "proof").write_bytes(bytes.fromhex(proof_hex.removeprefix("0x")))
            (tmp_path / "public_inputs").write_bytes(public_input_bytes)
            result = subprocess.run(
                [
                    "bb", "verify",
                    "-k", str(tmp_path / "vk"),
                    "-p", str(tmp_path / "proof"),
                    "-i", str(tmp_path / "public_inputs"),
                ],
                capture_output=True, text=True,
            )
            self.assertEqual(
                result.returncode, 0,
                f"bb verify failed: {result.stderr.strip()[-500:]}",
            )

            # A tampered public input (non-zero scope_id) must NOT verify.
            tampered = dict(entry["publicInputs"])
            tampered["scope_id"] = field_to_hex(1)
            (tmp_path / "tampered_inputs").write_bytes(encoder.encode_bytes(tampered))
            tampered_result = subprocess.run(
                [
                    "bb", "verify",
                    "-k", str(tmp_path / "vk"),
                    "-p", str(tmp_path / "proof"),
                    "-i", str(tmp_path / "tampered_inputs"),
                ],
                capture_output=True, text=True,
            )
            self.assertNotEqual(tampered_result.returncode, 0, "tampered inputs must fail")

    def test_zkcverifier_with_bb_backend_verifies_valid(self):
        """ZKCVerifier with the real bb backend verifies the anonymous envelope."""
        from zkc_verifier import (
            BBVerifyBackend,
            IssuerAccumulatorState,
            VerificationKeyStore,
            VerificationRequest,
            VerifierTrustPolicy,
            ZKCVerifier,
        )
        from zkc_verifier import TrustedIssuer as VerifierTrustedIssuer

        with tempfile.TemporaryDirectory(prefix="zkc-live-vkstore-v2-") as tmp:
            manifest_path = _write_vk_manifest_v2(pathlib.Path(tmp), KYC_V2_CIRCUIT)
            verifier = ZKCVerifier(
                REPO_ROOT,
                VerifierTrustPolicy(
                    **apr_verifier_identity(APR_VERIFIER_PRIVATE_KEY),
                    issuers=(
                        VerifierTrustedIssuer(
                            issuer_id=TEST_ISSUER_ID,
                            public_key_x=TEST_ISSUER_KEY_X,
                            public_key_y=TEST_ISSUER_KEY_Y,
                            proof_types=(KYC_V2_PROOF_TYPE,),
                        ),
                    )
                ),
                BBVerifyBackend(REPO_ROOT),
                vk_store=VerificationKeyStore(manifest_path),
            )
            request = VerificationRequest(
                proof_types=[KYC_V2_PROOF_TYPE],
                binding_selectors=_binding_selectors(KYC_V2_PROOF_TYPE),
                parameters={KYC_V2_PROOF_TYPE: dict(KYC_PARAMETERS)},
                context=self.context,
                accumulator_states={
                    TEST_ISSUER_ID: IssuerAccumulatorState(
                        current_epoch=self.provider.current_epoch(TEST_ISSUER_ID),
                        roots=self.provider.roots(TEST_ISSUER_ID),
                    )
                },
            )
            result = verifier.verify(self.envelope, request)
            self.assertTrue(result.valid, result.to_dict())


@unittest.skipUnless(TOOLCHAIN, "pinned historical nargo/bb toolchain not on PATH")
class LiveScopedProvingTests(unittest.TestCase):
    """Scoped-profile authenticated round trip + cross-verifier SCOPE_MISMATCH.

    ONE real scoped bb proof (against noir/zkc_kyc_v2, scope = verifier A) is
    generated in setUpClass and reused: (a) it verifies VALID under verifier A's
    own authenticated APR and its pseudonym equals the independently recomputed
    ``derive_presentation_pseudonym(cbk, derive_scope_id(...A...))``; (b) the
    SAME envelope under verifier B's validly-signed APR keeps a bb-valid proof
    body yet ``verify_authenticated`` returns exactly ``SCOPE_MISMATCH`` — the
    scope check operates on REAL proofs, independent of proof validity.
    """

    SCOPED_SESSION_ID = 701
    # Below the credential's expires_at (issue_kyc_credential defaults to
    # 2_000_000); with rotationEpochSeconds=0 the rotation epoch is 0 regardless
    # of timestamp, so scope derivation is unaffected by this value.
    SCOPED_TIMESTAMP = 1_700_000
    SCOPED_NONCE_A = 0xB1
    SCOPED_NONCE_B = 0xB2

    @classmethod
    def setUpClass(cls):
        cls.provider = LocalAccumulatorProvider()
        client = HolderClient.from_seed(
            HOLDER_SEED,
            PredicateRegistry.from_repo(REPO_ROOT),
            NargoBackend(REPO_ROOT),
            accumulator_provider=cls.provider,
        )
        client.store_credential(
            issue_kyc_credential(
                master_seed=HOLDER_SEED,
                credential_id=HOLDER_CREDENTIAL_ID,
                provider=cls.provider,
            )
        )
        cls.context = ProofContext.verifier_session(
            "verifier.example", cls.SCOPED_SESSION_ID, cls.SCOPED_TIMESTAMP
        )
        request = ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            binding_selectors=_binding_selectors(KYC_PROOF_TYPE),
            parameters={KYC_PROOF_TYPE: dict(KYC_PARAMETERS)},
            context=cls.context,
            trust_policy=TrustPolicy(
                issuers=(_trusted_holder_issuer([KYC_V2_PROOF_TYPE]),)
            ),
            presentation_profile=SCOPED_PROFILE,
        )
        # Verifier A signs the scoped APR; the holder derives scope_id from A's
        # authenticated signer key and answers with a REAL scoped proof.
        cls.apr_a = _scoped_apr(
            private_key=APR_VERIFIER_A_PRIVATE_KEY,
            session_id=cls.SCOPED_SESSION_ID,
            timestamp=cls.SCOPED_TIMESTAMP,
            nonce=cls.SCOPED_NONCE_A,
        )
        cls.envelope = client.generate_authenticated_proof(cls.apr_a, request, now=request.context.timestamp)["envelope"]
        # Verifier B's own validly-signed scoped APR (foreign scope), same
        # session/timestamp — only the signer identity differs.
        cls.apr_b = _scoped_apr(
            private_key=APR_VERIFIER_B_PRIVATE_KEY,
            session_id=cls.SCOPED_SESSION_ID,
            timestamp=cls.SCOPED_TIMESTAMP,
            nonce=cls.SCOPED_NONCE_B,
        )

    def _kyc_v2_entry(self) -> dict:
        proofs = [p for p in self.envelope["proofs"] if p["proofType"] == KYC_V2_PROOF_TYPE]
        self.assertEqual(len(proofs), 1, "expected exactly one zkc:proof:kyc:v2 proof")
        self.assertEqual(proofs[0]["bindingSelector"], HISTORICAL_BINDING_SELECTOR)
        return proofs[0]

    def _bb_verifier(self, manifest_path, private_key=APR_VERIFIER_A_PRIVATE_KEY):
        """A ZKCVerifier wired to the REAL bb backend over the v2 VK store."""
        from zkc_verifier import (
            BBVerifyBackend,
            VerificationKeyStore,
            VerifierTrustPolicy,
            ZKCVerifier,
        )
        from zkc_verifier import TrustedIssuer as VerifierTrustedIssuer

        return ZKCVerifier(
            REPO_ROOT,
            VerifierTrustPolicy(
                **apr_verifier_identity(private_key),
                issuers=(
                    VerifierTrustedIssuer(
                        issuer_id=TEST_ISSUER_ID,
                        public_key_x=TEST_ISSUER_KEY_X,
                        public_key_y=TEST_ISSUER_KEY_Y,
                        proof_types=(KYC_V2_PROOF_TYPE,),
                    ),
                )
            ),
            BBVerifyBackend(REPO_ROOT),
            vk_store=VerificationKeyStore(manifest_path),
        )

    def _verification_request(self):
        from zkc_verifier import IssuerAccumulatorState, VerificationRequest

        return VerificationRequest(
            proof_types=[KYC_V2_PROOF_TYPE],
            binding_selectors=_binding_selectors(KYC_V2_PROOF_TYPE),
            parameters={KYC_V2_PROOF_TYPE: dict(KYC_PARAMETERS)},
            context=self.context,
            max_proof_age=3600,
            accumulator_states={
                TEST_ISSUER_ID: IssuerAccumulatorState(
                    current_epoch=self.provider.current_epoch(TEST_ISSUER_ID),
                    roots=self.provider.roots(TEST_ISSUER_ID),
                )
            },
        )

    def test_scoped_v2_authenticated_round_trip(self):
        """Scoped envelope: pseudonym == recomputed scope-A pseudonym; VALID."""
        entry = self._kyc_v2_entry()
        # A real UltraHonk proof body, not a stub payload.
        proof_hex = entry["proof"]
        self.assertTrue(proof_hex.startswith("0x"))
        self.assertGreater(len(proof_hex), 1000, "expected a real UltraHonk proof")

        # The envelope is a v2 SCOPED presentation carrying a pseudonym + scopeId.
        self.assertEqual(self.envelope["version"], "zkc:proof:v2")
        binding = self.envelope["presentationBinding"]
        self.assertEqual(binding["profile"], SCOPED_PROFILE)
        self.assertIn("pseudonym", binding)
        self.assertIn("scopeId", binding)
        self.assertNotIn("holderBinding", self.envelope)

        # Independently recompute the expected scope-A pseudonym from public
        # material only: cbk = f(HOLDER_SEED), scope_id from verifier A's
        # AUTHENTICATED signer key + scopePolicy "verifier" + rotation epoch 0.
        cbk = derive_credential_binding_key(HOLDER_SEED)
        a_pubkey = apr_signer_pubkey(self.apr_a)
        expected_scope_id = derive_scope_id(
            derive_verifier_identity(a_pubkey), SCOPE_POLICY, ROTATION_EPOCH_SECONDS
        )
        expected_pseudonym = derive_presentation_pseudonym(cbk, expected_scope_id)
        self.assertEqual(hex_to_field(binding["scopeId"]), expected_scope_id)
        self.assertEqual(hex_to_field(binding["pseudonym"]), expected_pseudonym)
        # The circuit-bound public input agrees with the envelope binding.
        self.assertEqual(
            hex_to_field(entry["publicInputs"]["presentation_pseudonym"]),
            expected_pseudonym,
        )
        self.assertEqual(
            hex_to_field(entry["publicInputs"]["scope_id"]), expected_scope_id
        )

        # verify_authenticated under verifier A's OWN APR + the real bb backend
        # => VALID (scope recomputes to the same value the holder used).
        with tempfile.TemporaryDirectory(prefix="zkc-live-vkstore-v2-scoped-") as tmp:
            manifest_path = _write_vk_manifest_v2(pathlib.Path(tmp), KYC_V2_CIRCUIT)
            verifier = self._bb_verifier(manifest_path)
            result = verifier.verify_authenticated(
                self.apr_a, self.envelope, self._verification_request(),
                now=self._verification_request().context.timestamp
            )
            self.assertTrue(result.valid, result.to_dict())

    def test_scoped_v2_scope_mismatch_on_foreign_verifier(self):
        """SAME real envelope under verifier B: bb accepts proof, SCOPE_MISMATCH."""
        from zkc_verifier import VerificationErrorCode as Code

        entry = self._kyc_v2_entry()
        proof_hex = entry["proof"]
        encoder = PublicInputEncoder.load(
            REPO_ROOT / "schemas" / "public-inputs" / f"{KYC_V2_CIRCUIT}.json"
        )
        public_input_bytes = encoder.encode_bytes(entry["publicInputs"])

        with tempfile.TemporaryDirectory(prefix="zkc-live-vkstore-v2-mismatch-") as tmp:
            tmp_path = pathlib.Path(tmp)
            manifest_path = _write_vk_manifest_v2(tmp_path, KYC_V2_CIRCUIT)

            # The proof BYTES are still cryptographically valid (bb accepts them):
            # SCOPE_MISMATCH is a scope-binding decision, not a broken proof.
            raw = tmp_path / "raw"
            raw.mkdir()
            artifact = REPO_ROOT / "artifacts" / KYC_V2_CIRCUIT / f"{KYC_V2_CIRCUIT}.json"
            subprocess.run(
                ["bb", "write_vk", "-b", str(artifact), "-o", str(raw)],
                check=True, capture_output=True,
            )
            (raw / "proof").write_bytes(bytes.fromhex(proof_hex.removeprefix("0x")))
            (raw / "public_inputs").write_bytes(public_input_bytes)
            bb_result = subprocess.run(
                [
                    "bb", "verify",
                    "-k", str(raw / "vk"),
                    "-p", str(raw / "proof"),
                    "-i", str(raw / "public_inputs"),
                ],
                capture_output=True, text=True,
            )
            self.assertEqual(
                bb_result.returncode, 0,
                f"the scope-A proof bytes must remain bb-valid: {bb_result.stderr.strip()[-500:]}",
            )

            # But verify_authenticated under verifier B's validly-signed APR must
            # emit EXACTLY SCOPE_MISMATCH: B recomputes scope_id from its OWN
            # identity and gets a different value than the envelope's scope-A id.
            verifier = self._bb_verifier(manifest_path, APR_VERIFIER_B_PRIVATE_KEY)
            result = verifier.verify_authenticated(
                self.apr_b, self.envelope, self._verification_request(),
                now=self._verification_request().context.timestamp
            )
            self.assertFalse(result.valid, result.to_dict())
            self.assertIn(Code.SCOPE_MISMATCH, result.codes())


@unittest.skipUnless(TOOLCHAIN, "pinned historical nargo/bb toolchain not on PATH")
class LiveScopedNegativeTests(unittest.TestCase):
    """Circuit-constrained pseudonym negatives against REAL bb (design §6).

    ONE real scoped bb proof (against noir/zkc_kyc_v2, scope = verifier A) is
    generated in setUpClass and reused across two negatives that between them
    prove the pseudonym is enforced by the CIRCUIT, not merely by SDK
    bookkeeping:

    (a) ``test_tampered_pseudonym_fails_bb_verification``: flip BOTH the
        envelope ``presentationBinding.pseudonym`` AND the proof's
        ``presentation_pseudonym`` public input to another valid, mutually
        CONSISTENT field element. The SDK shape check (proof pseudonym ==
        envelope binding pseudonym) therefore still passes — yet a raw ``bb
        verify`` against the SAME VK MUST reject, because the circuit constrains
        ``presentation_pseudonym == poseidon3(DOMAIN, cbk, scope_id)`` and the
        flipped value breaks that constraint. ``ZKCVerifier`` then surfaces
        ``INVALID_PROOF`` (the bb reject), NOT ``PROFILE_MISMATCH`` — proving
        the enforcement is cryptographic, not bookkeeping.

    (b) ``test_scoped_proof_under_anonymous_binding_is_replay_rejected``: splice
        the real scoped proof entries under an ANONYMOUS presentationBinding.
        ``ZKCVerifier`` rejects with ``PROFILE_MISMATCH`` on the shape check
        alone (the scoped proof carries a non-zero pseudonym/scope, which an
        anonymous binding forbids) — no bb reject is needed, mirroring the v1
        live test's tamper pattern.
    """

    SCOPED_SESSION_ID = 703
    SCOPED_TIMESTAMP = 1_700_000
    SCOPED_NONCE_A = 0xC1

    @classmethod
    def setUpClass(cls):
        cls.provider = LocalAccumulatorProvider()
        client = HolderClient.from_seed(
            HOLDER_SEED,
            PredicateRegistry.from_repo(REPO_ROOT),
            NargoBackend(REPO_ROOT),
            accumulator_provider=cls.provider,
        )
        client.store_credential(
            issue_kyc_credential(
                master_seed=HOLDER_SEED,
                credential_id=HOLDER_CREDENTIAL_ID,
                provider=cls.provider,
            )
        )
        cls.context = ProofContext.verifier_session(
            "verifier.example", cls.SCOPED_SESSION_ID, cls.SCOPED_TIMESTAMP
        )
        request = ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            binding_selectors=_binding_selectors(KYC_PROOF_TYPE),
            parameters={KYC_PROOF_TYPE: dict(KYC_PARAMETERS)},
            context=cls.context,
            trust_policy=TrustPolicy(
                issuers=(_trusted_holder_issuer([KYC_V2_PROOF_TYPE]),)
            ),
            presentation_profile=SCOPED_PROFILE,
        )
        cls.apr_a = _scoped_apr(
            private_key=APR_VERIFIER_A_PRIVATE_KEY,
            session_id=cls.SCOPED_SESSION_ID,
            timestamp=cls.SCOPED_TIMESTAMP,
            nonce=cls.SCOPED_NONCE_A,
        )
        # ONE real scoped UltraHonk proof, reused (deep-copied) by each negative.
        cls.envelope = client.generate_authenticated_proof(cls.apr_a, request, now=request.context.timestamp)["envelope"]

    def _kyc_v2_entry(self, envelope) -> dict:
        proofs = [p for p in envelope["proofs"] if p["proofType"] == KYC_V2_PROOF_TYPE]
        self.assertEqual(len(proofs), 1, "expected exactly one zkc:proof:kyc:v2 proof")
        self.assertEqual(proofs[0]["bindingSelector"], HISTORICAL_BINDING_SELECTOR)
        return proofs[0]

    def _bb_verifier(self, manifest_path):
        """A ZKCVerifier wired to the REAL bb backend over the v2 VK store."""
        from zkc_verifier import (
            BBVerifyBackend,
            VerificationKeyStore,
            VerifierTrustPolicy,
            ZKCVerifier,
        )
        from zkc_verifier import TrustedIssuer as VerifierTrustedIssuer

        return ZKCVerifier(
            REPO_ROOT,
            VerifierTrustPolicy(
                **apr_verifier_identity(APR_VERIFIER_A_PRIVATE_KEY),
                issuers=(
                    VerifierTrustedIssuer(
                        issuer_id=TEST_ISSUER_ID,
                        public_key_x=TEST_ISSUER_KEY_X,
                        public_key_y=TEST_ISSUER_KEY_Y,
                        proof_types=(KYC_V2_PROOF_TYPE,),
                    ),
                )
            ),
            BBVerifyBackend(REPO_ROOT),
            vk_store=VerificationKeyStore(manifest_path),
        )

    def _verification_request(self):
        from zkc_verifier import IssuerAccumulatorState, VerificationRequest

        return VerificationRequest(
            proof_types=[KYC_V2_PROOF_TYPE],
            binding_selectors=_binding_selectors(KYC_V2_PROOF_TYPE),
            parameters={KYC_V2_PROOF_TYPE: dict(KYC_PARAMETERS)},
            context=self.context,
            max_proof_age=3600,
            accumulator_states={
                TEST_ISSUER_ID: IssuerAccumulatorState(
                    current_epoch=self.provider.current_epoch(TEST_ISSUER_ID),
                    roots=self.provider.roots(TEST_ISSUER_ID),
                )
            },
        )

    def test_tampered_pseudonym_fails_bb_verification(self):
        """Flipping the pseudonym (consistently) breaks the circuit binding."""
        from zkc_verifier import VerificationErrorCode as Code

        source = self._kyc_v2_entry(self.envelope)
        real_pseudonym = hex_to_field(source["publicInputs"]["presentation_pseudonym"])
        # Another VALID canonical field element, distinct from the real one. It
        # keeps the envelope self-consistent (shape checks pass) but no longer
        # satisfies presentation_pseudonym == poseidon3(DOMAIN, cbk, scope_id).
        forged_pseudonym = (real_pseudonym + 1) % FIELD_MODULUS
        self.assertNotEqual(forged_pseudonym, real_pseudonym)
        forged_hex = field_to_hex(forged_pseudonym)

        tampered = copy.deepcopy(self.envelope)
        # Flip BOTH sides so the SDK's proof-vs-binding shape check still passes.
        tampered["presentationBinding"]["pseudonym"] = forged_hex
        entry = self._kyc_v2_entry(tampered)
        entry["publicInputs"]["presentation_pseudonym"] = forged_hex
        # scope_id is UNCHANGED, so the scope stays non-zero and self-consistent:
        # the only broken invariant is the circuit's pseudonym constraint.
        self.assertEqual(
            hex_to_field(tampered["presentationBinding"]["pseudonym"]),
            hex_to_field(entry["publicInputs"]["presentation_pseudonym"]),
        )
        self.assertNotEqual(hex_to_field(entry["publicInputs"]["scope_id"]), 0)

        encoder = PublicInputEncoder.load(
            REPO_ROOT / "schemas" / "public-inputs" / f"{KYC_V2_CIRCUIT}.json"
        )
        public_input_bytes = encoder.encode_bytes(entry["publicInputs"])

        with tempfile.TemporaryDirectory(prefix="zkc-live-vkstore-v2-tamper-") as tmp:
            tmp_path = pathlib.Path(tmp)
            manifest_path = _write_vk_manifest_v2(tmp_path, KYC_V2_CIRCUIT)

            # 1) A raw `bb verify` against the SAME VK MUST reject the forged
            #    pseudonym — the circuit, not the SDK, enforces the binding.
            raw = tmp_path / "raw"
            raw.mkdir()
            artifact = REPO_ROOT / "artifacts" / KYC_V2_CIRCUIT / f"{KYC_V2_CIRCUIT}.json"
            subprocess.run(
                ["bb", "write_vk", "-b", str(artifact), "-o", str(raw)],
                check=True, capture_output=True,
            )
            (raw / "proof").write_bytes(
                bytes.fromhex(entry["proof"].removeprefix("0x"))
            )
            (raw / "public_inputs").write_bytes(public_input_bytes)
            bb_result = subprocess.run(
                [
                    "bb", "verify",
                    "-k", str(raw / "vk"),
                    "-p", str(raw / "proof"),
                    "-i", str(raw / "public_inputs"),
                ],
                capture_output=True, text=True,
            )
            self.assertNotEqual(
                bb_result.returncode, 0,
                "a forged presentation_pseudonym must fail the circuit's binding "
                "constraint under raw bb verify",
            )

            # 2) ZKCVerifier surfaces the bb reject as INVALID_PROOF (the shape
            #    check passed because both sides were flipped consistently, so a
            #    PROFILE_MISMATCH would mean the pseudonym was only SDK-checked).
            verifier = self._bb_verifier(manifest_path)
            result = verifier.verify(tampered, self._verification_request())
            self.assertFalse(result.valid, result.to_dict())
            self.assertIn(Code.INVALID_PROOF, result.codes())
            self.assertNotIn(
                Code.PROFILE_MISMATCH,
                result.codes(),
                "a consistently-flipped pseudonym must be rejected by the CIRCUIT "
                "(INVALID_PROOF), not by the SDK shape check (PROFILE_MISMATCH)",
            )

    def test_scoped_proof_under_anonymous_binding_is_replay_rejected(self):
        """Splicing scoped proof entries under an anonymous binding => PROFILE_MISMATCH."""
        from zkc_verifier import VerificationErrorCode as Code

        spliced = copy.deepcopy(self.envelope)
        # Replay the SAME scoped proof entries under an ANONYMOUS binding. An
        # anonymous binding is profile-only (the v2 schema forbids pseudonym /
        # scopeId on it), so the scoped proof's non-zero handles now contradict
        # the declared profile.
        spliced["presentationBinding"] = {"profile": ANONYMOUS_PROFILE}
        entry = self._kyc_v2_entry(spliced)
        self.assertNotEqual(hex_to_field(entry["publicInputs"]["presentation_pseudonym"]), 0)
        self.assertNotEqual(hex_to_field(entry["publicInputs"]["scope_id"]), 0)

        with tempfile.TemporaryDirectory(prefix="zkc-live-vkstore-v2-replay-") as tmp:
            manifest_path = _write_vk_manifest_v2(pathlib.Path(tmp), KYC_V2_CIRCUIT)
            verifier = self._bb_verifier(manifest_path)
            result = verifier.verify(spliced, self._verification_request())
            self.assertFalse(result.valid, result.to_dict())
            self.assertIn(Code.PROFILE_MISMATCH, result.codes())


if __name__ == "__main__":
    unittest.main()

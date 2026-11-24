"""Regression: high-s ECDSA malleability (security review 2026-10-04, R7.3).

The reference secp256k1 verifier accepted any ``1 <= s < n``, while the signer
normalizes to low-s and the in-circuit verifier enforces ``s < (n + 1) / 2``.
A party without the issuer key could therefore flip ``s -> n - s`` on a signed
epoch announcement. The flipped copy verified with the same transcript but a
different complete hash, so (a) a re-served checkpoint was retained as false
equivocation evidence against an honest issuer and (b) a flipped next epoch was
accepted and persisted, after which every honest successor failed linkage.

These tests pin spec section 2.4.1: verification rejects every high-s
signature for every caller, and announcement conflicts are classified by
signing transcript, not by signature bytes.
"""

import copy
import dataclasses
import hashlib
import importlib.util
import json
import tempfile
import unittest

import _path  # noqa: F401
from _path import REPO_ROOT
from holder_fixtures import (
    TEST_ISSUER_ID,
    TEST_ISSUER_KEY_X,
    TEST_ISSUER_KEY_Y,
    issue_kyc_credential,
    trusted_test_issuer,
)
from test_audit_disclosure import AuditBundleTestBase
from zkc_crypto import (
    ProofContext,
    compute_kyc_credential_digest,
    context_value_from_fixture,
    derive_credential_binding_key,
    derive_holder_commitment_from_seed,
    digest_to_message_bytes,
    field_to_hex,
    holder_public_key,
    sign_receipt,
    verify_apr_signature,
    verify_receipt,
)
from zkc_crypto.delegation import ViewingScope, mint_delegation_token
from zkc_crypto.ecdsa_secp256k1 import (
    GX,
    GY,
    HALF_N,
    N,
    P,
    _add,
    _inv,
    _mul,
    public_key_bytes,
    sign,
    verify,
)
from zkc_holder import (
    ConstraintViolationError,
    LocalAccumulatorProvider,
    StubBackend,
    build_kyc_witness,
    verify_audit_bundle,
)
from zkc_holder.errors import StaleWitnessError
from zkc_issuer import IssuerSigningKey, SandboxIssuerAdapter
from zkc_revocation.chain import AnnouncementKeyPin
from zkc_revocation import (
    AnnouncementAuthenticationError,
    AnnouncementChain,
    ChainLinkageError,
    EpochGapError,
    InMemoryVerifierCheckpointStore,
    PrivateWitnessProvider,
    RevocationAccumulatorService,
    SQLiteVerifierCheckpointStore,
    VerifierAccumulatorCache,
    announcement_hash,
    announcement_transcript,
    compute_announcement_digest,
    verify_epoch_announcement,
)

TIMESTAMP = 1_770_000_000
SIGNING_KEY = IssuerSigningKey.test_issuer()
KEY_X, KEY_Y = SIGNING_KEY.public_key_coordinates()
KEY_PIN = AnnouncementKeyPin.from_signing_key_entry(SIGNING_KEY.metadata_entry())
ISSUER_ID = "zkc:issuer:sandbox"
ACCUMULATOR_ID = "sandbox-active-credentials"


def _flip_s(signature: bytes) -> bytes:
    """The keyless high-s twin (r, n - s) of a 64-byte r||s signature."""
    s = int.from_bytes(signature[32:], "big")
    return signature[:32] + (N - s).to_bytes(32, "big")


def _flip_s_hex(value: str) -> str:
    return "0x" + _flip_s(bytes.fromhex(value.removeprefix("0x"))).hex()


def _satisfies_ecdsa_equation(key_x: bytes, key_y: bytes, signature: bytes, digest: bytes) -> bool:
    """The unrestricted ECDSA equation, for showing a rejection is not vacuous."""
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    w = _inv(s, N)
    z = int.from_bytes(digest, "big")
    key = (int.from_bytes(key_x, "big"), int.from_bytes(key_y, "big"))
    point = _add(_mul(z * w % N, (GX, GY)), _mul(r * w % N, key))
    return point is not None and point[0] % N == r


def _sign_with_nonce(digest: bytes, private_key: int, nonce: int) -> bytes:
    """A valid low-s signature with a chosen (non-RFC 6979) nonce."""
    r = _mul(nonce, (GX, GY))[0] % N
    s = _inv(nonce, N) * (int.from_bytes(digest, "big") + r * private_key) % N
    if s > HALF_N:
        s = N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _malleate_announcement(announcement: dict) -> dict:
    out = copy.deepcopy(announcement)
    out["signature"] = _flip_s_hex(out["signature"])
    return out


def _resign_same_transcript(announcement: dict) -> dict:
    out = copy.deepcopy(announcement)
    digest = digest_to_message_bytes(compute_announcement_digest(out))
    nonce = int.from_bytes(hashlib.sha256(b"zkc-low-s-alternate-nonce").digest(), "big") % N
    out["signature"] = "0x" + _sign_with_nonce(digest, SIGNING_KEY.private_key, nonce).hex()
    return out


def _malleate_metadata(metadata: dict, mutate=_malleate_announcement) -> dict:
    out = copy.deepcopy(metadata)
    out["revocation"]["currentAnnouncement"] = mutate(out["revocation"]["currentAnnouncement"])
    return out


def _service():
    return RevocationAccumulatorService(
        ACCUMULATOR_ID,
        "https://issuer.sandbox.zkc.dev/v1/revocation/updates",
        SIGNING_KEY,
        clock=lambda: TIMESTAMP,
    )


def _adapter(service):
    return SandboxIssuerAdapter(signing_key=SIGNING_KEY, accumulator=service, clock=lambda: TIMESTAMP)


def _cache(store):
    return VerifierAccumulatorCache(
        {ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}},
        accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        checkpoint_store=store,
        clock=lambda: TIMESTAMP,
    )


class LowSVerifyTests(unittest.TestCase):
    def test_signer_output_is_low_s_and_its_twin_is_rejected(self):
        for private_key in (1, 7, 0xDEADBEEF, SIGNING_KEY.private_key, N - 2):
            key_x, key_y = public_key_bytes(private_key)
            for label in (b"a", b"b", b"c", b"d"):
                digest = hashlib.sha256(b"zkc-low-s/" + label).digest()
                with self.subTest(private_key=private_key, label=label):
                    signature = sign(digest, private_key)
                    self.assertLessEqual(int.from_bytes(signature[32:], "big"), HALF_N)
                    self.assertTrue(verify(key_x, key_y, signature, digest))
                    twin = _flip_s(signature)
                    # The twin satisfies the ECDSA equation: the rejection is
                    # the low-s rule, not an unrelated malformed-input check.
                    self.assertTrue(_satisfies_ecdsa_equation(key_x, key_y, twin, digest))
                    self.assertFalse(verify(key_x, key_y, twin, digest))

    def test_boundary_matches_the_circuit_bound(self):
        """s = floor(n/2) is accepted; s = floor(n/2) + 1 = n - floor(n/2) is not."""
        self.assertEqual(HALF_N, (N - 1) // 2)  # n is odd: s <= HALF_N <=> s < (n+1)/2
        self.assertEqual(N - HALF_N, HALF_N + 1)
        # Recover the public key for a chosen (r, s, z): Q = r^-1 (s R - z G).
        nonce_point = _mul(0x1234567, (GX, GY))
        r = nonce_point[0] % N
        digest = hashlib.sha256(b"zkc-low-s-boundary").digest()
        z = int.from_bytes(digest, "big")
        minus_z_g = _mul(z, (GX, GY))
        minus_z_g = (minus_z_g[0], (P - minus_z_g[1]) % P)
        key = _mul(_inv(r, N), _add(_mul(HALF_N, nonce_point), minus_z_g))
        key_x, key_y = key[0].to_bytes(32, "big"), key[1].to_bytes(32, "big")
        boundary = r.to_bytes(32, "big") + HALF_N.to_bytes(32, "big")
        self.assertTrue(verify(key_x, key_y, boundary, digest))
        above = _flip_s(boundary)
        self.assertEqual(int.from_bytes(above[32:], "big"), HALF_N + 1)
        self.assertTrue(_satisfies_ecdsa_equation(key_x, key_y, above, digest))
        self.assertFalse(verify(key_x, key_y, above, digest))

    def test_test_issuer_tool_verifier_rejects_high_s(self):
        spec = importlib.util.spec_from_file_location(
            "zkc_test_issuer_tool", REPO_ROOT / "tools" / "zkc_test_issuer.py"
        )
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        digest = hashlib.sha256(b"zkc-low-s-tool").digest()
        signature = tool.sign(digest)
        self.assertTrue(tool.verify(tool.public_key(), signature, digest))
        self.assertFalse(tool.verify(tool.public_key(), _flip_s(signature), digest))


class CallerAuditTests(unittest.TestCase):
    """Every verify caller rejects (r, n - s); each low-s original still passes."""

    def test_epoch_announcement(self):
        service = _service()
        service.register(101)
        honest = service.current_announcement()
        malleated = _malleate_announcement(honest)
        self.assertTrue(verify_epoch_announcement(honest, KEY_X, KEY_Y, SIGNING_KEY.key_id))
        self.assertEqual(announcement_transcript(malleated), announcement_transcript(honest))
        self.assertNotEqual(announcement_hash(malleated), announcement_hash(honest))
        self.assertFalse(verify_epoch_announcement(malleated, KEY_X, KEY_Y, SIGNING_KEY.key_id))

    def _signed_apr(self):
        vectors = json.loads((REPO_ROOT / "conformance" / "vectors" / "zkc_core.json").read_text())
        return copy.deepcopy(vectors["aprs"]["apr_access_signed"])

    def test_authenticated_proof_request(self):
        apr = self._signed_apr()
        self.assertTrue(verify_apr_signature(apr))
        apr["signature"]["value"] = _flip_s_hex(apr["signature"]["value"])
        self.assertFalse(verify_apr_signature(apr))

    def test_disclosure_receipt(self):
        apr = self._signed_apr()
        holder_key = holder_public_key(0xA11CE)
        receipt = sign_receipt({
            "apr": apr, "outcome": "answered", "recordedAt": 1,
            "response": {
                "holderCommitment": field_to_hex(7),
                "contextValue": field_to_hex(context_value_from_fixture(apr["request"]["context"])),
                "answeredProofTypes": list(apr["request"]["proofTypes"]),
            },
        }, 0xA11CE)
        self.assertTrue(verify_receipt(receipt, expected_holder_key=holder_key)["valid"])
        receipt["holderSignature"]["value"] = _flip_s_hex(receipt["holderSignature"]["value"])
        result = verify_receipt(receipt, expected_holder_key=holder_key)
        self.assertFalse(result["holderValid"])
        self.assertFalse(result["valid"])

        malleated_apr = copy.deepcopy(apr)
        malleated_apr["signature"]["value"] = _flip_s_hex(apr["signature"]["value"])
        self.assertFalse(verify_receipt({**receipt, "apr": malleated_apr},
                                        expected_holder_key=holder_key)["aprValid"])

    def test_delegation_token(self):
        context = ProofContext.verifier_session("verifier.example", 555, 1_700_000)
        principal_x, principal_y = public_key_bytes(0xA11CE5EED)
        token = mint_delegation_token(
            master_seed=4242,
            holder_commitment=derive_holder_commitment_from_seed(4242),
            principal_key_x=principal_x,
            principal_key_y=principal_y,
            scope=ViewingScope(
                proof_types=("zkc:proof:jurisdiction:v3",),
                context_value=context.value,
                verifier_id="verifier.example",
                expires_at=context.timestamp + 3600,
            ),
            issued_at=context.timestamp,
            nonce=17,
        )
        self.assertTrue(token.verify_signature())
        twin = dataclasses.replace(token, signature=_flip_s(token.signature))
        self.assertFalse(twin.verify_signature())

    def test_issuer_credential_in_the_stub_constraint_mirror(self):
        """The holder's Python mirror refuses a high-s credential like the circuit."""
        seed = bytes.fromhex("5e" * 32)
        provider = LocalAccumulatorProvider()
        credential = issue_kyc_credential(
            master_seed=seed, credential_id=7, provider=provider, expires_at=2_000_000_000
        )
        accumulator = provider.witness(TEST_ISSUER_ID, 7)

        def witness_for(signature):
            credential.signature = signature
            return build_kyc_witness(
                credential_binding_key=derive_credential_binding_key(seed),
                credential=credential, issuer=trusted_test_issuer(), witness=accumulator,
                required_level=1, required_attributes=[False] * 5, proof_context=12345,
                timestamp=1_700_000_000, current_epoch=accumulator.accumulator_epoch,
            )

        low = credential.signature
        StubBackend().prove("zkc_kyc", witness_for(low))
        high = _flip_s(low)
        with self.assertRaisesRegex(ConstraintViolationError, "invalid issuer signature"):
            StubBackend().prove("zkc_kyc", witness_for(high))
        # The rejected twin satisfies the ECDSA equation under the issuer key:
        # before the fix the mirror proved it while nargo refused it.
        digest = digest_to_message_bytes(compute_kyc_credential_digest(
            credential.holder_commitment, credential.credential_id,
            int(credential.claims["level"]), credential.claims["verifiedAttributes"],
            credential.expires_at,
        ))
        self.assertTrue(verify(TEST_ISSUER_KEY_X, TEST_ISSUER_KEY_Y, low, digest))
        self.assertTrue(_satisfies_ecdsa_equation(TEST_ISSUER_KEY_X, TEST_ISSUER_KEY_Y, high, digest))


class AuditBundleLowSTests(AuditBundleTestBase):
    def test_audit_bundle_authorization(self):
        bundle = self.export()
        self.assertTrue(verify_audit_bundle(bundle, now=self.context.timestamp,
                                            expected_holder_key=self.holder_key()).valid)
        bundle["authorization"]["signature"] = _flip_s_hex(bundle["authorization"]["signature"])
        result = verify_audit_bundle(bundle, now=self.context.timestamp,
                                     expected_holder_key=self.holder_key())
        self.assertFalse(result.valid)
        self.assertIn("BAD_AUTHORIZATION_SIGNATURE", result.codes())


class AnnouncementMalleabilityRegressionTests(unittest.TestCase):
    """The lane-6 PoC (poc1_malleability) as a regression test."""

    def test_re_served_malleated_checkpoint_is_not_equivocation(self):
        service = _service()
        adapter = _adapter(service)
        store = InMemoryVerifierCheckpointStore()
        verifier = _cache(store)
        service.register(101)
        verifier.ingest_metadata(ISSUER_ID, adapter.issuer_metadata())
        with self.assertRaises(AnnouncementAuthenticationError) as ctx:
            verifier.ingest_metadata(ISSUER_ID, _malleate_metadata(adapter.issuer_metadata()))
        self.assertNotIsInstance(ctx.exception, ChainLinkageError)
        self.assertEqual(ctx.exception.code, "ANNOUNCEMENT_AUTHENTICATION_FAILED")
        self.assertEqual(store.evidence(ISSUER_ID, ACCUMULATOR_ID), [])
        self.assertEqual(verifier.state(ISSUER_ID).current_epoch, 1)

    def test_malleated_next_epoch_is_rejected_and_the_honest_chain_advances(self):
        service = _service()
        adapter = _adapter(service)
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/verifier.sqlite3"
            store = SQLiteVerifierCheckpointStore(path)
            verifier = _cache(store)
            service.register(101)
            verifier.ingest_metadata(ISSUER_ID, adapter.issuer_metadata())  # epoch 1

            service.register(102)
            with self.assertRaises(AnnouncementAuthenticationError):
                verifier.ingest_metadata(ISSUER_ID, _malleate_metadata(adapter.issuer_metadata()))
            self.assertEqual(verifier.state(ISSUER_ID).current_epoch, 1)

            service.register(103)
            # The rejected epoch 2 is simply missing: an honest backfill heals it.
            with self.assertRaises(EpochGapError):
                verifier.ingest_metadata(ISSUER_ID, adapter.issuer_metadata())
            verifier.ingest_metadata(
                ISSUER_ID, adapter.issuer_metadata(),
                history_loader=lambda start, end: [
                    service.announcement_for_epoch(epoch) for epoch in range(start, end + 1)
                ],
            )
            self.assertEqual(verifier.state(ISSUER_ID).current_epoch, 3)
            self.assertEqual(store.evidence(ISSUER_ID, ACCUMULATOR_ID), [])
            store.close()

            restarted_store = SQLiteVerifierCheckpointStore(path)
            restarted = _cache(restarted_store)
            service.register(104)
            restarted.ingest_metadata(ISSUER_ID, adapter.issuer_metadata())
            self.assertEqual(restarted.state(ISSUER_ID).current_epoch, 4)
            self.assertEqual(restarted_store.evidence(ISSUER_ID, ACCUMULATOR_ID), [])
            restarted_store.close()

    def test_same_transcript_resignature_is_authentication_failure_not_fork(self):
        """Classification by transcript, independent of the low-s rule."""
        service = _service()
        adapter = _adapter(service)
        store = InMemoryVerifierCheckpointStore()
        verifier = _cache(store)
        service.register(101)
        metadata = adapter.issuer_metadata()
        verifier.ingest_metadata(ISSUER_ID, metadata)
        resigned = _malleate_metadata(metadata, _resign_same_transcript)
        candidate = resigned["revocation"]["currentAnnouncement"]
        # A genuinely valid, distinct low-s signature over the same statement.
        self.assertTrue(verify_epoch_announcement(candidate, KEY_X, KEY_Y, SIGNING_KEY.key_id))
        self.assertNotEqual(
            candidate["signature"], metadata["revocation"]["currentAnnouncement"]["signature"]
        )

        chain = AnnouncementChain(
            trusted_keys={SIGNING_KEY.key_id: KEY_PIN},
            checkpoint=metadata["revocation"]["currentAnnouncement"],
        )
        with self.assertRaises(AnnouncementAuthenticationError) as ctx:
            chain.ingest(candidate)
        self.assertNotIsInstance(ctx.exception, ChainLinkageError)
        with self.assertRaises(AnnouncementAuthenticationError):
            verifier.ingest_metadata(ISSUER_ID, resigned)
        self.assertEqual(store.evidence(ISSUER_ID, ACCUMULATOR_ID), [])

        service.register(102)
        verifier.ingest_metadata(ISSUER_ID, adapter.issuer_metadata())
        self.assertEqual(verifier.state(ISSUER_ID).current_epoch, 2)

    def test_different_transcript_at_the_same_epoch_is_still_a_fork(self):
        service = _service()
        service.register(101)
        honest = service.current_announcement()
        conflicting = copy.deepcopy(honest)
        conflicting["announcedAt"] += 1
        conflicting["signature"] = "0x" + SIGNING_KEY.sign_digest(
            compute_announcement_digest(conflicting)
        ).hex()
        chain = AnnouncementChain(trusted_keys={SIGNING_KEY.key_id: KEY_PIN}, checkpoint=honest)
        with self.assertRaises(ChainLinkageError) as ctx:
            chain.ingest(conflicting)
        self.assertEqual(ctx.exception.code, "CHAIN_FORKED")


class _MalleatingRelay:
    """A keyless relay in front of the issuer's revocation service."""

    def __init__(self, inner, mutate):
        self.inner = inner
        self.mutate = mutate
        self.enabled = False

    @property
    def accumulator_id(self):
        return self.inner.accumulator_id

    @property
    def epoch(self):
        return self.inner.epoch

    def handle_request(self, request):
        response = self.inner.handle_request(request)
        if self.enabled:
            response = dict(response)
            response["announcement"] = self.mutate(response["announcement"])
        return response

    def announcement_for_epoch(self, epoch):
        return self.inner.announcement_for_epoch(epoch)


class HolderRelayRegressionTests(unittest.TestCase):
    def _run(self, mutate):
        service = _service()
        relay = _MalleatingRelay(service, mutate)
        store = InMemoryVerifierCheckpointStore()
        holder = PrivateWitnessProvider(
            {ISSUER_ID: relay},
            issuer_keys={ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}},
            announcement_sources={ISSUER_ID: service},
            checkpoint_store=store,
            clock=lambda: TIMESTAMP,
            accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        )
        service.register(101)
        holder.witness(ISSUER_ID, 101)
        service.register(105)
        relay.enabled = True
        with self.assertRaisesRegex(StaleWitnessError, "ANNOUNCEMENT_AUTHENTICATION_FAILED"):
            holder.witness(ISSUER_ID, 101)
        relay.enabled = False
        service.register(106)
        witness = holder.witness(ISSUER_ID, 101)
        self.assertEqual(witness.accumulator_epoch, service.epoch)
        scope = PrivateWitnessProvider.checkpoint_scope(ACCUMULATOR_ID)
        self.assertEqual(store.evidence(ISSUER_ID, scope), [])

    def test_holder_behind_a_high_s_relay_keeps_advancing(self):
        self._run(_malleate_announcement)

    def test_holder_rejects_a_same_epoch_resignature_without_evidence(self):
        service = _service()
        service.register(101)
        store = InMemoryVerifierCheckpointStore()
        relay = _MalleatingRelay(service, _resign_same_transcript)
        holder = PrivateWitnessProvider(
            {ISSUER_ID: relay},
            issuer_keys={ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}},
            announcement_sources={ISSUER_ID: service},
            checkpoint_store=store,
            clock=lambda: TIMESTAMP,
            accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        )
        holder.witness(ISSUER_ID, 101)
        relay.enabled = True
        with self.assertRaisesRegex(StaleWitnessError, "ANNOUNCEMENT_AUTHENTICATION_FAILED"):
            holder.witness(ISSUER_ID, 101)
        scope = PrivateWitnessProvider.checkpoint_scope(ACCUMULATOR_ID)
        self.assertEqual(store.evidence(ISSUER_ID, scope), [])


if __name__ == "__main__":
    unittest.main()

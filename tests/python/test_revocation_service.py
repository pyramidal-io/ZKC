"""Tests for the zkc_revocation accumulator + witness update service."""

import json
import unittest

import _path  # noqa: F401
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from _path import REPO_ROOT

from zkc_crypto import (
    compute_merkle_root,
    field_to_hex,
    hex_to_field,
)
from zkc_holder import (
    HolderClient,
    PredicateRegistry,
    ProofRequest,
    StubBackend,
    TrustPolicy,
    TrustedIssuer,
)
from zkc_holder.errors import StaleWitnessError
from zkc_issuer import (
    FORBIDDEN_FIELDS,
    AdapterError,
    IssuerSigningKey,
    SandboxIssuerAdapter,
)
from zkc_revocation.chain import AnnouncementKeyPin
from zkc_revocation import (
    ANNOUNCEMENT_VERSION,
    WITNESS_UPDATE_REQUEST,
    AnnouncementAuthenticationError,
    AnnouncementMetadataError,
    AnnouncementReplayError,
    InMemoryVerifierCheckpointStore,
    RevocationAccumulatorService,
    VerifierAccumulatorCache,
    WitnessUpdateProvider,
    announcement_hash,
    announcement_transcript,
    apply_witness_delta,
    complete_announcement_bytes,
    compute_announcement_digest,
    verify_epoch_announcement,
)
from zkc_crypto import ProofContext
from zkc_verifier import (
    StubVerifyBackend,
    VerificationErrorCode,
    VerificationRequest,
    VerifierTrustPolicy,
    ZKCVerifier,
)
from zkc_verifier import TrustedIssuer as VerifierTrustedIssuer

ISSUER_ID = "zkc:issuer:sandbox"
KYC_SCHEMA_ID = "zkc:cred:kyc:v1"
KYC_PROOF_TYPE = "zkc:proof:kyc:v1"
MASTER_SEED = 9001
TIMESTAMP = 1_770_000_000

SIGNING_KEY = IssuerSigningKey.test_issuer()
KEY_X, KEY_Y = SIGNING_KEY.public_key_coordinates()
KEY_PIN = AnnouncementKeyPin.from_signing_key_entry(SIGNING_KEY.metadata_entry())


def _service(**kwargs) -> RevocationAccumulatorService:
    kwargs.setdefault("clock", lambda: TIMESTAMP)
    return RevocationAccumulatorService(
        "sandbox-active-credentials",
        "https://issuer.sandbox.zkc.dev/v1/revocation/updates",
        SIGNING_KEY,
        **kwargs,
    )


def _verifier_cache(**kwargs) -> VerifierAccumulatorCache:
    return VerifierAccumulatorCache(
        {ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}},
        accumulator_ids={ISSUER_ID: "sandbox-active-credentials"},
        checkpoint_store=InMemoryVerifierCheckpointStore(),
        clock=lambda: TIMESTAMP,
        **kwargs,
    )


def _metadata(service):
    return SandboxIssuerAdapter(
        signing_key=SIGNING_KEY, accumulator=service, clock=lambda: TIMESTAMP
    ).issuer_metadata()


def _update_request(service, credential_id: int, from_epoch=None) -> dict:
    request = {
        "type": WITNESS_UPDATE_REQUEST,
        "accumulatorId": service.accumulator_id,
        "credentialId": field_to_hex(credential_id),
    }
    if from_epoch is not None:
        request["fromEpoch"] = from_epoch
    return request


def _scan_keys(value, hits):
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_FIELDS:
                hits.append(key)
            _scan_keys(child, hits)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _scan_keys(child, hits)


class EpochAnnouncementTests(unittest.TestCase):
    def test_v3_helpers_match_the_canonical_public_vector(self):
        vector = json.loads(
            (REPO_ROOT / "tests" / "vectors" / "revocation_announcement_v3.json").read_text()
        )
        announcement = vector["announcement"]
        self.assertEqual("0x" + announcement_transcript(announcement).hex(), vector["transcriptHex"])
        digest = compute_announcement_digest(announcement)
        self.assertEqual("0x" + digest.to_bytes(32, "big").hex(), vector["signingDigest"])
        self.assertEqual(
            "0x" + complete_announcement_bytes(announcement).hex()[-128:],
            announcement["signature"],
        )
        self.assertEqual(announcement_hash(announcement), vector["announcementHash"])
        self.assertTrue(verify_epoch_announcement(announcement, KEY_X, KEY_Y))

    def test_lifecycle_advances_epoch_and_signs_announcements(self):
        service = _service()
        self.assertEqual(service.epoch, 0)
        service.register(101)
        service.register(202)
        self.assertEqual(service.epoch, 2)
        announcement = service.current_announcement()
        self.assertEqual(announcement["version"], ANNOUNCEMENT_VERSION)
        self.assertEqual(announcement["epoch"], 2)
        self.assertEqual(announcement["root"], field_to_hex(service.root()))
        self.assertTrue(verify_epoch_announcement(announcement, KEY_X, KEY_Y))

        service.revoke(101)
        self.assertEqual(service.epoch, 3)
        self.assertNotEqual(service.current_announcement()["root"], announcement["root"])

    def test_tampered_announcements_fail_verification(self):
        service = _service()
        service.register(101)
        announcement = service.current_announcement()
        for mutation in (
            {"epoch": announcement["epoch"] + 1},
            {"root": field_to_hex(1)},
            {"announcedAt": announcement["announcedAt"] + 1},
            {"accumulatorId": "someone-else"},
            {"signature": "0x" + "00" * 64},
            {"version": "zkc:epoch-announcement:v1"},
            {"previousAnnouncementHash": "0x" + "11" * 32},
            {"maxEpochLag": announcement["maxEpochLag"] - 1},
            {"signingKeyId": "untrusted-rotation"},
            {"extra": "not-in-the-closed-v3-shape"},
        ):
            with self.subTest(mutation=mutation):
                self.assertFalse(
                    verify_epoch_announcement({**announcement, **mutation}, KEY_X, KEY_Y)
                )
        # Wrong issuer key must not verify either.
        rogue = IssuerSigningKey.generate("rogue")
        rx, ry = rogue.public_key_coordinates()
        self.assertFalse(verify_epoch_announcement(announcement, rx, ry))

    def test_historical_announcements_are_served_and_bounded(self):
        service = _service()
        for credential_id in (101, 202, 303):
            service.register(credential_id)
        history = service.announcement_history(from_epoch=1)
        self.assertEqual([item["epoch"] for item in history], [1, 2, 3])
        self.assertEqual(history, [service.announcement_for_epoch(i) for i in range(1, 4)])
        with self.assertRaises(AdapterError) as ctx:
            service.announcement_for_epoch(99)
        self.assertEqual(ctx.exception.code, "REVOCATION_METADATA_UNAVAILABLE")

    def test_authenticated_metadata_is_an_exact_snapshot_of_the_announcement(self):
        service = _service()
        service.register(101)
        metadata = service.metadata()
        announcement = metadata["currentAnnouncement"]
        self.assertEqual(metadata["accumulatorId"], announcement["accumulatorId"])
        self.assertEqual(metadata["currentRoot"], announcement["root"])
        self.assertEqual(metadata["currentEpoch"], announcement["epoch"])
        self.assertEqual(metadata["maxEpochLag"], announcement["maxEpochLag"])

    def test_default_issuer_metadata_publishes_v2_but_plain_accumulator_stays_legacy(self):
        adapter = SandboxIssuerAdapter(clock=lambda: TIMESTAMP)
        metadata = adapter.issuer_metadata()
        self.assertEqual(metadata["version"], "zkc:issuer-metadata:v2")
        self.assertEqual(
            metadata["revocation"]["currentAnnouncement"]["signingKeyId"],
            metadata["signingKeys"][0]["keyId"],
        )
        from zkc_issuer import IssuerAccumulator, build_issuer_metadata
        from zkc_issuer.schemas import SUPPORTED_SCHEMAS

        legacy = build_issuer_metadata(
            "zkc:issuer:legacy",
            "Legacy Issuer",
            [SIGNING_KEY],
            [SUPPORTED_SCHEMAS[KYC_SCHEMA_ID]],
            IssuerAccumulator("legacy-active", "https://legacy.example/v1/revocation/updates"),
            "https://legacy.example",
        )
        self.assertEqual(legacy["version"], "zkc:issuer-metadata:v1")
        self.assertNotIn("currentAnnouncement", legacy["revocation"])

    def test_metadata_builder_rejects_an_invalid_authenticated_snapshot(self):
        from zkc_issuer import build_issuer_metadata
        from zkc_issuer.schemas import SUPPORTED_SCHEMAS

        service = _service()
        service.register(101)

        class TamperedAccumulator:
            def metadata(self):
                metadata = service.metadata()
                metadata["currentAnnouncement"]["signature"] = "0x" + "00" * 64
                return metadata

        with self.assertRaisesRegex(ValueError, "signature"):
            build_issuer_metadata(
                ISSUER_ID,
                "Sandbox",
                [SIGNING_KEY],
                [SUPPORTED_SCHEMAS[KYC_SCHEMA_ID]],
                TamperedAccumulator(),
                "https://issuer.sandbox.zkc.dev",
            )


class WitnessUpdateProtocolTests(unittest.TestCase):
    def test_full_refresh(self):
        service = _service()
        service.register(101)
        response = service.handle_request(_update_request(service, 101))
        self.assertEqual(response["mode"], "full")
        witness = response["witness"]
        recomputed = compute_merkle_root(
            101, witness["pathIndex"], [hex_to_field(s) for s in witness["siblings"]]
        )
        self.assertEqual(field_to_hex(recomputed), response["root"])
        self.assertTrue(verify_epoch_announcement(response["announcement"], KEY_X, KEY_Y))

    def test_delta_refresh_matches_full_refresh(self):
        service = _service()
        service.register(101)
        old = service.handle_request(_update_request(service, 101))["witness"]
        # Another issuance and a revocation change the tree.
        service.register(202)
        service.register(303)
        service.revoke(202)

        delta_response = service.handle_request(
            _update_request(service, 101, from_epoch=old["accumulatorEpoch"])
        )
        self.assertEqual(delta_response["mode"], "delta")
        changed = delta_response["witnessDelta"]["changedSiblings"]
        self.assertTrue(0 < len(changed) < 32, changed)

        patched = apply_witness_delta(old, delta_response)
        full = service.handle_request(_update_request(service, 101))["witness"]
        self.assertEqual(patched, full)

    def test_unknown_from_epoch_falls_back_to_full(self):
        service = _service()
        service.register(101)
        response = service.handle_request(_update_request(service, 101, from_epoch=77))
        self.assertEqual(response["mode"], "full")

    def test_revoked_and_unknown_credentials_fail_closed(self):
        service = _service()
        service.register(101)
        service.revoke(101)
        with self.assertRaises(AdapterError) as ctx:
            service.handle_request(_update_request(service, 101))
        self.assertEqual(ctx.exception.code, "STALE_ACCUMULATOR_WITNESS")
        with self.assertRaises(AdapterError) as ctx:
            service.handle_request(_update_request(service, 999))
        self.assertEqual(ctx.exception.code, "STALE_ACCUMULATOR_WITNESS")

    def test_malformed_requests_fail_closed(self):
        service = _service()
        service.register(101)
        with self.assertRaises(AdapterError) as ctx:
            service.handle_request({"type": "zkc:other:v1"})
        self.assertEqual(ctx.exception.code, "REVOCATION_METADATA_UNAVAILABLE")
        with self.assertRaises(AdapterError) as ctx:
            service.handle_request(
                {**_update_request(service, 101), "accumulatorId": "not-mine"}
            )
        self.assertEqual(ctx.exception.code, "REVOCATION_METADATA_UNAVAILABLE")
        with self.assertRaises(AdapterError) as ctx:
            service.handle_request(
                {
                    "type": WITNESS_UPDATE_REQUEST,
                    "accumulatorId": service.accumulator_id,
                    "credentialId": "not-hex",
                }
            )
        self.assertEqual(ctx.exception.code, "STALE_ACCUMULATOR_WITNESS")

    def test_delta_apply_guards(self):
        service = _service()
        service.register(101)
        full = service.handle_request(_update_request(service, 101))
        with self.assertRaises(ValueError):
            apply_witness_delta(full["witness"], full)  # not a delta


class ZkaIndependenceTests(unittest.TestCase):
    def test_revocation_documents_carry_no_wallet_material(self):
        """Schema-level: announcements, updates, and metadata are ZKA-free."""
        service = _service()
        service.register(101)
        documents = {
            "announcement": service.current_announcement(),
            "witness_response": service.handle_request(_update_request(service, 101)),
            "metadata": service.metadata(),
        }
        for name, document in documents.items():
            with self.subTest(document=name):
                hits = []
                _scan_keys(document, hits)
                self.assertEqual(hits, [], f"wallet material in {name}: {hits}")
                rendered = json.dumps(document)
                for needle in ("zka", "payment", "wallet", "note", "seed"):
                    self.assertNotIn(needle, rendered.lower())

    def test_announcement_keys_are_a_closed_set(self):
        service = _service()
        self.assertEqual(
            sorted(service.current_announcement()),
            [
                "accumulatorId",
                "announcedAt",
                "epoch",
                "maxEpochLag",
                "previousAnnouncementHash",
                "root",
                "signature",
                "signingKeyId",
                "version",
            ],
        )


class VerifierAccumulatorCacheTests(unittest.TestCase):
    def test_ingest_validates_and_tracks_epochs(self):
        service = _service()
        cache = _verifier_cache()
        cache.ingest_metadata(ISSUER_ID, _metadata(service))
        service.register(101)
        cache.ingest_metadata(ISSUER_ID, _metadata(service))
        state = cache.state(ISSUER_ID)
        self.assertEqual(state.current_epoch, 1)
        self.assertEqual(state.roots[1], service.root())

    def test_rejects_unknown_issuer_bad_signature_and_regressing_epoch(self):
        service = _service()
        service.register(101)
        cache = _verifier_cache()
        metadata = _metadata(service)
        with self.assertRaises(AnnouncementMetadataError):
            cache.ingest_metadata("zkc:issuer:unknown", metadata)
        tampered = json.loads(json.dumps(metadata))
        tampered["revocation"]["currentAnnouncement"]["root"] = field_to_hex(1)
        tampered["revocation"]["currentRoot"] = field_to_hex(1)
        with self.assertRaises(AnnouncementAuthenticationError):
            cache.ingest_metadata(ISSUER_ID, tampered)
        cache.ingest_metadata(ISSUER_ID, metadata)
        # Re-polling the persisted head is a silent no-op (specification
        # 2.4.2); an older head is still a replay.
        cache.ingest_metadata(ISSUER_ID, metadata)
        self.assertEqual(cache.state(ISSUER_ID).current_epoch, 1)
        regressing = json.loads(json.dumps(metadata))
        genesis = service.announcement_for_epoch(0)
        regressing["revocation"].update(
            currentAnnouncement=genesis, currentRoot=genesis["root"], currentEpoch=0
        )
        regressing["revocation"].pop("currentLiveness")
        with self.assertRaises(AnnouncementReplayError):
            cache.ingest_metadata(ISSUER_ID, regressing)
        with self.assertRaises(KeyError):
            cache.state("zkc:issuer:nobody")

    def test_root_retention_is_bounded_by_the_lag_window(self):
        service = _service()
        cache = _verifier_cache(max_epoch_lag=2)
        for credential_id in range(1, 6):
            service.register(credential_id)
            cache.ingest_metadata(ISSUER_ID, _metadata(service))
        state = cache.state(ISSUER_ID)
        self.assertEqual(state.current_epoch, 5)
        self.assertEqual(sorted(state.roots), [3, 4, 5])


class EndToEndRevocationTests(unittest.TestCase):
    """issue -> prove (accept) -> revoke -> refresh fails -> prove rejected."""

    def _build_stack(self):
        service = _service()
        adapter = SandboxIssuerAdapter(
            signing_key=SIGNING_KEY, accumulator=service, clock=lambda: TIMESTAMP
        )
        provider = WitnessUpdateProvider(
            {ISSUER_ID: service},
            {ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}},
            checkpoint_store=InMemoryVerifierCheckpointStore(),
            clock=lambda: TIMESTAMP,
            accumulator_ids={ISSUER_ID: "sandbox-active-credentials"},
        )
        client = HolderClient.from_seed(
            MASTER_SEED,
            PredicateRegistry.from_repo(REPO_ROOT),
            StubBackend(),
            accumulator_provider=provider,
        )
        context = ProofContext.verifier_session("verifier.example", 7, TIMESTAMP)
        parameters = {
            KYC_PROOF_TYPE: {
                "requiredLevel": 1,
                "requiredAttributes": [True, False, False, False, True],
            }
        }
        trusted = TrustedIssuer(
            issuer_id=ISSUER_ID,
            public_key_x=KEY_X,
            public_key_y=KEY_Y,
            proof_types=(KYC_PROOF_TYPE,),
        )
        holder_request = ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters=parameters,
            context=context,
            trust_policy=TrustPolicy(issuers=(trusted,)),
        )
        verifier = ZKCVerifier(
            REPO_ROOT,
            VerifierTrustPolicy(
                issuers=(
                    VerifierTrustedIssuer(
                        issuer_id=ISSUER_ID,
                        public_key_x=KEY_X,
                        public_key_y=KEY_Y,
                        proof_types=(KYC_PROOF_TYPE,),
                    ),
                )
            ),
            StubVerifyBackend(),
        )
        cache = _verifier_cache()
        return service, adapter, provider, client, holder_request, verifier, cache, context, parameters

    def _obtain_credential(self, adapter, client):
        from zkc_holder import Credential

        holder_commitment_hex = field_to_hex(client.get_binding_commitment())
        subject = adapter.verify_subject(
            {"schemaId": KYC_SCHEMA_ID, "fixtureId": "sandbox-alice-basic"}
        )
        challenge = adapter.request_binding_challenge(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": holder_commitment_hex,
                "schemaId": KYC_SCHEMA_ID,
            }
        )
        response = client.binding_challenge_response(
            adapter.issuer_id, KYC_SCHEMA_ID, challenge["nonce"], challenge["expiresAt"]
        )
        adapter.bind_holder_commitment(
            {
                "subjectRef": subject["subjectRef"],
                "holderCommitment": holder_commitment_hex,
                "schemaId": KYC_SCHEMA_ID,
                "nonce": challenge["nonce"],
                "challengeResponse": response,
            }
        )
        envelope = adapter.issue_credential(
            {"subjectRef": subject["subjectRef"], "schemaId": KYC_SCHEMA_ID}
        )
        credential = Credential.from_dict(envelope["credential"])
        client.store_credential(credential)
        return credential

    def test_issue_prove_revoke_reject(self):
        (
            service,
            adapter,
            provider,
            client,
            holder_request,
            verifier,
            cache,
            context,
            parameters,
        ) = self._build_stack()
        credential = self._obtain_credential(adapter, client)

        # Accepted while active.
        envelope = generate_unauthenticated_linkable(client, holder_request)
        cache.refresh_from_issuer(ISSUER_ID, adapter)
        request = VerificationRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters=parameters,
            context=context,
            accumulator_states=cache.accumulator_states(),
        )
        result = verifier.verify(envelope, request)
        self.assertTrue(result.valid, result.to_dict())

        # Revoke -> witness refresh fails closed at the holder.
        adapter.revoke_credential(credential.credential_id)
        with self.assertRaises(StaleWitnessError):
            client.update_witness(credential.credential_id)
        with self.assertRaises(StaleWitnessError):
            generate_unauthenticated_linkable(client, holder_request)

        # The pre-revocation envelope is rejected against the new epoch.
        cache.refresh_from_issuer(ISSUER_ID, adapter)
        stale_request = VerificationRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters=parameters,
            context=context,
            accumulator_states=cache.accumulator_states(),
        )
        stale_result = verifier.verify(envelope, stale_request)
        self.assertFalse(stale_result.valid)
        self.assertIn(VerificationErrorCode.STALE_ACCUMULATOR, stale_result.codes())

    def test_delta_refresh_path_is_exercised_in_proof_generation(self):
        (
            service,
            adapter,
            provider,
            client,
            holder_request,
            verifier,
            cache,
            context,
            parameters,
        ) = self._build_stack()
        self._obtain_credential(adapter, client)
        generate_unauthenticated_linkable(client, holder_request)  # first refresh: full
        service.register(987_654_321)  # tree changes underneath the holder
        envelope = generate_unauthenticated_linkable(client, holder_request)  # second refresh: delta
        self.assertIn("delta", provider.refresh_modes)
        cache.refresh_from_issuer(ISSUER_ID, adapter)
        result = verifier.verify(
            envelope,
            VerificationRequest(
                proof_types=[KYC_PROOF_TYPE],
                parameters=parameters,
                context=context,
                accumulator_states=cache.accumulator_states(),
            ),
        )
        self.assertTrue(result.valid, result.to_dict())

    def test_stale_epoch_is_rejected_without_refresh(self):
        """A holder whose witness lags more than MAX_EPOCH_LAG fails closed."""
        (
            service,
            adapter,
            provider,
            client,
            holder_request,
            verifier,
            cache,
            context,
            parameters,
        ) = self._build_stack()
        self._obtain_credential(adapter, client)

        # Detach the holder from the update service (no refresh possible) and
        # advance the issuer accumulator beyond the lag bound.
        client._accumulator_provider = None
        for credential_id in range(1_000, 1_011):
            service.register(credential_id)
        stale_request = ProofRequest(
            proof_types=[KYC_PROOF_TYPE],
            parameters=parameters,
            context=context,
            trust_policy=holder_request.trust_policy,
            current_epochs={ISSUER_ID: service.epoch},
        )
        with self.assertRaises(StaleWitnessError):
            generate_unauthenticated_linkable(client, stale_request)


if __name__ == "__main__":
    unittest.main()

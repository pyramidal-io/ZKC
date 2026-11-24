"""Network transport for the issuer + revocation services over real loopback HTTP.

Stands up ``RevocationServer`` / ``IssuerServer`` on an ephemeral 127.0.0.1
port and drives them through the client SDKs — no mocks, an actual TCP socket.
Covers the witness-update + epoch-delta wire shapes, the holder-SDK HTTP
accumulator provider (delta-aware, root-verified), the four issuer adapter
stages end to end, and structured error mapping (AdapterError -> HTTP 422 ->
TransportError with the protocol code).
"""

import json
import unittest
import urllib.request
from unittest.mock import patch

import _path  # noqa: F401
from holder_fixtures import generate_unauthenticated_linkable  # noqa: E402
from _path import REPO_ROOT

from zkc_crypto import (
    ProofContext,
    derive_holder_commitment_from_seed,
    field_to_hex,
    hex_to_field,
    validate_compliance_proof_v1,
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
from zkc_issuer import IssuerSigningKey, SandboxIssuerAdapter, compute_binding_response
from zkc_revocation.chain import AnnouncementKeyPin
from zkc_revocation import (
    ANNOUNCEMENT_VERSION,
    EPOCH_DELTA_REQUEST,
    InMemoryVerifierCheckpointStore,
    PrivateWitnessProvider,
    RevocationAccumulatorService,
    WitnessUpdateProvider,
    compute_announcement_digest,
)
from zkc_transport import (
    REVOCATION_ANNOUNCEMENT_PATH,
    HTTPWitnessUpdateProvider,
    IssuerServer,
    IssuerServiceClient,
    RevocationServer,
    RevocationServiceClient,
    TransportError,
)

ISSUER_ID = "did:zkc:test-issuer"
ACCUMULATOR_ID = "sandbox-active-credentials"
UPDATE_ENDPOINT = "https://issuer.sandbox.zkc.dev/v1/revocation/updates"
KYC_SCHEMA_ID = "zkc:cred:kyc:v1"
KYC_PROOF_TYPE = "zkc:proof:kyc:v1"
TIMESTAMP = 1_770_000_000

SIGNING_KEY = IssuerSigningKey.test_issuer()
KEY_X, KEY_Y = SIGNING_KEY.public_key_coordinates()
KEY_PIN = AnnouncementKeyPin.from_signing_key_entry(SIGNING_KEY.metadata_entry())
ISSUER_KEYS = {ISSUER_ID: {SIGNING_KEY.key_id: KEY_PIN}}


def _service(**kwargs) -> RevocationAccumulatorService:
    kwargs.setdefault("clock", lambda: TIMESTAMP)
    return RevocationAccumulatorService(ACCUMULATOR_ID, UPDATE_ENDPOINT, SIGNING_KEY, **kwargs)


class RevocationTransportTests(unittest.TestCase):
    def test_witness_update_full_over_http(self):
        service = _service()
        service.register(1001)
        with RevocationServer(service) as server:
            client = RevocationServiceClient(server.base_url)
            response = client.witness_update(ACCUMULATOR_ID, 1001)
            self.assertEqual(response["mode"], "full")
            self.assertEqual(response["accumulatorId"], ACCUMULATOR_ID)
            self.assertIn("witness", response)
            self.assertEqual(response["announcement"]["version"], ANNOUNCEMENT_VERSION)

    def test_witness_update_delta_over_http(self):
        service = _service()
        service.register(1001)
        with RevocationServer(service) as server:
            client = RevocationServiceClient(server.base_url)
            first = client.witness_update(ACCUMULATOR_ID, 1001)
            from_epoch = first["epoch"]
            # New registration changes the tree, so a delta is servable.
            service.register(1002)
            delta = client.witness_update(ACCUMULATOR_ID, 1001, from_epoch=from_epoch)
            self.assertEqual(delta["mode"], "delta")
            self.assertEqual(delta["witnessDelta"]["fromEpoch"], from_epoch)

    def test_epoch_delta_over_http(self):
        service = _service()
        service.register(1001)
        with RevocationServer(service) as server:
            client = RevocationServiceClient(server.base_url)
            response = client.epoch_delta(ACCUMULATOR_ID)
            self.assertEqual(response["mode"], "full")
            self.assertIn("leaves", response)

    def test_announcements_over_http(self):
        service = _service()
        service.register(1001)  # epoch 1
        service.register(1002)  # epoch 2
        with RevocationServer(service) as server:
            client = RevocationServiceClient(server.base_url)
            current = client.current_announcement()
            self.assertEqual(current["epoch"], 2)
            genesis = client.announcement_for_epoch(0)
            self.assertEqual(genesis["epoch"], 0)
            # The chain link is intact across the HTTP boundary.
            self.assertEqual(genesis["previousAnnouncementHash"], "0x" + "00" * 32)

    def test_revoked_credential_maps_to_transport_error(self):
        service = _service()
        service.register(1001)
        service.revoke(1001)
        with RevocationServer(service) as server:
            client = RevocationServiceClient(server.base_url)
            with self.assertRaises(TransportError) as ctx:
                client.witness_update(ACCUMULATOR_ID, 1001)
            self.assertEqual(ctx.exception.status, 422)
            self.assertEqual(ctx.exception.code, "STALE_ACCUMULATOR_WITNESS")

    def test_unknown_accumulator_maps_to_transport_error(self):
        service = _service()
        service.register(1001)
        with RevocationServer(service) as server:
            client = RevocationServiceClient(server.base_url)
            with self.assertRaises(TransportError) as ctx:
                client.witness_update("wrong-accumulator", 1001)
            self.assertEqual(ctx.exception.code, "REVOCATION_METADATA_UNAVAILABLE")


class HolderOverHTTPTests(unittest.TestCase):
    """A full holder proof generation where witnesses are refreshed over HTTP."""

    def test_private_provider_refreshes_locally_from_credential_anonymous_http_requests(self):
        service = _service()
        service.register(1001)
        store = InMemoryVerifierCheckpointStore()
        with patch.object(
            service, "handle_request", wraps=service.handle_request
        ) as updates, patch.object(
            service, "announcement_for_epoch", wraps=service.announcement_for_epoch
        ) as history, RevocationServer(service) as server:
            client = RevocationServiceClient(server.base_url)
            provider = PrivateWitnessProvider(
                {ISSUER_ID: (client, ACCUMULATOR_ID)}, ISSUER_KEYS,
                announcement_sources={ISSUER_ID: service},
                checkpoint_store=store, clock=lambda: TIMESTAMP,
            )
            self.assertEqual(provider.witness(ISSUER_ID, 1001).to_dict(), service.witness(1001))
            service.register(1002)
            service.register(1003)
            self.assertEqual(provider.witness(ISSUER_ID, 1002).to_dict(), service.witness(1002))
            history.assert_called_once_with(2)
            self.assertEqual(provider.current_epoch(ISSUER_ID), 3)

            service.revoke(1001)
            with self.assertRaises(StaleWitnessError):
                provider.witness(ISSUER_ID, 1001)
            request = {"type": EPOCH_DELTA_REQUEST, "accumulatorId": ACCUMULATOR_ID}
            self.assertEqual([entry.args[0] for entry in updates.call_args_list], [request] * 3)
            with self.assertRaisesRegex(ValueError, "pinned revocation accumulator id"):
                PrivateWitnessProvider(
                    {ISSUER_ID: client}, ISSUER_KEYS,
                    announcement_sources={ISSUER_ID: service}, checkpoint_store=store,
                )

    def test_private_refresh_accepts_only_the_published_head_with_invariant_http_body(self):
        service = _service()
        service.register(1001)
        service.register(1002)
        request = {"type": EPOCH_DELTA_REQUEST, "accumulatorId": ACCUMULATOR_ID}
        older_state = service.handle_request(request)
        cold_store = InMemoryVerifierCheckpointStore()

        with RevocationServer(service) as leaves, RevocationServer(service) as publication, patch(
            "urllib.request.urlopen", wraps=urllib.request.urlopen,
        ) as http:
            client = RevocationServiceClient(leaves.base_url)
            sources = {ISSUER_ID: RevocationServiceClient(publication.base_url)}

            def holder(store):
                return PrivateWitnessProvider(
                    {ISSUER_ID: (client, ACCUMULATOR_ID)}, ISSUER_KEYS,
                    announcement_sources=sources, checkpoint_store=store,
                    clock=lambda: TIMESTAMP,
                )

            established = holder(InMemoryVerifierCheckpointStore())
            cold = holder(cold_store)
            self.assertEqual(established.witness(ISSUER_ID, 1001).accumulator_epoch, 2)
            service.register(1003)
            service.register(1004)
            with patch.object(service, "handle_request", return_value=older_state):
                with self.assertRaisesRegex(StaleWitnessError, "independently published"):
                    cold.witness(ISSUER_ID, 1002)
                self.assertIsNone(cold_store.load_checkpoint(
                    ISSUER_ID, cold.checkpoint_scope(ACCUMULATOR_ID),
                ))
                self.assertEqual(established.current_epoch(ISSUER_ID), 4)

            for provider, credential_id in ((cold, 1002), (established, 1001)):
                witness = provider.witness(ISSUER_ID, credential_id)
                self.assertEqual(witness.to_dict(), service.witness(credential_id))
                self.assertEqual(witness.accumulator_epoch, 4)

        requests = [call.args[0] for call in http.call_args_list]
        self.assertEqual(
            [req.data for req in requests if req.get_method() == "POST"],
            [json.dumps(request).encode("utf-8")] * 4,
        )
        announcement_urls = [req.full_url for req in requests if req.get_method() == "GET"]
        self.assertIn(f"{publication.base_url}{REVOCATION_ANNOUNCEMENT_PATH}/3", announcement_urls)
        self.assertTrue(all(url.startswith(publication.base_url + "/") for url in announcement_urls))

    def test_private_provider_resumes_bounded_catch_up_over_http(self):
        service = _service()
        service.register(1001)
        store = InMemoryVerifierCheckpointStore()
        with patch.object(
            service, "handle_request", wraps=service.handle_request
        ) as updates, patch.object(
            service, "announcement_for_epoch", wraps=service.announcement_for_epoch
        ) as history, RevocationServer(service) as server, RevocationServer(service) as publication:
            services = {ISSUER_ID: (RevocationServiceClient(server.base_url), ACCUMULATOR_ID)}
            sources = {ISSUER_ID: RevocationServiceClient(publication.base_url)}

            def open_provider():
                return PrivateWitnessProvider(
                    services, ISSUER_KEYS, announcement_sources=sources, checkpoint_store=store,
                    max_backfill=2, clock=lambda: TIMESTAMP,
                )

            provider = open_provider()
            self.assertEqual(provider.witness(ISSUER_ID, 1001).accumulator_epoch, 1)
            for credential_id in range(1002, 1007):
                service.register(credential_id)
            with self.assertRaisesRegex(StaleWitnessError, "ANNOUNCEMENT_BACKFILL_LIMIT_EXCEEDED"):
                provider.witness(ISSUER_ID, 1001)

            first = provider.catch_up(ISSUER_ID)
            self.assertEqual((first.checkpoint_epoch, first.verified, first.complete), (3, 2, False))
            restarted = open_provider()
            second = restarted.catch_up(ISSUER_ID)
            final = restarted.catch_up(ISSUER_ID)
            self.assertEqual((second.checkpoint_epoch, second.verified, second.complete), (5, 2, False))
            self.assertEqual((final.checkpoint_epoch, final.verified, final.complete), (6, 1, True))
            self.assertEqual([call.args[0] for call in history.call_args_list], [2, 3, 4, 5])
            self.assertEqual(updates.call_count, 2)
            self.assertEqual(restarted.witness(ISSUER_ID, 1001).to_dict(), service.witness(1001))

    def test_per_credential_providers_verify_signed_root_epoch_and_chain(self):
        service = _service()
        service.register(1001)
        honest_update = service.handle_request

        def signing_fork(response):
            announcement = response["announcement"]
            announcement["previousAnnouncementHash"] = "0x" + "00" * 32
            announcement["signature"] = "0x" + SIGNING_KEY.sign_digest(
                compute_announcement_digest(announcement)
            ).hex()

        with RevocationServer(service) as server:
            for provider_class, target, new_leaf in (
                (WitnessUpdateProvider, service, 1002),
                (HTTPWitnessUpdateProvider, (server.base_url, ACCUMULATOR_ID), 1003),
            ):
                with self.subTest(provider=provider_class.__name__):
                    store = InMemoryVerifierCheckpointStore()
                    provider = provider_class(
                        {ISSUER_ID: target}, ISSUER_KEYS,
                        checkpoint_store=store, clock=lambda: TIMESTAMP,
                        accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
                    )
                    first = provider.witness(ISSUER_ID, 1001)
                    service.register(new_leaf)

                    for mutation in (
                        lambda response: response.pop("announcement"),
                        lambda response: response["announcement"].update(signature="0x" + "00" * 64),
                        lambda response: response["announcement"].update(signingKeyId="untrusted"),
                        lambda response: response.update(root=field_to_hex(0)),
                        lambda response: response.update(epoch=response["epoch"] + 1),
                        lambda response: response.update(accumulatorId="wrong-accumulator"),
                        lambda response: response["witnessDelta"].update(fromEpoch=0),
                        signing_fork,
                    ):
                        def tampered_update(request):
                            response = honest_update(request)
                            mutation(response)
                            return response

                        with patch.object(service, "handle_request", side_effect=tampered_update):
                            with self.assertRaises(StaleWitnessError):
                                provider.witness(ISSUER_ID, 1001)
                    scope = provider.checkpoint_scope(ACCUMULATOR_ID)
                    retained = store.load_checkpoint(ISSUER_ID, scope)
                    self.assertEqual(retained["announcement"]["epoch"], first.accumulator_epoch)
                    self.assertEqual(len(store.evidence(ISSUER_ID, scope)), 1)
                    self.assertEqual(provider.refresh_modes, ["full"])
                    self.assertEqual(provider.witness(ISSUER_ID, 1001).to_dict(), service.witness(1001))
                    self.assertEqual(provider.refresh_modes, ["full", "delta"])

    def test_http_provider_rejects_a_full_witness_with_unsigned_root_or_epoch(self):
        service = _service()
        service.register(1001)
        honest_update = service.handle_request
        with RevocationServer(service) as server:
            for field, value in (("accumulatorEpoch", 999999), ("accumulatorRoot", field_to_hex(0))):
                with self.subTest(field=field):
                    store = InMemoryVerifierCheckpointStore()
                    provider = HTTPWitnessUpdateProvider(
                        {ISSUER_ID: (server.base_url, ACCUMULATOR_ID)}, ISSUER_KEYS,
                        checkpoint_store=store, clock=lambda: TIMESTAMP,
                    )

                    def tampered_update(request):
                        response = honest_update(request)
                        response["witness"][field] = value
                        return response

                    with patch.object(service, "handle_request", side_effect=tampered_update):
                        with self.assertRaises(StaleWitnessError):
                            provider.witness(ISSUER_ID, 1001)
                    scope = provider.checkpoint_scope(ACCUMULATOR_ID)
                    self.assertIsNone(store.load_checkpoint(ISSUER_ID, scope))

    def test_provider_rejects_an_unsigned_http_epoch_hint(self):
        service = _service()
        service.register(1001)
        with RevocationServer(service) as server:
            provider = HTTPWitnessUpdateProvider(
                {ISSUER_ID: (server.base_url, ACCUMULATOR_ID)}, ISSUER_KEYS,
                checkpoint_store=InMemoryVerifierCheckpointStore(), clock=lambda: TIMESTAMP,
            )
            self.assertEqual(provider.current_epoch(ISSUER_ID), 1)
            unsigned = {**service.current_announcement(), "epoch": 2}
            del unsigned["signature"]
            with patch.object(service, "current_announcement", return_value=unsigned):
                with self.assertRaises(StaleWitnessError):
                    provider.current_epoch(ISSUER_ID)
            self.assertEqual(provider.current_epoch(ISSUER_ID), 1)

    def test_holder_refreshes_witness_over_http_and_generates_proof(self):
        # The fixture registers into a LocalAccumulatorProvider; here we drive
        # the revocation service directly so the HTTP provider serves it.
        service = _service()
        master_seed = 9001
        credential_id = 4242
        holder_commitment = derive_holder_commitment_from_seed(master_seed)
        from zkc_crypto import (
            compute_kyc_credential_digest,
            digest_to_message_bytes,
        )
        from zkc_crypto.ecdsa_secp256k1 import sign
        from zkc_holder import Credential

        level = 2
        verified_attributes = [True, True, True, False, True]
        expires_at = 2_000_000_000
        digest = compute_kyc_credential_digest(
            holder_commitment, credential_id, level, verified_attributes, expires_at
        )
        credential = Credential(
            credential_type="zkc:kyc:v1",
            proof_type=KYC_PROOF_TYPE,
            issuer_id=ISSUER_ID,
            holder_commitment=holder_commitment,
            credential_id=credential_id,
            claims={"level": level, "verifiedAttributes": verified_attributes},
            expires_at=expires_at,
            signature=sign(digest_to_message_bytes(digest), SIGNING_KEY.private_key),
        )
        service.register(credential_id)

        with RevocationServer(service) as server:
            provider = HTTPWitnessUpdateProvider(
                {ISSUER_ID: (RevocationServiceClient(server.base_url), ACCUMULATOR_ID)},
                ISSUER_KEYS,
                checkpoint_store=InMemoryVerifierCheckpointStore(),
                clock=lambda: TIMESTAMP,
            )
            client = HolderClient.from_seed(
                master_seed,
                PredicateRegistry.from_repo(REPO_ROOT),
                StubBackend(),
                accumulator_provider=provider,
            )
            client.store_credential(credential)
            request = ProofRequest(
                proof_types=[KYC_PROOF_TYPE],
                parameters={
                    KYC_PROOF_TYPE: {
                        "requiredLevel": 1,
                        "requiredAttributes": [True, False, True, False, False],
                    }
                },
                context=ProofContext.verifier_session("verifier.example", 555, TIMESTAMP),
                trust_policy=TrustPolicy(
                    issuers=(
                        TrustedIssuer(
                            issuer_id=ISSUER_ID,
                            public_key_x=KEY_X,
                            public_key_y=KEY_Y,
                            proof_types=(KYC_PROOF_TYPE,),
                        ),
                    )
                ),
            )
            envelope = generate_unauthenticated_linkable(client, request)
            validate_compliance_proof_v1(envelope)
            self.assertEqual(envelope["proofs"][0]["proofType"], KYC_PROOF_TYPE)
            # The witness came over HTTP (full on first fetch).
            self.assertEqual(provider.refresh_modes, ["full"])

    def test_http_provider_fails_closed_on_revoked_credential(self):
        service = _service()
        service.register(4242)
        service.revoke(4242)
        with RevocationServer(service) as server:
            provider = HTTPWitnessUpdateProvider(
                {ISSUER_ID: (RevocationServiceClient(server.base_url), ACCUMULATOR_ID)},
                ISSUER_KEYS,
                checkpoint_store=InMemoryVerifierCheckpointStore(),
                clock=lambda: TIMESTAMP,
            )
            with self.assertRaises(StaleWitnessError):
                provider.witness(ISSUER_ID, 4242)


class IssuerTransportTests(unittest.TestCase):
    """The four issuer adapter stages + metadata, end to end over HTTP."""

    def _adapter(self):
        return SandboxIssuerAdapter(clock=lambda: TIMESTAMP)

    def test_full_issuance_flow_over_http(self):
        adapter = self._adapter()
        master_seed = 7
        holder_commitment = derive_holder_commitment_from_seed(master_seed)
        holder_commitment_hex = field_to_hex(holder_commitment)
        with IssuerServer(adapter) as server:
            client = IssuerServiceClient(server.base_url)

            metadata = client.issuer_metadata()
            self.assertIn("issuerId", metadata)

            subject = client.verify_subject(
                {"schemaId": KYC_SCHEMA_ID, "fixtureId": "sandbox-alice-basic"}
            )
            self.assertEqual(subject["status"], "verified")

            challenge = client.request_binding_challenge(
                {
                    "subjectRef": subject["subjectRef"],
                    "holderCommitment": holder_commitment_hex,
                    "schemaId": KYC_SCHEMA_ID,
                }
            )
            response = compute_binding_response(
                holder_commitment,
                adapter.issuer_id,
                KYC_SCHEMA_ID,
                hex_to_field(challenge["nonce"]),
                challenge["expiresAt"],
            )
            client.bind_holder_commitment(
                {
                    "subjectRef": subject["subjectRef"],
                    "holderCommitment": holder_commitment_hex,
                    "schemaId": KYC_SCHEMA_ID,
                    "nonce": challenge["nonce"],
                    "challengeResponse": field_to_hex(response),
                }
            )
            envelope = client.issue_credential(
                {"subjectRef": subject["subjectRef"], "schemaId": KYC_SCHEMA_ID}
            )
            # The issued envelope is holder-SDK consumable.
            credential = Credential_from_envelope(envelope)
            self.assertEqual(credential.holder_commitment, holder_commitment)

    def test_stage_order_enforced_over_http(self):
        adapter = self._adapter()
        with IssuerServer(adapter) as server:
            client = IssuerServiceClient(server.base_url)
            # Issuance before verification must fail with the protocol code.
            with self.assertRaises(TransportError) as ctx:
                client.issue_credential({"subjectRef": "nobody", "schemaId": KYC_SCHEMA_ID})
            self.assertEqual(ctx.exception.status, 422)
            self.assertIsNotNone(ctx.exception.code)

    def test_unknown_route_is_404(self):
        adapter = self._adapter()
        with IssuerServer(adapter) as server:
            with self.assertRaises(TransportError) as ctx:
                RevocationServiceClient(server.base_url)._get("/no/such/path")
            self.assertEqual(ctx.exception.status, 404)


def Credential_from_envelope(envelope: dict):
    """Helper: build a holder Credential from an issuer credential envelope."""
    from zkc_holder import Credential

    return Credential.from_dict(envelope["credential"])


if __name__ == "__main__":
    unittest.main()

"""Issuer operator mutations live on a separate, signature-authenticated router.

Regression for the 2026-10-04 review finding R7.8: ``IssuerServer`` used to
route ``POST /v1/issuer/revoke`` on the holder-facing listener with a body of
only ``{"credentialId"}``. The anonymous epoch-delta full mode lists every
active credential id, so any caller admitted to the holder stages could
enumerate and revoke every credential. These tests pin the fix over real
loopback HTTP:

* the holder listener routes no mutation (the revoke loop is 404 and leaves
  the accumulator untouched);
* ``IssuerAdminServer`` refuses unsigned, wrong-key, stale, replayed,
  body-tampered, retargeted, wrong-audience and high-s requests, and serves
  a correctly signed revoke or renewal;
* stage 4 stays a public status/witness oracle (it releases only what the
  published leaf set already reveals) and is rate-limited by default;
* the threat model states that credential ids are public and never act as
  authorization.
"""

import http.client
import json
import unittest
import urllib.error
import urllib.request

import _path  # noqa: F401
from _path import REPO_ROOT

from zkc_crypto import (
    SparseMerkleAccumulator,
    compute_merkle_root,
    derive_holder_commitment_from_seed,
    field_to_hex,
    hex_to_field,
)
from zkc_crypto.ecdsa_secp256k1 import N
from zkc_issuer import AdapterError, IssuerSigningKey, SandboxIssuerAdapter, compute_binding_response
from zkc_revocation import RevocationAccumulatorService
from zkc_transport import (
    ADMIN_RENEW_PATH,
    ADMIN_REVOKE_PATH,
    IssuerAdminClient,
    IssuerAdminServer,
    IssuerServer,
    IssuerServiceClient,
    OperatorAuthenticator,
    OperatorKey,
    RevocationServer,
    RevocationServiceClient,
    TransportError,
)
from zkc_transport.operator_auth import (
    OPERATOR_KEY_HEADER,
    OPERATOR_NONCE_HEADER,
    OPERATOR_SIGNATURE_HEADER,
    OPERATOR_TIMESTAMP_HEADER,
)
from zkc_transport.server import ISSUER_HOLDER_POST_PATHS

TIMESTAMP = 1_770_000_000
ACCUMULATOR_ID = "sandbox-active-credentials"
ENDPOINT = "https://issuer.sandbox.zkc.dev/v1/revocation/updates"
SCHEMA = "zkc:cred:kyc:v1"
KEY = IssuerSigningKey.test_issuer()
OPERATOR = OperatorKey.from_seed(b"zkc-test-operator-1", "operator-1")
INTRUDER = OperatorKey.from_seed(b"zkc-test-operator-intruder", "operator-1")
SEEDED = (111, 222, 333)


class Clock:
    def __init__(self, now=TIMESTAMP):
        self.now = now

    def __call__(self):
        return self.now


def raw_post(url: str, body: bytes, headers: dict = None):
    """POST exact bytes; return (status, decoded JSON body)."""
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, json.loads(exc.read() or b"{}")


def revoke_body(credential_id: int) -> bytes:
    return json.dumps({"credentialId": field_to_hex(credential_id)}).encode("utf-8")


class OperatorRouterFixture(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.service = RevocationAccumulatorService(
            ACCUMULATOR_ID, ENDPOINT, KEY, clock=self.clock
        )
        self.adapter = SandboxIssuerAdapter(
            signing_key=KEY, accumulator=self.service, clock=self.clock
        )
        for credential_id in SEEDED:
            self.service.register(credential_id)
        self.pinned = {OPERATOR.key_id: OPERATOR.public_key_hex()}

    def admin(self, **kwargs):
        kwargs.setdefault("clock", self.clock)
        return IssuerAdminServer(self.adapter, self.pinned, **kwargs)

    def signed(self, body: bytes, target: str = ADMIN_REVOKE_PATH, key: OperatorKey = OPERATOR,
               issuer_id: str = None, timestamp: int = None, method: str = "POST") -> dict:
        return key.sign_request(
            issuer_id=issuer_id or self.adapter.issuer_id,
            method=method,
            request_target=target,
            body=body,
            timestamp=self.clock.now if timestamp is None else timestamp,
        )

    def assert_untouched(self, epoch: int):
        self.assertEqual(self.service.epoch, epoch)
        for credential_id in SEEDED:
            self.assertTrue(self.service.is_active(credential_id))


class HolderListenerTests(OperatorRouterFixture):
    def test_holder_listener_routes_only_the_four_stages(self):
        with IssuerServer(self.adapter) as server:
            self.assertEqual(set(server._http._post_routes), set(ISSUER_HOLDER_POST_PATHS))
            for path in ("/v1/issuer/revoke", ADMIN_REVOKE_PATH, ADMIN_RENEW_PATH):
                with self.subTest(path=path):
                    status, _ = raw_post(server.base_url + path, revoke_body(222))
                    self.assertEqual(status, 404)

    def test_anonymous_revoke_loop_cannot_empty_the_accumulator(self):
        # The original PoC: enumerate ids from the anonymous epoch delta, then
        # revoke each one through the holder-facing listener.
        epoch = self.service.epoch
        with RevocationServer(self.service) as revocation, IssuerServer(self.adapter) as issuer:
            leaves = RevocationServiceClient(revocation.base_url).epoch_delta(ACCUMULATOR_ID)["leaves"]
            active = [hex_to_field(leaf) for leaf in leaves if hex_to_field(leaf) != 0]
            self.assertEqual(sorted(active), sorted(SEEDED))
            for credential_id in active:
                status, _ = raw_post(issuer.base_url + "/v1/issuer/revoke", revoke_body(credential_id))
                self.assertEqual(status, 404)
            self.assertFalse(hasattr(IssuerServiceClient(issuer.base_url), "revoke_credential"))
        self.assert_untouched(epoch)

    def test_admin_router_is_a_separate_listener_serving_no_holder_route(self):
        with IssuerServer(self.adapter) as holder, self.admin() as admin:
            self.assertNotEqual(holder.base_url, admin.base_url)
            for path in ISSUER_HOLDER_POST_PATHS:
                body = b"{}"
                status, _ = raw_post(admin.base_url + path, body, self.signed(body, path))
                self.assertEqual(status, 404)
            with self.assertRaises(TransportError) as ctx:
                RevocationServiceClient(admin.base_url)._get("/.well-known/zkc-issuer.json")
            self.assertEqual(ctx.exception.status, 404)


class AdminAuthenticationTests(OperatorRouterFixture):
    def post(self, admin, body: bytes, headers: dict, path: str = ADMIN_REVOKE_PATH):
        return raw_post(admin.base_url + path, body, headers)

    def assert_refused(self, admin, body, headers, path=ADMIN_REVOKE_PATH):
        epoch = self.service.epoch
        status, response = self.post(admin, body, headers, path)
        self.assertEqual(status, 401)
        self.assertEqual(response, {"error": {"message": "operator authentication required"}})
        self.assert_untouched(epoch)

    def test_signed_revoke_succeeds(self):
        epoch = self.service.epoch
        with self.admin() as admin:
            client = IssuerAdminClient(admin.base_url, OPERATOR, self.adapter.issuer_id, clock=self.clock)
            result = client.revoke_credential(222)
        self.assertEqual(result["credentialId"], field_to_hex(222))
        self.assertEqual(result["currentEpoch"], epoch + 1)
        self.assertEqual(self.service.epoch, epoch + 1)
        self.assertFalse(self.service.is_active(222))
        self.assertTrue(self.service.is_active(111) and self.service.is_active(333))

    def test_unsigned_request_is_refused(self):
        with self.admin() as admin:
            self.assert_refused(admin, revoke_body(222), {})
            client = IssuerServiceClient(admin.base_url)
            with self.assertRaises(TransportError) as ctx:
                client._post(ADMIN_REVOKE_PATH, {"credentialId": field_to_hex(222)})
            self.assertEqual(ctx.exception.status, 401)

    def test_each_missing_header_is_refused(self):
        body = revoke_body(222)
        with self.admin() as admin:
            for name in (OPERATOR_KEY_HEADER, OPERATOR_TIMESTAMP_HEADER,
                         OPERATOR_NONCE_HEADER, OPERATOR_SIGNATURE_HEADER):
                with self.subTest(missing=name):
                    headers = self.signed(body)
                    del headers[name]
                    self.assert_refused(admin, body, headers)

    def test_wrong_key_is_refused(self):
        body = revoke_body(222)
        with self.admin() as admin:
            # A key claiming the pinned key id, and an unpinned key id.
            self.assert_refused(admin, body, self.signed(body, key=INTRUDER))
            stranger = OperatorKey.from_seed(b"zkc-test-operator-2", "operator-2")
            self.assert_refused(admin, body, self.signed(body, key=stranger))

    def test_stale_and_future_timestamps_are_refused(self):
        body = revoke_body(222)
        with self.admin(max_clock_skew_seconds=60) as admin:
            for offset in (-61, 61, -10_000):
                with self.subTest(offset=offset):
                    self.assert_refused(admin, body, self.signed(body, timestamp=TIMESTAMP + offset))
            # The window edge is still accepted.
            status, _ = self.post(admin, body, self.signed(body, timestamp=TIMESTAMP - 60))
            self.assertEqual(status, 200)

    def test_replayed_request_is_refused(self):
        body = revoke_body(222)
        headers = self.signed(body)
        with self.admin() as admin:
            status, _ = self.post(admin, body, headers)
            self.assertEqual(status, 200)
            epoch = self.service.epoch
            # Byte-identical replay, later but inside the timestamp window.
            self.clock.now += 30
            status, response = self.post(admin, body, headers)
            self.assertEqual(status, 401)
            self.assertEqual(response["error"]["message"], "operator authentication required")
            self.assertEqual(self.service.epoch, epoch)

    def test_replayed_nonce_with_another_body_is_refused(self):
        first = revoke_body(111)
        headers = self.signed(first)
        with self.admin() as admin:
            self.assertEqual(self.post(admin, first, headers)[0], 200)
            second = revoke_body(333)
            nonce = bytes.fromhex(headers[OPERATOR_NONCE_HEADER])
            reused = OPERATOR.sign_request(
                issuer_id=self.adapter.issuer_id, method="POST",
                request_target=ADMIN_REVOKE_PATH, body=second,
                timestamp=TIMESTAMP, nonce=nonce,
            )
            status, _ = self.post(admin, second, reused)
            self.assertEqual(status, 401)
            self.assertTrue(self.service.is_active(333))

    def test_body_tampering_is_refused(self):
        signed_body = revoke_body(111)
        with self.admin() as admin:
            headers = self.signed(signed_body)
            self.assert_refused(admin, revoke_body(222), headers)
            # Same JSON value, different bytes: the signature covers bytes.
            respaced = json.dumps({"credentialId": field_to_hex(111)}, indent=1).encode()
            self.assert_refused(admin, respaced, headers)

    def test_retargeted_and_wrong_audience_requests_are_refused(self):
        body = revoke_body(222)
        with self.admin() as admin:
            self.assert_refused(admin, body, self.signed(body, target=ADMIN_RENEW_PATH))
            self.assert_refused(admin, body, self.signed(body, target=ADMIN_REVOKE_PATH + "?x=1"))
            self.assert_refused(admin, body, self.signed(body, method="PUT"))
            self.assert_refused(admin, body, self.signed(body, issuer_id="zkc:issuer:other"))

    def test_high_s_twin_and_malformed_headers_are_refused(self):
        body = revoke_body(222)
        with self.admin() as admin:
            headers = self.signed(body)
            raw = bytes.fromhex(headers[OPERATOR_SIGNATURE_HEADER][2:])
            high_s = (N - int.from_bytes(raw[32:], "big")).to_bytes(32, "big")
            self.assert_refused(admin, body, {
                **headers, OPERATOR_SIGNATURE_HEADER: "0x" + (raw[:32] + high_s).hex()
            })
            for name, value in (
                (OPERATOR_TIMESTAMP_HEADER, "+" + str(TIMESTAMP)),
                (OPERATOR_TIMESTAMP_HEADER, str(TIMESTAMP) + ".0"),
                (OPERATOR_NONCE_HEADER, headers[OPERATOR_NONCE_HEADER].upper()),
                (OPERATOR_NONCE_HEADER, headers[OPERATOR_NONCE_HEADER][:-2]),
                (OPERATOR_SIGNATURE_HEADER, headers[OPERATOR_SIGNATURE_HEADER].upper()),
            ):
                with self.subTest(header=name, value=value):
                    self.assert_refused(admin, body, {**headers, name: value})

    def test_repeated_authentication_header_is_refused(self):
        body = revoke_body(222)
        headers = self.signed(body)
        epoch = self.service.epoch
        with self.admin() as admin:
            host, port = admin._http.server_address[:2]
            # urllib collapses repeated headers; http.client sends both.
            connection = http.client.HTTPConnection(host, port, timeout=10)
            try:
                connection.putrequest("POST", ADMIN_REVOKE_PATH)
                connection.putheader("Content-Type", "application/json")
                connection.putheader("Content-Length", str(len(body)))
                for name, value in headers.items():
                    connection.putheader(name, value)
                connection.putheader(OPERATOR_KEY_HEADER, OPERATOR.key_id)
                connection.endheaders(body)
                self.assertEqual(connection.getresponse().status, 401)
            finally:
                connection.close()
        self.assert_untouched(epoch)

    def test_signed_malformed_body_is_a_client_error_after_authentication(self):
        with self.admin() as admin:
            for body in (b'{"credentialId": "0x01", "extra": 1}', b'{"credentialId": 7}', b"[]"):
                with self.subTest(body=body):
                    status, _ = self.post(admin, body, self.signed(body))
                    self.assertEqual(status, 400)
        self.assert_untouched(self.service.epoch)

    def test_signed_renewal_succeeds_and_unsigned_renewal_is_refused(self):
        holder = derive_holder_commitment_from_seed(7)
        with IssuerServer(self.adapter) as server, self.admin() as admin:
            stages = IssuerServiceClient(server.base_url)
            subject = stages.verify_subject({"schemaId": SCHEMA, "fixtureId": "sandbox-alice-basic"})
            base = {"subjectRef": subject["subjectRef"], "holderCommitment": field_to_hex(holder),
                    "schemaId": SCHEMA}
            challenge = stages.request_binding_challenge(base)
            response = compute_binding_response(
                holder, self.adapter.issuer_id, SCHEMA,
                hex_to_field(challenge["nonce"]), challenge["expiresAt"],
            )
            stages.bind_holder_commitment({**base, "nonce": challenge["nonce"],
                                           "challengeResponse": field_to_hex(response)})
            issued = stages.issue_credential({"subjectRef": subject["subjectRef"], "schemaId": SCHEMA})
            old_id = issued["credential"]["credentialId"]

            body = json.dumps({"credentialId": old_id}).encode()
            status, _ = raw_post(admin.base_url + ADMIN_RENEW_PATH, body)
            self.assertEqual(status, 401)
            self.assertTrue(self.service.is_active(hex_to_field(old_id)))

            client = IssuerAdminClient(admin.base_url, OPERATOR, self.adapter.issuer_id, clock=self.clock)
            renewed = client.renew_credential({"credentialId": old_id})
        self.assertEqual(renewed["renewal"]["renewedFrom"], old_id)
        self.assertFalse(self.service.is_active(hex_to_field(old_id)))
        self.assertTrue(self.service.is_active(hex_to_field(renewed["credential"]["credentialId"])))


class OperatorAuthenticatorTests(unittest.TestCase):
    def test_configuration_fails_closed(self):
        valid = OPERATOR.public_key_hex()
        off_curve = valid[:-1] + ("0" if valid[-1] != "0" else "1")
        for keys in ({}, {"operator-1": "0x1234"}, {"operator-1": valid.upper()},
                     {"operator-1": off_curve}, {"bad id": valid},
                     {"operator-1": valid, "operator-2": valid}):
            with self.subTest(keys=keys), self.assertRaises(ValueError):
                OperatorAuthenticator("zkc:issuer:sandbox", keys, clock=Clock())
        adapter = SandboxIssuerAdapter(clock=Clock())
        with self.assertRaises(ValueError):
            IssuerAdminServer(adapter, {})

    def test_nonce_is_not_revived_by_a_clock_step_backwards(self):
        clock = Clock()
        auth = OperatorAuthenticator("zkc:issuer:sandbox", {OPERATOR.key_id: OPERATOR.public_key_hex()},
                                     clock=clock, max_clock_skew_seconds=60)
        body = b"{}"
        headers = OPERATOR.sign_request(issuer_id="zkc:issuer:sandbox", method="POST",
                                        request_target=ADMIN_REVOKE_PATH, body=body,
                                        timestamp=TIMESTAMP)
        self.assertEqual(auth.authenticate("POST", ADMIN_REVOKE_PATH, headers, body), OPERATOR.key_id)
        self.assertIsNone(auth.authenticate("POST", ADMIN_REVOKE_PATH, headers, body))
        # Another accepted request far in the future prunes the old nonce.
        clock.now = TIMESTAMP + 1_000
        later = OPERATOR.sign_request(issuer_id="zkc:issuer:sandbox", method="POST",
                                      request_target=ADMIN_REVOKE_PATH, body=body,
                                      timestamp=clock.now)
        self.assertEqual(auth.authenticate("POST", ADMIN_REVOKE_PATH, later, body), OPERATOR.key_id)
        clock.now = TIMESTAMP
        self.assertIsNone(auth.authenticate("POST", ADMIN_REVOKE_PATH, headers, body))

    def test_nonce_cache_capacity_fails_closed(self):
        clock = Clock()
        auth = OperatorAuthenticator("zkc:issuer:sandbox", {OPERATOR.key_id: OPERATOR.public_key_hex()},
                                     clock=clock, max_tracked_nonces=1)

        def request():
            return OPERATOR.sign_request(issuer_id="zkc:issuer:sandbox", method="POST",
                                         request_target=ADMIN_REVOKE_PATH, body=b"{}",
                                         timestamp=TIMESTAMP)

        self.assertEqual(auth.authenticate("POST", ADMIN_REVOKE_PATH, request(), b"{}"), OPERATOR.key_id)
        self.assertIsNone(auth.authenticate("POST", ADMIN_REVOKE_PATH, request(), b"{}"))

    def test_operator_key_repr_hides_the_private_scalar(self):
        self.assertNotIn(str(OPERATOR.private_key), repr(OPERATOR))


class Stage4PublicOracleTests(OperatorRouterFixture):
    def test_stage4_releases_only_what_the_public_leaf_set_reveals(self):
        # Status and witness for any id are computable from the anonymous
        # epoch-delta leaf set, so stage 4 is documented as a public oracle.
        self.service.revoke(111)
        leaves = self.service.handle_epoch_delta_request(
            {"type": "zkc:epoch-delta-request:v1", "accumulatorId": ACCUMULATOR_ID}
        )["leaves"]
        public_tree = SparseMerkleAccumulator([hex_to_field(leaf) for leaf in leaves])
        with IssuerServer(self.adapter) as server:
            client = IssuerServiceClient(server.base_url)
            for credential_id, status in ((222, "active"), (111, "revoked"), (999, "unknown")):
                with self.subTest(credential_id=credential_id):
                    published = client.publish_revocation_handle(
                        {"credentialId": field_to_hex(credential_id)}
                    )
                    self.assertEqual(published["status"], status)
                    self.assertEqual(
                        status == "active",
                        field_to_hex(credential_id) in leaves,
                    )
            witness = client.publish_revocation_handle(
                {"credentialId": field_to_hex(222)}
            )["witness"]
        index = [hex_to_field(leaf) for leaf in leaves].index(222)
        self.assertEqual(witness["pathIndex"], index)
        self.assertEqual(
            compute_merkle_root(222, index, [hex_to_field(s) for s in witness["siblings"]]),
            public_tree.root(),
        )

    def test_stage4_is_rate_limited_without_a_configured_stage_limit(self):
        self.assertEqual(SandboxIssuerAdapter.default_publication_reads_per_window, 600)

        class SmallWindowAdapter(SandboxIssuerAdapter):
            default_publication_reads_per_window = 3

        adapter = SmallWindowAdapter(clock=Clock())
        self.assertIsNone(adapter._max_requests_per_stage)
        payload = {"credentialId": field_to_hex(222)}
        for _ in range(3):
            adapter.publish_revocation_handle(payload)
        with self.assertRaises(AdapterError) as ctx:
            adapter.publish_revocation_handle(payload)
        self.assertEqual(ctx.exception.code, "RATE_LIMITED")
        with IssuerServer(adapter) as server:
            with self.assertRaises(TransportError) as http_ctx:
                IssuerServiceClient(server.base_url).publish_revocation_handle(payload)
        self.assertEqual((http_ctx.exception.status, http_ctx.exception.code), (422, "RATE_LIMITED"))

    def test_configured_stage_limit_takes_precedence(self):
        adapter = SandboxIssuerAdapter(clock=Clock(), max_requests_per_stage=1)
        adapter.publish_revocation_handle({})
        with self.assertRaises(AdapterError):
            adapter.publish_revocation_handle({})

    def test_invalid_default_publication_limit_is_refused(self):
        for value in (0, -1, True, None, 1.5):
            class BadAdapter(SandboxIssuerAdapter):
                default_publication_reads_per_window = value

            with self.subTest(value=value), self.assertRaises(ValueError):
                BadAdapter(clock=Clock())


class PublicCredentialIdDocsTests(unittest.TestCase):
    def test_threat_model_states_ids_are_public_and_never_authorization(self):
        text = (REPO_ROOT / "docs" / "zkc_metadata_leakage_threat_model.md").read_text(encoding="utf-8")
        self.assertIn("### 1.10 Credential identifiers and operator mutations", text)
        self.assertIn("Credential identifiers are public", text)
        self.assertIn("must never act as authorization", text)
        self.assertIn("public status and witness oracle", text)


if __name__ == "__main__":
    unittest.main()

"""Bounded work before authentication and canonical parsing of closed formats.

Regression tests for review finding R7.12 (2026-10-04; PoCs lane6/poc10,
poc14, poc18 and poc20), over the revocation stack and the HTTP transport:

(a) unbounded work: a keyless relay inflated the private provider's leaf set
    with root-neutral trailing zero leaves; one far-future signed epoch made
    ``EpochGapError`` list every missing epoch before any backfill bound was
    checked (``MemoryError`` at epoch 2^62); the transport client read any
    response size;
(b) non-canonical parsing: ``bytes.fromhex`` skipped whitespace, so a
    64-character root decoded to 31 bytes; ``int(x, 16)`` took whitespace,
    ``_`` and short forms; metadata convenience fields compared type-loosely
    (``True == 1``, ``10.0 == 10``); byte bounds were unstated;
(c) the transport server dropped the connection on a malformed
    ``Content-Length`` or deeply nested JSON, accepted ``NaN``/``Infinity``,
    let a slow body hold a thread forever, started threads without limit,
    and reported issuer-state faults as client errors.

Every bound is asserted by size, count or a short deadline, never by a long
wall-clock run.
"""

import copy
import http.server
import json
import socket
import threading
import time
import tracemalloc
import unittest
from unittest import mock

import _path  # noqa: F401
from _path import REPO_ROOT

from zkc_crypto import canonical_hex_to_field, field_to_hex
from zkc_holder.errors import StaleWitnessError
from zkc_issuer import AdapterError, IssuerSigningKey, SandboxIssuerAdapter
from zkc_revocation import (
    ANNOUNCEMENT_VERSION,
    GENESIS_ANNOUNCEMENT_HASH,
    AnnouncementAuthenticationError,
    AnnouncementChain,
    AnnouncementKeyPin,
    AnnouncementMetadataError,
    BackfillLimitError,
    EpochGapError,
    InMemoryVerifierCheckpointStore,
    PrivateWitnessProvider,
    RevocationAccumulatorService,
    VerifierAccumulatorCache,
    announcement_hash,
    announcement_transcript,
    compute_announcement_digest,
    verify_epoch_announcement,
)
from zkc_revocation import private_provider as private_provider_module
from zkc_revocation.service import MAX_ANNOUNCEMENT_TRANSCRIPT_BYTES
from zkc_transport import (
    IssuerAdminServer,
    OperatorKey,
    RevocationServer,
    RevocationServiceClient,
    TransportError,
)
from zkc_transport.server import (
    ADMIN_REVOKE_PATH,
    REVOCATION_ANNOUNCEMENT_PATH,
    REVOCATION_UPDATES_PATH,
    loads_strict_json,
)

ISSUER_ID = "zkc:issuer:sandbox"
ACCUMULATOR_ID = "sandbox-active-credentials"
ENDPOINT = "https://issuer.sandbox.zkc.dev/v1/revocation/updates"
T0 = 1_770_000_000
KEY = IssuerSigningKey.test_issuer()
KEY_X, KEY_Y = KEY.public_key_coordinates()
PIN = AnnouncementKeyPin(KEY_X, KEY_Y, T0 - 86_400, T0 + 86_400)
PINS = {KEY.key_id: PIN}
OPERATOR = OperatorKey.from_seed(b"zkc-test-operator-1", "operator-1")
ZERO_LEAF = field_to_hex(0)
# A bound that holds whatever the allocator does: the 2,000,000-epoch gap
# message alone used to be about 17 MB.
SMALL_PEAK_BYTES = 1 << 20


def signed(epoch: int, previous: str = GENESIS_ANNOUNCEMENT_HASH, **fields) -> dict:
    announcement = {
        "version": ANNOUNCEMENT_VERSION,
        "accumulatorId": ACCUMULATOR_ID,
        "root": field_to_hex(7),
        "epoch": epoch,
        "announcedAt": T0,
        "maxEpochLag": 10,
        "signingKeyId": KEY.key_id,
        "previousAnnouncementHash": previous,
    }
    announcement.update(fields)
    announcement["signature"] = "0x" + KEY.sign_digest(
        compute_announcement_digest(announcement)
    ).hex()
    return announcement


def metadata(announcement: dict) -> dict:
    return {
        "version": "zkc:issuer-metadata:v2",
        "issuerId": ISSUER_ID,
        "revocation": {
            "accumulatorId": announcement["accumulatorId"],
            "currentRoot": announcement["root"],
            "currentEpoch": announcement["epoch"],
            "maxEpochLag": announcement["maxEpochLag"],
            "currentAnnouncement": copy.deepcopy(announcement),
        },
    }


def verifier_cache(store=None, **kwargs) -> VerifierAccumulatorCache:
    return VerifierAccumulatorCache(
        {ISSUER_ID: PINS},
        accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        checkpoint_store=store or InMemoryVerifierCheckpointStore(),
        clock=lambda: T0,
        **kwargs,
    )


def service() -> RevocationAccumulatorService:
    return RevocationAccumulatorService(ACCUMULATOR_ID, ENDPOINT, KEY, clock=lambda: T0)


def peak_bytes(call) -> tuple:
    """Run ``call``; return (exception or None, peak traced allocation)."""
    tracemalloc.start()
    try:
        try:
            call()
            raised = None
        except Exception as exc:  # noqa: BLE001 - returned to the test
            raised = exc
        return raised, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


# --- (a) bounded work -------------------------------------------------------------


class EpochGapArithmeticTests(unittest.TestCase):
    """PoC poc14: the gap is sized arithmetically, never listed first."""

    def test_far_future_epoch_is_a_bounded_gap_error(self):
        chain = AnnouncementChain(trusted_keys=PINS, checkpoint=signed(0))
        far = signed(2**62, "0x" + "11" * 32)
        raised, peak = peak_bytes(lambda: chain.ingest(far))
        self.assertIsInstance(raised, EpochGapError)
        self.assertEqual(raised.gap_size, 2**62 - 1)
        self.assertEqual((raised.last_seen_epoch, raised.received_epoch), (0, 2**62))
        self.assertLess(len(str(raised)), 200)
        self.assertLess(peak, SMALL_PEAK_BYTES)
        self.assertEqual(chain.last_epoch, 0)

    def test_small_gap_still_lists_its_epochs(self):
        chain = AnnouncementChain(trusted_keys=PINS, checkpoint=signed(0))
        with self.assertRaises(EpochGapError) as caught:
            chain.ingest(signed(4, "0x" + "11" * 32))
        self.assertEqual(caught.exception.gap_size, 3)
        self.assertEqual(caught.exception.missing_epochs, [1, 2, 3])

    def test_verifier_refuses_huge_gaps_with_backfill_limit_in_constant_memory(self):
        for epoch in (2_000_000, 2**62):
            with self.subTest(epoch=epoch):
                store = InMemoryVerifierCheckpointStore()
                cache = verifier_cache(store, max_backfill=32)
                genesis = signed(0)
                cache.ingest_metadata(ISSUER_ID, metadata(genesis))
                head = signed(epoch, announcement_hash(genesis))
                raised, peak = peak_bytes(
                    lambda: cache.ingest_metadata(ISSUER_ID, metadata(head))
                )
                self.assertIsInstance(raised, BackfillLimitError)
                self.assertIn("ANNOUNCEMENT_BACKFILL_LIMIT_EXCEEDED", str(raised))
                self.assertIn(str(epoch - 1), str(raised))
                self.assertLess(peak, SMALL_PEAK_BYTES)
                checkpoint = store.load_checkpoint(ISSUER_ID, ACCUMULATOR_ID)
                self.assertEqual(checkpoint["announcement"], genesis)


class InflatingRelay:
    """Keyless relay in front of an honest service (PoC poc10)."""

    def __init__(self, inner, rewrite):
        self._inner = inner
        self._rewrite = rewrite
        self.accumulator_id = inner.accumulator_id

    @property
    def epoch(self):
        return self._inner.epoch

    def current_announcement(self):
        return self._inner.current_announcement()

    def announcement_for_epoch(self, epoch):
        return self._inner.announcement_for_epoch(epoch)

    def handle_request(self, request):
        return self._rewrite(self._inner.handle_request(request))


class PrivateProviderLeafBoundTests(unittest.TestCase):
    """The leaf set is bounded by the authenticated epoch before decoding."""

    def setUp(self):
        self.service = service()
        for credential_id in (101, 102):
            self.service.register(credential_id)
        self.decoded = 0
        self.trees = 0

    def provider(self, source, **kwargs):
        # The honest service is the independent announcement source; the
        # relay only serves leaves.
        return PrivateWitnessProvider(
            {ISSUER_ID: source},
            issuer_keys={ISSUER_ID: PINS},
            announcement_sources={ISSUER_ID: self.service},
            checkpoint_store=InMemoryVerifierCheckpointStore(),
            clock=lambda: T0,
            accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
            **kwargs,
        )

    def counting(self):
        real_decode = private_provider_module.canonical_hex_to_field
        real_tree = private_provider_module.SparseMerkleAccumulator

        def decode(value):
            self.decoded += 1
            return real_decode(value)

        def tree(*args, **kwargs):
            self.trees += 1
            return real_tree(*args, **kwargs)

        return (
            mock.patch.object(private_provider_module, "canonical_hex_to_field", decode),
            mock.patch.object(private_provider_module, "SparseMerkleAccumulator", tree),
        )

    def assert_refused_before_decoding(self, provider):
        decode_patch, tree_patch = self.counting()
        with decode_patch, tree_patch:
            with self.assertRaises(StaleWitnessError):
                provider.witness(ISSUER_ID, 101)
        self.assertEqual((self.decoded, self.trees), (0, 0))

    def test_zero_padding_beyond_the_signed_epoch_fails_before_allocation(self):
        # Two epochs can add at most two leaf slots; 20,000 root-neutral zero
        # leaves used to be decoded, hashed and accepted.
        def pad(response):
            if response.get("mode") == "full":
                response = dict(response, leaves=response["leaves"] + [ZERO_LEAF] * 20_000)
            return response

        self.assert_refused_before_decoding(self.provider(InflatingRelay(self.service, pad)))

    def test_one_slot_over_the_epoch_bound_is_refused(self):
        def pad(response):
            return dict(response, leaves=response["leaves"] + [ZERO_LEAF])

        self.assert_refused_before_decoding(self.provider(InflatingRelay(self.service, pad)))

    def test_forged_head_is_refused_before_its_leaves_are_decoded(self):
        # The relay answers both the leaf fetch and the announcement source
        # with an unsigned far-future head, which would lift the epoch bound.
        forged = dict(self.service.current_announcement(), epoch=10**9)

        def forge(response):
            return dict(
                response,
                epoch=10**9,
                announcement=forged,
                leaves=response["leaves"] + [ZERO_LEAF] * 200,
            )

        relay = InflatingRelay(self.service, forge)
        relay.current_announcement = lambda: dict(forged)
        provider = PrivateWitnessProvider(
            {ISSUER_ID: relay},
            issuer_keys={ISSUER_ID: PINS},
            announcement_sources={ISSUER_ID: relay},
            checkpoint_store=InMemoryVerifierCheckpointStore(),
            clock=lambda: T0,
            accumulator_ids={ISSUER_ID: ACCUMULATOR_ID},
        )
        self.assert_refused_before_decoding(provider)

    def test_migration_allowance_is_explicit_local_policy(self):
        def pad(response):
            return dict(response, leaves=response["leaves"] + [ZERO_LEAF])

        relay = InflatingRelay(self.service, pad)
        witness = self.provider(relay, migrated_leaf_slots={ISSUER_ID: 1}).witness(ISSUER_ID, 101)
        self.assertEqual(witness.accumulator_root, self.service.root())
        for allowance in ({ISSUER_ID: -1}, {ISSUER_ID: 1.0}, {"zkc:issuer:other": 1}):
            with self.subTest(allowance=allowance):
                with self.assertRaises(ValueError):
                    self.provider(self.service, migrated_leaf_slots=allowance)

    def test_honest_trailing_revoked_slot_is_still_accepted(self):
        self.service.revoke(102)  # the newest slot is now a trailing zero
        provider = self.provider(self.service)
        witness = provider.witness(ISSUER_ID, 101)
        self.assertEqual(witness.accumulator_epoch, self.service.epoch)
        self.assertEqual(witness.accumulator_root, self.service.root())


def nested_json(depth: int) -> bytes:
    """Build one root object containing a chain of arrays."""
    arrays = depth - 1
    return b'{"nested":' + b"[" * arrays + b"null" + b"]" * arrays + b"}"


class StrictJSONDepthTests(unittest.TestCase):
    def test_accepts_64_containers_including_the_root(self):
        raw = nested_json(64)
        self.assertEqual(loads_strict_json(raw), json.loads(raw))

    def test_refuses_the_65th_container_before_json_decoding(self):
        with mock.patch("zkc_transport.server.json.loads") as decoder:
            with self.assertRaisesRegex(ValueError, "JSON nesting exceeds 64 containers"):
                loads_strict_json(nested_json(65))
        decoder.assert_not_called()

    def test_ignores_string_delimiters_and_counts_only_open_containers(self):
        # Exercise quotes, odd and even escape sequences, and many siblings.
        text = ('[{"\\' * 80) + "\\"
        payload = {"quoted": text, "siblings": [[] for _ in range(80)]}
        self.assertEqual(loads_strict_json(json.dumps(payload).encode()), payload)


class SlowJSONHandler(http.server.BaseHTTPRequestHandler):
    """Misbehaving server for the client bounds; ``mode`` picks the reply."""

    mode = "ok"

    def log_message(self, format, *args):  # noqa: A002
        pass

    def do_GET(self):  # noqa: N802
        try:
            self._reply()
        except OSError:
            pass  # the client refused the body and closed

    def _reply(self):
        mode = type(self).mode
        if mode == "declared-too-large":
            self.send_response(200)
            self.send_header("Content-Length", str(64 << 20))
            self.end_headers()
            self.wfile.write(b"{" + b" " * 1024)
        elif mode == "streamed-too-large":
            self.send_response(200)
            self.end_headers()  # no Content-Length: the body ends at close
            self.wfile.write(b'{"pad": "' + b"a" * 4096 + b'"}')
        elif mode == "drip":
            body = json.dumps({"pad": "a" * 80}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            for index in range(len(body)):
                self.wfile.write(body[index:index + 1])
                self.wfile.flush()
                time.sleep(0.05)
        else:
            body = {
                "nan": b'{"epoch": NaN}',
                "deep": nested_json(65),
                "duplicate": b'{"epoch": 1, "epoch": 2}',
                "ok": b'{"epoch": 1}',
            }[mode]
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


class ClientResponseBoundTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SlowJSONHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        host, port = cls.httpd.server_address[:2]
        cls.url = f"http://{host}:{port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def fetch(self, mode, **kwargs):
        SlowJSONHandler.mode = mode
        return RevocationServiceClient(self.url, **kwargs).current_announcement()

    def test_well_formed_response_is_read(self):
        self.assertEqual(self.fetch("ok", max_response_bytes=1024), {"epoch": 1})

    def test_declared_oversized_response_is_refused_before_reading(self):
        with self.assertRaises(TransportError) as caught:
            self.fetch("declared-too-large", max_response_bytes=1024)
        self.assertIn("exceeds 1024 bytes", str(caught.exception))

    def test_streamed_oversized_response_is_cut_at_the_cap(self):
        with self.assertRaises(TransportError) as caught:
            self.fetch("streamed-too-large", max_response_bytes=1024)
        self.assertIn("exceeds 1024 bytes", str(caught.exception))

    def test_slow_response_hits_the_total_deadline(self):
        # Each byte arrives well inside the 0.5 s socket timeout; the body as
        # a whole takes about 4.5 s.
        started = time.monotonic()
        with self.assertRaises(TransportError) as caught:
            self.fetch("drip", timeout=0.5)
        self.assertIn("not received in time", str(caught.exception))
        # Well below the 4.5 s the whole body would take; slack for load.
        self.assertLess(time.monotonic() - started, 3.5)

    def test_non_canonical_json_responses_are_transport_errors(self):
        for mode in ("nan", "deep", "duplicate"):
            with self.subTest(mode=mode):
                with self.assertRaises(TransportError):
                    self.fetch(mode)


# --- (b) canonical parsing --------------------------------------------------------


class CanonicalHexTests(unittest.TestCase):
    def test_field_parser_accepts_only_the_canonical_form(self):
        canonical = field_to_hex(10)
        self.assertEqual(canonical_hex_to_field(canonical), 10)
        digits = canonical[2:]
        for value in (
            canonical + " ",
            " " + canonical,
            canonical + "\n",
            "0x" + digits[:-2] + "_a",
            "0x" + digits.upper(),
            "0X" + digits,
            "0xa",
            "0x" + digits + "00",
            "0x" + digits[:-1] + chr(0x660),  # Arabic-Indic zero; int() takes it
            "0x" + "ff" * 32,  # 32 bytes, but not below the field modulus
            10,
            None,
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    canonical_hex_to_field(value)

    def test_wire_credential_ids_must_be_canonical(self):
        honest = service()
        honest.register(0xABC)
        canonical = field_to_hex(0xABC)
        request = {
            "type": "zkc:witness-update-request:v1",
            "accumulatorId": ACCUMULATOR_ID,
            "credentialId": canonical,
        }
        self.assertEqual(honest.handle_request(request)["mode"], "full")
        for alias in (canonical + " ", "0xabc", "0xa_bc", "0x" + canonical[2:].upper()):
            with self.subTest(alias=alias):
                with self.assertRaises(AdapterError) as caught:
                    honest.handle_request(dict(request, credentialId=alias))
                self.assertEqual(caught.exception.code, "STALE_ACCUMULATOR_WITNESS")

    def test_whitespace_padded_announcement_fields_are_malformed(self):
        # PoC poc20: 64 characters that bytes.fromhex read as 31 bytes.
        for field, value in (
            ("root", "0x" + "0a" * 31 + "  "),
            ("previousAnnouncementHash", "0x " + "00" * 31 + " "),
            ("signature", None),
        ):
            with self.subTest(field=field):
                announcement = signed(3)
                if value is None:
                    announcement["signature"] = announcement["signature"][:-2] + "\t0"
                else:
                    announcement[field] = value
                    with self.assertRaises(ValueError):
                        announcement_transcript(announcement)
                self.assertFalse(verify_epoch_announcement(announcement, KEY_X, KEY_Y))
                with self.assertRaises(AnnouncementAuthenticationError):
                    AnnouncementChain(trusted_keys=PINS).ingest(announcement)

    def test_key_pin_entry_refuses_whitespace_in_the_public_key(self):
        entry = KEY.metadata_entry()
        public_key = entry["publicKey"]
        for value in (public_key[:-2] + "  ", public_key[:-2] + "\n0", public_key.upper()):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    AnnouncementKeyPin.from_signing_key_entry(dict(entry, publicKey=value))


class ConvenienceFieldTypeTests(unittest.TestCase):
    """PoC poc20: ``currentEpoch: true`` and ``maxEpochLag: 10.0`` were accepted."""

    def test_verifier_requires_the_signed_json_types(self):
        head = signed(1)
        for name, value in (
            ("currentEpoch", True),
            ("currentEpoch", 1.0),
            ("maxEpochLag", 10.0),
            ("accumulatorId", [ACCUMULATOR_ID]),
        ):
            with self.subTest(field=name, value=value):
                document = metadata(head)
                document["revocation"][name] = value
                with self.assertRaises(AnnouncementMetadataError):
                    verifier_cache().ingest_metadata(ISSUER_ID, document)
        # signed(1) has the zero predecessor at epoch 1: a migration
        # checkpoint, which a cold start accepts only under local policy.
        verifier_cache(
            authorized_migrations={(ISSUER_ID, ACCUMULATOR_ID, 1)}
        ).ingest_metadata(ISSUER_ID, metadata(head))

    def test_issuer_metadata_assembly_requires_the_signed_json_types(self):
        honest = service()
        honest.register(101)
        adapter = SandboxIssuerAdapter(signing_key=KEY, accumulator=honest, clock=lambda: T0)
        adapter.issuer_metadata()
        real_metadata = honest.metadata
        for name, value in (("currentEpoch", True), ("maxEpochLag", 10.0)):
            with self.subTest(field=name):
                block = real_metadata()
                block[name] = value
                with mock.patch.object(honest, "metadata", lambda block=block: block):
                    with self.assertRaises(ValueError):
                        adapter.issuer_metadata()


class ByteBoundTests(unittest.TestCase):
    def test_transcript_is_bounded_to_65535_bytes(self):
        self.assertEqual(MAX_ANNOUNCEMENT_TRANSCRIPT_BYTES, 65535)
        # 143 fixed bytes leave 65392 for accumulatorId and signingKeyId.
        fits = signed(1)
        fits["accumulatorId"] = "a" * (65392 - len(KEY.key_id.encode()))
        self.assertEqual(len(announcement_transcript(fits)), 65535)
        over = dict(fits, accumulatorId=fits["accumulatorId"] + "a")
        with self.assertRaises(ValueError):
            announcement_transcript(over)
        # Code points are not bytes: 16,384 four-byte characters fit a
        # 65,535-character maxLength but not the byte bound.
        wide = dict(fits, accumulatorId="\U0001F600" * 16_384)
        with self.assertRaises(ValueError):
            announcement_transcript(wide)

    def test_schema_and_spec_state_the_byte_bounds(self):
        schema = json.loads((REPO_ROOT / "schemas" / "issuer-metadata.schema.json").read_text())
        fields = schema["properties"]["revocation"]["properties"]["currentAnnouncement"][
            "properties"
        ]
        for name in ("accumulatorId", "signingKeyId"):
            with self.subTest(field=name):
                comment = fields[name].get("$comment", "")
                self.assertIn("UTF-8 bytes", comment)
                self.assertIn("65535", comment)
        spec = (REPO_ROOT / "docs" / "zkc_specification.md").read_text()
        self.assertIn("`len(T)` MUST NOT exceed 65535 bytes", spec)
        self.assertIn("at most one leaf slot per epoch", spec)


# --- (c) transport server ---------------------------------------------------------


def exchange(server, payload: bytes, *, half_close: bool = False, timeout: float = 5.0):
    """Send raw bytes; return (status or None, decoded JSON body or None)."""
    host, port = server._http.server_address[:2]
    data = b""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(payload)
        if half_close:
            sock.shutdown(socket.SHUT_WR)
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        except ConnectionResetError:
            pass
    return parse_response(data)


def parse_response(data: bytes):
    if not data:
        return None, None
    head, _, body = data.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1])
    return status, json.loads(body) if body else None


def post_head(path: str = REVOCATION_UPDATES_PATH, headers: str = "") -> bytes:
    return f"POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n{headers}\r\n".encode()


def post(body: bytes, path: str = REVOCATION_UPDATES_PATH, headers: str = "") -> bytes:
    return post_head(path, f"Content-Length: {len(body)}\r\n{headers}") + body


def epoch_delta(**fields) -> bytes:
    return json.dumps(
        {"type": "zkc:epoch-delta-request:v1", "accumulatorId": ACCUMULATOR_ID, **fields}
    ).encode()


class TransportInputTests(unittest.TestCase):
    """PoC poc18: every malformed input gets a structured 400."""

    @classmethod
    def setUpClass(cls):
        cls.service = service()
        cls.service.register(101)
        cls.server = RevocationServer(cls.service)
        cls.server.start_background()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def assert_client_error(self, payload: bytes, status: int = 400, **kwargs):
        got, body = exchange(self.server, payload, **kwargs)
        self.assertEqual(got, status)
        self.assertEqual(set(body), {"error"})
        self.assertIsInstance(body["error"]["message"], str)
        return body

    def test_well_formed_request_is_served(self):
        status, body = exchange(self.server, post(epoch_delta()))
        self.assertEqual(status, 200)
        self.assertEqual(body["leaves"], [field_to_hex(101)])

    def test_malformed_content_length_is_a_400(self):
        for value in ("abc", "1_0", "+5", "-1", "0x10", "1e3", "99999999"):
            with self.subTest(value=value):
                self.assert_client_error(post_head(headers=f"Content-Length: {value}\r\n"))

    def test_repeated_content_length_and_transfer_encoding_are_400(self):
        # Headers only: the refusal comes before any body byte is read.
        self.assert_client_error(post_head(headers="Content-Length: 2\r\nContent-Length: 2\r\n"))
        self.assert_client_error(post_head(headers="Transfer-Encoding: chunked\r\n"))

    def test_truncated_body_is_a_400(self):
        self.assert_client_error(
            post_head(headers="Content-Length: 50\r\n") + b'{"type"', half_close=True
        )

    def test_non_canonical_json_is_a_400(self):
        delta = epoch_delta()
        for name, body in (
            ("deep nesting", nested_json(65)),
            ("NaN", delta[:-1] + b', "fromEpoch": NaN}'),
            ("Infinity", delta[:-1] + b', "fromEpoch": Infinity}'),
            ("-Infinity", delta[:-1] + b', "fromEpoch": -Infinity}'),
            ("overflowing float", delta[:-1] + b', "fromEpoch": 1e400}'),
            ("duplicate key", delta[:-1] + b', "accumulatorId": "other"}'),
            ("invalid UTF-8", b'{"type": "\xff"}'),
            ("not an object", b"[]"),
        ):
            with self.subTest(case=name):
                self.assert_client_error(post(body))

    def test_non_integer_from_epoch_is_a_protocol_error(self):
        for value in (True, 1.5, "1", -1, 2**64):
            with self.subTest(value=value):
                body = self.assert_client_error(post(epoch_delta(fromEpoch=value)), 422)
                self.assertEqual(body["error"]["code"], "REVOCATION_METADATA_UNAVAILABLE")

    def test_non_canonical_epoch_path_is_a_400(self):
        for segment in ("+1", "01", "1_0", " 1", "-1", "1.0", str(2**64), chr(0x661)):
            with self.subTest(segment=segment):
                path = REVOCATION_ANNOUNCEMENT_PATH + "/" + segment.replace(" ", "%20")
                self.assert_client_error(f"GET {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode("utf-8"))
        status, body = exchange(
            self.server, f"GET {REVOCATION_ANNOUNCEMENT_PATH}/1 HTTP/1.1\r\nHost: x\r\n\r\n".encode()
        )
        self.assertEqual((status, body["epoch"]), (200, 1))

    def test_http_server_errors_are_json(self):
        self.assert_client_error(b"BREW /pot HTTP/1.1\r\nHost: x\r\n\r\n", 501)
        # The parser stops after the 101st header line, so nothing is unread.
        self.assert_client_error(b"GET / HTTP/1.1\r\n" + b"X: y\r\n" * 101, 431)


class SlowClientTests(unittest.TestCase):
    """A slow request is cut at one deadline; it never pins a thread."""

    def setUp(self):
        self.service = service()
        self.server = RevocationServer(self.service, request_timeout=0.5)
        self.server.start_background()
        self.addCleanup(self.server.stop)
        self.host, self.port = self.server._http.server_address[:2]

    def test_drip_fed_body_gets_408_at_the_deadline(self):
        started = time.monotonic()
        with socket.create_connection((self.host, self.port), timeout=8) as sock:
            sock.sendall(post_head(headers="Content-Length: 1000\r\n") + b"{")
            sock.settimeout(0.1)
            data = b""
            # One byte every 0.1 s stays inside any per-read timeout.
            while time.monotonic() - started < 8:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    try:
                        sock.sendall(b" ")
                    except OSError:
                        pass
                    continue
                except ConnectionResetError:
                    break
                if not chunk:
                    break
                data += chunk
        status, body = parse_response(data)
        self.assertEqual(status, 408)
        self.assertIn("not received in time", body["error"]["message"])
        # The 0.5 s deadline, with slack for a loaded machine.
        self.assertLess(time.monotonic() - started, 5.0)

    def test_slow_request_line_is_dropped_at_the_deadline(self):
        started = time.monotonic()
        with socket.create_connection((self.host, self.port), timeout=8) as sock:
            sock.sendall(b"POST /v1/rev")
            self.assertEqual(sock.recv(1024), b"")
        self.assertLess(time.monotonic() - started, 5.0)


class ConcurrencyLimitTests(unittest.TestCase):
    def test_connections_beyond_the_limit_get_503_without_a_thread(self):
        server = RevocationServer(service(), max_concurrent_requests=2, request_timeout=5)
        server.start_background()
        self.addCleanup(server.stop)
        host, port = server._http.server_address[:2]
        holders = []
        for _ in range(2):
            sock = socket.create_connection((host, port), timeout=5)
            sock.sendall(post_head(headers="Content-Length: 100\r\n"))
            holders.append(sock)
        deadline = time.monotonic() + 10
        while server._http._slots._value and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(server._http._slots._value, 0)
        threads_before = threading.active_count()
        with socket.create_connection((host, port), timeout=5) as sock:
            data = b""
            while chunk := sock.recv(65536):
                data += chunk
        status, body = parse_response(data)
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": {"message": "server is at its connection limit"}})
        self.assertLessEqual(threading.active_count(), threads_before)
        for sock in holders:
            sock.close()
        # Closing the held connections frees their slots.
        client = RevocationServiceClient(server.base_url)
        deadline = time.monotonic() + 10
        while True:
            try:
                self.assertEqual(client.current_announcement()["epoch"], 0)
                break
            except TransportError as exc:
                if exc.status != 503 or time.monotonic() > deadline:
                    raise
                time.sleep(0.02)

    def test_limits_are_validated(self):
        for kwargs in (
            {"max_concurrent_requests": 0},
            {"max_concurrent_requests": 1.5},
            {"request_timeout": 0},
            {"request_timeout": float("inf")},
        ):
            with self.subTest(**kwargs):
                with self.assertRaises(ValueError):
                    RevocationServer(service(), **kwargs)


class BrokenService:
    """A revocation service whose own state fails in the given way."""

    accumulator_id = ACCUMULATOR_ID

    def __init__(self, error):
        self._error = error

    def _fail(self, *args):
        raise self._error

    current_announcement = _fail
    announcement_for_epoch = _fail
    handle_request = _fail


class ServerFaultMappingTests(unittest.TestCase):
    """Issuer-state faults are 5xx; only request faults are 4xx."""

    def status_of(self, error, payload: bytes):
        with RevocationServer(BrokenService(error)) as server:
            return exchange(server, payload)

    def test_state_faults_are_503(self):
        get_current = f"GET {REVOCATION_ANNOUNCEMENT_PATH} HTTP/1.1\r\nHost: x\r\n\r\n".encode()
        get_epoch = f"GET {REVOCATION_ANNOUNCEMENT_PATH}/3 HTTP/1.1\r\nHost: x\r\n\r\n".encode()
        for error in (KeyError("epoch"), ValueError("corrupt"), TypeError("bad"), IndexError(1)):
            for name, payload in (
                ("current", get_current),
                ("historical", get_epoch),
                ("updates", post(epoch_delta())),
            ):
                with self.subTest(error=type(error).__name__, route=name):
                    with self.assertLogs("zkc.transport", "WARNING"):
                        status, body = self.status_of(error, payload)
                    self.assertEqual(status, 503)
                    self.assertEqual(
                        body, {"error": {"message": "revocation service is unavailable"}}
                    )

    def test_current_announcement_adapter_error_is_503_with_its_code(self):
        error = AdapterError("REVOCATION_METADATA_UNAVAILABLE", "not durably published")
        status, body = self.status_of(
            error, f"GET {REVOCATION_ANNOUNCEMENT_PATH} HTTP/1.1\r\nHost: x\r\n\r\n".encode()
        )
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "REVOCATION_METADATA_UNAVAILABLE")
        self.assertNotIn("durably", body["error"]["message"])

    def test_request_faults_keep_their_4xx(self):
        error = AdapterError("REVOCATION_METADATA_UNAVAILABLE", "unknown accumulator id")
        self.assertEqual(self.status_of(error, post(epoch_delta()))[0], 422)
        self.assertEqual(self.status_of(error, post(b"{bad"))[0], 400)


class OperatorRouterTransportTests(unittest.TestCase):
    """The admin router keeps the bounds and still authenticates before parsing."""

    def setUp(self):
        self.service = service()
        self.service.register(111)
        adapter = SandboxIssuerAdapter(signing_key=KEY, accumulator=self.service, clock=lambda: T0)
        self.admin = IssuerAdminServer(
            adapter,
            {OPERATOR.key_id: OPERATOR.public_key_hex()},
            clock=lambda: T0,
            request_timeout=0.5,
        )
        self.admin.start_background()
        self.addCleanup(self.admin.stop)
        self.issuer_id = adapter.issuer_id

    def signed_post(self, body: bytes) -> bytes:
        headers = OPERATOR.sign_request(
            issuer_id=self.issuer_id, method="POST", request_target=ADMIN_REVOKE_PATH,
            body=body, timestamp=T0,
        )
        extra = "".join(f"{name}: {value}\r\n" for name, value in headers.items())
        return post(body, ADMIN_REVOKE_PATH, extra)

    def test_unsigned_malformed_body_is_refused_before_parsing(self):
        for body in (b"[" * 200_000 + b"]" * 200_000, b'{"credentialId": NaN}'):
            with self.subTest(size=len(body)):
                status, response = exchange(self.admin, post(body, ADMIN_REVOKE_PATH))
                self.assertEqual(status, 401)
                self.assertEqual(response["error"]["message"], "operator authentication required")
        self.assertTrue(self.service.is_active(111))

    def test_signed_non_canonical_json_is_a_400(self):
        good = json.dumps({"credentialId": field_to_hex(111)}).encode()
        for body in (
            b"[" * 200_000 + b"]" * 200_000,
            b'{"credentialId": NaN}',
            good[:-1] + b', "credentialId": "' + field_to_hex(111).encode() + b'"}',
            b'{"credentialId": "0x' + field_to_hex(111)[2:].upper().encode() + b'"}',
        ):
            with self.subTest(body=body[:40]):
                status, _ = exchange(self.admin, self.signed_post(body))
                self.assertEqual(status, 400)
        self.assertTrue(self.service.is_active(111))

    def test_malformed_content_length_and_slow_body_on_the_admin_router(self):
        status, _ = exchange(
            self.admin, post_head(ADMIN_REVOKE_PATH, "Content-Length: 1_0\r\n")
        )
        self.assertEqual(status, 400)
        status, _ = exchange(
            self.admin, post_head(ADMIN_REVOKE_PATH, "Content-Length: 100\r\n") + b"{"
        )
        self.assertEqual(status, 408)


if __name__ == "__main__":
    unittest.main()

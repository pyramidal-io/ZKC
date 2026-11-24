"""R7.14: issuer adapter privacy-boundary matching and validation/state gaps.

Regression tests for review 2026-10-04 finding R7.14:

(a) every nested and normalized variant of a forbidden key is rejected in the
    machine and human privacy profiles;
(b) rate limits are per-client sliding windows charged after validation,
    binding challenges are purged on expiry and capped, and already-expired
    credentials are refused at issuance;
(c) credential ids come from a CSPRNG, and a durable issuance ledger lets a
    restarted adapter issue fresh ids and renew pre-restart credentials;
(d) the accumulator API accepts only canonical credential ids 0 < id < p;
(e) the KYC level is bounded to u8 (1..255) and expiresAt to u64.
"""

import contextvars
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import _path  # noqa: F401
from zkc_crypto import FIELD_MODULUS, derive_holder_commitment_from_seed, field_to_hex, hex_to_field
from zkc_issuer import (
    FORBIDDEN_FIELDS,
    MACHINE_SUBJECT_FORBIDDEN_FIELDS,
    MACHINE_SUBJECT_FORBIDDEN_SUFFIXES,
    SUPPORTED_SCHEMAS,
    AdapterError,
    InMemoryIssuanceLedgerStore,
    IssuanceLedgerError,
    IssuerAccumulator,
    IssuerSigningKey,
    SandboxIssuerAdapter,
    SQLiteIssuanceLedgerStore,
    compute_binding_response,
    reject_forbidden,
)
from zkc_issuer.external import ExternalProviderAdapter, StaticProviderClient
from zkc_revocation import (
    DurableRevocationAccumulatorService,
    RevocationAccumulatorService,
    SQLiteAccumulatorStateStore,
)

NOW = 1_770_000_000
KYC = "zkc:cred:kyc:v1"
HOLDER = field_to_hex(derive_holder_commitment_from_seed(31337))
HUMAN = frozenset({"human"})
HUMAN_AND_MACHINE = frozenset({"human", "machine"})
KYC_CLAIMS = {"level": 2, "verifiedAttributes": [True, True, True, False, True]}
SIGNING_KEY = IssuerSigningKey.test_issuer()
ACCUMULATOR_ID = "hardening-active-credentials"
UPDATE_ENDPOINT = "https://issuer.example/v1/revocation/updates"


def rejected(payload, profiles) -> bool:
    try:
        reject_forbidden(payload, profiles=profiles)
    except AdapterError as error:
        return error.code == "INVALID_HOLDER_CHALLENGE"
    return False


def nested(segments, value="x"):
    payload = value
    for segment in reversed(segments):
        payload = {segment: payload}
    return payload


def camel_words(name):
    return [word.lower() for word in re.findall(r"[a-z]+|[A-Z][a-z]*", name)]


def name_variants(words):
    """Normalized and structural spellings of one name made of ``words``."""
    joined = "".join(words)
    camel = words[0] + "".join(word.capitalize() for word in words[1:])
    variants = [
        {camel: "x"},
        {joined: "x"},
        {joined.upper(): "x"},
        {"_".join(words): "x"},
        {"-".join(words).upper(): "x"},
        {camel[0].upper() + camel[1:]: "x"},
        {".".join(words): "x"},
        nested(words),
        {"outer": [{"inner": nested(words)}]},
        # Every split point, as nested objects and as one dotted key.
        *(nested([joined[:i], joined[i:]]) for i in range(1, len(joined))),
        *({f"{joined[:i]}.{joined[i:]}": "x"} for i in range(1, len(joined))),
        # One character per nesting level.
        nested(list(joined)),
    ]
    return variants


class PrivacyMatcherTests(unittest.TestCase):
    """(a) Nested and normalized forbidden keys are rejected in both profiles."""

    def test_review_poc_nested_machine_forms_are_rejected(self):
        for payload in (
            {"tee": {"quote": "<raw TEE quote bytes>"}},
            {"raw": {"evidence": "<raw provenance>"}},
            {"host": {"id": "i-0abc123"}},
            {"machine": {"id": "4c4c4544-0042"}},
            {"cloud": {"instance": {"id": "i-0abc123"}}},
            {"hardware": {"uuid": "4C4C4544-0042"}},
            {"report": {"data": "0x00"}},
            {"env": {"vars": {"AWS_SECRET_ACCESS_KEY": "x"}}},
            {"working": {"directory": "/home/alice/src"}},
            {"build": {"parameters": {"token": "x"}}},
            {"certificate": {"chain": ["-----BEGIN"]}},
        ):
            with self.subTest(payload=payload):
                self.assertTrue(rejected(payload, HUMAN_AND_MACHINE))

    def test_review_poc_human_forms_are_rejected(self):
        for payload in (
            {"masterSeed": "x"}, {"master_seed": "x"}, {"MasterSeed": "x"},
            {"masterseed": "x"}, {"master": {"seed": "x"}},
            {"credential_binding_key": "x"}, {"zka_address": "x"}, {"spending_key": "x"},
        ):
            for profiles in (HUMAN, HUMAN_AND_MACHINE):
                with self.subTest(payload=payload, profiles=sorted(profiles)):
                    self.assertTrue(rejected(payload, profiles))

    def test_every_machine_forbidden_name_variant_is_rejected(self):
        # Normalized names carry no word boundaries, so every split point is
        # exercised instead of a camelCase spelling.
        for name in sorted(MACHINE_SUBJECT_FORBIDDEN_FIELDS):
            for payload in name_variants([name]):
                with self.subTest(name=name, payload=payload):
                    self.assertTrue(rejected(payload, HUMAN_AND_MACHINE))

    def test_every_machine_forbidden_suffix_variant_is_rejected(self):
        for suffix in sorted(MACHINE_SUBJECT_FORBIDDEN_SUFFIXES):
            for payload in name_variants(list(suffix)):
                with self.subTest(suffix=suffix, payload=payload):
                    self.assertTrue(rejected(payload, HUMAN_AND_MACHINE))
            # Concatenated parents keep the semantic path, nested or dotted.
            merged = ["".join(suffix[:-1]), suffix[-1]]
            for payload in (nested(merged), {".".join(merged): "x"}):
                with self.subTest(suffix=suffix, payload=payload):
                    self.assertTrue(rejected(payload, HUMAN_AND_MACHINE))

    def test_every_human_forbidden_name_variant_is_rejected_in_both_profiles(self):
        for name in sorted(FORBIDDEN_FIELDS):
            for payload in name_variants(camel_words(name)):
                for profiles in (HUMAN, HUMAN_AND_MACHINE):
                    with self.subTest(name=name, payload=payload, profiles=sorted(profiles)):
                        self.assertTrue(rejected(payload, profiles))

    def test_human_unicode_compatibility_and_case_folding(self):
        for key in ("ＭａｓｔｅｒＳｅｅｄ", "MASTER SEED", "Master Seed", "SPENDING_KEY", "Zka.Address"):
            with self.subTest(key=key):
                self.assertTrue(rejected({key: "x"}, HUMAN))

    def test_human_error_names_key_paths_but_never_values(self):
        with self.assertRaises(AdapterError) as raised:
            reject_forbidden({"wallet": {"master": {"seed": "secret-value"}}}, profiles=HUMAN)
        self.assertIn("wallet.master.seed", raised.exception.message)
        self.assertNotIn("secret-value", str(raised.exception))

    def test_unqualified_and_protocol_keys_remain_usable(self):
        for payload in (
            {"witness": {"path": [1, 2], "pathIndex": 3}},
            {"report": "x", "quote": "x", "digest": "x", "platformId": "x", "builderIdentity": "x"},
            {"schemaId": KYC, "subjectRef": "ab", "holderCommitment": HOLDER, "nonce": "0x01"},
            {"credential": {"credentialId": "0x01", "claims": {"level": 1}, "expiresAt": 1}},
            {"seedPhraseHint": "x", "nullifierCount": 1, "keyId": "k"},
        ):
            for profiles in (HUMAN, HUMAN_AND_MACHINE):
                with self.subTest(payload=payload, profiles=sorted(profiles)):
                    reject_forbidden(payload, profiles=profiles)

    def test_adapter_stages_reject_nested_variants(self):
        adapter = SandboxIssuerAdapter(clock=lambda: NOW)
        for forbidden in ({"master": {"seed": "x"}}, {"Spending_Key": "x"}):
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(AdapterError) as raised:
                    adapter.verify_subject(
                        {"schemaId": KYC, "fixtureId": "sandbox-alice-basic", **forbidden}
                    )
                self.assertEqual(raised.exception.code, "INVALID_HOLDER_CHALLENGE")
        self.assertFalse(adapter._verified)


class AdapterFlowMixin:
    def challenge(self, adapter, ref, holder=HOLDER):
        return adapter.request_binding_challenge(
            {"subjectRef": ref, "schemaId": KYC, "holderCommitment": holder}
        )

    def bind(self, adapter, ref, holder=HOLDER):
        challenge = self.challenge(adapter, ref, holder)
        adapter.bind_holder_commitment({
            "subjectRef": ref, "schemaId": KYC, "holderCommitment": holder,
            "nonce": challenge["nonce"],
            "challengeResponse": field_to_hex(compute_binding_response(
                hex_to_field(holder), adapter.issuer_id, KYC,
                hex_to_field(challenge["nonce"]), challenge["expiresAt"],
            )),
        })

    def issue(self, adapter, subject_payload):
        ref = adapter.verify_subject({"schemaId": KYC, **subject_payload})["subjectRef"]
        self.bind(adapter, ref)
        return adapter.issue_credential({"subjectRef": ref, "schemaId": KYC})["credential"]


class RateLimitAndChallengeTests(AdapterFlowMixin, unittest.TestCase):
    """(b) Per-client sliding windows, challenge purge/cap, expiry at issuance."""

    def setUp(self):
        self.now = NOW
        self.identity = contextvars.ContextVar("authenticated-session", default="alice")

    def adapter(self, **kwargs):
        kwargs.setdefault("clock", lambda: self.now)
        kwargs.setdefault("session_identity", self.identity.get)
        return SandboxIssuerAdapter(**kwargs)

    def verify(self, adapter, fixture="sandbox-alice-basic", schema=KYC):
        return adapter.verify_subject({"schemaId": schema, "fixtureId": fixture})

    def test_review_poc_junk_requests_do_not_lock_out_other_clients(self):
        adapter = self.adapter(max_requests_per_stage=5)
        self.identity.set("attacker")
        for _ in range(5):
            with self.assertRaisesRegex(AdapterError, "unknown sandbox subject"):
                self.verify(adapter, fixture="nope")
        with self.assertRaises(AdapterError) as raised:
            self.verify(adapter)
        self.assertEqual(raised.exception.code, "RATE_LIMITED")
        self.identity.set("alice")
        self.assertEqual(self.verify(adapter)["status"], "verified")

    def test_requests_failing_validation_are_not_charged(self):
        adapter = self.adapter(max_requests_per_stage=2)
        for invalid in (
            ["not", "an", "object"],
            {"schemaId": "zkc:cred:unknown:v1", "fixtureId": "sandbox-alice-basic"},
            {"schemaId": KYC, "fixtureId": "sandbox-alice-basic", "master": {"seed": "x"}},
        ):
            for _ in range(3):
                with self.assertRaises(AdapterError) as raised:
                    adapter.verify_subject(invalid)
                self.assertNotEqual(raised.exception.code, "RATE_LIMITED")
        self.verify(adapter)
        self.verify(adapter)
        with self.assertRaises(AdapterError) as raised:
            self.verify(adapter)
        self.assertEqual(raised.exception.code, "RATE_LIMITED")

    def test_unauthenticated_requests_are_refused_before_any_charge(self):
        adapter = self.adapter(max_requests_per_stage=1)
        self.identity.set("")
        for _ in range(3):
            with self.assertRaisesRegex(AdapterError, "authenticated session required"):
                self.verify(adapter)
        self.identity.set("alice")
        self.verify(adapter)

    def test_window_slides_and_is_per_stage_and_per_client(self):
        adapter = self.adapter(max_requests_per_stage=2, rate_limit_window_seconds=60)
        first = self.verify(adapter)["subjectRef"]
        self.now += 30
        self.verify(adapter)
        with self.assertRaises(AdapterError) as raised:
            self.verify(adapter)
        self.assertEqual(raised.exception.code, "RATE_LIMITED")
        # Another stage of the same client keeps its own window.
        self.challenge(adapter, first)
        # Another client is unaffected.
        self.identity.set("bob")
        self.verify(adapter)
        self.identity.set("alice")
        # The first request leaves the window after 60 seconds.
        self.now += 30
        self.verify(adapter)
        with self.assertRaises(AdapterError):
            self.verify(adapter)
        self.now += 30
        self.verify(adapter)
        # Stale client windows are swept rather than retained forever.
        self.now += 120
        self.verify(adapter)
        self.assertEqual(set(adapter._rate_windows), {("verify_subject", "alice")})

    def test_rate_limit_configuration_is_validated(self):
        for kwargs in (
            {"max_requests_per_stage": 0}, {"max_requests_per_stage": True},
            {"rate_limit_window_seconds": 0}, {"rate_limit_window_seconds": 86401},
            {"rate_limit_window_seconds": 1.5},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    self.adapter(**kwargs)

    def test_review_poc_outstanding_challenges_are_capped(self):
        adapter = self.adapter()
        ref = self.verify(adapter)["subjectRef"]
        cap = adapter.max_outstanding_challenges_per_subject
        refused = 0
        for index in range(2000):
            try:
                self.challenge(adapter, ref, field_to_hex(index + 1))
            except AdapterError as error:
                self.assertEqual(error.code, "RATE_LIMITED")
                refused += 1
        self.assertEqual(len(adapter._challenges), cap)
        self.assertEqual(refused, 2000 - cap)

    def test_expired_challenges_are_purged(self):
        adapter = self.adapter(subject_session_ttl_seconds=3600)
        ref = self.verify(adapter)["subjectRef"]
        cap = adapter.max_outstanding_challenges_per_subject
        stale = [self.challenge(adapter, ref) for _ in range(cap)]
        with self.assertRaises(AdapterError):
            self.challenge(adapter, ref)
        self.now = stale[-1]["expiresAt"]
        fresh = self.challenge(adapter, ref)
        self.assertEqual(list(adapter._challenges), [fresh["nonce"]])
        # A purged challenge can no longer bind.
        with self.assertRaisesRegex(AdapterError, "expired"):
            adapter.bind_holder_commitment({
                "subjectRef": ref, "schemaId": KYC, "holderCommitment": HOLDER,
                "nonce": stale[0]["nonce"], "challengeResponse": field_to_hex(1),
            })

    def expiring_adapter(self, expires_at):
        fixtures = {"subject": {KYC: {"claims": KYC_CLAIMS, "expiresAt": expires_at}}}
        return self.adapter(fixtures=fixtures)

    def test_review_poc_already_expired_credentials_are_not_issued(self):
        for expires_at in (NOW - 86400, NOW):
            with self.subTest(expires_at=expires_at):
                adapter = self.expiring_adapter(expires_at)
                ref = self.verify(adapter, fixture="subject")["subjectRef"]
                self.bind(adapter, ref)
                with self.assertRaisesRegex(AdapterError, "already expired") as raised:
                    adapter.issue_credential({"subjectRef": ref, "schemaId": KYC})
                self.assertEqual(raised.exception.code, "PROVIDER_VERIFICATION_FAILED")
                self.assertEqual(adapter.accumulator.epoch, 0)
                self.assertFalse(adapter._issued)

    def test_future_and_no_deadline_expiry_still_issue(self):
        # Zero is the circuits' explicit no-expiry value, not a past time.
        for expires_at in (NOW + 1, 0):
            with self.subTest(expires_at=expires_at):
                adapter = self.expiring_adapter(expires_at)
                credential = self.issue(adapter, {"fixtureId": "subject"})
                self.assertEqual(credential["expiresAt"], expires_at)


class CredentialIdAndRestartTests(AdapterFlowMixin, unittest.TestCase):
    """(c) CSPRNG credential ids and a durable issuance ledger across restart."""

    DECISIONS = {
        "applicant-1": {KYC: {"claims": KYC_CLAIMS, "expiresAt": 2_000_000_000}},
        "applicant-2": {KYC: {"claims": KYC_CLAIMS, "expiresAt": 2_000_000_000}},
    }

    def setUp(self):
        self.now = NOW
        self.identity = contextvars.ContextVar("authenticated-session", default="alice")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "issuer.sqlite3"
        self.open_stores = []
        # The provider's private subject identities outlive issuer restarts.
        self.provider = StaticProviderClient(self.DECISIONS)

    def tearDown(self):
        for store in self.open_stores:
            store.close()

    def boot(self, ledger=True, issuer_id="zkc:issuer:external-reference"):
        """One issuer process: durable accumulator and (optionally) ledger."""
        for store in self.open_stores:
            store.close()
        self.open_stores = []
        accumulator_store = SQLiteAccumulatorStateStore(self.path, ACCUMULATOR_ID)
        self.open_stores.append(accumulator_store)
        accumulator = DurableRevocationAccumulatorService.open(
            ACCUMULATOR_ID, UPDATE_ENDPOINT, SIGNING_KEY, accumulator_store, clock=lambda: self.now,
        )
        ledger_store = None
        if ledger:
            ledger_store = SQLiteIssuanceLedgerStore(self.path, "external-reference")
            self.open_stores.append(ledger_store)
        return ExternalProviderAdapter(
            self.provider,
            issuer_id=issuer_id,
            signing_key=SIGNING_KEY,
            accumulator=accumulator,
            clock=lambda: self.now,
            session_identity=self.identity.get,
            issuance_ledger=ledger_store,
        )

    def test_review_poc_restart_issues_fresh_ids_and_renews_pre_restart_credentials(self):
        adapter = self.boot()
        first = self.issue(adapter, {"subjectId": "applicant-1"})
        first_id = hex_to_field(first["credentialId"])
        epoch = adapter.accumulator.epoch

        adapter = self.boot()  # restart
        self.assertEqual(adapter.accumulator.epoch, epoch)
        self.assertTrue(adapter._owns_issuance_ledger)
        # A returning subject keeps its lineage: issuance refuses, renewal works.
        with self.assertRaisesRegex(AdapterError, "use renewal"):
            self.issue(adapter, {"subjectId": "applicant-1"})
        renewed = adapter.renew_credential({"credentialId": first["credentialId"]})["credential"]
        renewed_id = hex_to_field(renewed["credentialId"])
        self.assertNotEqual(renewed_id, first_id)
        self.assertEqual(renewed["holderCommitment"], HOLDER)
        self.assertFalse(adapter.accumulator.is_active(first_id))
        self.assertTrue(adapter.accumulator.is_active(renewed_id))
        # A new subject after restart gets a fresh, active id.
        second = self.issue(adapter, {"subjectId": "applicant-2"})
        second_id = hex_to_field(second["credentialId"])
        self.assertNotIn(second_id, {first_id, renewed_id})
        self.assertTrue(adapter.accumulator.is_active(second_id))

        adapter = self.boot()  # restart again: the renewed lineage survives
        attestation = adapter.sign_rebind_attestation({"credentialId": renewed["credentialId"]})
        self.assertEqual(attestation["validUntil"], renewed["expiresAt"] - 1)
        with self.assertRaisesRegex(AdapterError, "not active"):
            adapter.renew_credential({"credentialId": first["credentialId"]})
        # Ownership still follows the trusted session after restart.
        self.identity.set("mallory")
        with self.assertRaisesRegex(AdapterError, "credential session unavailable"):
            adapter.renew_credential({"credentialId": renewed["credentialId"]})

    def test_restart_without_ledger_still_refuses_issuance(self):
        adapter = self.boot(ledger=False)
        self.issue(adapter, {"subjectId": "applicant-1"})
        adapter = self.boot(ledger=False)
        with self.assertRaisesRegex(AdapterError, "lineage ledger unavailable"):
            self.issue(adapter, {"subjectId": "applicant-2"})

    def test_credential_ids_come_from_the_csprng_and_skip_known_ids(self):
        adapter = self.boot()
        first = hex_to_field(self.issue(adapter, {"subjectId": "applicant-1"})["credentialId"])
        ref = adapter.verify_subject({"schemaId": KYC, "subjectId": "applicant-2"})["subjectRef"]
        self.bind(adapter, ref)
        draws = iter([first - 1, 41])
        with patch("zkc_issuer.adapter.secrets.randbelow", side_effect=lambda bound: next(draws)) as rng:
            second = adapter.issue_credential({"subjectRef": ref, "schemaId": KYC})["credential"]
        self.assertEqual(rng.call_count, 2)
        self.assertEqual(rng.call_args.args, (FIELD_MODULUS - 1,))
        self.assertEqual(hex_to_field(second["credentialId"]), 42)

    def test_crash_before_accumulator_mutation_drops_the_pending_record(self):
        adapter = self.boot()
        with patch.object(adapter.accumulator, "register", side_effect=RuntimeError("crash")):
            with self.assertRaises(RuntimeError):
                self.issue(adapter, {"subjectId": "applicant-1"})
        self.assertEqual(
            [record["state"] for record in adapter._issuance_ledger.load_state()["records"]],
            ["pending"],
        )
        adapter = self.boot()
        self.assertFalse(adapter._issued)
        self.assertEqual(adapter._issuance_ledger.load_state()["records"], [])
        self.issue(adapter, {"subjectId": "applicant-1"})

    def test_crash_after_accumulator_mutation_promotes_the_pending_record(self):
        adapter = self.boot()
        original = adapter._save_ledger

        def crash_on_commit(pending=None):
            if pending is None:
                raise RuntimeError("crash")
            original(pending)

        with patch.object(adapter, "_save_ledger", side_effect=crash_on_commit):
            with self.assertRaises(RuntimeError):
                self.issue(adapter, {"subjectId": "applicant-1"})
        (credential_id,) = adapter.accumulator.credential_ids()
        adapter = self.boot()
        self.assertEqual(list(adapter._issued), [credential_id])
        self.assertEqual(
            [record["state"] for record in adapter._issuance_ledger.load_state()["records"]],
            ["committed"],
        )
        renewed = adapter.renew_credential({"credentialId": field_to_hex(credential_id)})
        self.assertEqual(renewed["renewal"]["renewedFrom"], field_to_hex(credential_id))

    def test_diverged_stores_fail_closed(self):
        adapter = self.boot()
        credential = self.issue(adapter, {"subjectId": "applicant-1"})
        document = adapter._issuance_ledger.load_state()
        cases = {
            "empty ledger": None,
            "missing record": {**document, "records": []},
            "other issuer": {**document, "issuerId": "zkc:issuer:other"},
            "other accumulator": {**document, "accumulatorId": "other"},
            "unknown version": {**document, "version": "zkc:issuer-ledger:v0"},
            "committed but unknown": {**document, "records": document["records"] + [
                {**document["records"][0], "credentialId": field_to_hex(7)},
            ]},
            "broken chain": {**document, "records": [
                {**document["records"][0], "renewedFrom": field_to_hex(9)},
            ]},
            "non-canonical id": {**document, "records": [
                {**document["records"][0], "credentialId": hex(FIELD_MODULUS + 1)},
            ]},
        }
        for name, state in cases.items():
            with self.subTest(case=name):
                store = InMemoryIssuanceLedgerStore()
                if state is not None:
                    store.save_state(state)
                accumulator_store = SQLiteAccumulatorStateStore(self.path, ACCUMULATOR_ID)
                self.addCleanup(accumulator_store.close)
                accumulator = DurableRevocationAccumulatorService.open(
                    ACCUMULATOR_ID, UPDATE_ENDPOINT, SIGNING_KEY, accumulator_store,
                    clock=lambda: self.now,
                )
                with self.assertRaises(IssuanceLedgerError):
                    ExternalProviderAdapter(
                        self.provider, signing_key=SIGNING_KEY,
                        accumulator=accumulator, clock=lambda: self.now,
                        session_identity=self.identity.get, issuance_ledger=store,
                    )
        # The real ledger still restores.
        adapter = self.boot()
        self.assertIn(hex_to_field(credential["credentialId"]), adapter._issued)


class CanonicalAccumulatorIdTests(unittest.TestCase):
    """(d) The accumulator API requires canonical 0 < id < p."""

    def accumulators(self):
        return (
            IssuerAccumulator("acc", UPDATE_ENDPOINT),
            RevocationAccumulatorService("acc", UPDATE_ENDPOINT, SIGNING_KEY, clock=lambda: NOW),
        )

    NON_CANONICAL = (0, -1, FIELD_MODULUS, 5 + FIELD_MODULUS, 2**256, True, "5", 5.0)

    def test_review_poc_non_canonical_alias_is_refused(self):
        for accumulator in self.accumulators():
            with self.subTest(accumulator=type(accumulator).__name__):
                accumulator.register(5)
                with self.assertRaisesRegex(AdapterError, "canonical non-zero"):
                    accumulator.register(5 + FIELD_MODULUS)
                accumulator.revoke(5)
                self.assertFalse(accumulator.is_active(5))
                self.assertFalse(accumulator.is_active(5 + FIELD_MODULUS))
                self.assertFalse(accumulator.is_known(5 + FIELD_MODULUS))
                with self.assertRaises(AdapterError) as raised:
                    accumulator.witness(5)
                self.assertEqual(raised.exception.code, "STALE_ACCUMULATOR_WITNESS")
                self.assertEqual(accumulator.credential_ids(), frozenset({5}))

    def test_every_mutation_refuses_non_canonical_ids_without_advancing(self):
        for accumulator in self.accumulators():
            accumulator.register(7)
            epoch, root = accumulator.epoch, accumulator.root()
            for value in self.NON_CANONICAL:
                for name, call in (
                    ("register", lambda: accumulator.register(value)),
                    ("revoke", lambda: accumulator.revoke(value)),
                    ("replace-new", lambda: accumulator.replace(7, value)),
                    ("replace-old", lambda: accumulator.replace(value, 8)),
                ):
                    with self.subTest(accumulator=type(accumulator).__name__, value=value, call=name):
                        with self.assertRaises(AdapterError) as raised:
                            call()
                        self.assertEqual(raised.exception.code, "REVOCATION_METADATA_UNAVAILABLE")
                        self.assertEqual((accumulator.epoch, accumulator.root()), (epoch, root))
            self.assertTrue(accumulator.is_active(7))
            accumulator.register(FIELD_MODULUS - 1)
            self.assertTrue(accumulator.is_active(FIELD_MODULUS - 1))


class KycBoundsTests(unittest.TestCase):
    """(e) KYC level within u8 1..255 and expiresAt within u64."""

    schema = SUPPORTED_SCHEMAS[KYC]

    def claims(self, level):
        return {"level": level, "verifiedAttributes": [True] * 5}

    def test_review_poc_out_of_range_levels_are_unsupported(self):
        for level in (0, 256, 300, FIELD_MODULUS + 3, -1, True):
            with self.subTest(level=level):
                with self.assertRaises(AdapterError) as raised:
                    self.schema.normalize_claims(self.claims(level))
                self.assertEqual(raised.exception.code, "UNSUPPORTED_SCHEMA")
                with self.assertRaises(AdapterError) as raised:
                    self.schema.compute_digest(1, 2, self.claims(level), 3)
                self.assertEqual(raised.exception.code, "UNSUPPORTED_SCHEMA")
        for level in (1, 255):
            with self.subTest(level=level):
                self.assertEqual(self.schema.normalize_claims(self.claims(level))["level"], level)

    def test_level_p_plus_3_cannot_alias_level_3_digest(self):
        self.schema.compute_digest(1, 2, self.claims(3), 4)
        with self.assertRaises(AdapterError):
            self.schema.compute_digest(1, 2, self.claims(FIELD_MODULUS + 3), 4)

    def test_expires_at_outside_u64_is_unsupported(self):
        for expires_at in (2**64, FIELD_MODULUS + 3, -1, True, 1.0):
            with self.subTest(expires_at=expires_at):
                with self.assertRaises(AdapterError) as raised:
                    self.schema.compute_digest(1, 2, self.claims(3), expires_at)
                self.assertEqual(raised.exception.code, "UNSUPPORTED_SCHEMA")
        self.schema.compute_digest(1, 2, self.claims(3), 2**64 - 1)

    def test_adapter_refuses_out_of_range_kyc_issuance(self):
        flow = AdapterFlowMixin()
        for name, entry in (
            ("level 300", {"claims": self.claims(300), "expiresAt": 2_000_000_000}),
            ("level p+3", {"claims": self.claims(FIELD_MODULUS + 3), "expiresAt": 2_000_000_000}),
            ("expiresAt p+3", {"claims": self.claims(3), "expiresAt": FIELD_MODULUS + 3}),
            ("expiresAt 2^64", {"claims": self.claims(3), "expiresAt": 2**64}),
        ):
            with self.subTest(case=name):
                adapter = SandboxIssuerAdapter(clock=lambda: NOW, fixtures={"subject": {KYC: entry}})
                ref = adapter.verify_subject({"schemaId": KYC, "fixtureId": "subject"})["subjectRef"]
                flow.bind(adapter, ref)
                with self.assertRaises(AdapterError) as raised:
                    adapter.issue_credential({"subjectRef": ref, "schemaId": KYC})
                self.assertEqual(raised.exception.code, "UNSUPPORTED_SCHEMA")
                self.assertEqual(adapter.accumulator.epoch, 0)


class SandboxKeyWindowAfterDefaultExpiryTests(unittest.TestCase):
    """Exercise the sandbox fixtures after the default key expires.

    The default sandbox signing key's window ends 2027-01-01. Fixtures that
    build ``SandboxIssuerAdapter()`` on the real clock must keep working after
    that date, without the test-side renewal touching production windows.
    """

    AFTER_EXPIRY = 1_811_808_000  # 2027-06-01T00:00:00Z
    FAKE_CLOCK_MODULES = (
        "test_issuer_sdk",
        "test_issuer_subject_sessions",
        "test_zkc_registry",
    )

    def test_production_default_window_is_not_widened(self):
        self.assertEqual(
            IssuerSigningKey.__dataclass_fields__["not_after"].default, "2027-01-01T00:00:00Z"
        )
        with patch("time.time", return_value=self.AFTER_EXPIRY):
            key = IssuerSigningKey(key_id="plain", private_key=7)
        self.assertEqual(key.not_after, "2027-01-01T00:00:00Z")
        self.assertFalse(key.is_valid_at(self.AFTER_EXPIRY))

    def test_explicit_test_window_is_never_renewed(self):
        with patch("time.time", return_value=self.AFTER_EXPIRY):
            key = IssuerSigningKey.test_issuer(not_after="2026-06-01T00:00:00Z")
        self.assertEqual(key.not_after, "2026-06-01T00:00:00Z")

    def test_default_sandbox_adapter_signs_after_default_expiry(self):
        with patch("time.time", return_value=self.AFTER_EXPIRY):
            key = IssuerSigningKey.test_issuer()
            self.assertTrue(key.is_valid_at(self.AFTER_EXPIRY))
            self.assertTrue(key.is_valid_at(NOW))  # fixed 2026 fixtures stay valid
            adapter = SandboxIssuerAdapter(clock=lambda: self.AFTER_EXPIRY)
            self.assertEqual(adapter.issuer_metadata()["issuerId"], "zkc:issuer:sandbox")

    def test_issuer_fixtures_pass_with_clock_after_default_expiry(self):
        import subprocess
        import sys

        script = (
            "import sys, time, unittest\n"
            "fake = float(sys.argv[1])\n"
            "time.time = lambda: fake\n"
            "time.time_ns = lambda: int(fake * 1e9)\n"
            "unittest.main(module=None, argv=['fake-clock'] + sys.argv[2:])\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script, str(self.AFTER_EXPIRY), *self.FAKE_CLOCK_MODULES],
            cwd=Path(__file__).resolve().parent,
            capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])


if __name__ == "__main__":
    unittest.main()

"""R7.2: authenticated, expiring, single-use issuer continuations.

The public beta binding response is deliberately computable here by an
attacker. Authorization must come from the trusted session and provider,
never that public response or a guessed provider/evidence locator.
"""

import contextvars
import hashlib
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import _path  # noqa: F401
from zkc_crypto import (
    compute_rebind_attestation_digest, derive_holder_commitment_from_seed,
    digest_to_message_bytes, field_to_hex, hex_to_field, string_to_field,
)
from zkc_crypto.ecdsa_secp256k1 import verify
from zkc_holder import Credential
from zkc_issuer import AdapterError, IssuerSigningKey, compute_binding_response
from zkc_issuer.external import (
    ExternalProviderAdapter, StaticProviderClient, REFERENCE_DECISIONS,
    reference_external_adapter,
)
from zkc_issuer.runtime_attestation import (
    RUNTIME_ATTESTATION_SCHEMA_ID, RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
    StaticPreverifiedRuntimeAttestationProviderClient,
    reference_runtime_attestation_adapter,
)

NOW = 1_770_000_000
SCHEMA = "zkc:cred:kyc:v1"
HOLDER = field_to_hex(derive_holder_commitment_from_seed(31337))
ATTACKER = field_to_hex(derive_holder_commitment_from_seed(99))


class SubjectSessionTests(unittest.TestCase):
    def setUp(self):
        self.now = NOW
        self.identity = contextvars.ContextVar("authenticated-session", default="victim")
        self.adapter = reference_external_adapter(
            clock=lambda: self.now, session_identity=self.identity.get,
        )

    def verify(self, adapter=None, schema=SCHEMA):
        adapter = adapter or self.adapter
        return adapter.verify_subject({
            **adapter.conformance_subject_payload,
            "schemaId": schema, "holderCommitment": HOLDER,
        })["subjectRef"]

    def challenge(self, ref, holder=HOLDER, adapter=None, schema=SCHEMA):
        return (adapter or self.adapter).request_binding_challenge({
            "subjectRef": ref, "schemaId": schema, "holderCommitment": holder,
        })

    def response(self, challenge, adapter=None):
        adapter = adapter or self.adapter
        return {
            "subjectRef": challenge["subjectRef"],
            "schemaId": challenge["schemaId"],
            "holderCommitment": challenge["holderCommitment"],
            "nonce": challenge["nonce"],
            "challengeResponse": field_to_hex(compute_binding_response(
                hex_to_field(challenge["holderCommitment"]), adapter.issuer_id,
                challenge["schemaId"], hex_to_field(challenge["nonce"]),
                challenge["expiresAt"],
            )),
        }

    def bind(self, ref, holder=HOLDER, adapter=None, schema=SCHEMA):
        adapter = adapter or self.adapter
        ch = self.challenge(ref, holder, adapter, schema)
        adapter.bind_holder_commitment(self.response(ch, adapter))

    def issue(self, ref, adapter=None, schema=SCHEMA):
        return (adapter or self.adapter).issue_credential({"subjectRef": ref, "schemaId": schema})

    def test_offline_hash_fails_at_every_stage_without_burning_honest_challenge(self):
        ref = self.verify()
        ch = self.challenge(ref)
        guessed = hashlib.sha256(f"{self.adapter.issuer_id}|{SCHEMA}|case-applicant-1".encode()).hexdigest()
        self.assertNotEqual(guessed, ref)
        self.assertRegex(ref, r"^[0-9a-f]{64}$")
        for call in (
            lambda: self.challenge(guessed, ATTACKER),
            lambda: self.adapter.bind_holder_commitment({**self.response(ch), "subjectRef": guessed}),
            lambda: self.issue(guessed),
        ):
            with self.assertRaises(AdapterError):
                call()
        self.adapter.bind_holder_commitment(self.response(ch))
        credential = Credential.from_dict(self.issue(ref)["credential"])
        self.assertEqual(credential.holder_commitment, hex_to_field(HOLDER))
        self.assertTrue(self.adapter.accumulator.is_active(credential.credential_id))

    def test_stolen_handle_and_payload_session_spoof_do_not_authorize_any_stage(self):
        ref = self.verify()
        ch = self.challenge(ref)
        self.identity.set("attacker")
        for method, payload in (
            (self.adapter.request_binding_challenge, {"subjectRef": ref, "schemaId": SCHEMA, "holderCommitment": ATTACKER}),
            (self.adapter.bind_holder_commitment, self.response(ch)),
            (self.adapter.issue_credential, {"subjectRef": ref, "schemaId": SCHEMA}),
        ):
            for fake_key in ("sessionId", "authenticatedSession", "sessionIdentity"):
                with self.subTest(stage=method.__name__, field=fake_key):
                    with self.assertRaises(AdapterError):
                        method({**payload, fake_key: "victim"})
        self.identity.set("victim")
        self.adapter.bind_holder_commitment(self.response(ch))
        self.assertEqual(self.issue(ref)["credential"]["holderCommitment"], HOLDER)

    def test_missing_or_failed_trusted_identity_refuses_production_adapter(self):
        client = StaticProviderClient(REFERENCE_DECISIONS)
        for identity in (None, lambda: None, lambda: "", lambda: 1, lambda: "x" * 257):
            with self.subTest(identity=identity):
                adapter = ExternalProviderAdapter(client, session_identity=identity)
                with self.assertRaisesRegex(AdapterError, "authenticated session required"):
                    adapter.verify_subject({"schemaId": SCHEMA, "subjectId": "applicant-1", "sessionId": "victim"})
                self.assertFalse(adapter._verified)

    def test_expiry_at_exact_boundary_rejects_challenge_binding_and_issuance(self):
        for stage in ("challenge", "binding", "issuance"):
            with self.subTest(stage=stage):
                self.setUp()
                ref = self.verify()
                ch = self.challenge(ref)
                if stage == "issuance":
                    self.adapter.bind_holder_commitment(self.response(ch))
                self.now += 600
                with self.assertRaises(AdapterError):
                    if stage == "challenge":
                        self.challenge(ref)
                    elif stage == "binding":
                        self.adapter.bind_holder_commitment(self.response(ch))
                    else:
                        self.issue(ref)
                self.assertNotIn(ref, self.adapter._verified)
                self.assertNotIn(ref, self.adapter._bindings)
                self.assertFalse(self.adapter._challenges)

    def test_binding_cannot_be_overwritten_even_by_preissued_challenge(self):
        ref = self.verify()
        victim = self.challenge(ref)
        attacker = self.challenge(ref, ATTACKER)
        self.adapter.bind_holder_commitment(self.response(victim))
        for call in (
            lambda: self.challenge(ref, ATTACKER),
            lambda: self.adapter.bind_holder_commitment(self.response(attacker)),
        ):
            with self.assertRaises(AdapterError):
                call()
        self.assertEqual(self.issue(ref)["credential"]["holderCommitment"], HOLDER)

    def test_one_issuance_lineage_and_renewal_after_handle_consumption(self):
        ref = self.verify()
        self.bind(ref)
        first = self.issue(ref)
        with self.assertRaises(AdapterError):
            self.issue(ref)
        self.assertNotIn(ref, self.adapter._verified)
        self.assertNotIn(ref, self.adapter._bindings)
        fresh = self.verify()
        self.assertNotEqual(fresh, ref)
        self.bind(fresh, ATTACKER)
        with self.assertRaises(AdapterError):
            self.issue(fresh)
        self.now += 601
        self.identity.set("attacker")
        payload = {"credentialId": first["credential"]["credentialId"]}
        with self.assertRaises(AdapterError):
            self.adapter.renew_credential(payload)
        self.identity.set("victim")
        renewed = self.adapter.renew_credential(payload)
        self.assertEqual(renewed["credential"]["holderCommitment"], HOLDER)
        self.assertFalse(self.adapter.accumulator.is_active(hex_to_field(payload["credentialId"])))
        self.assertEqual(len(self.adapter._issued), 2)
        # Full verification cannot create a second lineage, including after revocation.
        self.adapter.revoke_credential(hex_to_field(renewed["credential"]["credentialId"]))
        fresh = self.verify()
        self.bind(fresh)
        with self.assertRaises(AdapterError):
            self.issue(fresh)

    def test_concurrent_issues_from_same_or_fresh_handles_produce_one_credential(self):
        for same_handle in (True, False):
            with self.subTest(same_handle=same_handle):
                self.setUp()
                ref = self.verify()
                self.bind(ref)
                refs = [ref] * 8
                if not same_handle:
                    refs = [self.verify() for _ in range(8)]
                    for other in refs:
                        self.bind(other)
                epoch = self.adapter.accumulator.epoch
                def issue_once(other):
                    try:
                        return self.issue(other)
                    except AdapterError:
                        return None
                with ThreadPoolExecutor(max_workers=8) as pool:
                    results = list(pool.map(issue_once, refs))
                self.assertEqual(sum(result is not None for result in results), 1)
                self.assertEqual(self.adapter.accumulator.epoch, epoch + 1)

    def test_failed_registration_can_retry_but_failed_publication_cannot_duplicate(self):
        ref = self.verify()
        self.bind(ref)
        with patch.object(self.adapter.accumulator, "register", side_effect=RuntimeError("storage unavailable")):
            with self.assertRaises(RuntimeError):
                self.issue(ref)
        self.assertIn(ref, self.adapter._bindings)
        with patch.object(self.adapter.accumulator, "witness", side_effect=RuntimeError("publication unavailable")):
            with self.assertRaises(RuntimeError):
                self.issue(ref)
        with self.assertRaises(AdapterError):
            self.issue(ref)
        self.assertEqual(len(self.adapter._issued), 1)

    def test_second_adapter_cannot_reset_lineage_for_shared_accumulator(self):
        other = reference_external_adapter(
            accumulator=self.adapter.accumulator, session_identity=self.identity.get,
        )
        # Both constructors ran at genesis, before either one issued anything.
        for adapter, allowed in ((self.adapter, True), (other, False)):
            ref = self.verify(adapter)
            self.bind(ref, adapter=adapter)
            if allowed:
                self.issue(ref, adapter)
            else:
                with self.assertRaisesRegex(AdapterError, "lineage ledger unavailable"):
                    self.issue(ref, adapter)

    def test_non_genesis_durable_restart_refuses_missing_private_ledger(self):
        import tempfile
        from contextlib import ExitStack
        from pathlib import Path
        from zkc_issuer import IssuerSigningKey
        from zkc_revocation import DurableRevocationAccumulatorService, SQLiteAccumulatorStateStore
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stores:
            path = Path(directory) / "accumulator.sqlite"
            key = IssuerSigningKey.test_issuer()
            def service():
                return DurableRevocationAccumulatorService.open(
                    accumulator_id="session-test", update_endpoint="https://example.test/updates",
                    signing_key=key, clock=lambda: self.now,
                    store=stores.enter_context(SQLiteAccumulatorStateStore(path, "session-test")),
                )
            first_service = service()
            first = reference_external_adapter(accumulator=first_service, session_identity=self.identity.get)
            ref = self.verify(first)
            self.bind(ref, adapter=first)
            envelope = self.issue(ref, first)
            restarted_service = service()
            restarted = reference_external_adapter(accumulator=restarted_service, session_identity=self.identity.get)
            ref = self.verify(restarted)
            self.bind(ref, adapter=restarted)
            with self.assertRaisesRegex(AdapterError, "lineage ledger unavailable"):
                self.issue(ref, restarted)
            self.assertTrue(restarted_service.is_active(hex_to_field(envelope["credential"]["credentialId"])))

    def test_returned_claims_cannot_modify_the_private_renewal_source(self):
        ref = self.verify()
        self.bind(ref)
        issued = self.issue(ref)
        original = dict(issued["credential"]["claims"])
        original["verifiedAttributes"] = list(original["verifiedAttributes"])
        issued["credential"]["claims"]["level"] = 99
        first = self.adapter.renew_credential({"credentialId": issued["credential"]["credentialId"]})
        self.assertEqual(first["credential"]["claims"], original)
        first["credential"]["claims"]["verifiedAttributes"][:] = [False] * 5
        second = self.adapter.renew_credential({"credentialId": first["credential"]["credentialId"]})
        self.assertEqual(second["credential"]["claims"], original)

    def test_runtime_evidence_aliases_share_a_private_subject_lineage(self):
        import copy
        from zkc_issuer.runtime_attestation import RuntimeAttestationAdapter
        reference = reference_runtime_attestation_adapter()
        entry = reference._provider_client._evidence_store["reference-build-provenance"]
        provider = StaticPreverifiedRuntimeAttestationProviderClient(
            {"first": entry, "alias": copy.deepcopy(entry)},
            RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
        )
        adapter = RuntimeAttestationAdapter(provider, clock=lambda: self.now,
                                            session_identity=self.identity.get)
        for index, locator in enumerate(("first", "alias")):
            ref = adapter.verify_subject({
                "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
                "evidenceRef": locator,
                "holderCommitment": HOLDER,
                "verificationContextDigest": RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
            })["subjectRef"]
            self.bind(ref, HOLDER, adapter, RUNTIME_ATTESTATION_SCHEMA_ID)
            if index == 0:
                self.issue(ref, adapter, RUNTIME_ATTESTATION_SCHEMA_ID)
            else:
                with self.assertRaises(AdapterError):
                    self.issue(ref, adapter, RUNTIME_ATTESTATION_SCHEMA_ID)

    def test_provider_receives_trusted_identity_and_owns_private_reference(self):
        class RecordingProvider(StaticProviderClient):
            seen = None
            def verify_subject(inner, schema_id, payload, *, authenticated_session):
                inner.seen = authenticated_session
                return super().verify_subject(schema_id, payload, authenticated_session=authenticated_session)
        provider = RecordingProvider(REFERENCE_DECISIONS)
        adapter = ExternalProviderAdapter(provider, session_identity=self.identity.get)
        result = adapter.verify_subject({"schemaId": SCHEMA, "subjectId": "applicant-1", "authenticatedSession": "attacker"})
        self.assertEqual(provider.seen, "victim")
        private_ref = adapter._verified[result["subjectRef"]]["providerRef"]
        self.assertNotIn("applicant", private_ref)
        self.assertNotEqual(private_ref, result["subjectRef"])

    def test_runtime_evidence_binds_actual_holder_and_rejects_missing_binding(self):
        adapter = reference_runtime_attestation_adapter(session_identity=self.identity.get)
        payload = {
            **adapter.conformance_subject_payload,
            "schemaId": RUNTIME_ATTESTATION_SCHEMA_ID,
            "verificationContextDigest": RUNTIME_ATTESTATION_VERIFICATION_CONTEXT,
        }
        for holder in (None, ATTACKER):
            with self.subTest(holder=holder):
                with self.assertRaises(AdapterError):
                    adapter.verify_subject({**payload, "holderCommitment": holder})
        ref = adapter.verify_subject(payload)["subjectRef"]
        with self.assertRaises(AdapterError):
            self.challenge(ref, ATTACKER, adapter, RUNTIME_ATTESTATION_SCHEMA_ID)
        self.bind(ref, HOLDER, adapter, RUNTIME_ATTESTATION_SCHEMA_ID)
        self.assertEqual(self.issue(ref, adapter, RUNTIME_ATTESTATION_SCHEMA_ID)["credential"]["holderCommitment"], HOLDER)
        store = adapter._provider_client._evidence_store
        store["reference-build-provenance"]["rawEvidence"].pop("holderCommitment")
        provider = StaticPreverifiedRuntimeAttestationProviderClient(store, RUNTIME_ATTESTATION_VERIFICATION_CONTEXT)
        decision = provider.verify_subject(RUNTIME_ATTESTATION_SCHEMA_ID, payload, authenticated_session="victim")
        self.assertFalse(decision.verified)

    # --- R4.2: rebind attestations come only from issued, active state ---------

    def issued_credential(self):
        ref = self.verify()
        self.bind(ref)
        return self.issue(ref)["credential"]

    def attest(self, credential_id, adapter=None):
        return (adapter or self.adapter).sign_rebind_attestation({"credentialId": credential_id})

    def assert_attests(self, attestation, credential, adapter=None):
        adapter = adapter or self.adapter
        key_x, key_y = adapter._signing_key.public_key_coordinates()
        digest = compute_rebind_attestation_digest(
            string_to_field(adapter.issuer_id), string_to_field(attestation["schemaId"]),
            hex_to_field(credential["holderCommitment"]), hex_to_field(credential["credentialId"]),
            attestation["validFrom"], attestation["validUntil"],
        )
        self.assertTrue(verify(key_x, key_y, bytes.fromhex(attestation["signature"][2:]),
                               digest_to_message_bytes(digest)))

    def test_rebind_attestation_signs_exact_issued_tuple_after_issuance_and_renewal(self):
        credential = self.issued_credential()
        own_window = (0, credential["expiresAt"] - 1)  # inclusive end, exclusive expiry
        issued = credential["rebindAttestation"]
        self.assertEqual((issued["validFrom"], issued["validUntil"]), own_window)
        self.assert_attests(issued, credential)
        later = self.attest(credential["credentialId"])
        self.assertEqual(
            {k: later[k] for k in ("version", "schemaId", "validFrom", "validUntil")},
            {k: issued[k] for k in ("version", "schemaId", "validFrom", "validUntil")},
        )
        self.assert_attests(later, credential)
        renewed = self.adapter.renew_credential({
            "credentialId": credential["credentialId"], "expiresAt": NOW + 1000,
        })["credential"]
        self.assertEqual(renewed["rebindAttestation"]["validUntil"], NOW + 999)
        self.assert_attests(renewed["rebindAttestation"], renewed)
        self.assert_attests(self.attest(renewed["credentialId"]), renewed)
        with self.assertRaisesRegex(AdapterError, "not active"):
            self.attest(credential["credentialId"])

    def test_poc_r4_2_victim_credential_cannot_be_attested_to_attacker(self):
        credential = self.issued_credential()
        victim_id = credential["credentialId"]
        legacy = dict(
            schema_id=SCHEMA, holder_commitment=hex_to_field(ATTACKER),
            credential_id=hex_to_field(victim_id), valid_from=0, valid_until=0,
        )
        with self.assertRaises(TypeError):
            self.adapter.sign_rebind_attestation(**legacy)
        self.identity.set("attacker")
        for payload in (
            {"credentialId": victim_id},
            {"credentialId": victim_id, "holderCommitment": ATTACKER},
            {"credentialId": victim_id, "sessionIdentity": "victim"},
        ):
            with self.subTest(payload=sorted(payload)):
                with self.assertRaises(AdapterError):
                    self.adapter.sign_rebind_attestation(payload)
        # A foreign credential is indistinguishable from an unknown one.
        refusals = []
        for credential_id in (victim_id, field_to_hex(7)):
            with self.assertRaises(AdapterError) as raised:
                self.attest(credential_id)
            refusals.append(raised.exception.to_dict())
        self.assertEqual(refusals[0], refusals[1])
        self.identity.set("victim")
        with self.assertRaises(AdapterError):
            self.attest(victim_id, reference_external_adapter(
                accumulator=self.adapter.accumulator, session_identity=self.identity.get,
            ))
        self.assert_attests(self.attest(victim_id), credential)

    def test_rebind_attestation_refuses_unknown_and_unissued_accumulator_members(self):
        self.issued_credential()
        member = 4242_0001  # registered directly, as in the R4.2 PoC, never issued
        self.adapter.accumulator.register(member)
        for credential_id in (field_to_hex(member), field_to_hex(7), "0x0", "zz", 7, None):
            with self.subTest(credential_id=credential_id):
                with self.assertRaises(AdapterError):
                    self.attest(credential_id)
        with self.assertRaises(AdapterError):
            self.adapter.sign_rebind_attestation("0x01")

    def test_rebind_attestation_refuses_revoked_credential(self):
        credential = self.issued_credential()
        self.adapter.revoke_credential(hex_to_field(credential["credentialId"]))
        with self.assertRaisesRegex(AdapterError, "not active"):
            self.attest(credential["credentialId"])

    def test_rebind_attestation_refuses_caller_window_schema_or_holder(self):
        credential = self.issued_credential()
        for extra in (
            {"validFrom": 0}, {"validUntil": 0}, {"validUntil": credential["expiresAt"] + 1},
            {"schemaId": SCHEMA}, {"holderCommitment": credential["holderCommitment"]},
        ):
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(AdapterError, "only credentialId"):
                    self.adapter.sign_rebind_attestation({"credentialId": credential["credentialId"], **extra})

    def test_rebind_attestation_refuses_expired_credential_and_signing_key(self):
        credential = self.issued_credential()
        renewed = self.adapter.renew_credential({
            "credentialId": credential["credentialId"], "expiresAt": NOW + 1000,
        })["credential"]
        self.now = NOW + 999  # last second the renewed credential is valid
        self.assert_attests(self.attest(renewed["credentialId"]), renewed)
        self.now = NOW + 1000
        with self.assertRaisesRegex(AdapterError, "credential has expired"):
            self.attest(renewed["credentialId"])
        # Renewal cannot revive the expired credential and re-emit an attestation.
        epoch = self.adapter.accumulator.epoch
        with self.assertRaisesRegex(AdapterError, "credential has expired"):
            self.adapter.renew_credential({
                "credentialId": renewed["credentialId"], "expiresAt": 2**64 - 1,
            })
        self.assertEqual(self.adapter.accumulator.epoch, epoch)
        self.setUp()
        # Pin the window explicitly: this case sits exactly on the key's notAfter.
        self.adapter = reference_external_adapter(
            clock=lambda: self.now, session_identity=self.identity.get,
            signing_key=IssuerSigningKey.test_issuer(not_after="2027-01-01T00:00:00Z"),
        )
        credential = self.issued_credential()
        self.now = 1_798_761_600  # pinned key notAfter, before the credential expires
        with self.assertRaises(AdapterError) as raised:
            self.attest(credential["credentialId"])
        self.assertEqual(raised.exception.code, "EXPIRED_ISSUER_KEY")

    def test_issued_rebind_window_never_exceeds_credential_expiry(self):
        from zkc_issuer import SandboxIssuerAdapter
        fixtures = {"subject": {"zkc:cred:jurisdiction:v1": {
            "claims": {"jurisdictionCode": 840, "claimType": 0, "verificationMethod": 1,
                       "validFrom": 1_600_000_000, "validUntil": NOW + 6000},
            "expiresAt": NOW + 5000,
        }}}
        adapter = SandboxIssuerAdapter(fixtures=fixtures, clock=lambda: self.now,
                                       session_identity=self.identity.get)
        schema = "zkc:cred:jurisdiction:v1"
        ref = adapter.verify_subject({"fixtureId": "subject", "schemaId": schema})["subjectRef"]
        self.bind(ref, adapter=adapter, schema=schema)
        credential = self.issue(ref, adapter, schema)["credential"]
        attestation = credential["rebindAttestation"]
        self.assertEqual((attestation["validFrom"], attestation["validUntil"]), (1_600_000_000, NOW + 4999))
        self.assert_attests(attestation, credential, adapter)
        self.assertEqual(self.attest(credential["credentialId"], adapter)["validUntil"], NOW + 4999)

    def test_renewal_expiry_must_be_a_u64_integer(self):
        credential = self.issued_credential()
        epoch = self.adapter.accumulator.epoch
        for expires_at in (str(NOW + 1000), True, float(NOW + 1000), 2**64, -1):
            with self.subTest(expires_at=expires_at):
                with self.assertRaisesRegex(AdapterError, "u64 integer"):
                    self.adapter.renew_credential({
                        "credentialId": credential["credentialId"], "expiresAt": expires_at,
                    })
        self.assertEqual(self.adapter.accumulator.epoch, epoch)
        self.assertTrue(self.adapter.accumulator.is_active(hex_to_field(credential["credentialId"])))

    # --- Renewal policy and request authorization ----------------------------

    def renewal_state(self, adapter=None):
        adapter = adapter or self.adapter
        return (
            adapter.accumulator.metadata(), dict(adapter._issued),
            dict(adapter._subject_credentials),
        )

    def test_renewal_cannot_extend_the_provider_verified_expiry(self):
        credential = self.issued_credential()
        before = self.renewal_state()
        for expires_at in (credential["expiresAt"] + 1, 2**64 - 1):
            with self.subTest(expires_at=expires_at):
                with self.assertRaisesRegex(AdapterError, "exceeds provider-verified expiry"):
                    self.adapter.renew_credential({
                        "credentialId": credential["credentialId"], "expiresAt": expires_at,
                    })
                self.assertEqual(self.renewal_state(), before)
        for expires_at in (0, NOW, NOW - 1):
            with self.subTest(expires_at=expires_at):
                with self.assertRaisesRegex(AdapterError, "must be in the future"):
                    self.adapter.renew_credential({
                        "credentialId": credential["credentialId"], "expiresAt": expires_at,
                    })
                self.assertEqual(self.renewal_state(), before)

    def test_renewal_retains_provider_cap_across_shortening_and_returned_mutation(self):
        credential = self.issued_credential()
        provider_expiry = credential["expiresAt"]
        credential["expiresAt"] = 2**64 - 1
        shortened = self.adapter.renew_credential({
            "credentialId": credential["credentialId"], "expiresAt": NOW + 1000,
        })["credential"]
        shortened["expiresAt"] = 2**64 - 1
        default = self.adapter.renew_credential({"credentialId": shortened["credentialId"]})["credential"]
        self.assertEqual(default["expiresAt"], NOW + 1000)
        before = self.renewal_state()
        with self.assertRaisesRegex(AdapterError, "exceeds provider-verified expiry"):
            self.adapter.renew_credential({
                "credentialId": default["credentialId"], "expiresAt": provider_expiry + 1,
            })
        self.assertEqual(self.renewal_state(), before)
        restored = self.adapter.renew_credential({
            "credentialId": default["credentialId"], "expiresAt": provider_expiry,
        })["credential"]
        self.assertEqual(restored["expiresAt"], provider_expiry)
        self.assertEqual(restored["holderCommitment"], HOLDER)
        self.assertEqual(restored["claims"], credential["claims"])
        self.assertEqual(restored["rebindAttestation"]["validUntil"], provider_expiry - 1)
        self.assert_attests(restored["rebindAttestation"], restored)
        self.assertNotIn("providerExpiresAt", restored)

    def test_renewal_of_provider_no_expiry_credential_keeps_finite_future_policy(self):
        from zkc_issuer import SandboxIssuerAdapter
        fixtures = {"subject": {SCHEMA: {
            "claims": REFERENCE_DECISIONS["applicant-1"][SCHEMA]["claims"], "expiresAt": 0,
        }}}
        adapter = SandboxIssuerAdapter(fixtures=fixtures, clock=lambda: self.now,
                                       session_identity=self.identity.get)
        ref = adapter.verify_subject({"fixtureId": "subject", "schemaId": SCHEMA})["subjectRef"]
        self.bind(ref, adapter=adapter)
        credential = self.issue(ref, adapter)["credential"]
        self.assertEqual(credential["expiresAt"], 0)
        for payload in ({"credentialId": credential["credentialId"]},
                        {"credentialId": credential["credentialId"], "expiresAt": 0}):
            with self.assertRaisesRegex(AdapterError, "must be in the future"):
                adapter.renew_credential(payload)
        renewed = adapter.renew_credential({
            "credentialId": credential["credentialId"], "expiresAt": NOW + 1000,
        })["credential"]
        self.assertEqual(renewed["expiresAt"], NOW + 1000)
        # Zero means the provider set no deadline, rather than the shortened
        # replacement becoming the provider's deadline.
        renewed = adapter.renew_credential({
            "credentialId": renewed["credentialId"], "expiresAt": NOW + 2000,
        })["credential"]
        self.assertEqual(renewed["expiresAt"], NOW + 2000)

    def test_renewal_unknown_and_foreign_states_have_one_refusal(self):
        credential = self.issued_credential()
        replacement = self.adapter.renew_credential({"credentialId": credential["credentialId"]})["credential"]
        self.identity.set("attacker")
        errors = []
        def refuse(credential_id):
            before = self.renewal_state()
            with self.assertRaises(AdapterError) as raised:
                self.adapter.renew_credential({"credentialId": credential_id})
            self.assertEqual(self.renewal_state(), before)
            errors.append(raised.exception.to_dict())
        for credential_id in (field_to_hex(123456789), credential["credentialId"], replacement["credentialId"]):
            refuse(credential_id)
        self.now = replacement["expiresAt"]
        refuse(replacement["credentialId"])
        self.now = NOW
        self.adapter.revoke_credential(hex_to_field(replacement["credentialId"]))
        refuse(replacement["credentialId"])
        self.assertEqual(errors, [{
            "code": "PROVIDER_VERIFICATION_FAILED", "message": "credential session unavailable",
        }] * len(errors))

    def test_renewal_validates_shape_and_rejects_extra_fields(self):
        credential = self.issued_credential()
        before = self.renewal_state()
        for payload in (None, [], "credential", {}, {"credentialId": None},
                        {"credentialId": "not-a-field"}):
            with self.subTest(payload=payload):
                with self.assertRaises(AdapterError):
                    self.adapter.renew_credential(payload)
                self.assertEqual(self.renewal_state(), before)
        for extra in ({"sessionIdentity": "victim"}, {"providerExpiresAt": 2**64 - 1},
                      {"holderCommitment": ATTACKER}, {"schemaId": SCHEMA}, {"ignored": {}}):
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(AdapterError, "only credentialId and optional expiresAt"):
                    self.adapter.renew_credential({"credentialId": credential["credentialId"], **extra})
                self.assertEqual(self.renewal_state(), before)

    def test_renewal_uses_human_and_machine_privacy_entry_scan(self):
        for adapter, forbidden in (
            (self.adapter, {"nested": {"masterSeed": "private"}}),
            (reference_runtime_attestation_adapter(clock=lambda: self.now),
             {"nested": {"rawEvidence": "private"}}),
        ):
            with self.subTest(adapter=type(adapter).__name__):
                before = self.renewal_state(adapter)
                with self.assertRaisesRegex(AdapterError, "forbidden"):
                    adapter.renew_credential({"credentialId": field_to_hex(123456789), **forbidden})
                self.assertEqual(self.renewal_state(adapter), before)

    def test_renewal_rate_limit_counts_refused_requests(self):
        adapter = reference_external_adapter(clock=lambda: self.now, session_identity=self.identity.get,
                                             max_requests_per_stage=2)
        ref = self.verify(adapter)
        self.bind(ref, adapter=adapter)
        credential = self.issue(ref, adapter)["credential"]
        before = self.renewal_state(adapter)
        for _ in range(2):
            with self.assertRaisesRegex(AdapterError, "credential session unavailable"):
                adapter.renew_credential({"credentialId": field_to_hex(123456789)})
        with self.assertRaises(AdapterError) as raised:
            adapter.renew_credential({"credentialId": credential["credentialId"]})
        self.assertEqual(raised.exception.code, "RATE_LIMITED")
        self.assertEqual(self.renewal_state(adapter), before)

    def test_renewal_requires_owned_ledger_and_current_lineage(self):
        credential = self.issued_credential()
        before = self.renewal_state()
        with patch.object(self.adapter, "_owns_issuance_ledger", False):
            with self.assertRaisesRegex(AdapterError, "lineage ledger unavailable"):
                self.adapter.renew_credential({"credentialId": credential["credentialId"]})
        self.assertEqual(self.renewal_state(), before)
        with patch.dict(self.adapter._subject_credentials, clear=True):
            with self.assertRaisesRegex(AdapterError, "not active"):
                self.adapter.renew_credential({"credentialId": credential["credentialId"]})
        self.assertEqual(self.renewal_state(), before)

    def test_failed_replace_preserves_renewal_policy_and_lineage(self):
        credential = self.issued_credential()
        before = self.renewal_state()
        payload = {"credentialId": credential["credentialId"], "expiresAt": NOW + 1000}
        with patch.object(self.adapter.accumulator, "replace", side_effect=RuntimeError("storage unavailable")):
            with self.assertRaises(RuntimeError):
                self.adapter.renew_credential(payload)
        self.assertEqual(self.renewal_state(), before)
        renewed = self.adapter.renew_credential(payload)["credential"]
        self.assertEqual(self.adapter.accumulator.epoch, before[0]["currentEpoch"] + 1)
        self.assertFalse(self.adapter.accumulator.is_active(hex_to_field(credential["credentialId"])))
        self.assertTrue(self.adapter.accumulator.is_active(hex_to_field(renewed["credentialId"])))


if __name__ == "__main__":
    unittest.main()

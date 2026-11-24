"""ZKC issuer adapter conformance kit.

Machine-readable contract tests every ``IssuerAdapter`` implementation must
pass. Each case is a named callable receiving a fresh adapter from the
factory under test; the kit acts as the holder side (it derives a holder
commitment from a test seed and answers binding challenges with the protocol
construction — adapter-independent).

Case ids are stable API: CI and third-party harnesses key off them.

Usage (library):
    from issuer_adapter.kit import run_conformance
    report = run_conformance(lambda: MyAdapter(...))

Usage (CLI):
    python3 conformance/run_issuer_adapter.py                 # reference adapter
    python3 conformance/run_issuer_adapter.py --adapter pkg.module:factory
    python3 conformance/run_issuer_adapter.py --json
"""

from __future__ import annotations

from collections.abc import Mapping
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "python") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "python"))

from zkc_crypto import (  # noqa: E402
    canonical_hex_to_field,
    compute_merkle_root,
    derive_holder_commitment_from_seed,
    digest_to_message_bytes,
    field_to_hex,
    hex_to_field,
)
from zkc_crypto.ecdsa_secp256k1 import verify as ecdsa_verify  # noqa: E402
from zkc_holder import Credential  # noqa: E402
from zkc_issuer import (  # noqa: E402
    ADAPTER_ERROR_CODES,
    HUMAN_PRIVACY_PROFILE,
    MACHINE_PRIVACY_PROFILE,
    SUPPORTED_SCHEMAS,
    AdapterError,
    compute_binding_response,
    get_schema,
    reject_forbidden,
    validate_adapter_capabilities,
)
from zkc_revocation import announcement_hash, verify_epoch_announcement  # noqa: E402

__all__ = ["CONFORMANCE_CASES", "run_conformance"]

KIT_SEED = 31337
HOLDER_COMMITMENT = derive_holder_commitment_from_seed(KIT_SEED)
HOLDER_COMMITMENT_HEX = field_to_hex(HOLDER_COMMITMENT)
_SAFE_MACHINE_ERROR = "request includes forbidden privacy-boundary material"
_TOP_LEVEL_SUBJECT_REF = frozenset({("subjectRef",)})
_RAW_FIXTURE_SENTINELS = frozenset(
    {
        "raw-provenance-must-stay-provider-side",
        "raw-checkpoint-must-stay-provider-side",
        "raw-report-quote-sentinel",
        "host-test-serial",
        "/customers/example/build/worktree",
    }
)


class CaseFailure(Exception):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CaseFailure(message)


def _expect_error(callable_, payload, codes, message) -> AdapterError:
    try:
        callable_(payload)
    except AdapterError as error:
        _require(
            error.code in codes,
            f"{message}: got code {error.code}, expected one of {sorted(codes)}",
        )
        return error
    except Exception as error:  # noqa: BLE001 — contract requires AdapterError
        raise CaseFailure(
            f"{message}: raised {type(error).__name__} instead of AdapterError"
        ) from error
    raise CaseFailure(f"{message}: adapter accepted the request")


def _validate_capabilities(adapter) -> None:
    try:
        validate_adapter_capabilities(
            getattr(adapter, "supported_schema_ids", None),
            getattr(adapter, "schema_required_privacy_profiles", None),
        )
    except ValueError as error:
        raise CaseFailure(str(error)) from None


def _contains_key_outside_paths(
    value, key: str, allowed_paths: frozenset[tuple] = frozenset()
) -> bool:
    worklist = [(value, ())]
    while worklist:
        current, path = worklist.pop()
        if type(current) is dict:
            for child_key, child in current.items():
                child_path = path + (child_key,)
                if child_key == key and child_path not in allowed_paths:
                    return True
                worklist.append((child, child_path))
        elif type(current) is list or type(current) is tuple:
            worklist.extend(
                (child, path + (index,))
                for index, child in enumerate(current)
            )
    return False


def _contains_raw_fixture_sentinel(value) -> bool:
    try:
        worklist = [value]
        while worklist:
            current = worklist.pop()
            if type(current) is dict:
                if any(
                    isinstance(key, str)
                    and any(
                        str.__contains__(key, sentinel)
                        for sentinel in _RAW_FIXTURE_SENTINELS
                    )
                    for key in current
                ):
                    return True
                worklist.extend(current.values())
            elif type(current) is list or type(current) is tuple:
                worklist.extend(current)
            elif isinstance(current, str) and any(
                str.__contains__(current, sentinel)
                for sentinel in _RAW_FIXTURE_SENTINELS
            ):
                return True
        return False
    except Exception:
        return True


def _assert_no_forbidden_machine_material(
    value,
    allowed_subject_ref_paths: frozenset[tuple] = frozenset(),
) -> None:
    """Validate a public result with the production privacy matcher."""
    try:
        reject_forbidden(
            value,
            profiles=frozenset({HUMAN_PRIVACY_PROFILE, MACHINE_PRIVACY_PROFILE}),
        )
    except AdapterError:
        raise CaseFailure("public result contains forbidden privacy-boundary material") from None
    if _contains_key_outside_paths(value, "evidenceRef") or _contains_key_outside_paths(
        value, "providerRef"
    ):
        raise CaseFailure("public result contains a private provider reference")
    if _contains_key_outside_paths(
        value, "subjectRef", allowed_subject_ref_paths
    ):
        raise CaseFailure("public result contains an out-of-scope subjectRef")
    if _contains_raw_fixture_sentinel(value):
        raise CaseFailure("public result contains private provider evidence")


def _first_schema(adapter) -> str:
    """The schema the kit exercises the full flow with.

    Adapters may pin it via ``conformance_schema_id`` (it must be one their
    conformance subject passes verification for); otherwise the first
    metadata-published schema is used.
    """
    _validate_capabilities(adapter)
    metadata = adapter.issuer_metadata()
    _assert_no_forbidden_machine_material(metadata)
    _require(bool(metadata.get("supportedSchemas")), "metadata lists no supported schemas")
    published = {entry["schemaId"] for entry in metadata["supportedSchemas"]}
    pinned = getattr(adapter, "conformance_schema_id", None)
    if pinned is not None:
        _require(pinned in published, "conformance_schema_id is not a published schema")
        return pinned
    return metadata["supportedSchemas"][0]["schemaId"]


def _verify_subject(adapter, schema_id: str) -> str:
    payload = dict(getattr(adapter, "conformance_subject_payload", {}))
    payload["schemaId"] = schema_id
    payload["holderCommitment"] = HOLDER_COMMITMENT_HEX
    subject = adapter.verify_subject(payload)
    _assert_no_forbidden_machine_material(
        subject, allowed_subject_ref_paths=_TOP_LEVEL_SUBJECT_REF
    )
    _require(subject.get("status") == "verified", "verify_subject did not return status=verified")
    _require(bool(subject.get("subjectRef")), "verify_subject returned no subjectRef")
    return subject["subjectRef"]


def _bind(adapter, schema_id: str, subject_ref: str) -> dict:
    base = {
        "subjectRef": subject_ref,
        "holderCommitment": HOLDER_COMMITMENT_HEX,
        "schemaId": schema_id,
    }
    challenge = adapter.request_binding_challenge(base)
    _assert_no_forbidden_machine_material(
        challenge, allowed_subject_ref_paths=_TOP_LEVEL_SUBJECT_REF
    )
    response = compute_binding_response(
        HOLDER_COMMITMENT,
        adapter.issuer_id,
        schema_id,
        hex_to_field(challenge["nonce"]),
        challenge["expiresAt"],
    )
    result = adapter.bind_holder_commitment(
        {**base, "nonce": challenge["nonce"], "challengeResponse": field_to_hex(response)}
    )
    _assert_no_forbidden_machine_material(
        result, allowed_subject_ref_paths=_TOP_LEVEL_SUBJECT_REF
    )
    return result


def _credential_id(envelope: dict, operation: str) -> int:
    try:
        credential_id = canonical_hex_to_field(envelope["credential"]["credentialId"])
    except (KeyError, TypeError, ValueError):
        raise CaseFailure(f"{operation} credentialId must be a canonical BN254 field element") from None
    _require(credential_id != 0, f"{operation} credentialId must be nonzero")
    return credential_id


def _issue(adapter, schema_id: str, subject_ref: str) -> dict:
    result = adapter.issue_credential({"subjectRef": subject_ref, "schemaId": schema_id})
    _assert_no_forbidden_machine_material(result)
    _credential_id(result, "issued")
    return result


def _full_flow(adapter, schema_id: str = None):
    schema_id = schema_id or _first_schema(adapter)
    subject_ref = _verify_subject(adapter, schema_id)
    _bind(adapter, schema_id, subject_ref)
    return schema_id, subject_ref, _issue(adapter, schema_id, subject_ref)


# --- cases --------------------------------------------------------------------------


def case_metadata_valid(make_adapter):
    """Issuer metadata conforms to the registry document rules."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "validate_issuer_metadata",
        REPO_ROOT / "tests" / "issuer_adapter" / "validate_issuer_metadata.py",
    )
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    adapter = make_adapter()
    _validate_capabilities(adapter)
    metadata = adapter.issuer_metadata()
    try:
        validator.validate_metadata(metadata)
    except (AssertionError, KeyError, TypeError) as exc:
        raise CaseFailure(f"issuer metadata invalid: {exc}") from exc
    published_schema_ids = {
        entry["schemaId"] for entry in metadata["supportedSchemas"]
    }
    _require(
        published_schema_ids == adapter.supported_schema_ids,
        "issuer metadata schemas differ from authoritative capabilities",
    )
    _assert_no_forbidden_machine_material(metadata)


def case_stage_order_binding_requires_verified_subject(make_adapter):
    """A binding challenge for an unverified subjectRef must be refused."""
    adapter = make_adapter()
    schema_id = _first_schema(adapter)
    _expect_error(
        adapter.request_binding_challenge,
        {
            "subjectRef": "never-verified",
            "holderCommitment": HOLDER_COMMITMENT_HEX,
            "schemaId": schema_id,
        },
        {"PROVIDER_VERIFICATION_FAILED", "INVALID_HOLDER_CHALLENGE"},
        "binding challenge without verified subject",
    )


def case_stage_order_issuance_requires_binding(make_adapter):
    """Issuance for a verified but unbound subject must be refused."""
    adapter = make_adapter()
    schema_id = _first_schema(adapter)
    subject_ref = _verify_subject(adapter, schema_id)
    _expect_error(
        adapter.issue_credential,
        {"subjectRef": subject_ref, "schemaId": schema_id},
        {"INVALID_HOLDER_CHALLENGE"},
        "issuance without holder binding",
    )


def case_binding_rejects_wrong_response(make_adapter):
    """A wrong challenge response must be refused."""
    adapter = make_adapter()
    schema_id = _first_schema(adapter)
    subject_ref = _verify_subject(adapter, schema_id)
    base = {
        "subjectRef": subject_ref,
        "holderCommitment": HOLDER_COMMITMENT_HEX,
        "schemaId": schema_id,
    }
    challenge = adapter.request_binding_challenge(base)
    _expect_error(
        adapter.bind_holder_commitment,
        {**base, "nonce": challenge["nonce"], "challengeResponse": field_to_hex(1)},
        {"INVALID_HOLDER_CHALLENGE"},
        "wrong binding challenge response",
    )


def case_binding_nonce_is_single_use(make_adapter):
    """Replaying a consumed challenge nonce must be refused."""
    adapter = make_adapter()
    schema_id = _first_schema(adapter)
    subject_ref = _verify_subject(adapter, schema_id)
    base = {
        "subjectRef": subject_ref,
        "holderCommitment": HOLDER_COMMITMENT_HEX,
        "schemaId": schema_id,
    }
    challenge = adapter.request_binding_challenge(base)
    response = field_to_hex(
        compute_binding_response(
            HOLDER_COMMITMENT,
            adapter.issuer_id,
            schema_id,
            hex_to_field(challenge["nonce"]),
            challenge["expiresAt"],
        )
    )
    bind_payload = {**base, "nonce": challenge["nonce"], "challengeResponse": response}
    adapter.bind_holder_commitment(bind_payload)
    _expect_error(
        adapter.bind_holder_commitment,
        bind_payload,
        {"INVALID_HOLDER_CHALLENGE"},
        "replayed binding challenge",
    )


def case_rejects_unsupported_schema(make_adapter):
    """verify_subject must refuse schemas outside the published set."""
    adapter = make_adapter()
    undeclared_registered = sorted(
        set(SUPPORTED_SCHEMAS) - set(adapter.supported_schema_ids)
    )
    if undeclared_registered:
        payload = dict(getattr(adapter, "conformance_subject_payload", {}))
        payload["schemaId"] = undeclared_registered[0]
        _expect_error(
            adapter.verify_subject,
            payload,
            {"UNSUPPORTED_SCHEMA"},
            "globally registered but adapter-undeclared schema",
        )
    _expect_error(
        adapter.verify_subject,
        {"schemaId": "zkc:cred:not-a-real-schema:v999"},
        {"UNSUPPORTED_SCHEMA"},
        "unsupported schema",
    )


def case_privacy_boundary_every_stage(make_adapter):
    """Every stage must reject wallet material, even on otherwise-valid requests.

    Forbidden fields (flat and nested) are injected into payloads that would
    otherwise succeed, so a rejection cannot be explained by anything except
    the privacy boundary.
    """
    probes = (
        {"masterSeed": "0xdead"},
        {"context": {"wallet": {"zkaAddress": "zka1..."}}},
        {"history": [{"paymentHistory": []}]},
    )

    class StringSubclass(str):
        pass

    class DictSubclass(dict):
        pass

    class ListSubclass(list):
        pass

    class TupleSubclass(tuple):
        pass

    class CustomMapping(Mapping):
        def __iter__(self):
            return iter(("safe",))

        def __len__(self):
            return 1

        def __getitem__(self, key):
            if key == "safe":
                return "value"
            raise KeyError(key)

    nested = {}
    cursor = nested
    for _ in range(32):
        cursor["safe"] = {}
        cursor = cursor["safe"]
    shared = {"safe": "value"}
    repeated = {"first": shared, "second": shared}
    cycle = {}
    cycle["self"] = cycle
    machine_probes = (
        {"teeQuote": {"hostSerial": "host-test-serial"}},
        {"provenance": {"buildPath": "/customers/example/build/worktree"}},
        {"build": {"path": "x"}},
        {"source": {"path": "x"}},
        {"workspace": {"path": "x"}},
        {"checkout": {"path": "x"}},
        {"provenance": {"build": {"path": "x"}}},
        {"build": {"components": [{"path": "x"}]}},
        {"host": {"serial": "x"}},
        {"host": {"serialNumber": "x"}},
        {"platform": {"serial": "x"}},
        {"chip": {"id": "x"}},
        {"build": {"builderIdentity": "x"}},
        {"build.path": "x"},
        {"source.path": "x"},
        {"workspace.path": "x"},
        {"checkout.path": "x"},
        {"provenance.build.path": "x"},
        {"build.components.path": "x"},
        {"host.serial": "x"},
        {"host.serialNumber": "x"},
        {"platform.serial": "x"},
        {"chip.id": "x"},
        {"build.builderIdentity": "x"},
        {"tee_quote": "x"},
        {"raw-evidence": "x"},
        {"tee.quote": "x"},
        {"raw.evidence": "x"},
        {"host.serial_number": "x"},
        {"host.serial-number": "x"},
        {"": "x"},
        {".host": "x"},
        {"host.": "x"},
        {"host..serial": "x"},
        {"---": "x"},
        {"_": "x"},
        {7: "x"},
        {StringSubclass("safe"): "x"},
        {"safe": DictSubclass()},
        {"safe": ListSubclass()},
        {"safe": TupleSubclass()},
        {"safe": CustomMapping()},
        {"hоstSerial": "x"},
        {"x" * 4097: "x"},
        nested,
        {"safe": [None] * 4095},
        repeated,
        cycle,
    )

    def stage_entry(stage_name):
        adapter = make_adapter()
        schema_id = _first_schema(adapter)
        if stage_name == "verify_subject":
            payload = dict(getattr(adapter, "conformance_subject_payload", {}))
            payload["schemaId"] = schema_id
            payload["holderCommitment"] = HOLDER_COMMITMENT_HEX
            return adapter.verify_subject, payload
        subject_ref = _verify_subject(adapter, schema_id)
        base = {
            "subjectRef": subject_ref,
            "holderCommitment": HOLDER_COMMITMENT_HEX,
            "schemaId": schema_id,
        }
        if stage_name == "request_binding_challenge":
            return adapter.request_binding_challenge, base
        if stage_name == "bind_holder_commitment":
            challenge = adapter.request_binding_challenge(base)
            _assert_no_forbidden_machine_material(
                challenge, allowed_subject_ref_paths=_TOP_LEVEL_SUBJECT_REF
            )
            response = field_to_hex(
                compute_binding_response(
                    HOLDER_COMMITMENT,
                    adapter.issuer_id,
                    schema_id,
                    hex_to_field(challenge["nonce"]),
                    challenge["expiresAt"],
                )
            )
            return adapter.bind_holder_commitment, {
                **base,
                "nonce": challenge["nonce"],
                "challengeResponse": response,
            }
        _bind(adapter, schema_id, subject_ref)
        if stage_name == "issue_credential":
            return adapter.issue_credential, {
                "subjectRef": subject_ref,
                "schemaId": schema_id,
            }
        envelope = _issue(adapter, schema_id, subject_ref)
        return adapter.publish_revocation_handle, {
            "credentialId": envelope["credential"]["credentialId"]
        }

    stage_names = (
        "verify_subject",
        "request_binding_challenge",
        "bind_holder_commitment",
        "issue_credential",
        "publish_revocation_handle",
    )
    for stage_name in stage_names:
        for probe in probes:
            stage, valid_payload = stage_entry(stage_name)
            _expect_error(
                stage,
                {**valid_payload, **probe},
                set(ADAPTER_ERROR_CODES),
                f"{stage_name} accepted wallet material",
            )

    capability_adapter = make_adapter()
    _first_schema(capability_adapter)
    machine_required = any(
        MACHINE_PRIVACY_PROFILE in profiles
        for profiles in capability_adapter.schema_required_privacy_profiles.values()
    )
    if machine_required:
        for stage_name in stage_names:
            for probe in machine_probes:
                stage, valid_payload = stage_entry(stage_name)
                error = _expect_error(
                    stage,
                    {**valid_payload, **probe},
                    {"INVALID_HOLDER_CHALLENGE"},
                    f"{stage_name} accepted machine privacy material",
                )
                _require(
                    error.message == _SAFE_MACHINE_ERROR,
                    f"{stage_name} returned an unsafe machine privacy error",
                )

        allowed_probe = {"witness": {"path": "/customers/example/build/worktree"}}
        for stage_name in stage_names:
            stage, valid_payload = stage_entry(stage_name)
            result = stage({**valid_payload, **allowed_probe})
            _assert_no_forbidden_machine_material(
                result,
                allowed_subject_ref_paths=(
                    _TOP_LEVEL_SUBJECT_REF
                    if stage_name
                    in {
                        "verify_subject",
                        "request_binding_challenge",
                        "bind_holder_commitment",
                    }
                    else frozenset()
                ),
            )

    # Scan one clean five-entry flow and metadata independently of the probes.
    adapter = make_adapter()
    schema_id = _first_schema(adapter)
    subject_ref = _verify_subject(adapter, schema_id)
    base = {
        "subjectRef": subject_ref,
        "holderCommitment": HOLDER_COMMITMENT_HEX,
        "schemaId": schema_id,
    }
    challenge = adapter.request_binding_challenge(base)
    _assert_no_forbidden_machine_material(
        challenge, allowed_subject_ref_paths=_TOP_LEVEL_SUBJECT_REF
    )
    response = field_to_hex(
        compute_binding_response(
            HOLDER_COMMITMENT,
            adapter.issuer_id,
            schema_id,
            hex_to_field(challenge["nonce"]),
            challenge["expiresAt"],
        )
    )
    binding = adapter.bind_holder_commitment(
        {**base, "nonce": challenge["nonce"], "challengeResponse": response}
    )
    _assert_no_forbidden_machine_material(
        binding, allowed_subject_ref_paths=_TOP_LEVEL_SUBJECT_REF
    )
    envelope = _issue(adapter, schema_id, subject_ref)
    publication = adapter.publish_revocation_handle(
        {"credentialId": envelope["credential"]["credentialId"]}
    )
    _assert_no_forbidden_machine_material(publication)
    _assert_no_forbidden_machine_material(adapter.issuer_metadata())


def case_envelope_is_holder_consumable(make_adapter):
    """Issued envelopes parse as holder-SDK credentials bound to the holder."""
    adapter = make_adapter()
    schema_id, _, envelope = _full_flow(adapter)
    credential = Credential.from_dict(envelope["credential"])
    _require(
        credential.holder_commitment == HOLDER_COMMITMENT,
        "credential is not bound to the holder commitment",
    )
    schema = get_schema(schema_id)
    _require(
        credential.proof_type == schema.proof_type,
        "credential proofType does not match the schema's proof type",
    )
    _assert_no_forbidden_machine_material(envelope)


def case_signature_verifies_under_published_key(make_adapter):
    """The issuer signature verifies under a metadata-published key."""
    adapter = make_adapter()
    schema_id, _, envelope = _full_flow(adapter)
    credential = Credential.from_dict(envelope["credential"])
    schema = get_schema(schema_id)
    digest = schema.compute_digest(
        credential.holder_commitment,
        credential.credential_id,
        schema.normalize_claims(envelope["credential"]["claims"]),
        credential.expires_at,
    )
    for key_entry in adapter.issuer_metadata()["signingKeys"]:
        public_key = bytes.fromhex(key_entry["publicKey"].removeprefix("0x"))
        if ecdsa_verify(
            public_key[:32],
            public_key[32:],
            credential.signature,
            digest_to_message_bytes(digest),
        ):
            return
    raise CaseFailure("credential signature does not verify under any published signing key")


def case_witness_verifies_against_published_root(make_adapter):
    """The accumulator witness proves membership under the published root."""
    adapter = make_adapter()
    _, _, envelope = _full_flow(adapter)
    credential = Credential.from_dict(envelope["credential"])
    witness = credential.witness
    _require(witness is not None, "envelope carries no accumulator witness")
    recomputed = compute_merkle_root(
        credential.credential_id, witness.path_index, witness.siblings
    )
    _require(
        recomputed == witness.accumulator_root,
        "witness does not verify against its accumulator root",
    )
    metadata_root = adapter.issuer_metadata()["revocation"]["currentRoot"]
    _require(
        field_to_hex(witness.accumulator_root) == metadata_root,
        "witness root differs from the published metadata root",
    )


def _validated_revocation_announcement(adapter):
    metadata = adapter.issuer_metadata()
    revocation = metadata["revocation"]
    announcement = revocation.get("currentAnnouncement")
    _require(announcement is not None, "metadata omits authenticated announcement")
    for metadata_name, announcement_name in (
        ("accumulatorId", "accumulatorId"),
        ("currentRoot", "root"),
        ("currentEpoch", "epoch"),
        ("maxEpochLag", "maxEpochLag"),
    ):
        _require(
            type(revocation.get(metadata_name)) is type(announcement.get(announcement_name))
            and revocation.get(metadata_name) == announcement.get(announcement_name),
            f"metadata {metadata_name} differs from signed announcement",
        )
    key_entry = next(
        (
            key
            for key in metadata["signingKeys"]
            if key["keyId"] == announcement.get("signingKeyId")
        ),
        None,
    )
    _require(key_entry is not None, "announcement key is not published in metadata")
    try:
        public_key = bytes.fromhex(key_entry["publicKey"].removeprefix("0x"))
    except (AttributeError, ValueError):
        raise CaseFailure("published signing key is invalid") from None
    _require(
        len(public_key) == 64,
        "published signing key is not a 64-byte secp256k1 coordinate pair",
    )
    _require(
        verify_epoch_announcement(
            announcement,
            public_key[:32],
            public_key[32:],
            expected_signing_key_id=key_entry["keyId"],
        ),
        "published revocation announcement signature is invalid",
    )
    return announcement


def case_revocation_publication(make_adapter):
    """Genesis -> issuance -> revocation is signed and predecessor-linked."""
    adapter = make_adapter()
    genesis = _validated_revocation_announcement(adapter)
    _require(genesis["epoch"] == 0, "revocation lifecycle does not start at epoch 0")
    _require(
        genesis["previousAnnouncementHash"] == "0x" + "00" * 32,
        "genesis announcement has a non-zero predecessor",
    )

    _, _, envelope = _full_flow(adapter)
    issuance = _validated_revocation_announcement(adapter)
    _require(issuance["epoch"] == genesis["epoch"] + 1, "issuance skipped an epoch")
    _require(
        issuance["previousAnnouncementHash"] == announcement_hash(genesis),
        "issuance announcement does not commit to genesis",
    )
    credential_id_hex = envelope["credential"]["credentialId"]
    before = adapter.publish_revocation_handle({})
    _assert_no_forbidden_machine_material(before)
    _require(
        before["currentEpoch"] == issuance["epoch"]
        and before["currentRoot"] == issuance["root"],
        "issuance publication differs from authenticated metadata",
    )
    handle = adapter.publish_revocation_handle({"credentialId": credential_id_hex})
    _assert_no_forbidden_machine_material(handle)
    _require(handle.get("status") == "active", "freshly issued credential is not active")

    try:
        zero_handle = adapter.publish_revocation_handle({"credentialId": field_to_hex(0)})
    except AdapterError as error:
        _require(error.code == "REVOCATION_METADATA_UNAVAILABLE", "unexpected zero credentialId refusal")
    else:
        _assert_no_forbidden_machine_material(zero_handle)
        _require(
            zero_handle.get("status") == "unknown" and "witness" not in zero_handle,
            "zero credentialId must have no registration or witness",
        )

    adapter.revoke_credential(hex_to_field(credential_id_hex))
    revocation = _validated_revocation_announcement(adapter)
    _require(
        revocation["epoch"] == issuance["epoch"] + 1,
        "revocation skipped an epoch",
    )
    _require(
        revocation["previousAnnouncementHash"] == announcement_hash(issuance),
        "revocation announcement does not commit to issuance",
    )
    after = adapter.publish_revocation_handle({"credentialId": credential_id_hex})
    _assert_no_forbidden_machine_material(after)
    _require(after.get("status") == "revoked", "revoked credential not reported as revoked")
    _require(
        int(after["currentEpoch"]) > int(before["currentEpoch"]),
        "revocation did not advance the accumulator epoch",
    )
    _require(
        after["currentRoot"] != before["currentRoot"],
        "revocation did not change the accumulator root",
    )
    _require(
        after["currentEpoch"] == revocation["epoch"]
        and after["currentRoot"] == revocation["root"],
        "revocation publication differs from authenticated metadata",
    )
    _require("witness" not in after, "revoked credential still served a witness")


def case_renewal_credential_id(make_adapter):
    """An adapter that implements renewal returns a fresh canonical nonzero ID."""
    adapter = make_adapter()
    renew = getattr(adapter, "renew_credential", None)
    if not callable(renew):
        return

    _, _, issued = _full_flow(adapter)
    credential = issued["credential"]
    issued_id = credential["credentialId"]
    payload = {"credentialId": issued_id}
    if credential["expiresAt"] == 0:
        payload["expiresAt"] = _validated_revocation_announcement(adapter)["announcedAt"] + 3600
    renewed = renew(payload)
    _assert_no_forbidden_machine_material(renewed)
    new_id = _credential_id(renewed, "renewed")
    _require(field_to_hex(new_id) != issued_id, "renewal reused the issued credentialId")


CONFORMANCE_CASES = (
    ("issuer-metadata-valid", case_metadata_valid),
    ("stage-order-binding-requires-verified-subject", case_stage_order_binding_requires_verified_subject),
    ("stage-order-issuance-requires-binding", case_stage_order_issuance_requires_binding),
    ("binding-rejects-wrong-response", case_binding_rejects_wrong_response),
    ("binding-nonce-single-use", case_binding_nonce_is_single_use),
    ("rejects-unsupported-schema", case_rejects_unsupported_schema),
    ("privacy-boundary-every-stage", case_privacy_boundary_every_stage),
    ("envelope-holder-consumable", case_envelope_is_holder_consumable),
    ("signature-verifies-under-published-key", case_signature_verifies_under_published_key),
    ("witness-verifies-against-published-root", case_witness_verifies_against_published_root),
    ("revocation-publication", case_revocation_publication),
    ("renewal-credential-id", case_renewal_credential_id),
)


def run_conformance(make_adapter) -> dict:
    """Run every case against fresh adapters; return a machine-readable report.

    ``make_adapter``: zero-argument factory returning a NEW adapter instance.
    """
    def make_validated_adapter():
        adapter = make_adapter()
        _validate_capabilities(adapter)
        return adapter

    results = []
    for case_id, case in CONFORMANCE_CASES:
        try:
            case(make_validated_adapter)
        except CaseFailure as failure:
            results.append({"id": case_id, "status": "FAIL", "reason": str(failure)})
        except Exception as error:  # noqa: BLE001 — fail closed, never crash the run
            results.append(
                {
                    "id": case_id,
                    "status": "FAIL",
                    "reason": f"unexpected {type(error).__name__}: {error}",
                }
            )
        else:
            results.append({"id": case_id, "status": "PASS"})
    passed = sum(1 for result in results if result["status"] == "PASS")
    return {
        "suite": "zkc-issuer-adapter-conformance:v1",
        "total": len(results),
        "passed": passed,
        "allPassed": passed == len(results),
        "results": results,
    }

"""Proof backends for the holder SDK.

Two backends implement `ProofBackend`:

* `NargoBackend` — real proving. Shells out to `nargo execute` + `bb prove`
  against the repository's Noir circuits. Used when the pinned toolchain is
  installed; integration tests skip live proving otherwise.

* `StubBackend` — deterministic test backend, CLEARLY NON-PRODUCTION
  (`is_production = False`). It first re-evaluates the circuit's constraints
  in Python (fail closed: it refuses to "prove" a statement the real circuit
  would reject) and then emits `zkc:stub:v1:<sha256(circuit, public inputs)>`,
  which the reference verifier's stub path can recompute. A stub proof carries
  NO cryptographic soundness; it exists so unit tests run without nargo/bb.

Witness values for a KYC proof (`zkc:proof:kyc:v1`) are assembled by
`build_kyc_witness`, in the exact ABI order of noir/zkc_kyc/src/main.nr. The
five non-KYC predicate circuits (jurisdiction, accreditation, source-of-funds,
tax-residency, sanctions-clearance, credential-rebind) are covered by builders,
constraint mirrors, and public-input extractors in `predicates.py`; both
backends dispatch to them through `_CONSTRAINT_CHECKS` /
`_PUBLIC_INPUT_EXTRACTORS` below, so no circuit is KYC-only anymore.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
from functools import partial

from zkc_crypto import (
    FIELD_MODULUS,
    compute_claim_binding_2,
    compute_attribute_flags_hash,
    compute_kyc_credential_digest,
    compute_merkle_root,
    derive_holder_commitment,
    digest_to_message_bytes,
    field_to_hex,
)
from zkc_crypto.credential_id_successors import NONZERO_CREDENTIAL_CIRCUIT_PREDECESSORS
from zkc_crypto.ecdsa_secp256k1 import verify as ecdsa_verify
from zkc_crypto.presentation import derive_presentation_pseudonym
from zkc_crypto.stub import stub_proof_payload

from .accumulator import MAX_EPOCH_LAG
from .errors import BackendUnavailableError, ConstraintViolationError

__all__ = [
    "ProofBackend",
    "StubBackend",
    "NargoBackend",
    "build_kyc_witness",
    "build_kyc_witness_v2",
    "kyc_public_inputs_v2",
    "KYC_V2_PUBLIC_INPUT_NAMES",
    "KYC_V2_CIRCUIT",
    "KYC_V2_PROOF_TYPE",
    "COMMUNITY_KYC_V2_CIRCUIT",
    "COMMUNITY_KYC_V2_PROOF_TYPE",
    "KYC_V3_CIRCUIT",
    "KYC_V3_PROOF_TYPE",
]

KYC_PROOF_TYPE = "zkc:proof:kyc:v1"
KYC_CIRCUIT = "zkc_kyc"

KYC_V2_PROOF_TYPE = "zkc:proof:kyc:v2"
KYC_V2_CIRCUIT = "zkc_kyc_v2"

# Draft beta.25 transport identities. They reuse the predecessor statement and
# witness shapes but resolve to distinct packages and verification keys.
COMMUNITY_KYC_V2_PROOF_TYPE = "zkc:proof:community_kyc:v2"
COMMUNITY_KYC_V2_CIRCUIT = "zkc_community_kyc_v2"
KYC_V3_PROOF_TYPE = "zkc:proof:kyc:v3"
KYC_V3_CIRCUIT = "zkc_kyc_v3"


def presentation_pseudonym_for(credential_binding_key: int, scope_id: int) -> int:
    """presentation_pseudonym for a v2 witness.

    Anonymous profile (``scope_id == 0``) has no scope, so the pseudonym is the
    anonymous sentinel ``0``; a scoped profile derives the provable pseudonym
    ``derive_presentation_pseudonym(cbk, scope_id)`` (design §4.1).
    """
    if int(scope_id) == 0:
        return 0
    return derive_presentation_pseudonym(int(credential_binding_key), int(scope_id))


def build_kyc_witness(
    *,
    credential_binding_key: int,
    credential,
    issuer,
    witness,
    required_level: int,
    required_attributes,
    proof_context: int,
    timestamp: int,
    current_epoch: int,
) -> dict:
    """Assemble the full zkc_kyc witness (public + private inputs)."""
    required_attributes = [bool(flag) for flag in required_attributes]
    if len(required_attributes) != 5:
        raise ConstraintViolationError("requiredAttributes must have exactly 5 flags")
    verified_attributes = [bool(flag) for flag in credential.claims["verifiedAttributes"]]
    required_attribute_hash = compute_attribute_flags_hash(required_attributes)
    claim_binding = compute_claim_binding_2(
        required_level, required_attribute_hash, proof_context, timestamp
    )
    return {
        # === Public inputs (encoder order) ===
        "holder_commitment": credential.holder_commitment,
        "claim_binding": claim_binding,
        "proof_context": proof_context,
        "accumulator_root": witness.accumulator_root,
        "accumulator_epoch": witness.accumulator_epoch,
        "timestamp": timestamp,
        "current_epoch": current_epoch,
        "issuer_public_key_x": list(issuer.public_key_x),
        "issuer_public_key_y": list(issuer.public_key_y),
        # === Private inputs ===
        "credential_binding_key": credential_binding_key,
        "credential_holder_commitment": credential.holder_commitment,
        "credential_id": credential.credential_id,
        "credential_level": int(credential.claims["level"]),
        "verified_attributes": verified_attributes,
        "credential_expires_at": credential.expires_at,
        "issuer_signature": list(credential.signature),
        "required_level": int(required_level),
        "required_attributes": required_attributes,
        "nonrevocation_siblings": list(witness.siblings),
        "nonrevocation_path_index": witness.path_index,
    }


KYC_PUBLIC_INPUT_NAMES = (
    "holder_commitment",
    "claim_binding",
    "proof_context",
    "accumulator_root",
    "accumulator_epoch",
    "timestamp",
    "current_epoch",
    "issuer_public_key_x",
    "issuer_public_key_y",
)


def kyc_public_inputs(witness: dict) -> dict:
    """Extract the JSON-able public-input object for the proof envelope."""
    output = {}
    for name in KYC_PUBLIC_INPUT_NAMES:
        value = witness[name]
        if name in ("issuer_public_key_x", "issuer_public_key_y"):
            output[name] = "0x" + bytes(value).hex()
        elif name in ("accumulator_epoch", "timestamp", "current_epoch"):
            output[name] = int(value)
        else:
            output[name] = field_to_hex(value)
    return output


def build_kyc_witness_v2(
    *,
    credential_binding_key: int,
    credential,
    issuer,
    witness,
    required_level: int,
    required_attributes,
    proof_context: int,
    timestamp: int,
    current_epoch: int,
    scope_id: int = 0,
) -> dict:
    """Assemble a zkc_kyc **v2** witness (design §4.1).

    ADDITIVE: the v1 :func:`build_kyc_witness` is untouched. Relative to v1 the
    public-input head becomes ``presentation_pseudonym`` (index 0) + ``scope_id``
    (index 1); ``holder_commitment`` drops OUT of the public inputs and survives
    only as a private witness (its constraint against ``credential_binding_key``
    is unchanged). ``scope_id == 0`` is the anonymous profile.
    """
    base = build_kyc_witness(
        credential_binding_key=credential_binding_key,
        credential=credential,
        issuer=issuer,
        witness=witness,
        required_level=required_level,
        required_attributes=required_attributes,
        proof_context=proof_context,
        timestamp=timestamp,
        current_epoch=current_epoch,
    )
    scope_id = int(scope_id)
    pseudonym = presentation_pseudonym_for(credential_binding_key, scope_id)
    # Head with the v2 public inputs; holder_commitment remains present as a
    # private witness (kyc_public_inputs_v2 simply does not surface it).
    return {
        "presentation_pseudonym": pseudonym,
        "scope_id": scope_id,
        **base,
    }


KYC_V2_PUBLIC_INPUT_NAMES = (
    "presentation_pseudonym",
    "scope_id",
    "claim_binding",
    "proof_context",
    "accumulator_root",
    "accumulator_epoch",
    "timestamp",
    "current_epoch",
    "issuer_public_key_x",
    "issuer_public_key_y",
)


def kyc_public_inputs_v2(witness: dict) -> dict:
    """Extract the v2 public-input object (holder_commitment stays private)."""
    output = {}
    for name in KYC_V2_PUBLIC_INPUT_NAMES:
        value = witness[name]
        if name in ("issuer_public_key_x", "issuer_public_key_y"):
            output[name] = "0x" + bytes(value).hex()
        elif name in ("accumulator_epoch", "timestamp", "current_epoch"):
            output[name] = int(value)
        else:
            output[name] = field_to_hex(value)
    return output


def check_kyc_constraints(witness: dict) -> None:
    """Python mirror of every assert in noir/zkc_kyc/src/main.nr.

    Raises ConstraintViolationError with the circuit's failure message when a
    constraint does not hold. Keeps the stub backend honest: it cannot emit a
    stub proof for a statement the real circuit would reject.
    """

    def fail(message: str):
        raise ConstraintViolationError(message)

    if derive_holder_commitment(witness["credential_binding_key"]) != witness["holder_commitment"]:
        fail("holder commitment does not match credential binding key")
    if witness["credential_holder_commitment"] != witness["holder_commitment"]:
        fail("credential holder commitment does not match public holder commitment")

    digest = compute_kyc_credential_digest(
        witness["credential_holder_commitment"],
        witness["credential_id"],
        witness["credential_level"],
        witness["verified_attributes"],
        witness["credential_expires_at"],
    )
    if not ecdsa_verify(
        bytes(witness["issuer_public_key_x"]),
        bytes(witness["issuer_public_key_y"]),
        bytes(witness["issuer_signature"]),
        digest_to_message_bytes(digest),
    ):
        fail("invalid issuer signature")

    root = compute_merkle_root(
        witness["credential_id"],
        witness["nonrevocation_path_index"],
        witness["nonrevocation_siblings"],
    )
    epoch_fresh = (
        witness["current_epoch"] >= witness["accumulator_epoch"]
        and witness["current_epoch"] - witness["accumulator_epoch"] <= MAX_EPOCH_LAG
    )
    if root != witness["accumulator_root"] or not epoch_fresh:
        fail("credential is revoked or accumulator epoch is stale")

    if witness["credential_level"] < witness["required_level"]:
        fail("credential level below requested level")
    for required, verified in zip(witness["required_attributes"], witness["verified_attributes"]):
        if required and not verified:
            fail("credential does not satisfy required KYC attributes")
    expires_at = witness["credential_expires_at"]
    if expires_at != 0 and expires_at <= witness["timestamp"]:
        fail("credential expired")

    expected_claim_binding = compute_claim_binding_2(
        witness["required_level"],
        compute_attribute_flags_hash(witness["required_attributes"]),
        witness["proof_context"],
        witness["timestamp"],
    )
    if expected_claim_binding != witness["claim_binding"]:
        fail("claim binding mismatch")
    if witness["proof_context"] == 0:
        fail("proof context must be non-zero")
    if witness["timestamp"] == 0:
        fail("timestamp must be non-zero")


def assert_presentation_binding(witness: dict) -> None:
    """Python mirror of zkc_lib::assert_presentation_binding (design §4.1).

    Shared by every v2 predicate constraint mirror: scope_id == 0 (anonymous)
    forces presentation_pseudonym == 0; otherwise the pseudonym must derive from
    the credential binding key and scope. Assertion messages match the circuit."""
    scope_id = int(witness["scope_id"])
    pseudonym = witness["presentation_pseudonym"]
    if scope_id == 0:
        if pseudonym != 0:
            raise ConstraintViolationError("anonymous profile must not carry a pseudonym")
    else:
        expected = derive_presentation_pseudonym(
            int(witness["credential_binding_key"]), scope_id
        )
        if pseudonym != expected:
            raise ConstraintViolationError(
                "presentation pseudonym does not derive from binding key and scope"
            )


def check_kyc_constraints_v2(witness: dict) -> None:
    """Python mirror of noir/zkc_kyc_v2/src/main.nr.

    The v1 KYC constraints (``check_kyc_constraints``) over a private holder
    commitment, plus the shared presentation-binding constraint (design §4.1).
    """
    check_kyc_constraints(witness)
    assert_presentation_binding(witness)


from .predicates import (  # noqa: E402  (imported here to register dispatch entries)
    JURISDICTION_V1_CIRCUIT,
    JURISDICTION_V2_CIRCUIT,
    JURISDICTION_V3_CIRCUIT,
    JURISDICTION_V4_CIRCUIT,
    JURISDICTION_V5_CIRCUIT,
    JURISDICTION_V6_CIRCUIT,
    REBIND_CIRCUIT,
    REBIND_BINDING_V2_CIRCUIT,
    REBIND_V2_CIRCUIT,
    REBIND_V2_BINDING_V2_CIRCUIT,
    REBIND_AUTH_CIRCUIT,
    REBIND_AUTH_V2_CIRCUIT,
    REBIND_AUTH_V3_CIRCUIT,
    REMAINING_CIRCUIT,
    REMAINING_V2_CIRCUIT,
    REMAINING_V3_CIRCUIT,
    REMAINING_V4_CIRCUIT,
    REMAINING_V5_CIRCUIT,
    REMAINING_V6_CIRCUIT,
    REMAINING_V7_CIRCUIT,
    REMAINING_V8_CIRCUIT,
    REMAINING_V9_CIRCUIT,
    REMAINING_V10_CIRCUIT,
    REMAINING_V11_CIRCUIT,
    check_jurisdiction_constraints,
    check_jurisdiction_constraints_v2,
    check_jurisdiction_constraints_v3,
    check_jurisdiction_constraints_v4,
    check_jurisdiction_constraints_v6,
    check_profile_constraints,
    check_profile_constraints_v2,
    check_profile_constraints_v3,
    check_profile_constraints_v4,
    check_profile_constraints_v5,
    check_profile_constraints_v6,
    check_profile_constraints_v7,
    check_profile_constraints_v8,
    check_profile_constraints_v11,
    jurisdiction_public_inputs_v6,
    profile_public_inputs_v11,
    check_rebind_constraints,
    check_rebind_binding_v2_constraints,
    check_rebind_constraints_v2,
    check_rebind_v2_binding_v2_constraints,
    check_rebind_auth_constraints,
    check_rebind_auth_v2_constraints,
    jurisdiction_public_inputs,
    jurisdiction_public_inputs_v2,
    profile_public_inputs,
    profile_public_inputs_v2,
    rebind_public_inputs,
    rebind_public_inputs_v2,
    rebind_auth_public_inputs,
    rebind_auth_public_inputs_v2,
)
from .disclosure import (  # noqa: E402
    DISCLOSURE_CIRCUIT,
    DISCLOSURE_V2_CIRCUIT,
    DISCLOSURE_V3_CIRCUIT,
    check_selective_disclosure_constraints,
    selective_disclosure_public_inputs,
)

_CONSTRAINT_CHECKS = {
    KYC_CIRCUIT: check_kyc_constraints,
    COMMUNITY_KYC_V2_CIRCUIT: check_kyc_constraints,
    JURISDICTION_V1_CIRCUIT: check_jurisdiction_constraints,
    REMAINING_CIRCUIT: check_profile_constraints,
    REBIND_CIRCUIT: check_rebind_constraints,
    # The binding-v2 packages retain their predecessor public ABIs but add an
    # exact private proof-type domain, giving each successor a distinct ACIR/VK.
    REBIND_BINDING_V2_CIRCUIT: check_rebind_binding_v2_constraints,
    # v2 (presentation-profile) circuits — additive.
    KYC_V2_CIRCUIT: check_kyc_constraints_v2,
    KYC_V3_CIRCUIT: check_kyc_constraints_v2,
    JURISDICTION_V2_CIRCUIT: check_jurisdiction_constraints_v2,
    REMAINING_V2_CIRCUIT: check_profile_constraints_v2,
    JURISDICTION_V3_CIRCUIT: check_jurisdiction_constraints_v3,
    REMAINING_V3_CIRCUIT: check_profile_constraints_v3,
    JURISDICTION_V4_CIRCUIT: check_jurisdiction_constraints_v4,
    JURISDICTION_V5_CIRCUIT: check_jurisdiction_constraints_v4,
    JURISDICTION_V6_CIRCUIT: check_jurisdiction_constraints_v6,
    REMAINING_V4_CIRCUIT: check_profile_constraints_v4,
    REMAINING_V5_CIRCUIT: check_profile_constraints_v5,
    REMAINING_V6_CIRCUIT: check_profile_constraints_v6,
    REMAINING_V7_CIRCUIT: check_profile_constraints_v7,
    REMAINING_V8_CIRCUIT: check_profile_constraints_v8,
    REMAINING_V9_CIRCUIT: check_profile_constraints_v8,
    REMAINING_V10_CIRCUIT: check_profile_constraints_v8,
    REMAINING_V11_CIRCUIT: check_profile_constraints_v11,
    REBIND_V2_CIRCUIT: check_rebind_constraints_v2,
    REBIND_V2_BINDING_V2_CIRCUIT: check_rebind_v2_binding_v2_constraints,
    # Issuer-authenticated successors (spec section 7.4).
    REBIND_AUTH_CIRCUIT: check_rebind_auth_constraints,
    REBIND_AUTH_V2_CIRCUIT: check_rebind_auth_v2_constraints,
    REBIND_AUTH_V3_CIRCUIT: check_rebind_auth_v2_constraints,
    DISCLOSURE_CIRCUIT: check_selective_disclosure_constraints,
    DISCLOSURE_V2_CIRCUIT: check_selective_disclosure_constraints,
    DISCLOSURE_V3_CIRCUIT: partial(check_selective_disclosure_constraints, layout_bound=True),
}
_PUBLIC_INPUT_EXTRACTORS = {
    KYC_CIRCUIT: kyc_public_inputs,
    COMMUNITY_KYC_V2_CIRCUIT: kyc_public_inputs,
    JURISDICTION_V1_CIRCUIT: jurisdiction_public_inputs,
    REMAINING_CIRCUIT: profile_public_inputs,
    REBIND_CIRCUIT: rebind_public_inputs,
    REBIND_BINDING_V2_CIRCUIT: rebind_public_inputs,
    # v2 (presentation-profile) circuits — additive.
    KYC_V2_CIRCUIT: kyc_public_inputs_v2,
    KYC_V3_CIRCUIT: kyc_public_inputs_v2,
    JURISDICTION_V2_CIRCUIT: jurisdiction_public_inputs_v2,
    REMAINING_V2_CIRCUIT: profile_public_inputs_v2,
    JURISDICTION_V3_CIRCUIT: jurisdiction_public_inputs,
    REMAINING_V3_CIRCUIT: profile_public_inputs,
    JURISDICTION_V4_CIRCUIT: jurisdiction_public_inputs_v2,
    JURISDICTION_V5_CIRCUIT: jurisdiction_public_inputs_v2,
    JURISDICTION_V6_CIRCUIT: jurisdiction_public_inputs_v6,
    REMAINING_V4_CIRCUIT: profile_public_inputs_v2,
    REMAINING_V5_CIRCUIT: profile_public_inputs,
    REMAINING_V6_CIRCUIT: profile_public_inputs_v2,
    REMAINING_V7_CIRCUIT: profile_public_inputs,
    REMAINING_V8_CIRCUIT: profile_public_inputs_v2,
    REMAINING_V9_CIRCUIT: profile_public_inputs_v2,
    REMAINING_V10_CIRCUIT: profile_public_inputs_v2,
    REMAINING_V11_CIRCUIT: profile_public_inputs_v11,
    REBIND_V2_CIRCUIT: rebind_public_inputs_v2,
    REBIND_V2_BINDING_V2_CIRCUIT: rebind_public_inputs_v2,
    REBIND_AUTH_CIRCUIT: rebind_auth_public_inputs,
    REBIND_AUTH_V2_CIRCUIT: rebind_auth_public_inputs_v2,
    REBIND_AUTH_V3_CIRCUIT: rebind_auth_public_inputs_v2,
    DISCLOSURE_CIRCUIT: selective_disclosure_public_inputs,
    DISCLOSURE_V2_CIRCUIT: selective_disclosure_public_inputs,
    DISCLOSURE_V3_CIRCUIT: partial(selective_disclosure_public_inputs, layout_bound=True),
}


def _check_successor_constraints(witness, *, predecessor_check):
    credential_id = witness.get("credential_id")
    if type(credential_id) is not int or not 0 < credential_id < FIELD_MODULUS:
        raise ConstraintViolationError("credential ID must be nonzero and canonical")
    predecessor_check(witness)


for _successor, _predecessor in NONZERO_CREDENTIAL_CIRCUIT_PREDECESSORS.items():
    _CONSTRAINT_CHECKS[_successor] = partial(
        _check_successor_constraints, predecessor_check=_CONSTRAINT_CHECKS[_predecessor]
    )
    _PUBLIC_INPUT_EXTRACTORS[_successor] = _PUBLIC_INPUT_EXTRACTORS[_predecessor]


class ProofBackend:
    """Backend interface: prove a circuit statement from a full witness."""

    name = "abstract"
    is_production = False

    def prove(self, circuit: str, witness: dict) -> str:
        """Return the proof string for the envelope. MUST fail closed."""
        raise NotImplementedError

    def public_inputs(self, circuit: str, witness: dict) -> dict:
        extractor = _PUBLIC_INPUT_EXTRACTORS.get(circuit)
        if extractor is None:
            raise BackendUnavailableError(f"no public-input extractor for circuit '{circuit}'")
        return extractor(witness)




class StubBackend(ProofBackend):
    """Deterministic NON-PRODUCTION backend for tests.

    Emits no real ZK proof. Constraint checks run in Python first, so the
    stub fails closed exactly where the circuit would.
    """

    name = "stub"
    is_production = False

    def prove(self, circuit: str, witness: dict) -> str:
        check = _CONSTRAINT_CHECKS.get(circuit)
        if check is None:
            raise BackendUnavailableError(f"stub backend has no constraint mirror for '{circuit}'")
        check(witness)
        return stub_proof_payload(circuit, self.public_inputs(circuit, witness))


def _toml_value(value) -> str:
    if isinstance(value, bool):
        return f'"{1 if value else 0}"'
    if isinstance(value, int):
        return f'"{value:#x}"' if value > 2**63 else f'"{value}"'
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    raise ValueError(f"unsupported witness value type: {type(value).__name__}")


def witness_to_prover_toml(witness: dict) -> str:
    lines = []
    for key, value in witness.items():
        lines.append(f"{key} = {_toml_value(value)}")
    return "\n".join(lines) + "\n"


class NargoBackend(ProofBackend):
    """Real proving in a private, disposable copy of the Noir workspace."""

    name = "nargo"
    is_production = True

    def __init__(self, repo_root, nargo: str = "nargo", bb: str = "bb"):
        self._root = pathlib.Path(repo_root)
        self._nargo = nargo
        self._bb = bb

    @classmethod
    def available(cls, nargo: str = "nargo", bb: str = "bb") -> bool:
        return shutil.which(nargo) is not None and shutil.which(bb) is not None

    def _run(self, command, cwd) -> None:
        self._check_private_paths(pathlib.Path(cwd).parent)
        result = subprocess.run(
            command, cwd=cwd, capture_output=True, text=True, umask=0o077,
        )
        if result.returncode != 0:
            # Compiler diagnostics can contain witness values. Do not expose them.
            raise BackendUnavailableError(
                f"proving tool failed (exit {result.returncode})"
            )
        self._check_private_paths(pathlib.Path(cwd).parent)

    @staticmethod
    def _check_private_paths(root: pathlib.Path) -> None:
        for path in (root, *root.rglob("*")):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise BackendUnavailableError("unsafe proving workspace path")

    @staticmethod
    def _create_private_file(path: pathlib.Path, content: bytes = b"") -> None:
        if not hasattr(os, "O_NOFOLLOW"):
            raise BackendUnavailableError("secure proving files are unsupported")
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)

    @staticmethod
    def _read_private_file(path: pathlib.Path) -> bytes:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise BackendUnavailableError("unsafe proving output")
            return source.read()

    def prove(self, circuit: str, witness: dict) -> str:
        # Run the Python constraint mirror first when we have one: a witness
        # the circuit rejects should produce a structured error, not a raw
        # toolchain failure.
        check = _CONSTRAINT_CHECKS.get(circuit)
        if check is not None:
            check(witness)

        if (
            not isinstance(circuit, str) or not circuit
            or circuit in (".", "..") or "/" in circuit or "\\" in circuit
        ):
            raise BackendUnavailableError("invalid circuit package name")
        source_noir = self._root / "noir"
        package_dir = source_noir / circuit
        if not package_dir.is_dir():
            raise BackendUnavailableError(f"circuit package not found: {package_dir}")

        temporary_root = pathlib.Path(tempfile.gettempdir()).resolve()
        repository_root = self._root.resolve()
        if temporary_root == repository_root or repository_root in temporary_root.parents:
            raise BackendUnavailableError("temporary proving directory must be outside repository")

        with tempfile.TemporaryDirectory(prefix="zkc-prove-", dir=temporary_root) as scratch:
            scratch_path = pathlib.Path(scratch)
            try:
                # Inspect excluded outputs too: a planted source-tree symlink
                # must fail closed rather than receive a holder's witness.
                self._check_private_paths(source_noir)
                noir_dir = scratch_path / "noir"
                shutil.copytree(
                    source_noir, noir_dir, symlinks=True,
                    ignore=shutil.ignore_patterns(
                        "target", "Prover*.toml", "Verifier*.toml", ".DS_Store",
                    ),
                )
                self._check_private_paths(scratch_path)
                for directory in (scratch_path, *noir_dir.rglob("*")):
                    if directory.is_dir():
                        directory.chmod(0o700)
                noir_dir.chmod(0o700)
                target = noir_dir / "target"
                target.mkdir(mode=0o700)
                prover_name = "ProverZkcHolderSdk"
                prover_path = noir_dir / circuit / f"{prover_name}.toml"
                self._create_private_file(
                    prover_path, witness_to_prover_toml(witness).encode("utf-8"),
                )
                witness_name = f"zkc_holder_{circuit}"
                witness_file = target / f"{witness_name}.gz"
                self._create_private_file(witness_file)
                self._run(
                    [
                        self._nargo, "execute",
                        "--package", circuit,
                        "--prover-name", prover_name,
                        witness_name,
                    ],
                    cwd=noir_dir,
                )
                artifact = target / f"{circuit}.json"
                self._create_private_file(scratch_path / "vk")
                self._run(
                    [
                        self._bb, "write_vk",
                        "-b", str(artifact),
                        "-o", str(scratch_path),
                    ],
                    cwd=noir_dir,
                )
                self._create_private_file(scratch_path / "proof")
                self._run(
                    [
                        self._bb, "prove",
                        "-b", str(artifact),
                        "-w", str(witness_file),
                        "-k", str(scratch_path / "vk"),
                        "-o", str(scratch_path),
                    ],
                    cwd=noir_dir,
                )
                proof_bytes = self._read_private_file(scratch_path / "proof")
                if not proof_bytes:
                    raise BackendUnavailableError("proving tool produced no proof")
                return "0x" + proof_bytes.hex()
            except OSError:
                raise BackendUnavailableError("could not use private proving workspace") from None

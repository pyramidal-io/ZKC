"""Holder-authorized audit disclosure (zkc:audit-bundle:v1).

Regulated workflows sometimes need compliance evidence shared with an
auditor. The privacy boundary must survive that: the platform and the
auditor receive ONLY what the holder explicitly authorized — selected proof
envelopes plus the context needed to re-verify them — and never credential
secrets or broad payment/activity history.

An :class:`AuditExporter` (holder-side) builds an **AuditBundle**:

- the selected ``zkc:proof:v1`` envelopes, each with its verification
  context (request parameters, proof context metadata, accumulator epochs,
  the verifier's published policy snapshot, registry refs);
- a **holder-signed authorization record** scoping the disclosure: which
  proofs (by content hash), for whom (auditor key id), a validity window,
  and a purpose string;
- a tamper-evident **hash chain** over the members; the chain head is the
  bundle's content address (``bundleHash``).

Schema-level exclusion: bundles MUST NOT contain credentials, seeds,
binding keys, witnesses, or payment/activity history. Export and auditor
validation both run a recursive forbidden-key scan and fail closed
(:class:`~zkc_holder.errors.ForbiddenMaterialError`).

Authorization signing key: one stable key per auditor, derived from the
exact holder master-seed bytes under dedicated domain tags
(:func:`zkc_crypto.holder_keys.derive_audit_authorization_key`) — NOT the
credential binding key, which never signs anything and never leaves the
client. Two auditors see unrelated keys. The key carried in the bundle is
self-asserted: an auditor MUST pass the holder key it obtained from the holder
out of band (``expected_holder_key``), and a bundle without one never
validates. A verifier or platform holding a holder's envelopes can therefore
not mint a bundle that passes as holder-authorized.

Revocation semantics: an authorization is bounded by its validity window;
there is deliberately NO central revocation service for authorizations
(a revocation chokepoint would let a platform decide whose audit evidence
stays valid — the same centralization the protocol exists to avoid).
Auditors MUST check the window at use time; holders revoke by letting the
window lapse and, where earlier invalidation is required, by scoping
windows narrowly. See docs/zkc_audit_disclosure.md.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from zkc_crypto.ecdsa_secp256k1 import sign, verify
from zkc_crypto.holder_keys import (
    derive_audit_authorization_key,
    derive_audit_authorization_root,
    holder_key_bytes,
    holder_key_matches,
    holder_public_key,
)

from .errors import ForbiddenMaterialError, HolderError
from .rebind_secret import is_secret_key

__all__ = [
    "AUDIT_BUNDLE_VERSION",
    "FORBIDDEN_BUNDLE_KEYS",
    "AuditExporter",
    "AuditBundleError",
    "AuditCheckResult",
    "scan_forbidden_material",
    "verify_audit_bundle",
    "reverify_bundle_proofs",
    "derive_authorization_key",
]

AUDIT_BUNDLE_VERSION = "zkc:audit-bundle:v1"
ZERO_HASH = "0x" + "00" * 32

# Keys that may NEVER appear anywhere in an audit bundle: credential
# material, holder secrets, and broad payment/activity history. The bundle
# is proofs + re-verification context, nothing else.
FORBIDDEN_BUNDLE_KEYS = frozenset(
    {
        "claims",
        "credential",
        "credentials",
        "seed",
        "masterseed",
        "master_seed",
        "bindingkey",
        "binding_key",
        "privatekey",
        "private_key",
        "witness",
        "witnesses",
        "siblings",
        "passphrase",
        "paymenthistory",
        "payment_history",
        "transactions",
        "transactionhistory",
        "transaction_history",
        "activityhistory",
        "activity_history",
        "balances",
    }
)


class AuditBundleError(HolderError):
    code = "AUDIT_BUNDLE_ERROR"


def _canonical(content) -> bytes:
    return json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_hex(payload: bytes) -> str:
    return "0x" + hashlib.sha256(payload).hexdigest()


def _chain(previous_hex: str, content_hash_hex: str) -> str:
    return _sha256_hex(
        bytes.fromhex(previous_hex.removeprefix("0x"))
        + bytes.fromhex(content_hash_hex.removeprefix("0x"))
    )


def scan_forbidden_material(node, path: str = "") -> None:
    """Recursive schema-level exclusion scan; fail closed on any hit."""
    if isinstance(node, dict):
        for key, value in node.items():
            # Exact names, plus any spelling of holder secret material: the
            # SDK's own rebind fields (newMasterSeed, newCredentialBindingKey)
            # would otherwise slip past an exact-name list.
            if str(key).lower() in FORBIDDEN_BUNDLE_KEYS or is_secret_key(key):
                raise ForbiddenMaterialError(
                    f"audit bundle must not contain {path}{key} "
                    "(credential secrets and payment/activity history are excluded by schema)"
                )
            scan_forbidden_material(value, f"{path}{key}.")
    elif isinstance(node, (list, tuple)):
        for index, item in enumerate(node):
            scan_forbidden_material(item, f"{path}{index}.")


def _require_auditor_key_id(auditor_key_id) -> None:
    if not isinstance(auditor_key_id, str) or not auditor_key_id:
        raise AuditBundleError("auditor key id must be a non-empty string")
    try:
        auditor_key_id.encode("utf-8")
    except UnicodeEncodeError:
        raise AuditBundleError("auditor key id must be valid UTF-8 text") from None


def derive_authorization_key(master_seed: int | bytes | str, auditor_key_id: str) -> int:
    """Per-auditor audit-authorization ECDSA key from the holder master seed.

    ``derive_audit_authorization_key(derive_audit_authorization_root(seed),
    auditor_key_id)``: domain-separated from every other derivation, stable
    for one auditor, unrelated across auditors. The credential binding key is
    never used for signing and never leaves the client."""
    _require_auditor_key_id(auditor_key_id)
    return derive_audit_authorization_key(
        derive_audit_authorization_root(master_seed), auditor_key_id
    )


def _authorization_digest(authorization: dict, bundle_hash: str) -> bytes:
    unsigned = {key: value for key, value in authorization.items() if key != "signature"}
    unsigned["bundleHash"] = bundle_hash
    return hashlib.sha256(_canonical(unsigned)).digest()


class AuditExporter:
    """Holder-side audit bundle construction.

    Constructed from the holder master seed (same trust domain as
    HolderClient). The seed itself is not retained: the exporter keeps only
    the 64-byte audit-authorization root, which yields nothing but per-auditor
    authorization keys."""

    __slots__ = ("_authorization_root",)

    def __init__(self, master_seed: int | bytes | str):
        object.__setattr__(
            self, "_authorization_root", derive_audit_authorization_root(master_seed)
        )

    # The root mints authorization keys for every auditor: it stays in this
    # process. No pickling, no copies that could leak it, no revealing repr.
    def __setattr__(self, name, value):
        raise AttributeError("AuditExporter is immutable")

    def __delattr__(self, name):
        raise AttributeError("AuditExporter is immutable")

    def __getstate__(self):
        raise TypeError("AuditExporter is holder-local and cannot be serialized")

    def __repr__(self) -> str:
        return "AuditExporter(<redacted>)"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("AuditExporter is holder-local and cannot be serialized")

    def __reduce_ex__(self, protocol):
        raise TypeError("AuditExporter is holder-local and cannot be serialized")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self

    def _authorization_key(self, auditor_key_id: str) -> int:
        # Validate before the root is passed on, so no failing frame (and no
        # chained traceback with captured locals) ever holds the root.
        _require_auditor_key_id(auditor_key_id)
        return derive_audit_authorization_key(self._authorization_root, auditor_key_id)

    def authorization_public_key(self, auditor_key_id: str) -> dict:
        """The holder key one auditor must anchor (``expected_holder_key``).

        The holder hands it to that auditor out of band, once per auditor
        relationship; the auditor never takes it from a bundle."""
        return holder_public_key(self._authorization_key(auditor_key_id))

    def export(
        self,
        proofs: list,
        *,
        auditor_key_id: str,
        valid_from: int,
        valid_until: int,
        purpose: str,
    ) -> dict:
        """Build a holder-authorized, content-addressed audit bundle.

        `proofs` is a list of {"envelope": <zkc:proof:v1>, "verification":
        {proofTypes, parameters, context, accumulatorStates, policySnapshot,
        registryRefs}} entries — exactly what an auditor needs to re-verify,
        and nothing more.
        """
        if not proofs:
            raise AuditBundleError("an audit bundle must contain at least one proof")
        if not isinstance(auditor_key_id, str) or not auditor_key_id:
            raise AuditBundleError("an audit bundle must name its auditor (auditor_key_id)")
        if not (0 < valid_from < valid_until):
            raise AuditBundleError("authorization validity window is malformed")
        if not purpose:
            raise AuditBundleError("an audit authorization must state its purpose")

        members = []
        chain = ZERO_HASH
        for index, entry in enumerate(proofs):
            content = {
                "envelope": entry["envelope"],
                "verification": dict(entry.get("verification", {})),
            }
            # Schema-level exclusion BEFORE anything is hashed or signed.
            scan_forbidden_material(content, f"members.{index}.")
            content_hash = _sha256_hex(_canonical(content))
            chain = _chain(chain, content_hash)
            members.append(
                {
                    "index": index,
                    "type": "proof-record",
                    "content": content,
                    "contentHash": content_hash,
                    "chainHash": chain,
                }
            )
        bundle_hash = chain

        authorization_key = self._authorization_key(auditor_key_id)
        authorization = {
            "holderAuthorizationKey": holder_public_key(authorization_key),
            "auditorKeyId": auditor_key_id,
            "proofRefs": [member["contentHash"] for member in members],
            "validFrom": int(valid_from),
            "validUntil": int(valid_until),
            "purpose": purpose,
        }
        digest = _authorization_digest(authorization, bundle_hash)
        authorization["signature"] = "0x" + sign(digest, authorization_key).hex()

        bundle = {
            "version": AUDIT_BUNDLE_VERSION,
            "members": members,
            "authorization": authorization,
            "bundleHash": bundle_hash,
        }
        # Belt and braces: the assembled bundle as a whole must also be clean.
        scan_forbidden_material(bundle)
        return bundle


# ---------------------------------------------------------------------------
# Auditor side
# ---------------------------------------------------------------------------

CHECK_MALFORMED = "MALFORMED_BUNDLE"
CHECK_TAMPERED = "TAMPERED"
CHECK_FORBIDDEN = "FORBIDDEN_CONTENT"
CHECK_BAD_SIGNATURE = "BAD_AUTHORIZATION_SIGNATURE"
CHECK_NOT_YET_VALID = "AUTHORIZATION_NOT_YET_VALID"
CHECK_EXPIRED = "AUTHORIZATION_EXPIRED"
CHECK_AUDITOR_MISMATCH = "AUDITOR_MISMATCH"
CHECK_PROOF_REFS = "PROOF_REFS_MISMATCH"
CHECK_REVERIFICATION = "REVERIFICATION_FAILED"
CHECK_HOLDER_KEY_UNANCHORED = "HOLDER_KEY_UNANCHORED"
CHECK_HOLDER_KEY_MISMATCH = "HOLDER_KEY_MISMATCH"


@dataclass
class AuditCheckResult:
    """Structured auditor-side validation result (fail closed)."""

    errors: list = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.errors

    def add(self, code: str, message: str) -> None:
        self.errors.append({"code": code, "message": message})

    def codes(self) -> list:
        return [error["code"] for error in self.errors]


def verify_audit_bundle(
    bundle: dict,
    *,
    now: int,
    expected_holder_key: dict = None,
    expected_auditor_key_id: str = None,
) -> AuditCheckResult:
    """Validate bundle integrity + authorization (no proof re-verification;
    see :func:`reverify_bundle_proofs` for the cryptographic re-check).

    ``expected_holder_key`` is the holder's per-auditor authorization key
    (``{"x", "y"}``) that the auditor obtained from the holder out of band.
    The key carried in the bundle is never a trust anchor: without an
    expected key the result fails with ``HOLDER_KEY_UNANCHORED``, and a
    bundle signed under any other key fails with ``HOLDER_KEY_MISMATCH``.
    A malformed ``expected_holder_key`` raises ValueError."""
    if expected_holder_key is not None:
        holder_key_bytes(expected_holder_key)
    result = AuditCheckResult()
    if not isinstance(bundle, dict) or bundle.get("version") != AUDIT_BUNDLE_VERSION:
        result.add(CHECK_MALFORMED, "not a zkc:audit-bundle:v1 document")
        return result
    members = bundle.get("members")
    authorization = bundle.get("authorization")
    bundle_hash = bundle.get("bundleHash")
    if not isinstance(members, list) or not members or not isinstance(authorization, dict):
        result.add(CHECK_MALFORMED, "bundle lacks members or authorization")
        return result

    # Forbidden material: an auditor must refuse over-disclosed bundles.
    try:
        scan_forbidden_material(bundle)
    except ForbiddenMaterialError as exc:
        result.add(CHECK_FORBIDDEN, exc.message)

    # Hash-chain integrity (content-addressed, tamper-evident).
    chain = ZERO_HASH
    recomputed_refs = []
    try:
        for index, member in enumerate(members):
            content_hash = _sha256_hex(_canonical(member["content"]))
            if content_hash != member.get("contentHash"):
                result.add(CHECK_TAMPERED, f"member {index} content does not match its hash")
            chain = _chain(chain, content_hash)
            if chain != member.get("chainHash"):
                result.add(CHECK_TAMPERED, f"member {index} breaks the bundle hash chain")
            recomputed_refs.append(content_hash)
        if chain != bundle_hash:
            result.add(CHECK_TAMPERED, "bundleHash does not match the recomputed chain head")
    except (KeyError, TypeError, ValueError) as exc:
        result.add(CHECK_MALFORMED, f"unparseable bundle member: {exc}")
        return result

    # Authorization scope: the signed proof refs must be exactly the members.
    if list(authorization.get("proofRefs", [])) != recomputed_refs:
        result.add(CHECK_PROOF_REFS, "authorization proofRefs do not match bundle members")

    # Validity window (auditor MUST check at use time; no central revocation).
    try:
        valid_from = int(authorization["validFrom"])
        valid_until = int(authorization["validUntil"])
    except (KeyError, TypeError, ValueError):
        result.add(CHECK_MALFORMED, "authorization validity window is malformed")
        return result
    if now < valid_from:
        result.add(CHECK_NOT_YET_VALID, "authorization is not yet valid")
    if now > valid_until:
        result.add(CHECK_EXPIRED, "authorization validity window has lapsed")

    # Auditor binding.
    if (
        expected_auditor_key_id is not None
        and authorization.get("auditorKeyId") != expected_auditor_key_id
    ):
        result.add(CHECK_AUDITOR_MISMATCH, "bundle is authorized for a different auditor")

    # Holder authorization signature over (authorization − signature, bundleHash).
    try:
        key = authorization["holderAuthorizationKey"]
        key_x = bytes.fromhex(key["x"].removeprefix("0x"))
        key_y = bytes.fromhex(key["y"].removeprefix("0x"))
        signature = bytes.fromhex(authorization["signature"].removeprefix("0x"))
        digest = _authorization_digest(authorization, bundle_hash)
        if not verify(key_x, key_y, signature, digest):
            result.add(CHECK_BAD_SIGNATURE, "holder authorization signature is invalid")
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        result.add(CHECK_MALFORMED, f"unparseable authorization: {exc}")

    # Holder anchoring: the carried key is self-asserted; only the auditor's
    # own expected key ties the authorization to the holder.
    if expected_holder_key is None:
        result.add(
            CHECK_HOLDER_KEY_UNANCHORED,
            "no expected holder key: the key carried in the bundle is self-asserted",
        )
    elif not holder_key_matches(authorization.get("holderAuthorizationKey"), expected_holder_key):
        result.add(
            CHECK_HOLDER_KEY_MISMATCH,
            "bundle is not signed by the expected holder authorization key",
        )
    return result


def reverify_bundle_proofs(
    bundle: dict, verifier_factory, issuer_roots: dict = None
) -> AuditCheckResult:
    """Re-verify contained proofs against independently known historical roots.

    `verifier_factory(policy_snapshot) -> ZKCVerifier` lets the auditor
    decide which trust policy to verify under — typically built from the
    bundled policy snapshot via ``zkc_registry.to_verifier_trust_policy``,
    but the auditor may substitute its own.

    ``issuer_roots`` maps ``issuer_id -> {epoch: root}`` that the AUDITOR
    obtained from an authenticated source (e.g. the issuer's signed
    announcement history). Revocation is checked against those roots only:
    the bundle is holder-authored, so any roots it carries are holder
    assertions, and a revoked holder could bundle its own self-made root.
    The bundle supplies each member's claimed original ``currentEpoch``.
    A valid result establishes cryptographic consistency with the auditor's
    historical roots, not that the credential was unrevoked when the proof
    was created or today: those claims additionally need an independently
    authenticated epoch view. Without ``issuer_roots`` every member fails
    re-verification; unchecked-root policy warnings also fail this check.
    """
    from zkc_crypto import ProofContext
    from zkc_verifier import IssuerAccumulatorState, VerificationRequest
    from zkc_verifier.errors import VerificationWarningCode

    result = AuditCheckResult()
    for index, member in enumerate(bundle.get("members", [])):
        content = member.get("content", {})
        envelope = content.get("envelope")
        verification = content.get("verification", {})
        if issuer_roots is None:
            result.add(
                CHECK_REVERIFICATION,
                f"member {index} cannot be re-verified without auditor-supplied issuer "
                "accumulator roots (bundle-carried roots are holder assertions)",
            )
            continue
        try:
            context = ProofContext.from_metadata(verification["context"])
            accumulator_states = {}
            for issuer_id, state in verification.get("accumulatorStates", {}).items():
                bundled = IssuerAccumulatorState.from_dict(state)
                # currentEpoch is the bundle's claimed original view;
                # the independently known roots come from the auditor only.
                roots = dict(issuer_roots.get(issuer_id, {}))
                if not roots:
                    raise ValueError(f"no auditor-supplied roots for issuer {issuer_id}")
                accumulator_states[issuer_id] = IssuerAccumulatorState(
                    current_epoch=bundled.current_epoch,
                    roots=roots,
                )
            request = VerificationRequest(
                proof_types=list(verification["proofTypes"]),
                parameters=dict(verification["parameters"]),
                context=context,
                max_proof_age=int(verification.get("maxProofAge", 3600)),
                accumulator_states=accumulator_states,
            )
            verifier = verifier_factory(verification.get("policySnapshot"))
            verification_result = verifier.verify(envelope, request)
        except Exception as exc:  # fail closed on anything unexpected
            result.add(
                CHECK_REVERIFICATION,
                f"member {index} could not be re-verified: {type(exc).__name__}",
            )
            continue
        unchecked_root = VerificationWarningCode.UNCHECKED_ACCUMULATOR_ROOT
        codes = verification_result.codes()
        if unchecked_root in verification_result.warning_codes():
            codes.append(unchecked_root)
        if not verification_result.valid or unchecked_root in codes:
            result.add(
                CHECK_REVERIFICATION,
                f"member {index} failed re-verification: "
                f"{','.join(codes)}",
            )
    return result

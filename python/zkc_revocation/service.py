"""Issuer-side revocation accumulator service.

Extends ``zkc_issuer.IssuerAccumulator`` (the Poseidon2 Merkle active set)
with per-epoch history, signed epoch announcements, and a serializable
witness-update protocol. The service is in-process — the reference stack
also has an optional HTTP transport — but every request/response is a plain
JSON-able dict with a versioned ``type`` field, so an HTTP wrapper is a thin
``POST body -> handle_request -> response`` translation.

Wire shapes
-----------
Witness update request (``zkc:witness-update-request:v1``)::

    {"type": "zkc:witness-update-request:v1",
     "accumulatorId": "<issuer accumulator id>",
     "credentialId": "0x<64 hex>",
     "fromEpoch": <int, optional>}

Witness update response (``zkc:witness-update-response:v1``)::

    {"type": "zkc:witness-update-response:v1",
     "accumulatorId": "...", "epoch": <int>, "root": "0x…",
     "announcement": <signed epoch announcement>,
     "liveness": <signed zkc:epoch-liveness:v1 for that head, optional>,
     "mode": "full" | "delta",
     # full mode:
     "witness": {"pathIndex": int, "siblings": ["0x…", …32],
                 "accumulatorRoot": "0x…", "accumulatorEpoch": int},
     # delta mode (when fromEpoch is known to the service):
     "witnessDelta": {"pathIndex": int, "fromEpoch": int,
                      "changedSiblings": [[level, "0x…"], …]}}

Signed epoch announcement (``zkc:epoch-announcement:v3``)::

    {"version": "zkc:epoch-announcement:v3",
     "accumulatorId": "...", "root": "0x…", "epoch": <int>,
     "announcedAt": <unix seconds>, "maxEpochLag": <int>,
     "signingKeyId": "<pre-trusted issuer key id>",
     "previousAnnouncementHash": "0x<sha256>",  # chain link (zero hash at genesis)
     "signature": "0x<r||s>"}   # issuer ECDSA over SHA-256 of the
                                  # normative deterministic binary transcript,
                                  # reduced into the BN254 field

Announcements are CHAINED: each one commits to the sha256 hash of the
previous announcement (``announcement_hash``), and the link is covered by
the issuer signature. Holders and verifiers can therefore detect epoch
GAPS and forks (see ``zkc_revocation.chain.AnnouncementChain``) — a
revocation service cannot silently show different histories to different
parties without producing two signed, conflicting chains.

Errors are ``zkc_issuer.AdapterError`` with the protocol's closed code set
(``STALE_ACCUMULATOR_WITNESS`` for revoked/unknown credentials,
``REVOCATION_METADATA_UNAVAILABLE`` for unknown accumulators/epochs).

Signing-key rotation
--------------------
The service records every announcement signer as ``{"keyId", "publicKey",
"fromEpoch"}`` (public material only). ``rotate_signing_key`` appends a
successor that signs from the next epoch on; nothing is re-signed and the
chain continues unbroken. Verifiers must pre-pin the successor key id.

Signing-key validity windows
----------------------------
An announcement signer must expose ``is_valid_at`` (``IssuerSigningKey``
does). The service reads its clock once per epoch, and refuses to sign with
``EXPIRED_ISSUER_KEY`` unless the active key is valid at that
``announcedAt``. The check runs before the accumulator, epoch, snapshots,
announcements or durable store change, so an issuance, revocation or renewal
under an expired key changes nothing. Construction refuses an expired genesis
signer and rotation refuses a successor that is not valid now. Recovery
still opens with an expired active key, so its history stays readable and
the operator can rotate to a valid successor.

Delta snapshot window
---------------------
Per-epoch leaf snapshots exist only to serve deltas. The service keeps the
newest ``DELTA_SNAPSHOT_WINDOW`` epochs before the current one and answers an
older ``fromEpoch`` with a full refresh.

Head liveness (``zkc:epoch-liveness:v1``)
-----------------------------------------
The epoch advances only on a mutation, so a quiet issuer's head keeps its
old ``announcedAt``. A liveness statement lets consumers keep that head
fresh without a new epoch::

    {"version": "zkc:epoch-liveness:v1",
     "accumulatorId": "...", "epoch": <int>,
     "headHash": "0x<sha256>",   # announcement_hash of the head it names
     "issuedAt": <unix seconds>,
     "signingKeyId": "<pre-trusted issuer key id>",
     "signature": "0x<r||s>"}    # same signer rules as an announcement

It is signed by the active announcement key over its own domain-separated
transcript (``liveness_transcript``). It never changes the epoch, the root,
the announcement history or the chain, and it is never fork evidence.
``current_liveness`` re-signs it on the ``liveness_interval`` cadence
(default ``DEFAULT_LIVENESS_INTERVAL``); ``metadata`` publishes it as
``currentLiveness`` and the update responses carry it as ``liveness``.
"""

from __future__ import annotations

import copy
import hashlib
import re
import time

from zkc_crypto import (
    SparseMerkleAccumulator,
    canonical_hex_to_field,
    digest_to_message_bytes,
    field_to_hex,
    hex_to_field,
)
from zkc_crypto.field import FIELD_MODULUS
from zkc_crypto.ecdsa_secp256k1 import verify as ecdsa_verify
from zkc_issuer.accumulator import MAX_EPOCH_LAG, IssuerAccumulator, _locked
from zkc_issuer.errors import AdapterError
from zkc_issuer.keys import IssuerSigningKey

__all__ = [
    "ANNOUNCEMENT_VERSION",
    "DEFAULT_LIVENESS_INTERVAL",
    "DELTA_SNAPSHOT_WINDOW",
    "EPOCH_DELTA_REQUEST",
    "EPOCH_DELTA_RESPONSE",
    "GENESIS_ANNOUNCEMENT_HASH",
    "LIVENESS_VERSION",
    "WITNESS_UPDATE_REQUEST",
    "WITNESS_UPDATE_RESPONSE",
    "RevocationAccumulatorService",
    "announcement_hash",
    "announcement_transcript",
    "apply_witness_delta",
    "complete_announcement_bytes",
    "compute_announcement_digest",
    "compute_liveness_digest",
    "liveness_transcript",
    "verify_epoch_announcement",
    "verify_epoch_liveness",
]

ANNOUNCEMENT_VERSION = "zkc:epoch-announcement:v3"
LIVENESS_VERSION = "zkc:epoch-liveness:v1"
MAX_LIVENESS_TRANSCRIPT_BYTES = 0xFFFF
# Re-sign cadence of the head liveness statement. With the consumers'
# default max_announcement_age (3600 s), metadataCacheSeconds (300 s) and
# max_clock_skew (300 s), a consumer that re-polls at least every 2100 s keeps
# a quiet issuer fresh (specification section 2.4.2).
DEFAULT_LIVENESS_INTERVAL = 900
EPOCH_DELTA_REQUEST = "zkc:epoch-delta-request:v1"
EPOCH_DELTA_RESPONSE = "zkc:epoch-delta-response:v1"
GENESIS_ANNOUNCEMENT_HASH = "0x" + "00" * 32
# Byte bound of the v3 signing transcript T: the complete record encodes
# len(T) as u16be. With the fixed fields (143 bytes), accumulatorId and
# signingKeyId together may hold at most 65392 UTF-8 bytes.
MAX_ANNOUNCEMENT_TRANSCRIPT_BYTES = 0xFFFF
WITNESS_UPDATE_REQUEST = "zkc:witness-update-request:v1"
WITNESS_UPDATE_RESPONSE = "zkc:witness-update-response:v1"

# Delta responses are a bandwidth optimization: a ``fromEpoch`` without a
# retained snapshot gets a full refresh. The window equals the default
# announcement backfill bound of the delta consumers (``max_backfill=32`` in
# VerifierAccumulatorCache and PrivateWitnessProvider) plus the epoch the
# client already holds: a client further behind must backfill more than 32
# announcements and is refused before it can apply a delta. The window also
# exceeds MAX_EPOCH_LAG, so every witness that can still prove gets a delta.
DELTA_SNAPSHOT_WINDOW = 33

_SIGNER_FIELDS = frozenset({"keyId", "publicKey", "fromEpoch"})

_MUTATIONS = {
    "register": IssuerAccumulator.register,
    "revoke": IssuerAccumulator.revoke,
    "replace": IssuerAccumulator.replace,
}

_ANNOUNCEMENT_FIELDS = frozenset(
    {
        "version",
        "accumulatorId",
        "root",
        "epoch",
        "announcedAt",
        "maxEpochLag",
        "signingKeyId",
        "previousAnnouncementHash",
        "signature",
    }
)
_LOWER_HEX = re.compile(r"0x[0-9a-f]+")
_TRANSCRIPT_DOMAIN = b"ZKC-EPOCH-ANNOUNCEMENT\x00\x03"
_COMPLETE_DOMAIN = b"ZKC-EPOCH-ANNOUNCEMENT-COMPLETE\x00\x03"
_LIVENESS_FIELDS = frozenset(
    {
        "version",
        "accumulatorId",
        "epoch",
        "headHash",
        "issuedAt",
        "signingKeyId",
        "signature",
    }
)
_LIVENESS_DOMAIN = b"ZKC-EPOCH-LIVENESS\x00\x01"


def _text(value, name: str) -> bytes:
    if type(value) is not str or not value:
        raise ValueError(f"{name} must be a non-empty string")
    encoded = value.encode("utf-8")
    if len(encoded) > 0xFFFF:
        raise ValueError(f"{name} exceeds the v3 transcript limit")
    return len(encoded).to_bytes(2, "big") + encoded


def _u64(value, name: str, *, nonzero: bool = False) -> bytes:
    minimum = 1 if nonzero else 0
    if type(value) is not int or not minimum <= value < 1 << 64:
        raise ValueError(f"{name} must be an unsigned 64-bit integer")
    return value.to_bytes(8, "big")


def _fixed_hex(value, size: int, name: str) -> bytes:
    # Match the whole closed form before decoding: bytes.fromhex skips
    # whitespace, so a 64-character field could otherwise decode to 31 bytes.
    if (
        type(value) is not str
        or len(value) != 2 + size * 2
        or _LOWER_HEX.fullmatch(value) is None
    ):
        raise ValueError(f"{name} must be canonical {size}-byte 0x-prefixed lowercase hex")
    return bytes.fromhex(value[2:])


def announcement_transcript(announcement: dict) -> bytes:
    """Return the exact normative v3 binary signing transcript."""
    if not isinstance(announcement, dict):
        raise ValueError("announcement must be an object")
    if announcement.get("version") != ANNOUNCEMENT_VERSION:
        raise ValueError("unsupported announcement version")
    root = _fixed_hex(announcement.get("root"), 32, "root")
    # Reject a 32-byte integer outside the canonical BN254 field range.
    canonical_hex_to_field(announcement["root"])
    max_epoch_lag = announcement.get("maxEpochLag")
    if type(max_epoch_lag) is not int or not 0 <= max_epoch_lag <= MAX_EPOCH_LAG:
        raise ValueError("maxEpochLag is outside the launch range")
    transcript = b"".join(
        (
            _TRANSCRIPT_DOMAIN,
            _text(announcement.get("version"), "version"),
            _text(announcement.get("accumulatorId"), "accumulatorId"),
            root,
            _u64(announcement.get("epoch"), "epoch"),
            _u64(announcement.get("announcedAt"), "announcedAt", nonzero=True),
            _u64(max_epoch_lag, "maxEpochLag"),
            _text(announcement.get("signingKeyId"), "signingKeyId"),
            _fixed_hex(
                announcement.get("previousAnnouncementHash"),
                32,
                "previousAnnouncementHash",
            ),
        )
    )
    # The complete record frames the transcript with u16be(len(T)), so a
    # longer transcript has no canonical complete encoding; refuse to sign it.
    if len(transcript) > MAX_ANNOUNCEMENT_TRANSCRIPT_BYTES:
        raise ValueError("announcement transcript exceeds 65535 bytes")
    return transcript


def complete_announcement_bytes(announcement: dict) -> bytes:
    """Canonical complete signed announcement committed to by its successor."""
    if set(announcement) != _ANNOUNCEMENT_FIELDS:
        raise ValueError("announcement fields do not match the closed v3 shape")
    transcript = announcement_transcript(announcement)
    if len(transcript) > 0xFFFF:
        raise ValueError("announcement transcript exceeds the complete-record limit")
    signature = _fixed_hex(announcement.get("signature"), 64, "signature")
    return _COMPLETE_DOMAIN + len(transcript).to_bytes(2, "big") + transcript + signature


def _request_from_epoch(request: dict):
    """The optional ``fromEpoch`` of a request: a JSON integer u64 or absent.

    ``int()`` would also take ``true``, ``1.5``, ``"7"`` or raise on
    ``Infinity``; each is a request fault with the protocol's code instead.
    """
    from_epoch = request.get("fromEpoch")
    if from_epoch is not None and (type(from_epoch) is not int or not 0 <= from_epoch < 1 << 64):
        raise AdapterError(
            "REVOCATION_METADATA_UNAVAILABLE", "fromEpoch must be an unsigned 64-bit integer"
        )
    return from_epoch


def announcement_hash(announcement: dict) -> str:
    """Content hash of a (signed) announcement — the value its successor
    commits to in ``previousAnnouncementHash``."""
    return "0x" + hashlib.sha256(complete_announcement_bytes(announcement)).hexdigest()


def compute_announcement_digest(announcement: dict) -> int:
    """SHA-256 of the v3 transcript, reduced into the BN254 field."""
    return int.from_bytes(hashlib.sha256(announcement_transcript(announcement)).digest(), "big") % FIELD_MODULUS


def signer_public_key_hex(signing_key) -> str:
    """0x-prefixed x||y public key of an announcement signer."""
    x, y = signing_key.public_key_coordinates()
    if type(x) is not bytes or type(y) is not bytes or len(x) != 32 or len(y) != 32:
        raise ValueError("announcement signer public key must be two 32-byte coordinates")
    return "0x" + x.hex() + y.hex()


def signer_record(signing_key, from_epoch: int) -> dict:
    """Public record of a signer that signs every epoch from ``from_epoch`` on."""
    key_id = getattr(signing_key, "key_id", None)
    if type(key_id) is not str or not key_id:
        raise ValueError("announcement signer key id must be a non-empty string")
    if type(from_epoch) is not int or from_epoch < 0:
        raise ValueError("announcement signer fromEpoch must be a non-negative integer")
    return {
        "keyId": key_id,
        "publicKey": signer_public_key_hex(signing_key),
        "fromEpoch": from_epoch,
    }


def verify_epoch_announcement(
    announcement: dict,
    public_key_x: bytes,
    public_key_y: bytes,
    expected_signing_key_id: str = None,
) -> bool:
    """Verify a signed epoch announcement. Fails closed on anything malformed."""
    try:
        if set(announcement) != _ANNOUNCEMENT_FIELDS:
            return False
        if (
            expected_signing_key_id is not None
            and announcement.get("signingKeyId") != expected_signing_key_id
        ):
            return False
        complete_announcement_bytes(announcement)
        digest = compute_announcement_digest(announcement)
        signature = _fixed_hex(announcement.get("signature"), 64, "signature")
    except (KeyError, TypeError, ValueError, OverflowError):
        return False
    try:
        return ecdsa_verify(public_key_x, public_key_y, signature, digest_to_message_bytes(digest))
    except (TypeError, ValueError):
        return False


def liveness_transcript(liveness: dict) -> bytes:
    """Return the exact normative ``zkc:epoch-liveness:v1`` signing transcript.

    Its domain tag differs from both announcement domains, so a liveness
    signature can never verify as an announcement or the reverse.
    """
    if not isinstance(liveness, dict):
        raise ValueError("liveness statement must be an object")
    if liveness.get("version") != LIVENESS_VERSION:
        raise ValueError("unsupported liveness statement version")
    transcript = b"".join(
        (
            _LIVENESS_DOMAIN,
            _text(liveness.get("version"), "version"),
            _text(liveness.get("accumulatorId"), "accumulatorId"),
            _u64(liveness.get("epoch"), "epoch"),
            _fixed_hex(liveness.get("headHash"), 32, "headHash"),
            _u64(liveness.get("issuedAt"), "issuedAt", nonzero=True),
            _text(liveness.get("signingKeyId"), "signingKeyId"),
        )
    )
    # The same bound as the announcement transcript (95 fixed bytes, so
    # accumulatorId and signingKeyId together hold at most 65440 UTF-8 bytes).
    if len(transcript) > MAX_LIVENESS_TRANSCRIPT_BYTES:
        raise ValueError("liveness transcript exceeds 65535 bytes")
    return transcript


def compute_liveness_digest(liveness: dict) -> int:
    """SHA-256 of the liveness transcript, reduced into the BN254 field."""
    return int.from_bytes(hashlib.sha256(liveness_transcript(liveness)).digest(), "big") % FIELD_MODULUS


def verify_epoch_liveness(
    liveness: dict,
    public_key_x: bytes,
    public_key_y: bytes,
    expected_signing_key_id: str = None,
) -> bool:
    """Verify a signed liveness statement. Fails closed on anything malformed.

    This checks only the signature over the closed object. Whether the
    statement names the caller's head, and whether its key may sign at
    ``issuedAt``, are the consumer's checks (``verify_liveness_statement``).
    """
    try:
        if set(liveness) != _LIVENESS_FIELDS:
            return False
        if (
            expected_signing_key_id is not None
            and liveness.get("signingKeyId") != expected_signing_key_id
        ):
            return False
        digest = compute_liveness_digest(liveness)
        signature = _fixed_hex(liveness.get("signature"), 64, "signature")
    except (KeyError, TypeError, ValueError, OverflowError):
        return False
    try:
        return ecdsa_verify(public_key_x, public_key_y, signature, digest_to_message_bytes(digest))
    except (TypeError, ValueError):
        return False


def _liveness_interval(value) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("liveness_interval must be a positive number of seconds")
    return value


class RevocationAccumulatorService(IssuerAccumulator):
    """Accumulator lifecycle + signed announcements + witness updates.

    A drop-in ``IssuerAccumulator`` (the SandboxIssuerAdapter accepts it via
    its ``accumulator=`` parameter), so issuance automatically registers
    credentials here and the published metadata reflects this service.
    """

    def __init__(
        self,
        accumulator_id: str,
        update_endpoint: str,
        signing_key: IssuerSigningKey,
        max_epoch_lag: int = MAX_EPOCH_LAG,
        clock=time.time,
        *,
        liveness_interval: int = DEFAULT_LIVENESS_INTERVAL,
    ):
        super().__init__(accumulator_id, update_endpoint, max_epoch_lag)
        self._liveness_interval = _liveness_interval(liveness_interval)
        # Latest signed liveness statement; never part of the chain.
        self._liveness = None
        # Ordered signer history; replaced, never mutated, on rotation.
        self._signers = (self._admit_signing_key(signing_key, 0),)
        self._signing_key = signing_key
        self._clock = clock
        # epoch -> leaf snapshot for the delta window (copy-on-write).
        self._snapshots: dict = {0: []}
        self._last_announcement_hash = GENESIS_ANNOUNCEMENT_HASH
        self._announcements: dict = {0: self._announce(self._signing_time())}
        self._publication_ready = True

    # --- announcement signers ------------------------------------------------------

    def _admit_signing_key(self, signing_key, from_epoch: int) -> dict:
        """Admission policy for a key that will sign from ``from_epoch`` on.

        Construction, recovery and rotation all call this hook. A signer
        must expose its validity window through ``is_valid_at``; a key
        without one is refused. The window itself is checked when the key
        signs (``_signing_time``) and, for a successor, when it is rotated
        in. Returns the key's public signer record.
        """
        if not callable(getattr(signing_key, "sign_digest", None)):
            raise ValueError("announcement signer must provide sign_digest")
        if not callable(getattr(signing_key, "is_valid_at", None)):
            raise ValueError("announcement signer must expose its validity window (is_valid_at)")
        return signer_record(signing_key, from_epoch)

    @staticmethod
    def _require_valid_signer(signing_key, timestamp: int) -> None:
        """Fail closed unless ``signing_key`` may sign at ``timestamp``."""
        if signing_key.is_valid_at(timestamp) is not True:
            raise AdapterError(
                "EXPIRED_ISSUER_KEY",
                f"announcement signing key {signing_key.key_id!r} is outside its "
                f"validity window at {timestamp}",
            )

    def _signing_time(self) -> int:
        """Read the clock once for the next announcement and check the signer.

        Runs before any state of the next epoch is built, so a key outside
        its window refuses the whole transition.
        """
        announced_at = int(self._clock())
        self._require_valid_signer(self._signing_key, announced_at)
        return announced_at

    @_locked
    def ensure_can_sign(self, timestamp: int = None) -> None:
        """Raise ``EXPIRED_ISSUER_KEY`` unless the active signer is valid now.

        Callers that write ahead of a mutation (the issuer adapter's ledger)
        use this to refuse before their own write. The mutation itself
        re-checks at the time it signs.
        """
        if timestamp is None:
            timestamp = int(self._clock())
        self._require_valid_signer(self._signing_key, timestamp)

    @_locked
    def rotate_signing_key(self, signing_key) -> dict:
        """Make ``signing_key`` the announcement signer from the next epoch on.

        The successor is recorded with ``fromEpoch = epoch + 1``. Nothing is
        signed now: the current announcement stays the chain head, and the
        next epoch is signed by the successor and commits to that head.
        Key ids and public keys of recorded signers are never reused. A
        durable service persists the record before it switches keys, so a
        failed write leaves the active signer unchanged. Returns the record.
        """
        record = self._admit_signing_key(signing_key, self.epoch + 1)
        if any(record["keyId"] == signer["keyId"] for signer in self._signers):
            raise ValueError("announcement signer key id is already recorded")
        if any(record["publicKey"] == signer["publicKey"] for signer in self._signers):
            raise ValueError("announcement signer public key is already recorded")
        # A successor that cannot sign now would only make the next epoch fail.
        self._require_valid_signer(signing_key, int(self._clock()))
        self._after_signer_recorded(record)
        self._signers = self._signers + (record,)
        self._signing_key = signing_key
        return dict(record)

    def _after_signer_recorded(self, record: dict) -> None:
        """Persistence hook; the active signer changes only after it returns."""

    @_locked
    def signing_key_history(self) -> list:
        """Ordered announcement signer records (public material only)."""
        return [dict(signer) for signer in self._signers]

    # --- epoch lifecycle (signed announcements) -----------------------------------

    def _announce(self, announced_at: int) -> dict:
        if self._signing_key.key_id != self._signers[-1]["keyId"]:
            # Only rotate_signing_key may change the signer; an unrecorded
            # key would leave history that recovery cannot authenticate.
            raise RuntimeError("signing key is not the active recorded announcement signer")
        # _signing_time already checked this instant; re-check at the signer.
        self._require_valid_signer(self._signing_key, announced_at)
        root = self.root()
        previous_hash = self._last_announcement_hash
        announcement = {
            "version": ANNOUNCEMENT_VERSION,
            "accumulatorId": self.accumulator_id,
            "root": field_to_hex(root),
            "epoch": self.epoch,
            "announcedAt": announced_at,
            "maxEpochLag": self.max_epoch_lag,
            "signingKeyId": self._signing_key.key_id,
            "previousAnnouncementHash": previous_hash,
        }
        digest = compute_announcement_digest(announcement)
        announcement["signature"] = "0x" + self._signing_key.sign_digest(digest).hex()
        self._last_announcement_hash = announcement_hash(announcement)
        return announcement

    def _record_epoch(self, operation: tuple, announced_at: int) -> None:
        self._publication_ready = False
        self._snapshots[self.epoch] = self._accumulator.leaves()
        oldest_servable = self.epoch - DELTA_SNAPSHOT_WINDOW
        for epoch in [epoch for epoch in self._snapshots if epoch < oldest_servable]:
            del self._snapshots[epoch]
        self._announcements[self.epoch] = self._announce(announced_at)
        self._after_epoch_recorded(operation)
        self._publication_ready = True

    def _after_epoch_recorded(self, operation: tuple) -> None:
        """Candidate persistence hook; live state stays unchanged until it returns.

        ``operation`` is ``(name, *args)`` of the mutation that produced the
        epoch, e.g. ``("register", credential_id)``.
        """

    @_locked
    def _transition(self, operation: str, *args):
        """Build, sign and persist privately; publish only a successful epoch.

        The same lock covers the entire transition and every public read. The
        candidate copies every mutable state container; existing history
        entries are shared but never changed. A mutation, signing or store
        failure discards the candidate. A signer outside its validity window
        is refused first, before any candidate exists.
        """
        mutation = _MUTATIONS[operation]
        announced_at = self._signing_time()
        candidate = copy.copy(self)
        candidate._accumulator = SparseMerkleAccumulator(self._accumulator.leaves())
        candidate._index_by_credential = dict(self._index_by_credential)
        candidate._revoked = set(self._revoked)
        candidate._snapshots = dict(self._snapshots)
        candidate._announcements = dict(self._announcements)
        result = mutation(candidate, *args)
        candidate._record_epoch((operation, *args), announced_at)
        # No caller can observe the field swaps while the lock is held.
        for name in (
            "_accumulator", "_epoch", "_index_by_credential", "_revoked",
            "_snapshots", "_announcements", "_last_announcement_hash",
        ):
            setattr(self, name, getattr(candidate, name))
        return result

    def register(self, credential_id: int) -> int:
        return self._transition("register", credential_id)

    def revoke(self, credential_id: int) -> None:
        self._transition("revoke", credential_id)

    def replace(self, old_credential_id: int, new_credential_id: int) -> int:
        """Atomic renewal swap (both-or-neither): ONE epoch, ONE announcement."""
        return self._transition("replace", old_credential_id, new_credential_id)

    @_locked
    def current_announcement(self) -> dict:
        self._require_publication_ready()
        return dict(self._announcements[self.epoch])

    @_locked
    def announcement_for_epoch(self, epoch: int) -> dict:
        self._require_publication_ready()
        if type(epoch) is not int or epoch < 0:
            raise AdapterError(
                "REVOCATION_METADATA_UNAVAILABLE", "invalid announcement epoch"
            )
        announcement = self._announcements.get(epoch)
        if announcement is None:
            raise AdapterError(
                "REVOCATION_METADATA_UNAVAILABLE", f"no announcement recorded for epoch {epoch}"
            )
        return dict(announcement)

    @_locked
    def announcement_history(self, from_epoch: int = 0, to_epoch: int = None) -> list:
        """Return a contiguous inclusive epoch range in ascending order."""
        self._require_publication_ready()
        if type(from_epoch) is not int or from_epoch < 0:
            raise AdapterError("REVOCATION_METADATA_UNAVAILABLE", "invalid history start epoch")
        if to_epoch is None:
            to_epoch = self.epoch
        if type(to_epoch) is not int or to_epoch < from_epoch or to_epoch > self.epoch:
            raise AdapterError("REVOCATION_METADATA_UNAVAILABLE", "invalid history end epoch")
        try:
            return [dict(self._announcements[epoch]) for epoch in range(from_epoch, to_epoch + 1)]
        except KeyError:
            raise AdapterError(
                "REVOCATION_METADATA_UNAVAILABLE", "announcement history is incomplete"
            ) from None

    def _require_publication_ready(self) -> None:
        if not getattr(self, "_publication_ready", False):
            raise AdapterError(
                "REVOCATION_METADATA_UNAVAILABLE",
                "current announcement is not durably published",
            )

    # --- head liveness (zkc:epoch-liveness:v1) -------------------------------------

    @_locked
    def sign_liveness(self) -> dict:
        """Sign a liveness statement for the current head at the clock time.

        The statement names the head by its complete hash and changes no
        state of the chain: no epoch, root, announcement or snapshot. The
        active announcement key signs it, under the same validity window
        rule as an announcement (``EXPIRED_ISSUER_KEY`` outside it). After
        ``rotate_signing_key`` the successor signs liveness for the head its
        predecessor announced, so consumers pin the successor before the
        rotation. A scheduler may call this on a fixed cadence; otherwise
        ``current_liveness`` re-signs on demand.
        """
        self._require_publication_ready()
        if self._signing_key.key_id != self._signers[-1]["keyId"]:
            raise RuntimeError("signing key is not the active recorded announcement signer")
        issued_at = int(self._clock())
        self._require_valid_signer(self._signing_key, issued_at)
        statement = {
            "version": LIVENESS_VERSION,
            "accumulatorId": self.accumulator_id,
            "epoch": self.epoch,
            "headHash": self._last_announcement_hash,
            "issuedAt": issued_at,
            "signingKeyId": self._signing_key.key_id,
        }
        digest = compute_liveness_digest(statement)
        statement["signature"] = "0x" + self._signing_key.sign_digest(digest).hex()
        self._liveness = statement
        return dict(statement)

    @_locked
    def current_liveness(self) -> dict:
        """The liveness statement for the current head, re-signed on the cadence.

        Returns the retained statement while it names the current head and
        is younger than ``liveness_interval`` seconds; otherwise signs a new
        one. Raises ``EXPIRED_ISSUER_KEY`` when the active key cannot sign.
        """
        self._require_publication_ready()
        retained = self._liveness
        now = int(self._clock())
        if (
            retained is not None
            and retained["epoch"] == self.epoch
            and retained["headHash"] == self._last_announcement_hash
            and 0 <= now - retained["issuedAt"] < self._liveness_interval
        ):
            return dict(retained)
        return self.sign_liveness()

    def _published_liveness(self):
        """``current_liveness`` for publication, or ``None`` without a valid signer.

        An expired active key cannot attest liveness. Publication then
        carries the head alone, so consumers fall back to the head's own
        ``announcedAt`` exactly as before liveness existed; the operator
        sees ``EXPIRED_ISSUER_KEY`` from ``current_liveness`` and from every
        mutation until a valid successor is rotated in.
        """
        try:
            return self.current_liveness()
        except AdapterError as exc:
            if exc.code != "EXPIRED_ISSUER_KEY":
                raise
            return None

    @_locked
    def metadata(self) -> dict:
        """Authenticated issuer-metadata revocation block from one signed snapshot.

        ``currentLiveness`` (additive) names ``currentAnnouncement`` by its
        complete hash; it is omitted only while the active key cannot sign.
        """
        announcement = self.current_announcement()
        block = {
            "accumulatorId": announcement["accumulatorId"],
            "type": "POSEIDON2_MERKLE_ACTIVE_SET",
            "currentRoot": announcement["root"],
            "currentEpoch": announcement["epoch"],
            "maxEpochLag": announcement["maxEpochLag"],
            "updateEndpoint": self.update_endpoint,
            "currentAnnouncement": announcement,
        }
        liveness = self._published_liveness()
        if liveness is not None:
            block["currentLiveness"] = liveness
        return block

    # --- witness update protocol ------------------------------------------------------

    def _attach_liveness(self, response: dict) -> None:
        """Add the head's liveness statement to an update response (additive)."""
        liveness = self._published_liveness()
        if liveness is not None:
            response["liveness"] = liveness

    def _witness_at_epoch(self, credential_id: int, epoch: int):
        """(path_index, siblings) at a historical epoch, or None if unservable."""
        leaves = self._snapshots.get(epoch)
        if leaves is None:
            return None
        index = self._index_by_credential.get(credential_id)
        if index is None or index >= len(leaves) or leaves[index] != credential_id:
            return None
        return SparseMerkleAccumulator(leaves).witness(index)

    @_locked
    def handle_request(self, request: dict) -> dict:
        """Serve one witness-update wire request (shapes in module docstring).

        Returns a delta response when ``fromEpoch`` names an epoch this
        service can still reconstruct the caller's witness for; otherwise a
        full refresh. Fails closed for revoked/unknown credentials.
        """
        if isinstance(request, dict) and request.get("type") == EPOCH_DELTA_REQUEST:
            return self.handle_epoch_delta_request(request)
        if not isinstance(request, dict) or request.get("type") != WITNESS_UPDATE_REQUEST:
            raise AdapterError(
                "REVOCATION_METADATA_UNAVAILABLE", "unrecognized witness update request type"
            )
        if request.get("accumulatorId") != self.accumulator_id:
            raise AdapterError("REVOCATION_METADATA_UNAVAILABLE", "unknown accumulator id")
        try:
            credential_id = canonical_hex_to_field(request["credentialId"])
        except (KeyError, ValueError):
            raise AdapterError(
                "STALE_ACCUMULATOR_WITNESS", "credentialId is not a canonical field element"
            ) from None

        # Raises STALE_ACCUMULATOR_WITNESS when revoked or unknown.
        current = self.witness(credential_id)

        response = {
            "type": WITNESS_UPDATE_RESPONSE,
            "accumulatorId": self.accumulator_id,
            "epoch": self.epoch,
            "root": field_to_hex(self.root()),
            "announcement": self.current_announcement(),
        }
        self._attach_liveness(response)

        from_epoch = _request_from_epoch(request)
        if from_epoch is not None:
            old = self._witness_at_epoch(credential_id, from_epoch)
            if old is not None:
                _, old_siblings = old
                new_siblings = [hex_to_field(s) for s in current["siblings"]]
                response["mode"] = "delta"
                response["witnessDelta"] = {
                    "pathIndex": current["pathIndex"],
                    "fromEpoch": from_epoch,
                    "changedSiblings": [
                        [level, field_to_hex(new_siblings[level])]
                        for level in range(len(new_siblings))
                        if new_siblings[level] != old_siblings[level]
                    ],
                }
                return response

        response["mode"] = "full"
        response["witness"] = current
        return response

    @_locked
    def handle_epoch_delta_request(self, request: dict) -> dict:
        """Serve accumulator leaves without a credential identifier.

        The wire still supports an optional delta base for raw clients.
        ``PrivateWitnessProvider`` omits it to avoid disclosing prior sync state
        and checks the full response against an independent announcement source.

        Request (``zkc:epoch-delta-request:v1``)::

            {"type": "zkc:epoch-delta-request:v1",
             "accumulatorId": "...", "fromEpoch": <int, optional>}

        Response (``zkc:epoch-delta-response:v1``)::

            {"type": "zkc:epoch-delta-response:v1", "accumulatorId": "...",
             "epoch": <int>, "root": "0x…", "announcement": <signed>,
             "liveness": <signed, optional>,
             "mode": "full" | "delta",
             # full: the entire current leaf set
             "leaves": ["0x…", …],
             # delta: changes relative to the fromEpoch snapshot
             "fromEpoch": <int>, "leafCount": <int>,
             "changedLeaves": [[index, "0x…"], …]}
        """
        if not isinstance(request, dict) or request.get("type") != EPOCH_DELTA_REQUEST:
            raise AdapterError(
                "REVOCATION_METADATA_UNAVAILABLE", "unrecognized epoch delta request type"
            )
        if request.get("accumulatorId") != self.accumulator_id:
            raise AdapterError("REVOCATION_METADATA_UNAVAILABLE", "unknown accumulator id")
        current_leaves = self._accumulator.leaves()
        response = {
            "type": EPOCH_DELTA_RESPONSE,
            "accumulatorId": self.accumulator_id,
            "epoch": self.epoch,
            "root": field_to_hex(self.root()),
            "announcement": self.current_announcement(),
        }
        self._attach_liveness(response)
        from_epoch = _request_from_epoch(request)
        if from_epoch is not None:
            old_leaves = self._snapshots.get(from_epoch)
            if old_leaves is not None:
                changed = [
                    [index, field_to_hex(leaf)]
                    for index, leaf in enumerate(current_leaves)
                    if index >= len(old_leaves) or old_leaves[index] != leaf
                ]
                response["mode"] = "delta"
                response["fromEpoch"] = from_epoch
                response["leafCount"] = len(current_leaves)
                response["changedLeaves"] = changed
                return response
        response["mode"] = "full"
        response["leaves"] = [field_to_hex(leaf) for leaf in current_leaves]
        return response


def apply_witness_delta(witness: dict, response: dict) -> dict:
    """Holder-side: patch a stored witness dict with a delta response.

    Fails closed on mode/path mismatches; the caller should still verify the
    patched witness against the announced root (WitnessUpdateProvider does).
    """
    if response.get("mode") != "delta":
        raise ValueError("response is not a delta witness update")
    delta = response["witnessDelta"]
    if witness["pathIndex"] != delta["pathIndex"]:
        raise ValueError("witness delta path index mismatch")
    siblings = list(witness["siblings"])
    for level, sibling in delta["changedSiblings"]:
        siblings[int(level)] = sibling
    return {
        "pathIndex": witness["pathIndex"],
        "siblings": siblings,
        "accumulatorRoot": response["root"],
        "accumulatorEpoch": response["epoch"],
    }

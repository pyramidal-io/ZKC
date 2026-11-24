"""Epoch-announcement chain validation (gap + fork detection).

Epoch announcements are chained: each commits to the sha256 hash of its
predecessor, under the issuer signature. ``AnnouncementChain`` is the
holder/verifier-side consumer of that chain:

- signatures are verified against the issuer's allowlisted key;
- epochs must advance; a regression is rejected (replay);
- a skipped epoch raises :class:`EpochGapError` — a STRUCTURED error naming
  the missing epoch range, so the caller can backfill from
  ``RevocationAccumulatorService.announcement_for_epoch`` and re-ingest in
  order;
- a successor that does not commit to the hash of the announcement actually
  seen raises :class:`ChainLinkageError` — the signed history forked, which
  a holder/verifier must treat as a serious revocation-distribution failure.
- conflicts are classified by the signed TRANSCRIPT, not by the signature
  bytes: a same-epoch candidate whose transcript equals the retained
  checkpoint's but whose signature differs is a re-encoded copy, not issuer
  equivocation, and raises :class:`AnnouncementAuthenticationError` (no
  fork evidence). Only a different signed transcript is ``CHAIN_FORKED``.

The first ingested announcement is the local trust anchor (any epoch); the
chain is enforced from there on. A consumer that cold-starts applies
:func:`require_authorized_anchor` to that first announcement: a
zero-predecessor "migration checkpoint" at an epoch above 0 is accepted only
when the consumer's ``authorized_migrations`` policy names
``(issuer_id, accumulatorId, epoch)``.

Scope and evidence
------------------
An announcement for an accumulator other than the chain's scope raises
:class:`AccumulatorIdMismatchError` (``ACCUMULATOR_ID_MISMATCH``) before its
signature is checked. The scope is the ``accumulator_id=`` pin when one is
given, otherwise the anchor's ``accumulatorId``. One issuer key may sign
several accumulators, so a mismatch is a consumer-scope failure, never fork
evidence. A :class:`ChainLinkageError` carries the announcement the chain had
actually accepted immediately before the candidate (``predecessor``) and the
candidate. :attr:`ChainLinkageError.evidence_pair` is that pair only when
both name the same accumulator and the same signing key id, and only then is
it equivocation evidence (:func:`equivocation_evidence`).

Key pins carry validity windows
-------------------------------
Every trusted key is an :class:`AnnouncementKeyPin`: the public key plus a
mandatory ``[notBefore, notAfter)`` window in Unix seconds and an optional
``retireAfterEpoch``. An authentic announcement whose signed ``announcedAt``
lies outside its signer's window, or whose epoch is above the signer's
``retireAfterEpoch``, raises :class:`AnnouncementKeyWindowError`. The check
applies to every ingested announcement: the head, each backfilled or
caught-up historical announcement, and a persisted checkpoint when it is
loaded again. A bare ``(x, y)`` pin has no window and fails closed.

Liveness statements are not chain members
-----------------------------------------
A ``zkc:epoch-liveness:v1`` statement (``verify_liveness_statement``) is
signed under the same pins and window rule, with ``issuedAt`` in place of
``announcedAt``. It only extends the freshness of the one announcement whose
complete hash it names (``liveness_names_head``). ``AnnouncementChain`` never
ingests one: it cannot advance or replace an epoch, and a statement that
names another head raises ``LivenessHeadMismatchError``, never
``CHAIN_FORKED``.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass

from .service import (
    GENESIS_ANNOUNCEMENT_HASH,
    announcement_hash,
    announcement_transcript,
    verify_epoch_announcement,
    verify_epoch_liveness,
)

__all__ = [
    "AnnouncementChainError",
    "AnnouncementAuthenticationError",
    "AnnouncementKeyWindowError",
    "AnnouncementReplayError",
    "AccumulatorIdMismatchError",
    "MigrationCheckpointUnauthorizedError",
    "EpochGapError",
    "ChainLinkageError",
    "LivenessHeadMismatchError",
    "AnnouncementChain",
    "AnnouncementKeyPin",
    "EQUIVOCATION_EVIDENCE_VERSION",
    "equivocation_evidence",
    "liveness_names_head",
    "require_authorized_anchor",
    "validate_announcement_key_pins",
    "validate_authorized_migrations",
    "verify_liveness_statement",
]

EQUIVOCATION_EVIDENCE_VERSION = "zkc:revocation-equivocation-evidence:v2"

_U64_LIMIT = 1 << 64
_PUBLIC_KEY_HEX = re.compile(r"0x[0-9a-f]{128}")


class AnnouncementChainError(Exception):
    """Base class; subclasses define a stable `code`."""

    code = "ANNOUNCEMENT_CHAIN_ERROR"

    def __init__(self, message: str):
        super().__init__(f"[{self.code}] {message}")
        self.message = message


class AnnouncementAuthenticationError(AnnouncementChainError):
    """The key id is not pinned or its signature is invalid."""

    code = "ANNOUNCEMENT_AUTHENTICATION_FAILED"


class AnnouncementKeyWindowError(AnnouncementAuthenticationError):
    """A pinned key signed outside its validity window or retirement epoch."""

    code = "ANNOUNCEMENT_KEY_OUTSIDE_VALIDITY"


def _rfc3339_seconds(value, name: str) -> int:
    """Unix seconds of an RFC 3339 timestamp that names its UTC offset."""
    if type(value) is not str or not value:
        raise ValueError(f"{name} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"{name} must be an RFC 3339 timestamp") from None
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must state its UTC offset")
    return int(parsed.timestamp())


@dataclass(frozen=True)
class AnnouncementKeyPin:
    """Verifier-local trust pin for one announcement signing key.

    ``x`` and ``y`` are the 32-byte secp256k1 public key coordinates.
    ``not_before`` and ``not_after`` are Unix seconds; the key may sign an
    announcement whose ``announcedAt`` satisfies
    ``not_before <= announcedAt < not_after`` (the issuer key's own
    ``is_valid_at`` rule). ``retire_after_epoch``, when set, is the last
    epoch the key may sign. Both bounds are mandatory parts of the pin; there
    is no unbounded default.
    """

    x: bytes
    y: bytes
    not_before: int
    not_after: int
    retire_after_epoch: int = None

    def __post_init__(self):
        if any(type(value) is not bytes or len(value) != 32 for value in (self.x, self.y)):
            raise ValueError("announcement public key coordinates must be 32 bytes each")
        for name in ("not_before", "not_after"):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value < _U64_LIMIT:
                raise ValueError(f"announcement key pin {name} must be u64 Unix seconds")
        if self.not_before >= self.not_after:
            raise ValueError("announcement key pin window is empty (notBefore >= notAfter)")
        retire = self.retire_after_epoch
        if retire is not None and (type(retire) is not int or not 0 <= retire < _U64_LIMIT):
            raise ValueError("announcement key pin retireAfterEpoch must be a u64 epoch")

    @classmethod
    def from_signing_key_entry(cls, entry: dict, *, retire_after_epoch: int = None):
        """Pin from a ``signingKeys[]``-shaped record obtained out of band.

        The record supplies ``publicKey`` (0x x||y) and RFC 3339
        ``notBefore``/``notAfter``. Pinning is a verifier-local decision: a
        record read from the same metadata document it would authenticate
        grants no authority.
        """
        if type(entry) is not dict:
            raise ValueError("signing key entry must be an object")
        public_key = entry.get("publicKey")
        # The pattern runs before bytes.fromhex, which would skip whitespace.
        if type(public_key) is not str or _PUBLIC_KEY_HEX.fullmatch(public_key) is None:
            raise ValueError("signing key entry publicKey must be 0x-prefixed 64-byte hex")
        raw = bytes.fromhex(public_key[2:])
        return cls(
            x=raw[:32],
            y=raw[32:],
            not_before=_rfc3339_seconds(entry.get("notBefore"), "notBefore"),
            not_after=_rfc3339_seconds(entry.get("notAfter"), "notAfter"),
            retire_after_epoch=retire_after_epoch,
        )

    def check(self, announcement: dict) -> None:
        """Raise ``AnnouncementKeyWindowError`` unless this key may sign it."""
        self._check_signed(announcement, "announcedAt", "announcement")

    def check_liveness(self, liveness: dict) -> None:
        """The same window and retirement rule for a liveness statement.

        ``issuedAt`` takes the place of ``announcedAt``; ``epoch`` is the
        epoch of the head the statement names.
        """
        self._check_signed(liveness, "issuedAt", "liveness statement")

    def _check_signed(self, signed: dict, time_field: str, label: str) -> None:
        signed_at = signed.get(time_field)
        epoch = signed.get("epoch")
        if type(signed_at) is not int or type(epoch) is not int:
            raise AnnouncementAuthenticationError(f"{label} time or epoch is malformed")
        if not self.not_before <= signed_at < self.not_after:
            raise AnnouncementKeyWindowError(
                f"{label} key {signed.get('signingKeyId')!r} signed at "
                f"{signed_at}, outside its pinned window "
                f"[{self.not_before}, {self.not_after})"
            )
        if self.retire_after_epoch is not None and epoch > self.retire_after_epoch:
            raise AnnouncementKeyWindowError(
                f"{label} key {signed.get('signingKeyId')!r} signed epoch "
                f"{epoch}, after its pinned retireAfterEpoch {self.retire_after_epoch}"
            )


def validate_announcement_key_pins(keys_by_id) -> dict:
    """Return a copy of ``signingKeyId -> AnnouncementKeyPin``; fail closed.

    A legacy bare ``(x, y)`` pin is refused: it carries no validity window,
    and accepting it would trust the key forever.
    """
    if not isinstance(keys_by_id, dict) or not keys_by_id:
        raise ValueError("at least one pre-authorized announcement key pin is required")
    pins = {}
    for key_id, pin in keys_by_id.items():
        if type(key_id) is not str or not key_id:
            raise ValueError("announcement signing key ids must be non-empty strings")
        if not isinstance(pin, AnnouncementKeyPin):
            raise ValueError(
                f"announcement key {key_id!r} must be pinned as an AnnouncementKeyPin with "
                "notBefore/notAfter; a bare (x, y) pin has no validity window"
            )
        pins[key_id] = pin
    return pins


class AnnouncementReplayError(AnnouncementChainError):
    """The candidate does not advance a retained checkpoint."""

    code = "ANNOUNCEMENT_REPLAY"


class AccumulatorIdMismatchError(AnnouncementChainError):
    """The announcement names an accumulator outside the consumer's scope.

    The consumer pins the accumulator it follows; a server or relay cannot
    choose it. One issuer key may sign several accumulators, so a mismatch
    is not fork evidence and is never retained as such.
    """

    code = "ACCUMULATOR_ID_MISMATCH"


class MigrationCheckpointUnauthorizedError(AnnouncementChainError):
    """A cold-start anchor is an unauthorized zero-predecessor checkpoint."""

    code = "MIGRATION_CHECKPOINT_UNAUTHORIZED"


def validate_authorized_migrations(entries) -> frozenset:
    """Return the ``authorized_migrations`` policy as a frozenset; fail closed.

    Each entry is an ``(issuer_id, accumulator_id, epoch)`` tuple with
    non-empty string ids and a u64 epoch above 0. ``None`` or an empty
    iterable authorizes no migration.
    """
    if entries is None:
        return frozenset()
    if isinstance(entries, (str, bytes, dict)):
        raise ValueError(
            "authorized_migrations must be an iterable of (issuer_id, accumulator_id, epoch)"
        )
    policy = set()
    for entry in entries:
        if type(entry) is not tuple or len(entry) != 3:
            raise ValueError(
                "each authorized migration must be an (issuer_id, accumulator_id, epoch) tuple"
            )
        issuer_id, accumulator_id, epoch = entry
        if any(type(value) is not str or not value for value in (issuer_id, accumulator_id)):
            raise ValueError("authorized migration ids must be non-empty strings")
        if type(epoch) is not int or not 0 < epoch < _U64_LIMIT:
            raise ValueError("authorized migration epoch must be a u64 above 0")
        policy.add(entry)
    return frozenset(policy)


def require_authorized_anchor(
    announcement: dict, issuer_id: str, authorized_migrations: frozenset
) -> None:
    """Apply the cold-start anchor rule to an authenticated first announcement.

    A zero ``previousAnnouncementHash`` at epoch 0 is a native genesis, and an
    anchor with a non-zero predecessor is an ordinary local checkpoint; both
    are accepted. A zero predecessor at an epoch above 0 is a migration
    checkpoint, accepted only when ``authorized_migrations`` contains
    ``(issuer_id, accumulatorId, epoch)``.
    """
    epoch = announcement.get("epoch")
    if announcement.get("previousAnnouncementHash") != GENESIS_ANNOUNCEMENT_HASH or epoch == 0:
        return
    if (issuer_id, announcement.get("accumulatorId"), epoch) not in authorized_migrations:
        raise MigrationCheckpointUnauthorizedError(
            f"zero-predecessor announcement at epoch {epoch} is a migration checkpoint "
            "that local policy does not authorize"
        )


class EpochGapError(AnnouncementChainError):
    """One or more epoch announcements were missed; backfill and re-ingest.

    Construction is O(1) for any u64 gap: ``gap_size`` is computed
    arithmetically and the message names the range by its ends. Check
    ``gap_size`` against a backfill bound before reading ``missing_epochs``,
    which lists every missing epoch.
    """

    code = "EPOCH_GAP"

    def __init__(self, last_seen_epoch: int, received_epoch: int):
        self.last_seen_epoch = last_seen_epoch
        self.received_epoch = received_epoch
        self.gap_size = received_epoch - last_seen_epoch - 1
        super().__init__(
            f"{self.gap_size} epoch announcements missing for epochs "
            f"{last_seen_epoch + 1}..{received_epoch - 1} "
            f"(last seen {last_seen_epoch}, received {received_epoch})"
        )

    @property
    def missing_epochs(self) -> list:
        """Every missing epoch in order; size it with ``gap_size`` first."""
        return list(range(self.last_seen_epoch + 1, self.received_epoch))


class ChainLinkageError(AnnouncementChainError):
    """A signed announcement does not extend the observed chain (fork).

    ``predecessor`` is the announcement the chain had accepted immediately
    before ``candidate``: the retained checkpoint, or the last announcement
    verified earlier in the same backfill or catch-up.
    """

    code = "CHAIN_FORKED"

    def __init__(self, message: str, *, predecessor: dict = None, candidate: dict = None):
        super().__init__(message)
        self.predecessor = None if predecessor is None else dict(predecessor)
        self.candidate = None if candidate is None else dict(candidate)

    @property
    def evidence_pair(self):
        """``(predecessor, candidate)`` when it is equivocation evidence, else None.

        Both announcements must name the same accumulator and the same
        signing key id; the chain verified each under that one pinned key.
        """
        predecessor, candidate = self.predecessor, self.candidate
        if type(predecessor) is not dict or type(candidate) is not dict:
            return None
        key_id = predecessor.get("signingKeyId")
        if (
            type(key_id) is not str
            or candidate.get("signingKeyId") != key_id
            or candidate.get("accumulatorId") != predecessor.get("accumulatorId")
        ):
            return None
        return dict(predecessor), dict(candidate)


def equivocation_evidence(error: ChainLinkageError, observed_at: int):
    """The evidence record for ``error``, or None when it is not evidence."""
    pair = error.evidence_pair
    if pair is None:
        return None
    return {
        "version": EQUIVOCATION_EVIDENCE_VERSION,
        "observedAt": int(observed_at),
        "errorCode": error.code,
        "predecessor": pair[0],
        "candidate": pair[1],
    }


class LivenessHeadMismatchError(AnnouncementChainError):
    """An authentic liveness statement names a different head.

    It is never fork evidence: a liveness statement carries no root and no
    predecessor, so it cannot show which history its signer published. A
    consumer that wants to know fetches the issuer's head and ingests it
    through the chain, which classifies any real fork.
    """

    code = "LIVENESS_HEAD_MISMATCH"


def verify_liveness_statement(liveness, trusted_keys: dict) -> dict:
    """Authenticate a ``zkc:epoch-liveness:v1`` statement; return a copy.

    The signer must be pinned in ``trusted_keys``
    (``signingKeyId -> AnnouncementKeyPin``), the signature must verify over
    the closed object, and ``issuedAt`` and ``epoch`` must satisfy the pin's
    window and ``retireAfterEpoch`` (``check_liveness``). This says nothing
    about which head the statement names; ``liveness_names_head`` does.
    """
    pins = validate_announcement_key_pins(trusted_keys)
    key_id = liveness.get("signingKeyId") if type(liveness) is dict else None
    pin = pins.get(key_id) if type(key_id) is str else None
    if pin is None:
        raise AnnouncementAuthenticationError(
            f"liveness statement signing key id {key_id!r} is not pre-authorized"
        )
    if not verify_epoch_liveness(liveness, pin.x, pin.y, expected_signing_key_id=key_id):
        raise AnnouncementAuthenticationError(
            "liveness statement signature is invalid or malformed"
        )
    pin.check_liveness(liveness)
    return dict(liveness)


def liveness_names_head(liveness: dict, head: dict) -> bool:
    """True when ``liveness`` names exactly ``head`` (accumulator, epoch, hash)."""
    try:
        epoch = liveness.get("epoch")
        return (
            type(liveness.get("accumulatorId")) is str
            and liveness.get("accumulatorId") == head.get("accumulatorId")
            # Type-strict: Python equates True with 1.
            and type(epoch) is int
            and type(head.get("epoch")) is int
            and epoch == head.get("epoch")
            and liveness.get("headHash") == announcement_hash(head)
        )
    except (AttributeError, TypeError, ValueError):
        return False


class AnnouncementChain:
    """Per-accumulator chain validator with pre-pinned rotation keys.

    ``trusted_keys`` maps ``signingKeyId`` to an :class:`AnnouncementKeyPin`,
    so metadata cannot authorize its own signing key and every key is
    trusted only inside its pinned window. The former positional
    ``(public_key_x, public_key_y)`` form trusted one key without a window;
    it now fails closed.

    ``accumulator_id`` pins the accumulator this consumer follows. Without
    it, the anchor's ``accumulatorId`` is the scope. An announcement outside
    the scope (the checkpoint included) raises
    :class:`AccumulatorIdMismatchError`.
    """

    def __init__(
        self,
        public_key_x: bytes = None,
        public_key_y: bytes = None,
        *,
        trusted_keys: dict = None,
        checkpoint: dict = None,
        accumulator_id: str = None,
    ):
        if accumulator_id is not None and (type(accumulator_id) is not str or not accumulator_id):
            raise ValueError("a pinned accumulator id must be a non-empty string")
        self._accumulator_id = accumulator_id
        if public_key_x is not None or public_key_y is not None:
            raise ValueError(
                "positional announcement key coordinates carry no validity window; "
                "pass trusted_keys={signingKeyId: AnnouncementKeyPin(...)}"
            )
        if trusted_keys is None:
            raise ValueError("announcement verification keys are required")
        self._trusted_keys = validate_announcement_key_pins(trusted_keys)
        self._last = None  # last accepted announcement
        self._last_hash = None
        if checkpoint is not None:
            self.ingest(checkpoint)

    @property
    def last_epoch(self):
        return None if self._last is None else int(self._last["epoch"])

    @property
    def last_announcement(self):
        return None if self._last is None else dict(self._last)

    @property
    def last_hash(self):
        return self._last_hash

    def _key_for(self, announcement: dict) -> AnnouncementKeyPin:
        key_id = announcement.get("signingKeyId") if type(announcement) is dict else None
        key = self._trusted_keys.get(key_id) if type(key_id) is str else None
        if key is None:
            raise AnnouncementAuthenticationError(
                f"announcement signing key id {key_id!r} is not pre-authorized"
            )
        return key

    @property
    def accumulator_id(self):
        """The chain's scope: the pin, else the anchor's accumulatorId."""
        if self._accumulator_id is not None:
            return self._accumulator_id
        return None if self._last is None else self._last.get("accumulatorId")

    def ingest(self, announcement: dict) -> None:
        """Validate one announcement against the chain (fail closed)."""
        scope = self.accumulator_id
        if scope is not None and (
            type(announcement) is not dict or announcement.get("accumulatorId") != scope
        ):
            # Checked before the signature: a genuine announcement of another
            # accumulator under the same key is out of scope, not a fork.
            raise AccumulatorIdMismatchError(
                "announcement accumulator id does not match the chain's accumulator"
            )
        key = self._key_for(announcement)
        if not verify_epoch_announcement(
            announcement,
            key.x,
            key.y,
            expected_signing_key_id=announcement.get("signingKeyId"),
        ):
            raise AnnouncementAuthenticationError(
                "announcement signature is invalid or malformed"
            )
        # Only an authentic announcement reaches the window check, so a
        # window error always names something the pinned key really signed.
        key.check(announcement)
        epoch = int(announcement["epoch"])
        if self._last is None:
            # Local trust anchor: the first announcement this party sees.
            self._last = dict(announcement)
            self._last_hash = announcement_hash(self._last)
            return
        last_epoch = int(self._last["epoch"])
        if epoch < last_epoch:
            raise AnnouncementReplayError(
                f"announcement epoch {epoch} is older than checkpoint {last_epoch}"
            )
        if epoch == last_epoch:
            if announcement_hash(announcement) == self._last_hash:
                raise AnnouncementReplayError(
                    f"announcement epoch {epoch} replays the retained checkpoint"
                )
            if announcement_transcript(announcement) == announcement_transcript(self._last):
                # Same signed statement, different signature bytes: a
                # re-encoding (for example a relay's malleated copy), never
                # evidence that the issuer signed two conflicting views.
                raise AnnouncementAuthenticationError(
                    f"announcement epoch {epoch} carries the retained checkpoint's "
                    "transcript under different signature bytes"
                )
            raise ChainLinkageError(
                f"issuer signed conflicting announcements for epoch {epoch}",
                predecessor=self._last,
                candidate=announcement,
            )
        if epoch > last_epoch + 1:
            raise EpochGapError(last_epoch, epoch)
        if announcement.get("previousAnnouncementHash") != self._last_hash:
            raise ChainLinkageError(
                "announcement does not commit to the previously observed "
                "announcement (signed history fork)",
                predecessor=self._last,
                candidate=announcement,
            )
        self._last = dict(announcement)
        self._last_hash = announcement_hash(self._last)

    def backfill(self, announcements) -> None:
        """Ingest a sequence of recovered announcements in epoch order."""
        for announcement in announcements:
            self.ingest(announcement)

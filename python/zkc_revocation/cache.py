"""Verifier acceptance of authenticated revocation metadata and chain roots."""

from __future__ import annotations

import json
import threading
import time

from zkc_verifier.trust_policy import (
    PROTOCOL_MAX_EPOCH_LAG,
    _authenticated_accumulator_state,
)

from .chain import (
    AnnouncementAuthenticationError,
    AnnouncementChain,
    AnnouncementChainError,
    AnnouncementReplayError,
    ChainLinkageError,
    EpochGapError,
    LivenessHeadMismatchError,
    equivocation_evidence,
    liveness_names_head,
    require_authorized_anchor,
    validate_announcement_key_pins,
    validate_authorized_migrations,
    verify_liveness_statement,
)
from .checkpoint import (
    CatchUpStatus,
    VerifierCheckpointConflictError,
    VerifierCheckpointStore,
    VerifierCheckpointStoreError,
)
from .service import announcement_hash

__all__ = [
    "AnnouncementMetadataError",
    "AnnouncementFreshnessError",
    "BackfillLimitError",
    "VerifierAccumulatorCache",
]

CHECKPOINT_VERSION = "zkc:verifier-revocation-checkpoint:v1"
AUTHENTICATED_METADATA_VERSION = "zkc:issuer-metadata:v2"

# A compare-and-swap fails only when another worker committed a different
# head between this worker's re-read and its write. Each retry re-reads that
# head and validates the candidate against it again.
_CHECKPOINT_SWAP_ATTEMPTS = 3

_U64_LIMIT = 1 << 64


def _exactly_equal(value, signed) -> bool:
    """JSON-type-strict equality of a convenience field and its signed value.

    Python ``==`` equates ``True`` with ``1`` and ``10.0`` with ``10``; the
    metadata convenience fields must carry the signed JSON value itself.
    """
    return type(value) is type(signed) and value == signed


def _same_announcement(candidate: dict, retained: dict) -> bool:
    """True when ``candidate`` is byte-for-byte the retained announcement.

    The complete hash covers every signed field and the signature, so equal
    hashes mean the candidate states nothing that was not already accepted.
    """
    try:
        return announcement_hash(candidate) == announcement_hash(retained)
    except (TypeError, ValueError):
        return False


class AnnouncementMetadataError(AnnouncementChainError):
    """Issuer metadata is missing v2 authentication or contradicts it."""

    code = "ANNOUNCEMENT_METADATA_MISMATCH"


class AnnouncementFreshnessError(AnnouncementChainError):
    """The signed publication time falls outside verifier-local policy."""

    code = "ANNOUNCEMENT_STALE"


class BackfillLimitError(AnnouncementChainError):
    """A gap exceeds the verifier's bounded history-fetch policy.

    ``ingest_metadata`` stays all-or-nothing and raises this for a gap wider
    than ``max_backfill``. ``catch_up`` closes such a gap in bounded,
    resumable steps without discarding the checkpoint.
    """

    code = "ANNOUNCEMENT_BACKFILL_LIMIT_EXCEEDED"


class VerifierAccumulatorCache:
    """Durable, metadata-authenticated accumulator state for verification.

    ``issuer_keys`` is ``issuer_id -> signingKeyId -> AnnouncementKeyPin``
    (public key, ``notBefore``/``notAfter`` window, optional
    ``retireAfterEpoch``). Key ids and pins, plus ``accumulator_ids``, are
    verifier-local trust configuration; metadata's own identifiers and
    ``signingKeys`` array are deliberately never allowed to bootstrap
    authority. Every announcement ingested, backfilled, caught up, or
    reloaded from the checkpoint store must lie inside its signer's pin.

    Workers, threads, and restarts that share one checkpoint store share one
    durable head. Every ingest and every ``state`` call re-reads the persisted
    checkpoint under a per-(issuer, accumulator) lock, and ingest writes with
    a compare-and-swap against the head it validated. A worker holding an
    older view therefore cannot move the shared checkpoint backwards.

    A checkpoint more than ``max_backfill`` epochs behind the current head is
    brought forward with ``catch_up``, one bounded step per call, never by
    deleting the checkpoint.

    Every chain is pinned to the issuer's configured accumulator id, so a
    backfilled or caught-up announcement of another accumulator fails with
    ``ACCUMULATOR_ID_MISMATCH`` and is never retained as evidence. A signed
    fork retains the announcement actually accepted before the candidate and
    the candidate, and only when both share an accumulator and signing key.

    At cold start the first head is the local trust anchor. A zero-predecessor
    head at an epoch above 0 (a migration checkpoint) is refused with
    ``MIGRATION_CHECKPOINT_UNAUTHORIZED`` unless ``authorized_migrations``, a
    set of ``(issuer_id, accumulator_id, epoch)`` tuples, names it.

    Freshness and revocation latency (specification §2.4.2): the head is
    fresh while ``max(announcedAt, issuedAt of a verified liveness statement
    that names it)`` is within ``max_announcement_age``. Metadata v2 may carry
    that statement as ``revocation.currentLiveness``; this worker keeps the
    newest one it verified in memory (it is not part of the checkpoint) and
    uses it only while it names the persisted head. A superseded root is
    served only while the earliest ``announcedAt`` of the announcements
    after it is within ``max_announcement_age``. So no root is served more
    than ``max_announcement_age + max_clock_skew`` seconds after the issuer
    signed the announcement that removed a credential, however few epochs
    follow. Re-ingesting the persisted head is a no-op for the chain.
    """

    def __init__(
        self,
        issuer_keys: dict,
        *,
        accumulator_ids: dict,
        checkpoint_store: VerifierCheckpointStore,
        max_epoch_lag: int = PROTOCOL_MAX_EPOCH_LAG,
        max_backfill: int = 32,
        max_announcement_age: int = 3600,
        max_clock_skew: int = 300,
        clock=time.time,
        authorized_migrations=(),
    ):
        if not 0 <= max_epoch_lag <= PROTOCOL_MAX_EPOCH_LAG:
            raise ValueError(
                f"max_epoch_lag must be within [0, {PROTOCOL_MAX_EPOCH_LAG}]"
            )
        if type(max_backfill) is not int or max_backfill < 0:
            raise ValueError("max_backfill must be a non-negative integer")
        if type(max_announcement_age) is not int or max_announcement_age < 0:
            raise ValueError("max_announcement_age must be a non-negative integer")
        if type(max_clock_skew) is not int or max_clock_skew < 0:
            raise ValueError("max_clock_skew must be a non-negative integer")
        if not isinstance(checkpoint_store, VerifierCheckpointStore):
            raise ValueError("a verifier checkpoint store is required")
        # Each pin carries the key's validity window (AnnouncementKeyPin); a
        # bare (x, y) pin fails closed here.
        self._issuer_keys = {
            issuer_id: validate_announcement_key_pins(keys_by_id)
            for issuer_id, keys_by_id in issuer_keys.items()
        }
        self._accumulator_ids = dict(accumulator_ids)
        if set(self._accumulator_ids) != set(self._issuer_keys):
            raise ValueError("issuer key and accumulator-id policies must name the same issuers")
        if any(
            not isinstance(accumulator_id, str) or not accumulator_id
            for accumulator_id in self._accumulator_ids.values()
        ):
            raise ValueError("trusted accumulator ids must be non-empty strings")
        self._authorized_migrations = validate_authorized_migrations(authorized_migrations)
        if any(
            self._accumulator_ids.get(issuer_id) != accumulator_id
            for issuer_id, accumulator_id, _epoch in self._authorized_migrations
        ):
            raise ValueError("an authorized migration names an accumulator that is not pinned")
        self._store = checkpoint_store
        self._max_epoch_lag = max_epoch_lag
        self._max_backfill = max_backfill
        self._max_announcement_age = max_announcement_age
        self._max_clock_skew = max_clock_skew
        self._clock = clock
        self._states = {}
        self._issuer_accumulators = {}
        # (issuer, accumulator) -> newest verified liveness statement. In
        # memory only: liveness never changes the checkpoint.
        self._liveness = {}
        self._locks = {}
        self._locks_guard = threading.Lock()

    def _keys(self, issuer_id: str) -> dict:
        keys = self._issuer_keys.get(issuer_id)
        if keys is None:
            raise AnnouncementAuthenticationError(
                f"issuer {issuer_id} is not in the verifier key allowlist"
            )
        return keys

    def _validate_metadata(self, issuer_id: str, metadata: dict):
        if type(metadata) is not dict or metadata.get("version") != AUTHENTICATED_METADATA_VERSION:
            raise AnnouncementMetadataError(
                "selective-disclosure roots require zkc:issuer-metadata:v2"
            )
        if metadata.get("issuerId") != issuer_id:
            raise AnnouncementMetadataError("metadata issuerId does not match the trusted issuer")
        revocation = metadata.get("revocation")
        if type(revocation) is not dict:
            raise AnnouncementMetadataError("metadata has no revocation object")
        announcement = revocation.get("currentAnnouncement")
        if type(announcement) is not dict:
            raise AnnouncementMetadataError("metadata has no signed current announcement")
        for metadata_name, announcement_name in (
            ("accumulatorId", "accumulatorId"),
            ("currentRoot", "root"),
            ("currentEpoch", "epoch"),
            ("maxEpochLag", "maxEpochLag"),
        ):
            if not _exactly_equal(
                revocation.get(metadata_name), announcement.get(announcement_name)
            ):
                raise AnnouncementMetadataError(
                    f"revocation.{metadata_name} does not match the signed announcement"
                )
        accumulator_id = announcement.get("accumulatorId")
        if not isinstance(accumulator_id, str) or not accumulator_id:
            raise AnnouncementMetadataError("announcement accumulatorId is malformed")
        if accumulator_id != self._accumulator_ids.get(issuer_id):
            raise AnnouncementMetadataError(
                "announcement accumulatorId is not pinned for this issuer"
            )
        observed = self._issuer_accumulators.get(issuer_id)
        if observed is not None and observed != accumulator_id:
            raise AnnouncementMetadataError(
                "issuer accumulatorId changed after a checkpoint was retained"
            )
        return announcement, accumulator_id

    def _validate_freshness(self, announcement: dict, liveness=None, now=None) -> None:
        """Fail unless the head was attested current within the age limit.

        ``liveness`` is a verified statement that names ``announcement`` (or
        ``None``). The head's freshness time is the later of its
        ``announcedAt`` and the statement's ``issuedAt``.
        """
        announced_at = announcement.get("announcedAt")
        if type(announced_at) is not int:
            raise AnnouncementFreshnessError("announcement publication time is malformed")
        if now is None:
            now = int(self._clock())
        if announced_at > now + self._max_clock_skew:
            raise AnnouncementFreshnessError("announcement publication time is in the future")
        attested_at = announced_at
        if liveness is not None:
            attested_at = max(attested_at, liveness["issuedAt"])
        if now - attested_at > self._max_announcement_age:
            raise AnnouncementFreshnessError("announcement exceeds the verifier age limit")

    def _metadata_liveness(self, metadata: dict, keys: dict):
        """Verify metadata's optional ``revocation.currentLiveness``.

        Returns the authenticated statement, or ``None`` when metadata
        carries none. A present statement must verify under a pinned key
        inside its window and must not be dated beyond the clock-skew
        allowance; otherwise the whole metadata document is refused. Which
        head it names is checked by the caller, after the head itself has
        been classified.
        """
        revocation = metadata["revocation"]
        if "currentLiveness" not in revocation:
            return None
        liveness = verify_liveness_statement(revocation["currentLiveness"], keys)
        if liveness["issuedAt"] > int(self._clock()) + self._max_clock_skew:
            raise AnnouncementFreshnessError("liveness statement time is in the future")
        return liveness

    @staticmethod
    def _require_names_head(liveness, names_head: bool) -> None:
        if liveness is not None and not names_head:
            raise LivenessHeadMismatchError(
                "revocation.currentLiveness does not name revocation.currentAnnouncement"
            )

    def _retain_liveness(self, issuer_id: str, accumulator_id: str, liveness) -> None:
        """Keep the newest verified statement for the persisted head.

        The caller holds the (issuer, accumulator) lock and has checked that
        ``liveness`` names the head it just persisted or found persisted.
        """
        if liveness is None:
            return
        key = (issuer_id, accumulator_id)
        retained = self._liveness.get(key)
        if (
            retained is None
            or retained["headHash"] != liveness["headHash"]
            or liveness["issuedAt"] > retained["issuedAt"]
        ):
            self._liveness[key] = liveness

    def _servable_roots(self, state: dict, now: int) -> dict:
        """Roots the issuer attested current within ``max_announcement_age``.

        The head root is attested by the head's freshness (checked by the
        caller). A superseded root at epoch ``e`` stopped being current no
        later than the earliest ``announcedAt`` among epochs ``e + 1 ..
        head``; it is served only while that time is within the age limit.
        The bound depends on time alone, never on how many epochs follow.
        """
        from zkc_crypto import hex_to_field

        announcements = state["announcements"]
        head_epoch = int(state["announcement"]["epoch"])
        roots = {head_epoch: hex_to_field(announcements[head_epoch]["root"])}
        superseded_at = None
        for epoch in sorted((epoch for epoch in announcements if epoch < head_epoch), reverse=True):
            successor_at = announcements[epoch + 1]["announcedAt"]
            superseded_at = (
                successor_at if superseded_at is None else min(superseded_at, successor_at)
            )
            if now - superseded_at > self._max_announcement_age:
                break
            roots[epoch] = hex_to_field(announcements[epoch]["root"])
        return roots

    def _lock_for(self, issuer_id: str, accumulator_id: str):
        """Serialize each read-validate-write of one checkpoint in this process."""
        key = (issuer_id, accumulator_id)
        with self._locks_guard:
            lock = self._locks.get(key)
            if lock is None:
                lock = self._locks[key] = threading.Lock()
            return lock

    def _load_state(self, issuer_id: str, accumulator_id: str, keys: dict):
        """Reconcile this worker's view with the persisted checkpoint.

        The caller holds the (issuer, accumulator) lock. The store is re-read
        on every call, so a head that another worker or thread persisted
        replaces this worker's older view. A persisted head that is missing,
        older than, or different from the view this worker already accepted
        means the store lost or rewrote history, so it fails closed.
        """
        state_key = (issuer_id, accumulator_id)
        accepted = self._states.get(state_key)
        persisted = self._store.load_checkpoint(issuer_id, accumulator_id)
        if persisted is None:
            if accepted is not None:
                raise VerifierCheckpointStoreError(
                    "persisted verifier checkpoint disappeared after it was accepted"
                )
            return None
        if accepted is not None and persisted == accepted["document"]:
            return accepted
        state = self._validated_state(issuer_id, accumulator_id, keys, persisted)
        if accepted is not None:
            accepted_epoch = int(accepted["announcement"]["epoch"])
            retained = state["announcements"].get(accepted_epoch)
            if int(state["announcement"]["epoch"]) < accepted_epoch or (
                retained is not None and retained != accepted["announcement"]
            ):
                raise VerifierCheckpointStoreError(
                    "persisted verifier checkpoint does not extend the accepted view"
                )
        self._states[state_key] = state
        self._issuer_accumulators[issuer_id] = accumulator_id
        return state

    def _validated_state(
        self, issuer_id: str, accumulator_id: str, keys: dict, persisted
    ) -> dict:
        try:
            expected_fields = {
                "version",
                "issuerId",
                "accumulatorId",
                "announcement",
                "announcements",
            }
            if type(persisted) is not dict or set(persisted) != expected_fields:
                raise ValueError("checkpoint shape is invalid")
            if persisted["version"] != CHECKPOINT_VERSION:
                raise ValueError("checkpoint version is invalid")
            if persisted["issuerId"] != issuer_id or persisted["accumulatorId"] != accumulator_id:
                raise ValueError("checkpoint scope is invalid")
            announcement = persisted["announcement"]
            announcements = {
                int(epoch): candidate
                for epoch, candidate in persisted["announcements"].items()
            }
            if not announcements:
                raise ValueError("checkpoint announcement window is empty")
            chain = AnnouncementChain(trusted_keys=keys, accumulator_id=accumulator_id)
            for epoch in sorted(announcements):
                candidate = announcements[epoch]
                if int(candidate["epoch"]) != epoch:
                    raise ValueError("checkpoint announcement epoch is inconsistent")
                if candidate.get("accumulatorId") != accumulator_id:
                    raise ValueError("checkpoint announcement accumulator scope is invalid")
                chain.ingest(candidate)
            epoch = int(announcement["epoch"])
            if chain.last_announcement != announcement or max(announcements) != epoch:
                raise ValueError("checkpoint head is inconsistent")
        except (AnnouncementChainError, KeyError, TypeError, ValueError) as exc:
            raise VerifierCheckpointStoreError(
                "persisted verifier checkpoint is invalid"
            ) from exc
        return {
            "announcement": dict(announcement),
            "announcements": announcements,
            "document": persisted,
        }

    def _retain_fork(
        self, issuer_id: str, accumulator_id: str, error: ChainLinkageError
    ) -> None:
        """Retain the conflicting pair the chain saw, when it is evidence."""
        evidence = equivocation_evidence(error, self._clock())
        if evidence is not None:
            self._store.retain_evidence(issuer_id, accumulator_id, evidence)

    def _chain_ingest(
        self,
        chain: AnnouncementChain,
        issuer_id: str,
        accumulator_id: str,
        candidate: dict,
    ) -> None:
        try:
            chain.ingest(candidate)
        except ChainLinkageError as exc:
            self._retain_fork(issuer_id, accumulator_id, exc)
            raise

    def _advance(
        self,
        issuer_id: str,
        accumulator_id: str,
        keys: dict,
        state,
        announcement: dict,
        history_loader,
    ) -> dict:
        """Validate ``announcement`` against ``state``; return the new window."""
        if state is None:
            chain = AnnouncementChain(trusted_keys=keys, accumulator_id=accumulator_id)
            chain.ingest(announcement)
            # Cold start: the authentic head becomes the local anchor, unless
            # it is a migration checkpoint that local policy does not name.
            require_authorized_anchor(announcement, issuer_id, self._authorized_migrations)
            announcements = {int(announcement["epoch"]): dict(announcement)}
        else:
            checkpoint = state["announcement"]
            chain = AnnouncementChain(
                trusted_keys=keys, checkpoint=checkpoint, accumulator_id=accumulator_id
            )
            announcements = {
                epoch: dict(candidate)
                for epoch, candidate in state["announcements"].items()
            }
            try:
                self._chain_ingest(chain, issuer_id, accumulator_id, announcement)
            except EpochGapError as gap:
                # gap_size is arithmetic; the epoch list exists only within bound.
                if gap.gap_size > self._max_backfill:
                    raise BackfillLimitError(
                        f"gap of {gap.gap_size} announcements exceeds "
                        f"limit {self._max_backfill}; close it with catch_up"
                    ) from gap
                if history_loader is None:
                    raise
                recovered = history_loader(
                    gap.missing_epochs[0], gap.missing_epochs[-1]
                )
                if type(recovered) is not list or [
                    item.get("epoch") if type(item) is dict else None for item in recovered
                ] != gap.missing_epochs:
                    raise AnnouncementMetadataError(
                        "historical backfill is unavailable, incomplete, or unordered"
                    )
                for historical in recovered:
                    self._chain_ingest(chain, issuer_id, accumulator_id, historical)
                    announcements[int(historical["epoch"])] = dict(historical)
                self._chain_ingest(chain, issuer_id, accumulator_id, announcement)
            announcements[int(announcement["epoch"])] = dict(announcement)
        return self._retained_window(announcement, announcements)

    def _retained_window(self, head: dict, announcements: dict) -> dict:
        """Keep the roots inside the effective epoch lag of ``head``."""
        effective_lag = min(self._max_epoch_lag, int(head["maxEpochLag"]))
        floor = int(head["epoch"]) - effective_lag
        return {
            epoch: candidate
            for epoch, candidate in announcements.items()
            if epoch >= floor
        }

    def _commit(
        self,
        issuer_id: str,
        accumulator_id: str,
        state,
        head: dict,
        announcements: dict,
    ) -> None:
        """Compare-and-swap ``head`` over the head ``state`` was validated at.

        The caller holds the (issuer, accumulator) lock. A conflict raises
        ``VerifierCheckpointConflictError`` and leaves this worker's view as
        it was.
        """
        persisted = {
            "version": CHECKPOINT_VERSION,
            "issuerId": issuer_id,
            "accumulatorId": accumulator_id,
            "announcement": dict(head),
            "announcements": {
                str(epoch): candidate
                for epoch, candidate in sorted(announcements.items())
            },
        }
        self._store.compare_and_swap_checkpoint(
            issuer_id,
            accumulator_id,
            None if state is None else state["announcement"],
            persisted,
        )
        self._states[(issuer_id, accumulator_id)] = {
            "announcement": dict(head),
            "announcements": announcements,
            "document": json.loads(json.dumps(persisted)),
        }
        self._issuer_accumulators[issuer_id] = accumulator_id

    def _settled_catch_up(
        self,
        issuer_id: str,
        accumulator_id: str,
        keys: dict,
        state,
        head: dict,
        verified: int,
    ):
        """Return a status unless ``head`` lies ahead of the persisted head.

        A head byte-identical to the persisted head completes the catch-up.
        Any other head at or below it fails exactly as in ``ingest_metadata``:
        a replay, a signed fork (evidence retained), or an authentication
        failure. Returns ``None`` when ``head`` is ahead or nothing is
        persisted yet.
        """
        if state is None:
            return None
        checkpoint = state["announcement"]
        checkpoint_epoch = int(checkpoint["epoch"])
        if head["epoch"] > checkpoint_epoch:
            return None
        if _same_announcement(head, checkpoint):
            return CatchUpStatus(
                issuer_id, accumulator_id, checkpoint_epoch, head["epoch"], verified
            )
        self._advance(issuer_id, accumulator_id, keys, state, head, None)
        # The chain never accepts an epoch at or below its checkpoint.
        raise AnnouncementReplayError(
            f"announcement epoch {head['epoch']} does not advance checkpoint {checkpoint_epoch}"
        )

    def _catch_up_step(
        self,
        issuer_id: str,
        accumulator_id: str,
        keys: dict,
        state: dict,
        head: dict,
        history_loader,
    ):
        """Verify at most ``max_backfill`` announcements past the checkpoint.

        Fetches the next consecutive historical announcements, verifies each
        one's signature, epoch continuity, and predecessor link from the
        persisted head, and ends at ``head`` when it is within reach.
        Historical announcements carry no freshness requirement: their
        signatures and links to the checkpoint authenticate them. Returns the
        new head and its retained window; nothing is persisted here.
        """
        checkpoint = state["announcement"]
        start = int(checkpoint["epoch"])
        target = head["epoch"]
        end = min(target, start + self._max_backfill)
        reaches_head = end == target
        last_historical = end - 1 if reaches_head else end
        expected = list(range(start + 1, last_historical + 1))
        recovered = history_loader(start + 1, last_historical) if expected else []
        if type(recovered) is not list or [
            item.get("epoch") if type(item) is dict else None for item in recovered
        ] != expected:
            raise AnnouncementMetadataError(
                "historical backfill is unavailable, incomplete, or unordered"
            )
        if reaches_head:
            recovered = recovered + [head]
        chain = AnnouncementChain(
            trusted_keys=keys, checkpoint=checkpoint, accumulator_id=accumulator_id
        )
        announcements = {
            epoch: dict(candidate) for epoch, candidate in state["announcements"].items()
        }
        for candidate in recovered:
            self._chain_ingest(chain, issuer_id, accumulator_id, candidate)
            announcements[int(candidate["epoch"])] = dict(candidate)
        new_head = chain.last_announcement
        return new_head, self._retained_window(new_head, announcements)

    def catch_up(self, issuer_id: str, metadata: dict, history_loader) -> CatchUpStatus:
        """Advance the durable checkpoint one bounded step toward the head.

        This is the supported recovery for a checkpoint more than
        ``max_backfill`` epochs behind ``metadata``'s current head. Call it
        until the returned status is ``complete``. Each call re-reads the
        persisted checkpoint, verifies the signatures of at most
        ``max_backfill`` announcements past it (their epoch continuity and
        ``previousAnnouncementHash`` links included), and persists the last
        one with a compare-and-swap. A restart, or another worker, resumes
        from that checkpoint.

        Historical announcements carry no freshness requirement. The head
        keeps the ``max_announcement_age`` rule: it is checked before any
        work, and the head's signature and link are verified by the call
        that reaches it. ``state`` keeps failing closed while the persisted
        head is outside the age limit, so an intermediate checkpoint serves
        roots only while its own announcement is fresh.

        ``history_loader(start_epoch, end_epoch)`` must return that
        inclusive range of historical announcements in order. A forged,
        forked, missing, or reordered announcement fails closed exactly as in
        ``ingest_metadata`` and persists nothing from the step. A head that
        is already the persisted head returns a complete status. If another
        worker advances the checkpoint during the call, the status reports
        that worker's head; the call verifies no second step.

        Without a persisted checkpoint the fresh head becomes the local trust
        anchor, as in ``ingest_metadata``.

        The head's freshness may come from ``revocation.currentLiveness``
        when it names the head, exactly as in ``ingest_metadata``.
        """
        announcement, accumulator_id = self._validate_metadata(issuer_id, metadata)
        target_epoch = announcement.get("epoch")
        if type(target_epoch) is not int or not 0 <= target_epoch < _U64_LIMIT:
            raise AnnouncementMetadataError("announcement epoch is malformed")
        if not callable(history_loader):
            raise ValueError("catch_up requires a history_loader")
        keys = self._keys(issuer_id)
        liveness = self._metadata_liveness(metadata, keys)
        names_head = liveness is not None and liveness_names_head(liveness, announcement)
        self._validate_freshness(announcement, liveness if names_head else None)
        with self._lock_for(issuer_id, accumulator_id):
            state = self._load_state(issuer_id, accumulator_id, keys)
            settled = self._settled_catch_up(
                issuer_id, accumulator_id, keys, state, announcement, 0
            )
            if settled is not None:
                self._require_names_head(liveness, names_head)
                self._retain_liveness(issuer_id, accumulator_id, liveness)
                return settled
            if self._max_backfill == 0:
                raise BackfillLimitError(
                    "catch_up verifies at most max_backfill (0) announcements per call"
                )
            if state is None:
                head = dict(announcement)
                announcements = self._advance(
                    issuer_id, accumulator_id, keys, None, announcement, None
                )
                verified = 1
            else:
                head, announcements = self._catch_up_step(
                    issuer_id, accumulator_id, keys, state, announcement, history_loader
                )
                verified = int(head["epoch"]) - int(state["announcement"]["epoch"])
            self._require_names_head(liveness, names_head)
            try:
                self._commit(issuer_id, accumulator_id, state, head, announcements)
            except VerifierCheckpointConflictError:
                # Another worker committed first. Report the shared head and
                # leave the next step to the next call, which keeps each call
                # within max_backfill signatures.
                state = self._load_state(issuer_id, accumulator_id, keys)
                if state is None:
                    raise
                settled = self._settled_catch_up(
                    issuer_id, accumulator_id, keys, state, announcement, verified
                )
                if settled is not None:
                    self._retain_liveness(issuer_id, accumulator_id, liveness)
                    return settled
                return CatchUpStatus(
                    issuer_id,
                    accumulator_id,
                    int(state["announcement"]["epoch"]),
                    target_epoch,
                    verified,
                )
            if int(head["epoch"]) == target_epoch:
                self._retain_liveness(issuer_id, accumulator_id, liveness)
            return CatchUpStatus(
                issuer_id, accumulator_id, int(head["epoch"]), target_epoch, verified
            )

    def ingest_metadata(self, issuer_id: str, metadata: dict, history_loader=None) -> None:
        """Validate metadata v2 and atomically advance its durable checkpoint.

        The candidate is validated against the persisted head, re-read under
        the (issuer, accumulator) lock, and written with a compare-and-swap
        against that head. An announcement older than the shared head raises
        ``AnnouncementReplayError`` even when this worker's previous view was
        older still.

        ``history_loader(start_epoch, end_epoch)`` is called only for a
        bounded gap and must return every missing announcement in order. A
        gap wider than ``max_backfill`` raises ``BackfillLimitError`` and
        changes nothing; ``catch_up`` closes it in bounded steps.

        Metadata whose head is byte-identical to the persisted head changes
        no checkpoint and raises nothing, so re-polling unchanged metadata is
        a silent no-op. A ``revocation.currentLiveness`` statement is
        verified before anything else is read from the store. When it names
        the head, it extends the head's freshness and is kept for ``state``.
        When it names another head, the head is still classified first (a
        fork keeps its evidence), and then ``LivenessHeadMismatchError``
        refuses the document without persisting anything.
        """
        announcement, accumulator_id = self._validate_metadata(issuer_id, metadata)
        keys = self._keys(issuer_id)
        liveness = self._metadata_liveness(metadata, keys)
        names_head = liveness is not None and liveness_names_head(liveness, announcement)
        self._validate_freshness(announcement, liveness if names_head else None)
        with self._lock_for(issuer_id, accumulator_id):
            for attempt in range(1, _CHECKPOINT_SWAP_ATTEMPTS + 1):
                state = self._load_state(issuer_id, accumulator_id, keys)
                if state is not None and _same_announcement(announcement, state["announcement"]):
                    # Re-polling the persisted head states nothing new.
                    self._require_names_head(liveness, names_head)
                    self._retain_liveness(issuer_id, accumulator_id, liveness)
                    return
                announcements = self._advance(
                    issuer_id, accumulator_id, keys, state, announcement, history_loader
                )
                self._require_names_head(liveness, names_head)
                try:
                    self._commit(
                        issuer_id, accumulator_id, state, announcement, announcements
                    )
                except VerifierCheckpointConflictError:
                    if attempt == _CHECKPOINT_SWAP_ATTEMPTS:
                        raise
                    continue
                self._retain_liveness(issuer_id, accumulator_id, liveness)
                return

    def refresh_from_issuer(self, issuer_id: str, issuer, history_loader=None) -> None:
        """Ingest an issuer adapter's current full metadata document."""
        self.ingest_metadata(issuer_id, issuer.issuer_metadata(), history_loader)

    def state(self, issuer_id: str, accumulator_id: str = None):
        """Return an immutable authenticated state at the persisted head.

        The head is re-read from the shared checkpoint store, so a newer
        checkpoint persisted by another worker is served here too. During a
        ``catch_up`` the persisted head can be an intermediate announcement;
        like any head, it is served only while it passes the age limit.

        The head is fresh while its ``announcedAt``, or the ``issuedAt`` of
        the newest liveness statement this worker verified for exactly that
        head, is within ``max_announcement_age``. The state's ``roots`` hold
        only roots the issuer attested current within that limit (see the
        class docstring), so obtain a state for each verification instead of
        keeping one.
        """
        if accumulator_id is None:
            accumulator_id = self._issuer_accumulators.get(issuer_id)
        if accumulator_id is None:
            raise KeyError(f"no accumulator state cached for issuer {issuer_id}")
        keys = self._keys(issuer_id)
        with self._lock_for(issuer_id, accumulator_id):
            state = self._load_state(issuer_id, accumulator_id, keys)
            liveness = self._liveness.get((issuer_id, accumulator_id))
        if state is None:
            raise KeyError(
                f"no accumulator state cached for issuer {issuer_id} accumulator {accumulator_id}"
            )
        announcement = state["announcement"]
        if liveness is not None and not liveness_names_head(liveness, announcement):
            # The persisted head moved on (possibly through another worker).
            liveness = None
        now = int(self._clock())
        self._validate_freshness(announcement, liveness, now)
        return _authenticated_accumulator_state(
            current_epoch=int(announcement["epoch"]),
            roots=self._servable_roots(state, now),
            accumulator_id=accumulator_id,
            max_epoch_lag=min(self._max_epoch_lag, int(announcement["maxEpochLag"])),
            checkpoint_hash=announcement_hash(announcement),
        )

    def accumulator_state_results(self) -> dict:
        """Per-issuer outcome: an authenticated state or the error refusing it.

        Each issuer is evaluated on its own, so one stale or unreadable
        issuer cannot hide another issuer's servable state. An error value
        is the ``AnnouncementChainError`` (for example
        ``AnnouncementFreshnessError``) or ``VerifierCheckpointStoreError``
        that ``state`` raised for that issuer.
        """
        results = {}
        for issuer_id, accumulator_id in list(self._issuer_accumulators.items()):
            try:
                results[issuer_id] = self.state(issuer_id, accumulator_id)
            except (AnnouncementChainError, VerifierCheckpointStoreError) as exc:
                results[issuer_id] = exc
        return results

    def accumulator_states(self) -> dict:
        """Servable authenticated states, ready for ``VerificationRequest``.

        Computed per issuer: an issuer whose state cannot be served (stale,
        or its checkpoint is invalid) is left out, so a proof against it
        fails closed with ``STALE_ACCUMULATOR`` while every other issuer
        keeps verifying. ``accumulator_state_results`` reports why.
        """
        return {
            issuer_id: result
            for issuer_id, result in self.accumulator_state_results().items()
            if not isinstance(result, Exception)
        }

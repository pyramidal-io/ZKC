"""Holder-side witness refresh and shared signed-announcement verification."""

from __future__ import annotations

import json
import threading
import time

from zkc_crypto import compute_merkle_root, field_to_hex
from zkc_holder.accumulator import AccumulatorProvider
from zkc_holder.credential import AccumulatorWitness
from zkc_holder.errors import StaleWitnessError
from zkc_issuer.errors import AdapterError

from .chain import (
    AnnouncementChain,
    AnnouncementChainError,
    ChainLinkageError,
    EpochGapError,
    equivocation_evidence,
    liveness_names_head,
    require_authorized_anchor,
    validate_announcement_key_pins,
    validate_authorized_migrations,
    verify_liveness_statement,
)
from .checkpoint import (
    VerifierCheckpointConflictError,
    VerifierCheckpointStore,
    VerifierCheckpointStoreError,
)
from .service import WITNESS_UPDATE_REQUEST, announcement_hash, apply_witness_delta

__all__ = ["WitnessUpdateProvider"]


HOLDER_CHECKPOINT_VERSION = "zkc:holder-revocation-checkpoint:v1"
_HOLDER_CHECKPOINT_SCOPE_PREFIX = "zkc:holder-witness:"
# A compare-and-swap fails only when another holder committed a different
# head between this provider's re-read and its write; retry from that head.
_CHECKPOINT_SWAP_ATTEMPTS = 3


class _SignedWitnessProvider(AccumulatorProvider):
    """Shared signed-announcement and checkpoint policy for holder refresh."""

    def __init__(
        self,
        services: dict,
        issuer_keys: dict,
        *,
        checkpoint_store: VerifierCheckpointStore,
        max_backfill: int = 32,
        max_announcement_age: int = 3600,
        max_clock_skew: int = 300,
        clock=time.time,
        accumulator_ids: dict = None,
        authorized_migrations=(),
    ):
        """Map issuers to local services or (source, pinned accumulator id).

        Each issuer needs an explicit, holder-local accumulator-id pin:
        ``accumulator_ids={issuer_id: accumulator_id}``, or the id in a
        ``(source, accumulator_id)`` target. When both are given they must
        agree. A service object's own ``accumulator_id`` is never the pin; a
        service, response, or announcement that names another accumulator is
        rejected with ``ACCUMULATOR_ID_MISMATCH``.

        Issuer keys map each issuer id to pre-pinned signing-key ids and
        their ``AnnouncementKeyPin`` (public key, ``notBefore``/``notAfter``
        window, optional ``retireAfterEpoch``); a bare (x, y) pin fails
        closed. A checkpoint store preserves replay and fork history.

        ``authorized_migrations`` is a set of ``(issuer_id, accumulator_id,
        epoch)`` tuples. Without a matching entry, a cold-start head with a
        zero predecessor at an epoch above 0 is refused with
        ``MIGRATION_CHECKPOINT_UNAUTHORIZED``.

        A head is fresh while its ``announcedAt``, or the ``issuedAt`` of a
        verified ``zkc:epoch-liveness:v1`` statement that names exactly that
        head, is within ``max_announcement_age``. Statements come from update
        responses (``liveness``) or from a source's ``current_liveness()``;
        the newest verified one is kept in memory and is never part of the
        checkpoint.
        """
        if not isinstance(checkpoint_store, VerifierCheckpointStore):
            raise ValueError("a verifier checkpoint store is required")
        if type(max_backfill) is not int or max_backfill < 0:
            raise ValueError("max_backfill must be a non-negative integer")
        if type(max_announcement_age) is not int or max_announcement_age < 0:
            raise ValueError("max_announcement_age must be a non-negative integer")
        if type(max_clock_skew) is not int or max_clock_skew < 0:
            raise ValueError("max_clock_skew must be a non-negative integer")
        pins = {} if accumulator_ids is None else accumulator_ids
        if type(pins) is not dict or not set(pins) <= set(services):
            raise ValueError("accumulator_ids must map configured issuer ids to accumulator ids")
        self._services = {}
        for issuer_id, target in services.items():
            accumulator_id = pins.get(issuer_id)
            if isinstance(target, tuple):
                service, target_pin = target
                if accumulator_id is None:
                    accumulator_id = target_pin
                elif target_pin != accumulator_id:
                    raise ValueError("the target's accumulator id contradicts accumulator_ids")
            else:
                service = target
            if not isinstance(accumulator_id, str) or not accumulator_id:
                raise ValueError(
                    "a pinned revocation accumulator id is required "
                    "(accumulator_ids= or a (source, accumulator_id) target)"
                )
            self._services[issuer_id] = (service, accumulator_id)
        self._authorized_migrations = validate_authorized_migrations(authorized_migrations)
        if any(
            issuer_id not in self._services or self._services[issuer_id][1] != accumulator_id
            for issuer_id, accumulator_id, _epoch in self._authorized_migrations
        ):
            raise ValueError("an authorized migration names an accumulator that is not pinned")
        if any(not keys_by_id for keys_by_id in issuer_keys.values()):
            raise ValueError("each issuer requires a pre-pinned revocation announcement key")
        self._issuer_keys = {
            issuer_id: validate_announcement_key_pins(keys_by_id)
            for issuer_id, keys_by_id in issuer_keys.items()
        }
        if set(self._issuer_keys) != set(self._services):
            raise ValueError("service and announcement-key policies must name the same issuers")
        self._checkpoint_store = checkpoint_store
        self._max_backfill = max_backfill
        self._max_announcement_age = max_announcement_age
        self._max_clock_skew = max_clock_skew
        self._clock = clock
        # issuer_id -> (persisted checkpoint document, AnnouncementChain)
        self._chains: dict = {}
        # (issuer_id, accumulator_id) -> newest verified liveness statement
        self._liveness: dict = {}
        self._locks: dict = {}
        self._locks_guard = threading.Lock()

    def _service(self, issuer_id: str):
        target = self._services.get(issuer_id)
        if target is None:
            raise StaleWitnessError(f"no revocation service known for issuer {issuer_id}")
        service, accumulator_id = target
        if getattr(service, "accumulator_id", accumulator_id) != accumulator_id:
            raise StaleWitnessError(
                "[ACCUMULATOR_ID_MISMATCH] revocation service accumulator id does not "
                "match the pinned accumulator"
            )
        return service, accumulator_id

    def current_epoch(self, issuer_id: str) -> int:
        service, accumulator_id = self._service(issuer_id)
        source = self._announcement_source(issuer_id, service)
        announcement = self._current_announcement(source, accumulator_id)
        with self._lock_for(issuer_id, accumulator_id):
            self._ingest_announcement(issuer_id, source, accumulator_id, announcement)
        return announcement["epoch"]

    def _announcement_source(self, issuer_id: str, service):
        return service

    def _current_announcement(self, service, accumulator_id: str) -> dict:
        """Fetch the candidate head without changing the holder checkpoint."""
        try:
            current = getattr(service, "current_announcement", None)
            if current is not None:
                announcement = current()
            else:
                # In-process sources can publish the head through their epoch
                # property and the historical announcement endpoint.
                epoch = service.epoch
                announcement = service.announcement_for_epoch(epoch)
                if self._announcement_epoch(announcement, accumulator_id) != epoch:
                    raise ValueError("current announcement returned the wrong epoch")
        except (RuntimeError, OSError, KeyError, IndexError, TypeError, ValueError) as exc:
            raise StaleWitnessError("current revocation announcement is unavailable") from exc
        return announcement

    @staticmethod
    def _announcement_epoch(announcement, accumulator_id: str) -> int:
        if type(announcement) is dict and announcement.get("accumulatorId") != accumulator_id:
            raise StaleWitnessError(
                "[ACCUMULATOR_ID_MISMATCH] revocation announcement names an accumulator "
                "other than the pinned accumulator"
            )
        if (
            type(announcement) is not dict
            or type(announcement.get("epoch")) is not int
            or not 0 <= announcement["epoch"] < (1 << 64)
            or type(announcement.get("signingKeyId")) is not str
        ):
            raise StaleWitnessError("revocation announcement has invalid identity or epoch")
        return announcement["epoch"]

    @classmethod
    def _response_announcement(cls, response, accumulator_id: str) -> dict:
        if type(response) is dict and response.get("accumulatorId") != accumulator_id:
            raise StaleWitnessError(
                "[ACCUMULATOR_ID_MISMATCH] revocation response names an accumulator "
                "other than the pinned accumulator"
            )
        if type(response) is not dict or type(response.get("epoch")) is not int:
            raise StaleWitnessError("revocation response has invalid identity or epoch")
        announcement = response.get("announcement")
        if (
            cls._announcement_epoch(announcement, accumulator_id) != response["epoch"]
            or announcement.get("root") != response.get("root")
        ):
            raise StaleWitnessError("epoch announcement does not match the response")
        return announcement

    @staticmethod
    def _request_update(service, request: dict, operation: str) -> dict:
        try:
            return service.handle_request(request)
        except (AdapterError, RuntimeError, OSError) as exc:
            # HTTP transport failures are RuntimeError (or a socket error).
            code = getattr(exc, "code", None) or "TRANSPORT_ERROR"
            raise StaleWitnessError(f"revocation service refused the {operation} ({code})") from exc

    @staticmethod
    def checkpoint_scope(accumulator_id: str) -> str:
        """Return the holder-only store scope for an accumulator.

        Verifiers and holders may share one persistence backend, but their
        checkpoint documents retain different history windows. A distinct
        scope prevents either component from overwriting the other's state.
        """
        return f"{_HOLDER_CHECKPOINT_SCOPE_PREFIX}{accumulator_id}"

    def _lock_for(self, issuer_id: str, accumulator_id: str):
        """Serialize each read-validate-write of one holder checkpoint."""
        key = (issuer_id, accumulator_id)
        with self._locks_guard:
            lock = self._locks.get(key)
            if lock is None:
                lock = self._locks[key] = threading.Lock()
            return lock

    def _chain(self, issuer_id: str, accumulator_id: str) -> AnnouncementChain:
        """Return a chain at the persisted holder checkpoint head.

        The caller holds the (issuer, accumulator) lock. The store is re-read
        on every call, so a head another holder thread or process persisted
        replaces this provider's older view; a head that regressed or forked
        from the view this provider accepted fails closed.
        """
        keys = self._issuer_keys[issuer_id]
        store_scope = self.checkpoint_scope(accumulator_id)
        try:
            checkpoint = self._checkpoint_store.load_checkpoint(issuer_id, store_scope)
        except VerifierCheckpointStoreError as exc:
            raise StaleWitnessError("revocation checkpoint store read failed") from exc
        accepted = self._chains.get(issuer_id)
        if accepted is not None and checkpoint == accepted[0]:
            return accepted[1]
        if checkpoint is not None and (
            type(checkpoint) is not dict
            or checkpoint.get("version") != HOLDER_CHECKPOINT_VERSION
            or checkpoint.get("issuerId") != issuer_id
            or checkpoint.get("accumulatorId") != accumulator_id
        ):
            raise StaleWitnessError("persisted revocation checkpoint is invalid")
        announcement = None if checkpoint is None else checkpoint.get("announcement")
        if checkpoint is not None:
            self._announcement_epoch(announcement, accumulator_id)
        try:
            chain = AnnouncementChain(
                trusted_keys=keys, checkpoint=announcement, accumulator_id=accumulator_id
            )
        except AnnouncementChainError as exc:
            raise StaleWitnessError(str(exc)) from exc
        previous = None if accepted is None else accepted[1]
        if previous is not None and previous.last_epoch is not None and (
            chain.last_epoch is None
            or chain.last_epoch < previous.last_epoch
            or (
                chain.last_epoch == previous.last_epoch
                and chain.last_hash != previous.last_hash
            )
        ):
            raise StaleWitnessError(
                "persisted revocation checkpoint does not extend the accepted view"
            )
        self._chains[issuer_id] = (checkpoint, chain)
        return chain

    def _retain_fork(self, issuer_id, accumulator_id, error: ChainLinkageError) -> None:
        """Retain the conflicting pair the chain saw, when it is evidence."""
        evidence = equivocation_evidence(error, self._clock())
        if evidence is None:
            return
        try:
            self._checkpoint_store.retain_evidence(
                issuer_id, self.checkpoint_scope(accumulator_id), evidence
            )
        except VerifierCheckpointStoreError as exc:
            raise StaleWitnessError(
                "revocation checkpoint store evidence write failed"
            ) from exc

    def _advanced_chain(
        self, issuer_id, service, accumulator_id, retained, announcement
    ) -> AnnouncementChain:
        """Validate ``announcement`` (with bounded backfill) after ``retained``."""
        # Bound the gap before AnnouncementChain materializes the missing epochs.
        if (
            retained.last_epoch is not None
            and announcement["epoch"] - retained.last_epoch - 1 > self._max_backfill
        ):
            raise StaleWitnessError(
                "[ANNOUNCEMENT_BACKFILL_LIMIT_EXCEEDED] epoch gap exceeds policy"
            )
        keys = self._issuer_keys[issuer_id]
        chain = AnnouncementChain(
            trusted_keys=keys,
            checkpoint=retained.last_announcement,
            accumulator_id=accumulator_id,
        )
        try:
            try:
                chain.ingest(announcement)
            except EpochGapError as gap:
                for missing_epoch in gap.missing_epochs:
                    candidate = service.announcement_for_epoch(missing_epoch)
                    if self._announcement_epoch(candidate, accumulator_id) != missing_epoch:
                        raise ValueError("historical announcement returned the wrong epoch")
                    chain.ingest(candidate)
                chain.ingest(announcement)
            if retained.last_epoch is None:
                # Cold start: the authentic head becomes the local anchor,
                # unless it is a migration checkpoint policy does not name.
                require_authorized_anchor(
                    announcement, issuer_id, self._authorized_migrations
                )
        except ChainLinkageError as exc:
            self._retain_fork(issuer_id, accumulator_id, exc)
            raise StaleWitnessError(str(exc)) from exc
        except AnnouncementChainError as exc:
            raise StaleWitnessError(str(exc)) from exc
        except (RuntimeError, OSError, KeyError, IndexError, TypeError, ValueError) as exc:
            raise StaleWitnessError(
                f"historical announcement backfill failed ({type(exc).__name__})"
            ) from exc
        return chain

    def _is_fresh(self, announcement: dict, liveness=None) -> bool:
        """``liveness``, when given, is verified and names ``announcement``."""
        announced_at = announcement.get("announcedAt")
        now = int(self._clock())
        if type(announced_at) is not int or announced_at > now + self._max_clock_skew:
            return False
        attested_at = announced_at
        if liveness is not None:
            attested_at = max(attested_at, liveness["issuedAt"])
        return now - attested_at <= self._max_announcement_age

    def _require_fresh(self, announcement: dict, liveness=None) -> None:
        if not self._is_fresh(announcement, liveness):
            raise StaleWitnessError("[ANNOUNCEMENT_STALE] announcement is outside age policy")

    def _authentic_liveness(self, issuer_id: str, liveness) -> dict:
        """Verify a liveness statement under the issuer's pins; fail closed."""
        try:
            verified = verify_liveness_statement(liveness, self._issuer_keys[issuer_id])
        except AnnouncementChainError as exc:
            raise StaleWitnessError(str(exc)) from exc
        if verified["issuedAt"] > int(self._clock()) + self._max_clock_skew:
            raise StaleWitnessError(
                "[ANNOUNCEMENT_STALE] liveness statement time is in the future"
            )
        return verified

    def _retain_liveness(self, issuer_id: str, accumulator_id: str, liveness: dict) -> None:
        """Keep the newest verified statement; it vouches only for its own head."""
        key = (issuer_id, accumulator_id)
        retained = self._liveness.get(key)
        if (
            retained is None
            or retained["headHash"] != liveness["headHash"]
            or liveness["issuedAt"] > retained["issuedAt"]
        ):
            self._liveness[key] = liveness

    def _source_liveness(self, issuer_id, service, accumulator_id, head):
        """A verified statement for ``head`` from ``service.current_liveness``.

        Returns ``None`` when the source publishes none, cannot attest now,
        or has already moved to another head. A statement that fails
        verification raises ``StaleWitnessError``.
        """
        current = getattr(service, "current_liveness", None)
        if not callable(current):
            return None
        try:
            candidate = current()
        except (AdapterError, RuntimeError, OSError, KeyError, TypeError, ValueError):
            return None
        liveness = self._authentic_liveness(issuer_id, candidate)
        if not liveness_names_head(liveness, head):
            return None
        self._retain_liveness(issuer_id, accumulator_id, liveness)
        return liveness

    def _require_fresh_head(self, issuer_id, service, accumulator_id, head) -> None:
        """Raise ``ANNOUNCEMENT_STALE`` unless ``head`` was attested recently.

        Uses the head's ``announcedAt``, then a kept statement that names the
        head, then one fetched from the source.
        """
        retained = self._liveness.get((issuer_id, accumulator_id))
        if retained is not None and not liveness_names_head(retained, head):
            retained = None
        if self._is_fresh(head, retained):
            return
        fetched = self._source_liveness(issuer_id, service, accumulator_id, head)
        self._require_fresh(head, fetched)

    @staticmethod
    def _require_liveness_names_head(names_head: bool) -> None:
        if not names_head:
            raise StaleWitnessError(
                "[LIVENESS_HEAD_MISMATCH] liveness statement does not name the "
                "announcement it was served with"
            )

    @staticmethod
    def _response_liveness(response: dict):
        """The optional liveness statement of an update response."""
        return response.get("liveness")

    def _persist_checkpoint(self, issuer_id, accumulator_id, retained, chain) -> None:
        """Save a verified extension and update the caller's locked chain view."""
        checkpoint = {
            "version": HOLDER_CHECKPOINT_VERSION,
            "issuerId": issuer_id,
            "accumulatorId": accumulator_id,
            "announcement": chain.last_announcement,
            "announcements": {str(chain.last_epoch): chain.last_announcement},
        }
        self._checkpoint_store.compare_and_swap_checkpoint(
            issuer_id,
            self.checkpoint_scope(accumulator_id),
            retained.last_announcement,
            checkpoint,
        )
        self._chains[issuer_id] = (json.loads(json.dumps(checkpoint)), chain)

    def _ingest_announcement(
        self, issuer_id, service, accumulator_id, announcement, liveness=None
    ) -> None:
        """Advance the durable holder checkpoint; the caller holds the lock.

        ``liveness`` is the statement a response carried with
        ``announcement``, if any. It is verified first. When it names the
        announcement it may make the head fresh; when it names another head,
        the announcement is still classified by the chain (a fork keeps its
        evidence) and the refresh then fails with ``LIVENESS_HEAD_MISMATCH``
        before anything is persisted. An announcement equal to the persisted
        head changes nothing.
        """
        epoch = self._announcement_epoch(announcement, accumulator_id)
        names_head = True
        if liveness is not None:
            liveness = self._authentic_liveness(issuer_id, liveness)
            names_head = liveness_names_head(liveness, announcement)
            if names_head:
                self._retain_liveness(issuer_id, accumulator_id, liveness)
        self._require_fresh_head(issuer_id, service, accumulator_id, announcement)
        try:
            candidate_hash = announcement_hash(announcement)
        except (TypeError, ValueError) as exc:
            raise StaleWitnessError(
                "[ANNOUNCEMENT_AUTHENTICATION_FAILED] malformed epoch announcement"
            ) from exc
        for attempt in range(1, _CHECKPOINT_SWAP_ATTEMPTS + 1):
            retained = self._chain(issuer_id, accumulator_id)
            if retained.last_epoch == epoch and retained.last_hash == candidate_hash:
                self._require_liveness_names_head(names_head)
                return
            chain = self._advanced_chain(issuer_id, service, accumulator_id, retained, announcement)
            self._require_liveness_names_head(names_head)
            try:
                self._persist_checkpoint(issuer_id, accumulator_id, retained, chain)
            except VerifierCheckpointConflictError as exc:
                if attempt < _CHECKPOINT_SWAP_ATTEMPTS:
                    continue
                raise StaleWitnessError(
                    "revocation checkpoint store write conflicted with another holder"
                ) from exc
            except VerifierCheckpointStoreError as exc:
                raise StaleWitnessError("revocation checkpoint store write failed") from exc
            return


class WitnessUpdateProvider(_SignedWitnessProvider):
    """Delta-aware holder provider that sends the credential id on each refresh."""

    def __init__(self, services: dict, issuer_keys: dict, **policy):
        super().__init__(services, issuer_keys, **policy)
        # (issuer_id, credential_id) -> last verified witness in wire format.
        self._cached: dict = {}
        self.refresh_modes: list = []

    def witness(self, issuer_id: str, credential_id: int) -> AccumulatorWitness:
        service, accumulator_id = self._service(issuer_id)
        cache_key = (issuer_id, credential_id)
        cached = self._cached.get(cache_key)
        request = {
            "type": WITNESS_UPDATE_REQUEST,
            "accumulatorId": accumulator_id,
            "credentialId": field_to_hex(credential_id),
        }
        if cached is not None:
            request["fromEpoch"] = cached["accumulatorEpoch"]
        response = self._request_update(service, request, "witness update")
        announcement = self._response_announcement(response, accumulator_id)

        try:
            mode = response["mode"]
            if mode == "delta":
                delta = response["witnessDelta"]
                if (
                    cached is None
                    or type(delta.get("fromEpoch")) is not int
                    or delta["fromEpoch"] != cached["accumulatorEpoch"]
                ):
                    raise ValueError("witness delta does not match the cached epoch")
                witness_data = apply_witness_delta(cached, response)
            elif mode == "full":
                witness_data = response["witness"]
            else:
                raise ValueError("unrecognized witness refresh mode")

            witness = AccumulatorWitness.from_dict(witness_data)
            if (
                type(witness_data["pathIndex"]) is not int
                or type(witness_data["accumulatorEpoch"]) is not int
                or witness.accumulator_epoch != response["epoch"]
                or witness_data["accumulatorRoot"] != response["root"]
                or compute_merkle_root(credential_id, witness.path_index, witness.siblings)
                != witness.accumulator_root
            ):
                raise ValueError("witness does not match the announced root and epoch")
        except (AttributeError, KeyError, IndexError, OverflowError, TypeError, ValueError) as exc:
            raise StaleWitnessError("invalid refreshed revocation witness") from exc

        with self._lock_for(issuer_id, accumulator_id):
            self._ingest_announcement(
                issuer_id, service, accumulator_id, announcement,
                self._response_liveness(response),
            )
            self._cached[cache_key] = witness.to_dict()
            self.refresh_modes.append(mode)
        return witness

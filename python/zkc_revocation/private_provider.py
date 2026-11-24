"""Credential-anonymous witness refresh (metadata-leakage mitigation).

The per-credential witness-update protocol necessarily tells the revocation
service WHICH credential is refreshing — query metadata that links a
credential to a holder session over time. ``PrivateWitnessProvider`` removes
that channel: it fetches the full leaf set every time using
``zkc:epoch-delta-request:v1`` with only the accumulator id, reconstructs the
accumulator locally, and computes its own witness. It accepts only the exact
signed head also observed at a holder-independent announcement source.
Network and timing correlation and split views at the announcement source
remain possible (see docs/zkc_metadata_leakage_threat_model.md).

Every refresh is verified against the issuer-signed epoch announcement
(signature + root), using mandatory pre-pinned issuer keys, bounded gap
backfill, freshness policy, and a durable checkpoint/evidence store. The
holder checkpoint is monotonic: each refresh re-reads it under a
per-(issuer, accumulator) lock and writes it with a compare-and-swap, so
holder threads or processes sharing a store cannot move it backwards."""

from __future__ import annotations

import time

from zkc_crypto import (
    MERKLE_DEPTH,
    SparseMerkleAccumulator,
    canonical_hex_to_field,
    field_to_hex,
)
from zkc_holder.credential import AccumulatorWitness
from zkc_holder.errors import StaleWitnessError

from .chain import AnnouncementChain, AnnouncementChainError, ChainLinkageError
from .checkpoint import (
    CatchUpStatus,
    VerifierCheckpointConflictError,
    VerifierCheckpointStore,
    VerifierCheckpointStoreError,
)
from .provider import _SignedWitnessProvider
from .service import EPOCH_DELTA_REQUEST, announcement_hash

__all__ = ["PrivateWitnessProvider"]


def _announcement_hash_or_none(announcement):
    """Complete hash of an unauthenticated announcement; ``None`` if malformed."""
    try:
        return announcement_hash(announcement)
    except (TypeError, ValueError):
        return None


def _leaf_slot_limit(epoch: int, migrated_slots: int = 0) -> int:
    """Most leaf slots an accumulator at ``epoch`` can have.

    Genesis has no slot, and each epoch appends at most one (a registration,
    or the new half of a replace; a revocation only zeroes a slot). Trailing
    zero slots leave the root unchanged, so this bound, not the root check,
    stops a relay from padding the leaf set. ``migrated_slots`` is the
    local allowance for an authorized legacy migration checkpoint that
    started with more slots than its epoch.
    """
    return min(epoch + migrated_slots, 1 << MERKLE_DEPTH)


def _decode_leaves(wire_leaves, limit: int) -> list:
    """Decode canonical wire leaves; refuse the list by size before allocating."""
    if type(wire_leaves) is not list or len(wire_leaves) > limit:
        raise ValueError("leaf set is malformed or larger than its signed epoch allows")
    return [canonical_hex_to_field(leaf) for leaf in wire_leaves]


class PrivateWitnessProvider(_SignedWitnessProvider):
    """Compute witnesses locally from verified accumulator state.

    Pass local leaf services by issuer id with ``accumulator_ids=``, or
    (RevocationServiceClient, pinned accumulator id) pairs for HTTP; the
    accumulator id is always a holder-local pin, never read from the service.
    For each issuer, also configure a trusted
    publication source with ``current_announcement()`` and
    ``announcement_for_epoch(epoch)``. It must serve a common view independently
    of the leaf service and holder session. A trusted in-process issuer can
    serve both roles when it provides that common view directly.

    A leaf set is refused before it is decoded when it has more slots than
    its signed epoch allows (one per epoch since genesis). An accumulator
    whose authorized legacy migration checkpoint started with more slots
    than its epoch needs ``migrated_leaf_slots={issuer_id: extra_slots}``.
    """

    def __init__(
        self,
        services: dict,
        issuer_keys: dict,
        *,
        announcement_sources: dict,
        checkpoint_store: VerifierCheckpointStore,
        max_backfill: int = 32,
        max_announcement_age: int = 3600,
        max_clock_skew: int = 300,
        clock=time.time,
        migrated_leaf_slots: dict = None,
        accumulator_ids: dict = None,
        authorized_migrations=(),
    ):
        super().__init__(
            services,
            issuer_keys,
            checkpoint_store=checkpoint_store,
            max_backfill=max_backfill,
            max_announcement_age=max_announcement_age,
            max_clock_skew=max_clock_skew,
            clock=clock,
            accumulator_ids=accumulator_ids,
            authorized_migrations=authorized_migrations,
        )
        if set(announcement_sources) != set(self._services):
            raise ValueError("each issuer requires an independent announcement source")
        for source in announcement_sources.values():
            if not (
                callable(getattr(source, "current_announcement", None))
                and callable(getattr(source, "announcement_for_epoch", None))
            ):
                raise ValueError("announcement sources must publish current and historical heads")
        self._announcement_sources = dict(announcement_sources)
        migrated = dict(migrated_leaf_slots or {})
        if not set(migrated) <= set(self._services) or any(
            type(slots) is not int or slots < 0 for slots in migrated.values()
        ):
            raise ValueError(
                "migrated_leaf_slots maps configured issuers to non-negative integers"
            )
        self._migrated_leaf_slots = migrated
        self.sent_requests: list = []

    def _announcement_source(self, issuer_id: str, service):
        return self._announcement_sources[issuer_id]

    def _settled_catch_up(self, issuer_id, source, accumulator_id, retained, head, verified):
        """Return a status unless ``head`` lies ahead of the holder checkpoint.

        A head byte-identical to the persisted head completes the catch-up.
        Any other head at or below it fails as a witness refresh fails: a
        replay, a signed fork (evidence retained), or an authentication
        failure. Returns ``None`` when ``head`` is ahead or nothing is
        persisted yet.
        """
        if retained.last_epoch is None or head["epoch"] > retained.last_epoch:
            return None
        if retained.last_hash == _announcement_hash_or_none(head):
            return CatchUpStatus(
                issuer_id,
                accumulator_id,
                retained.last_epoch,
                head["epoch"],
                verified,
            )
        self._advanced_chain(issuer_id, source, accumulator_id, retained, head)
        # The chain never accepts an epoch at or below its checkpoint.
        raise StaleWitnessError(
            "[ANNOUNCEMENT_REPLAY] announcement does not advance the holder checkpoint"
        )

    def _catch_up_chain(
        self, issuer_id, source, accumulator_id, retained, head
    ) -> AnnouncementChain:
        """Verify at most ``max_backfill`` announcements past ``retained``.

        Each historical announcement is fetched by epoch and must verify its
        signature, epoch continuity, and predecessor link from the persisted
        head; none needs to be fresh. The step ends at ``head`` when it is
        within reach. Nothing is persisted here.
        """
        start = retained.last_epoch
        target = head["epoch"]
        end = min(target, start + self._max_backfill)
        # The pin makes a substituted announcement of another accumulator an
        # ACCUMULATOR_ID_MISMATCH, never fork evidence.
        chain = AnnouncementChain(
            trusted_keys=self._issuer_keys[issuer_id],
            checkpoint=retained.last_announcement,
            accumulator_id=accumulator_id,
        )
        try:
            for epoch in range(start + 1, end + 1):
                if epoch == target:
                    candidate = head
                else:
                    candidate = source.announcement_for_epoch(epoch)
                    if (
                        type(candidate) is not dict
                        or type(candidate.get("epoch")) is not int
                        or candidate["epoch"] != epoch
                    ):
                        raise StaleWitnessError(
                            "historical announcement backfill failed (unexpected epoch)"
                        )
                chain.ingest(candidate)
        except ChainLinkageError as exc:
            # The error names the announcement accepted just before the
            # candidate, which mid-step is not the persisted checkpoint.
            self._retain_fork(issuer_id, accumulator_id, exc)
            raise StaleWitnessError(str(exc)) from exc
        except AnnouncementChainError as exc:
            raise StaleWitnessError(str(exc)) from exc
        except (RuntimeError, OSError, KeyError, IndexError, TypeError, ValueError) as exc:
            raise StaleWitnessError(
                f"historical announcement backfill failed ({type(exc).__name__})"
            ) from exc
        return chain

    def catch_up(self, issuer_id: str) -> CatchUpStatus:
        """Advance the holder checkpoint one bounded step toward the head.

        This is the supported recovery when ``witness`` refuses a gap wider
        than ``max_backfill`` (``ANNOUNCEMENT_BACKFILL_LIMIT_EXCEEDED``).
        Call it until the returned status is ``complete``, then refresh the
        witness. Each call fetches the publication source's current announcement,
        re-reads the persisted holder checkpoint, verifies the signatures of
        at most ``max_backfill`` announcements past it (epoch continuity and
        ``previousAnnouncementHash`` links included), and persists the last
        one with a compare-and-swap. A restart, or another holder process,
        resumes from that checkpoint.

        Historical announcements carry no freshness requirement. The current
        head keeps the age rule: it is checked before any work (through its
        ``announcedAt`` or a verified liveness statement that names it), and
        its signature and link are verified by the call that reaches it. The
        request names no credential, and no leaves are fetched.

        A forged, forked, missing, or misnumbered announcement fails closed
        with ``StaleWitnessError`` and persists nothing from the step; a fork
        retains signed evidence as a witness refresh does. If another holder
        advances the checkpoint during the call, the status reports that
        head; the call verifies no second step. Without a persisted
        checkpoint the fresh head becomes the local trust anchor.
        """
        service, accumulator_id = self._service(issuer_id)
        source = self._announcement_source(issuer_id, service)
        head = self._current_announcement(source, accumulator_id)
        target_epoch = self._announcement_epoch(head, accumulator_id)
        self._require_fresh_head(issuer_id, source, accumulator_id, head)
        with self._lock_for(issuer_id, accumulator_id):
            retained = self._chain(issuer_id, accumulator_id)
            settled = self._settled_catch_up(issuer_id, source, accumulator_id, retained, head, 0)
            if settled is not None:
                return settled
            if self._max_backfill == 0:
                raise StaleWitnessError(
                    "[ANNOUNCEMENT_BACKFILL_LIMIT_EXCEEDED] catch_up verifies at most "
                    "max_backfill (0) announcements per call"
                )
            if retained.last_epoch is None:
                chain = self._advanced_chain(issuer_id, source, accumulator_id, retained, head)
                verified = 1
            else:
                chain = self._catch_up_chain(issuer_id, source, accumulator_id, retained, head)
                verified = chain.last_epoch - retained.last_epoch
            try:
                self._persist_checkpoint(issuer_id, accumulator_id, retained, chain)
            except VerifierCheckpointConflictError as exc:
                # Another holder committed first. Report the shared head and
                # leave the next step to the next call, which keeps each call
                # within max_backfill signatures.
                retained = self._chain(issuer_id, accumulator_id)
                settled = self._settled_catch_up(
                    issuer_id, source, accumulator_id, retained, head, verified
                )
                if settled is not None:
                    return settled
                if retained.last_epoch is None:
                    raise StaleWitnessError(
                        "revocation checkpoint store write conflicted with another holder"
                    ) from exc
                return CatchUpStatus(
                    issuer_id, accumulator_id, retained.last_epoch, target_epoch, verified
                )
            except VerifierCheckpointStoreError as exc:
                raise StaleWitnessError("revocation checkpoint store write failed") from exc
            return CatchUpStatus(
                issuer_id, accumulator_id, chain.last_epoch, target_epoch, verified
            )

    def _authenticated_epoch(self, issuer_id: str, announcement: dict) -> int:
        """Signature and key window of a head, checked before O(leaves) work.

        Costs one signature check and persists nothing; the chain, link and
        freshness checks still run when the head is ingested. A relay
        without the issuer key cannot raise the epoch that bounds the leaf
        set this provider will decode and hash.
        """
        try:
            AnnouncementChain(trusted_keys=self._issuer_keys[issuer_id], checkpoint=announcement)
        except AnnouncementChainError as exc:
            raise StaleWitnessError(str(exc)) from exc
        return announcement["epoch"]

    def _sync(self, issuer_id: str) -> tuple[SparseMerkleAccumulator, int, int]:
        """Fetch full state and bind it to the independently published head."""
        service, accumulator_id = self._service(issuer_id)
        request = {"type": EPOCH_DELTA_REQUEST, "accumulatorId": accumulator_id}
        self.sent_requests.append(dict(request))
        response = self._request_update(service, request, "epoch fetch")
        announcement = self._response_announcement(response, accumulator_id)
        source = self._announcement_source(issuer_id, service)
        published = self._current_announcement(source, accumulator_id)
        self._announcement_epoch(published, accumulator_id)
        published_hash = _announcement_hash_or_none(published)
        if published_hash is None or published_hash != _announcement_hash_or_none(announcement):
            raise StaleWitnessError(
                "[ANNOUNCEMENT_AUTHENTICATION_FAILED] epoch response does not match "
                "the independently published announcement"
            )
        epoch = self._authenticated_epoch(issuer_id, published)

        try:
            if response["mode"] != "full":
                raise ValueError("expected the full accumulator leaf set")
            accumulator = SparseMerkleAccumulator(
                _decode_leaves(
                    response["leaves"],
                    _leaf_slot_limit(epoch, self._migrated_leaf_slots.get(issuer_id, 0)),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StaleWitnessError("invalid revocation epoch response") from exc

        root = accumulator.root()
        if field_to_hex(root) != published["root"]:
            raise StaleWitnessError(
                "reconstructed accumulator does not match the announced root"
            )
        with self._lock_for(issuer_id, accumulator_id):
            # The response's liveness statement must name the published head
            # (the response announcement has the same complete hash).
            self._ingest_announcement(
                issuer_id, source, accumulator_id, published,
                self._response_liveness(response),
            )
        return accumulator, root, epoch

    def witness(self, issuer_id: str, credential_id: int) -> AccumulatorWitness:
        """Locally-computed membership witness; the service never learns
        which credential this is for."""
        accumulator, root, epoch = self._sync(issuer_id)
        try:
            index = accumulator.leaves().index(credential_id)
        except ValueError:
            raise StaleWitnessError(
                "credential is not in the issuer accumulator (revoked or never registered)"
            ) from None
        path_index, siblings = accumulator.witness(index)
        return AccumulatorWitness(
            path_index=path_index,
            siblings=siblings,
            accumulator_root=root,
            accumulator_epoch=epoch,
        )

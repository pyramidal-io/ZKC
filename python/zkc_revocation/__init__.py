"""ZKC revocation accumulator and witness update service (stdlib-only).

Beta accumulator selection
--------------------------
The beta revocation accumulator is the depth-32 Poseidon2 Merkle active set
(``POSEIDON2_MERKLE_ACTIVE_SET``, ``noir/zkc_nonrevocation``), chosen over
RSA/bilinear accumulators because:

1. **Circuit compatibility** — the proving system is BN254/UltraHonk and the
   circuits already verify Poseidon2 Merkle paths natively; an RSA accumulator
   would require non-native bignum arithmetic in-circuit (orders of magnitude
   more constraints).
2. **No extra trusted setup** — RSA accumulators need a trusted modulus.
3. **Servable witness updates** — Merkle witness staleness is local: only
   sibling-path entries change, so the issuer can serve compact deltas.

The trade-off — membership witnesses go stale whenever the accumulator
changes — is bounded by ``MAX_EPOCH_LAG`` (mirrors
``zkc_nonrevocation::MAX_EPOCH_LAG``) and served by this update service.

Components
----------
* ``RevocationAccumulatorService`` — issuer-side accumulator lifecycle
  (register/revoke → new root + epoch), signed epoch announcements, and the
  witness-update wire protocol (in-process ``handle_request``; JSON shapes
  documented there so an HTTP wrapper is trivial).
* ``apply_witness_delta`` — holder-side delta patch.
* ``WitnessUpdateProvider`` — holder ``AccumulatorProvider`` that refreshes
  witnesses through the wire protocol (delta when possible, full otherwise),
  verifying every refreshed witness against the pinned issuer's signed chain.
* ``PrivateWitnessProvider`` — credential-anonymous local or HTTP refresh
  that derives the witness from verified accumulator state.
* ``AnnouncementKeyPin`` — a verifier/holder trust pin: public key plus a
  mandatory ``notBefore``/``notAfter`` window and optional
  ``retireAfterEpoch``; announcements signed outside it fail closed.
* ``VerifierAccumulatorCache`` — verifier-side ingestion of authenticated
  metadata with pre-pinned keys, chained durable checkpoints, bounded
  backfill, freshness validation, and signed-fork evidence retention (the
  actually conflicting same-accumulator, same-key pair only).
* Cold start: a zero-predecessor migration checkpoint at an epoch above 0
  is accepted only when ``authorized_migrations`` names
  ``(issuer_id, accumulator_id, epoch)``.
* ``catch_up`` on ``VerifierAccumulatorCache`` and ``PrivateWitnessProvider``
  — resumable, bounded recovery for a checkpoint more than ``max_backfill``
  epochs behind: each call verifies at most ``max_backfill`` announcements
  past the checkpoint, persists the step, and returns a ``CatchUpStatus``.
* Head liveness (``zkc:epoch-liveness:v1``) — a signed statement that the
  issuer's head is still current. It keeps a quiet issuer's unchanged head
  fresh without a new epoch and is never fork evidence. Consumers time out
  every root, current or superseded, ``max_announcement_age`` after the
  issuer last attested it, so revocation reaches every consumer within
  ``max_announcement_age + max_clock_skew`` seconds (specification §2.4.2).

ZKA independence: revocation metadata, announcements, and witness updates
carry credential ids, roots, and epochs ONLY — never ZKA addresses, payment
activity, or other wallet material (asserted by schema-level tests).
Revocation affects only future credential-proof acceptance; ZKA note
semantics are out of scope.
"""

from .service import (  # noqa: F401
    ANNOUNCEMENT_VERSION,
    DEFAULT_LIVENESS_INTERVAL,
    EPOCH_DELTA_REQUEST,
    EPOCH_DELTA_RESPONSE,
    GENESIS_ANNOUNCEMENT_HASH,
    LIVENESS_VERSION,
    WITNESS_UPDATE_REQUEST,
    WITNESS_UPDATE_RESPONSE,
    RevocationAccumulatorService,
    announcement_hash,
    announcement_transcript,
    apply_witness_delta,
    complete_announcement_bytes,
    compute_announcement_digest,
    compute_liveness_digest,
    liveness_transcript,
    verify_epoch_announcement,
    verify_epoch_liveness,
)
from .chain import (  # noqa: F401
    AccumulatorIdMismatchError,
    AnnouncementAuthenticationError,
    AnnouncementChain,
    AnnouncementChainError,
    AnnouncementKeyPin,
    AnnouncementKeyWindowError,
    AnnouncementReplayError,
    ChainLinkageError,
    EpochGapError,
    LivenessHeadMismatchError,
    MigrationCheckpointUnauthorizedError,
    liveness_names_head,
    validate_announcement_key_pins,
    verify_liveness_statement,
)
from .provider import WitnessUpdateProvider  # noqa: F401
from .private_provider import PrivateWitnessProvider  # noqa: F401
from .cache import (  # noqa: F401
    AnnouncementFreshnessError,
    AnnouncementMetadataError,
    BackfillLimitError,
    VerifierAccumulatorCache,
)
from .checkpoint import (  # noqa: F401
    CatchUpStatus,
    InMemoryVerifierCheckpointStore,
    SQLiteVerifierCheckpointStore,
    VerifierCheckpointConflictError,
    VerifierCheckpointStore,
    VerifierCheckpointStoreError,
)
from .store import (  # noqa: F401
    AccumulatorStateStore,
    AccumulatorStoreError,
    InMemoryAccumulatorStateStore,
    SQLiteAccumulatorStateStore,
)
from .durable import DurableRevocationAccumulatorService  # noqa: F401

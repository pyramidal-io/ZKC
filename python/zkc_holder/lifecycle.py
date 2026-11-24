"""Holder credential lifecycle management (expiry + revocation freshness).

Production holders must not discover staleness at proof time. This module
makes lifecycle state explicit and refresh PROACTIVE:

States (see docs/zkc_credential_lifecycle.md for the diagram):

- ``FRESH``    — proof generation will succeed; no action needed.
- ``AGING``    — still usable, action recommended: the witness epoch lag has
  entered the refresh margin (refresh before it crosses ``MAX_EPOCH_LAG``),
  or the credential expiry is inside the expiry margin (plan renewal).
- ``STALE``    — proofs WILL be rejected until the witness is refreshed
  (lag exceeded ``MAX_EPOCH_LAG``); recoverable via witness refresh.
- ``UNUSABLE`` — not recoverable by refresh: the credential is expired,
  revoked, or has no witness source — renewal/re-issuance is required.

``RefreshPolicy`` is a pure scheduling computation (no daemon, no threads):
``LifecycleManager.tick(now)`` assesses every stored credential, refreshes
witnesses that are due, and reports — the caller decides when to tick
(cron, event loop, before a proof session, …).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .accumulator import MAX_EPOCH_LAG
from .errors import StaleWitnessError

__all__ = [
    "STATE_FRESH",
    "STATE_AGING",
    "STATE_STALE",
    "STATE_UNUSABLE",
    "RefreshPolicy",
    "CredentialHealth",
    "TickReport",
    "LifecycleManager",
    "assess_credential",
]

STATE_FRESH = "fresh"
STATE_AGING = "aging"
STATE_STALE = "stale"
STATE_UNUSABLE = "unusable"

_STATE_SEVERITY = {STATE_FRESH: 0, STATE_AGING: 1, STATE_STALE: 2, STATE_UNUSABLE: 3}


@dataclass(frozen=True)
class RefreshPolicy:
    """Pure refresh-scheduling thresholds.

    - ``refresh_margin_epochs``: refresh a witness once its lag reaches
      ``MAX_EPOCH_LAG - refresh_margin_epochs`` (refresh BEFORE staleness,
      not after rejection).
    - ``expiry_margin_seconds``: surface expiry (AGING) this far ahead so
      renewal can be planned before the credential dies.
    """

    refresh_margin_epochs: int = 3
    expiry_margin_seconds: int = 7 * 86_400
    max_epoch_lag: int = MAX_EPOCH_LAG

    def __post_init__(self):
        if not 0 <= self.refresh_margin_epochs <= self.max_epoch_lag:
            raise ValueError(
                "refresh_margin_epochs must be within [0, max_epoch_lag]"
            )
        if self.expiry_margin_seconds < 0:
            raise ValueError("expiry_margin_seconds must be non-negative")

    @property
    def refresh_due_lag(self) -> int:
        """Witness lag at which a refresh becomes due."""
        return self.max_epoch_lag - self.refresh_margin_epochs

    def next_refresh_epoch(self, witness_epoch: int) -> int:
        """The issuer epoch at which a witness from `witness_epoch` is due."""
        return witness_epoch + self.refresh_due_lag


@dataclass(frozen=True)
class CredentialHealth:
    """Lifecycle assessment of one stored credential."""

    credential_id: int
    issuer_id: str
    proof_type: str
    state: str
    reasons: tuple = ()
    witness_lag: int = None  # None when no witness / no epoch view
    expires_in: int = None  # seconds; None for non-expiring credentials
    refresh_due: bool = False
    renewal_required: bool = False

    def to_dict(self) -> dict:
        return {
            "issuerId": self.issuer_id,
            "proofType": self.proof_type,
            "state": self.state,
            "reasons": list(self.reasons),
            "witnessLag": self.witness_lag,
            "expiresIn": self.expires_in,
            "refreshDue": self.refresh_due,
            "renewalRequired": self.renewal_required,
        }


def assess_credential(credential, current_epoch, now: int, policy: RefreshPolicy) -> CredentialHealth:
    """Pure lifecycle assessment (no I/O, no refresh side effects)."""
    state = STATE_FRESH
    reasons = []
    refresh_due = False
    renewal_required = False

    def worsen(new_state, reason):
        nonlocal state
        reasons.append(reason)
        if _STATE_SEVERITY[new_state] > _STATE_SEVERITY[state]:
            state = new_state

    # Expiry axis.
    expires_in = None
    if credential.expires_at:
        expires_in = int(credential.expires_at) - int(now)
        if expires_in <= 0:
            renewal_required = True
            worsen(STATE_UNUSABLE, "credential expired (renewal required)")
        elif expires_in <= policy.expiry_margin_seconds:
            renewal_required = True
            worsen(STATE_AGING, "credential expires within the expiry margin (plan renewal)")

    # Revocation-freshness axis.
    witness_lag = None
    if credential.witness is None:
        worsen(STATE_UNUSABLE, "credential has no non-revocation witness")
    elif current_epoch is None:
        worsen(STATE_AGING, "issuer epoch view unavailable; freshness unknown")
        refresh_due = True
    else:
        witness_lag = int(current_epoch) - int(credential.witness.accumulator_epoch)
        if witness_lag > policy.max_epoch_lag:
            refresh_due = True
            worsen(
                STATE_STALE,
                f"witness lag {witness_lag} exceeds MAX_EPOCH_LAG "
                f"{policy.max_epoch_lag} (proofs will be rejected until refresh)",
            )
        elif witness_lag >= policy.refresh_due_lag:
            refresh_due = True
            worsen(STATE_AGING, f"witness lag {witness_lag} is inside the refresh margin")

    return CredentialHealth(
        credential_id=credential.credential_id,
        issuer_id=credential.issuer_id,
        proof_type=credential.proof_type,
        state=state,
        reasons=tuple(reasons),
        witness_lag=witness_lag,
        expires_in=expires_in,
        refresh_due=refresh_due,
        renewal_required=renewal_required,
    )


@dataclass
class TickReport:
    """Outcome of one lifecycle tick."""

    assessed: list = field(default_factory=list)  # CredentialHealth (pre-refresh)
    # (issuer_id, credential_id): credential ids are unique only per issuer.
    refreshed: list = field(default_factory=list)
    # {"issuerId", "credentialId", "reason"}; to_dict omits credentialId so a
    # serialized report never carries a revocation handle.
    refresh_failed: list = field(default_factory=list)
    renewal_required: list = field(default_factory=list)  # CredentialHealth

    def to_dict(self) -> dict:
        return {
            "assessed": [health.to_dict() for health in self.assessed],
            "refreshedCount": len(self.refreshed),
            "refreshFailed": [
                {"issuerId": entry["issuerId"], "reason": entry["reason"]}
                for entry in self.refresh_failed
            ],
            "renewalRequired": [health.to_dict() for health in self.renewal_required],
        }


class LifecycleManager:
    """Tick-driven lifecycle upkeep for a holder's credential store.

    ``client`` is a :class:`zkc_holder.HolderClient`; ``provider`` is its
    accumulator provider (used only for the current-epoch view). There is no
    daemon: the embedding application calls :meth:`tick`.
    """

    def __init__(self, client, provider, policy: RefreshPolicy = None):
        self._client = client
        self._provider = provider
        self.policy = policy if policy is not None else RefreshPolicy()

    def _current_epoch(self, issuer_id: str):
        if self._provider is None:
            return None
        try:
            return self._provider.current_epoch(issuer_id)
        except Exception:
            return None

    def assess(self, now: int) -> list:
        """Assess every stored credential (pure; no refreshes)."""
        return [
            assess_credential(
                credential, self._current_epoch(credential.issuer_id), now, self.policy
            )
            for credential in self._client.list_credentials()
        ]

    def tick(self, now: int) -> TickReport:
        """One upkeep pass: assess, refresh due witnesses, report renewals.

        Refreshes are attempted for every credential whose witness is due
        (AGING-by-lag or STALE). A refresh refusal from the issuer
        (revoked/unknown) marks the credential renewal-required — the
        recover-by-renewal path, never a silent skip.
        """
        report = TickReport()
        for credential in self._client.list_credentials():
            health = assess_credential(
                credential, self._current_epoch(credential.issuer_id), now, self.policy
            )
            report.assessed.append(health)
            if health.renewal_required:
                report.renewal_required.append(health)
            if health.refresh_due and not (
                health.renewal_required and health.state == STATE_UNUSABLE
            ):
                try:
                    self._client.update_witness(
                        credential.credential_id, issuer_id=credential.issuer_id
                    )
                    report.refreshed.append((credential.issuer_id, credential.credential_id))
                except StaleWitnessError as exc:
                    report.refresh_failed.append(
                        {
                            "issuerId": credential.issuer_id,
                            "credentialId": credential.credential_id,
                            "reason": exc.code,
                        }
                    )
                    if health not in report.renewal_required:
                        report.renewal_required.append(health)
        return report

"""Verifier-local trust policy.

There are NO canonical issuers, NO default issuers, and NO recommended
policies (Freedom Safeguard 1 / requirement non-goal): every trusted issuer
is explicit verifier configuration, and an empty policy trusts nobody —
fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Optional

from zkc_crypto.digests import LEGACY_SELECTIVE_DISCLOSURE_PROOF_TYPES, parse_attribute_layout_id
from zkc_crypto.field import hex_to_field
from zkc_crypto.presentation import ANONYMOUS_PROFILE, LINKABLE_PROFILE, SCOPED_PROFILE

__all__ = ["TrustedIssuer", "IssuerAccumulatorState", "VerifierTrustPolicy"]

# Mirrors zkc_nonrevocation::MAX_EPOCH_LAG; a policy may only tighten it.
PROTOCOL_MAX_EPOCH_LAG = 10

# The presentation profiles a v2 envelope may declare. The escrowed
# auditor-linkable profile is out of scope (separate ADR).
_KNOWN_PRESENTATION_PROFILES = (ANONYMOUS_PROFILE, SCOPED_PROFILE, LINKABLE_PROFILE)

# Default accepted v2 presentation profiles (design §6 rule 1): anonymous +
# scoped. LINKABLE corresponds to v1/linkable envelopes: an unset policy keeps
# accepting them for compatibility, while an explicitly configured policy
# accepts them only when it lists LINKABLE.
DEFAULT_ACCEPTED_PROFILES = (ANONYMOUS_PROFILE, SCOPED_PROFILE)


class _DefaultAcceptedProfiles(tuple):
    """Keep an unset policy distinguishable through dataclasses.replace()."""


@dataclass(frozen=True)
class TrustedIssuer:
    issuer_id: str
    public_key_x: bytes
    public_key_y: bytes
    proof_types: tuple
    attribute_layout_id: Optional[str] = None

    def __post_init__(self):
        if len(self.public_key_x) != 32 or len(self.public_key_y) != 32:
            raise ValueError("issuer public key coordinates must be 32 bytes each")
        if not self.proof_types:
            raise ValueError("a trusted issuer must list the proof types it is trusted for")
        if self.attribute_layout_id is not None:
            parse_attribute_layout_id(self.attribute_layout_id)


@dataclass(frozen=True)
class IssuerAccumulatorState:
    """The verifier's view of an issuer's non-revocation accumulator."""

    current_epoch: int
    # The issuer's published accumulator roots by epoch. A proof claiming an
    # epoch MUST use the root recorded for it; a proof claiming an epoch with
    # no recorded root is rejected (a circuit only proves membership in the
    # root the PROVER supplies, so an unchecked root enforces no revocation).
    roots: dict = field(default_factory=dict)

    @property
    def authenticated(self) -> bool:
        return False

    @classmethod
    def from_dict(cls, state) -> "IssuerAccumulatorState":
        """Parse the JSON wire form used by conformance requests and audit
        bundles: ``{"currentEpoch": n, "roots": {"<epoch>": "0x<root>"}}``.

        Fail closed: a malformed state raises ``ValueError``. An absent
        ``roots`` object parses to no recorded roots, which the verifier then
        rejects for every root-carrying proof -- never to "accept any root"."""
        if not isinstance(state, dict):
            raise ValueError("accumulator state must be an object")
        current_epoch = state.get("currentEpoch")
        if type(current_epoch) is not int or current_epoch < 0:
            raise ValueError("accumulator state currentEpoch must be a non-negative integer")
        raw_roots = state.get("roots", {})
        if not isinstance(raw_roots, dict):
            raise ValueError("accumulator state roots must be an object")
        roots = {}
        for epoch, root in raw_roots.items():
            if not isinstance(epoch, str) or not epoch.isdigit() or epoch != str(int(epoch)):
                raise ValueError("accumulator state root epochs must be canonical decimal strings")
            roots[int(epoch)] = hex_to_field(root)
        return cls(current_epoch=current_epoch, roots=roots)


_AUTHENTICATED_STATE_TOKEN = object()


@dataclass(frozen=True)
class _AuthenticatedIssuerAccumulatorState(IssuerAccumulatorState):
    accumulator_id: str = ""
    max_epoch_lag: int = PROTOCOL_MAX_EPOCH_LAG
    checkpoint_hash: str = ""
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if self._token is not _AUTHENTICATED_STATE_TOKEN:
            raise ValueError("authenticated accumulator states are issued by verifier ingestion")
        object.__setattr__(self, "roots", MappingProxyType(dict(self.roots)))

    @property
    def authenticated(self) -> bool:
        return True


def _authenticated_accumulator_state(
    *, current_epoch: int, roots: dict, accumulator_id: str, max_epoch_lag: int, checkpoint_hash: str
):
    return _AuthenticatedIssuerAccumulatorState(
        current_epoch=current_epoch,
        roots=roots,
        accumulator_id=accumulator_id,
        max_epoch_lag=max_epoch_lag,
        checkpoint_hash=checkpoint_hash,
        _token=_AUTHENTICATED_STATE_TOKEN,
    )


def _is_authenticated_accumulator_state(state) -> bool:
    return isinstance(state, _AuthenticatedIssuerAccumulatorState) and state.authenticated


@dataclass(frozen=True)
class VerifierTrustPolicy:
    issuers: tuple
    max_epoch_lag: int = PROTOCOL_MAX_EPOCH_LAG
    # Optional context requirements: when set, proofs must use this profile.
    required_context_profile: str = ""
    # Optional predicate-registry review-status requirement: when non-empty,
    # every admitted source identity publishing the selected manifest VK
    # must carry one of these statuses, across labels and bindings. Empty means this
    # VERIFIER-LOCAL policy imposes no review-status requirement — there is no
    # global default beyond refusing unknown proof types (Safeguard 1: the
    # registry informs the policy; it never decides for it).
    # Matching is exact: ("reviewed",) REJECTS a 'self_attested' entry, since
    # an author verifying their own predicate is not independent review. A
    # verifier with real exposure should require ("reviewed",).
    accepted_review_statuses: tuple = ()
    # Independent v2 artifact-review gate. None inherits the source-review
    # policy when present, otherwise accepts the two publishable assurance
    # states. This never broadens issuer or source trust.
    accepted_binding_review_statuses: Optional[tuple] = None
    # Optional exact local allowlist. Empty means no additional narrowing;
    # registry activation/review and issuer policy still apply. A
    # selector-free proof is checked through its exact same-artifact alias.
    # A v1-only sibling spelling with no binding artifact (e.g. linkable
    # kyc:v1) is outside the allowlist: restrict it with accepted_profiles
    # and accepted_review_statuses.
    accepted_binding_ids: tuple = ()
    allow_inactive_bindings: bool = False
    # Presentation profiles this verifier accepts (design §6 rule 1). `None`
    # (the default when unset) applies the {anonymous, scoped} default to v2
    # envelopes and keeps accepting v1/linkable envelopes, so existing
    # constructions keep working without opting in. A policy that sets this
    # field EXPLICITLY is the linkable gate as well: it accepts a v1 envelope
    # only when it lists the linkable profile (see accepts_linkable_envelopes).
    accepted_profiles: Optional[tuple] = None
    # Named protocol scope policies this verifier explicitly honors. The
    # scope still includes the pinned signer identity: identical names under
    # different keys do not create a shared cross-verifier pseudonym. These
    # names retain their distinct holder consent and verifier declaration gate.
    declared_protocol_scopes: tuple = ()
    # UNSAFE opt-out, off by default. A proof's accumulator_root is checked
    # against the root the verifier records for the proof's epoch, and a
    # missing record is STALE_ACCUMULATOR. Setting this accepts a proof whose
    # epoch has no recorded root WITHOUT any revocation check (a revoked
    # holder can prove against a self-made tree); every such acceptance is
    # logged and carries an UNCHECKED_ACCUMULATOR_ROOT warning. A recorded,
    # mismatching root is still rejected, and proof types that require
    # authenticated metadata-v2 state never use this opt-out.
    allow_unrecorded_accumulator_roots: bool = False
    # Verifier-owned APR identity, configured independently of the received
    # request. Empty pins refuse authenticated verification. Multiple SEC1
    # compressed keys permit an explicitly managed signing-key rotation.
    verifier_id: str = ""
    verifier_signing_keys: tuple = ()
    # Off by default. An anonymous presentation carries no holder handle, so
    # two of its proofs can come from two different holders; answering a
    # conjunctive request (KYC AND accreditation) that way is pooling, and is
    # rejected with UNBOUND_COMPOSITE. Set this ONLY when every multi-proof
    # request this verifier makes is a set of independent facts that may be
    # proven by different holders.
    accept_independent_anonymous_proofs: bool = False
    # Off by default. A holder may answer a scoped request anonymously (spec
    # section 5.9.2 rule 4), and the default verifier accepts that downgrade.
    # A verifier that RELIES on repeat recognition (one claim per holder,
    # Sybil resistance) sets this so every accepted answer carries a
    # continuity handle the holder could not choose freely:
    #   * anonymous v2 envelope -> PROFILE_MISMATCH (it has no handle);
    #   * scoped v2 envelope whose scopeId this verifier did not recompute
    #     from its own pinned signing identity -> SCOPE_MISMATCH. Plain
    #     verify() never recomputes scope, so it refuses every scoped answer;
    #     use verify_authenticated();
    #   * linkable v1 envelope -> accepted (if accepted_profiles admits it):
    #     its global holderCommitment is a stable continuity handle that no
    #     presentation parameter changes;
    #   * an envelope in which no requested proof bound the handle (e.g. a
    #     request listing no proof types) -> PROFILE_MISMATCH.
    # One holder has a DIFFERENT handle under each handle-bearing profile
    # (scoped pseudonym vs linkable commitment), so de-duplicating on the
    # handle needs exactly one of them: this flag therefore requires
    # accepted_profiles to be set explicitly to admit exactly one of
    # SCOPED_PROFILE or LINKABLE_PROFILE (ANONYMOUS_PROFILE may be listed;
    # it is rejected anyway). The unset default admits both (scoped v2 and,
    # for compatibility, v1 linkable) and is refused with ValueError. Even
    # then one holder can hold several scoped handles at one verifier:
    # scopeId derives from the APR signer key, the scopePolicy and the
    # rotation epoch, so several pinned verifier_signing_keys, a key
    # rotation, several scope policies or a rotation period each yield
    # another handle.
    require_presentation_continuity: bool = False

    def __post_init__(self):
        if type(self.accept_independent_anonymous_proofs) is not bool:
            raise ValueError("accept_independent_anonymous_proofs must be a boolean")
        if type(self.require_presentation_continuity) is not bool:
            raise ValueError("require_presentation_continuity must be a boolean")
        if not isinstance(self.verifier_id, str):
            raise ValueError("verifier_id must be a string")
        if isinstance(self.verifier_signing_keys, (str, bytes)):
            raise ValueError("verifier_signing_keys must be a sequence of SEC1 keys")
        keys = tuple(self.verifier_signing_keys)
        if any(type(key) is not bytes or len(key) != 33 or key[0] not in (2, 3) for key in keys):
            raise ValueError("verifier signing keys must be compressed SEC1 public keys")
        if keys and not self.verifier_id:
            raise ValueError("verifier signing keys require a verifier_id")
        object.__setattr__(self, "verifier_signing_keys", keys)
        if type(self.allow_unrecorded_accumulator_roots) is not bool:
            raise ValueError("allow_unrecorded_accumulator_roots must be a boolean")
        if self.max_epoch_lag < 0 or self.max_epoch_lag > PROTOCOL_MAX_EPOCH_LAG:
            raise ValueError(
                f"max_epoch_lag must be within [0, {PROTOCOL_MAX_EPOCH_LAG}] "
                "(the circuit enforces the protocol bound)"
            )
        for status in self.accepted_review_statuses:
            if status not in ("draft", "in_review", "self_attested", "reviewed", "deprecated"):
                raise ValueError(f"unknown review status in policy: {status!r}")
        if self.accepted_binding_review_statuses is None:
            inherited = self.accepted_review_statuses or ("reviewed", "self_attested")
            object.__setattr__(self, "accepted_binding_review_statuses", tuple(inherited))
        else:
            object.__setattr__(
                self,
                "accepted_binding_review_statuses",
                tuple(self.accepted_binding_review_statuses),
            )
        for status in self.accepted_binding_review_statuses:
            if status not in ("draft", "in_review", "self_attested", "reviewed", "deprecated"):
                raise ValueError(f"unknown binding review status in policy: {status!r}")
        object.__setattr__(self, "accepted_binding_ids", tuple(self.accepted_binding_ids))
        for binding_id in self.accepted_binding_ids:
            if not (
                isinstance(binding_id, str)
                and len(binding_id) == 71
                and binding_id.startswith("sha256:")
                and all(character in "0123456789abcdef" for character in binding_id[7:])
            ):
                raise ValueError(f"malformed binding id in policy: {binding_id!r}")
        if self.accepted_profiles is None:
            # Preserve the origin of the default when replace() copies it,
            # while an explicitly replaced tuple always derives a fresh gate.
            object.__setattr__(
                self, "accepted_profiles", _DefaultAcceptedProfiles(DEFAULT_ACCEPTED_PROFILES)
            )
        elif not isinstance(self.accepted_profiles, _DefaultAcceptedProfiles):
            object.__setattr__(self, "accepted_profiles", tuple(self.accepted_profiles))
        for presentation_profile in self.accepted_profiles:
            if presentation_profile not in _KNOWN_PRESENTATION_PROFILES:
                raise ValueError(
                    f"unknown presentation profile in policy: {presentation_profile!r}"
                )
        if self.require_presentation_continuity:
            handle_profiles = self.accepted_handle_profiles
            if len(handle_profiles) != 1:
                raise ValueError(
                    "require_presentation_continuity needs accepted_profiles to admit "
                    "exactly one handle-bearing profile (SCOPED_PROFILE or "
                    "LINKABLE_PROFILE): one holder has a different handle under each, "
                    f"so a handle cannot de-duplicate holders; effective: "
                    f"{sorted(handle_profiles)}"
                )
        object.__setattr__(self, "declared_protocol_scopes", tuple(self.declared_protocol_scopes))
        for scope_policy in self.declared_protocol_scopes:
            if not (isinstance(scope_policy, str) and scope_policy.startswith("protocol:")):
                raise ValueError(
                    f"declared protocol scope must be a 'protocol:<name>' string: "
                    f"{scope_policy!r}"
                )

    @property
    def accepts_linkable_envelopes(self) -> bool:
        """Accept v1 for an unset policy or an explicit linkable profile."""
        return (
            isinstance(self.accepted_profiles, _DefaultAcceptedProfiles)
            or LINKABLE_PROFILE in self.accepted_profiles
        )

    @property
    def accepted_handle_profiles(self) -> tuple:
        """The accepted profiles that carry a holder handle, as enforced:
        scoped when listed, linkable when v1 envelopes are accepted (which
        includes the unset default, see accepts_linkable_envelopes)."""
        profiles = []
        if SCOPED_PROFILE in self.accepted_profiles:
            profiles.append(SCOPED_PROFILE)
        if self.accepts_linkable_envelopes:
            profiles.append(LINKABLE_PROFILE)
        return tuple(profiles)

    def issuer_by_key(self, public_key_x: bytes, public_key_y: bytes) -> Optional[TrustedIssuer]:
        for issuer in self.issuers:
            if issuer.public_key_x == public_key_x and issuer.public_key_y == public_key_y:
                return issuer
        return None

    def trusts(self, issuer: TrustedIssuer, proof_type: str) -> bool:
        return proof_type in issuer.proof_types

    def legacy_attribute_layout_id(self, public_key_x: bytes, public_key_y: bytes) -> Optional[str]:
        """Return the key's single layout pin. Missing or conflicting pins refuse."""
        layouts = {
            issuer.attribute_layout_id
            for issuer in self.issuers
            if issuer.public_key_x == public_key_x and issuer.public_key_y == public_key_y
            and LEGACY_SELECTIVE_DISCLOSURE_PROOF_TYPES.intersection(issuer.proof_types)
        }
        return next(iter(layouts)) if len(layouts) == 1 else None

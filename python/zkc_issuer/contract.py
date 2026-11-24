"""The production issuer adapter contract (interoperability interface).

``IssuerAdapter`` is the abstract contract every ZKC issuer adapter —
sandbox or production — implements. It is the four protocol stages of
docs/zkc_issuer_adapter_protocol_v1.md as typed Python methods, plus the two
issuer-side surfaces verifiers and holders depend on (metadata publication
and revocation). Conformance is machine-checked by
``conformance/issuer_adapter`` (the kit), which any implementation must pass.

Contract rules (enforced by the kit):

* Every stage takes and returns plain JSON-able dicts (the wire shapes).
* Failures raise ``zkc_issuer.AdapterError`` with the protocol's closed
  error-code set; messages never contain provider secrets, raw identity
  documents, or wallet identifiers.
* Every stage rejects payloads carrying privacy-boundary material
  (``zkc_issuer.reject_forbidden`` semantics — recursive).
* Stage order is enforced: binding requires a verified subject; issuance
  requires a holder-bound subject.
* Issued envelopes are holder-SDK consumable
  (``zkc_holder.Credential.from_dict``), signed under a key published in
  issuer metadata, with a witness that verifies against the published
  accumulator root.

No adapter is canonical and no verifier is required to trust one
(Freedom Safeguard 1): implementing this contract grants interoperability,
not authority.
"""

from __future__ import annotations

import abc

__all__ = ["IssuerAdapter"]


class IssuerAdapter(abc.ABC):
    """Abstract issuer adapter: the 4 protocol stages + issuer-side surfaces."""

    issuer_id: str

    # --- protocol stages (holder/provider facing) ---------------------------------

    @abc.abstractmethod
    def verify_subject(self, payload: dict) -> dict:
        """Stage 1: provider-specific subject verification.

        Returns ``{"status": "verified", "subjectRef": str, "schemaId": str,
        "expiresAt": int}``.
        ``subjectRef`` is a CSPRNG continuation with at least 128 random bits,
        bound to the caller's authenticated stage-1 session. It expires and
        is consumed by issuance, and MUST NOT appear in public credentials,
        metadata, on-chain state, or proof public inputs. Trusted caller
        context comes from the authenticating gateway, never request JSON.
        """

    @abc.abstractmethod
    def request_binding_challenge(self, payload: dict) -> dict:
        """Stage 2a: mint a single-use, expiring holder-binding challenge."""

    @abc.abstractmethod
    def bind_holder_commitment(self, payload: dict) -> dict:
        """Stage 2b: verify the challenge response and bind the commitment."""

    @abc.abstractmethod
    def issue_credential(self, payload: dict) -> dict:
        """Stage 3: sign the credential digest and return its envelope.

        The credential identifier must be in [1, BN254 scalar-field modulus)
        before signing or registering the credential.
        """

    @abc.abstractmethod
    def publish_revocation_handle(self, payload: dict) -> dict:
        """Stage 4: publish accumulator state (and per-credential status)."""

    # --- issuer-side surfaces -------------------------------------------------------

    @abc.abstractmethod
    def issuer_metadata(self) -> dict:
        """The /.well-known/zkc-issuer.json registry document."""

    @abc.abstractmethod
    def revoke_credential(self, credential_id: int) -> dict:
        """Issuer-side revocation; returns the updated revocation metadata."""

# ZKC Python Reference Packages

Standard-library-only Python reference implementations of the ZKC client stack. Layout:

| Package | Purpose |
|---------|---------|
| `zkc_crypto/` | Shared primitives, bit-compatible with `noir/zkc_lib`: Poseidon2 (BN254, t=4 sponge), KDC §A.6 credential binding, claim bindings, credential digests, depth-32 Poseidon2 Merkle trees, secp256k1 ECDSA, proof-context construction, `zkc:proof:v1` envelope validation. |
| `zkc_holder/` | Reference holder SDK (spec §5): credential storage (in-memory, encrypted-file, and durable `SQLiteCredentialStore` — survives restart), selection by proof request + trust policy, witness refresh, `zkc:proof:v1` generation, aggregation entry point, context binding, opaque-predicate refusal (Freedom Safeguard 4), minimal-disclosure planning + negotiation (`planner.py`) with typed per-predicate disclosure comparators for consent ceilings and published minimums (`ceilings.py`), holder-authorized audit export (`audit_export.py`), and lifecycle upkeep (`lifecycle.py`: fresh/aging/stale/unusable states, tick-driven proactive witness refresh). |
| `zkc_verifier/` | Reference verifier library (spec §6): `zkc:proof:v1` parsing, freshness, context binding, holder binding, verification-key lookup via the artifact manifest, authenticated accumulator-state enforcement for selective disclosure, issuer trust policy, type-specific requirement checks, structured `VerificationError` codes. |
| `zkc_registry/` | Local registry/discovery helpers plus shared predicate-entry v2 canonical identity, exact selector, and authenticated request-extension primitives used by validators, holders, and verifiers. |
| `zkc_issuer/` | Reference issuer SDK and sandbox adapter (issuer adapter protocol v1): signing-key generation/loading, the four adapter stages against sandbox fixtures, seven issuer credential schemas (circuit-exact digests for kyc / jurisdiction / accreditation / source / tax / sanctions, plus issuance-only runtime attestation), holder-binding challenge (beta profile), Poseidon2 Merkle revocation accumulator state, `/.well-known/zkc-issuer.json` metadata generation, recursive privacy-boundary enforcement. Production interop: the `IssuerAdapter` contract (`contract.py`), the shared `BaseIssuerAdapter`, and provider-plugin adapters (`external.py`, `runtime_attestation.py`); conformance kit in `conformance/issuer_adapter/`. |
| `zkc_agent/` | Reference agent compliance API (spec §5.4): deny-by-default `AgentCompliancePolicy` (tri-state auto/approve/block per proof type × verifier, disclosure ceiling as hard, typed consent scope), `handle_proof_request` auto-response through the minimal-disclosure planner, principal approval queue + notification hooks, `precompute_proofs` warm path, `verify_counterparty` via the reference verifier, replay / wrong-verifier rejection, and a redacting JSONL audit log. Non-goals by construction: no disclosure without principal policy, no custody of spending authority. |
| `zkc_revocation/` | Revocation accumulator + witness update service: exact binary-transcript issuer-signed CHAINED epoch announcements (`zkc:epoch-announcement:v3`) published in authenticated issuer metadata v2, historical backfill, gap/fork detection via `AnnouncementChain`, the witness-update wire protocol (delta + full refresh; in-process `handle_request`, HTTP-wrappable), holder-side delta application and credential-anonymous epoch fetch, and verifier ingestion with pre-pinned key/accumulator ids (each key pinned as an `AnnouncementKeyPin` with a mandatory `notBefore`/`notAfter` window and optional `retireAfterEpoch`; the issuer also refuses to sign outside its key window), signed freshness, signed head liveness (`zkc:epoch-liveness:v1`, which keeps a quiet issuer's unchanged head fresh without a new epoch), roots served only while the issuer attested them within the age limit (worst-case revocation latency `max_announcement_age + max_clock_skew`), per-issuer `accumulator_states()`, bounded backfill, resumable bounded catch-up (`catch_up`, one persisted step of at most `max_backfill` announcements per call) for a verifier or holder checkpoint that fell further behind, durable SQLite checkpoints that never move backwards when workers, threads, or processes share them (compare-and-swap writes), and retained equivocation evidence (only the actually conflicting same-accumulator, same-key pair; an announcement for another accumulator is `ACCUMULATOR_ID_MISMATCH`). Holders pin the accumulator id (`accumulator_ids=` or a `(source, accumulator_id)` target), and at cold start verifiers and holders refuse a zero-predecessor migration checkpoint above epoch 0 unless `authorized_migrations` names `(issuer_id, accumulator_id, epoch)`. Issuer state remains durable through `DurableRevocationAccumulatorService` + `SQLiteAccumulatorStateStore`: an append-only log with one row per epoch (the mutation and its signed announcement, constant size per write) and one row per announcement signer. Recovery replays the log and fails closed unless each announcement verifies under the signer recorded for its epoch and each replayed root matches its signed root. `rotate_signing_key()` records a successor that signs from the next epoch on; the service then reopens with the successor key, and `open(..., allow_rotation=True)` rotates at open time when only the successor key is available. Leaf snapshots serve deltas for the last `DELTA_SNAPSHOT_WINDOW` (33) epochs; an older `fromEpoch` gets a full refresh. A v2 single-document store is verified and migrated on open (see [the lifecycle doc](../docs/zkc_credential_lifecycle.md#durable-issuer-storage-and-announcement-key-rotation)). ZKA-independent by construction. |
| `zkc_transport/` | Stdlib HTTP transport for the in-process issuer + revocation services. `RevocationServer` / `IssuerServer` (`http.server`) forward documented wire shapes to a `RevocationAccumulatorService` / `IssuerAdapter` unchanged; `RevocationServiceClient` / `IssuerServiceClient` (`urllib`) speak the same shapes; `HTTPWitnessUpdateProvider` refreshes per-credential witnesses over HTTP and verifies signed roots and epochs. `PrivateWitnessProvider` works with `RevocationServiceClient` for credential-anonymous HTTP refresh. `IssuerAdminServer` / `IssuerAdminClient` carry operator revoke/renew on a separate, signature-authenticated listener. NOT production (no TLS; the holder-facing listeners authenticate no caller) — a real gateway sits in front and reuses the identical wire shapes. |

For credential-anonymous refresh over HTTP, configure the holder with issuer
announcement keys and accumulator ids obtained from local trust policy. Also
configure a trusted publication mirror that serves one common signed view
without selecting heads by holder or taking directions from the leaf service.
Both its current and historical announcement endpoints must be independent of
the leaf endpoint. In production, use authenticated transport for both.
Each key pin carries the key's validity window (Unix seconds,
`notBefore <= announcedAt < notAfter`) and optionally `retire_after_epoch`;
a bare `(x, y)` pin is refused.

```python
from zkc_revocation import AnnouncementKeyPin, PrivateWitnessProvider
from zkc_transport import RevocationServiceClient

pin = AnnouncementKeyPin(public_key_x, public_key_y, not_before, not_after)
provider = PrivateWitnessProvider(
    {issuer_id: (RevocationServiceClient(base_url), accumulator_id)},
    {issuer_id: {signing_key_id: pin}},
    announcement_sources={issuer_id: RevocationServiceClient(publication_url)},
    checkpoint_store=holder_checkpoint_store,
)
```

Pass the provider as the holder's `accumulator_provider`. Use a
`SQLiteVerifierCheckpointStore` for persistent holder state.
Each refresh requests the full leaf set with only the accumulator id. The
response must match the exact signed head from the publication mirror. If the
sources are out of sync or the mirror is unavailable, refresh fails closed
and can be retried after they agree.
For a gap beyond `max_backfill`, call `provider.catch_up(issuer_id)` until the
returned status is `complete`, then refresh the witness.
`WitnessUpdateProvider` and `HTTPWitnessUpdateProvider` require the same
issuer-key map and checkpoint store when using per-credential refresh.

These packages are **reference implementations**: they prioritize auditability and spec fidelity over performance, and have zero external dependencies (Python ≥ 3.9). Circuit-backed hashes are KAT-pinned against `tests/vectors/zkc_core_vectors.json` and the Noir circuit fixtures. The runtime-attestation issuer hashes are pinned by Python KATs; its external-artifact digests (AFP External Artifact v2 exact-byte framing) are KAT-pinned against `tests/vectors/runtime_attestation_external_artifact_v2.json`. This release has no runtime-attestation Noir circuit.

### Current remaining-predicate profiles

For accreditation, source-of-funds, tax-residency, and sanctions-clearance,
the holder selects `zkc:proof:*:v7` for linkable presentations and
`zkc:proof:*:v8` for anonymous or scoped presentations. They use
`zkc_remaining_predicates_v7` / `_v8` and require the matching
`zkc:cred:*:v2` issuer schema. `compute_profile_digest_v2(holder,
credential_id, predicate_type, claim0, claim1, valid_from, valid_until)` is
exactly `poseidon4(poseidon4(holder, credential_id, predicate_type,
valid_from), claim0, claim1, valid_until)`, so both validity bounds are
issuer-authenticated. v7/v8 retain `compute_claim_binding_4` for
`flagRequired` and enforce
`successor_path_index == predecessor_path_index + 1` for sanctions.

The immutable v1–v6 proof identities remain available only to verify already
generated historical proofs. In particular, v3/v4 bind `flagRequired` but
still lack exact sanctions adjacency and omit `validFrom` from the issuer
digest. v5/v6 add raw-code and exact sanctions-adjacency checks but retain the
legacy issuer digest, so they also omit `validFrom`. A `zkc:cred:*:v1` profile
credential cannot generate v7/v8; reissue it as the matching `:v2` credential.
Callers must make the current proof type, credential schema, and trusted issuer
explicit in the signed APR and trust policy; the SDK does not silently upgrade
a legacy credential.

The draft `zkc_remaining_predicates_v10` successor adds circuit assertions for
accreditation u8 levels, tax u64 years and sanctions u16 claims. Its four `:v10`
proof types require explicit anonymous/scoped requests and explicit local
acceptance of the draft identity. They do not change v7/v8 defaults, activate
the entry, or authorize public publication. Draft v10 files are excluded from
the public snapshot; an exported holder must refuse an absent identity rather
than substitute a predecessor.

`zkc:cred:runtime-attestation:v1` is an issuer credential schema only. Its reserved `zkc:proof:runtime-attestation:v1` identifier has no reviewed Noir circuit or predicate-registry entry in this release, so holders and verifiers must retain the normal Safeguard 4 refusal path until that separate review is complete.

`StaticPreverifiedRuntimeAttestationProviderClient` is a test/reference fixture. It structurally validates and binds caller-supplied preverified verdicts, but performs no cryptographic SLSA, transparency-log, or TEE verification. Production integrations must implement `ProviderClient.verify_subject` inside their provider trust boundary and cryptographically verify signatures, authenticated checkpoints and inclusion, reports, endorsements, revocation/collateral, freshness, measurements, and report-data binding before returning `ProviderDecision`.

Issuer continuations are random, expiring, single-use handles bound to trusted gateway session context. Production adapters require a `session_identity` callback and pass that identity to `ProviderClient.verify_subject(..., authenticated_session=...)`; request-body session ids and public applicant/evidence locators provide no authentication. Runtime evidence must bind the stage-1 holder commitment, returned as `ProviderDecision.holder_commitment` and enforced during binding. Sandbox and `reference_*_adapter` factories provide a test-only local identity. The [issuer session contract](../docs/zkc_issuer_adapter_protocol_v1.md#trusted-session-integration) describes gateway authentication, the per-client rate limit, and the issuance ledger: in memory by default, or durable across restart with `SQLiteIssuanceLedgerStore` (no replica coordination).

Issuer adapters publish immutable, authoritative schema-to-privacy-profile capabilities. Existing human adapters require `frozenset({"human"})`; the runtime-attestation adapter requires `frozenset({"human", "machine"})`. The machine profile uses the production bounded normalized-key matcher at every stage entry and on the owned provider result. It rejects raw evidence and provenance, host/hardware identifiers, and qualified build/environment paths across camel, snake, kebab, dotted, and nested spellings. Exact built-in containers are limited to depth 32, 4,096 value nodes, and 4,096 UTF-8 bytes per key; malformed keys, custom/subclass containers, repeated containers, and cycles fail with one detail-free error. Values are not searched: generic `witness.path`, digests, and the scoped opaque reference handles remain valid.

Raw reports, quotes, inclusion paths, endorsements, collateral, host serials, and customer build paths may exist only in the provider-private evidence store. They may not appear in `ProviderDecision` claims, retained issuer credential source, any of the five protocol results, issuer metadata, or renewal output. `evidenceRef` ends at the provider boundary, `providerRef` remains provider/issuer-private, and issuer-scoped `subjectRef` is limited to stage continuity—not credentials, metadata, revocation, proofs, or presentations. The fixed library error/log guarantee does not promise sanitization of caller frames or arbitrary Python tracebacks. This boundary changes no digest, AFP artifact, proof/circuit, platform policy, or provider trust decision.

`renew_credential` accepts only `credentialId` and optional `expiresAt`, applies
the shared privacy scan and per-client rate limit, and authorizes the trusted
owner before checking credential status. Unknown and foreign ids have the same
refusal. The requested future u64 expiry cannot exceed the original nonzero
provider-verified expiry, retained privately across all replacements. Omission
keeps the current expiry; shortening and restoration within the original bound
are allowed where the schema's unchanged claim/expiry rules permit them.
Provider expiry zero means no provider deadline; renewal still requires a
finite future expiry. See the [renewal contract](../docs/zkc_credential_lifecycle.md#issuer-renewal-atomic-re-issuance).

**Operator mutations over HTTP.** The holder-facing `IssuerServer` routes only
the issuance stages and the metadata document; it has no revoke or renew route.
`IssuerAdminServer` serves `POST /v1/admin/revoke` and `POST /v1/admin/renew` on
a separate listener. It admits a request only when the request carries an
ECDSA secp256k1 signature by a pinned operator key (`OperatorKey`, verified
low-s through `zkc_crypto`). The signature binds the issuer id, method, request
target, body digest, a timestamp inside the clock-skew window (60 s by default)
and a single-use nonce. Any other request gets HTTP 401 before its body is
parsed. `IssuerAdminClient` signs requests. Credential ids are public (every
active id is a published accumulator leaf), so an id never authorizes anything.
Stage 4 stays a rate-limited public status and witness oracle. Both listeners
remain reference code with no TLS, and the holder-facing listeners authenticate
no caller, so neither is a production security boundary. See
[threat model section 1.10](../docs/zkc_metadata_leakage_threat_model.md#110-credential-identifiers-and-operator-mutations).

**Transport bounds.** Every listener refuses a malformed request with a JSON
HTTP 400 before any handler runs: a `Content-Length` that is not one header of
ASCII digits up to 1 MiB, any `Transfer-Encoding`, a body shorter than
declared, and JSON with `NaN`/`Infinity`, an overflowing number, a duplicate
key or more than 64 nested objects or arrays (including the root container).
The transport checks depth before decoding JSON. Requests must arrive within
`request_timeout` (10 s by default; a slow body gets 408). A threaded listener
serves at most `max_concurrent_requests` connections (32 by default;
the next one gets 503 without a thread). On the operator listener the body is
still authenticated before it is parsed, so an unsigned malformed body gets
401. Revocation-route failures that are not protocol errors are issuer-state
faults (503). The clients cap each response at `max_response_bytes` (16 MiB by
default) and the whole read at `timeout`, and parse responses with the same
strict JSON rules.

## Usage

The packages are plain directories; put `python/` on `PYTHONPATH` (the test suite does this for you):

```python
import sys; sys.path.insert(0, "python")

from zkc_crypto import ProofContext, generate_master_seed
from zkc_holder import (
    HolderClient, StubBackend, NargoBackend, PredicateRegistry,
    LocalAccumulatorProvider, ProofRequest, TrustPolicy, TrustedIssuer,
)

registry = PredicateRegistry.from_repo(".")                 # reviewed predicates
backend = NargoBackend(".") if NargoBackend.available() else StubBackend()
master_seed = generate_master_seed()                         # exact 32 secret bytes
client = HolderClient.from_seed(master_seed, registry, backend,
                                accumulator_provider=provider)

context = ProofContext.verifier_session("verifier.example", session_id, timestamp)
request = ProofRequest(
    proof_types=["zkc:proof:kyc:v1"],
    parameters={"zkc:proof:kyc:v1": {"requiredLevel": 2,
                                     "requiredAttributes": [True, False, False, False, False]}},
    context=context,
    trust_policy=TrustPolicy(issuers=(TrustedIssuer(...),)),
)                                       # presentation_profile defaults to anonymous

# `signed_apr` is the verifier's Authenticated Proof Request for this request.
# The anonymous KYC answer is `zkc:proof:kyc:v2`, a `draft` registry entry, so
# it needs the Safeguard 4 opt-in described below: here the per-call override,
# which is logged and recorded as UNREVIEWED.
result = client.generate_authenticated_proof(
    signed_apr, request, seen_nonces=seen, allow_opaque=True,
)
envelope = result["envelope"]           # zkc:proof:v2 presentationBinding (anonymous)
receipt = result["receipt"]             # holder-custodied Disclosure Receipt; keep it
```

**Unauthenticated requests are refused by default (Safeguard 6).** Answer
verifier requests with `generate_authenticated_proof`. `generate_proof(request)`
answers a request that carries no APR, so it raises `UnauthenticatedRequestError`
(`UNSIGNED_REQUEST`) unless you pass `allow_unauthenticated=True`. That opt-in is
logged and recorded in `override_log` as `UNAUTHENTICATED`. The same rule
applies to `authorize_delegated_material`, whose delegated requests carry no APR.
Every opt-in (`allow_unauthenticated`, `allow_opaque`, `allow_linkable`) counts
only when it is exactly `True`. Every check the holder can decide before proving
(secrets, parameter keys, profile and consent, the Safeguard 4 gate, composite
rules, context) runs before the override is recorded.

**Receipt and audit keys (spec §5.6.1).** A receipt's
`holderSignature.holderKey` and an audit bundle's `holderAuthorizationKey` are
self-asserted, so neither is a trust anchor. `verify_receipt(receipt,
expected_holder_key=...)` and `verify_audit_bundle(bundle, now=...,
expected_holder_key=...)` fail closed unless the caller passes the holder key it
obtained from the holder out of band; the caller must also compare the
receipt's response handle with the handle it associated with that key. Receipt
keys are scoped to the active profile: stable per verifier identity (linkable,
authenticated), stable per `scopeId` (scoped), and fresh per receipt
(anonymous, refused, unauthenticated). A fresh key mixes a discarded random
nonce with the receipt digest, so nobody can derive it again and a third party
cannot anchor such a receipt.
Audit-authorization keys are stable per auditor. The holder publishes a stable
key's public half with `HolderClient.receipt_public_key(verifier_identity=...)`,
`receipt_public_key(scope_id=...)` or
`AuditExporter.authorization_public_key(auditor_key_id)`. Every key derives from
the exact seed bytes in `zkc_crypto/holder_keys.py`; no derived private key is
logged, serialized or stored.

**Presentation profile.** Both entry points honor
`ProofRequest.presentation_profile`, the holder's own profile choice (spec §5.9).
It is holder-local configuration: never fill it from verifier wire input. The
default anonymous profile yields a `zkc:proof:v2` envelope with a
`presentationBinding` and never a `holderBinding`. A scoped answer needs an
authenticated APR with a `scopePolicy`, so `generate_proof` refuses it. The
linkable profile yields the frozen `zkc:proof:v1` envelope with the global,
linkable `holderCommitment`. Without an APR, `generate_proof` also requires the
holder's explicit `allow_linkable=True` for it and otherwise refuses with
`ConsentRequiredError` (`CONSENT_REQUIRED`); the recorded `UNAUTHENTICATED`
override names the linkable profile. The same applies to
`generate_authenticated_proof` and `answer_as_hosted_service` when the APR does
not authenticate and `allow_unauthenticated=True` is the override. Under an
authenticated APR, the holder's linkable ceiling plus an APR that asks for
linkable (or is silent) is the consent, and the verifier can only lower the
profile, never raise it. The linkable profile supports `aggregate=True` for
committing to the entries in a v1 envelope. The verifier checks every covered
entry individually against the request and the envelope's holder commitment,
then recomputes the aggregate commitments. Aggregate proof bytes carry no
verification authority. The verifier rejects aggregation blocks in anonymous
and scoped envelopes with `INVALID_AGGREGATION`.

```python
import dataclasses
from zkc_crypto import LINKABLE_PROFILE

# Explicit, logged override: no APR, and explicit linkable consent.
legacy = client.generate_proof(
    dataclasses.replace(request, presentation_profile=LINKABLE_PROFILE),
    allow_unauthenticated=True,
    allow_linkable=True,
)                                       # zkc:proof:v1 with holderBinding
```

**Review-status gate (Safeguard 4).** The holder refuses a predicate whose
registry entries are all outside its `accepted_review_statuses` (default
`("reviewed", "self_attested")`) with `OpaquePredicateError`, on the v1 path and
on the anonymous/scoped presentation path alike. A v2 presentation identity is
its own registry entry and does not inherit its v1 family's status. Until the
independent cryptographic review promotes them, the v2 presentation entries
(for example `zkc:proof:kyc:v2`) are `draft`, so the default holder, and an
agent built on it, refuses anonymous and scoped answers. Opt in either by
adding `"draft"` to `accepted_review_statuses` or per call with
`allow_opaque=True`; the per-call override is logged and recorded in
`override_log` as `UNREVIEWED`.

## Proof backends

* **`NargoBackend`** — real UltraHonk proving via `nargo execute` + `bb prove` against a private per-call copy of the repository circuits (requires the toolchain pinned in `.noir-version`). It never writes proving inputs or outputs into the source tree. Production path.
* **`StubBackend`** — deterministic test backend, **clearly non-production** (`is_production = False`). It re-evaluates the circuit constraints in pure Python first (fail closed: it refuses to "prove" anything the real circuit would reject) and then emits a `zkc:stub:v1:…` payload. No cryptographic soundness; unit tests / CI only.

## Verifier

```python
from zkc_verifier import (
    ZKCVerifier, VerifierTrustPolicy, TrustedIssuer, IssuerAccumulatorState,
    VerificationRequest, BBVerifyBackend, StubVerifyBackend,
)

verifier = ZKCVerifier(
    ".",
    VerifierTrustPolicy(issuers=(TrustedIssuer(...),)),   # explicit allowlist; no canonical issuers
    BBVerifyBackend(".") if BBVerifyBackend.available() else StubVerifyBackend(),
)
result = verifier.verify(envelope, VerificationRequest(
    proof_types=["zkc:proof:kyc:v1"], parameters={...}, context=context,
    # The issuer's published accumulator root for every epoch you accept.
    # Prefer VerifierAccumulatorCache.state(issuer_id), which records roots
    # from the issuer's signed announcement chain.
    accumulator_states={"did:zkc:issuer": IssuerAccumulatorState(
        current_epoch=current_epoch, roots={epoch: issuer_root, ...},
    )},
))
result.valid          # True only when every check passes
result.to_dict()      # {"valid": ..., "errors": [{"code": ..., "message": ...}], "warnings": [...]}
```

**Accumulator roots are mandatory.** Every circuit proves membership only in the `accumulator_root` the *prover* supplies, so the verifier compares it with the root it records for the proof's epoch and rejects an epoch with no recorded root (`STALE_ACCUMULATOR`). A state without roots therefore rejects every proof — it never "accepts any root", which would let a revoked holder prove against a self-made tree. `VerifierTrustPolicy(allow_unrecorded_accumulator_roots=True)` is an explicit, UNSAFE opt-out for deployments that cannot record roots: each unchecked acceptance is logged and carries an `UNCHECKED_ACCUMULATOR_ROOT` warning. Selective disclosure and the rebind successors always require authenticated (`VerifierAccumulatorCache`) state.

Every rejection carries a stable code from the closed `VerificationErrorCode` enumeration (`MALFORMED_PROOF`, `STALE_PROOF`, `EXPIRED_PROOF`, `CONTEXT_MISMATCH`, `INVALID_BINDING`, `INVALID_PROOF`, `UNKNOWN_PROOF_TYPE`, `UNREVIEWED_PREDICATE`, `UNKNOWN_VERIFICATION_KEY`, `STALE_ACCUMULATOR`, `UNAUTHENTICATED_ACCUMULATOR`, `UNTRUSTED_ISSUER`, `REQUIREMENTS_NOT_MET`, `MISSING_PROOF`, `INVALID_AGGREGATION`, `UNSIGNED_REQUEST`, `PURPOSE_MISMATCH`, `PROFILE_NOT_ACCEPTED`, `PROFILE_MISMATCH`, `SCOPE_MISMATCH`, `UNBOUND_PROOF_TYPE`, `UNAUTHENTICATED_CREDENTIAL`, `DEPRECATED_PROOF_TYPE`, `UNBOUND_COMPOSITE`, `MALFORMED_BINDING_SELECTOR`, `UNKNOWN_BINDING`, `INACTIVE_BINDING`, `DEPRECATED_BINDING`, `DISALLOWED_BINDING`). Verification keys resolve through the committed `artifacts/manifest.json` (falling back to a local `artifacts/build/manifest.json`) and are sha256-checked against the manifest pin before use. Entry-v2 proofs use the exact authenticated `(predicateId, entryVersion, bindingId)` selector and expose selected source, toolchain, build profile, and artifact identities in `VerificationResult.bindings`. Selector-free legacy proofs keep their original circuit and VK; when those artifact pins uniquely match a v2 binding, its gates apply and the result carries binding evidence marked `resolution: legacyVkAlias` with the presented proof type and circuit. Legacy proofs without such an alias retain their original serialized result shape. `verify()` and `verify_authenticated()` both enforce requested selector pins. The alias is found by the circuit's manifest VK pins (`vkSha256` alone is enough; an absent `vkHash`/`acirHash` is not compared). A binding allowlist applies to a selector-free proof through its alias (`DISALLOWED_BINDING`); it does not govern a legacy artifact that is no binding's artifact, such as a linkable `kyc:v1` answer. Restrict those with `accepted_profiles` and `accepted_review_statuses`. The production `BBVerifyBackend` unconditionally rejects `zkc:stub:v1` payloads.

**Request parameters are a closed vocabulary.** Each proof type accepts only the parameter keys its binding sidecar references with `param:`, plus the documented request-only keys (canonical code sets, legacy filters, holder witness hints, `credentialId`) in `zkc_crypto.request_parameters.REQUEST_ONLY_PARAMETERS` and specification §6.2.1. `verify()` and `verify_authenticated()` reject any other key with `REQUIREMENTS_NOT_MET`, naming the key and the proof type; a misspelled key can no longer drop the requirement it was meant to state. `HolderClient.generate_proof`, `generate_authenticated_proof` and `ProofPlanner` refuse such a request with `ConstraintViolationError` (`CONSTRAINT_VIOLATION`) before proving, after the `SECRET_IN_REQUEST` check. A parameter block for a proof type the request does not list is rejected the same way. The holder checks an aliased request (for example `source:v1` answered as `source:v7`) against the emitted identity's set, and refuses a non-empty block whose set cannot be derived (no encoders or sidecars under the registry's repository root); pass `repo_root` (as `PredicateRegistry.from_repo` does) outside this checkout. A new successor identity derives its keys from its own sidecar.

**Multi-predicate answers need a same-holder binding.** An anonymous envelope binds its proofs to no holder, so two people could splice their honest anonymous proofs to satisfy a conjunctive request. The verifier rejects an anonymous envelope answering two or more distinct requested proof types with `UNBOUND_COMPOSITE` unless `VerifierTrustPolicy(accept_independent_anonymous_proofs=True)` declares them independent. Ask for conjunctions with the scoped profile and `"scopePolicy": "session"`: all proofs then share one pseudonym bound in-circuit to the holder's key, unique to that fresh request context. The holder answers such a request only if its own ceiling permits it (`ProofRequest(presentation_profile=SCOPED_PROFILE)`; the default is anonymous). Whenever the effective profile is anonymous, `HolderClient` refuses a request for two or more distinct proof types before consent or proving, with `AnonymousCompositeRefusedError` (`ANONYMOUS_COMPOSITE_REFUSED`): the verifier would only reject the answer, which would still disclose which predicates you satisfy. Set `ProofRequest(allow_unlinked_composite=True)` only for a verifier that declares the proofs independent. Single-proof anonymous answers are unchanged.

**Check which presentation you received.** A holder may answer a scoped request anonymously (specification §5.9.2 rule 4), and a default verifier accepts that answer. The result therefore reports the effective presentation: `result.presentation_profile` (a v1 envelope is `LINKABLE_PROFILE`), `result.presentation_handle` (the scoped pseudonym, the linkable `holderCommitment`, or `None` for anonymous), `result.scope_id`, and `result.scope_recomputed`. `scope_recomputed` is `True` only when `verify_authenticated()` recomputed `scopeId` from this verifier's own pinned signing key and it matched. `verify()` has no APR and never recomputes scope, so it accepts a holder-chosen `scopeId`; do not use a pseudonym from `verify()` as a continuity handle. For `zkc:proof:v2` envelopes, `result.to_dict()` adds a `presentation` object (`profile`, `scopeRecomputed`, and for scoped `pseudonym` and `scopeId`); the v1 wire result keeps its legacy shape. The handle and scope are reported only when at least one requested proof was checked against the envelope binding; an envelope answering no requested proof reports none. If you rely on repeat recognition (one claim per holder), set `VerifierTrustPolicy(require_presentation_continuity=True, accepted_profiles=...)` with exactly one handle-bearing profile: `(SCOPED_PROFILE,)` or `(LINKABLE_PROFILE,)` (`ANONYMOUS_PROFILE` may be added). One holder has a different handle under each, so a policy admitting both, including the unset default (scoped v2 plus compatibility v1), raises `ValueError`. An anonymous answer then fails with `PROFILE_MISMATCH` on both entry points, as does an answer whose handle no requested proof bound. A scoped answer passes only through `verify_authenticated()`; `verify()` refuses it with `SCOPE_MISMATCH`. A linkable answer passes, because its global commitment is a stable handle. A scoped handle is constant only while `scopeId` is: each pinned `verifier_signing_keys` entry (including across a key rotation), each `scopePolicy`, and each rotation epoch gives the same holder another handle, and `scopePolicy` `"session"` gives one handle per request context. The handle identifies a credential binding key, not a person.

**Deprecated identities need an explicit opt-in.** The known unsafe historical identities (jurisdiction v1/v2, accreditation/source/tax/sanctions v1-v6) require `deprecated` in the verifier's `accepted_review_statuses` (e.g. `("reviewed", "self_attested", "deprecated")`), otherwise authenticated verification returns `DEPRECATED_PROOF_TYPE`. This gate remains effective without registry entries or when another listing assigns a current status. Unauthenticated historical proofs retain their `UNSIGNED_REQUEST` refusal. A signed APR naming the identity is not an opt-in: an APR is fresh, so only a newly generated proof can answer it.

Rejections aside, a result may also carry **non-fatal** warnings from the closed `VerificationWarningCode` set (`OVER_DISCLOSURE`, `OVERBROAD_REQUEST`, `UNBINDABLE_PARAMETER`, `UNCHECKED_ACCUMULATOR_ROOT`): these flag disclosure-hygiene issues (e.g. an envelope disclosing more than was asked for) without affecting `result.valid`, which depends on errors only.

## Credential-rebind security containment

**Operator warning.** The four published credential-rebind proof types (`zkc:proof:credential_rebind:v1`, `zkc:proof:rebind:v2`, `zkc:proof:credential_rebind:v2`, `zkc:proof:rebind:v3`) authenticate no credential: their circuits constrain only holder-key continuity, every credential field they carry is an unconstrained prover witness, and no issuer signature or accumulator membership is verified. A valid proof under any of them is evidence of attacker-chosen key continuity, never of an issuer-created, non-revoked credential.

Both reference packages fail closed on them (spec §4.5):

* `HolderClient` never selects, generates, or negotiates them; an explicit request raises `UnauthenticatedProofTypeError` (`UNAUTHENTICATED_PROOF_TYPE`) before any registry resolution or proving, on the v1 and the v2 presentation paths alike. `resolve_presentation_proof_type` refuses the `rebind` family for every profile.
* `ZKCVerifier.verify` and `ZKCVerifier.verify_authenticated` reject any envelope or request naming one of them with `UNAUTHENTICATED_CREDENTIAL` before backend verification, with an empty and with a configured trust policy alike. Request-pinned `issuerIdHash` / `schemaIdHash` values were only ever equality filters and cannot make such a proof valid; an APR authenticates the requester, not a credential.

Deployments that ingested rebind proofs from these identities MUST treat the resulting continuity records as unauthenticated. The historical circuits, encoders, sidecars, artifacts, and registry pins are byte-frozen and unchanged.

### The supported replacement

Use the issuer-authenticated successors (spec §7.4, ADR 0004):

| Profile | Proof type | Circuit | Registry entry |
|---|---|---|---|
| linkable | `zkc:proof:credential_rebind:v3` | `zkc_credential_rebind_auth` | `zkc-credential-rebind@5.0.0` |
| scoped | `zkc:proof:rebind:v4` | `zkc_credential_rebind_auth_v2` | `zkc-credential-rebind@6.0.0` |

Both verify an issuer ECDSA signature over the `zkc:attestation:credential-rebind:v1` transcript **recomputed in-circuit** from constrained fields, and prove fresh accumulator membership for that same authenticated credential identifier. There is no anonymous rebind: continuity is verifier-facing.

* **Issuers** emit the attestation with each credential they permit to migrate (`BaseIssuerAdapter.issue_credential` and `renew_credential` do this automatically; `sign_rebind_attestation({"credentialId": …})` re-emits one for an already-issued credential — representation-only, no credential field changes). The later call takes only the credential identifier. The adapter loads the schema, holder commitment and validity window from its private issuance record, and serves only the authenticated session that owns the credential's lineage. It refuses unknown, foreign, revoked, superseded and expired credentials, any caller-supplied schema, holder or window, and an expired signing key. The window never exceeds the credential's own validity: its end is the earlier of the claimed `validUntil` and `expiresAt − 1`, since the window end is inclusive and `expiresAt` is exclusive. Renewal refuses an expired credential and accepts only a u64 integer `expiresAt`. It names only the credential's *current* holder commitment, so issuing it creates no old-to-new mapping (§4.5 audit-mapping rules are unaffected).
* **Holders** name the credential to migrate with a `credentialId` request parameter and supply the NEW identity through the holder-local channel only: `ProofRequest(..., rebind_secret=RebindSecret.from_master_seed(fresh_seed))` (or `RebindSecret(new_binding_key)`). The new key/seed is the holder's next root secret, so it never travels in request parameters, which the verifier chooses and, on the authenticated path, signs and keeps; any request, APR, negotiation request or verifier policy naming `newMasterSeed`/`newCredentialBindingKey` (or any key whose name, ignoring case and separators, contains `seed`, `secret`, `mnemonic`, `passphrase`, `bindingkey`, `privatekey`/`privkey`) is refused before proving with `SecretInRequestError` (`SECRET_IN_REQUEST`). Delegated request batches refuse a nonempty `rebind_secret`; the secret stays in the holder process. `RebindSecret` has a redacted `repr`, cannot be pickled or JSON-serialized, and the audit-bundle and agent-log scans reject or redact those key names too (key names only: they cannot recognise a secret stored under a neutral key). `build_rebind_auth_witness{,_v2}` verify the attestation locally and refuse missing, zero, malformed, mismatched, expired, stale or revoked material before proving. A credential without an attestation cannot be rebound; ask its issuer for one.
* **Verifiers** must configure the issuer's exact key for the proof type *and* supply an authenticated accumulator state (`VerifierAccumulatorCache`) — a bare `IssuerAccumulatorState` is refused with `UNAUTHENTICATED_ACCUMULATOR`. `issuerIdHash` is checked against the matched trusted issuer; `schemaIdHash` is an optional narrowing filter applied only after authentication.
* **A rebind is a continuity claim, not a migration.** The credential stays bound to the old holder commitment (the new key cannot present or rebind it) and nothing in the statement is one-time, so one old key can fan a credential out to many keys. A verifier that moves an account on an accepted rebind keeps state with `zkc_verifier.RebindLedger`: `ledger.apply(envelope, request, result)` records only the rebind entries the verifier checked as answers to `request`, honours one claim per `(issuer, credential)` across statements and scopes, retires the old handle, treats an identical replay as idempotent, and freezes the credential on a conflicting second claim (resolution: the issuer revokes and re-issues). Real migration is issuer re-issuance to the new commitment.

There is **no downgrade path**: a request must name a successor explicitly, and neither direction of mapping between deprecated and successor identities is permitted.

The `scripts/check_credential_authentication.py` CI gate keeps this honest — every credential-derived circuit must either authenticate the credential (issuer signature + non-revocation, with a verifier contract, a binding sidecar, and adversarial tests) or be an explicitly contained identity the verifier refuses.

## Delegation trust anchor

`ZKCAgentClient.delegateViewing` and `HolderClient.delegate_viewing` mint a scoped token whose delegation key and holder commitment come from the same authenticated local master-seed bytes. A token's `holder_key_x` and `holder_key_y` fields are untrusted compatibility metadata: `DelegationToken.verify_signature()` checks only that the token is internally self-consistent under its claimed key. It does not authenticate the holder or authorize release of holder-controlled material.

Use `ZKCAgentClient.authorize_delegated_material` (which forwards to `HolderClient.authorize_delegated_material`) for that authorization. Delegated requests carry no APR, so authorization refuses unless the holder passes `allow_unauthenticated=True` (recorded as an `UNAUTHENTICATED` override per request). Material follows each reviewed request's presentation profile: anonymous by default, so a consumer requests and trusts the v2 sibling identity (for example `zkc:proof:jurisdiction:v4` for a `zkc:proof:jurisdiction:v3` request, spec §5.3). Scoped requests are refused; a linkable request also needs `allow_linkable=True`; a predicate outside the holder's accepted review statuses (for example draft `zkc:proof:kyc:v2`) needs the logged `allow_opaque=True`. Each opt-in counts only when it is exactly `True`. These checks, plus the parameter keys, context, composite rules and pure credential selection (trusted issuer, expiry, KYC level and attributes, canonical set), run before any delegation use is reserved, so their refusals consume no budget and record no override. Witness refresh, revocation and accumulator checks, backend and proving failures happen after the reservation and still consume the reserved uses; earlier proofs in a batch are discarded. The holder resolves its expected delegation key from local seed state, compares both token coordinates to that key, and verifies the signature under the locally resolved key before generating any proof material. Matching scope, consent, credential state, or `holder_commitment` is not a substitute; in particular, KDC-alias seeds can share a commitment while retaining distinct byte-domain delegation keys.

Mint usable tokens with `requests=[reviewed_request]` and the exact holder-reviewed `consents` mapping. The request commitment covers every `ProofRequest` field, including parameters, full context metadata, issuer trust and keys, accumulator epochs, binding selectors, presentation profile, request consent flags, and explicit per-predicate consent decisions. Requests must match the token's context, verifier, and proof types. Tokens minted without reviewed requests retain their historical inspection/signature behavior, but the holder refuses to authorize material with them.

`token.digest()` is the length-prefixed `zkc/delegation-token:v2` transcript of spec §5.4 (`delegation_token_transcript_v2` returns the exact preimage; known answers are in `tests/vectors/delegation_token_digest_v2.json`). Every field carries a `u32be` length, the proof-type list carries its count, and the reviewed request commitment is a field of the same transcript. The retired v1 transcript NUL-terminated strings and was not injective (security review R3.8). `DelegationToken.digest_version` must be exactly `2`: `digest()`, `verify_signature()`, `DelegatedProver` and the holder gate fail closed on any other value, and v1 tokens are not accepted. Re-mint them with a fresh `nonce`: the use store keys tokens by holder key and nonce, so reusing the nonce of a token already used under v1 fails closed ("delegation nonce was already bound to another token"). Proof types and `verifier_id` must be nonempty strings without code points of Unicode General Category `Cc`, `Cf`, `Cs`, `Co`, `Cn`, `Zl` or `Zp` (`validate_delegation_identifier`); minting, the holder gate and `ViewingScope.covers` refuse them, so NUL and invisible format characters such as zero-width joiners and bidi overrides cannot be signed into a scope. `proof_types` must be a tuple, principal key coordinates exactly 32 bytes, `context_value` an exact integer in `[0, r)`, and `max_uses` in `[1, 2^32)`. `ViewingScope.covers` matches only exact `str` query values. The policy is not a confusables filter: look-alikes, default-ignorable combining marks and variation selectors (U+034F, U+FE0F, U+180B), U+2800, `Zs` spaces (NBSP, U+3000, leading or trailing spaces) and Hangul fillers stay with the review UI.

Configure `HolderClient(..., delegation_use_store=SQLiteDelegationUseStore(path))` with a durable database in a holder-owned private directory (0700). All holder processes serving the same seed must use the same protected database. Authorization requires an explicit trusted local `now` and a principal signature over `delegation_authorization_digest(token.digest(), delegation_request_digest(requests, consents=consents), authorization_nonce)`; use a fresh 32-byte `authorization_nonce` per call, and pass it alongside the signature. The holder supplies `now` from its own trusted clock, never from the delegate, token, or proof request. Both helpers are exported by their respective `zkc_crypto` and `zkc_holder` packages. Missing storage, missing principal signatures, expired/not-yet-issued tokens, request substitution, and exhausted budgets fail before proving.

The store atomically records each authorization nonce and reserves one use per request in the batch before generating any material. Replaying a captured signature/nonce pair fails even when a token still has budget. A holder nonce cannot be rebound to another token. Reservations survive restart and are never refunded after proof failure or a lost response. Deleting, replacing, or restoring the usage database resets replay state, so protect and retain it alongside the holder's other authorization state. The store retains hashes and counters, not credentials or secrets. The holder proves from detached request snapshots so caller mutations cannot alter a request after its commitment was checked.

## Custody invariants

The holder's master seed is never passed to the proving toolchain. Credential binding keys enter the backend only as private circuit witnesses; neither secret belongs in a proof envelope or log. `NargoBackend` temporarily serializes circuit inputs and the solved witness inside a fresh 0700 workspace, creates witness inputs and reserved outputs exclusively without following symlinks at mode 0600, and runs its tools with a private file-creation mask. Concurrent calls use separate workspaces. The entire workspace is removed after success or an exception, and raw tool diagnostics are withheld because they can contain witness values. This cleanup does not promise secure erasure from storage media or cleanup after process termination; deployments requiring no disk exposure must supply an appropriate memory-backed temporary filesystem or their own backend.

The bundled `EncryptedFileCredentialStore` exists so the reference stack runs with the stdlib alone; production holders supply their own `CredentialStore` implementation backed by real authenticated encryption. Its file format `zkc-credential-store:v2` derives a 32-byte master key with PBKDF2-HMAC-SHA256 (600,000 iterations, a fresh 16-byte random salt on every write). The encryption key is `HMAC-SHA256(master, "zkc/credential-store/v2/enc")` and the MAC key is `HMAC-SHA256(master, "zkc/credential-store/v2/mac")`. The legacy v1 split of 64 PBKDF2 bytes is used only to read a v1 file for migration, so a v2 tag never authenticates v1 input. It encrypts with a SHA-256 counter-mode keystream under a 16-byte random nonce and authenticates with HMAC-SHA256 (encrypt-then-MAC, constant-time compare). The MAC covers a length-framed header (format version, KDF id, iteration count, salt, nonce) and the ciphertext. A salt or nonce of any length other than 16 bytes, an unknown field, or another KDF or iteration count fails before decryption. The store writes a 0600 temporary file created exclusively in the same directory, fsyncs it, and renames it over the store with `os.replace`. It refuses a symbolic link at the store path, and a planted `<name>.tmp` is never opened. Reads open with `O_NOFOLLOW|O_NONBLOCK` and require a regular file by `fstat`. This protection covers the final path component only: a symbolic link in a parent directory is followed, so keep the store in a directory that only the holder can write. Windows has no `O_NOFOLLOW`; there the check is an `lstat` before use only. If the directory sync after the rename fails, the error says the file was already replaced. A v1 file (unframed MAC input) is authenticated, checked entry by entry, and rewritten as v2 on first access; any inconsistency raises `StorageError` and leaves the file unchanged, and a v1 file in a directory the holder cannot write fails with a message that it requires migration. `SQLiteCredentialStore` creates a new database file with mode 0600 (SQLite gives its `-wal`/`-shm` files the same mode). It sets an existing database and its existing `-wal`/`-shm`/`-journal` files to 0600 when the current user owns them, refuses a symbolic link at those paths, and refuses to continue if the path changed between its own check and `sqlite3.connect`. A `file:` prefix is an ordinary file name; the store never opens SQLite URIs. It migrates a version-1 database in one transaction when it opens it.

Issuers choose credential identifiers, so a `credentialId` is unique only within its issuer. Every bundled store keys a credential by `(issuer_id, credential_id)`: a credential from another issuer that reuses an identifier is stored alongside the first, never in its place. `CredentialStore.get` and `delete`, and `HolderClient.update_witness` and `remove_credential`, take an optional `issuer_id`; without it they raise `AmbiguousCredentialError` (`AMBIGUOUS_CREDENTIAL`) when credentials from more than one issuer carry the identifier. Witness refresh during proving and lifecycle upkeep always name the issuer. Authenticated rebind names only a `credentialId`, so the holder narrows the matches to issuers the request trusts for the rebind proof type and refuses two trusted matches. A custom `CredentialStore` must implement the same keying and the optional `issuer_id` parameter. This is an API break: the holder client now calls `get(credential_id, issuer_id=...)` on every witness refresh, so a store with the old `get(credential_id)` signature raises `TypeError` on every accumulator-backed proof, not only when identifiers collide. `LifecycleManager.tick` reports refreshed credentials as `(issuer_id, credential_id)` pairs and failed refreshes with `issuerId` and `credentialId`; `TickReport.to_dict()` still omits credential ids.

## Tests

```bash
python3 -m unittest discover -s tests/python -t . -v
```

Live-proving integration tests skip automatically when `nargo`/`bb` are not on `PATH`.

Authenticated verifiers must configure `VerifierTrustPolicy(verifier_id=...,
verifier_signing_keys=(compressed_sec1_public_key, ...), issuers=...)` from their
own trusted configuration. Empty pins refuse every APR. Never pin the key from
the received APR. `verify_authenticated` checks the complete context and proof
age before proof verification and consumes the nonce only on success. Its
instance cache is in-memory; share `seen_nonces` across recreated instances and
supply atomic durable replay protection across workers/restarts. Omitted `now`
uses wall-clock Unix seconds. Pass an explicit trusted u64 `now` for historical
checks or deterministic simulation; a live admission clock must be independent
of the received request/context.

Holder, hosted, and verifier APR admission require a nonce encoded exactly as
`field_to_hex`: `0x` followed by 64 lowercase hex digits. Short, overpadded,
uppercase-digit, underscore, and whitespace aliases are refused even if their
signature is valid. Digest and historical receipt verification remain unchanged.
The holder checks the caller's `seen_nonces` container without populating it;
callers record observed canonical nonce strings and reuse that container across
calls. Omitting it gives no cross-call replay protection. The verifier retains
its own successful-use reservation behavior described above.

Holder and hosted admission also require complete context agreement. Opaque
contexts need `verification_context_extension(context)` merged into the request
before signing, and its context must match both the APR and the holder's
`ProofContext`. Known profiles still accept legacy fixtures that omit derived
fields. Admission snapshots the APR and context reference against caller
mutation while proving. Contradicting a valid signed context is refused before proving even
with `allow_unauthenticated=True`; the logged unauthenticated override remains
available for requests without a valid signature. Existing APR and receipt
digest bytes are unchanged.

APR and context timestamps must be exact u64 integers, and field inputs must
be canonical `[0, r)` scalars. Numeric strings, floats, booleans and modular
aliases fail before commitment. APR/receipt/context host commitments select
strict Poseidon input validation; arithmetic/KAT behavior is unchanged.
Delegation's length-prefixed v2 SHA-256 transcript applies the same strict integer checks;
the agent generates its default nonce uniformly in `[0, r)`.

Legacy APRs retain their digest and imply `maxProofAge=3600`. To sign a custom
age or opaque context, merge `verification_context_extension(context, age)`
(from `zkc_crypto`) into `request.extensions` before `sign_apr`; keep any
`request.maxProofAge` equal to the signed block. Holder and hosted admission require
the local `ProofRequest.max_proof_age` and any wire `request.maxProofAge` to equal
that authenticated age as exact non-negative integers, including the legacy
3600-second default. A disagreement under a valid signature is refused before
proving, even with the unauthenticated override. Context metadata and extension
must agree exactly after documented derived-field normalization. The extension
does not cover the legacy request `trustPolicy`. `protocol:<name>` scopes remain
local to the pinned signer, with distinct holder consent and verifier policy
declaration; the same name under another signing key is a different scope.

## Agent requester authentication

Configure `AgentCompliancePolicy.verifier_signing_keys` as a mapping from each
trusted verifier id to a tuple of compressed SEC1 public keys (33-byte `bytes`)
from trusted local configuration. Never take a pin from an incoming APR.
`ZKCAgentClient.handle_proof_request(request, context, apr=signed_apr)` requires
the signed APR to name the same verifier, canonical nonce, proof types,
parameters, and fully recomputable verifier-session or purpose-bound context.
Use the APR's canonical nonce in the `NegotiationRequest`; legacy negotiation
nonces alone do not authenticate a demand. Opaque contexts are always refused.

`precompute_proofs` accepts `(request, context, apr)` triples. Approval release
and cache release recheck the current key pins, policy, consent and APR expiry.
Queued objects and caller inputs are detached from the retained authorization.
If minimal planning changes the signed demand, obtain a new APR for that plan.
Every successful `AgentDecision` includes a holder-custodied `.receipt`; the
wire response contains only the envelope. Disclosure audit events name the
pinned `verifier_key` and `AUTHENTICATED` status, without signatures or receipts.
Authenticated generation follows the holder's anonymous presentation default;
issuer trust pins must cover the actual emitted predicate identity.
The holder's review-status gate applies to that identity, so a default holder
blocks with `GENERATION_FAILED` while the presentation entry is `draft`.

Only explicit `allow_unauthenticated=True` permits an unsigned request. This
uses the holder's authenticated generation entry point with its logged
`UNAUTHENTICATED` override and produces a holder-signed receipt whose demand is
unauthenticated. Audit records have no authenticated key in that case. A valid
signature under an unpinned key, a different verifier, or a contradictory context
is refused even with that override. Omitted `now` uses the local wall clock;
historical simulations must pass their own trusted integer time, including at
`approve`. Replay state and the warm cache remain instance-local; use one agent
instance per serialized holder admission stream and retain replay state across
requests. This reference client does not supply a durable, multi-worker agent
admission service.

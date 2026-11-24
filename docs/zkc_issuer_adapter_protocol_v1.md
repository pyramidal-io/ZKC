# ZKC Issuer Adapter Protocol v1

Status: Draft conformance profile

The issuer adapter protocol defines the provider-facing path from subject verification to holder-bound ZKC credential issuance. It is provider-shaped but provider-neutral: no issuer, provider, endpoint, schema, or jurisdiction is canonical or privileged.

## Privacy Boundary

Every adapter declares its authoritative capabilities as a nonempty exact immutable `frozenset` of supported schema ids and a `MappingProxyType` from every one of those ids to a nonempty exact `frozenset` of required privacy profiles. The mapping must cover exactly the supported set; every profile set includes `human`, and only the registered `human` and `machine` names are valid. The declaration is validated at construction and again by conformance before any case runs. It is not inferred from request data, metadata, or the first schema in a list. The runtime-attestation adapter declares exactly:

```text
supported_schema_ids = frozenset({"zkc:cred:runtime-attestation:v1"})
schema_required_privacy_profiles = MappingProxyType({
  "zkc:cred:runtime-attestation:v1": frozenset({"human", "machine"})
})
```

The existing human profile remains unchanged. A conforming issuer adapter MUST NOT receive any of the following human holder material:

- ZKA address
- `masterSeed`, spending key, proof key, or credential binding key
- note plaintext, nullifiers, note commitments not needed for a requested proof
- payment history or wallet transaction graph
- unencrypted ZKC witness material

The human-profile scan matches key names, never values. Each key is NFKC-normalized and casefolded, split on literal dots, and stripped of `_`, `-` and whitespace. A key path matches when any trailing run of its segments, across literal dots and nested objects, concatenates to a forbidden name. `masterSeed`, `master_seed`, `MasterSeed`, `master.seed`, and `{"master": {"seed": …}}` therefore all match. List and tuple indices add no segment. The error names the offending key paths but never their values.

The holder supplies only `holderCommitment = H("zkc/binding", cbk)`, schema request data, and a holder-control challenge response. The beta profile uses a challenge over `(holderCommitment, issuerId, schemaId, nonce, expiresAt)`.

The additive machine profile also rejects raw evidence/provenance keys; raw TEE quote, report, endorsement, collateral, runtime-measurement, and report-data keys; stable host, hardware, VM, chip, or cloud-instance identifiers; and build, source, checkout, workspace, working-directory, environment, build-parameter, or build-invocation keys. Matching is structural and key-based. Each key must be an exact nonempty ASCII `str`, at most 4,096 UTF-8 bytes, split on literal dots into segments matching `[A-Za-z0-9][A-Za-z0-9_-]*`. Every segment is ASCII-casefolded with `_` and `-` removed. A key path is the sequence of normalized segments from the root, across literal dots and nested objects alike. It matches when any trailing run of its segments concatenates to a forbidden name, so `teeQuote`, `tee_quote`, `tee-quote`, `tee.quote`, and `{"tee": {"quote": …}}` coincide. The human names above are matched the same way when both profiles are active. The forbidden suffixes below are matched as trailing segment runs too, so `build.components.path`, `buildComponents.path`, and `{"build": {"components": {"path": …}}}` coincide:

```text
build.path                  source.path
workspace.path              checkout.path
provenance.build.path       build.components.path
host.serial                 host.serialnumber
platform.serial             chip.id
build.builderidentity
```

List and tuple indices do not add semantic path segments. The scanner accepts only exact built-in `dict`, `list`, and `tuple` containers, rejects container subclasses and custom mappings, permits at most 32 containers of depth, 4,096 visited value nodes, and 4,096 UTF-8 bytes per key, and rejects repeated or cyclic containers. Non-string, empty, malformed, or non-ASCII/confusable keys fail closed.

The matcher never inspects scalar values. Generic keys such as `path`, `serial`, `id`, `identifier`, `report`, `statement`, `quote`, `measurement`, `digest`, `platformId`, and unqualified `builderIdentity` remain valid; `witness.path` is therefore not confused with a build path. The opaque handles `evidenceRef`, `providerRef`, and `subjectRef` are also qualified exceptions, with the scopes below. These exceptions do not permit a forbidden qualified key or a raw artifact to cross the boundary.

The active profile union is enforced before work at all five callable entries: stage 1, binding challenge request (stage 2a), binding response (stage 2b), issuance (stage 3), and revocation publication (stage 4). The schema-specific profile is also applied to the owned resolved provider result before issuer state retains it. Conformance scans successful stage-1, stage-2a, stage-2b, stage-3, and stage-4 results, issuer metadata, and the independently tested `renew_credential` result. A provider-private raw-evidence store is deliberately outside this scan: a provider may resolve and verify raw material there, but it must return only normalized claims and private references.

`evidenceRef` is a bounded opaque stage-1 locator consumed inside the provider boundary and is not retained in later results. `providerRef` is a stable identity allocated in the provider's private store, independent of request-supplied `subjectId`, `fixtureId`, or `evidenceRef`; it is never derived from those fields or returned publicly. It keys the private subject/schema issuance lineage. `subjectRef` is an independent CSPRNG continuation handle (at least 128 random bits; the reference uses 256) returned by stage 1, carried by stage-2a, stage-2b, and stage-3 requests, and allowed in the two binding results. It is not a stage-3 result, metadata, a credential claim, a stage-4 or renewal publication, an on-chain value, a proof public input, or a presentation disclosure.

Every machine-profile rejection uses `INVALID_HOLDER_CHALLENGE` and the fixed message `request includes forbidden privacy-boundary material`. The library puts no matched key, value, provider detail, host identifier, or path in the public error, cause, context, or its own logs. That narrow guarantee does not claim to sanitize arbitrary caller-owned locals, Python frame locals, or interpreter tracebacks.

## Stages

1. `verify_subject`

   The issuer performs provider-specific checks and authenticates the subject's authorization in the caller's authenticated session before returning a random, issuer-scoped `subjectRef` and session `expiresAt`. The continuation MUST be bound to that trusted session, expire, and be consumed on successful issuance. The reference TTL defaults to 600 seconds, configurable from 1 to 3,600, with expiry at `now >= expiresAt`. All later stages check the trusted session before accessing a challenge or binding. A request-body session id is never trusted. This handle MUST NOT be published on-chain or embedded in a proof public input.

2. `bind_holder_commitment`

   The holder sends `holderCommitment` and a challenge response. The issuer binds the verified subject once without learning the seed or ZKA address. A bound session cannot be rebound, including through challenges minted before binding. A fresh stage 1 is required to attempt another binding. The beta response is publicly computable and supplies tuple integrity only; the authenticated session and provider authorization enforce access.

3. `issue_credential`

   The issuer signs the credential digest for a supported `schemaId` and returns the credential body, issuer signature, revocation handle, and accumulator witness. It consumes the continuation and binding and permits only one issuance lineage per provider subject/schema. Repeating issuance with the handle or a new verification cannot create another credential. `renew_credential` is the only replacement path: it preserves the holder, authorizes the original trusted identity, and atomically replaces the active accumulator slot. Revoked credentials cannot be renewed or bypassed by opening a new lineage.

4. `publish_revocation_handle`

   The issuer publishes revocation metadata and accumulator state at the endpoint advertised by issuer metadata. Revocation affects only future credential proof acceptance by counterparties. Given a `credentialId`, the stage also returns that credential's status and, when active, its membership witness. This is a public oracle: credential ids are public accumulator leaves, so the answer reveals nothing the published leaf set does not. A credential id is never authorization for any operation. The reference adapter rate-limits stage 4 even when no per-stage limit is configured (`docs/zkc_metadata_leakage_threat_model.md` section 1.10).

## Trusted session integration

Production `BaseIssuerAdapter` / `ExternalProviderAdapter` constructors require a
`session_identity` callback returning the authenticated caller/session identity
from trusted, request-local gateway context (for example a `ContextVar` populated
after gateway authentication). Missing, empty, malformed, or failed context is
refused. The callback takes no payload. The provider receives this identity in
the keyword-only `authenticated_session` argument and MUST authorize its subject
for it. Never populate the callback from an unverified header or request JSON.

`SandboxIssuerAdapter` and the explicitly named `reference_*_adapter` factories
are test-only fixture entry points with a single local test identity. Fixture
selectors are public and perform no real authentication. The bundled
holder-facing HTTP server (`IssuerServer`) supplies no caller authentication,
TLS, or trusted identity injection and remains a local test transport. It routes
only the stages and metadata, never an operator mutation. Revocation and renewal
over HTTP are served only by the separate `IssuerAdminServer` listener, which
requires each request to be signed by a pinned operator key (ECDSA secp256k1,
bound to the issuer id, method, request target, body digest, a timestamp window
and a single-use nonce). It has no TLS either. Production integrations must
supply their own authenticated gateway and trusted callback; do not expose
fixture adapters as production.

The reference adapter serializes its in-memory sessions, lineage records and
mutation calls; lock order is adapter, accumulator, durable store. It retains
private claims, commitment, provider identity and trusted identity for renewal,
plus the original provider-verified expiry, separately from consumed continuations.
`renew_credential` accepts only `credentialId` and optional `expiresAt` and uses
the same active-profile privacy scan and per-client rate limit as protocol entries.
It authenticates the owning session before checking credential status, returning
one indistinguishable refusal for unknown and foreign ids. Only the current,
active, unexpired credential in an owned lineage can be replaced. The expiry
must be a future u64 integer and cannot exceed a nonzero original provider expiry;
that private bound survives every replacement. Omission keeps the current expiry,
and a shortened expiry may be restored within the original bound. Provider expiry
zero means no provider deadline; renewal still requires a finite future expiry.
Schema-specific claim/expiry consistency rules still apply, and renewal never
rewrites verified claims to accommodate a requested expiry.

An adapter MUST issue and renew credentials only with canonical identifiers in
`[1, r)`, where `r` is the BN254 scalar-field modulus. It MUST reject an
out-of-range identifier before signing or registration, without advancing the
accumulator. Zero is reserved for empty and revoked accumulator slots.

The reference adapter draws credential ids from a CSPRNG as canonical non-zero field elements,
skipping any id the adapter or accumulator already holds. They never derive
from an in-memory counter, so a restarted issuer cannot re-derive an id that a
durable accumulator holds. The accumulator API itself refuses a non-canonical
id (`0`, negative, `>= r`, or non-`int`) for every mutation. Queries report
such an id as unknown.

By default the issuance ledger is in memory, even when passed a durable
accumulator. An adapter starting with a non-genesis accumulator then refuses
issuance without its ledger. Pass `issuance_ledger=SQLiteIssuanceLedgerStore(path,
ledger_id)` to persist it (format `zkc:issuer-ledger:v1`, bound to the issuer
id and accumulator id). The adapter writes each new record as `pending` before
the accumulator mutation and as `committed` after it. On restart it promotes a
pending record that the accumulator holds and drops one that the accumulator
does not hold. It refuses to start (`IssuanceLedgerError`) when a committed
record is missing from the accumulator, when the accumulator holds a credential
with no record, or when the document is malformed or names another issuer or
accumulator. A restarted adapter with a consistent ledger issues fresh ids and
renews and attests pre-restart credentials for their owning trusted sessions.
The ledger holds provider identities, trusted session identities and verified
claims, but no key or holder secret; protect it like other provider-private
data. Before this format existed the reference adapter persisted no ledger, so
there is no earlier format to migrate.

A second adapter sharing the same accumulator object cannot independently reset
ownership, including at genesis. The guard is process-local; separate service
processes and replicas are not coordinated, and one adapter process must own a
ledger at a time. A durable accumulator without the ledger is not a durable
issuer service. If a publication read fails after registration, the
continuation stays consumed and cannot duplicate issuance; recover through the
private issuance record.

The optional `max_requests_per_stage` limit is a per-client sliding window
(`rate_limit_window_seconds`, default 60). The client is the trusted
`session_identity` value; unauthenticated revocation-publication reads share
one window. A request is charged only after it passes the payload checks, the
privacy scan and authentication, and before any provider call or state lookup,
so failed provider verifications and unknown credential ids count but malformed
or unauthenticated requests do not. A refused request is not recorded. Expired
binding challenges are purged, and one subject session may hold at most 8
unexpired, unused challenges (`RATE_LIMITED` beyond that). Stage 3 refuses a
provider expiry outside u64 (`UNSUPPORTED_SCHEMA`) and a nonzero expiry at or
before the current time (`PROVIDER_VERIFICATION_FAILED`). Zero remains the
circuits' explicit no-expiry value.

## Metadata Registry

Issuer metadata is a non-exclusive registry document. Verifiers decide which issuers, schemas, keys, and accumulator states they trust. The schema is published at `schemas/issuer-metadata.schema.json`.

Required metadata includes:

- issuer identifier, display name, and metadata version
- active signing keys, validity windows, and supported signature schemes
- supported credential schemas and proof types
- adapter endpoints for the four stages above
- revocation accumulator id, type, root, current epoch, update endpoint, and `maxEpochLag` (metadata v2 adds the signed `currentAnnouncement` and MAY add the signed head liveness statement `currentLiveness`)
- service-level publication fields: `maxRevocationPropagationSeconds`, `expectedIssuanceLatencySeconds`, and `metadataCacheSeconds`

For §7.2b selective disclosure, the launch publication profile is `zkc:issuer-metadata:v2`. Its `revocation.currentAnnouncement` is the complete closed `zkc:epoch-announcement:v3` object defined byte-for-byte in ZKC Specification §2.4.1. The unsigned convenience fields `accumulatorId`, `currentRoot`, `currentEpoch`, and `maxEpochLag` MUST equal the announcement's signed values. Publication MUST be atomic: the issuer durably records the announcement and makes it available through the current and historical announcement endpoints before exposing the matching metadata head.

Metadata v1 remains a legacy discovery shape only. It does not authenticate a §7.2b root and MUST NOT be silently upgraded. A metadata-published key is also not self-authenticating: `signingKeyId` is accepted only when that key is already pinned by verifier-local trust policy. Rotation therefore requires an out-of-band pre-pin (or a separately specified delegation signed by an already pinned key) before the new key signs an accepted head. Implementations fail closed on metadata/announcement mismatch, untrusted or expired keys (a key pin carries `notBefore`/`notAfter` and optional `retireAfterEpoch`, and the issuer refuses to sign outside its key window; specification §2.4.1), signature failure, downgrade, replay, gaps that cannot be boundedly backfilled, and non-linking successors.

The launch epoch rule is one announcement per successful state mutation: registration/issuance +1, revocation +1, and atomic renewal/replace +1. Failed, duplicate, and no-op requests publish nothing. This rule intentionally exposes state-mutation timing and volume; the alternatives and launch rationale are recorded in `docs/zkc_metadata_leakage_threat_model.md`. Changing the rule, the announcement bytes, or the meaning of an announcement's `announcedAt` requires a new announcement version.

A quiet issuer keeps its unchanged head fresh with the separately versioned `zkc:epoch-liveness:v1` statement (ZKC Specification §2.4.2). Metadata v2 MAY publish it as `revocation.currentLiveness`, atomically with the `currentAnnouncement` whose complete hash it names; the witness-update and epoch-delta responses MAY carry it as `liveness`. The field is additive and changes no announcement byte, epoch, or root: a consumer that ignores it applies the v3 rules unchanged. The issuer signs it with its active announcement key, inside that key's validity window, and re-signs it at least every liveness interval (900 seconds in the reference service). A published statement whose key is not in `signingKeys`, whose key is not valid at `issuedAt`, whose signature fails, or that names another announcement makes the document invalid. Consumers authenticate it against their own pins, never against the same document's `signingKeys`, and pin a successor key before the issuer rotates to it, because the successor signs liveness statements from that moment.

### Runtime attestation extension

The non-exclusive issuer registry includes `zkc:cred:runtime-attestation:v1` under ZKC Freedom Safeguard 1. This is capability advertisement, not a canonical issuer, root, schema, or trust decision. The extension maps only the third-party-verifiable AFP v2 roots: authenticated transparency-log inclusion for `root:build-provenance`, and an authenticated, fresh, collateral-checked report for `root:tee-attestation`. It rejects `root:publisher-manifest`.

Stage 1 includes the intended `holderCommitment` and resolves raw evidence through an opaque `evidenceRef` inside the provider boundary. The provider MUST cryptographically verify that authenticated report-data or the signed provenance subject commits to that actual holder commitment, using its authenticated challenge/nonce and replay policy. A public evidence locator or an echo of the requested commitment is insufficient. `ProviderDecision.holder_commitment` records the evidence-verified commitment; the adapter requires exact equality at stage 1 and binding, refusing absent or mismatched values. The static fixture requires a private `subjectIdentity` independent of evidence locators, so multiple reports/aliases for the same subject share a lineage. It checks its private `rawEvidence.holderCommitment` preverified verdict; this does not parse or authenticate opaque signed bytes. Only normalized claims cross the boundary. `provider_ref` remains issuer-private and is excluded from credential claims and public outputs. `expires_at` is the provider decision expiry; stage 3 publishes it as credential `expiresAt`, which must equal claim `validUntil`. It is not a raw artifact or subject identifier. Stage 2 enforces the evidence-verified holder; stage 4 is unchanged. Stage 3 may sign the registered credential, but the reserved proof type remains unreviewed and unregistered; Safeguard 4 refusal still applies. The strict credential contract is published as [`credential-runtime-attestation-v1.schema.json`](../schemas/credential-runtime-attestation-v1.schema.json).

The bundled `StaticPreverifiedRuntimeAttestationProviderClient` is test-only. It structurally validates and digest-binds caller-supplied preverified verdict fixtures; it does not cryptographically verify SLSA signatures, log checkpoints or inclusion, TEE reports, endorsements, or collateral. A production `ProviderClient.verify_subject` implementation MUST perform those cryptographic checks, plus revocation/collateral currency, freshness, measurement policy, and report-data binding, inside its provider trust boundary before returning `ProviderDecision`.

Runtime-attestation canonical JSON v1 is compact UTF-8 JSON over plain objects and arrays, UTF-8 strings, booleans, null, and signed 64-bit integers. Object keys are ordered by ascending Unicode scalar value; host-language default or UTF-16 ordering is not normative. The profile permits at most 32 nested containers, 4,096 total value nodes, and 4,096 UTF-8 bytes per key or string value. The credential schema permits at most 256 UTF-8 bytes per `rootAuthorityIdentifier` for every adapter. The static fixture additionally permits at most 256 evidence-store entries and 256 UTF-8 bytes per `evidenceRef`. Verification-context digests are canonical, nonzero lowercase `sha256:` digests. Violations fail with the fixed provider error; constructor misconfiguration uses one fixed non-sensitive error.

Canonical JSON v1 governs the evidence-store *structure* only. External artifacts — the signed provenance statement, transparency-log checkpoint, TEE report, and endorsement/collateral bundle — are exact scheme-native signed bytes and MUST NOT be re-encoded as JSON of any canonicalization. Their public digests use the versioned profile `zkc:runtime-attestation:external-artifact-digest:v2`: SHA-256 over the AFP External Artifact v2 framing `ASCII("AFP-External-Artifact-v2\0") || u32be(len(kind)) || UTF8(kind) || u32be(len(scheme)) || UTF8(scheme) || u64be(len(signed_bytes)) || signed_bytes` (AFP `docs/afp_specification.md` at `7d10e0e`). `scheme` is the nonempty ASCII identifier fixed by the accepted verification policy; `kind` is fixed per claim and root class:

| Claim | `root:build-provenance` | `root:tee-attestation` |
|-------|-------------------------|------------------------|
| `attestationEvidenceDigest` | `provenance-statement` — the exact signed provenance statement | `tee-report` — the exact hardware attestation report |
| `rootMaterialDigest` | `transparency-checkpoint` — the exact accepted signed checkpoint | `tee-endorsement-collateral` — the exact verifier-accepted endorsement/collateral bundle |

A store-carried external artifact is exactly `{"digestProfile", "kind", "scheme", "signedBytesHex"}` with the profile id above, the slot's fixed kind, a policy-fixed scheme, and nonempty lowercase hex of the exact signed bytes (at most 2,048 bytes in the static fixture). `includedStatementDigest` is the statement's external-artifact digest — the log's leaf commitment to the evidence — while the inclusion path stays provider-side and is never digested into a claim. Because the artifacts are opaque bytes, the manifest and verification-context bindings are provider-asserted verdict fields (`rawEvidence.artifactDigest` for build provenance; `rawEvidence.attestedManifestDigest` and `rawEvidence.verificationContextDigest` for TEE), checked for equality against the entry and configured context.

Versioning is explicit and fail-closed: the retired v1 canonical-JSON digest derivation is not accepted — a legacy entry carrying a parsed artifact tree fails with the fixed provider error, and credentials previously issued from canonical-JSON-derived digests are never silently reinterpreted under v2 semantics. Re-encoding an external artifact as JSON changes its bytes and therefore its digest; conforming implementations and the published known-answer vectors (`tests/vectors/runtime_attestation_external_artifact_v2.json`, including a deliberately rejected canonical-JSON re-encoding vector) make ZKC issuers and AFP verifiers derive byte-identical public digests for the same artifact.

JSON Schema `maxLength` counts Unicode code points; the normative issuer contract additionally enforces at most 256 UTF-8 bytes.

Normative baselines: ZKC `f69652c`, AFP `7d10e0e`, and the zka-langgraph runtime-attestation design merged at `8f02546`.

This privacy profile does not change any runtime-attestation claim key or credential-digest construction. It does not reinterpret or recompute AFP artifact digests, add an AFP artifact, circuit, proof type, TEE/provider trust policy, or platform/provider dependency. Those remain separate reviewed surfaces.

## Error Semantics

Adapters return stable error codes:

- `UNSUPPORTED_SCHEMA`
- `INVALID_HOLDER_CHALLENGE`
- `UNTRUSTED_ISSUER_KEY`
- `EXPIRED_ISSUER_KEY`
- `REVOCATION_METADATA_UNAVAILABLE`
- `STALE_ACCUMULATOR_WITNESS`
- `PROVIDER_VERIFICATION_FAILED`
- `RATE_LIMITED`

Errors MUST NOT include provider secrets, raw identity documents, or wallet identifiers.

## Production Adapter Interface & Conformance (annex)

The reference contract for implementing this protocol is the Python ABC `zkc_issuer.IssuerAdapter` (`python/zkc_issuer/contract.py`): the four stages above as typed methods (the bind stage is split into `request_binding_challenge` / `bind_holder_commitment`), plus the two issuer-side surfaces the ecosystem depends on (`issuer_metadata`, `revoke_credential`). `zkc_issuer.BaseIssuerAdapter` implements the shared protocol machinery. A production integration implements the provider boundary and declares the schema/privacy capabilities that boundary supports:

- `SandboxIssuerAdapter` — subjects resolve against bundled fixtures (reference adapter; passes the kit).
- `ExternalProviderAdapter` (`python/zkc_issuer/external.py`) — subjects resolve through a pluggable `ProviderClient`; `ProviderClient.verify_subject` is the ONLY place a vendor API call belongs, and it returns a provider-neutral `ProviderDecision` (issuer-attestable claims — never raw identity documents). The reference adapter's validated default capability is KYC-only. Replacing its client is therefore sufficient only for that KYC capability. A production adapter supporting any non-KYC schema MUST subclass it and declare a nonempty exact `supported_schema_ids` frozenset plus an exact `MappingProxyType` `schema_required_privacy_profiles` mapping with a nonempty exact `frozenset` entry for every declared schema. The bundled client is fixture-driven; no vendor is integrated or privileged.
- `StaticPreverifiedRuntimeAttestationProviderClient` (`python/zkc_issuer/runtime_attestation.py`) — test/reference-only static verdict binder, not an evidence verifier. Production runtime-attestation adapters supply their own cryptographic `ProviderClient` implementation.

Conformance is machine-checked by the issuer-adapter kit (`conformance/issuer_adapter/`, runner `conformance/run_issuer_adapter.py`). Any adapter implementation MUST pass every case; the case ids are stable API:

| Case id | Checks |
|---------|--------|
| `issuer-metadata-valid` | metadata document rules + no wallet-material fields |
| `stage-order-binding-requires-verified-subject` | binding requires stage 1 |
| `stage-order-issuance-requires-binding` | issuance requires stage 2 |
| `binding-rejects-wrong-response` | challenge response is actually checked |
| `binding-nonce-single-use` | challenge nonces cannot be replayed |
| `rejects-unsupported-schema` | schema set is closed (`UNSUPPORTED_SCHEMA`) |
| `privacy-boundary-every-stage` | human material is always rejected; declared-machine adapters also reject normalized machine keys, hostile structures, and raw evidence on independently otherwise-valid requests at all five entries, while clean public results remain free of private material |
| `envelope-holder-consumable` | envelopes parse as holder-SDK credentials bound to the holder commitment and carry canonical nonzero credential identifiers |
| `signature-verifies-under-published-key` | signature verifies under a metadata-published key over the schema-defined issuer digest |
| `witness-verifies-against-published-root` | accumulator witness proves membership under the published root |
| `revocation-publication` | revocation advances the epoch, flips status and refuses witnesses. Zero has no registration or witness |
| `renewal-credential-id` | when renewal is supported, the replacement has a fresh canonical nonzero identifier |

A seeded NON-conformant adapter (`conformance/issuer_adapter/seeded_bad_adapter.py`) exists to prove the kit catches violations. Its valid declared-machine seed deliberately runs only the human scanner and must fail only `privacy-boundary-every-stage`; CI asserts the exact failure sets. Passing the kit grants interoperability, not authority: verifiers still allowlist issuers explicitly, and no adapter, provider, or schema is canonical.

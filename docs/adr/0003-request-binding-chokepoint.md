# ADR 0003: Request-Binding Chokepoint for Predicate Verification

**Status: Accepted**
**Date:** 2026-08-26
**Accepted:** 2026-08-26

## Context

`python/zkc_verifier/verifier.py` ran a per-predicate requirement check for only
four proof families — KYC v1/v2, selective disclosure, and rebind v1/v2. For the
five other predicate families it registers — jurisdiction (v1/v2) and the four
`zkc_remaining_predicates` meanings (accreditation, source-of-funds,
tax-residency, sanctions-clearance; v1/v2) — `_verify_individual` and
`_verify_individual_v2` simply fell off the end of their per-type gate with no
branch at all. A syntactically and cryptographically valid proof for any of
these nine proof types passed verification regardless of what the caller's
`VerificationRequest.parameters` asked for: an inclusion proof answered an
exclusion request, an accreditation proof relabeled `zkc:proof:sanctions:v1`
was accepted as sanctions clearance, and a request with an empty parameters
dict verified as `True` with zero result entries. This is P1 of the
requirement this ADR closes.

A second, structurally distinct defect (P2) compounds the first for the four
`zkc_remaining_predicates` meanings specifically. `_load_circuit_map` maps
every declared `proofType` to its encoder's `circuit` field by globbing
`schemas/public-inputs/*.json`, and `VerificationKeyStore` keys verification
keys by **circuit name only** (`vk_store.py:49-53`). Because
`zkc:proof:{accreditation,source,tax,sanctions}:{v1,v2}` all compile to the
single circuit `zkc_remaining_predicates` (resp. `_v2`), all eight proof types
share one verification key. VK identity alone therefore carries zero
information about which of the four meanings a proof asserts — a proof can be
freely relabeled from one meaning to another and a VK-only check cannot tell
the difference. Closing P1 for these four proof types requires also closing
this labeling gap, or the new per-type gate could itself be defeated by a
relabeled proof.

`docs/zkc_public_input_classification.md` (ratified the same day as this ADR)
is the normative contract this decision implements: it enumerates, per
circuit, every public input's class (bound / derived / free) and what it must
be checked against. This ADR is the design record for how the verifier
satisfies that contract at the chokepoint; it does not restate the per-field
tables.

## Decision

### (a) Bind `apr.request.parameters` and assert agreement with the caller's request

For an authenticated presentation, the request the caller passes to
`verify_authenticated` and the request the holder actually answered (recorded
in the signed Authenticated Presentation Request, `apr.request`) are two
independent values. Nothing previously compared them. A caller could pass a
weaker `VerificationRequest` than the one the holder cryptographically agreed
to — silently downgrading the effective requirement — and the mismatch would
never surface.

`verify_authenticated` now runs a new step 0d, `_request_matches_apr`, before
delegating to `verify`: it canonicalizes both the APR's recorded request and
the caller's request (`_canonical_json`) and rejects on any divergence,
including proof-type-list and parameter-value mismatches. This is exactly the
check `docs/zkc_specification.md:1490-1500` already mandates normatively
(`verifyComplianceProof` step 0: `canonicalSerialize(request) !==
canonicalSerialize(apr.request)`), and the spec assigns it an existing code,
`UNSIGNED_REQUEST` — so the implementation emits `UNSIGNED_REQUEST`, not a new
code, for this condition. (An earlier draft of this change minted a distinct
`REQUEST_BINDING_MISMATCH` code for it; that was corrected before merge
because the reference verifier emitting an undocumented code where the
normative spec already names one would itself be a conformance defect, and
punch-list P3's conformance vectors are generated from that spec.) One
deliberate exception is documented in the implementation and is not a
loosening: an APR that names a proof type by its `:v1` family spelling while
the presentation profile answers with the sibling `:v2` type is resolved
before comparison by `_apr_presentation_proof_types`, which mirrors the
holder's own `_resolve_presentation` semantics (`zkc_holder/client.py`
~865-905) rather than guessing one fixed spelling for every case. The holder
computes `effective = min(apr_profile, holder_profile)` by presentation rank
(ANONYMOUS < SCOPED < LINKABLE) and answers with the `:v1` spelling only when
`effective` is LINKABLE; ANONYMOUS or SCOPED both answer with the `:v2`
spelling. `apr_profile` is the request's `presentation.profile` (defaulting
to ANONYMOUS when the block is present but silent on profile — not
LINKABLE), or, when there is no presentation block at all, the holder's own
ceiling, which this verifier cannot observe. Consequently: whenever
`apr_profile` is ANONYMOUS or SCOPED, `effective` can only land on ANONYMOUS
or SCOPED too (both rank at or below it), which share the `:v2` spelling
deterministically — so `:v2` is the SOLE accepted answer for that case.
Whenever `apr_profile` is LINKABLE (declared explicitly, or implied because
the request named no presentation and the holder's own unseen ceiling
governs), `holder_profile` could still pull `effective` down to
ANONYMOUS/SCOPED without this verifier ever finding out — so BOTH the `:v1`
and `:v2` spelling of that family are accepted in that case. A proof type
with no family mapping is left untranslated and must still match verbatim,
and parameter *values* are compared with full type strictness (`true` does
not equal `1`) regardless. Without this translation the verifier would
reject every authenticated v2 presentation, which is not the defect this ADR
closes.

An earlier version of this fix instead resolved every case through a single
`v1 -> v2` translation — `resolve_presentation_proof_type(family_for_v1_proof_type(pt),
profile)` called once per proof type, always producing exactly one accepted
spelling, with the unstated/no-presentation-block case defaulting `profile`
to LINKABLE. That default was wrong, not merely imprecise: the holder's own
default is ANONYMOUS, not LINKABLE (`zkc_holder/client.py:878, 884-892`;
`credential.py:151`), and `resolve_presentation_proof_type` returns the `:v1`
spelling for a LINKABLE profile. So an APR that never mentions `presentation`
at all — the common, presentation-silent authenticated exchange — had this
translation resolve to `:v1`, while the holder, governed by its real
ANONYMOUS ceiling, always answers `:v2`. This deadlocked every such exchange:
no `VerificationRequest` shape could satisfy both the APR-agreement gate and
the proof-type presence check downstream. Supplying `:v1` (matching the
gate's resolved expectation) satisfied the gate but left `verify()` unable to
find the `:v1` proof the envelope never contains (`MISSING_PROOF`); supplying
`:v2` (matching the actual envelope) failed the gate itself
(`UNSIGNED_REQUEST`) because it disagreed with the resolved `:v1`
expectation. Deriving `apr_profile` the same way the holder derives its own
default, and accepting both legitimate spellings exactly when that derivation
cannot be observed deterministically (the LINKABLE case), closes the
deadlock instead of merely relocating it.

**Divergence from the spec's literal comparison, stated plainly:** the spec
text compares the *whole* serialized `request` object
(`canonicalSerialize(request) !== canonicalSerialize(apr.request)`), while
`_request_matches_apr` compares only `parameters` and `proofTypes`. This is a
deliberate, narrower comparison, not an oversight: the signed APR digest
itself only commits to `proofTypes` + `parameters` (see `_apr_presentation_proof_types`
and the digest construction on the holder side), and the Python
`VerificationRequest` the caller supplies to `verify()`/`verify_authenticated()`
has no field carrying the request's other members (`context`, `trustPolicy`,
etc.) in the same shape `apr.request` does — there is nothing on the caller
side to compare those fields against without inventing a parallel
serialization the SDK does not define. Comparing the two fields that are both
(a) present on `VerificationRequest` and (b) part of what the signature
actually covers is the largest comparison this implementation can make
honestly; claiming a full-object comparison without one would be worse than
naming the gap. This is called out again under Follow-up.

### (b) Placement: inside `_verify_individual` / `_verify_individual_v2`, not `verify_authenticated`

The binding chokepoint is placed inside the per-predicate gates in
`_verify_individual` and `_verify_individual_v2` — the same functions that
already enforce KYC and selective-disclosure requirements — rather than solely
in `verify_authenticated`.

`verify_authenticated` has zero callers in this codebase today. If the fix
lived only there, every caller of the plain `verify()` entry point — which is
to say every caller that exists right now — would remain completely unbound
for these nine proof types, and the P1 gap would be closed on paper but open
in every real code path. Binding at `_verify_individual`/`_verify_individual_v2`
means the check runs for both the authenticated and the plain-`verify` path,
because both dispatch through the same per-proof-entry gate. `(a)`'s
APR-agreement check is additive on top of this, not a substitute for it: it
protects the authenticated path specifically against a caller passing a
weaker request than the holder agreed to, while the chokepoint in (b)
protects every path against a request-parameter/proof mismatch at all.

### (c) Interaction with the v1 freeze

`_verify_v1` (`verifier.py:528-530`) is documented as producing output
"byte-identical to the pre-dispatch `verify`". That freeze is a **structural**
invariant: it fixes envelope-version dispatch and the malformed-input
taxonomy so that v1 callers see no shape change in *how* a result is produced
or reported. It was never a promise that unsound acceptances would be
preserved, and treating it as one would make the freeze a vulnerability
pin rather than an API-stability guarantee.

Closing the P1 gap necessarily changes v1 verdicts for the five previously
unbound families: a proof that used to verify `True` with an empty error list
now verifies `False` with `REQUIREMENTS_NOT_MET` entries when its public
inputs disagree with the request. This is confirmed, not assumed. Before this
change, no test in the suite and no conformance vector in
`conformance/generate_vectors.py` asserted that any of these nine proof types
verify against an unmatched or empty `parameters` dict — the only existing
reference to `jurisdiction:v1` in `generate_vectors.py` is a `MISSING_PROOF`
vector that fails at step 5, before any per-proof check runs. The 12 existing
predicate tests in `tests/python/test_predicate_proofs.py` and
`tests/python/test_live_predicate_proving.py` already construct
`VerificationRequest`s with full matching parameters, so their expected
verdicts (`True`) are unchanged; the full suite (705 tests) passes unchanged
before and after this change. The freeze's structural guarantees — dispatch
shape and malformed-input taxonomy — are untouched: the new branches were
added inside `_verify_individual`'s existing per-type gate, and `_verify_v1`
and the version dispatch (`verifier.py:~219-236` prior to this change) were
not restructured.

### (d) P2: verifier-side `predicate_type` binding, chosen over per-predicate verification keys

Two ways exist to make `zkc:proof:{accreditation,source,tax,sanctions}:v1`
cryptographically distinguishable: (i) split `zkc_remaining_predicates` into
four (eight, counting v2) per-predicate circuits, each with its own VK, or
(ii) keep the single shared circuit and have the verifier compare the
proof's public `predicate_type` input against an authoritative
`proofType -> predicate_type` map before trusting anything else about the
proof.

This ADR chooses (ii). The circuit already folds `predicate_type` into the
claim binding and asserts it:
`compute_claim_binding_3(predicate_type, required_0, required_1, proof_context,
timestamp)` (`noir/zkc_remaining_predicates/src/main.nr:47-48`) is asserted
equal to the proof's public `claim_binding` at `main.nr:233`. A four-way VK
split would add domain separation the circuit's own constraint system already
provides; it would not close any soundness gap the shared circuit leaves
open. What it *would* cost is real: a P0 artifact regeneration for four (eight)
new circuits, four new `registry/predicates/<id>/<version>/` entries each
needing independent review evidence, and a second `noir compile` /
`bb`-artifact pipeline to keep in sync — for zero additional soundness over
comparing a public input the circuit already binds.

The authoritative map already exists and was already shipped by an earlier
change (P4): `schemas/public-input-bindings/zkc_remaining_predicates.json` and
`_v2.json` carry a `predicateTypes` object (`{"zkc:proof:accreditation:v1":
1, "zkc:proof:source:v1": 2, "zkc:proof:tax:v1": 3,
"zkc:proof:sanctions:v1": 4}`, mirrored for `:v2`), pinned against the
circuit's own `PREDICATE_*` Noir constants by
`tests/vectors/validate_public_input_encoders.py`. `PublicInputBindings`
(`python/zkc_crypto/encoders.py:111-165`) already exposes
`.for_circuit(root, circuit).predicate_type_for(proof_type)` over that sidecar
and was, before this change, unused at runtime. The fix is to use it as the
sole source of `predicate_type` — never a literal — with a missing
sidecar/entry resolving to the new `UNBOUND_PROOF_TYPE` code and no fallback.

**Residual risk, stated plainly:** this decision is a verifier-side fix. VK
identity alone still does not distinguish the four meanings — nothing at the
cryptographic-artifact layer changed. Any *other* implementation of a ZKC
verifier that checks the VK and the claim-binding recomputation but skips the
authoritative-map comparison inherits exactly the same bug this ADR closes.
That is precisely why this requirement does not stop at one Python
implementation: `docs/zkc_public_input_classification.md` states the
`predicate_type` / `set_root` binding as a normative, per-circuit contract
(punch-list P3), and conformance vectors exercising a relabeled
`predicate_type` are the durable way to make a non-conforming verifier fail
CI rather than fail silently in production.

### (e) `community-kyc/1.0.0` vs `zkc-kyc/1.0.0`: not a third collision

Part of this requirement's remit was to determine whether the two registry
entries sharing `vkHash`
`0x01acb7647dbd8a70110bdd35648e383ffc79bcc8a16bd5c24e4d9853fe7a2c2c` (and every
other circuit field) constitute a third instance of the P2 defect — two
listings, one artifact, colliding meanings. They do not, and the registry's
own review records say so explicitly rather than requiring inference:

`registry/reviews/community-kyc-1.0.0.md` states: *"This entry was authored in
this repository by the same maintainer as `zkc-kyc`, and it pins the identical
circuit — same `sourcePath`, same `sourceSha256`, same ACIR and
verification-key hashes, same public-input encoder. A reader should treat it
as a structural placeholder demonstrating that independent lineages can
coexist, not as evidence that an independent party has listed or reviewed this
predicate."* And further: *"It is not a third-party listing."* The entry is
seeded, per that same record, *"so that the registry's pluralism guarantee is
executable rather than aspirational: lookups must return every matching
entry, never a blessed one, and that property is only testable when more than
one entry exists."*

This is the opposite shape from the P2 defect. The P2 bug was **one
verification key backing four distinct meanings** (`predicate_type` 1 through
4), each of which a caller could silently substitute for another. The
`community-kyc` / `zkc-kyc` pair is **two registry listings for the same
proof type with the same meaning** (`zkc:proof:kyc:v1`, byte-identical circuit,
byte-identical encoder) — disclosed on the record as intentional aliasing to
prove out non-exclusivity, not an independent listing and not a second meaning
sharing a key. No verifier-side change closes or should attempt to close this;
it is a registry-governance fact, not a soundness gap, and it is already
correctly labeled `self_attested` (not `reviewed`) in both review records for
an unrelated, previously-resolved reason (no independent third-party review
of either listing) documented in
`registry/reviews/zkc-kyc-1.0.0.md`'s Disposition section.

## Consequences

- v1 and v2 verdicts change for nine previously-unbound proof types
  (jurisdiction v1/v2; accreditation/source/tax/sanctions v1/v2): proofs whose
  public inputs disagree with the request now fail with
  `REQUIREMENTS_NOT_MET`, `UNBOUND_PROOF_TYPE`, or (authenticated path only)
  `UNSIGNED_REQUEST` where they previously verified silently.
- One new error code, `UNBOUND_PROOF_TYPE`, is added to
  `VerificationErrorCode` and its `ALL` tuple in
  `python/zkc_verifier/errors.py`. The request-vs-APR disagreement condition
  does **not** get a new code: `docs/zkc_specification.md:1490-1500` already
  mandates this exact check and names `UNSIGNED_REQUEST` for it, so the
  implementation reuses that code (see (a) above) rather than adding a
  second. `UNBOUND_PROOF_TYPE` is different: the spec contemplates no
  equivalent state (a proof type wholly outside the binding registry), so
  there is no existing code to conform to.
- The original chokepoint fix made no circuit, registry-entry, or artifact
  change. A follow-up added the remaining-predicate v3/v4 circuit generations
  to bind `flagRequired`. The v1/v2 and v5/v6 identities remain immutable;
  the combined raw-code, validity-bound, and exact-adjacency hardening is
  published additively as v7/v8.
- `VerificationWarningCode.UNBINDABLE_PARAMETER` remains part of the API for
  compatibility, but a positive or malformed legacy accreditation
  `flagRequired` request now fails with `REQUIREMENTS_NOT_MET`. False/absent
  remains usable. v3-v8 bind the exact boolean and therefore need no warning.
- Accreditation's `set_root` is bound as a `_FixedValue(0, "setRoot")`, not a
  request-settable `_Param`, because the circuit never constrains this input
  on that branch (`main.nr:194-197`) — the only sound "requirement" is the
  literal the spec fixes. A request asking for any other `setRoot` value is
  rejected outright (`REQUIREMENTS_NOT_MET`, naming `setRoot` and "must be
  0") rather than being echoed back as an expectation the predicate cannot
  actually enforce.
- `_verify_predicate_requirements` fails closed when
  `request.parameters[proof_type]` is not a mapping at all (`None`, a list,
  …): it rejects with `REQUIREMENTS_NOT_MET` instead of raising
  `AttributeError`/`TypeError` out of `_resolve_binding_source`'s own `.get`
  call, mirroring the KYC path's existing `(KeyError, TypeError, ValueError)`
  catch for the same class of malformed input.
- `flagRequired` remains unenforceable in immutable v1/v2 because it is a
  private witness outside their claim-binding preimage. The additive v3/v4
  successors close that gap by folding the same private bit into
  `compute_claim_binding_4`; the verifier recomputes it from the request while
  the circuit uses it to gate the issuer-signed institutional `claim_1` check.
  The request bit is deliberately not added to the credential digest. v7/v8
  preserve this transcript exactly while adding non-zero raw-code and adjacent
  sanctions-neighbour constraints; circuit suffixes MUST NOT be used to infer
  a binding formula.
- Remaining-predicate v1-v6 are deprecated but remain verifiable under an
  explicit policy for historical proofs. New linkable proofs resolve to v7 and
  new anonymous/scoped proofs resolve to v8; absence of an acceptable current
  entry is a refusal, not permission to fall back to a vulnerable profile.
- The gap this ADR closes for the reference implementation remains open for
  any independent ZKC verifier implementation until the normative contract
  (`docs/zkc_public_input_classification.md`) and conformance vectors for it
  are the thing new implementations are tested against — see (d).

## Follow-up

- Registry-completeness test added alongside this ADR
  (`tests/python/test_request_binding.py`): it asserts that
  `_REQUEST_BINDINGS` covers every non-excluded proof type the encoders
  declare across `schemas/public-inputs/*.json`, so a newly added predicate
  type cannot silently reach the chokepoint unbound. The exclusion set (the
  aggregation envelope types, handled by `_verify_aggregation*` rather than
  `_verify_individual*`) is verified against the dispatch code, not assumed,
  and the test comments say why each exclusion is safe.
- For punch-list P3: add `UNBOUND_PROOF_TYPE` to `docs/zkc_specification.md`
  §6.2's error-code table — the spec has no equivalent code today. Separately,
  consider whether the spec should be amended to add a distinct, more
  diagnostic code for request-vs-APR disagreement instead of overloading
  `UNSIGNED_REQUEST` for two conditions ("not authenticated at all" vs
  "authenticated but disagrees with the caller's request") — today both are
  intentionally the same code per (a) above, distinguished only by message
  text, because the spec as written names only one code for this whole
  family and the reference verifier must not invent one unilaterally.
- P3 should also decide whether `docs/zkc_specification.md`'s step-0 request
  comparison should be narrowed to match what a real APR digest and a real
  `VerificationRequest` can actually carry (see the "Divergence from the
  spec's literal comparison" note in (a)), since as written it compares the
  whole serialized request object, which no implementation described in this
  repo can currently do.
- Extend `conformance/generate_vectors.py` with negative vectors for each of
  the nine previously-unbound proof types (mismatched `membershipType`,
  relabeled `predicate_type`, prover-chosen `setRoot`, empty parameters),
  so any independent verifier implementation is tested against the same
  regression this ADR fixes in the reference implementation.

# ZKC Minimal-Disclosure Planning & Verifier Policy Negotiation

**Status:** Reference (non-normative)
**Implementation:** `python/zkc_holder/planner.py`, `python/zkc_holder/ceilings.py`, `python/zkc_verifier/disclosure.py`
**Wire version:** `zkc:negotiation:v1`

This document describes the reference SDK's minimal-disclosure proof planner and the small request/counter-offer negotiation protocol built on top of it. It is a reference for the privacy behavior the SDKs implement; it changes no normative protocol surface (credentials, circuits, proofs, or envelopes are untouched).

## Problem

A verifier asks for a proof. Without planning, the holder's only choices are "satisfy exactly what was asked" or "refuse" — even when the verifier's own PUBLISHED trust policy says it needs less than it asked for (e.g. a request demands KYC level 3 with all five verified attributes while the published policy minimum is level 1 with one attribute). That gap is the compliance over-disclosure problem: every element disclosed beyond the published need is a privacy loss with no compliance gain.

## Published policy minimums: `proofRequirements`

Published verifier trust policies (`registry/verifiers/*.json`, schema `registry/schema/verifier-policy.schema.json`) may carry an **optional** `proofRequirements` section:

```json
"proofRequirements": {
  "zkc:proof:kyc:v1": {
    "requiredLevel": 1,
    "requiredAttributes": [true, false, false, false, false]
  }
}
```

Semantics:

- When present, it is the **complete statement of the verifier's need**: each listed proof type (which must also appear in `acceptedProofTypes`) maps to the minimum parameters the verifier requires. A parameter the policy does not publish is a parameter the policy does not need.
- Requests beyond these minimums are **overbroad**. Requested proof types not listed in `proofRequirements` are **unnecessary predicates**.
- Each minimum states only keys its typed disclosure comparator governs (see below), each well-formed for its rule: for example KYC `requiredAttributes` is exactly five booleans and `requiredLevel` a non-boolean integer in `[1, 255]`. Witness paths, unknown keys and proof types with no comparator are rejected when the policy is validated, so the planner and the counter-offer evaluator always read the same requirement.
- When absent, the policy publishes no parameter minimums: holders cannot narrow, and an accepted request is taken as the best available statement of need.
- Like everything in the discovery registry it is **discovery only** — enforcement stays verifier-local, and publication grants/removes nothing (Freedom Safeguard 1).

Accessor: `zkc_registry.VerifierPolicyDocument.proof_requirements()`.

## The planner (`zkc_holder.ProofPlanner`)

```python
from zkc_holder import ProofPlanner, NegotiationRequest
from zkc_registry import DiscoveryRegistry

registry = PredicateRegistry.from_repo(repo_root)
policy = DiscoveryRegistry.from_repo(repo_root).verifier_policy(verifier_id)
planner = ProofPlanner(registry, policy)
```

Planning is a **pure policy computation**: it never reads the credential store, so producing (or refusing) a plan leaks nothing about which credentials the holder holds.

### `plan(request, consent_scope=None) -> PlanReport` (strict)

Computes the minimal satisfying plan, or refuses:

- **Opaque predicates**, and predicates whose registry review status is outside the planner's accepted set (`accepted_review_statuses`, defaulting to `zkc_holder.registry.DEFAULT_ACCEPTED_STATUSES`), raise `OpaquePredicateError` — the existing Safeguard-4 refusal path.
- **Any overbroad element** raises `OverbroadRequestError`, whose `.elements` lists every overbroad element as `{proofType, element, requested, permitted, kind}` with kinds:
  - `predicate_not_accepted` — proof type outside `acceptedProofTypes`;
  - `unnecessary_predicate` — accepted, but not in `proofRequirements`;
  - `parameter_exceeds_policy` — a parameter beyond the published minimum in the direction that discloses more, or (for a pinned value such as a set root) different from it, or malformed;
  - `unknown_parameter` — a parameter, or a proof type, that no typed comparator governs;
  - `beyond_consent` — outside the holder's explicit consent scope.
- Otherwise returns a `PlanReport`.

`consent_scope` is an optional holder-side ceiling: `{proof_type: parameter object}`, in each proof type's own request vocabulary. Requests beyond it are refused (`beyond_consent`), independent of policy. The agent's `AgentCompliancePolicy.disclosure_ceiling` is passed here. Both the ceiling and a published minimum are compared with the typed comparators below.

### Typed disclosure comparators (`zkc_holder.ceilings`)

A ceiling or minimum is only meaningful if the comparison knows which direction discloses more. Key presence is not enough: before security review 2026-10-04 (R3.6) only KYC values were compared, so a ceiling of accreditation `required0 = 100000` admitted a request for `required0 = 10000000000`. Every parameter of every proof type now has one rule kind:

| Kind | Meaning | Comparison with the bound |
|---|---|---|
| `threshold` | exact integer in the circuit's unsigned domain (u8 or u64); **larger discloses more** (the circuit proves `value >= requested`) | refused when requested > bound, or when either side is outside the domain (the circuit casts it, so `-253` would act as `3`); narrowed to `min` |
| `flag` | exact boolean; **`true` adds a requirement** | refused when requested is `true` and bound is `false`; narrowed to `and` |
| `flag_vector` | fixed-length booleans, each `true` adds a requirement | refused for any extra `true`; narrowed element-wise |
| `subset` | distinct integer positions; **a superset discloses more** | refused for any position outside the bound; narrowed to the intersection |
| `pinned` | no disclosure order (roots, modes, claim types, dead slots, fixed flags, selectors) | must equal the bound exactly; never narrowed |
| `canonical_set` | canonical code list deriving a set root, and from which the holder derives its own witness | against a ceiling, a requested list must equal the ceiling's list as a set; against a published minimum, lists are compared only when both state one |
| `witness_path` | verifier-supplied Merkle path or exclusion neighbours | not compared value by value, but governed through the set-predicate rules below: a fixed inclusion path makes the proof an exact-member disclosure |

An absent key takes the documented default on both sides: the verifier's own default where it has one (KYC `requiredLevel` defaults to 1, not 0), otherwise the least-disclosing value. Values are type-strict: a boolean is not an integer, and a pinned root given as an integer does not equal the same root given as a hex string (fail closed). The table is keyed by circuit family and, for the multiplexed remaining-predicates circuit, by proof-type meaning, like the closed request vocabulary (spec §6.2.1):

| Family / meaning | Parameter | Kind (default) | Why this direction |
|---|---|---|---|
| `zkc_kyc`, `zkc_community_kyc` | `requiredLevel` | threshold u8 (1) | the circuit proves `kycLevel >= requiredLevel`; a higher level admits fewer holders |
| | `requiredAttributes` | flag_vector[5] (all false) | each `true` proves one more verified attribute |
| `zkc_selective_disclosure` | `disclosedPositions` | subset (empty) | each position reveals one attribute value |
| `zkc_selective_disclosure` | `layoutId` | pinned | positions have meaning only within the exact layout |
| `zkc_jurisdiction` | `membershipType` | pinned | inclusion vs exclusion; modes are not ordered |
| | `requiredClaimType` | pinned | which jurisdiction claim is proved; claim types are not ordered |
| | `jurisdictionSetRoot` | pinned | roots of different sets are not comparable |
| | `jurisdictionCanonicalSet` | canonical_set | the code list that derives the root |
| | `membershipPathIndex`, `membershipSiblings` | witness_path | without a canonical list the holder proves along this path: exact-member disclosure |
| | `predecessor*`, `successor*` | witness_path | exclusion neighbours; the holder re-derives them from the list exclusion requires |
| `zkc_remaining_predicates` / `accreditation` | `required0` | threshold u8 (0) | the circuit proves `accreditationLevel >= required0` |
| | `flagRequired` | flag (false) | `true` additionally proves institutional status from the issuer-signed `claim_1` |
| | `required1` | pinned (0) | circuit-dead claim-binding slot |
| | `setRoot` | pinned (0) | unconstrained on this branch; the contract requires 0 |
| `zkc_remaining_predicates` / `tax` | `required1` | threshold u64 (0) | the circuit proves `taxYear >= required1`; a later minimum year discloses more |
| | `required0` | pinned (0) | circuit-dead slot |
| | `flagRequired` | pinned (false) | the contract requires false |
| | `setRoot` | pinned | accepted tax-jurisdiction set root |
| | `pathIndex`, `siblings` | witness_path | the holder always proves along this path: exact-member disclosure |
| `zkc_remaining_predicates` / `source` | `required0`, `required1` | pinned (0) | circuit-dead slots |
| | `flagRequired` | pinned (false) | the contract requires false |
| | `setRoot` | pinned | accepted-source set root |
| | `pathIndex`, `siblings` | witness_path | the holder always proves along this path: exact-member disclosure |
| `zkc_remaining_predicates` / `sanctions` | `required0`, `required1` | pinned (0) | circuit-dead slots |
| | `flagRequired` | pinned (false) | the contract requires false |
| | `setRoot` | pinned | blocked-set root |
| | `canonicalSet` | canonical_set | the blocked-code list that derives the root |
| | `predecessor*`, `successor*` | witness_path | exclusion neighbours; the holder re-derives them from the required list |
| `zkc_credential_rebind_auth` | `credentialId` | pinned | selects the credential whose public `credential_id` the proof reveals |
| | `schemaIdHash` | pinned | schema equality pin |

Set roots are pinned rather than ordered because a root alone does not reveal its set: two roots cannot be compared for size or containment. A pinned root is NOT consent to how much a set proof reveals; that is governed separately below.

Without a circuit (the verifier's audit, counter-offer evaluation), rebind proof types (`credential_rebind`, `rebind`) use a meaning-level comparator that pins every key any rebind generation accepts (`credentialId`, `schemaIdHash`, `issuerIdHash`) and orders none. The planner always uses the registry-resolved circuit, and a circuit selects a comparator only for the meanings its family serves.

**Refused under a ceiling.** A proof type with no comparator is always refused under a ceiling (`beyond_consent`, element `proofType`). By design that covers the aggregation identities (`zkc_aggregation`, envelope-level blocks, never individual requests) and the unauthenticated rebind statements (`zkc_credential_rebind`, `zkc_credential_rebind_binding`, `zkc_credential_rebind_v2_binding`, which verifiers reject unconditionally, spec §4.5). `tests/python/test_disclosure_ceilings.py` derives every proof type from the repository's encoders and requires each to have a comparator with a rule for every key of its closed request vocabulary, or a family in this refused list.

**Planning against a published minimum** keeps the predicate's own parameters: ordered values (thresholds, flags, attribute vectors, positions) are lowered toward the minimum, while pinned values, canonical sets and witness paths are kept. A pinned mismatch with the minimum is a hard refusal, not a narrowing: substituting the published root would plan a statement the consent check never saw.

### Set predicates and exact-member disclosure

A set predicate can disclose more than its parameters suggest. Membership in a singleton inclusion set reveals the exact jurisdiction. Worse, an inclusion proof along a **verifier-fixed Merkle path** is an equality test: with the path index and siblings fixed, only one leaf hashes to the root, so a successful proof (or the holder's refusal) reveals the holder's exact code, whatever set the root was built from. The holder derives its own witness only from a canonical code list in the request (`jurisdictionCanonicalSet`, `canonicalSet`, spec §7.2c.5). Without one, it proves along the request's path, or along the default path when none is supplied.

`zkc_holder.ceilings.set_disclosure` therefore sizes the anonymity set (the codes the proof leaves possible) only from what constrains the witness, never from a ceiling's list:

| Request | Outcome | Anonymity set |
|---|---|---|
| jurisdiction or sanctions with a canonical list | determined | inclusion: distinct listed codes; exclusion: the u16 domain `[1, 65534]` minus the blocked codes |
| jurisdiction inclusion without a list; source of funds and tax residency always | exact member | 1 |
| unknown `membershipType`, malformed list, exclusion without a list | unknown | - |

Under a ceiling, an `unknown` request is refused (`beyond_consent`). An `exact member` request is refused too, unless that proof type's ceiling sets the ceiling-only key `"allowExactMemberDisclosure": true` (exact JSON `true`; `AgentCompliancePolicy` rejects any other non-boolean value, and the closed request vocabulary rejects the key in a request). This is the principal's explicit consent to reveal the exact member. Source-of-funds and tax-residency codes are full field elements with no canonical-set construction, so every such proof is exact-member and always needs the opt-in.

The planner attaches holder-local overbreadth notes to `PlanReport.warnings` (not part of the `zkc:negotiation:v1` wire shape, and ignored by equality). The agent shows them in the approval summary and the `proof_disclosed` notification, and records them in the `proof_disclosed` audit entry:

- `narrow_set`: the anonymity set has fewer than `NARROW_SET_THRESHOLD = 5` codes (`anonymitySetSize: 1` for an exact-member proof).
- `verifier_inclusion_path`: the request ships inclusion-path material (`pathIndex`, `siblings`, `membershipPathIndex`, `membershipSiblings`).
- `set_size_unknown`: the size cannot be determined.

The verifier's own audit (`disclosure_warnings`) reports a narrow listed set, and any request that ships inclusion-path material, as `OVERBROAD_REQUEST`.

**Known limitation.** The repository defines no assigned-code domain per predicate (tracked by security review R5.2). Sizes count every code of the u16 canonical domain, so an inclusion set padded with unassigned codes is over-counted (`[840, 60001, 60002, 60003, 60004]` counts as 5), and a narrow exclusion set is never detected: requests carry at most 4096 blocked codes, which leaves more than 61000 codes of the domain.

### `PlanReport`

The structured explanation of what is disclosed and why:

- `items`: one `PlanItem` per disclosed predicate — proof type, the narrowest parameters, the resolved registry entry (`predicateId`, `entryVersion`, `circuit`), and a `justification` list mapping each disclosed element to the policy clause that requires it (e.g. `requiredLevel → proofRequirements['zkc:proof:kyc:v1'].requiredLevel`).
- `narrowed`: the elements the plan reduced relative to the original request.
- `to_proof_request(context, trust_policy)`: materializes the plan as a holder `ProofRequest` for `HolderClient.generate_authenticated_proof` (the verifier's signed APR must commit to the planned proof types and parameters).
- `to_dict()/from_dict()`: stable JSON shape.

### Minimality

The plan is **exactly** the published minimum when the request is at or above it: the smallest predicate set, the lowest satisfying threshold (KYC level, accreditation level, minimum tax year), no requirement flag, verified attribute, or disclosed position the policy does not require, and the predicate's pinned values unchanged. Property-style tests (`tests/python/test_disclosure_planning.py`) sweep generated policies and verify that every single-step weakening of a plan (level − 1, or any required attribute dropped) no longer satisfies the policy.

## Negotiation protocol (`zkc:negotiation:v1`)

Three in-process objects with stable JSON wire shapes (no network protocol is defined here):

1. **`NegotiationRequest`** (verifier → holder): `verifierId`, `proofTypes`,
   `parameters`, `nonce` (`type: "proof-request"`).
2. **`NegotiationCounterOffer`** (holder → verifier,
   `planner.counter_offer(request)`):
   - `status: "counter"` with the minimal `plan` when the request is
     narrowable — overbroad parameters are reduced to the published minimums
     and unnecessary predicates are dropped (recorded in `plan.narrowed`);
   - `status: "refusal"` with `refusal.code` and structured
     `refusal.elements` when the request is overbroad beyond repair
     (unaccepted predicate, beyond consent) or names an opaque predicate.
3. **`NegotiationDecision`** (verifier → holder,
   `evaluate_counter_offer(policy, counter)`): `accept` iff the counter-plan
   satisfies the verifier's own published minimums exactly — it rejects both
   under-disclosure (below minimum) **and over-disclosure** (beyond minimum):
   a verifier must not silently accept more than its published policy needs.

All `from_dict` parsers fail closed on a wrong `version` or `type`.

### Constant-shape refusals

Every wire-level refusal carries the same message (`zkc_holder.REFUSAL_MESSAGE`: `"cannot satisfy this proof request"`), whether the private cause is "no such credential", "policy refusal", "consent refusal", or "opaque predicate". Combined with planning being store-independent, a refusal does not reveal whether the holder holds the credential — see the metadata-leakage threat model.

## Verifier-side disclosure hygiene

Two **non-fatal warning codes** (`zkc_verifier.VerificationWarningCode`) complement the closed error enumeration. Warnings never affect `VerificationResult.valid`; they flag disclosure-hygiene issues a verifier should not silently ignore:

- **`OVER_DISCLOSURE`** — `ZKCVerifier.verify` now warns when an envelope contains a proof the request did not ask for (still ignored for validity per spec §6.2 step 4a).
- **`OVERBROAD_REQUEST`** — `zkc_verifier.disclosure_warnings(request, policy, envelope=None)` audits the verifier's **own** request (and optionally a received envelope) against its published policy: requests above the published minimums (typed per predicate), requests for unlisted predicates, set predicates over a narrow set, and extra envelope proofs are all flagged.

## Relationship to the Freedom Safeguards

- **Safeguard 1** — published policies and `proofRequirements` are discovery data; nothing here turns registry membership into trust, and the planner only ever narrows toward, never substitutes for, verifier-local enforcement.
- **Safeguard 2 (minimal disclosure)** — the planner makes the lowest-privilege selection a *planned* property (with a per-element justification), instead of only a credential-selection heuristic.
- **Safeguard 4** — opaque predicates, and predicates whose review status the planner does not accept, are refused through the existing logged refusal path before any policy reasoning happens.

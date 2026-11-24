# ADR 0004: Issuer-Authenticated Credential Rebind Statements

**Status: Accepted**
**Date:** 2026-09-06
**Accepted:** 2026-09-06

## Context

The four published credential-rebind statements — `zkc:proof:credential_rebind:v1`
(`zkc_credential_rebind`), `zkc:proof:rebind:v2` (`zkc_credential_rebind_v2`),
`zkc:proof:credential_rebind:v2` (`zkc_credential_rebind_binding_v2`) and
`zkc:proof:rebind:v3` (`zkc_credential_rebind_v2_binding_v2`) — were specified
and implemented as "proves credential ownership and old/new holder control". They
do not. Each circuit constrains exactly three things: that the prover knows the
credential binding keys behind the public old and new holder handles, that the
two handles differ, and that the public claim binding was computed over the
public values. The credential itself is represented by unconstrained private
witnesses (`credential_holder_commitment`, `credential_issuer_id_hash`,
`credential_schema_id_hash`, both validity bounds); every equality the circuit
asserts over them compares one prover-chosen value with another, and no issuer
signature or accumulator membership is verified.

A prover with no credential can therefore produce a valid proof for any
`credential_id`, issuer, schema and validity window, and the reference verifier
reported it as credential continuity. The verifier's optional `issuerIdHash` /
`schemaIdHash` request pins compared a verifier expectation against a
prover-chosen public input and never authenticated anything; an Authenticated
Proof Request authenticates the *requester*, not a credential.

The containment (spec §4.5, `UNAUTHENTICATED_CREDENTIAL`,
`UnauthenticatedProofTypeError`) closed the exposure but left the protocol
without any supported rebind statement. This ADR records the design of the
additive, issuer-authenticated successors.

## Decision

### D1. Authenticate an issuer-signed credential transcript, not a per-rebind authorization

Two designs were considered: (a) the circuit verifies an issuer signature over a
credential transcript that binds the credential to its issuer, schema, holder
commitment, identifier and validity, and the holder proves control of that
holder commitment plus a fresh one; (b) the issuer signs a per-migration
authorization naming the old **and new** holder commitments.

**(a) is adopted.** (b) requires issuer involvement at every rebind and hands the
issuer the old-to-new mapping the specification (§4.5) requires to be sealed and
minimized; it would also turn "issuer-assisted migration MAY be offered" into
"issuer-assisted migration is the only path". (a) keeps rebind holder-initiated
and unlinkable at the issuer: the transcript names only the *old* holder
commitment (the one the issuer already knows) and is issued once, at issuance
time or on request for an already-issued credential.

### D2. One schema-agnostic transcript, recomputed in-circuit from constrained fields

Credential digests differ per schema (`compute_kyc_credential_digest`,
`compute_profile_digest_v2`, the jurisdiction and attribute-set digests), so a
circuit that re-verified the *credential's own* signature would have to embed
every schema's claim layout. Instead the issuer signs a dedicated transcript
whose preimage is the same for every schema:

```text
header = Poseidon4(DOMAIN_ZKC_CLAIM, string_to_field("zkc:attestation:credential-rebind:v1"),
                   issuer_id_hash, schema_id_hash)
body   = Poseidon4(holder_commitment, credential_id, valid_from, valid_until)
digest = Poseidon2(header, body)
```

with `issuer_id_hash = string_to_field(issuerId)` and
`schema_id_hash = string_to_field(schemaId)`. The circuit recomputes `digest`
from `issuer_id_hash`, `schema_id_hash` (public), `old_holder_commitment`
(derived in-circuit from the private old binding key), `credential_id` (public)
and the private validity bounds, and verifies the issuer's secp256k1 ECDSA
signature over `digest.to_be_bytes()` against the **public** issuer key. A
prover-supplied digest is never accepted: there is no digest input at all.
The explicit type field, the registered `zkc/claim` domain and the fixed slot
order make the transcript distinct from every credential digest and from the
selective-disclosure transcript, so a signature over one can never be replayed
as another.

### D3. Non-revocation is proven for the same authenticated credential identifier

Both successors compose `zkc_nonrevocation::assert_nonrevocation` over the same
`credential_id` the transcript authenticates, with public `accumulator_root`,
`accumulator_epoch` and `current_epoch`, exactly as the KYC and profile
predicates do. In-circuit freshness (`current_epoch - accumulator_epoch <=
MAX_EPOCH_LAG`) bounds the witness age; the verifier supplies `current_epoch`
from its own authenticated view and requires the public root to be the root its
authenticated announcement chain records for that epoch (D5).

### D4. Two additive identities, one per presentation profile, no downgrade

- Linkable: `zkc:proof:credential_rebind:v3`, package `zkc_credential_rebind_auth`,
  registry entry `zkc-credential-rebind@5.0.0` (supersedes 4.0.0). Public old/new
  holder commitments; presented in a `zkc:proof:v1` envelope whose
  `holderBinding` equals the old commitment.
- Scoped: `zkc:proof:rebind:v4`, package `zkc_credential_rebind_auth_v2`, registry
  entry `zkc-credential-rebind@6.0.0` (supersedes 5.0.0). Public old/new
  presentation pseudonyms sharing one non-zero `scope_id`; presented in a
  scoped `zkc:proof:v2` envelope whose binding pseudonym equals the old
  pseudonym. There is no anonymous rebind: continuity is verifier-facing.

Each circuit asserts a private `statement_domain` equal to
`string_to_field(<its proof type>)`, giving it a distinct ACIR/VK from the
predecessors that use a different proof type.

*Correction:* the draft beta.25 successor `zkc:proof:rebind:v5` (package
`zkc_credential_rebind_auth_v3`, registry `zkc-credential-rebind@7.0.0`)
deliberately keeps the v4 statement domain
(`string_to_field("zkc:proof:rebind:v4")`; see the 7.0.0 review record), and its
bytecode equals a beta.25 build of the v4 source. Its ACIR/VK distinctness from
`zkc:proof:rebind:v4` therefore rests on the toolchain lane (beta.25 /
Barretenberg 5.0.0 versus the historical beta.21 build), not on the statement
domain; identity separation between the two is the proof-type label plus the
registry and manifest pins. The four deprecated identities stay rejected; a request MUST name a
successor explicitly and no implementation maps a deprecated identity to a
successor or the reverse.

### D5. Verifier acceptance is issuer-trust- and revocation-gated, with no special case

A successor proof is accepted only when: the public issuer key is an exact
member of the verifier's key allowlist **and** trusted for that proof type; the
public `issuer_id_hash` equals `string_to_field` of the matched issuer's id; the
verifier holds an **authenticated** accumulator state for that issuer
(metadata-v2 signed announcement chain), its `current_epoch` equals the proof's,
the proof's epoch lies within the tighter of the policy and announcement lag
bounds, and the recorded root for that epoch equals the public root; the old
handle equals the envelope binding; the claim binding recomputes; and the
optional sidecar-declared `schemaIdHash` pin, when supplied, compares equal.
`issuer_id_hash` is deliberately **bound**, not pinned: comparing it against the
verifier's own matched trusted issuer identifier is strictly stronger than an
optional filter, so the deprecated statements' `issuerIdHash` filter is not
carried forward. A pin is applied **after** cryptographic issuer authentication
and can only narrow acceptance. `verify()` and `verify_authenticated()` apply
identical credential-authentication and revocation semantics.

### D6. A rebind is a continuity claim; exclusivity is verifier state (2026-11-18)

The statements authenticate the credential and the old key's continuity to a
new key, nothing more: the credential stays bound to the old holder, the new key
cannot present or rebind it, the old key keeps full power, and nothing is
one-time. The security review (2026-10-04) reproduced the consequence: the same
old key rebinding one credential to three unrelated keys, each accepted. We
therefore specify rebind as continuity (spec §4.5, §7.4.6), make real migration
issuer re-issuance, and put exclusivity in normative verifier state (§7.4.7:
one claim per credential per verifier across statements and scopes, retire the
old handle, freeze on conflict, record only entries the verifier checked;
reference `zkc_verifier.RebindLedger`). A successor nullifier
`H(domain, old_cbk, credentialId[, scopeId])` was considered and not adopted: it
adds no protection against an old-key compromise race beyond the ledger, and a
cross-verifier form would add a linking handle. Compromise is resolved by issuer
revocation and re-issuance.

## Consequences

- A prover lacking a live issuer-signed, non-revoked credential cannot obtain a
  verifier-accepted continuity result; forging one requires the issuer's key.
- Issuers must emit the rebind attestation with each credential they are willing
  to let migrate, and can emit it later for already-issued credentials
  (representation-only migration: no credential field changes). Recovery of a
  credential whose old binding key is lost is re-issuance, not rebind.
- Every rebind discloses an old-to-new link to its recipient: the linkable
  profile reveals both holder commitments, the scoped profile both pseudonyms;
  both reveal `credential_id`, the issuer key and the accumulator root/epochs,
  as every issuer-authenticated predicate does. *Correction:* the field set
  matches the deprecated statements, but `credential_id` is now
  issuer-authenticated, which makes it a reliable cross-scope and
  cross-verifier handle the issuer can map back to the subject;
  issuer-verifier collusion de-pseudonymizes a scoped rebind (spec §7.4.6).
- The transcript, both ABIs, the claim bindings and the KATs are normative in
  spec §7.4 and `tests/vectors/zkc_core_vectors.json`
  (`credential_rebind_attestation_v1`).

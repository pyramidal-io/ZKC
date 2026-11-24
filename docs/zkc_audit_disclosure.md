# ZKC Holder-Authorized Audit Disclosure

**Status:** Reference (non-normative)
**Implementation:** `python/zkc_holder/audit_export.py`, agent integration in `python/zkc_agent/agent.py`
**Bundle version:** `zkc:audit-bundle:v1`

Regulated workflows need compliance evidence shared with auditors. This module makes that possible **without** breaking the ZKC privacy boundary: the auditor (and any platform relaying the bundle) receives only what the holder explicitly authorized — selected proof envelopes plus the context needed to re-verify them — and never credential secrets or broad payment/activity history.

## The AuditBundle

`AuditExporter(master_seed).export(proofs, auditor_key_id=…, valid_from=…, valid_until=…, purpose=…)` produces a content-addressed, tamper-evident bundle:

```
{
  "version": "zkc:audit-bundle:v1",
  "members": [
    {
      "index": 0,
      "type": "proof-record",
      "content": {
        "envelope":      <zkc:proof:v1 envelope>,
        "verification":  { proofTypes, parameters, context,
                           accumulatorStates, policySnapshot, registryRefs }
        // accumulatorStates: { "<issuerId>": { "currentEpoch": n,
        //   "roots": { "<epoch>": "0x<issuer root>" } } } -- currentEpoch is the
        //   original verification view; bundled roots are holder assertions
        //   and re-verification checks revocation against the AUDITOR's roots
      },
      "contentHash": "0x…",   // sha256 of canonical JSON content
      "chainHash":   "0x…"    // sha256(prevChain || contentHash)
    }, …
  ],
  "authorization": {
    "holderAuthorizationKey": {"x": "0x…", "y": "0x…"},   // per-auditor key; NOT a trust anchor
    "auditorKeyId": "did:zkc:auditor:…#key-1",
    "proofRefs":   ["0x…", …],          // exactly the member content hashes
    "validFrom":   1700000000,
    "validUntil":  1700086400,
    "purpose":     "annual compliance audit FY2026",
    "signature":   "0x…"                // ECDSA over (authorization − signature, bundleHash)
  },
  "bundleHash": "0x…"                   // chain head = the bundle's content address
}
```

- **Hash chain:** `chain_i = sha256(chain_{i-1} ‖ contentHash_i)` with a zero seed; `bundleHash` is the final chain value. Any member edit, reorder, insertion, or removal changes the head.
- **Authorization record:** holder-signed scope — which proofs (by content hash), for whom (`auditorKeyId`), when (`validFrom`/`validUntil`), and why (`purpose`). The signature covers the authorization fields **and** the `bundleHash`, so the authorization cannot be replayed onto different content.
- **Signing key:** one stable key per auditor, derived from the exact holder master-seed bytes (spec §5.6.1): `root = HMAC-SHA512(seed, frame("zkc/audit-authorization-root:v2"))`, then the secp256k1 key `map(HMAC-SHA512(root, frame("zkc/audit-authorization-key:v2", utf8(auditorKeyId))))`, where `frame` length-prefixes each part with a 4-byte big-endian length and `map(d) = int_be(d) mod (n − 1) + 1`. Two auditors see unrelated keys, so the key is no cross-auditor linking handle. It is NOT the credential binding key — that key never signs anything and never leaves the client. The exporter keeps only the 64-byte root, never the seed.

## Holder-key anchoring (what a bundle proves)

The `holderAuthorizationKey` in a bundle is self-asserted. A verifier or platform that holds a holder's envelopes can build a bundle over them and sign it under a key of its own. The bundle alone cannot tell that key from the holder's. An auditor therefore **MUST** anchor the key:

1. The holder gives the auditor its per-auditor public key out of band, once per auditor relationship, over a channel the auditor authenticates as the holder (reference: `AuditExporter(seed).authorization_public_key(auditor_key_id)`).
2. The auditor passes that key as `expected_holder_key` to `verify_audit_bundle`. It never takes the key from a bundle, from a verifier, or from a relaying platform.
3. Without `expected_holder_key` the result fails with `HOLDER_KEY_UNANCHORED`. A bundle signed under any other key fails with `HOLDER_KEY_MISMATCH`.

An anchored, valid bundle proves exactly this: the holder known to the auditor under that key authorized the disclosure of exactly these members (by content hash), to this auditor, within this window, for this purpose. It does **not** prove that the bundled envelopes were produced from that holder's credentials. Anonymous `zkc:proof:v2` envelopes bind no holder at all. A linkable `zkc:proof:v1` envelope ties to a holder only through a `holderCommitment` that the auditor must already know from another source. Whether each envelope is a valid proof is a separate check (`reverify_bundle_proofs`).

The bundle format is unchanged (`zkc:audit-bundle:v1`). A bundle that an earlier reference exporter signed with its seed-global key verifies only when the auditor supplies that key explicitly as `expected_holder_key`. That legacy key was `int_be(SHA-256("zkc/audit-authorization:v1:" || seed)) mod n` (spec §5.6.1); the current SDK does not derive it.

The exporter's root yields the authorization key for every auditor, so it is as sensitive as the seed. `AuditExporter` keeps it in a slot, refuses pickling, returns itself from `copy`/`deepcopy`, and redacts its `repr`.

## Schema-level exclusion (what a bundle can never contain)

`FORBIDDEN_BUNDLE_KEYS` is enforced recursively at **export** and again at **auditor validation** (`ForbiddenMaterialError` / `FORBIDDEN_CONTENT`): credential claims, credentials, seeds, binding/private keys, witnesses, and payment/activity history (`transactions`, `transactionHistory`, `activityHistory`, `balances`, …). A bundle is proofs + re-verification context, nothing else. Platform services relaying a bundle therefore cannot receive credential secrets through this path even if a buggy caller tries to include them.

## Auditor-side validation

```python
from zkc_holder import verify_audit_bundle, reverify_bundle_proofs

result = verify_audit_bundle(
    bundle, now=…,
    expected_holder_key=holder_key_from_enrolment,   # REQUIRED; never bundle["authorization"][…]
    expected_auditor_key_id=…,
)
# integrity (hash chain), forbidden content, authorization signature,
# holder-key anchoring, proofRefs scope, validity window, auditor binding —
# fail closed.

# issuer_roots: {issuer_id: {epoch: root}} from the AUDITOR's own authenticated
# source (e.g. the issuer's signed announcement history) -- never from the
# holder-authored bundle, whose roots are assertions a revoked holder controls.
reverify = reverify_bundle_proofs(bundle, verifier_factory, issuer_roots)
# cryptographic re-verification of every contained envelope via
# zkc_verifier, under a trust policy the AUDITOR chooses (typically built
# from the bundled policySnapshot via zkc_registry.to_verifier_trust_policy).
```

Missing auditor roots fail re-verification even if the selected verifier policy
allows unchecked roots. An `UNCHECKED_ACCUMULATOR_ROOT` warning fails this check.
A valid result establishes cryptographic consistency with independently known
historical roots. It does not establish that the credential was unrevoked at
proof creation or today: the bundle's `currentEpoch` is its claimed original
view, and those claims additionally require an independently authenticated epoch
view. Independently supplied roots alone do not authenticate that view.

Error codes: `MALFORMED_BUNDLE`, `TAMPERED`, `FORBIDDEN_CONTENT`, `BAD_AUTHORIZATION_SIGNATURE`, `HOLDER_KEY_UNANCHORED`, `HOLDER_KEY_MISMATCH`, `AUTHORIZATION_NOT_YET_VALID`, `AUTHORIZATION_EXPIRED`, `AUDITOR_MISMATCH`, `PROOF_REFS_MISMATCH`, `REVERIFICATION_FAILED`.

## Disclosure Receipts follow the same rule

A Disclosure Receipt's `holderSignature.holderKey` is also self-asserted. `verify_receipt(receipt, expected_holder_key=…)` is valid only when the holder signature verifies and the carried key equals the relying party's expected key (spec §5.6.1). The relying party MUST also compare the response handle (`holderCommitment`, or `presentationPseudonym` + `scopeId`) with the handle it associated with that key: an anchored key alone does not stop a holder from naming another holder's handle.

Receipt keys are stable per verifier identity for linkable answers and stable per `scopeId` for scoped answers; the holder can give those to a relying party out of band. Anonymous, refused and unauthenticated answers use a fresh key derived from a discarded random nonce and the receipt's own digest. Nobody can derive that key again, the holder included, and its public half exists only inside the receipt. A third party therefore **cannot anchor** such a receipt. For it, only `aprValid` (the verifier's signed demand) and `contextBound` carry third-party meaning; the holder signature proves only that the receipt is intact under the key it carries. Passing that carried key as the expected key means only that the presenter vouches for it.

## Revocation semantics (and why there is no revocation service)

An authorization is valid exactly within its window; **auditors MUST check the window at use time** (`verify_audit_bundle` does). There is deliberately no central authorization-revocation service: such a service would be a platform chokepoint deciding whose audit evidence remains valid — precisely the centralization the protocol's Freedom Safeguards exclude. Holders control exposure by:

- scoping validity windows narrowly (hours/days, not years);
- scoping `proofRefs` to the minimum proof set for the stated `purpose`;
- issuing a fresh bundle (new window, new scope) instead of "extending" one.

Early invalidation, where genuinely required, is a relationship-level matter between holder and auditor (e.g. the auditor contractually discards bundles on request) — not a protocol service.

## Agent API integration (principal authorization)

Audit export through `zkc_agent.ZKCAgentClient` is **never automatic** — whatever the compliance policy auto-approves for proof requests, releasing compliance evidence requires the principal:

```python
export_id = agent.request_audit_export(exporter, proofs,
    auditor_key_id=…, valid_from=…, valid_until=…, purpose=…)
# → principal notified ("audit_export_requested"); nothing released yet
bundle = agent.approve_audit_export(export_id)   # explicit principal step
agent.deny_audit_export(export_id)               # or refuse
```

The agent audit log records the scope (auditor, window, purpose, `bundleHash`, `proofRefs`) — never bundle contents.

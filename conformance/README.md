# ZKC Conformance Suite

Machine-readable test vectors and a deterministic runner for checking ZKC implementations against the specification. Standard-library Python only.

```bash
# Run the ZKC-Core suite against the bundled reference implementation:
python3 conformance/run_zkc_core.py

# Run it against your own implementation:
python3 conformance/run_zkc_core.py --adapter your_package.your_adapter_module

# Machine-readable output / nonzero exit on any failure:
python3 conformance/run_zkc_core.py --json

# Run the authenticated-revocation launch profile:
python3 conformance/generate_revocation_vectors.py --check
python3 conformance/run_revocation.py
```

## Layout

| Path | Purpose |
|------|---------|
| `vectors/zkc_core.json` | ZKC-Core vectors: credential fixtures (signed by the well-known test issuer), request fixtures, envelope mutation cases with expected error codes, malformed-envelope fixtures, and Freedom Safeguard cases. Regenerate with `generate_vectors.py` (deterministic). |
| `run_zkc_core.py` | The runner CLI. Deterministic PASS/FAIL per case, summary, exit code 0/1. |
| `vectors/zkc_presentation.json` | Presentation-profile vectors (design §8 matrix): the eleven `presentation-*` cases asserting cross-envelope properties (anonymous unlinkability, scoped pseudonym joins/rotation, replay + profile/scope rejection, and same-holder composites: anonymous pooling rejected as `UNBOUND_COMPOSITE`, session-scoped conjunctions accepted and unlinkable across fresh sessions and distinct verifier keys). |
| `run_presentation.py` | Presentation-profile runner: drives the eleven vectors through the real holder→verifier pipeline (`presentation_vectors.py`); `--json` and `--vector <id>` supported. Exit 0 only when every vector passes. |
| `adapters/reference.py` | Adapters wiring the bundled reference holder SDK + verifier. |
| `adapters/seeded_negatives.py` | Deliberately broken adapters (canonical-issuer verifier, opaque-accepting holder). The suite MUST fail them; `tests/python/test_conformance.py` asserts it does. |
| `run_issuer_adapter.py` | Issuer-adapter conformance runner: contract cases for any `zkc_issuer.IssuerAdapter` implementation (stage ordering, binding-challenge enforcement, schema validation, privacy boundary, metadata validity, revocation publication). |
| `issuer_adapter/kit.py` | The issuer-adapter case implementations (stable case ids; see the protocol doc annex). |
| `issuer_adapter/seeded_bad_adapter.py` | Deliberately NON-conformant issuer adapter; the kit MUST fail it (CI + `tests/python/test_issuer_adapter_contract.py` assert it does). |
| `../tests/vectors/revocation_equivocation_v1.json` | Public deterministic authenticated-revocation vectors: exact transcripts, complete predecessor hashes, signed-field tampering, high-s and same-transcript signature malleation, lifecycle, rotation, cold-start, isolated split-view, and quiet-issuer `zkc:epoch-liveness:v1` fixtures. |
| `run_revocation.py` | Network-independent authenticated-revocation launch runner. Its eleven stable cases exercise metadata equality, durable restart, replay/gap rejection, fork evidence, high-s and same-transcript signature malleation, the local-only cold-start guarantee, announcement key windows, and quiet-issuer liveness with time-bounded roots. |

## Adapter contract

An adapter is a Python module importable from the repository root (use a thin wrapper that shells out to your implementation if it is not written in Python). It must expose:

```python
def make_holder_adapter():
    """Returns an object with:

    generate(request: dict, credentials: list[dict], master_seed: str) -> dict
        Generate a zkc:proof:v1 envelope for the request from the given
        credential fixtures. The request fixture carries no Authenticated
        Proof Request and no presentation profile. The adapter, acting as
        the holder, selects the linkable profile, gives its explicit
        linkable consent, and answers through the SDK's explicit, logged
        unauthenticated opt-in (Safeguard 6). An SDK must not answer such a
        request, or emit the linkable envelope, by default.
        The fixture's optional holderExactMemberConsents map represents
        holder-local consent for fixed inclusion paths. It is fixture
        metadata outside the proof request parameters and APR.
        Returns {"envelope": {...}}                on success,
                {"refusal": {"code": "<CODE>"}}    on a structured refusal.
    """

    generate_authenticated(request: dict, apr: dict, credentials: list[dict],
                           master_seed: str) -> dict
        Answer an Authenticated Proof Request (Safeguard 6). Returns
        {"envelope": {...}, "receipt": {...}, "receiptHolderKey": {"x", "y"}}
        or {"refusal": {"code": "<CODE>"}}. receiptHolderKey is the holder's
        out-of-band anchor for the receipt key (spec 5.6.1): re-derived from
        the seed for linkable and scoped receipts, never copied from another
        party. Without it, the receipt-roundtrip cases fail.

    answer_hosted(request, apr, credentials, master_seed) -> dict
        Hosted-SDK answer: {"envelope", "receipt", "retained": False,
        "custody": "holder"}.
    """

def make_verifier_adapter():
    """Returns an object with:

    verify(envelope: dict, request: dict) -> dict
        Verify a zkc:proof:v1 envelope against the request.
        Returns {"valid": bool, "codes": ["<CODE>", ...]}.

    verify_authenticated(envelope: dict, request: dict, apr: dict) -> dict
        Authenticated verification (spec 6.2 step 0); same result shape.

    verify_receipt(receipt: dict, *, expected_holder_key: dict | None) -> dict
        Third-party Disclosure Receipt verification. Returns {"valid": bool,
        ...}. MUST fail closed: valid only when the verifier signature, the
        holder signature and the context binding hold AND the holder key
        carried in the receipt equals expected_holder_key. With no expected
        key the receipt is never valid. The carried key is never an anchor.
    """
```

The runner probes `verify_receipt` on every `apr_receipt_roundtrip` case,
independently of the case expectation: the holder's genuine receipt MUST be
rejected with no expected key and with a foreign expected key, and the same
receipt re-signed under an attacker key MUST be rejected against
`receiptHolderKey`. A verifier that trusts the carried key fails these cases. The runner also
probes the holder's receipt key scope (spec 5.6.1) as a black box: it answers
the same APR twice (linkable and scoped keys, and `receiptHolderKey`, MUST be
equal; anonymous keys MUST differ), and answers the same request under a
second, TEST-ONLY verifier key (linkable keys for the two verifier identities
MUST differ). This catches unstable keys and one global key. It cannot catch a
holder that echoes an honest, correctly scoped key, or one whose derivation
differs from the reference but has the same scope: the derivation itself is
not observable from outside, and the core vectors exercise only the linkable
profile.
Compatibility: an adapter written before spec 5.6.1 (a `verify_receipt`
without the keyword, or a holder without `receiptHolderKey`) fails the
`safeguard-6-receipt-*` cases until it is updated.

### Fixture formats

**Request fixture** (used for both generation and verification):

```json
{
  "proofTypes": ["zkc:proof:kyc:v1"],
  "parameters": {"zkc:proof:kyc:v1": {"requiredLevel": 1, "requiredAttributes": [true,false,true,false,false]}},
  "context": {"profile": "zkc:context:verifier-session:v1",
              "verifierId": "verifier.example", "sessionId": "0x…", "timestamp": 1700000000},
  "maxProofAge": 3600,
  "trustPolicy": {"issuers": [{"issuerId": "…", "publicKeyX": "0x…", "publicKeyY": "0x…",
                               "proofTypes": ["zkc:proof:kyc:v1"]}]},
  "accumulatorStates": {"<issuerId>": {"currentEpoch": 1, "roots": {"1": "0x…"}}}
}
```

The context is given in structured form; the adapter constructs the context value with the reference profile construction (`zkc:context:verifier-session:v1`, see `python/zkc_crypto/context.py`).

`accumulatorStates[issuer].roots` maps a decimal epoch string to the issuer's published accumulator root for that epoch. A verifier adapter MUST pass these roots to its verifier: a conforming verifier rejects a proof whose `accumulator_root` differs from the recorded root for its epoch, or whose epoch has no recorded root (`STALE_ACCUMULATOR`, spec §6.2 step 4c), so a revoked holder cannot prove non-revocation against a self-made tree. All fixture credentials of one issuer share that issuer's single accumulator.

**Credential fixture**: the documented holder credential serialization (`python/zkc_holder/credential.py` `Credential.to_dict`), including a static non-revocation `witness` so adapters do not need a live accumulator service.

### Error codes

Refusal/verification codes are the stable code sets of the reference stack — holder codes in `python/zkc_holder/errors.py` (e.g. `OPAQUE_PREDICATE_REFUSED`, `UNKNOWN_ISSUER`, `STALE_CREDENTIAL`) and the closed verifier enumeration in `python/zkc_verifier/errors.py` (`MALFORMED_PROOF`, `CONTEXT_MISMATCH`, `UNTRUSTED_ISSUER`, …). Map your implementation's internal errors to these codes in your adapter. A case may accept any of several codes (`expect.anyCode`).

### How verifier cases work

Proof bytes are implementation-specific, so verifier rejection cases are not static envelopes: the runner first obtains a **base envelope from the holder adapter under test**, then applies JSON-level mutations from the vectors (`{"op": "set"|"delete", "path": "metadata/generatedAt", "value": …}`) and requires the verifier adapter to reject with the expected code. Round-trip acceptance cases require `valid: true`. A handful of static malformed envelopes are included verbatim.

The `core-verifier-*-requirements-not-met` request-binding cases use a stricter
shape: the generated proof and all of its public inputs remain untouched
(`mutations: []`), while `verifyRequest` names a different, internally valid
request. KYC, jurisdiction, accreditation, source-of-funds, tax-residency, and
sanctions-clearance each have an honest round-trip control and an out-of-request
rejection requiring `REQUIREMENTS_NOT_MET`. This distinguishes a real step 4e
request-binding check from proof-byte tamper detection (`INVALID_PROOF`) and
prevents an implementation that rejects a predicate unconditionally from
passing only negative vectors.

The remaining-predicate controls use the current linkable v7 proof identities.
Historical v1-v6 proofs remain a verification-compatibility surface, not a
holder-generation target for the core vectors. v8 is the current
anonymous/scoped counterpart and is exercised by the presentation-profile
suite rather than the linkable ZKC-Core fixtures.

`core-verifier-noncanonical-requirement` separately verifies that a numeric
request value shifted by the BN254 modulus does not alias the canonical value
attested by an otherwise untouched proof.

## Freedom Safeguard checks (CI-enforced)

Three safeguards are executable conformance cases, not documentation:

* **Safeguard 1 — no canonical issuers** (`safeguard-1-*`): a verifier MUST reject an issuer absent from the verifier-local trust policy, even the "well-known" test issuer, and an empty trust policy MUST trust nobody.
* **Safeguard 4 — opaque predicate refusal** (`safeguard-4-*`): a holder MUST refuse, by default, to generate against a predicate that does not resolve to a registry entry whose review status the holder accepts (reference default: `reviewed` or `self_attested` — see `docs/zkc_predicate_registry_governance.md` §2).
* **Safeguard 6 — verifier accountability** (`safeguard-6-*`): a verifier MUST authenticate its request under a stable identity (Authenticated Proof Request); a holder/SDK MUST refuse an unsigned request by default (`safeguard-6-unsigned-request-refusal`) and reject a proof bound under a mismatched declared purpose (`safeguard-6-purpose-mismatch`); Disclosure Receipts MUST round-trip against the holder key that the holder adapter returns out of band as `receiptHolderKey`, never a key read from the receipt, and tampered receipts MUST be rejected (`safeguard-6-receipt-*`, spec §5.6.1); and no operator/hosted SDK may be required to retain receipts (`safeguard-6-hosted-retention-refusal`) (spec §1.4, §9.2).

`tests/python/test_conformance.py` additionally (a) runs the suite against the seeded-negative adapters and asserts the suite catches the Safeguard 1, 4, and 6 violations, and (b) statically scans the reference packages for hardcoded issuer material. CI runs the full suite plus the runner on every push/PR.

## Expansion hooks (Standard / Full / Agent)

Vectors are namespaced by profile: `vectors/zkc_core.json` is `{"profile": "core", "cases": [...]}`. Additional profiles ship as sibling files (`zkc_standard.json`, `zkc_full.json`, `zkc_agent.json`) using the same case schema and runner (`--profile standard` etc.); the runner reports not-yet-published profiles explicitly instead of passing them silently. ZKC-Agent is an orthogonal extension profile, not a level above Full (spec §9.1).

The reference adapters evaluate historical APR vectors at an explicit fixture
clock (`now=context.timestamp`) so their pinned signatures remain reproducible.
This is simulation time. Production holder/verifier admission defaults to the
wall clock and must never derive a live expiry clock from received context.

# Draft review record — `zkc-kyc` 3.0.0

## Publication scope

This entry is the additive beta.25 / Barretenberg 5.0.0 artifact successor to
`zkc-kyc@2.0.0`. The new package's `src/main.nr` is byte-identical to
`noir/zkc_kyc_v2/src/main.nr`; its anonymous/scoped presentation statement,
72-field ABI, encoder classifications, and semantic transcript values are
unchanged. The new `zkc:proof:kyc:v3` transport identity exists because the
frozen predicate-entry v1 model cannot attach a second artifact binding to one
source identity.

The entry is draft and unactivated. Existing proof types, presentation-profile
resolution, and holder/verifier defaults remain unchanged.

## Verification evidence

- `nargo test --package zkc_kyc_v3`: 16/16 passed under beta.25.
- The encoder/source parser and binding-sidecar classifier passed.
- Reproducible generation recorded beta.25 / bb 5.0.0 ACIR and VK pins without
  changing the beta.21 predecessor package or artifacts.
- Registry admission, immutability, committed-artifact, holder/verifier, and
  live proof checks are required before merge.

## Family coordination and disposition

Epoch `zka:protocol-family:2026-09-10.1` intentionally bound the pre-publication
ZKC identities. This successor is not activated or asserted by that epoch;
family alignment and activation remain separate authorized work.

**Status: draft. Independent review: none.**

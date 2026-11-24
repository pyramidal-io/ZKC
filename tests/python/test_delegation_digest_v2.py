"""Delegation token digest v2: length-prefixed framing and identifier policy.

Regression for security review R3.8: the v1 digest NUL-terminated proof types
and the verifier id with no length prefix or proof-type count, so a token the
holder signed for ONE proof type containing NUL had the digest of a token for
TWO proof types, and the holder gate authorized both.
"""

import dataclasses
import hashlib
import json
import pathlib
import random
import tempfile
import unittest
from unittest import mock

import _path  # noqa: F401  (sys.path side effect)
from _path import REPO_ROOT

from test_delegation import (
    AUTHORIZATION_NONCE,
    DELEGATE_SK,
    MASTER_SEED,
    TIMESTAMP,
    VERIFIER_ID,
    _context,
    _jurisdiction_request,
)
from zkc_crypto import FIELD_MODULUS, derive_holder_commitment_from_seed
from zkc_crypto.delegation import (
    DELEGATION_TOKEN_DIGEST_VERSION,
    FORBIDDEN_IDENTIFIER_CATEGORIES,
    DelegatedProver,
    DelegationError,
    ViewingScope,
    _frame_transcript_v2,
    delegation_authorization_digest,
    delegation_token_transcript_v2,
    derive_delegation_signing_key,
    mint_delegation_token,
    validate_delegation_identifier,
)
from zkc_crypto.ecdsa_secp256k1 import public_key_bytes, sign
from zkc_holder import (
    HolderClient,
    LocalAccumulatorProvider,
    PredicateRegistry,
    SQLiteDelegationUseStore,
    StubBackend,
    delegation_request_digest,
)

VECTORS = json.loads(
    (REPO_ROOT / "tests" / "vectors" / "delegation_token_digest_v2.json").read_text("utf-8")
)
DOMAIN = bytes.fromhex(VECTORS["domain"])
KYC = "zkc:proof:kyc:v1"
SANCTIONS = "zkc:proof:sanctions:v8"
JURISDICTION = "zkc:proof:jurisdiction:v3"


# --- independent reference framing, written from the spec text ---------------

def _ref_field(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def _ref_transcript(px, py, proof_types, context_value, verifier_id, expires_at,
                    max_uses, holder_commitment, issued_at, nonce, request_digest):
    types = sorted({item.encode("utf-8") for item in proof_types})
    out = DOMAIN + _ref_field(px) + _ref_field(py) + len(types).to_bytes(4, "big")
    for item in types:
        out += _ref_field(item)
    return (
        out
        + _ref_field(context_value.to_bytes(32, "big"))
        + _ref_field(verifier_id.encode("utf-8"))
        + _ref_field(expires_at.to_bytes(8, "big"))
        + _ref_field(max_uses.to_bytes(4, "big"))
        + _ref_field(holder_commitment.to_bytes(32, "big"))
        + _ref_field(issued_at.to_bytes(8, "big"))
        + _ref_field(nonce.to_bytes(32, "big"))
        + _ref_field(request_digest)
    )


def _decode(transcript: bytes):
    """Parse a v2 transcript back into its fields; fail on any slack."""
    if not transcript.startswith(DOMAIN):
        raise AssertionError("missing v2 domain")
    offset = len(DOMAIN)

    def take(width):
        nonlocal offset
        if offset + width > len(transcript):
            raise AssertionError("truncated transcript")
        chunk = transcript[offset:offset + width]
        offset += width
        return chunk

    def field():
        return take(int.from_bytes(take(4), "big"))

    px, py = field(), field()
    proof_types = [field() for _ in range(int.from_bytes(take(4), "big"))]
    rest = [field() for _ in range(8)]
    if offset != len(transcript):
        raise AssertionError("trailing bytes after the last field")
    return (px, py, tuple(proof_types), *rest)


def _frame(px, py, proof_types, context_value, verifier_id, expires_at, max_uses,
           holder_commitment, issued_at, nonce, request_digest):
    return _frame_transcript_v2(
        px, py, list(proof_types), context_value, verifier_id, expires_at, max_uses,
        holder_commitment, issued_at, nonce, request_digest,
    )


def _framed_fields(px, py, proof_types, context_value, verifier_id, expires_at,
                   max_uses, holder_commitment, issued_at, nonce, request_digest):
    """Expected `_decode` output for the given framing inputs."""
    return (
        px, py, tuple(proof_types),
        context_value.to_bytes(32, "big"), verifier_id,
        expires_at.to_bytes(8, "big"), max_uses.to_bytes(4, "big"),
        holder_commitment.to_bytes(32, "big"), issued_at.to_bytes(8, "big"),
        nonce.to_bytes(32, "big"), request_digest,
    )


class KnownAnswerTests(unittest.TestCase):
    def test_vectors_match_module_reference_and_minting(self):
        self.assertEqual(DOMAIN, b"zkc/delegation-token:v2\0")
        self.assertEqual(VECTORS["version"], "zkc:delegation-token-digest:v2")
        self.assertEqual(DELEGATION_TOKEN_DIGEST_VERSION, 2)
        self.assertGreaterEqual(len(VECTORS["cases"]), 3)
        for case in VECTORS["cases"]:
            with self.subTest(case=case["name"]):
                px = bytes.fromhex(case["principalKey"]["x"])
                py = bytes.fromhex(case["principalKey"]["y"])
                raw = case["scope"]
                scope = ViewingScope(
                    proof_types=tuple(raw["proofTypes"]),
                    context_value=int(raw["contextValue"], 16),
                    verifier_id=raw["verifierId"],
                    expires_at=raw["expiresAt"],
                    max_uses=raw["maxUses"],
                )
                holder_commitment = int(case["holderCommitment"], 16)
                nonce = int(case["nonce"], 16)
                request_digest = bytes.fromhex(case["requestDigest"])
                transcript = delegation_token_transcript_v2(
                    px, py, scope, holder_commitment, case["issuedAt"], nonce, request_digest,
                )
                self.assertEqual(transcript.hex(), case["transcript"])
                self.assertEqual(
                    _ref_transcript(px, py, scope.proof_types, scope.context_value,
                                    scope.verifier_id, scope.expires_at, scope.max_uses,
                                    holder_commitment, case["issuedAt"], nonce,
                                    request_digest).hex(),
                    case["transcript"],
                )
                self.assertEqual(hashlib.sha256(transcript).hexdigest(), case["digest"])
                seed = int(case["masterSeed"], 16)
                self.assertEqual(derive_holder_commitment_from_seed(seed), holder_commitment)
                token = mint_delegation_token(
                    master_seed=seed, holder_commitment=holder_commitment,
                    principal_key_x=px, principal_key_y=py, scope=scope,
                    issued_at=case["issuedAt"], nonce=nonce, request_digest=request_digest,
                )
                self.assertEqual(token.digest().hex(), case["digest"])
                self.assertEqual(token.digest_version, 2)
                self.assertTrue(token.verify_signature())

    def test_identifier_policy_vectors(self):
        policy = VECTORS["identifierPolicy"]
        self.assertEqual(
            sorted(FORBIDDEN_IDENTIFIER_CATEGORIES), policy["forbiddenGeneralCategories"],
        )
        for value in policy["rejected"]:
            with self.subTest(rejected=ascii(value)):
                with self.assertRaises(DelegationError):
                    validate_delegation_identifier(value, name="identifier")
        for value in policy["accepted"]:
            with self.subTest(accepted=ascii(value)):
                self.assertEqual(
                    validate_delegation_identifier(value, name="identifier"),
                    value.encode("utf-8"),
                )


class ProofOfConceptRegressionTests(unittest.TestCase):
    """The R3.8 PoC, at the framing, minting, and holder-gate layers."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zkc-delegation-v2-")
        self.addCleanup(self.temp.cleanup)
        self.provider = LocalAccumulatorProvider()
        self.credential, self.request, _ = _jurisdiction_request()
        self.provider.register(self.credential.issuer_id, self.credential.credential_id)
        self.holder = HolderClient.from_seed(
            MASTER_SEED,
            PredicateRegistry.from_repo(REPO_ROOT),
            StubBackend(),
            accumulator_provider=self.provider,
            delegation_use_store=SQLiteDelegationUseStore(
                pathlib.Path(self.temp.name) / "uses.sqlite"
            ),
        )
        self.holder.store_credential(self.credential)
        self.principal = public_key_bytes(DELEGATE_SK)

    def _scope(self, proof_types, **changes):
        values = dict(
            proof_types=proof_types, context_value=_context().value,
            verifier_id=VERIFIER_ID, expires_at=TIMESTAMP + 3600,
        )
        values.update(changes)
        return ViewingScope(**values)

    def _assert_gate_rejects_before_proof(self, token, requests=None):
        requests = [self.request] if requests is None else requests
        try:
            signature = sign(
                delegation_authorization_digest(
                    token.digest(), delegation_request_digest(requests), AUTHORIZATION_NONCE,
                ),
                DELEGATE_SK,
            )
        except DelegationError:
            signature = b"\x00" * 64
        with mock.patch.object(self.holder, "generate_proof") as generate_proof:
            with self.assertRaises(DelegationError):
                self.holder.authorize_delegated_material(
                    token, requests, now=TIMESTAMP, principal_signature=signature,
                    authorization_nonce=AUTHORIZATION_NONCE, allow_unauthenticated=True,
                )
            generate_proof.assert_not_called()

    def _holder_signed(self, token, transcript):
        """Re-sign ``token`` under this holder's real key over ``transcript``.

        Models a signature the holder produced on some other path (e.g. a
        v1-era token), so the gate's own checks are exercised directly.
        """
        signing_key = derive_delegation_signing_key(MASTER_SEED)
        return dataclasses.replace(
            token, signature=sign(hashlib.sha256(transcript).digest(), signing_key),
        )

    def test_poc_scopes_have_distinct_framings_and_digests(self):
        single = [(JURISDICTION + "\0" + SANCTIONS).encode()]
        double = sorted([JURISDICTION.encode(), SANCTIONS.encode()])
        common = dict(
            px=self.principal[0], py=self.principal[1], context_value=_context().value,
            verifier_id=VERIFIER_ID.encode(), expires_at=TIMESTAMP + 3600, max_uses=1,
            holder_commitment=derive_holder_commitment_from_seed(MASTER_SEED),
            issued_at=TIMESTAMP, nonce=1, request_digest=b"\x07" * 32,
        )
        single_t = _frame(proof_types=single, **common)
        double_t = _frame(proof_types=double, **common)
        self.assertNotEqual(single_t, double_t)
        self.assertNotEqual(hashlib.sha256(single_t).digest(), hashlib.sha256(double_t).digest())
        self.assertEqual(_decode(single_t)[2], tuple(single))
        self.assertEqual(_decode(double_t)[2], tuple(double))
        # The original PoC pair (KYC / sanctions), likewise separated.
        self.assertNotEqual(
            _frame(proof_types=[(KYC + "\0" + SANCTIONS).encode()], **common),
            _frame(proof_types=[KYC.encode(), SANCTIONS.encode()], **common),
        )

    def test_nul_bearing_proof_type_cannot_be_minted(self):
        scope = self._scope((JURISDICTION + "\0" + SANCTIONS,))
        with self.assertRaises(DelegationError):
            self.holder.delegate_viewing(*self.principal, scope, issued_at=TIMESTAMP, nonce=1)
        with self.assertRaises(DelegationError):
            self.holder.delegate_viewing(
                *self.principal, scope, issued_at=TIMESTAMP, nonce=1, requests=[self.request],
            )

    def test_reparsed_token_fails_signature_and_gate(self):
        token = self.holder.delegate_viewing(
            *self.principal, self._scope((JURISDICTION, SANCTIONS)),
            issued_at=TIMESTAMP, nonce=1, requests=[self.request],
        )
        self.assertTrue(token.verify_signature())
        for proof_types in ((JURISDICTION + "\0" + SANCTIONS,), (JURISDICTION,),
                            (SANCTIONS + "\0" + JURISDICTION,)):
            with self.subTest(proof_types=ascii(proof_types)):
                reparsed = dataclasses.replace(
                    token, scope=dataclasses.replace(token.scope, proof_types=proof_types),
                )
                self.assertFalse(reparsed.verify_signature())
                self._assert_gate_rejects_before_proof(reparsed)
        # The honest token still authorizes its reviewed request.
        with mock.patch.object(self.holder, "generate_proof", return_value={"proofs": []}):
            signature = sign(
                delegation_authorization_digest(
                    token.digest(), delegation_request_digest([self.request]),
                    AUTHORIZATION_NONCE,
                ),
                DELEGATE_SK,
            )
            material = self.holder.authorize_delegated_material(
                token, [self.request], now=TIMESTAMP, principal_signature=signature,
                authorization_nonce=AUTHORIZATION_NONCE, allow_unauthenticated=True,
            )
        self.assertIn(JURISDICTION, material)

    def test_gate_rejects_holder_signed_nul_scope(self):
        # Even a genuine holder signature over a NUL-bearing scope (signed off
        # the minting path) is refused by the gate's own identifier policy.
        honest = self.holder.delegate_viewing(
            *self.principal, self._scope((JURISDICTION,)),
            issued_at=TIMESTAMP, nonce=2, requests=[self.request],
        )
        for field, value in (
            ("proof_types", (JURISDICTION + "\0" + SANCTIONS,)),
            ("proof_types", (JURISDICTION, "zkc:proof:‍sanctions:v8")),
            ("verifier_id", VERIFIER_ID + "\0"),
            ("verifier_id", VERIFIER_ID + "‮"),
        ):
            with self.subTest(field=field, value=ascii(value)):
                scope = dataclasses.replace(honest.scope, **{field: value})
                proof_types = sorted({item.encode() for item in scope.proof_types})
                transcript = _frame(
                    honest.principal_key_x, honest.principal_key_y, proof_types,
                    scope.context_value, scope.verifier_id.encode(), scope.expires_at,
                    scope.max_uses, honest.holder_commitment, honest.issued_at,
                    honest.nonce, honest.request_digest,
                )
                forged = self._holder_signed(dataclasses.replace(honest, scope=scope), transcript)
                with self.assertRaises(DelegationError):
                    forged.digest()
                self.assertFalse(forged.verify_signature())
                self._assert_gate_rejects_before_proof(forged)

    def test_unknown_digest_versions_fail_closed(self):
        token = self.holder.delegate_viewing(
            *self.principal, self._scope((JURISDICTION,)),
            issued_at=TIMESTAMP, nonce=3, requests=[self.request],
        )
        for version in (1, 3, 0, True, "2", 2.0, None):
            with self.subTest(version=version):
                other = dataclasses.replace(token, digest_version=version)
                with self.assertRaises(DelegationError):
                    other.digest()
                self.assertFalse(other.verify_signature())
                with self.assertRaises(DelegationError):
                    DelegatedProver(other, DELEGATE_SK, {})
                with mock.patch.object(self.holder, "generate_proof") as generate_proof:
                    with self.assertRaises(DelegationError):
                        self.holder.authorize_delegated_material(
                            other, [self.request], now=TIMESTAMP,
                            principal_signature=b"\x00" * 64,
                            authorization_nonce=AUTHORIZATION_NONCE,
                            allow_unauthenticated=True,
                        )
                    generate_proof.assert_not_called()

    def test_control_and_format_characters_rejected_at_mint_gate_and_prover(self):
        honest = self.holder.delegate_viewing(
            *self.principal, self._scope((JURISDICTION,)),
            issued_at=TIMESTAMP, nonce=4, requests=[self.request],
        )
        prover = DelegatedProver(honest, DELEGATE_SK, {JURISDICTION: {"proofs": []}})
        for bad in VECTORS["identifierPolicy"]["rejected"]:
            for field in ("proof_types", "verifier_id"):
                value = (bad,) if field == "proof_types" else bad
                with self.subTest(field=field, value=ascii(bad)):
                    scope = dataclasses.replace(self._scope((JURISDICTION,)), **{field: value})
                    with self.assertRaises(DelegationError):
                        mint_delegation_token(
                            master_seed=MASTER_SEED,
                            holder_commitment=derive_holder_commitment_from_seed(MASTER_SEED),
                            principal_key_x=self.principal[0],
                            principal_key_y=self.principal[1],
                            scope=scope, issued_at=TIMESTAMP, nonce=5,
                        )
                    with self.assertRaises(DelegationError):
                        self.holder.delegate_viewing(
                            *self.principal, scope, issued_at=TIMESTAMP, nonce=5,
                            requests=[self.request],
                        )
                    self.assertFalse(scope.covers(
                        scope.proof_types[0], scope.context_value, scope.verifier_id, TIMESTAMP,
                    ))
                    self._assert_gate_rejects_before_proof(
                        dataclasses.replace(honest, scope=scope)
                    )
        # Requests outside the honest scope's identifiers never reach material.
        with self.assertRaises(DelegationError):
            prover.prove(JURISDICTION + "\0", _context().value, VERIFIER_ID, now=TIMESTAMP)
        self.assertEqual(
            prover.prove(JURISDICTION, _context().value, VERIFIER_ID, now=TIMESTAMP),
            {"proofs": []},
        )

    def test_scope_shape_rejected(self):
        for proof_types in ((), [JURISDICTION], JURISDICTION, (JURISDICTION, b"x"), (1,)):
            with self.subTest(proof_types=ascii(proof_types)):
                with self.assertRaises(DelegationError):
                    mint_delegation_token(
                        master_seed=MASTER_SEED,
                        holder_commitment=derive_holder_commitment_from_seed(MASTER_SEED),
                        principal_key_x=self.principal[0], principal_key_y=self.principal[1],
                        scope=self._scope(proof_types), issued_at=TIMESTAMP, nonce=6,
                    )
        for key in (self.principal[0][:31], self.principal[0] + b"\x00", bytearray(32)):
            with self.subTest(principal_key=ascii(key)):
                with self.assertRaises(DelegationError):
                    mint_delegation_token(
                        master_seed=MASTER_SEED,
                        holder_commitment=derive_holder_commitment_from_seed(MASTER_SEED),
                        principal_key_x=key, principal_key_y=self.principal[1],
                        scope=self._scope((JURISDICTION,)), issued_at=TIMESTAMP, nonce=6,
                    )

    def test_zero_use_budget_rejected_by_transcript_mint_gate_and_covers(self):
        honest = self.holder.delegate_viewing(
            *self.principal, self._scope((JURISDICTION,)),
            issued_at=TIMESTAMP, nonce=9, requests=[self.request],
        )
        scope = dataclasses.replace(honest.scope, max_uses=0)
        with self.assertRaises(DelegationError):
            delegation_token_transcript_v2(
                *self.principal, scope, honest.holder_commitment, TIMESTAMP, 9,
                honest.request_digest,
            )
        zero_budget = dataclasses.replace(honest, scope=scope)
        with self.assertRaises(DelegationError):
            zero_budget.digest()
        self.assertFalse(zero_budget.verify_signature())
        with self.assertRaises(DelegationError):
            mint_delegation_token(
                master_seed=MASTER_SEED,
                holder_commitment=derive_holder_commitment_from_seed(MASTER_SEED),
                principal_key_x=self.principal[0], principal_key_y=self.principal[1],
                scope=scope, issued_at=TIMESTAMP, nonce=9,
            )
        self.assertFalse(scope.covers(JURISDICTION, scope.context_value, VERIFIER_ID, TIMESTAMP))
        self._assert_gate_rejects_before_proof(zero_budget)
        # The boundaries of [1, 2^32) still encode.
        for max_uses in (1, (1 << 32) - 1):
            delegation_token_transcript_v2(
                *self.principal, dataclasses.replace(scope, max_uses=max_uses),
                honest.holder_commitment, TIMESTAMP, 9, honest.request_digest,
            )

    def test_covers_requires_exact_str_queries(self):
        class AlwaysEqual(str):
            def __eq__(self, other):
                return True

            __hash__ = str.__hash__

        scope = self._scope((JURISDICTION,))
        ctx = scope.context_value
        self.assertTrue(scope.covers(JURISDICTION, ctx, VERIFIER_ID, TIMESTAMP))
        self.assertTrue(AlwaysEqual("x") == JURISDICTION)  # the subclass really lies
        self.assertFalse(scope.covers(AlwaysEqual("x"), ctx, VERIFIER_ID, TIMESTAMP))
        self.assertFalse(scope.covers(JURISDICTION, ctx, AlwaysEqual("x"), TIMESTAMP))
        self.assertFalse(scope.covers(AlwaysEqual(JURISDICTION), ctx, VERIFIER_ID, TIMESTAMP))
        self.assertFalse(scope.covers(JURISDICTION, ctx, AlwaysEqual(VERIFIER_ID), TIMESTAMP))
        for bad in (None, b"zkc:proof:jurisdiction:v3", 1):
            self.assertFalse(scope.covers(bad, ctx, VERIFIER_ID, TIMESTAMP))
            self.assertFalse(scope.covers(JURISDICTION, ctx, bad, TIMESTAMP))
        # The delegated prover inherits the check.
        token = self.holder.delegate_viewing(
            *self.principal, scope, issued_at=TIMESTAMP, nonce=10, requests=[self.request],
        )
        prover = DelegatedProver(token, DELEGATE_SK, {JURISDICTION: {"proofs": []}})
        with self.assertRaises(DelegationError):
            prover.prove(AlwaysEqual("x"), ctx, VERIFIER_ID, now=TIMESTAMP)
        with self.assertRaises(DelegationError):
            prover.prove(JURISDICTION, ctx, AlwaysEqual("x"), now=TIMESTAMP)
        self.assertEqual(prover.remaining_uses, 1)

    def test_context_value_outside_scalar_field_rejected_at_mint_and_gate(self):
        honest = self.holder.delegate_viewing(
            *self.principal, self._scope((JURISDICTION,)),
            issued_at=TIMESTAMP, nonce=7, requests=[self.request],
        )
        for bad in (FIELD_MODULUS, FIELD_MODULUS + 1, FIELD_MODULUS + _context().value,
                    1 << 256, -1, True, False, str(_context().value), float(1), None):
            with self.subTest(context_value=ascii(bad)):
                scope = self._scope((JURISDICTION,), context_value=bad)
                with self.assertRaises(DelegationError):
                    mint_delegation_token(
                        master_seed=MASTER_SEED,
                        holder_commitment=derive_holder_commitment_from_seed(MASTER_SEED),
                        principal_key_x=self.principal[0], principal_key_y=self.principal[1],
                        scope=scope, issued_at=TIMESTAMP, nonce=8,
                    )
                with self.assertRaises(DelegationError):
                    self.holder.delegate_viewing(
                        *self.principal, scope, issued_at=TIMESTAMP, nonce=8,
                        requests=[self.request],
                    )
                self.assertFalse(scope.covers(JURISDICTION, bad, VERIFIER_ID, TIMESTAMP))
                self._assert_gate_rejects_before_proof(dataclasses.replace(honest, scope=scope))


# --- seeded property test (stdlib only) --------------------------------------

# Bytes chosen to shift field boundaries: NUL, length-prefix look-alikes, the
# separator ':' used in proof-type names, and multi-byte UTF-8 sequences.
_ALPHABET = [b"\x00", b"\x00\x00\x00", b"\x00\x00\x00\x05", b"\x01", b"\xff", b":",
             b"a", b"z", b"zkc:proof:", b"\xc3\xa9", b"\xe2\x80\x8d", b"v2"]


def _random_bytes(rng, max_parts):
    return b"".join(rng.choice(_ALPHABET) for _ in range(rng.randint(0, max_parts)))


def _random_input(rng):
    count = rng.choice([0, 1, 1, 2, 2, 3, 4, 8])
    proof_types = [_random_bytes(rng, rng.choice([0, 3, 12, 120])) for _ in range(count)]
    return dict(
        px=rng.choice([b"\x02" * 32, bytes(range(32)), rng.randbytes(32)]),
        py=rng.choice([b"\x03" * 32, rng.randbytes(32)]),
        proof_types=proof_types,
        context_value=rng.choice([0, 1, FIELD_MODULUS - 1, rng.randrange(FIELD_MODULUS)]),
        verifier_id=_random_bytes(rng, rng.choice([0, 4, 40])),
        expires_at=rng.choice([0, (1 << 64) - 1, rng.randrange(1 << 64)]),
        max_uses=rng.choice([1, (1 << 32) - 1, rng.randrange(1 << 32)]),
        holder_commitment=rng.randrange(FIELD_MODULUS),
        issued_at=rng.randrange(1 << 64),
        nonce=rng.choice([0, rng.randrange(FIELD_MODULUS)]),
        request_digest=rng.choice([b"", b"\x00" * 32, rng.randbytes(32)]),
    )


def _boundary_variants(rng, base):
    """Inputs whose naive concatenations collide with ``base``'s."""
    types = base["proof_types"]
    variants = []
    joined = b"\x00".join(types)
    variants.append(dict(base, proof_types=[joined]))           # merge with NUL
    variants.append(dict(base, proof_types=[b"".join(types)]))   # merge without separator
    if joined:
        cut = rng.randrange(len(joined) + 1)
        variants.append(dict(base, proof_types=[joined[:cut], joined[cut:]]))  # split
    if types:
        last = types[-1]
        cut = rng.randrange(len(last) + 1)
        # Move bytes between the last proof type and the verifier id.
        variants.append(dict(base, proof_types=types[:-1] + [last[:cut]],
                             verifier_id=last[cut:] + base["verifier_id"]))
        variants.append(dict(base, proof_types=types[:-1] + [last + b"\x00"]))
        variants.append(dict(base, proof_types=types + [b""]))   # extra empty type
        variants.append(dict(base, proof_types=types[:-1]))      # drop one
    verifier = base["verifier_id"]
    cut = rng.randrange(len(verifier) + 1)
    variants.append(dict(base, proof_types=types + [verifier[:cut]],
                         verifier_id=verifier[cut:]))
    variants.append(dict(base, verifier_id=verifier + b"\x00"))
    variants.append(dict(base, request_digest=b"" if base["request_digest"] else b"\x00" * 32))
    return variants


class InjectivityPropertyTests(unittest.TestCase):
    SEED = 20261004  # security review date; fixed for reproducibility
    BASES = 1500

    def test_framing_is_injective_over_structured_and_boundary_shifted_inputs(self):
        rng = random.Random(self.SEED)
        seen = {}
        checked = 0
        for _ in range(self.BASES):
            base = _random_input(rng)
            for candidate in [base] + _boundary_variants(rng, base):
                transcript = _frame(**candidate)
                fields = _framed_fields(**candidate)
                # Round trip: the transcript determines every field exactly.
                self.assertEqual(_decode(transcript), fields)
                previous = seen.setdefault(transcript, fields)
                self.assertEqual(previous, fields, "distinct inputs share a transcript")
                checked += 1
        self.assertGreater(checked, self.BASES * 8)
        # Distinct transcripts produced distinct digests in this sample.
        digests = {hashlib.sha256(transcript).digest() for transcript in seen}
        self.assertEqual(len(digests), len(seen))

    def test_valid_scopes_have_distinct_digests(self):
        rng = random.Random(self.SEED + 1)
        words = ["zkc:proof:kyc:v1", "zkc:proof:sanctions:v8", "kyc", "v1", ":", "a", "café",
                 "測", " ", "zkc:proof:", "x" * 300]
        principal = public_key_bytes(DELEGATE_SK)
        seen = {}
        for _ in range(1200):
            types = tuple(
                "".join(rng.choice(words) for _ in range(rng.randint(1, 3)))
                for _ in range(rng.randint(1, 5))
            )
            verifier = "".join(rng.choice(words) for _ in range(rng.randint(1, 4)))
            scope = ViewingScope(types, rng.choice([1, 2]), verifier, rng.choice([10, 11]),
                                 rng.choice([1, 2]))
            request_digest = rng.choice([b"", b"\x01" * 32])
            transcript = delegation_token_transcript_v2(
                *principal, scope, 5, 1, 1, request_digest,
            )
            key = (scope.normalized_types(), scope.context_value, scope.verifier_id,
                   scope.expires_at, scope.max_uses, request_digest)
            digest = hashlib.sha256(transcript).digest()
            self.assertEqual(seen.setdefault(digest, key), key)
            # Set semantics: order and duplicates do not change the digest.
            shuffled = list(types) + [types[0]]
            rng.shuffle(shuffled)
            self.assertEqual(
                delegation_token_transcript_v2(
                    *principal, dataclasses.replace(scope, proof_types=tuple(shuffled)),
                    5, 1, 1, request_digest,
                ),
                transcript,
            )
        self.assertGreater(len(seen), 1000)


if __name__ == "__main__":
    unittest.main()

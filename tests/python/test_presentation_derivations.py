"""Derivation tests for presentation profiles (design §2)."""

import unittest

import _path  # noqa: F401

from zkc_crypto.kdc import derive_credential_binding_key, derive_domain
from zkc_crypto.poseidon2 import poseidon3
from zkc_crypto.presentation import (
    ANONYMOUS_PROFILE,
    DOMAIN_ZKC_PRESENTATION_SCOPE,
    DOMAIN_ZKC_SCOPE,
    DOMAIN_ZKC_VERIFIER_ID,
    LINKABLE_PROFILE,
    SCOPED_PROFILE,
    derive_presentation_pseudonym,
    derive_scope_id,
    derive_verifier_identity,
)


class PresentationDerivationTests(unittest.TestCase):
    def test_domain_constants_are_pinned(self):
        self.assertEqual(DOMAIN_ZKC_PRESENTATION_SCOPE, derive_domain("zkc/presentation-scope:v1"))
        self.assertEqual(DOMAIN_ZKC_SCOPE, derive_domain("zkc/scope:v1"))
        self.assertEqual(DOMAIN_ZKC_VERIFIER_ID, derive_domain("zkc/verifier-id:v1"))

    def test_profile_identifiers(self):
        self.assertEqual(ANONYMOUS_PROFILE, "zkc:presentation:anonymous:v1")
        self.assertEqual(SCOPED_PROFILE, "zkc:presentation:scoped:v1")
        self.assertEqual(LINKABLE_PROFILE, "zkc:presentation:linkable:v1")

    def test_pseudonym_matches_manual_poseidon(self):
        cbk = derive_credential_binding_key(42)
        scope_id = 7
        self.assertEqual(
            derive_presentation_pseudonym(cbk, scope_id),
            poseidon3(DOMAIN_ZKC_PRESENTATION_SCOPE, cbk, scope_id),
        )

    def test_pseudonym_rejects_zero_scope(self):
        cbk = derive_credential_binding_key(42)
        with self.assertRaises(ValueError):
            derive_presentation_pseudonym(cbk, 0)

    def test_scope_id_is_deterministic_and_scope_exclusive(self):
        verifier_a = derive_verifier_identity(b"\x02" + b"\x11" * 32)
        verifier_b = derive_verifier_identity(b"\x03" + b"\x22" * 32)
        scope_a = derive_scope_id(verifier_a, "verifier", 0)
        self.assertEqual(scope_a, derive_scope_id(verifier_a, "verifier", 0))
        self.assertNotEqual(scope_a, derive_scope_id(verifier_b, "verifier", 0))
        self.assertNotEqual(scope_a, derive_scope_id(verifier_a, "protocol:demo", 0))
        self.assertNotEqual(scope_a, derive_scope_id(verifier_a, "verifier", 1))
        self.assertNotEqual(scope_a, 0)

    def test_cross_scope_pseudonyms_differ_within_scope_equal(self):
        cbk = derive_credential_binding_key(42)
        verifier_a = derive_verifier_identity(b"\x02" + b"\x11" * 32)
        verifier_b = derive_verifier_identity(b"\x03" + b"\x22" * 32)
        scope_a = derive_scope_id(verifier_a, "verifier", 0)
        scope_b = derive_scope_id(verifier_b, "verifier", 0)
        self.assertEqual(
            derive_presentation_pseudonym(cbk, scope_a),
            derive_presentation_pseudonym(cbk, scope_a),
        )
        self.assertNotEqual(
            derive_presentation_pseudonym(cbk, scope_a),
            derive_presentation_pseudonym(cbk, scope_b),
        )


if __name__ == "__main__":
    unittest.main()

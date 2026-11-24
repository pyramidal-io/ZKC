"""Regression tests for ZKC unlinkability documentation.

These tests pin the privacy claim corrected by the holderCommitment analysis and
the ADR that records the multi-show presentation decision.
"""

import re
import unittest

import _path  # noqa: F401
from _path import REPO_ROOT


SPEC = REPO_ROOT / "docs" / "zkc_specification.md"
ADR = REPO_ROOT / "docs" / "adr" / "0001-multi-show-unlinkable-presentations.md"
WEBSITE_SPEC = REPO_ROOT / "website" / "llms-full.txt"


def _between(text: str, start: str, end: str) -> str:
    start_at = text.index(start)
    end_at = text.index(end, start_at)
    return text[start_at:end_at]


def _squash(text: str) -> str:
    return " ".join(text.split())


def _unquote(text: str) -> str:
    """Strip blockquote markers so an assertion pins the quoted sentence itself
    rather than the line positions the quote happens to wrap at."""
    return re.sub(r"(?m)^\s*>\s?", "", text)


class UnlinkabilityDocumentationTests(unittest.TestCase):
    def test_privacy_table_no_longer_claims_same_credential_unlinkability(self):
        section = _between(
            SPEC.read_text(),
            "### 8.2 Privacy Properties",
            "### 8.3 Attack Mitigations",
        )

        self.assertNotIn(
            "| Credential unlinkability | Different proofs from same credential cannot be linked |",
            section,
        )
        self.assertIn("| Credential binding pseudonymity |", section)
        self.assertIn("stable, deterministic", section)
        self.assertIn("cross-verifier-linkable", section)
        self.assertIn("pseudonymous anchor, not an unlinkability mechanism", section)
        self.assertIn("Known limitation / open item", section)
        self.assertIn("docs/adr/0001-multi-show-unlinkable-presentations.md", section)

    def test_spec_separates_seed_unlinkability_from_presentation_linkability(self):
        spec = SPEC.read_text()
        derivation_section = _between(spec, "### 2.1 Credential Binding", "### 2.2 Proof Context Binding")
        privacy_section = _between(
            spec,
            "### 8.2 Privacy Properties",
            "### 8.3 Attack Mitigations",
        )

        derivation_words = _squash(derivation_section)
        self.assertIn("ZKA address derive along separate paths", derivation_words)
        self.assertIn("unlinkable without the seed", derivation_words)
        self.assertIn("ZKA value-address and ZKC credential-commitment", privacy_section)
        self.assertIn("not cross-verifier multi-show unlinkability", privacy_section)

    def test_spec_normatively_defines_presentation_profiles(self):
        spec = SPEC.read_text()

        # The history records the version that introduced the ladder.
        self.assertRegex(
            spec,
            r"\| 0\.4\.0-draft \| .*Presentation-profile ladder",
        )

        section = _between(
            spec,
            "### 5.9 Presentation Profiles (Normative)",
            "## 6. Verifier Specification",
        )
        words = _squash(section)

        # The three profiles, with anonymous named as the default.
        self.assertIn("zkc:presentation:anonymous:v1", section)
        self.assertIn("zkc:presentation:scoped:v1", section)
        self.assertIn("zkc:presentation:linkable:v1", section)
        self.assertIn("is the default profile", words)

        # Derivation strings, pinned byte-for-byte to the reference derivations.
        self.assertIn(
            'presentationPseudonym = H("zkc/presentation-scope:v1", cbk, scopeId)',
            section,
        )
        self.assertIn(
            'scopeId          = H("zkc/scope:v1", verifierIdentity, scopePolicy, rotationEpoch)',
            section,
        )
        self.assertIn(
            'verifierIdentity = H("zkc/verifier-id:v1", sec1_compressed(aprVerifierPubkey))',
            section,
        )

        # The three new verifier error codes are stated normatively.
        self.assertIn("PROFILE_MISMATCH", section)
        self.assertIn("SCOPE_MISMATCH", section)
        self.assertIn("PROFILE_NOT_ACCEPTED", section)

        # The public-input determinism invariant, as a MUST. Compared with the
        # blockquote markers stripped, so it holds however the quote is wrapped.
        self.assertIn(
            "No public input of a presentation may be deterministic in "
            "credential-only material unless it is the declared linking handle "
            "of the active profile.",
            _squash(_unquote(section)),
        )
        self.assertIn("This is a **MUST**", section)

    def test_issuer_privacy_is_not_claimed_for_current_circuits(self):
        # Security review 2026-10-04 R2.5: the issuer key is a public input,
        # so the verifier learns the specific issuer (threat model M6).
        section = _between(
            SPEC.read_text(),
            "### 8.2 Privacy Properties",
            "### 8.3 Attack Mitigations",
        )
        self.assertNotIn("Verifier learns issuer type, not specific issuer", section)
        row = next(line for line in section.splitlines() if line.startswith("| Issuer privacy |"))
        self.assertIn("Not provided by the current circuits", row)
        self.assertIn("M6", row)

    def test_spec_states_effective_presentation_and_continuity_policy(self):
        section = _squash(_between(
            SPEC.read_text(),
            "#### 5.9.4 Verifier rules",
            "#### 5.9.5 Public-input determinism invariant",
        ))
        self.assertIn("**Reporting the effective presentation.**", section)
        self.assertIn("`scope_recomputed`", section)
        self.assertIn("**Continuity-required policy.**", section)
        self.assertIn("`VerifierTrustPolicy.require_presentation_continuity`", section)
        self.assertIn("an anonymous envelope with `PROFILE_MISMATCH`", section)
        self.assertIn("Without an APR the verifier cannot recompute `scopeId`", section)

    def test_adr_does_not_claim_presentation_profile_is_in_proof_context(self):
        adr = _squash(ADR.read_text())
        self.assertNotIn(
            "The profile identifier is bound into the proof context, so a proof",
            adr,
        )
        self.assertNotIn("(§5.5) and bound into the proof context", adr)
        self.assertIn("the proof context hashes the *context* profile", adr)
        self.assertIn("shape-consistency check", adr)

    def test_zkm_boundary_uses_current_spec_reference(self):
        spec = SPEC.read_text()
        relationship = _between(
            spec,
            "### 1.2a Relationship to ZKM (Informative)",
            "### 1.3 Notation",
        )

        self.assertNotIn("ZKC v0.4.0", relationship)
        self.assertIn("`zkm:issuance-zkc:v1` binds the credential subject to the mandate principal", relationship)
        self.assertIn("`zkm:spend-zkc-binding:v1` binds the credential subject to the ZKA recipient", relationship)

    def test_delegate_viewing_comment_does_not_imply_proving_authority(self):
        spec = SPEC.read_text()

        self.assertIn("Delegate viewing-limited access to principal.", spec)
        self.assertNotIn("Delegate viewing-limited ZKC proving to principal.", spec)

    def test_multi_show_unlinkability_adr_records_design_decision(self):
        self.assertTrue(ADR.exists(), "missing multi-show unlinkability ADR")
        adr = ADR.read_text()

        self.assertIn("Status: Accepted", adr)
        self.assertIn("domain-specific / scope-exclusive pseudonyms", adr)
        self.assertIn("rerandomizable credentials", adr)
        self.assertIn("ZKA note-binding", adr)
        self.assertIn("revocation accumulator", adr)
        self.assertIn("7.3 aggregation", adr)
        self.assertIn("credential-rebind", adr)
        self.assertIn("Follow-up implementation requirement", adr)

    def test_adr_amendment_records_presentation_profile_ladder(self):
        adr = ADR.read_text()

        # The ladder and its three implementable profiles.
        self.assertIn("presentation-profile ladder", adr)
        self.assertIn("zkc:presentation:anonymous:v1", adr)
        self.assertIn("zkc:presentation:scoped:v1", adr)
        self.assertIn("zkc:presentation:linkable:v1", adr)

        # Anonymous is the default; continuity is requested, not ambient.
        self.assertIn("This is the default profile", adr)

        # Pseudonym and scope derivations are pinned exactly.
        self.assertIn('H("zkc/presentation-scope:v1", cbk, scopeId)', adr)
        self.assertIn('H("zkc/scope:v1", verifierIdentity, scopePolicy', adr)

        # Scope governance is named as the security assumption, not a footnote.
        self.assertIn("Scope governance is the guarantee", adr)

        # Receipts/APR reconciliation closes the portable-evidence leak.
        self.assertIn("Disclosure Receipts bind", adr)
        self.assertIn("the active profile's handle, never more", adr)

        # The determinism invariant is stated normatively.
        self.assertIn(
            "No public input of a presentation may be deterministic",
            adr,
        )

        # Escrowed audit linkability is a recorded direction, deferred.
        self.assertIn("verifiable encryption", adr)
        self.assertIn("own ADR before any implementation", adr)


if __name__ == "__main__":
    unittest.main()

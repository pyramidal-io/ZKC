"""Real UltraHonk proof/verification for selective disclosure."""

import copy
import pathlib
import subprocess
import tempfile
import unittest

import _path  # noqa: F401
from _path import REPO_ROOT
from _live_toolchain import historical_toolchain_available

from holder_fixtures import (
    TEST_ISSUER_ID,
    issue_attribute_set_credential,
    trusted_test_issuer,
)
from zkc_crypto import ProofContext
from zkc_holder import LocalAccumulatorProvider, NargoBackend
from zkc_holder.disclosure import (
    DISCLOSURE_CIRCUIT,
    build_selective_disclosure_witness,
    selective_disclosure_public_inputs,
)
from zkc_verifier import BBVerifyBackend


TOOLCHAIN = historical_toolchain_available()


@unittest.skipUnless(TOOLCHAIN, "pinned historical nargo/bb toolchain not on PATH")
class LiveSelectiveDisclosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider = LocalAccumulatorProvider()
        cls.credential = issue_attribute_set_credential(
            master_seed=42,
            credential_id=707,
            provider=cls.provider,
        )
        witness = cls.provider.witness(TEST_ISSUER_ID, cls.credential.credential_id)
        cls.context = ProofContext.verifier_session("verifier.example", 55, 12345)
        cls.full_witness = build_selective_disclosure_witness(
            master_seed=42,
            credential=cls.credential,
            issuer=trusted_test_issuer(("zkc:proof:selective_disclosure:v1",)),
            witness=witness,
            disclosed_positions=[0, 2],
            proof_context=cls.context.value,
            timestamp=cls.context.timestamp,
            current_epoch=witness.accumulator_epoch,
            scope_id=0,
        )
        cls.public_inputs = selective_disclosure_public_inputs(cls.full_witness)
        cls.proof = NargoBackend(REPO_ROOT).prove(DISCLOSURE_CIRCUIT, cls.full_witness)
        with tempfile.TemporaryDirectory(prefix="zkc-disclosure-vk-") as scratch:
            subprocess.run(
                [
                    "bb",
                    "write_vk",
                    "-b",
                    str(REPO_ROOT / "artifacts" / DISCLOSURE_CIRCUIT / f"{DISCLOSURE_CIRCUIT}.json"),
                    "-o",
                    scratch,
                ],
                check=True,
                capture_output=True,
            )
            cls.vk_bytes = (pathlib.Path(scratch) / "vk").read_bytes()

    def test_real_proof_verifies(self):
        self.assertTrue(
            BBVerifyBackend(REPO_ROOT).verify(
                DISCLOSURE_CIRCUIT,
                self.proof,
                self.public_inputs,
                self.vk_bytes,
            )
        )

    def test_real_proof_rejects_altered_position_value(self):
        altered = copy.deepcopy(self.public_inputs)
        altered["disclosed_attributes"][2] = "0x" + "0" * 62 + "17"
        self.assertFalse(
            BBVerifyBackend(REPO_ROOT).verify(
                DISCLOSURE_CIRCUIT,
                self.proof,
                altered,
                self.vk_bytes,
            )
        )


if __name__ == "__main__":
    unittest.main()

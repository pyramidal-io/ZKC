"""Discriminating source and native-Nargo controls for the authentication gate."""

from __future__ import annotations

import contextlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import credential_authentication as auth


@contextlib.contextmanager
def fixture(circuit="zkc_kyc"):
    """Copy actual reviewed sources; frozen repository packages stay untouched."""
    with tempfile.TemporaryDirectory(prefix="zkc-auth-regression-") as temporary:
        root = pathlib.Path(temporary)
        for source in auth.source_closure(ROOT / "noir", circuit):
            target = root / source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        for relative in (".noir-version", "noir/toolchains.json",
                         "scripts/check-poseidon-source-integrity.sh",
                         "scripts/poseidon-v0.3.0.source.sha256"):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        yield root


def replace_main(root, circuit, transform):
    path = root / "noir" / circuit / "src/main.nr"
    source = path.read_text()
    main = auth.functions(auth.tokens(source))["main"]
    body = source[main.open_brace.end:main.close_brace.start]
    path.write_text(main.replace_body(source, transform(body)))


class CredentialAuthenticationSourceTests(unittest.TestCase):
    def rejected(self, transform, message=None):
        with fixture() as root:
            replace_main(root, "zkc_kyc", transform)
            with self.assertRaisesRegex(auth.AuthenticationError, message or ".+"):
                auth.analyze(root / "noir", "zkc_kyc")

    def test_actual_direct_and_reviewed_wrapper_paths_pass(self):
        for circuit in ("zkc_kyc", "zkc_credential_rebind_auth"):
            with self.subTest(circuit=circuit):
                evidence = auth.analyze(ROOT / "noir", circuit)
                self.assertTrue(evidence.positive)
                self.assertTrue(all(evidence.tests.values()))

    def test_comments_and_strings_cannot_authenticate(self):
        for representation in ("block comment", "string literal"):
            with self.subTest(representation=representation):
                if representation == "block comment":
                    self.rejected(lambda body: "/* nested /* comment */ " + body + "*/", "no unconditional")
                else:
                    self.rejected(lambda body: "let marker = " + json.dumps(body) + "; assert(marker == marker);",
                                  "no unconditional")

    def test_unreachable_dependency_calls_and_tests_cannot_authenticate_main(self):
        # Archive R6.2: both real dependencies and their library-calling tests
        # are present, but main does not constrain a credential.
        self.rejected(lambda _: "assert(proof_context != 0);", "no unconditional")

    def test_conditional_authentication_is_not_an_unconditional_constraint(self):
        self.rejected(lambda body: "if false {" + body + "}", "no unconditional")

    def test_nested_early_return_cannot_bypass_later_authentication(self):
        self.rejected(lambda body: "if proof_context == 999 { return; }" + body, "early return")

    def test_prefixed_raw_strings_are_visibly_unsupported(self):
        self.rejected(lambda body: 'let text = r#"marker "; assert_issuer_signature();"#;' + body,
                      "unsupported prefixed/raw string")

    def test_archive_rebind_dependency_only_bypass_is_rejected(self):
        with fixture("zkc_credential_rebind") as root:
            for source in auth.source_closure(ROOT / "noir", "zkc_kyc"):
                if source.is_relative_to(ROOT / "noir/zkc_kyc"):
                    continue
                target = root / source.relative_to(ROOT)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            manifest = root / "noir/zkc_credential_rebind/Nargo.toml"
            manifest.write_text(manifest.read_text() + '\nzkc_issuer_sig = { path = "../zkc_issuer_sig" }\n'
                                'zkc_nonrevocation = { path = "../zkc_nonrevocation" }\n')
            path = root / "noir/zkc_credential_rebind/src/main.nr"
            path.write_text(path.read_text() + '''
                #[test(should_fail_with = "invalid issuer signature")]
                fn gate_only_bad_signature() {
                    zkc_issuer_sig::assert_issuer_signature(1, [1; 32], [1; 32], [1; 64], [1; 32]);
                }
                #[test(should_fail_with = "credential is revoked or accumulator epoch is stale")]
                fn gate_only_revoked() {
                    zkc_nonrevocation::assert_nonrevocation(1, 1, 0, [0; 32], 0, 0, 0);
                }
            ''')
            with self.assertRaisesRegex(auth.AuthenticationError, "does not declare public"):
                auth.analyze(root / "noir", "zkc_credential_rebind")

    def test_boolean_gadget_result_cannot_be_discarded(self):
        self.rejected(lambda body: body.replace("assert_issuer_signature(", "verify_issuer_signature("),
                      "no unconditional")

    def test_public_input_substitution_is_rejected(self):
        for before, after in (("issuer_public_key_x,", "[0; 32],"),
                              ("accumulator_root,", "0,"),
                              ("current_epoch,", "accumulator_epoch,")):
            with self.subTest(input=before):
                self.rejected(lambda body: body.replace(before, after))

    def test_private_key_and_root_parameters_are_rejected(self):
        for name in ("issuer_public_key_x", "accumulator_root"):
            with self.subTest(input=name), fixture() as root:
                path = root / "noir/zkc_kyc/src/main.nr"
                path.write_text(path.read_text().replace(f"{name}: pub ", f"{name}: ", 1))
                with self.assertRaisesRegex(auth.AuthenticationError, "does not declare public"):
                    auth.analyze(root / "noir", "zkc_kyc")

    def test_shadowed_or_mutated_input_is_rejected(self):
        for prefix in ("let accumulator_root = 0;", "issuer_public_key_x[0] = 0;",
                       "let assert_issuer_signature = fake;"):
            with self.subTest(prefix=prefix):
                self.rejected(lambda body: prefix + body, "shadowed|mutated")

    def test_changed_same_named_gadget_cannot_authorize_acceptance(self):
        with fixture() as root:
            path = root / "noir/zkc_issuer_sig/src/lib.nr"
            source = path.read_text()
            function = auth.functions(auth.tokens(source))[auth.ISSUER]
            path.write_text(function.replace_body(source, ""))
            with self.assertRaisesRegex(auth.AuthenticationError, "unreviewed authentication gadget"):
                auth.analyze(root / "noir", "zkc_kyc")

    def test_dependency_path_cannot_be_resolved_by_basename(self):
        with fixture() as root:
            path = root / "noir/zkc_kyc/Nargo.toml"
            path.write_text(path.read_text().replace("../zkc_issuer_sig", "../../fake/zkc_issuer_sig"))
            with self.assertRaisesRegex(auth.AuthenticationError, "unsupported dependency"):
                auth.analyze(root / "noir", "zkc_kyc")

    def test_library_manifest_cannot_substitute_matching_name_tests(self):
        with fixture() as root:
            manifest = root / "noir/zkc_kyc/Nargo.toml"
            manifest.write_text(manifest.read_text().replace('type = "bin"', 'type = "lib"'))
            # Before the fix these native tests passed the original, sentinel
            # and constraint-removal phases: all edits targeted unused main.nr.
            (root / "noir/zkc_kyc/src/lib.nr").write_text('''
                #[test]
                fn test_valid_kyc_predicate() {}
                #[test(should_fail_with = "invalid issuer signature")]
                fn test_kyc_rejects_tampered_issuer_signature() {
                    assert(false, "invalid issuer signature");
                }
                #[test(should_fail_with = "credential is revoked or accumulator epoch is stale")]
                fn test_kyc_rejects_stale_accumulator_epoch() {
                    assert(false, "credential is revoked or accumulator epoch is stale");
                }
            ''')
            with self.assertRaisesRegex(auth.AuthenticationError, "manifest type must be bin"):
                auth.analyze(root / "noir", "zkc_kyc")

    def test_unknown_entrypoint_configuration_is_rejected(self):
        with fixture() as root:
            manifest = root / "noir/zkc_kyc/Nargo.toml"
            manifest.write_text(manifest.read_text().replace(
                'type = "bin"', 'type = "bin"\nentry = "src/other.nr"'))
            with self.assertRaisesRegex(auth.AuthenticationError, "unsupported package configuration"):
                auth.analyze(root / "noir", "zkc_kyc")

    def test_import_alias_cannot_shadow_reviewed_authentication_namespace(self):
        for alias in ("use zkc_fake as zkc_issuer_sig;", "use zkc_lib::{zkc_issuer_sig};"):
            with self.subTest(alias=alias), fixture() as root:
                path = root / "noir/zkc_kyc/src/main.nr"
                path.write_text(alias + path.read_text())
                with self.assertRaisesRegex(auth.AuthenticationError, "unsupported source import|shadowed authentication namespace"):
                    auth.analyze(root / "noir", "zkc_kyc")

    def test_annotations_and_dependency_tests_are_not_main_execution(self):
        with fixture() as root:
            path = root / "noir/zkc_kyc/src/main.nr"
            source = path.read_text()
            # Real authentication main remains; its negative tests now call a
            # dependency helper only. Marker text and test attributes survive.
            for name in ("test_kyc_rejects_tampered_issuer_signature",
                         "test_kyc_rejects_tampered_credential_claims"):
                fn = auth.functions(auth.tokens(source))[name]
                source = fn.replace_body(source, 'assert(false, "invalid issuer signature");')
            path.write_text(source)
            with self.assertRaisesRegex(auth.AuthenticationError, "missing main-driven"):
                auth.analyze(root / "noir", "zkc_kyc")


class CredentialAuthenticationNativeEvidenceTests(unittest.TestCase):
    def test_empty_toolchain_mapping_cannot_skip_execution(self):
        with fixture() as root:
            path = root / "noir/toolchains.json"
            config = json.loads(path.read_text())
            config["packages"]["zkc_kyc"] = []
            path.write_text(json.dumps(config))
            evidence = auth.analyze(root / "noir", "zkc_kyc")
            with self.assertRaisesRegex(auth.AuthenticationError, "missing or unsupported toolchain"):
                auth.execute(root, evidence)

    def test_zero_tests_and_forged_suite_totals_are_rejected(self):
        outputs = ["", '{"findings":[],"ok":true}\n',
                   '{"type":"suite","event":"ok","passed":0,"failed":0,"ignored":0}\n',
                   '\n'.join(json.dumps(row) for row in [
                       {"type": "test", "name": "negative", "event": "ok"},
                       {"type": "suite", "passed": 0, "failed": 0, "ignored": 0}])]
        for output in outputs:
            with self.subTest(output=output), mock.patch.object(auth.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], 0, output, "")):
                with self.assertRaises(auth.AuthenticationError):
                    auth.run_tests("nargo", ROOT, "zkc_kyc", ["negative"])

    def test_native_main_and_constraint_removal_controls_pass(self):
        evidence = auth.analyze(ROOT / "noir", "zkc_kyc")
        receipts = auth.execute(ROOT, evidence)
        self.assertEqual(["historical"], [receipt["lane"] for receipt in receipts])
        self.assertTrue(receipts[0]["main_execution"])
        self.assertTrue(receipts[0]["constraint_removal"])

    def test_main_followed_by_fabricated_matching_failure_is_rejected(self):
        with fixture() as root:
            path = root / "noir/zkc_kyc/src/main.nr"
            source = path.read_text()
            fn = auth.functions(auth.tokens(source))["test_kyc_rejects_tampered_issuer_signature"]
            path.write_text(fn.replace_body(source, '''
                run_kyc_main(valid_kyc_fixture());
                assert(false, "invalid issuer signature");
            '''))
            evidence = auth.analyze(root / "noir", "zkc_kyc")
            with self.assertRaisesRegex(auth.AuthenticationError, "not defeated by removing"):
                auth.execute(root, evidence)

    def test_matching_failure_before_main_is_rejected(self):
        with fixture() as root:
            path = root / "noir/zkc_kyc/src/main.nr"
            source = path.read_text()
            fn = auth.functions(auth.tokens(source))["test_kyc_rejects_tampered_issuer_signature"]
            path.write_text(fn.replace_body(source, '''
                assert(false, "invalid issuer signature");
                run_kyc_main(valid_kyc_fixture());
            '''))
            evidence = auth.analyze(root / "noir", "zkc_kyc")
            with self.assertRaisesRegex(auth.AuthenticationError, "did not execute main"):
                auth.execute(root, evidence)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Validate the checked-in jurisdiction/sanctions canonical-set vectors.

This validator recomputes every pinned root and witness from the reference
builder. It also executes the safe Python constraint mirrors against the
hand-assembled outer-member attack and confirms the normative P5 contract in
the specification.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
VECTOR_PATH = ROOT / "tests" / "vectors" / "canonical_set_vectors.json"
SPEC_PATH = ROOT / "docs" / "zkc_specification.md"

sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "tests" / "python"))

HEX32_RE = re.compile(r"0x[0-9a-f]{64}")


def H(value: int) -> str:
    return f"0x{value:064x}"


def load_vectors() -> dict:
    return json.loads(VECTOR_PATH.read_text())


def walk_hex(prefix: str, value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk_hex(f"{prefix}.{key}" if prefix else key, child)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_hex(f"{prefix}[{index}]", child)
    elif (
        isinstance(value, str)
        and value.startswith("0x")
        and prefix != "field_encoding"
    ):
        yield prefix, value


def assert_hex_fields(vectors: dict) -> None:
    for name, value in walk_hex("", vectors):
        if not HEX32_RE.fullmatch(value):
            raise AssertionError(
                f"{name} is not a lowercase 0x-prefixed 32-byte field: {value}"
            )


def membership_json(witness) -> dict:
    return {
        "code": witness.code,
        "leaf": H(witness.leaf),
        "path_index": witness.path_index,
        "siblings": [H(sibling) for sibling in witness.siblings],
    }


def non_membership_json(witness) -> dict:
    return {
        "is_adjacent": witness.is_adjacent,
        "predecessor_code": witness.predecessor_code,
        "predecessor_leaf": H(witness.predecessor_leaf),
        "predecessor_path_index": witness.predecessor_path_index,
        "predecessor_siblings": [H(sibling) for sibling in witness.predecessor_siblings],
        "successor_code": witness.successor_code,
        "successor_leaf": H(witness.successor_leaf),
        "successor_path_index": witness.successor_path_index,
        "successor_siblings": [H(sibling) for sibling in witness.successor_siblings],
    }


def assert_membership_exact(name: str, actual, pinned: dict, expected_root: int) -> None:
    if membership_json(actual) != pinned:
        raise AssertionError(f"{name}: pinned membership witness differs from builder output")
    if actual.root() != expected_root:
        raise AssertionError(f"{name}: membership witness does not re-derive the root")
    if len(actual.siblings) != 32:
        raise AssertionError(f"{name}: membership witness must contain 32 siblings")


def assert_non_membership_exact(
    name: str, actual, pinned: dict, expected_root: int
) -> None:
    if non_membership_json(actual) != pinned:
        raise AssertionError(
            f"{name}: pinned non-membership witness differs from builder output"
        )
    if not actual.is_adjacent:
        raise AssertionError(f"{name}: builder emitted non-adjacent neighbours")
    if actual.successor_path_index != actual.predecessor_path_index + 1:
        raise AssertionError(f"{name}: neighbour indices are not consecutive")
    if not (
        actual.predecessor_code < actual.subject_code < actual.successor_code
    ):
        raise AssertionError(f"{name}: neighbour ordering does not bracket the subject")
    if actual.predecessor_witness().root() != expected_root:
        raise AssertionError(f"{name}: predecessor witness does not re-derive the root")
    if actual.successor_witness().root() != expected_root:
        raise AssertionError(f"{name}: successor witness does not re-derive the root")


def validate_protocol_scope(vectors: dict) -> None:
    from zkc_crypto import CANONICAL_SET_MAX_REQUEST_CODES

    scope = vectors["protocol_scope"]
    expected = {
        "apr_binding": (
            "A signed APR using canonical construction carries both the canonical "
            "code array and its matching derived root."
        ),
        "exclusion_bare_root_fallback": "rejected",
        "max_request_codes": CANONICAL_SET_MAX_REQUEST_CODES,
        "jurisdiction": {
            "codes_key": "jurisdictionCanonicalSet",
            "modes": ["inclusion", "exclusion"],
            "root_key": "jurisdictionSetRoot",
        },
        "sanctions": {
            "codes_key": "canonicalSet",
            "modes": ["exclusion"],
            "root_key": "setRoot",
        },
        "unsupported_families": ["source", "tax"],
    }
    if scope != expected:
        raise AssertionError("protocol_scope does not pin the confirmed P5 contract")


def validate_jurisdiction_exclusion(section: dict) -> None:
    from zkc_crypto import CANONICAL_SET_EXCLUSION, CanonicalCodeSet

    if section["mode"] != CANONICAL_SET_EXCLUSION:
        raise AssertionError("jurisdiction exclusion vector has the wrong explicit mode")
    canonical = CanonicalCodeSet.for_jurisdiction(
        section["input_codes"], section["claim_type"], section["mode"]
    )
    if list(canonical.members) != section["canonical_members"]:
        raise AssertionError("jurisdiction exclusion canonical members mismatch")
    if list(canonical.leaf_codes) != section["leaf_codes"]:
        raise AssertionError("jurisdiction exclusion leaf codes mismatch")
    if H(canonical.root()) != section["root"]:
        raise AssertionError("jurisdiction exclusion root mismatch")
    assert_membership_exact(
        "jurisdiction exclusion membership 840",
        canonical.membership_witness(840),
        section["membership_witness_840"],
        canonical.root(),
    )
    assert_non_membership_exact(
        "jurisdiction exclusion non-membership 500",
        canonical.non_membership_witness(500),
        section["non_membership_witness_500"],
        canonical.root(),
    )
    claim_2 = CanonicalCodeSet.for_jurisdiction(
        section["input_codes"], 2, CANONICAL_SET_EXCLUSION
    )
    if H(claim_2.root()) != section["same_codes_claim_type_2_root"]:
        raise AssertionError("jurisdiction exclusion claim-type-2 root mismatch")
    if section["roots_differ_by_claim_type"] is not (
        canonical.root() != claim_2.root()
    ):
        raise AssertionError("jurisdiction exclusion claim-type separation mismatch")


def validate_jurisdiction_inclusion(section: dict) -> None:
    from zkc_crypto import CANONICAL_SET_INCLUSION, CanonicalCodeSet

    if section["mode"] != CANONICAL_SET_INCLUSION:
        raise AssertionError("jurisdiction inclusion vector has the wrong explicit mode")
    canonical = CanonicalCodeSet.for_jurisdiction(
        section["input_codes"], section["claim_type"], section["mode"]
    )
    if list(canonical.members) != section["canonical_members"]:
        raise AssertionError("jurisdiction inclusion canonical members mismatch")
    if list(canonical.leaf_codes) != section["leaf_codes"]:
        raise AssertionError("jurisdiction inclusion leaf codes mismatch")
    if [H(leaf) for leaf in canonical.leaves] != section["leaves"]:
        raise AssertionError("jurisdiction inclusion encoded leaves mismatch")
    if H(canonical.root()) != section["root"]:
        raise AssertionError("jurisdiction inclusion root mismatch")
    assert_membership_exact(
        "jurisdiction inclusion membership 840",
        canonical.membership_witness(840),
        section["membership_witness_840"],
        canonical.root(),
    )
    claim_2 = CanonicalCodeSet.for_jurisdiction(
        section["input_codes"], 2, CANONICAL_SET_INCLUSION
    )
    if H(claim_2.root()) != section["same_codes_claim_type_2_root"]:
        raise AssertionError("jurisdiction inclusion claim-type-2 root mismatch")
    if section["roots_differ_by_claim_type"] is not (
        canonical.root() != claim_2.root()
    ):
        raise AssertionError("jurisdiction inclusion claim-type separation mismatch")


def validate_mode_separation(inclusion: dict, exclusion: dict) -> None:
    if inclusion["input_codes"] != exclusion["input_codes"]:
        raise AssertionError("mode vectors must use the same jurisdiction input codes")
    if inclusion["claim_type"] != exclusion["claim_type"]:
        raise AssertionError("mode vectors must use the same jurisdiction claim type")
    if inclusion["root"] == exclusion["root"]:
        raise AssertionError("jurisdiction inclusion and exclusion roots must differ")
    if inclusion["leaf_codes"] == exclusion["leaf_codes"]:
        raise AssertionError("jurisdiction inclusion and exclusion tree shapes must differ")
    if 0 in inclusion["leaf_codes"] or 65535 in inclusion["leaf_codes"]:
        raise AssertionError("jurisdiction inclusion vector must not carry sentinels")
    if exclusion["leaf_codes"][0] != 0 or exclusion["leaf_codes"][-1] != 65535:
        raise AssertionError("jurisdiction exclusion vector must carry both sentinels")


def validate_empty_sets(section: dict) -> None:
    from zkc_crypto import (
        CANONICAL_SET_EXCLUSION,
        CANONICAL_SET_INCLUSION,
        CanonicalCodeSet,
        CanonicalSetError,
    )
    from zkc_crypto.merkle import zero_subtree_root

    entries = {
        "jurisdiction_inclusion": CanonicalCodeSet.for_jurisdiction(
            [], 1, CANONICAL_SET_INCLUSION
        ),
        "jurisdiction_exclusion": CanonicalCodeSet.for_jurisdiction(
            [], 1, CANONICAL_SET_EXCLUSION
        ),
        "sanctions_exclusion": CanonicalCodeSet.for_sanctions([]),
    }
    for name, canonical in entries.items():
        pinned = section[name]
        if canonical.mode != pinned["mode"]:
            raise AssertionError(f"empty_sets.{name}.mode mismatch")
        if list(canonical.leaf_codes) != pinned["leaf_codes"]:
            raise AssertionError(f"empty_sets.{name}.leaf_codes mismatch")
        if H(canonical.root()) != pinned["root"]:
            raise AssertionError(f"empty_sets.{name}.root mismatch")

    inclusion = entries["jurisdiction_inclusion"]
    if inclusion.root() != zero_subtree_root(32):
        raise AssertionError("empty inclusion root is not zeroSubtree[32]")
    try:
        inclusion.membership_witness(150)
        raise AssertionError("empty inclusion unexpectedly emitted a membership witness")
    except CanonicalSetError:
        pass

    expected = section["expected_exclusion_neighbours"]
    subject = section["exclusion_witness_subject"]
    for name in ("jurisdiction_exclusion", "sanctions_exclusion"):
        canonical = entries[name]
        witness = canonical.non_membership_witness(subject)
        shape = {
            "predecessor_code": witness.predecessor_code,
            "predecessor_path_index": witness.predecessor_path_index,
            "successor_code": witness.successor_code,
            "successor_path_index": witness.successor_path_index,
            "is_adjacent": witness.is_adjacent,
        }
        if shape != expected:
            raise AssertionError(f"empty_sets.{name} exclusion witness shape mismatch")
        if witness.predecessor_witness().root() != canonical.root():
            raise AssertionError(f"empty_sets.{name} predecessor root mismatch")
        if witness.successor_witness().root() != canonical.root():
            raise AssertionError(f"empty_sets.{name} successor root mismatch")


def validate_sanctions_multi_member(section: dict) -> None:
    from zkc_crypto import CANONICAL_SET_EXCLUSION, CanonicalCodeSet

    if section["mode"] != CANONICAL_SET_EXCLUSION:
        raise AssertionError("sanctions multi-member vector must use exclusion")
    canonical = CanonicalCodeSet.for_sanctions(section["input_codes"])
    if list(canonical.members) != section["canonical_members"]:
        raise AssertionError("sanctions multi-member canonical members mismatch")
    if list(canonical.leaf_codes) != section["leaf_codes"]:
        raise AssertionError("sanctions multi-member leaf codes mismatch")
    if [H(leaf) for leaf in canonical.leaves] != section["leaves"]:
        raise AssertionError("sanctions multi-member encoded leaves mismatch")
    if H(canonical.root()) != section["root"]:
        raise AssertionError("sanctions multi-member root mismatch")
    assert_membership_exact(
        "sanctions membership 408",
        canonical.membership_witness(408),
        section["membership_witness_408"],
        canonical.root(),
    )
    for subject_string, pinned in section["non_membership_witnesses"].items():
        subject = int(subject_string)
        assert_non_membership_exact(
            f"sanctions non-membership {subject}",
            canonical.non_membership_witness(subject),
            pinned,
            canonical.root(),
        )


def validate_sanctions_single_member(section: dict) -> None:
    from zkc_crypto import CANONICAL_SET_EXCLUSION, CanonicalCodeSet, raw_code_leaf
    from zkc_holder.predicates import single_leaf_set_root

    if section["mode"] != CANONICAL_SET_EXCLUSION:
        raise AssertionError("sanctions single-member vector must use exclusion")
    canonical = CanonicalCodeSet.for_sanctions(section["input_codes"])
    direct_root = single_leaf_set_root(raw_code_leaf(section["input_codes"][0]))
    if list(canonical.members) != section["canonical_members"]:
        raise AssertionError("sanctions single-member canonical members mismatch")
    if list(canonical.leaf_codes) != section["leaf_codes"]:
        raise AssertionError("sanctions single-member leaf codes mismatch")
    if H(canonical.root()) != section["root"]:
        raise AssertionError("sanctions single-member root mismatch")
    if H(direct_root) != section["single_leaf_set_root_of_same_leaf"]:
        raise AssertionError("sanctions legacy single-leaf root mismatch")
    if section["roots_differ"] is not (canonical.root() != direct_root):
        raise AssertionError("sanctions single-member root divergence mismatch")


def validate_duplicates(section: dict) -> None:
    from zkc_crypto import CanonicalCodeSet

    duplicate = CanonicalCodeSet.for_sanctions(section["codes_with_duplicate"])
    deduplicated = CanonicalCodeSet.for_sanctions(section["deduplicated_codes"])
    if H(duplicate.root()) != section["root_from_codes_with_duplicate"]:
        raise AssertionError("duplicate-input root mismatch")
    if H(deduplicated.root()) != section["root_from_deduplicated_codes"]:
        raise AssertionError("deduplicated-input root mismatch")
    if section["roots_equal"] is not (duplicate.root() == deduplicated.root()):
        raise AssertionError("duplicate canonicalization equality mismatch")


def validate_unsorted_naive_tree(section: dict) -> None:
    from zkc_crypto import CanonicalCodeSet, raw_code_leaf
    from zkc_crypto.merkle import SparseMerkleAccumulator

    unsorted = CanonicalCodeSet.for_sanctions(section["unsorted_input_codes"])
    sorted_set = CanonicalCodeSet.for_sanctions(section["sorted_codes"])
    naive = SparseMerkleAccumulator(
        [raw_code_leaf(code) for code in section["unsorted_input_codes"]]
    )
    if H(unsorted.root()) != section["canonical_root_unsorted_input"]:
        raise AssertionError("unsorted canonical root mismatch")
    if H(sorted_set.root()) != section["canonical_root_sorted_input"]:
        raise AssertionError("sorted canonical root mismatch")
    if H(naive.root()) != section["naive_unsorted_unbracketed_tree_root"]:
        raise AssertionError("naive unsorted root mismatch")
    if section["canonical_root_order_independent"] is not (
        unsorted.root() == sorted_set.root()
    ):
        raise AssertionError("canonical order-independence flag mismatch")
    if section["naive_root_differs_from_canonical_root"] is not (
        naive.root() != sorted_set.root()
    ):
        raise AssertionError("naive/canonical root-divergence flag mismatch")


def validate_missing_sentinels(section: dict) -> None:
    from zkc_crypto import CanonicalCodeSet, raw_code_leaf
    from zkc_crypto.merkle import SparseMerkleAccumulator

    members = section["members_only"]
    sentinel_less = SparseMerkleAccumulator([raw_code_leaf(code) for code in members])
    canonical = CanonicalCodeSet.for_sanctions(members)
    if H(sentinel_less.root()) != section["sentinel_less_root"]:
        raise AssertionError("sentinel-less root mismatch")
    if H(canonical.root()) != section["canonical_root_with_sentinels"]:
        raise AssertionError("sentinel-bracketed root mismatch")
    if section["roots_differ"] is not (sentinel_less.root() != canonical.root()):
        raise AssertionError("sentinel root-divergence flag mismatch")
    below = canonical.non_membership_witness(section["subject_below_range"])
    above = canonical.non_membership_witness(section["subject_above_range"])
    if below.predecessor_code != 0 or above.successor_code != 65535:
        raise AssertionError("sentinels do not bracket edge subjects")
    if not (
        section["canonical_bracket_below_uses_min_sentinel"]
        and section["canonical_bracket_above_uses_max_sentinel"]
    ):
        raise AssertionError("sentinel-bracketing flags must both be true")


def validate_outer_member_attack(section: dict) -> None:
    from predicate_fixtures import (
        TEST_ISSUER_ID,
        issue_sanctions_credential,
        trusted_predicate_issuer,
    )
    from zkc_crypto import (
        CanonicalCodeSet,
        CanonicalSetError,
        derive_credential_binding_key,
    )
    from zkc_holder.accumulator import LocalAccumulatorProvider
    from zkc_holder.errors import ConstraintViolationError
    from zkc_holder.predicates import (
        PREDICATE_SANCTIONS_CLEARANCE,
        build_profile_witness_v3,
        build_profile_witness_v4,
        check_profile_constraints_v7,
        check_profile_constraints_v8,
    )

    canonical = CanonicalCodeSet.for_sanctions(section["set_codes"])
    subject = section["subject_code"]
    if H(canonical.root()) != section["root"]:
        raise AssertionError("outer-member root mismatch")
    if not canonical.contains(subject) or section["subject_is_member"] is not True:
        raise AssertionError("outer-member subject must be a genuine set member")
    try:
        canonical.non_membership_witness(subject)
        raise AssertionError("builder emitted an exclusion witness for a present subject")
    except CanonicalSetError:
        pass
    if section["builder_refuses_non_membership_witness_for_subject"] is not True:
        raise AssertionError("outer-member builder-refusal flag must be true")
    predecessor = canonical.membership_witness(section["predecessor"]["code"])
    successor = canonical.membership_witness(section["successor"]["code"])
    assert_membership_exact(
        "outer-member predecessor", predecessor, section["predecessor"], canonical.root()
    )
    assert_membership_exact(
        "outer-member successor", successor, section["successor"], canonical.root()
    )
    is_adjacent = successor.path_index == predecessor.path_index + 1
    if section["is_adjacent"] is not is_adjacent or is_adjacent:
        raise AssertionError("outer-member flanking leaves must be non-adjacent")
    if section["ordering_holds_pred_lt_subject_lt_succ"] is not (
        predecessor.code < subject < successor.code
    ):
        raise AssertionError("outer-member ordering flag mismatch")
    if section["circuit_enforces_adjacency"] is not True:
        raise AssertionError("current circuit vectors must pin index adjacency enforcement")

    # Prove the checked-in attack vector reaches the adjacency assertion: both
    # current mirrors receive an otherwise-valid, issuer-authenticated witness
    # and reject this exact non-adjacent pair.
    provider = LocalAccumulatorProvider()
    master_seed = 4242
    credential = issue_sanctions_credential(
        master_seed=master_seed,
        credential_id=302,
        screening_code=subject,
        provider=provider,
    )
    witness_args = {
        "predicate_type": PREDICATE_SANCTIONS_CLEARANCE,
        "credential_binding_key": derive_credential_binding_key(master_seed),
        "credential": credential,
        "issuer": trusted_predicate_issuer(),
        "witness": provider.witness(TEST_ISSUER_ID, credential.credential_id),
        "required_0": 0,
        "required_1": 0,
        "flag_required": False,
        "set_root": int(section["root"], 16),
        "path_index": 0,
        "siblings": [0] * 32,
        "predecessor_code": predecessor.code,
        "predecessor_path_index": section["predecessor"]["path_index"],
        "predecessor_siblings": [
            int(value, 16) for value in section["predecessor"]["siblings"]
        ],
        "successor_code": successor.code,
        "successor_path_index": section["successor"]["path_index"],
        "successor_siblings": [
            int(value, 16) for value in section["successor"]["siblings"]
        ],
        "proof_context": 12345,
        "timestamp": 1_700_000,
        "current_epoch": provider.current_epoch(TEST_ISSUER_ID),
    }

    # Assemble the deliberately invalid adjacency pair through the historical
    # ABI-compatible builders; the current v7/v8 builders correctly reject it
    # before returning a witness, while the mirrors below must independently
    # demonstrate the same circuit constraint has teeth.
    linkable_witness = build_profile_witness_v3(**witness_args)
    presentation_witness = build_profile_witness_v4(scope_id=0, **witness_args)

    mirrors = {
        "zkc_remaining_predicates_v7": (
            check_profile_constraints_v7,
            linkable_witness,
        ),
        "zkc_remaining_predicates_v8": (
            check_profile_constraints_v8,
            presentation_witness,
        ),
    }
    if set(section["constraint_mirror_rejections"]) != set(mirrors):
        raise AssertionError("outer-member constraint-mirror identities differ")
    for circuit, (check_constraints, witness) in mirrors.items():
        expected_message = section["constraint_mirror_rejections"][circuit]
        try:
            check_constraints(witness)
        except ConstraintViolationError as exc:
            if exc.message != expected_message:
                raise AssertionError(
                    f"{circuit}: unexpected adjacency rejection: {exc}"
                ) from exc
        else:
            raise AssertionError(f"{circuit}: accepted the outer-member attack")

    # Exercise the compiled Noir identities too. Each named test is a full
    # circuit invocation marked should_fail; Nargo exits non-zero if a circuit
    # regression starts accepting the outer-member witness.
    noir_tests = section["noir_rejection_tests"]
    if set(noir_tests) != set(mirrors):
        raise AssertionError("outer-member Noir rejection identities differ")
    nargo = shutil.which("nargo")
    if nargo is None:
        raise AssertionError(
            "nargo is required for compiled canonical-set validation; "
            "install the pinned toolchain from .noir-version"
        )
    for package, test_name in noir_tests.items():
        process = subprocess.run(
            [
                nargo,
                "test",
                "--package",
                package,
                "--exact",
                test_name,
            ],
            cwd=ROOT / "noir",
            capture_output=True,
            text=True,
        )
        if process.returncode != 0:
            output = (process.stdout + process.stderr).strip()
            raise AssertionError(
                f"{package}: Noir adjacency rejection test failed:\n{output}"
            )


def validate_domain_refusals(section: dict) -> None:
    from zkc_crypto import CanonicalCodeSet, CanonicalSetError

    if "empty_set" in section["cases"]:
        raise AssertionError("empty sets are valid and must not be a refusal vector")
    expected_codes = {
        "min_sentinel_as_member": 0,
        "max_sentinel_as_member": 65535,
        "above_u16_domain": 65536,
        "negative_code": -1,
    }
    if set(section["cases"]) != set(expected_codes):
        raise AssertionError("out-of-domain refusal cases do not match the contract")
    for name, code in expected_codes.items():
        pinned = section["cases"][name]
        try:
            CanonicalCodeSet.for_sanctions([code])
            raise AssertionError(f"{name}: invalid code was accepted")
        except CanonicalSetError as exc:
            if pinned["raises"] != "CanonicalSetError":
                raise AssertionError(f"{name}: wrong pinned exception type")
            if str(exc) != pinned["message"]:
                raise AssertionError(f"{name}: pinned error message differs: {exc}")
    non_arrays = {
        "tuple": (1, 2),
        "set": {1, 2},
        "iterator": iter([1, 2]),
        "mapping": {1: 2},
        "string": "1,2",
    }
    pinned_non_arrays = section["non_array_inputs"]
    if pinned_non_arrays["cases"] != list(non_arrays):
        raise AssertionError("non-array refusal cases do not match the contract")
    if pinned_non_arrays["raises"] != "CanonicalSetError":
        raise AssertionError("non-array refusals pin the wrong exception type")
    for name, value in non_arrays.items():
        try:
            CanonicalCodeSet.for_sanctions(value)
            raise AssertionError(f"{name}: non-array canonical-set input was accepted")
        except CanonicalSetError as exc:
            if str(exc) != pinned_non_arrays["message"]:
                raise AssertionError(f"{name}: pinned error message differs: {exc}")


def validate_spec_contract() -> None:
    normalized = " ".join(SPEC_PATH.read_text().split())
    required = (
        "### 7.2c Canonical Blocked-Set Construction and Root Distribution",
        "Source-of-funds and tax-residency are not covered by this u16 protocol.",
        "The construction mode is mandatory:",
        "Reject a non-array input, a non-integer or boolean entry",
        "Empty arrays are valid.",
        "The verifier therefore MUST publish both the canonical code list and its derived root in the signed Authenticated Proof Request (APR).",
        "an exclusion request containing only a root MUST be rejected.",
        "jurisdictionCanonicalSet: <array of canonical-domain codes>",
        "jurisdictionSetRoot: <BN254 field integer>",
        "canonicalSet: <array of canonical-domain codes>",
        "setRoot: <BN254 field integer>",
        "An online APR code array MUST contain no more than 4,096 entries",
        "CANONICAL_SET_MAX_REQUEST_CODES",
        "Issuers MUST reject either value as a `jurisdictionCode` or `screeningCode` before signing.",
        "Supplying either reserved key to source-of-funds, tax-residency, accreditation, or another unsupported predicate",
        "`successor_path_index == predecessor_path_index + 1`.",
        "The historical remaining-predicate v1-v4 and jurisdiction v1/v2 circuits verify membership of both neighbours",
        "The remaining-predicate v5-v11 sanctions branches and jurisdiction v3-v6 exclusion branches additionally constrain the successor index",
    )
    for statement in required:
        if statement not in normalized:
            raise AssertionError(
                f"docs/zkc_specification.md does not pin the P5 contract: {statement}"
            )


def main() -> int:
    vectors = load_vectors()
    assert_hex_fields(vectors)
    if vectors["version"] != "zkc-canonical-set-vectors:v3":
        raise AssertionError(f"unexpected vector version: {vectors['version']}")
    if vectors["field_encoding"] != (
        "0x-prefixed 32-byte big-endian BN254 scalar field element"
    ):
        raise AssertionError("unexpected field encoding")
    if "nargo" not in vectors["toolchain"]:
        raise AssertionError("toolchain must pin nargo")

    from zkc_crypto import (
        CANONICAL_CODE_MAX,
        CANONICAL_CODE_MIN,
        CANONICAL_SENTINEL_MAX,
        CANONICAL_SENTINEL_MIN,
    )

    if vectors["sentinels"] != {
        "code_max": CANONICAL_CODE_MAX,
        "code_min": CANONICAL_CODE_MIN,
        "max": CANONICAL_SENTINEL_MAX,
        "min": CANONICAL_SENTINEL_MIN,
    }:
        raise AssertionError("sentinel metadata differs from the implementation")

    validate_protocol_scope(vectors)
    positive = vectors["positive"]
    exclusion = positive["jurisdiction_exclusion_claim_type_scoped"]
    inclusion = positive["jurisdiction_inclusion_claim_type_scoped"]
    validate_jurisdiction_exclusion(exclusion)
    validate_jurisdiction_inclusion(inclusion)
    validate_mode_separation(inclusion, exclusion)
    validate_empty_sets(positive["empty_sets"])
    validate_sanctions_multi_member(positive["sanctions_multi_member"])
    validate_sanctions_single_member(positive["sanctions_single_member"])

    negative = vectors["negative"]
    validate_duplicates(negative["duplicates_canonicalize"])
    validate_unsorted_naive_tree(negative["unsorted_naive_tree_diverges"])
    validate_missing_sentinels(negative["missing_sentinel_bracket"])
    validate_outer_member_attack(negative["outer_member_attack"])
    validate_domain_refusals(negative["out_of_domain_refusals"])
    validate_spec_contract()

    print(
        f"validated {VECTOR_PATH.relative_to(ROOT)} against canonical_set.py and spec §7.2c"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

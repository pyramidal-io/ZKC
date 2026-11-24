"""Bounded authentication analysis and executable main-test evidence.

This is deliberately not a Noir verifier. It recognizes the repository's two
reviewed call shapes: main -> asserted issuer/membership gadgets, and main ->
assert_authenticated_rebind -> those gadgets. Public argument provenance and
unconditional assertion calls are checked, rather than mere call reachability.
The gadget implementation/manifest pins are part of this gate's review policy;
changing them requires reviewing the ECDSA assertion and the public-root Merkle
comparison again. Novel call shapes fail closed until explicitly supported.

Tests run in disposable source copies. Main instrumentation proves execution;
removing the relevant gadget must turn a negative into an unexpected success.
Neither candidate failure-message strings nor a process exit code are receipts.
This evidence does not establish arbitrary credential or predicate semantics.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass

from noir_toolchains import package_toolchains, read_version_file


class AuthenticationError(ValueError):
    """Unsupported, ambiguous, missing, or failed authentication evidence."""


# These reviewed bodies assert ECDSA's boolean result and Merkle membership
# against the passed root, with freshness. Include manifests and the primitive
# library so a same-named dependency or changed implementation cannot stand in.
GADGET_PINS = {
    "zkc_issuer_sig/Nargo.toml": "cbb5a2bb89ba4629b4c88a2c3d3bc67536fb73e131a1eb02e0882f58564edbc0",
    "zkc_issuer_sig/src/lib.nr": "076a41ed3a4dd51414affb980697246ec6ca60724e57eef40c57d176153dd54d",
    "zkc_nonrevocation/Nargo.toml": "6c1307a3563ab51cd445509624568a098a010485fc459a4556350f4277613df4",
    "zkc_nonrevocation/src/lib.nr": "a40ead9cf920ac257c8c039b9f03107352ae9472ee8ed6d09dcb701b32155af7",
    "zkc_lib/Nargo.toml": "fb3215d44330cecb63156b4c5bc5bcde6303393a4e92ab16d39d87f92d82edf2",
    "zkc_lib/src/lib.nr": "4427a529e2ce54ce83597e77538661b8407735a4940fdd4c6d4c17cb65f99809",
    "zkc_rebind_auth/Nargo.toml": "cf4bcbdebdb96a1e9091133e3417198283f7145da8949f84d8fde7d521ddc244",
    "zkc_rebind_auth/src/lib.nr": "69895216f16a7873f8b948f62e5c9a58d3895727f5d7542e2beea19efdb74306",
}
ISSUER = "assert_issuer_signature"
REVOCATION = "assert_nonrevocation"
REBIND = "assert_authenticated_rebind"
GADGET_NAMESPACES = {"zkc_issuer_sig", "zkc_nonrevocation", "zkc_rebind_auth"}
EXPECTED_FAILURES = {
    "issuer signature": frozenset({
        "invalid issuer signature", "Signature provided for ECDSA verification is zero",
    }),
    "revocation / epoch freshness": frozenset({
        "credential is revoked or accumulator epoch is stale",
    }),
}
PUBLIC_TYPES = {
    "issuer_public_key_x": "pub[u8;32]",
    "issuer_public_key_y": "pub[u8;32]",
    "accumulator_root": "pubField",
    "accumulator_epoch": "pubu64",
    "current_epoch": "pubu64",
}
SENTINEL = "credential authentication gate: main executed"


@dataclass(frozen=True)
class Token:
    text: str
    start: int
    end: int


def tokens(source: str) -> list[Token]:
    """Lex comments and quoted strings separately, preserving source offsets.

    Nested block comments are legal Noir. Raw/format strings and unsupported
    metaprogramming never become calls: the bounded analyzer refuses them.
    """
    result = []
    index = 0
    while index < len(source):
        start = index
        if source[index].isspace():
            index += 1
        elif source.startswith("//", index):
            end = source.find("\n", index)
            index = len(source) if end < 0 else end
        elif source.startswith("/*", index):
            depth = 1
            index += 2
            while depth and index < len(source):
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                raise AuthenticationError("unterminated block comment")
        elif source[index] == '"':
            index += 1
            while index < len(source) and source[index] != '"':
                index += 2 if source[index] == "\\" else 1
            if index >= len(source):
                raise AuthenticationError("unterminated string")
            index += 1
            result.append(Token(source[start:index], start, index))
        else:
            match = re.match(r"[A-Za-z_][A-Za-z_0-9]*|[0-9][A-Za-z_0-9]*|::|->|[=+*!<>/&|^-]=|.", source[index:])
            assert match is not None
            index += len(match[0])
            if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", match[0]) and re.match(r'[#]*"', source[index:]):
                raise AuthenticationError("unsupported prefixed/raw string syntax")
            result.append(Token(match[0], start, index))
    return result


def closing(items: list[Token], start: int) -> int:
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = []
    for index in range(start, len(items)):
        value = items[index].text
        if value in pairs:
            stack.append(pairs[value])
        elif value in pairs.values():
            if not stack or stack.pop() != value:
                raise AuthenticationError("unbalanced source delimiters")
            if not stack:
                return index
    raise AuthenticationError("unclosed source delimiters")


def split(items: list[Token]) -> list[list[Token]]:
    """Split comma-separated parameters/arguments, respecting nesting."""
    result, part = [], []
    index = 0
    while index < len(items):
        value = items[index].text
        if value == ",":
            result.append(part)
            part = []
        elif value in ("(", "[", "{"):
            end = closing(items, index)
            part.extend(items[index:end + 1])
            index = end
        else:
            part.append(items[index])
        index += 1
    if part:
        result.append(part)
    return result


@dataclass
class Function:
    name: str
    parameters: list[list[Token]]
    body: list[Token]
    open_brace: Token
    close_brace: Token
    attribute: list[Token]

    def replace_body(self, source: str, body: str) -> str:
        return source[:self.open_brace.end] + body + source[self.close_brace.start:]


def functions(items: list[Token]) -> dict[str, Function]:
    result = {}
    index = 0
    attribute: list[Token] = []
    while index < len(items):
        value = items[index].text
        if value == "#" and items[index + 1].text == "[":
            end = closing(items, index + 1)
            attribute.extend(items[index:end + 1])
            index = end + 1
            continue
        if value == "fn":
            name = items[index + 1].text
            if items[index + 2].text != "(":
                raise AuthenticationError(f"unsupported generic function {name}")
            end_parameters = closing(items, index + 2)
            brace = end_parameters + 1
            while brace < len(items) and items[brace].text != "{":
                brace += 1
            if brace == len(items):
                raise AuthenticationError(f"missing function body: {name}")
            end = closing(items, brace)
            if name in result:
                raise AuthenticationError(f"ambiguous function {name}")
            if index and items[index - 1].text in {"unconstrained", "comptime"}:
                raise AuthenticationError(f"unsupported unconstrained/comptime function {name}")
            result[name] = Function(name, split(items[index + 3:end_parameters]),
                                    items[brace + 1:end], items[brace], items[end], attribute)
            attribute = []
            index = end + 1
            continue
        if value in {"mod", "contract", "impl", "comptime", "unsafe"}:
            raise AuthenticationError(f"unsupported source construct {value}")
        if value == "{":
            index = closing(items, index)
        elif value == ";":
            attribute = []
        index += 1
    return result


def calls(body: list[Token], *, unconditional: bool = False) -> list[tuple[str, list[list[Token]]]]:
    result = []
    index = 0
    boundary = True
    while index < len(body):
        value = body[index].text
        if value == "return" and unconditional:
            raise AuthenticationError("early return in main is unsupported")
        if value in {"{", "["} and unconditional:
            index = closing(body, index) + 1
            boundary = value == "{"
            continue
        if re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*", value):
            end = index + 1
            while end + 1 < len(body) and body[end].text == "::":
                end += 2
            if end < len(body) and body[end].text == "(":
                last = closing(body, end)
                if not unconditional or (boundary and last + 1 < len(body) and body[last + 1].text == ";"):
                    result.append(("".join(t.text for t in body[index:end]), split(body[end + 1:last])))
                if unconditional:
                    index = last + 1
                    boundary = False
                    continue
        boundary = value in {";", "}"}
        index += 1
    return result


def compact(items: list[Token]) -> str:
    return "".join(t.text for t in items)


def imports(items: list[Token]) -> dict[str, str]:
    result = {}
    index = 0
    while index < len(items):
        if items[index].text == "use":
            end = index + 1
            while end < len(items) and items[end].text != ";":
                end += 1
            text = compact(items[index + 1:end])
            match = re.fullmatch(r"(zkc_\w+)::\{([A-Za-z_0-9,]+)\}", text)
            if match:
                for name in filter(None, match[2].split(",")):
                    if name in result:
                        raise AuthenticationError(f"ambiguous import {name}")
                    result[name] = f"{match[1]}::{name}"
            else:
                raise AuthenticationError(f"unsupported source import {text}")
            index = end
        elif items[index].text == "{":
            index = closing(items, index)
        index += 1
    return result


def source_closure(noir: pathlib.Path, circuit: str) -> list[pathlib.Path]:
    """Resolve literal sibling dependencies, never basename an arbitrary path."""
    seen: set[str] = set()
    stack = [circuit]
    result = []
    while stack:
        package = stack.pop()
        if not re.fullmatch(r"zkc_[a-z0-9_]+", package):
            raise AuthenticationError(f"unsupported package name {package!r}")
        if package in seen:
            continue
        seen.add(package)
        directory = noir / package
        manifest = directory / "Nargo.toml"
        if (directory.is_symlink() or (directory / "src").is_symlink()
                or not manifest.is_file() or manifest.is_symlink()):
            raise AuthenticationError(f"missing or symlinked manifest for {package}")
        result.append(manifest)
        for path in sorted((directory / "src").rglob("*")):
            if path.is_symlink() or any(p.is_symlink() for p in path.parents if p.is_relative_to(noir)):
                raise AuthenticationError(f"symlinked package source {path}")
            if path.is_file():
                if path.suffix != ".nr":
                    raise AuthenticationError(f"unsupported source input {path}")
                result.append(path)
        definition = tomllib.loads(manifest.read_text())
        package_definition = definition.get("package", {})
        if package_definition.get("name") != package:
            raise AuthenticationError(f"manifest name mismatch for {package}")
        expected_type = "bin" if package == circuit else "lib"
        if package_definition.get("type") != expected_type:
            raise AuthenticationError(f"{package}: manifest type must be {expected_type}")
        # Nargo must compile the same src/main.nr that is analyzed and
        # instrumented. A lib target instead runs src/lib.nr, where matching
        # test names can forge every apparent main-execution control.
        if (set(definition) - {"package", "dependencies"}
                or set(package_definition) - {
                    "name", "type", "authors", "compiler_version", "description", "version",
                }):
            raise AuthenticationError(f"{package}: unsupported package configuration")
        for name, dependency in definition.get("dependencies", {}).items():
            if name == "poseidon" and package == "zkc_lib":
                continue  # pinned manifest plus verify-after-fetch source gate
            if dependency != {"path": f"../{name}"}:
                raise AuthenticationError(f"unsupported dependency {package}::{name}")
            stack.append(name)
    return result


@dataclass
class Authentication:
    circuit: str
    sources: list[pathlib.Path]
    functions: dict[str, Function]
    tests: dict[str, list[str]]
    positive: list[str]


def analyze(noir: pathlib.Path, circuit: str) -> Authentication:
    sources = source_closure(noir, circuit)
    source = (noir / circuit / "src/main.nr").read_text()
    items = tokens(source)
    if any(token.text in {"comptime", "unconstrained", "unsafe", "oracle", "foreign"} for token in items):
        raise AuthenticationError("unsupported source execution/metaprogramming construct")
    defined = functions(items)
    if "main" not in defined or defined["main"].attribute:
        raise AuthenticationError("missing or attributed main")
    main = defined["main"]
    if any(token.text in {"return", "comptime", "unsafe", "use"} for token in main.body):
        raise AuthenticationError("early return or unsupported main execution construct")
    parameters = {}
    for parameter in main.parameters:
        if len(parameter) < 3 or parameter[1].text != ":":
            raise AuthenticationError("unsupported main parameter")
        parameters[parameter[0].text] = compact(parameter[2:])
    for name, expected in PUBLIC_TYPES.items():
        if parameters.get(name) != expected:
            raise AuthenticationError(f"main does not declare public {name}: {expected}")

    imported = imports(items)
    protected = set(PUBLIC_TYPES) | GADGET_NAMESPACES | {"credential_id", "issuer_signature",
        "nonrevocation_path_index", "nonrevocation_siblings", ISSUER, REVOCATION, REBIND,
        "ISSUER_SIGNATURE_SCHEME_ECDSA_SECP256K1", "NONREVOCATION_ACCUMULATOR_MERKLE_POSEIDON2"}
    if ({ISSUER, REVOCATION, REBIND} | GADGET_NAMESPACES) & set(defined):
        raise AuthenticationError("authentication function is locally redefined")
    if GADGET_NAMESPACES & set(imported):
        raise AuthenticationError("shadowed authentication namespace")
    # Reject shadowing/mutation rather than inferring aliases or SSA versions.
    for index, token in enumerate(main.body):
        if token.text == "let":
            end = index + 1
            while end < len(main.body) and main.body[end].text not in {"=", ";"}:
                end += 1
            if protected & {t.text for t in main.body[index + 1:end]}:
                raise AuthenticationError("shadowed authentication input or function")
        if token.text in protected and index + 1 < len(main.body):
            end = index + 1
            if main.body[end].text == "[":
                end = closing(main.body, end) + 1
            if end < len(main.body) and main.body[end].text in {"=", "+=", "-=", "*=", "/=", "^=", "&=", "|="}:
                raise AuthenticationError("mutated public authentication input")
    resolved = {}
    for name, arguments in calls(main.body, unconditional=True):
        qualified = imported.get(name, name)
        if qualified in {f"zkc_issuer_sig::{ISSUER}", f"zkc_nonrevocation::{REVOCATION}", f"zkc_rebind_auth::{REBIND}"}:
            if qualified in resolved:
                raise AuthenticationError("ambiguous repeated authentication call")
            resolved[qualified] = [compact(argument) for argument in arguments]

    rebind = resolved.get(f"zkc_rebind_auth::{REBIND}")
    if rebind is not None:
        # Reviewed wrapper passes these exact arguments into the pinned gadgets.
        expected = ["old_holder_commitment", "new_holder_commitment", "credential_id",
            "issuer_id_hash", "schema_id_hash", "proof_context", "timestamp",
            "accumulator_root", "accumulator_epoch", "current_epoch",
            "issuer_public_key_x", "issuer_public_key_y", "old_credential_binding_key",
            "new_credential_binding_key", "credential_valid_from", "credential_valid_until",
            "issuer_signature", "nonrevocation_siblings", "nonrevocation_path_index"]
        if rebind != expected:
            raise AuthenticationError("rebind wrapper does not forward authentication inputs")
        required_packages = {"zkc_issuer_sig", "zkc_nonrevocation", "zkc_lib", "zkc_rebind_auth"}
    else:
        issuer = resolved.get(f"zkc_issuer_sig::{ISSUER}", [])
        revocation = resolved.get(f"zkc_nonrevocation::{REVOCATION}", [])
        if len(issuer) != 5 or issuer[:4] != ["ISSUER_SIGNATURE_SCHEME_ECDSA_SECP256K1",
                "issuer_public_key_x", "issuer_public_key_y", "issuer_signature"]:
            raise AuthenticationError("no unconditional asserted ECDSA call with public issuer key")
        if revocation != ["NONREVOCATION_ACCUMULATOR_MERKLE_POSEIDON2", "credential_id",
                "nonrevocation_path_index", "nonrevocation_siblings", "accumulator_root",
                "accumulator_epoch", "current_epoch"]:
            raise AuthenticationError("no unconditional asserted accumulator path with public root/epochs")
        for name, package in [("ISSUER_SIGNATURE_SCHEME_ECDSA_SECP256K1", "zkc_issuer_sig"),
                ("NONREVOCATION_ACCUMULATOR_MERKLE_POSEIDON2", "zkc_nonrevocation")]:
            if imported.get(name) != f"{package}::{name}":
                raise AuthenticationError(f"unreviewed scheme constant {name}")
        required_packages = {"zkc_issuer_sig", "zkc_nonrevocation", "zkc_lib"}
    source_set = set(sources)
    for relative, expected in GADGET_PINS.items():
        if relative.split("/")[0] not in required_packages:
            continue
        path = noir / relative
        if path not in source_set or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise AuthenticationError(f"unreviewed authentication gadget {relative}")
    # Reject global values/import aliases that could shadow the checked bindings.
    for index, token in enumerate(items[:-1]):
        if token.text in {"global", "struct", "type", "enum"} and items[index + 1].text in protected:
            raise AuthenticationError("locally redefined authentication binding")

    edges = {name: {call for call, _ in calls(fn.body)} & set(defined)
             for name, fn in defined.items()}

    def reaches_main(name: str, seen: set[str]) -> bool:
        if name == "main":
            return True
        return name not in seen and any(reaches_main(child, seen | {name}) for child in edges[name])

    tests = {label: [] for label in EXPECTED_FAILURES}
    positive = []
    for name, fn in defined.items():
        annotation = compact(fn.attribute)
        if not reaches_main(name, set()):
            continue
        if annotation == "#[test]":
            positive.append(name)
        else:
            match = re.fullmatch(r'#\[test\(should_fail_with=("(?:[^"\\]|\\.)*")\)\]', annotation)
            if match:
                message = json.loads(match[1])
                for label, messages in EXPECTED_FAILURES.items():
                    if message in messages:
                        tests[label].append(name)
    if not positive or not all(tests.values()):
        raise AuthenticationError("missing main-driven honest or adversarial test declarations")
    return Authentication(circuit, sources, defined, tests, positive)


def nargo_binary(root: pathlib.Path, lane: str, config: dict) -> str:
    executable = os.environ.get(f"ZKC_{lane.upper()}_NARGO")
    executable = executable or shutil.which("nargo")
    if not executable:
        raise AuthenticationError(f"missing {lane} Nargo; set ZKC_{lane.upper()}_NARGO")
    result = subprocess.run([executable, "--version"], capture_output=True, text=True, check=False, timeout=20)
    expected = config["toolchains"][lane]
    if result.returncode or not all(f"{tool} version = {expected[tool]}\n" in result.stdout
                                    for tool in ("nargo", "noirc")):
        raise AuthenticationError(f"{lane} Nargo/noirc does not match pinned toolchain")
    pins = read_version_file(root / ".noir-version")
    if expected["nargo"] != pins[f"{lane.upper()}_NARGO_VERSION"]:
        raise AuthenticationError(f"{lane} Nargo configuration/pin mismatch")
    return executable


def run_tests(binary: str, directory: pathlib.Path, circuit: str, names: list[str]) -> dict[str, str]:
    result = subprocess.run([binary, "test", "--package", circuit, "--format", "json",
                            "--exact", *names], cwd=directory, capture_output=True, text=True,
                            check=False, timeout=180)
    events = []
    for line in result.stdout.splitlines():
        if line.startswith("{"):
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise AuthenticationError("malformed Nargo test evidence") from exc
    completed = [event for event in events
                 if event.get("type") == "test" and event.get("event") in {"ok", "failed"}]
    ended = {event.get("name"): event.get("event") for event in completed}
    suite = [event for event in events if event.get("type") == "suite" and "passed" in event]
    if set(ended) != set(names) or len(completed) != len(names) or len(suite) != 1:
        detail = (result.stderr + result.stdout)[-3000:]
        raise AuthenticationError(f"missing/ambiguous native Nargo test results ({circuit}): {detail}")
    expected_code = 0 if all(status == "ok" for status in ended.values()) else 1
    passed = sum(status == "ok" for status in ended.values())
    if (result.returncode != expected_code or suite[0].get("ignored") != 0
            or suite[0].get("passed") != passed or suite[0].get("failed") != len(names) - passed):
        raise AuthenticationError("Nargo process/suite/test evidence disagrees")
    return ended


def execute(root: pathlib.Path, evidence: Authentication) -> list[dict]:
    """Execute main controls and constraint-removal witnesses in every pinned lane."""
    config = json.loads((root / "noir/toolchains.json").read_text())
    circuit = evidence.circuit
    receipts = []
    lanes = package_toolchains(config, circuit)
    if not lanes or len(set(lanes)) != len(lanes) or any(lane not in {"historical", "successor"} for lane in lanes):
        raise AuthenticationError(f"{circuit}: missing or unsupported toolchain lanes")
    for lane in lanes:
        binary = nargo_binary(root, lane, config)
        with tempfile.TemporaryDirectory(prefix="zkc-auth-main-") as temporary:
            directory = pathlib.Path(temporary)
            for path in evidence.sources:
                target = directory / path.relative_to(root / "noir")
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
            (directory / "Nargo.toml").write_text(f'[workspace]\nmembers = ["{circuit}"]\n')
            main_path = directory / circuit / "src/main.nr"
            original = main_path.read_text()
            positive = evidence.positive[0]
            negatives = [names[0] for names in evidence.tests.values()]
            names = [positive, *negatives]
            if any(value != "ok" for value in run_tests(binary, directory, circuit, names).values()):
                raise AuthenticationError(f"{circuit}/{lane}: honest or negative main test failed")
            # The selected tests must actually enter main, not fail in a library,
            # pre-main setup, or an unrelated assertion with a matching message.
            instrumented = evidence.functions["main"].replace_body(original, f'\nassert(false, "{SENTINEL}");\n')
            selected = functions(tokens(instrumented))
            replacements = []
            for name in names:
                annotation = selected[name].attribute
                replacements.append((annotation[0].start, annotation[-1].end,
                                     f'#[test(should_fail_with = "{SENTINEL}")]'))
            for start, end, replacement in sorted(replacements, reverse=True):
                instrumented = instrumented[:start] + replacement + instrumented[end:]
            main_path.write_text(instrumented)
            if any(value != "ok" for value in run_tests(binary, directory, circuit, names).values()):
                raise AuthenticationError(f"{circuit}/{lane}: selected test did not execute main")
            main_path.write_text(original)
            for label, name, gadget, package in zip(evidence.tests, negatives,
                    (ISSUER, REVOCATION), ("zkc_issuer_sig", "zkc_nonrevocation")):
                path = directory / package / "src/lib.nr"
                source = path.read_text()
                function = functions(tokens(source))[gadget]
                path.write_text(function.replace_body(source, "\n"))
                # Change the test into an ordinary test: it must now succeed.
                # Requiring an observed OK avoids interpreting compiler errors,
                # missing tests or arbitrary process failures as a killed test.
                fn = evidence.functions[name]
                annotation = fn.attribute
                main_path.write_text(original[:annotation[0].start] + "#[test]" + original[annotation[-1].end:])
                result = run_tests(binary, directory, circuit, [name])
                path.write_text(source)
                main_path.write_text(original)
                if result[name] != "ok":
                    raise AuthenticationError(f"{circuit}/{lane}: {label} test is not defeated by removing its constraint")
            integrity = subprocess.run(["bash", str(root / "scripts/check-poseidon-source-integrity.sh")],
                                       capture_output=True, text=True, check=False, timeout=30)
            if integrity.returncode:
                raise AuthenticationError(f"Poseidon verify-after-fetch failed: {integrity.stderr[-2000:]}")
            receipts.append({"circuit": circuit, "lane": lane, "honest_test": positive,
                             "negative_tests": dict(zip(evidence.tests, negatives)),
                             "main_execution": True, "constraint_removal": True})
    return receipts

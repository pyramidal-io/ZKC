#!/usr/bin/env python3
"""ZKC issuer-adapter conformance runner.

Runs the machine-readable contract cases in conformance/issuer_adapter/kit.py
against an issuer adapter factory and reports deterministic per-case
PASS/FAIL plus a summary. Exit code 0 only when every case passes.

Usage:
    python3 conformance/run_issuer_adapter.py                       # reference (sandbox)
    python3 conformance/run_issuer_adapter.py --adapter zkc_issuer:reference_external_adapter
    python3 conformance/run_issuer_adapter.py --adapter issuer_adapter.seeded_bad_adapter:make_adapter
    python3 conformance/run_issuer_adapter.py --json

The --adapter argument is ``module:factory`` where ``factory`` is a
zero-argument callable returning a FRESH IssuerAdapter per invocation.

Standard library only.
"""

from __future__ import annotations

import argparse
import importlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
for path in (str(ROOT / "conformance"), str(ROOT / "python"), str(ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from issuer_adapter.kit import run_conformance  # noqa: E402


def _reference_factory():
    from zkc_issuer import SandboxIssuerAdapter

    # Clock pinned inside the sandbox signing-key validity window.
    return SandboxIssuerAdapter(clock=lambda: 1_770_000_000)


def _load_factory(spec: str):
    module_name, _, attribute = spec.partition(":")
    if not attribute:
        raise SystemExit(f"--adapter must be module:factory, got {spec!r}")
    module = importlib.import_module(module_name)
    factory = getattr(module, attribute)
    if not callable(factory):
        raise SystemExit(f"{spec!r} is not callable")
    return factory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--adapter",
        default=None,
        help="module:factory returning a fresh IssuerAdapter (default: bundled sandbox)",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable report on stdout")
    arguments = parser.parse_args()

    factory = _load_factory(arguments.adapter) if arguments.adapter else _reference_factory
    report = run_conformance(factory)

    if arguments.json:
        print(json.dumps(report, indent=2))
    else:
        for result in report["results"]:
            line = f"[{result['status']}] {result['id']}"
            if result["status"] == "FAIL":
                line += f" — {result['reason']}"
            print(line)
        print()
        print(f"{report['passed']}/{report['total']} cases passed")
    return 0 if report["allPassed"] else 1


if __name__ == "__main__":
    sys.exit(main())

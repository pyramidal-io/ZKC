#!/usr/bin/env python3
"""ZKC presentation-profile conformance runner (design §8 matrix).

Runs the eleven ``presentation-*`` vectors declared in
``conformance/vectors/zkc_presentation.json`` through the REAL reference
holder→verifier pipeline (see ``conformance/presentation_vectors.py``) and
reports deterministic per-vector PASS/FAIL plus a summary. Exit code 0 only
when every vector passes.

Unlike ``run_zkc_core.py`` (whose JSON cases carry a single ``expect`` shape),
the presentation vectors assert cross-envelope properties — equality joins,
public-input-set diffs, and structured verifier error codes — so the assertion
logic lives in Python next to the pipeline, and this runner is a thin driver.

Usage:
    python3 conformance/run_presentation.py
    python3 conformance/run_presentation.py --json
    python3 conformance/run_presentation.py --vector presentation-scoped-cross-scope

Standard library only.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
for path in (str(ROOT / "conformance"), str(ROOT / "python"), str(ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

import presentation_vectors  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--vector", default=None, help="run a single vector id")
    args = parser.parse_args()

    results = presentation_vectors.run_all()
    if args.vector is not None:
        results = [r for r in results if r["id"] == args.vector]
        if not results:
            print(f"no vector with id {args.vector}", file=sys.stderr)
            return 2

    failed = [r for r in results if r["status"] == "FAIL"]
    if args.json:
        print(json.dumps({
            "profile": "presentation",
            "total": len(results),
            "passed": len(results) - len(failed),
            "failed": len(failed),
            "results": results,
        }, indent=2))
    else:
        for r in results:
            line = f"[{r['status']}] {r['id']}"
            if r["status"] == "FAIL":
                line += f" — {r['reason']}"
            print(line)
        print(f"\n{len(results) - len(failed)}/{len(results)} presentation vectors passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

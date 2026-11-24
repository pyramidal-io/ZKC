#!/usr/bin/env python3
"""Run authenticated-revocation launch conformance."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
for path in (str(ROOT / "conformance"), str(ROOT / "python"), str(ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from revocation_vectors import run_conformance  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = run_conformance()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for result in report["results"]:
            suffix = "" if result["status"] == "PASS" else f": {result['error']}"
            print(f"[{result['status']}] {result['id']}{suffix}")
        print(
            f"\n{report['passed']}/{len(report['results'])} cases passed "
            "(profile: revocation-launch)"
        )
    return 0 if report["allPassed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

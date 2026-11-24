"""Toolchain guard for live tests using committed historical artifacts."""

import shutil
import subprocess

from _path import REPO_ROOT


def historical_toolchain_available() -> bool:
    """Require the published historical lane, not merely ambient binaries."""
    if not all(shutil.which(tool) for tool in ("nargo", "bb")):
        return False
    pins = dict(
        line.split("=", 1)
        for line in (REPO_ROOT / ".noir-version").read_text().splitlines()
        if line.startswith(("HISTORICAL_NARGO_VERSION=", "HISTORICAL_BB_VERSION="))
    )
    try:
        nargo = subprocess.run(
            ["nargo", "--version"], check=True, capture_output=True,
            text=True, timeout=10,
        ).stdout.splitlines()[0]
        bb = subprocess.run(
            ["bb", "--version"], check=True, capture_output=True,
            text=True, timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError, IndexError):
        return False
    return (
        nargo == "nargo version = " + pins["HISTORICAL_NARGO_VERSION"]
        and bb == pins["HISTORICAL_BB_VERSION"]
    )

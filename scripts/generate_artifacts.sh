#!/usr/bin/env bash
# Generate reproducible ZKC circuit artifacts, verification keys, and the
# artifact manifest (artifacts/build/manifest.json).
#
# Requires both toolchains pinned in .noir-version. Explicit paths prevent an
# ambient PATH change from substituting one toolchain for the other.
#
# Usage: scripts/generate_artifacts.sh [--require-encoders]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for variable in \
    ZKC_HISTORICAL_NARGO ZKC_HISTORICAL_BB \
    ZKC_SUCCESSOR_NARGO ZKC_SUCCESSOR_BB; do
    if [ -z "${!variable:-}" ]; then
        echo "error: ${variable} must name the explicitly installed pinned binary" >&2
        exit 1
    fi
done

HISTORICAL_NARGO="$ZKC_HISTORICAL_NARGO"
HISTORICAL_BB="$ZKC_HISTORICAL_BB"
SUCCESSOR_NARGO="$ZKC_SUCCESSOR_NARGO"
SUCCESSOR_BB="$ZKC_SUCCESSOR_BB"
CACHE_ROOT="${ZKC_TOOLCHAIN_CACHE_ROOT:-${ROOT}/artifacts/build-cache}"
OUTPUT_ROOT="${ZKC_TOOLCHAIN_OUTPUT_ROOT:-${ROOT}/artifacts/build-output}"

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is not on PATH" >&2
    exit 1
fi

echo "==> building artifact manifest"
python3 "$ROOT/scripts/build_artifact_manifest.py" \
    --nargo "historical=${HISTORICAL_NARGO}" \
    --bb "historical=${HISTORICAL_BB}" \
    --nargo "successor=${SUCCESSOR_NARGO}" \
    --bb "successor=${SUCCESSOR_BB}" \
    --cache-root "$CACHE_ROOT" \
    --output-root "$OUTPUT_ROOT" \
    "$@"

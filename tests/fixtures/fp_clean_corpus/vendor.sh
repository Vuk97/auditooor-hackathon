#!/usr/bin/env bash
# Re-vendor the known-clean FP calibration corpus from pinned release tags.
# Verifies SHA-256 prefixes against MANIFEST.json after fetching.
#
# Usage: bash tests/fixtures/fp_clean_corpus/vendor.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

fetch() {
  local url="$1" dest="$2"
  mkdir -p "$(dirname "$dest")"
  curl -sfL --max-time 30 "$url" -o "$dest"
  echo "fetched $dest"
}

OZ="https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v5.1.0/contracts"
SOLADY="https://raw.githubusercontent.com/Vectorized/solady/v0.0.245/src"
SOLMATE="https://raw.githubusercontent.com/transmissions11/solmate/v6/src"

fetch "$OZ/utils/Address.sol"                       openzeppelin/v5.1.0/Address.sol
fetch "$OZ/utils/math/SafeCast.sol"                 openzeppelin/v5.1.0/SafeCast.sol
fetch "$OZ/utils/structs/EnumerableSet.sol"         openzeppelin/v5.1.0/EnumerableSet.sol
fetch "$OZ/token/ERC20/ERC20.sol"                   openzeppelin/v5.1.0/ERC20.sol
fetch "$OZ/token/ERC721/ERC721.sol"                 openzeppelin/v5.1.0/ERC721.sol
fetch "$OZ/access/Ownable.sol"                      openzeppelin/v5.1.0/Ownable.sol
fetch "$OZ/utils/Pausable.sol"                      openzeppelin/v5.1.0/Pausable.sol
fetch "$SOLADY/utils/SafeTransferLib.sol"           solady/v0.0.245/SafeTransferLib.sol
fetch "$SOLADY/utils/FixedPointMathLib.sol"         solady/v0.0.245/FixedPointMathLib.sol
fetch "$SOLMATE/utils/SafeTransferLib.sol"          solmate/v6/SafeTransferLib.sol
fetch "$SOLMATE/utils/FixedPointMathLib.sol"        solmate/v6/FixedPointMathLib.sol

echo "verifying SHA-256 prefixes against MANIFEST.json"
python3 - <<'PY'
import json, hashlib, sys, pathlib
m = json.load(open("MANIFEST.json"))
bad = 0
for lib in m["libraries"]:
    for f in lib["files"]:
        p = pathlib.Path(f["path"])
        got = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
        want = f["sha256_16"]
        status = "ok" if got == want else "MISMATCH"
        if got != want:
            bad += 1
        print("  %-8s %s (%s)" % (status, f["path"], got))
sys.exit(1 if bad else 0)
PY
echo "vendor.sh complete"

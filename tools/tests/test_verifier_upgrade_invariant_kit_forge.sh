#!/usr/bin/env bash
# Smoke test: the verifier-upgrade-invariant fixture kit must compile under forge.
# Skipped silently if forge or forge-std is not available locally.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
KIT="${ROOT}/reference/harness-fixture-kits/verifier-upgrade-invariant"

if ! command -v forge >/dev/null 2>&1; then
  echo "[op1-kit-forge] SKIP: forge not installed" >&2
  exit 0
fi

# Locate any forge-std on disk; fall back to the kit's expected location.
FORGE_STD=""
for cand in \
  "${HOME}/audits/polymarket/lib/forge-std" \
  "${HOME}/audits/monetrix/lib/forge-std" \
  "${HOME}/.calibration-workspaces/openzeppelin-contracts/lib/forge-std"; do
  if [ -d "${cand}" ]; then
    FORGE_STD="${cand}"
    break
  fi
done

if [ -z "${FORGE_STD}" ]; then
  echo "[op1-kit-forge] SKIP: forge-std not available" >&2
  exit 0
fi

SCRATCH="$(mktemp -d -t op1_kit_forge_XXXXXX)"
trap 'rm -rf "${SCRATCH}"' EXIT

mkdir -p "${SCRATCH}/src" "${SCRATCH}/test" "${SCRATCH}/lib"
cp "${KIT}/src/MockUpgradeableVerifier.sol" "${SCRATCH}/src/"
cp "${KIT}/src/Invariant_VerifierUpgrade.t.sol" "${SCRATCH}/test/"
ln -sf "${FORGE_STD}" "${SCRATCH}/lib/forge-std"

# Test file imports the mock from the same directory in the kit; rewrite to
# the standard src path inside the smoke project.
sed -i.bak 's|"./MockUpgradeableVerifier.sol"|"../src/MockUpgradeableVerifier.sol"|' \
  "${SCRATCH}/test/Invariant_VerifierUpgrade.t.sol"
rm -f "${SCRATCH}/test/Invariant_VerifierUpgrade.t.sol.bak"

cat > "${SCRATCH}/foundry.toml" <<EOF
[profile.default]
src = "src"
test = "test"
out = "out"
libs = ["lib"]
solc_version = "0.8.20"
EOF

cd "${SCRATCH}"
forge build >/dev/null
echo "[op1-kit-forge] OK"

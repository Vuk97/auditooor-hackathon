#!/usr/bin/env bash
# correlator-validate.sh — batch validation for exploit-chain correlator.
#
# Runs the keyword correlator against a fixed set of known exploits and
# checks whether each URL's expected detector classes appear in top-15.
# Prints PASS / PARTIAL / FAIL per case and a summary at the end.
# Exit non-zero only if any case is FAIL (PARTIAL is acceptable).

set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
CORR="python3 ${REPO}/tools/exploit-chain-correlator.py"
TOP=15

# Format: URL|||class1,class2,...|||label
CASES=(
  "https://gist.github.com/banteg/705d0284513b74ad20f61d90f5b5de62|||cross-chain-destination-accepts-out-of-sequence-inbound-nonce,lz-oft-single-dvn-configuration-quorum-bypass,bridge-destination-adapter-ignores-source-pause-state|||Kelp rsETH"
  "https://solodit.cyfrin.io/issues/price-can-be-manipulated-via-flashloans-zokyo-none-radiant-capital-markdown|||single-dex-spot-reserves-flashloan-manipulable-oracle|||Radiant"
  "https://solodit.cyfrin.io/issues/h-10-wrong-parameter-in-remote-transfer-makes-it-possible-to-steal-all-usdo-balance-from-users-sherlock-tapioca-git|||layerzero-remote-transfer-caller-supplied-from-unauth-pull|||Tapioca USDO"
  "https://solodit.cyfrin.io/issues/h-1-h-01-wsteth-eth-curve-lp-token-price-can-be-manipulated-to-cause-unexpected-liquidations-sherlock-sentiment-sentiment-update-2-git|||curve-lp-virtual-price-read-only-reentrancy-oracle|||Sentiment wstETH"
)

total=0; pass=0; partial=0; fail=0
declare -a RESULTS

for entry in "${CASES[@]}"; do
  url="${entry%%|||*}"; rest="${entry#*|||}"
  classes_csv="${rest%%|||*}"; label="${rest##*|||}"
  total=$((total+1))
  echo "---"
  echo "[${label}] ${url}"
  out="$($CORR "$url" --top "$TOP" 2>&1)" || true
  IFS=',' read -r -a classes <<< "$classes_csv"
  found=0; missing=()
  for c in "${classes[@]}"; do
    if printf '%s' "$out" | grep -qE "  ${c}($|[^a-z0-9-])"; then
      found=$((found+1))
    else
      missing+=("$c")
    fi
  done
  n=${#classes[@]}
  if [ "$found" -eq "$n" ]; then
    echo "  PASS ($found/$n)"
    pass=$((pass+1)); RESULTS+=("PASS    ${label} (${found}/${n})")
  elif [ "$found" -gt 0 ]; then
    echo "  PARTIAL: ${found} of ${n} found; missing: ${missing[*]}"
    partial=$((partial+1)); RESULTS+=("PARTIAL ${label} (${found}/${n}) missing: ${missing[*]}")
  else
    echo "  FAIL: 0 of ${n} found; missing: ${missing[*]}"
    fail=$((fail+1)); RESULTS+=("FAIL    ${label} (0/${n}) missing: ${missing[*]}")
  fi
done

echo
echo "======================================================================"
echo "Summary: total=${total} pass=${pass} partial=${partial} fail=${fail}"
echo "======================================================================"
for r in "${RESULTS[@]}"; do echo "  $r"; done

[ "$fail" -eq 0 ]

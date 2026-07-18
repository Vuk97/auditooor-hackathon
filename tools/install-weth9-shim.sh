#!/usr/bin/env bash
# install-weth9-shim.sh — when a workspace's contracts import canonical-weth
# (WETH9), the upstream repo pins `pragma solidity >=0.4.22 <0.6` which
# modern foundry cannot resolve (no pre-0.6 solc ships on recent toolchains).
# Ships a vetted 0.8 compat shim at the expected path so `forge build`
# proceeds. The shim is compile-only — production contracts link to real
# WETH9 on mainnet.
#
# Usage:
#   ./tools/install-weth9-shim.sh <workspace-root>
#   ./tools/install-weth9-shim.sh <workspace-root> --check
#
# Closes SKILL_ISSUES #168 (R67 Snowbridge engagement lesson).

set -uo pipefail

WS="${1:-}"
MODE="${2:-install}"

if [ -z "$WS" ] || [ "$WS" = "-h" ] || [ "$WS" = "--help" ]; then
    cat >&2 <<EOF
Usage: $0 <workspace-root> [--check]

Installs a 0.8-compatible WETH9 compile shim at every
\$WS/**/lib/canonical-weth/contracts/WETH9.sol that currently holds the
pinned pre-0.6 original. Prevents modern-solc forge/slither scans from
aborting on 'No solc version exists that matches'.

The shim preserves the external ABI (deposit/withdraw/transfer/balanceOf/
approve/allowance) but targets solc 0.8.x. A clear header comment marks
it as audit-only — must not be deployed.

--check: reports which canonical-weth copies are still on the old pragma
         and would be patched, without writing anything.
EOF
    exit 1
fi

if [ ! -d "$WS" ]; then
    echo "[err] workspace not found: $WS" >&2
    exit 1
fi

# Find every canonical-weth/contracts/WETH9.sol under $WS.
CANDIDATES=()
while IFS= read -r f; do
    [ -z "$f" ] && continue
    CANDIDATES+=("$f")
done < <(find "$WS" -path "*/lib/canonical-weth/contracts/WETH9.sol" 2>/dev/null)

if [ "${#CANDIDATES[@]}" -eq 0 ]; then
    echo "[info] no canonical-weth/contracts/WETH9.sol found under $WS — nothing to do"
    exit 0
fi

echo "[info] found ${#CANDIDATES[@]} canonical-weth copy/copies:"
printf '       %s\n' "${CANDIDATES[@]}"
echo ""

need_patch=()
for f in "${CANDIDATES[@]}"; do
    # If the header comment already matches our shim, skip.
    if grep -q "0.8.x compatibility shim for the WETH9 interface" "$f" 2>/dev/null; then
        echo "[ok] $f — already shimmed"
        continue
    fi
    # If the pragma is already 0.8.x-compatible (repo updated upstream), skip.
    if grep -qE 'pragma solidity (>=0\.8|\^0\.8|0\.8)' "$f" 2>/dev/null; then
        echo "[ok] $f — pragma already 0.8.x"
        continue
    fi
    need_patch+=("$f")
done

if [ "${#need_patch[@]}" -eq 0 ]; then
    echo "[ok] all canonical-weth copies are already compatible"
    exit 0
fi

if [ "$MODE" = "--check" ]; then
    echo "[check] would patch ${#need_patch[@]} file(s):"
    printf '         %s\n' "${need_patch[@]}"
    exit 0
fi

# Write the shim in place of each pre-0.6 pinned WETH9.
for f in "${need_patch[@]}"; do
    BAK="${f}.auditooor.pre-shim.bak"
    cp "$f" "$BAK"
    cat > "$f" <<'SHIM'
// SPDX-License-Identifier: GPL-3.0
// 0.8.x compatibility shim for the WETH9 interface — the canonical WETH9.sol
// pins to solc <0.6, which modern foundry cannot install. This stub exposes
// the same external surface the contracts import. Installed by
// tools/install-weth9-shim.sh (auditooor R67b). Audit / PoC use only —
// must not be deployed; production contracts link to real WETH9 on mainnet.
pragma solidity >=0.8.0;

contract WETH9 {
    string public name     = "Wrapped Ether";
    string public symbol   = "WETH";
    uint8  public decimals = 18;

    event Approval(address indexed src, address indexed guy, uint256 wad);
    event Transfer(address indexed src, address indexed dst, uint256 wad);
    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    receive() external payable { deposit(); }

    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 wad) public {
        require(balanceOf[msg.sender] >= wad, "WETH9: insufficient");
        balanceOf[msg.sender] -= wad;
        (bool ok,) = msg.sender.call{value: wad}("");
        require(ok, "WETH9: withdraw failed");
        emit Withdrawal(msg.sender, wad);
    }

    function totalSupply() public view returns (uint256) {
        return address(this).balance;
    }

    function approve(address guy, uint256 wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    function transfer(address dst, uint256 wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint256 wad) public returns (bool) {
        require(balanceOf[src] >= wad, "WETH9: insufficient");
        if (src != msg.sender && allowance[src][msg.sender] != type(uint256).max) {
            require(allowance[src][msg.sender] >= wad, "WETH9: allowance");
            allowance[src][msg.sender] -= wad;
        }
        balanceOf[src] -= wad;
        balanceOf[dst] += wad;
        emit Transfer(src, dst, wad);
        return true;
    }
}
SHIM
    echo "[patched] $f (backup at $BAK)"
done

echo ""
echo "[ok] installed WETH9 shim in ${#need_patch[@]} location(s)"
echo "     Run 'forge build' / 'slither src/' now — they should compile."

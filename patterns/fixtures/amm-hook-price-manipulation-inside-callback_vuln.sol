// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal v4-style interfaces — enough for the hook body to type-check.
struct PoolKey {
    address currency0;
    address currency1;
    uint24 fee;
    int24 tickSpacing;
    address hooks;
}

struct BalanceDelta {
    int128 amount0;
    int128 amount1;
}

struct Slot0 {
    uint160 sqrtPriceX96;
    int24 tick;
}

interface IPoolManager {
    function getSlot0(PoolKey calldata key) external view returns (Slot0 memory);
    function getLiquidity(PoolKey calldata key) external view returns (uint128);
}

// VULN: dynamic-fee hook reads live slot0/liquidity from the PoolManager
// inside beforeSwap() and uses the reading to decide the fee tier. An
// attacker opening a JIT position that warps slot0 for exactly this
// block sees their own swap priced off the warped reading, then
// withdraws the JIT position — extracting fee-tier value from LPs.
contract AmmHookVuln {
    IPoolManager public immutable poolManager;

    uint160 public referenceSqrtPriceX96;
    uint24 public lowFee = 500;
    uint24 public highFee = 10000;

    constructor(address _pm, uint160 _ref) {
        poolManager = IPoolManager(_pm);
        referenceSqrtPriceX96 = _ref;
    }

    // BUG: reads live pool state inside the hook callback to derive the
    // fee tier. `slot0` at this point is the mid-swap state, which an
    // attacker can pre-warp. No snapshot / cachedSlot0 / preHookState
    // indicator — the detector fires on the absence of the guard.
    function beforeSwap(
        address /* sender */,
        PoolKey calldata key,
        bytes calldata /* params */,
        bytes calldata /* hookData */
    ) external view returns (bytes4, BalanceDelta memory, uint24) {
        Slot0 memory s = poolManager.getSlot0(key);
        uint128 liq = poolManager.getLiquidity(key);

        uint160 live = s.sqrtPriceX96;
        uint160 ref = referenceSqrtPriceX96;
        uint256 delta = live > ref ? uint256(live - ref) : uint256(ref - live);

        // Charge the low fee if price looks stable. Attacker warps slot0
        // so `live ~= ref` exactly when they swap, paying the low fee.
        uint24 fee = delta * 10000 < uint256(ref) * 5 ? lowFee : highFee;
        if (liq == 0) fee = highFee;

        BalanceDelta memory d;
        return (bytes4(0), d, fee);
    }
}

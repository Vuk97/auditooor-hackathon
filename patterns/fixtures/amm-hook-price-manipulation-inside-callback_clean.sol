// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

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

// CLEAN: the hook refuses to read live pool state inside beforeSwap. The
// fee tier is derived from a pre-hook snapshot (`cachedSlot0`) written
// by a trusted choke-point (`sync()`, owner-gated). The attacker cannot
// warp the cached value during their own swap.
contract AmmHookClean {
    IPoolManager public immutable poolManager;
    address public owner;

    // Pre-hook snapshot: updated OUTSIDE of a swap, cannot be manipulated
    // mid-swap. The hook reads this storage value, not live slot0.
    uint160 public cachedSlot0;
    uint256 public cachedAt;

    uint160 public referenceSqrtPriceX96;
    uint24 public lowFee = 500;
    uint24 public highFee = 10000;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _pm, uint160 _ref) {
        owner = msg.sender;
        poolManager = IPoolManager(_pm);
        referenceSqrtPriceX96 = _ref;
    }

    // Owner-gated snapshot update. Runs OUTSIDE any swap, so slot0 is a
    // clean pre-action reading. This is the trust choke-point.
    function snapshot(PoolKey calldata key) external onlyOwner {
        Slot0 memory s = poolManager.getSlot0(key);
        cachedSlot0 = s.sqrtPriceX96;
        cachedAt = block.number;
    }

    // FIX: read the cached snapshot, not live pool state. Attacker-warped
    // mid-swap slot0 is ignored entirely.
    function beforeSwap(
        address /* sender */,
        PoolKey calldata /* key */,
        bytes calldata /* params */,
        bytes calldata /* hookData */
    ) external view returns (bytes4, BalanceDelta memory, uint24) {
        uint160 cached = cachedSlot0;
        uint160 ref = referenceSqrtPriceX96;
        uint256 delta = cached > ref ? uint256(cached - ref) : uint256(ref - cached);

        uint24 fee = delta * 10000 < uint256(ref) * 5 ? lowFee : highFee;

        BalanceDelta memory d;
        return (bytes4(0), d, fee);
    }
}

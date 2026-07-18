// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: zero-liquidity short-circuit on every entry point that
// performs arithmetic or indexing on tierLiquidity.
contract PrizeClaimZeroLiquidityDosClean {
    mapping(uint8 => uint256) public tierLiquidity;
    mapping(uint8 => uint256) public prizeCount;
    mapping(address => mapping(uint8 => bool)) public claimed;
    uint256 public jackpot;

    // CLEAN: short-circuit when tier is drained.
    function claimPrize(uint8 tier) external returns (uint256 payout) {
        require(!claimed[msg.sender][tier], "already claimed");
        if (tierLiquidity[tier] == 0) return 0;
        claimed[msg.sender][tier] = true;
        uint256 count = prizeCount[tier];
        payout = tierLiquidity[tier] / count;
        tierLiquidity[tier] -= payout;
    }

    // CLEAN: skip drained tiers in batch claims.
    function claimReward(uint8[] calldata tiers) external returns (uint256 total) {
        for (uint256 i; i < tiers.length; ++i) {
            uint8 t = tiers[i];
            if (tierLiquidity[t] == 0) continue;
            uint256 share = tierLiquidity[t] * 10_000 / prizeCount[t];
            total += share;
            tierLiquidity[t] -= share;
        }
    }
}

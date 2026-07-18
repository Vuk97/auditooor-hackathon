// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal PrizePool contract that reads tier liquidity in the claim path
// without a zero-liquidity short-circuit. When the last tier drains, the
// division panics and all subsequent winners are DoS'd.
contract PrizeClaimZeroLiquidityDosVuln {
    mapping(uint8 => uint256) public tierLiquidity;
    mapping(uint8 => uint256) public prizeCount;
    mapping(address => mapping(uint8 => bool)) public claimed;
    uint256 public jackpot;

    // VULN: divides by tierLiquidity without checking it's non-zero.
    function claimPrize(uint8 tier) external returns (uint256 payout) {
        require(!claimed[msg.sender][tier], "already claimed");
        claimed[msg.sender][tier] = true;
        uint256 count = prizeCount[tier];
        payout = tierLiquidity[tier] / count;            // DoS when liquidity is 0
        tierLiquidity[tier] -= payout;                   // can underflow
    }

    // VULN: batch claim. Indexes liquidity[tier] without zero-short-circuit,
    // so one drained tier DoS's the whole batch.
    function claimReward(uint8[] calldata tiers) external returns (uint256 total) {
        for (uint256 i; i < tiers.length; ++i) {
            uint8 t = tiers[i];
            uint256 share = tierLiquidity[t] * 10_000 / prizeCount[t];
            total += share;
            tierLiquidity[t] -= share;
        }
    }
}

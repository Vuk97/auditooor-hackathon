// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: every exit path either ceil-rounds the share→asset
// conversion OR explicitly reverts when assets would round to zero.
// Either guard closes the dust-redeem wealth transfer.
contract VaultDustSharesWithdrawRoundsToZeroClean {
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public shares;

    constructor(uint256 _assets, uint256 _supply) {
        totalAssets = _assets;
        totalSupply = _supply;
    }

    // Ceil-divide helper: `mulDivRoundingUp` style.
    function _mulDivRoundingUp(uint256 a, uint256 b, uint256 d) internal pure returns (uint256) {
        return (a * b + d - 1) / d;
    }

    // CLEAN: require(assets > 0) guard — dust redeem reverts loudly.
    function redeem(uint256 shareAmount) external returns (uint256 assets) {
        assets = (shareAmount * totalAssets) / totalSupply;
        require(assets > 0, "ZeroAssets");
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= assets;
    }

    // CLEAN: ceil-round so the caller always gets at least 1 wei of assets
    // (and the rest of the pool absorbs the tiebreaker cost).
    function withdraw(uint256 shareAmount) external returns (uint256 assets) {
        assets = _mulDivRoundingUp(shareAmount, totalAssets, totalSupply);
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= assets;
    }

    // CLEAN: uses ceilDiv-style function — body regex matches the guard.
    function _withdraw(address user, uint256 shareAmount) external returns (uint256 assets) {
        assets = _mulDivRoundingUp(shareAmount, totalAssets, totalSupply);
        shares[user] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= assets;
    }

    // CLEAN: require(_assets != 0) variant — also a recognized guard.
    function unstake(uint256 shareAmount) external returns (uint256 _assets) {
        _assets = (shareAmount * totalAssets) / totalSupply;
        require(_assets != 0, "ZeroAssets");
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -=_assets;
    }
}

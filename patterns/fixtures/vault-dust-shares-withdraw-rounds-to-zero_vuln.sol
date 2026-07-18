// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Share-based vault. Exit paths convert shares→assets via floor division
// without ceil-rounding or a nonzero-assets guard. A user redeeming a tiny
// number of shares burns them for zero assets.
contract VaultDustSharesWithdrawRoundsToZeroVuln {
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public shares;

    constructor(uint256 _assets, uint256 _supply) {
        totalAssets = _assets;
        totalSupply = _supply;
    }

    // VULN: assets computed as shares * totalAssets / totalSupply with
    // floor division. Dust redeem → assets=0 → share burnt for nothing.
    function redeem(uint256 shareAmount) external returns (uint256 assets) {
        assets = (shareAmount * totalAssets) / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= assets;
        // No require(assets > 0) — dust redeem silently succeeds with 0.
    }

    // VULN: withdraw via the same floor formula, same zero-out risk.
    function withdraw(uint256 shareAmount) external returns (uint256 assets) {
        assets = (shareAmount * totalAssets) / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= assets;
    }

    // VULN: internal helper used by external exits — same bug shape.
    function _withdraw(address user, uint256 shareAmount) external returns (uint256 assets) {
        assets = (shareAmount * totalAssets) / totalSupply;
        shares[user] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= assets;
    }

    // VULN: staking-style exit with identical shape.
    function unstake(uint256 shareAmount) external returns (uint256 assets) {
        assets = (shareAmount * totalAssets) / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= assets;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

/// @notice VULNERABLE FIXTURE — detector MUST fire.
///
/// Vault exposes totalAssets / previewRedeem / previewWithdraw /
/// convertToAssets accessors that read asset balanceOf(address(this))
/// directly as the canonical reserve figure. There is no internal
/// ledger variable defending against donation-attack inflation.
///
/// An attacker direct-transfers the underlying into this contract
/// (bypassing deposit), which inflates the balance reading without
/// updating totalShares or totalSupply, causing subsequent share math
/// to misprice. This is the 0x8d2e family 2025 exploit shape.
contract DonationAttackVaultVuln {
    IERC20 public asset;
    uint256 public totalShares;
    uint256 public totalSupply;
    mapping(address => uint256) public shares;

    constructor(address a) { asset = IERC20(a); }

    // VULN #1: totalAssets sourced from balanceOf(self).
    function totalAssets() external view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    // VULN #2: previewRedeem divides by a balanceOf-sourced figure.
    function previewRedeem(uint256 shareAmt) external view returns (uint256) {
        uint256 bal = asset.balanceOf(address(this));
        return shareAmt * bal / totalSupply;
    }

    // VULN #3: previewWithdraw — same issue.
    function previewWithdraw(uint256 assets) external view returns (uint256) {
        uint256 bal = asset.balanceOf(address(this));
        return assets * totalSupply / bal;
    }

    // VULN #4: convertToAssets uses bare balanceOf(address(this)).
    function convertToAssets(uint256 shareAmt) external view returns (uint256) {
        return shareAmt * IERC20(asset).balanceOf(address(this)) / totalSupply;
    }

    // VULN #5: pricePerShare pricing accessor reads balanceOf(self).
    function pricePerShare() external view returns (uint256) {
        return asset.balanceOf(address(this)) * 1e18 / totalSupply;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: ERC4626-style share price computed from raw token balance,
// manipulable by a direct donation to the vault.
contract SharePriceManipulationVulnerable {
    uint256 public totalShares;

    function depositConvert(uint256 assets, address token) external view returns (uint256) {
        uint256 totalAssets = IERC20Bal(token).balanceOf(address(this));
        if (totalShares == 0) return assets;
        return assets * totalShares / totalAssets;
    }
}
interface IERC20Bal { function balanceOf(address) external view returns (uint256); }

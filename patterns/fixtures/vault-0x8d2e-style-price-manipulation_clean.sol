// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
///
/// The vault maintains an internal `trackedAssets` ledger that is the
/// source of truth for share math. balanceOf(address(this)) is never
/// consulted in the pricing accessors, so direct-transfer donations
/// cannot influence share price. The negative-regex guard matches
/// `trackedAssets` and suppresses the detector.
///
/// A `sync` function is provided for defense-in-depth: any excess
/// balanceOf over trackedAssets is swept to the protocol treasury
/// rather than being credited to shareholders.
contract DonationDefendedVaultClean {
    IERC20 public asset;
    uint256 public totalShares;
    uint256 public totalSupply;
    uint256 public trackedAssets; // canonical reserve figure
    address public treasury;
    mapping(address => uint256) public shares;

    constructor(address a, address t) { asset = IERC20(a); treasury = t; }

    // Clean: trackedAssets, not balanceOf(self).
    function totalAssets() external view returns (uint256) {
        return trackedAssets;
    }

    // Clean: previewRedeem priced against the tracked ledger.
    function previewRedeem(uint256 shareAmt) external view returns (uint256) {
        return shareAmt * trackedAssets / totalSupply;
    }

    function previewWithdraw(uint256 assets) external view returns (uint256) {
        return assets * totalSupply / trackedAssets;
    }

    function convertToAssets(uint256 shareAmt) external view returns (uint256) {
        return shareAmt * trackedAssets / totalSupply;
    }

    function pricePerShare() external view returns (uint256) {
        return trackedAssets * 1e18 / totalSupply;
    }

    // Defense-in-depth: reconcile donated balance to treasury, not to
    // shareholders. Keeps trackedAssets canonical.
    function sync() external {
        uint256 bal = asset.balanceOf(address(this));
        if (bal > trackedAssets) {
            uint256 delta = bal - trackedAssets;
            asset.transfer(treasury, delta);
        }
    }
}

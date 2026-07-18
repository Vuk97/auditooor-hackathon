// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice Minimal ERC4626-style vault used as the EVM 0-day proof-pipeline
/// VULNERABLE fixture. This is the real target under test: the harness drives
/// the unmodified deposit()/redeem() entrypoints below, snapshots victim share
/// balances before and after, and asserts a real impact (a non-trivial
/// depositor must not be griefed to zero shares).
///
/// Bug class: first-depositor / share-price inflation (donation) attack.
/// Root cause: convertToShares uses the live underlying balance of the vault
/// (balanceOf(this)) as the denominator, so an attacker who mints 1 wei of
/// shares then *donates* assets directly to the vault inflates the share price.
/// A subsequent victim deposit that is smaller than the inflated price rounds
/// down to ZERO shares while the assets stay in the pool, redeemable by the
/// attacker's single share.
///
/// No mitigation is present: no virtual shares/assets offset, no dead-shares
/// seed, no minimum first deposit. The omission is the vulnerability.
contract MiniVault {
    IERC20 public immutable asset;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    constructor(address _asset) {
        asset = IERC20(_asset);
    }

    /// @dev DENOMINATOR uses the live vault balance -> inflatable by donation.
    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalShares;
        if (supply == 0) {
            return assets;
        }
        uint256 totalAssets = asset.balanceOf(address(this));
        // rounds DOWN; victim shares -> 0 when price is inflated.
        return (assets * supply) / totalAssets;
    }

    function convertToAssets(uint256 shareAmount) public view returns (uint256) {
        uint256 supply = totalShares;
        if (supply == 0) {
            return shareAmount;
        }
        uint256 totalAssets = asset.balanceOf(address(this));
        return (shareAmount * totalAssets) / supply;
    }

    /// @notice REAL entrypoint the harness calls. Pulls `assets` from caller,
    /// credits `convertToShares(assets)` shares.
    function deposit(uint256 assets, address receiver) external returns (uint256 mintedShares) {
        mintedShares = convertToShares(assets);
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer fail");
        totalShares += mintedShares;
        shares[receiver] += mintedShares;
    }

    /// @notice REAL entrypoint the harness calls.
    function redeem(uint256 shareAmount, address receiver) external returns (uint256 assetsOut) {
        assetsOut = convertToAssets(shareAmount);
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        require(asset.transfer(receiver, assetsOut), "transfer fail");
    }
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

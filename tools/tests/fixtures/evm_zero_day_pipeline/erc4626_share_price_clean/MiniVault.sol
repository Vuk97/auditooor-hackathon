// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice Minimal ERC4626-style vault used as the EVM 0-day proof-pipeline
/// CLEAN negative-control fixture. Identical surface to the vulnerable sibling
/// (../erc4626_share_price_vuln/MiniVault.sol) EXCEPT the share-price math
/// applies a virtual-shares / virtual-assets offset (the OpenZeppelin ERC4626
/// "decimals offset" mitigation). This makes a first-depositor donation attack
/// economically inert: a 50 ether victim deposit still mints non-zero shares.
///
/// This is the expected-PASS variant. The proof pipeline runs the identical
/// PoC assertion against this contract; it must NOT revert. A negative control
/// that also reverted would mean the test asserts a tautology, not the bug.
contract MiniVault {
    IERC20 public immutable asset;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    /// @dev virtual offset: 1e3 virtual shares + 1 virtual asset baked into the
    /// price denominator so an attacker cannot inflate it via donation.
    uint256 private constant VIRTUAL_SHARES = 1e3;
    uint256 private constant VIRTUAL_ASSETS = 1;

    constructor(address _asset) {
        asset = IERC20(_asset);
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalShares + VIRTUAL_SHARES;
        uint256 totalAssets = asset.balanceOf(address(this)) + VIRTUAL_ASSETS;
        return (assets * supply) / totalAssets;
    }

    function convertToAssets(uint256 shareAmount) public view returns (uint256) {
        uint256 supply = totalShares + VIRTUAL_SHARES;
        uint256 totalAssets = asset.balanceOf(address(this)) + VIRTUAL_ASSETS;
        return (shareAmount * totalAssets) / supply;
    }

    /// @notice REAL entrypoint the harness calls (identical signature to vuln).
    function deposit(uint256 assets, address receiver) external returns (uint256 mintedShares) {
        mintedShares = convertToShares(assets);
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer fail");
        totalShares += mintedShares;
        shares[receiver] += mintedShares;
    }

    /// @notice REAL entrypoint the harness calls (identical signature to vuln).
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

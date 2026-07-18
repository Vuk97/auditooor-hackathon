// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}

// Minimal ERC4626 marker — real deployments inherit a full ERC4626 base.
abstract contract ERC4626 {
    function totalAssets() public view virtual returns (uint256);
    function previewDeposit(uint256 assets) public view virtual returns (uint256);
    function _mintShares(address receiver, uint256 shares) internal virtual;
}

// VULN: deposit() computes shares via previewDeposit but does not revert
// when the rounded result is zero. The asset pull still executes; the
// depositor receives zero shares and their underlying becomes an
// accounting donation to every other holder.
contract VaultVuln is ERC4626 {
    IERC20 public immutable asset;
    uint256 private _totalAssets;

    constructor(IERC20 a) { asset = a; }

    function totalAssets() public view override returns (uint256) { return _totalAssets; }
    function previewDeposit(uint256 assets) public view override returns (uint256) {
        // canonical vulnerable ratio — assets * totalSupply / totalAssets
        // (totalSupply omitted for brevity; the shape is what matters)
        return assets / (_totalAssets == 0 ? 1 : _totalAssets);
    }
    function _mintShares(address, uint256) internal override {}

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = previewDeposit(assets);
        // NO `require(shares > 0)` — zero shares silently accepted.
        asset.transferFrom(msg.sender, address(this), assets);
        _totalAssets += assets;
        _mintShares(receiver, shares);
    }
}

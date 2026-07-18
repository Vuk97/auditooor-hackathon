// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}

abstract contract ERC4626 {
    function totalAssets() public view virtual returns (uint256);
    function previewDeposit(uint256 assets) public view virtual returns (uint256);
    function _mintShares(address receiver, uint256 shares) internal virtual;
}

// CLEAN: identical deposit() as the vuln fixture but with an explicit
// non-zero shares requirement. A zero-rounded share calculation reverts
// instead of silently accepting the donation.
contract VaultClean is ERC4626 {
    IERC20 public immutable asset;
    uint256 private _totalAssets;

    constructor(IERC20 a) { asset = a; }

    function totalAssets() public view override returns (uint256) { return _totalAssets; }
    function previewDeposit(uint256 assets) public view override returns (uint256) {
        return assets / (_totalAssets == 0 ? 1 : _totalAssets);
    }
    function _mintShares(address, uint256) internal override {}

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = previewDeposit(assets);
        require(shares > 0, "ZeroShares");          // <-- the fix
        asset.transferFrom(msg.sender, address(this), assets);
        _totalAssets += assets;
        _mintShares(receiver, shares);
    }
}

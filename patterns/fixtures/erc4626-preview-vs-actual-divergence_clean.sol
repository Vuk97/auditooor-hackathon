// SPDX-License-Identifier: MIT
// Fixture: erc4626-preview-vs-actual-divergence — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

abstract contract ERC4626 {
    function totalAssets() public view virtual returns (uint256);
}

contract VaultClean is ERC4626 {
    IERC20 public asset;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    uint256 public constant ENTRY_FEE_BPS = 30;

    constructor(address a) { asset = IERC20(a); }

    function totalAssets() public view override returns (uint256) {
        return asset.balanceOf(address(this));
    }

    // Preview applies the same fee + ceil-rounding as the live path, so
    // integrators and the live deposit agree.
    function previewDeposit(uint256 assets) public view returns (uint256) {
        uint256 feeAmount = (assets * ENTRY_FEE_BPS) / 10000;
        uint256 assetsAfterFee = assets - feeAmount;
        uint256 supply = totalSupply;
        uint256 ta = totalAssets();
        if (supply == 0 || ta == 0) return assetsAfterFee;
        uint256 num = assetsAfterFee * supply;
        return (num + ta - 1) / ta;
    }

    // CLEAN: deposit() delegates to previewDeposit() — the body mentions
    // `previewDeposit`, so function.body_not_contains_regex trips and the
    // detector does NOT fire.
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = previewDeposit(assets);
        asset.transferFrom(msg.sender, address(this), assets);
        totalSupply += shares;
        balanceOf[receiver] += shares;
    }
}

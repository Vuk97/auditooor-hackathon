// SPDX-License-Identifier: MIT
// Fixture: erc4626-preview-vs-actual-divergence — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

// Minimal ERC4626 marker so contract.inherits_any: [ERC4626] succeeds.
abstract contract ERC4626 {
    function totalAssets() public view virtual returns (uint256);
}

contract VaultVuln is ERC4626 {
    IERC20 public asset;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // 30 bps entry fee applied only in the mutating path.
    uint256 public constant ENTRY_FEE_BPS = 30;

    constructor(address a) { asset = IERC20(a); }

    function totalAssets() public view override returns (uint256) {
        return asset.balanceOf(address(this));
    }

    // Preview does NOT model the fee or the ceilDiv rounding performed in deposit().
    function previewDeposit(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        uint256 ta = totalAssets();
        if (supply == 0 || ta == 0) return assets;
        return (assets * supply) / ta;
    }

    // VULN: applies fee AND ceil-rounding that previewDeposit never simulates.
    // Integrators pricing off previewDeposit() get filled at a worse rate.
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        uint256 feeAmount = (assets * ENTRY_FEE_BPS) / 10000;
        uint256 assetsAfterFee = assets - feeAmount;

        uint256 supply = totalSupply;
        uint256 ta = totalAssets();
        if (supply == 0 || ta == 0) {
            shares = assetsAfterFee;
        } else {
            // ceilDiv rounds up against the depositor.
            uint256 num = assetsAfterFee * supply;
            shares = (num + ta - 1) / ta;
        }

        asset.transferFrom(msg.sender, address(this), assets);
        totalSupply += shares;
        balanceOf[receiver] += shares;
    }
}

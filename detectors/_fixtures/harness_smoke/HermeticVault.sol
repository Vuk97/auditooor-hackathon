// SPDX-License-Identifier: MIT
// HermeticVault — minimal ERC4626-style vault used as the H-04 hermetic smoke
// fixture (PR603 § Gate 2 acceptance #8). NOT production code; NOT Base.
//
// Vulnerability: first-depositor share-inflation attack.
//
//   1) Attacker deposits 1 wei of asset; the vault mints `1` share (totalSupply
//      goes from 0 → 1). The vault now has 1 wei of asset and 1 share.
//   2) Attacker `donates` (transfers in) a large lump of the underlying asset
//      directly to the vault — bypassing the share-mint path. totalAssets
//      jumps to e.g. 1e18 + 1, totalSupply stays at 1 share.
//   3) Victim deposits `assets` expecting to receive
//      `shares = assets * totalSupply / totalAssets`.
//      With the inflated ratio, integer-division truncates `shares` to 0 for
//      any deposit <= totalAssets. Victim receives 0 shares for non-zero asset
//      → the donated lump (now including the victim's deposit) backs the
//      attacker's single share.
//   4) Attacker redeems their 1 share and walks away with totalAssets,
//      including the victim's deposit.
pragma solidity ^0.8.20;

interface IERC20Min {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

contract HermeticVault {
    IERC20Min public immutable asset;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(IERC20Min _asset) {
        asset = _asset;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    // VULNERABLE: raw share computation with no virtual-shares / virtual-assets
    // offset. When totalSupply is small (1) and totalAssets is large (donated),
    // `assets * totalSupply / totalAssets` truncates to 0 — victim gets 0
    // shares for a non-zero asset deposit.
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        if (totalSupply == 0) {
            // VULNERABLE: 1:1 mint on first deposit, no minimum-shares dead-mint.
            shares = assets;
        } else {
            // VULNERABLE: no virtual-offset; integer-division truncation under
            // an inflated price-per-share lets `shares = 0` go through.
            shares = (assets * totalSupply) / totalAssets();
        }
        // VULNERABLE: no `require(shares > 0)` slippage check.
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer failed");
        totalSupply += shares;
        balanceOf[receiver] += shares;
        return shares;
    }

    function redeem(uint256 shares, address receiver) external returns (uint256 assets) {
        require(balanceOf[msg.sender] >= shares, "insufficient shares");
        assets = (shares * totalAssets()) / totalSupply;
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        require(asset.transfer(receiver, assets), "transfer failed");
        return assets;
    }
}

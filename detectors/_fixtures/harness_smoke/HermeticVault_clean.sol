// SPDX-License-Identifier: MIT
// HermeticVault_clean — H-04 hermetic smoke fixture, fixed variant.
//
// FIX strategy: virtual-shares / virtual-assets offset (OpenZeppelin ERC4626
// v4.9+ approach) PLUS a slippage / minimum-shares-out check. Either is
// individually sufficient to neutralise the share-inflation attack; both are
// applied here for defense-in-depth and to make the diff explicit.
pragma solidity ^0.8.20;

// Reuse IERC20Min from HermeticVault.sol so the two files co-compile in
// the same Foundry profile without a duplicate-symbol error.
import {IERC20Min} from "./HermeticVault.sol";

// Renamed to `HermeticVaultClean` so it can co-compile alongside the
// vulnerable variant in the same Foundry profile. The negative-control
// test in `HermeticVault.t.sol` exercises this contract directly to
// confirm the inflation attack is neutralised by the fix.
contract HermeticVaultClean {
    IERC20Min public immutable asset;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // FIX: virtual-offset constants. Make the price-per-share inflation
    // attack arbitrarily expensive: every share donated to the vault
    // requires the attacker to also donate `10**DECIMALS_OFFSET` underlying
    // asset to skew the ratio.
    uint256 internal constant VIRTUAL_SHARES = 1;
    uint256 internal constant VIRTUAL_ASSETS = 1;

    constructor(IERC20Min _asset) {
        asset = _asset;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    // FIX: virtual-offset share computation. `shares = assets *
    // (totalSupply + V_S) / (totalAssets + V_A)`. Even when totalSupply is 1
    // and totalAssets is donated to 1e18, the +1 virtual-share / +1
    // virtual-asset offset prevents the 0-shares truncation and forces the
    // attacker to internalise the bulk of any donation.
    function deposit(uint256 assets, address receiver, uint256 minSharesOut)
        external
        returns (uint256 shares)
    {
        shares = (assets * (totalSupply + VIRTUAL_SHARES))
            / (totalAssets() + VIRTUAL_ASSETS);
        // FIX: slippage check — depositor states a floor; reverts on dust.
        require(shares >= minSharesOut, "slippage: shares < min");
        // FIX: positive-shares invariant (cheap belt-and-braces).
        require(shares > 0, "zero shares");
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer failed");
        totalSupply += shares;
        balanceOf[receiver] += shares;
        return shares;
    }

    function redeem(uint256 shares, address receiver, uint256 minAssetsOut)
        external
        returns (uint256 assets)
    {
        require(balanceOf[msg.sender] >= shares, "insufficient shares");
        assets = (shares * (totalAssets() + VIRTUAL_ASSETS))
            / (totalSupply + VIRTUAL_SHARES);
        // FIX: slippage check on the redeem leg too.
        require(assets >= minAssetsOut, "slippage: assets < min");
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        require(asset.transfer(receiver, assets), "transfer failed");
        return assets;
    }
}

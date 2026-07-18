// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice UNSEEN fixture for the INTERFACE-CAST CTOR ASSET ARG lift (FIX 1,
/// approach (b)). Unlike the sibling `LibVault` whose constructor takes a plain
/// `address` asset, THIS vault's constructor declares the asset arg with the
/// solmate `ERC20` type:
///
///     constructor(ERC20 _asset) ...
///
/// so the converter must synthesize a deploy expression that casts the inline
/// synthesized token to the REAL ctor parameter type (`ERC20(address(token))`)
/// AND make that `ERC20` identifier resolve in the authored harness. Approach
/// (b): the ctor type is a resolvable import (solmate `ERC20`, already vendored
/// for the common-library lift), so the converter co-imports it from the cited
/// file's import graph and the cast type-checks against the vendored lib. Before
/// the FIX the converter emitted a hardcoded `IERC20(address(token))` cast with
/// NO matching import/declaration -> solc Error 7576 Undeclared identifier at
/// `new TypedAssetVault(..., ERC20(address(token)))`.
///
/// Bug shape is the converter's already-routed donation / share-price-inflation
/// (first-depositor) CLASS: `totalAssets()` reads a RAW live token balance as the
/// share-mint denominator, and `deposit()` mints via rounding-DOWN integer
/// division with NO virtual-offset / dead-shares / min-first-deposit guard. A
/// first depositor seeds 1 wei -> 1 share, DONATES assets directly to the vault
/// (raw transfer) to inflate the live denominator, and a later victim deposit
/// rounds DOWN to ZERO shares (its assets stay in the pool, redeemable by the
/// attacker's single pre-inflation share). Target-literal-free: no real-target
/// identity literal anywhere; the identifiers are deliberately generic.

import {ERC20} from "solmate/tokens/ERC20.sol";
import {SafeTransferLib} from "solmate/utils/SafeTransferLib.sol";
import {FixedPointMathLib} from "solmate/utils/FixedPointMathLib.sol";
// bare `openzeppelin-contracts/` prefix (foundry-install default) - the converter
// must remap this to the SAME OZ contracts/ root the vendoring resolves.
import {Address} from "openzeppelin-contracts/utils/Address.sol";

// The vault IS its own ERC20 share token (solmate ERC20 base provides
// `balanceOf` / `_mint` / `totalSupply`).
contract TypedAssetVault is ERC20 {
    using SafeTransferLib for ERC20;
    using FixedPointMathLib for uint256;
    using Address for address;

    // the asset is held as the solmate `ERC20` type (not a bare `address`); this
    // is what makes the ctor arg interface-cast-typed.
    ERC20 public immutable asset;

    constructor(ERC20 _asset)
        ERC20("Typed Yield Share", "tyYLD", 18)
    {
        asset = _asset;
    }

    /// @dev DONATION LEVER: reads the LIVE vault balance, so a raw transfer into
    /// the vault inflates it without minting shares -> share price inflates and a
    /// later victim deposit rounds DOWN to zero. No virtual offset.
    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    /// @dev per-holder share balance accessor (forwards the inherited solmate
    /// ERC20 `balanceOf` so the share balance is observable by name).
    function shares(address holder) public view returns (uint256) {
        return balanceOf[holder];
    }

    /// @dev rounding-DOWN integer division, no virtual offset / dead shares.
    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        return supply == 0 ? assets : (assets * supply) / totalAssets();
    }

    function deposit(uint256 assets, address receiver)
        external
        returns (uint256 shares_)
    {
        shares_ = convertToShares(assets);
        // real solmate SafeTransferLib pull (a COMMON-LIBRARY call site) on the
        // `ERC20`-typed asset handle directly (no extra cast needed).
        asset.safeTransferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares_);
    }
}

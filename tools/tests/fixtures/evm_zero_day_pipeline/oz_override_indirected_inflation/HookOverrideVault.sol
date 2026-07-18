// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ERC4626, IERC20Like} from "./base/ERC4626Base.sol";

/// @notice UNSEEN fixture (codex95 OBL4 blocker 2b): the OZ-OVERRIDE-INDIRECTED
/// reachability case (Pods-class).
///
/// The cited vulnerable fn is the INTERNAL `_deposit` OVERRIDE. This file - the
/// CITED candidate source - does NOT declare a public `deposit()`; the public
/// `deposit(uint256,address)` entrypoint lives in the IMPORTED, out-of-cited-
/// file ERC4626 base and reaches the override via
///     deposit() -> _deposit() [base dispatch] -> _deposit override [here].
/// No body in THIS file literally calls `_deposit(`, so the textual-call wrapper
/// binder (steps 1-3) cannot bind it. The binder's OZ-override-indirected step
/// must recognize the ERC4626 inheritance + the `_deposit` override and bind the
/// canonical inherited public `deposit()` as the real entrypoint.
///
/// The inflation surface is the raw-balance `totalAssets()` override (donation
/// lever): a first depositor seeds 1 wei -> 1 share, donates assets directly to
/// inflate the live totalAssets() denominator, and a later victim deposit (which
/// flows public deposit -> base -> the overridden _deposit) rounds DOWN to ZERO
/// shares. No virtual offset / dead shares / min first deposit.
///
/// Bug class: first-depositor / share-price inflation (donation). GENERIC and
/// target-literal-free.
contract HookOverrideVault is ERC4626 {
    constructor(IERC20Like _asset)
        ERC4626(_asset, "Indirect Yield", "iyYLD")
    {}

    /// @dev raw-balance donation lever (no virtual offset / dead shares / min).
    function totalAssets() public view override returns (uint256) {
        return asset.balanceOf(address(this));
    }

    /// @dev the OVERRIDDEN internal _deposit hook. Reached ONLY through the
    /// inherited public deposit()/mint() via super-dispatch; no public body in
    /// THIS file calls `_deposit(` textually.
    function _deposit(
        address caller,
        address receiver,
        uint256 assets,
        uint256 shares
    ) internal override {
        require(
            asset.transferFrom(caller, address(this), assets),
            "transfer fail"
        );
        _mint(receiver, shares);
    }
}

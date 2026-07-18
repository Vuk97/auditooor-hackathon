// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice UNSEEN fixture for the COMMON-LIBRARY-vendoring lift. This vault
/// imports the well-known COMMON LIBRARY deps the converter must now resolve at
/// compile: solmate (`ERC20`, `SafeTransferLib`, `FixedPointMathLib`) and
/// OpenZeppelin (`Address`, via the bare `openzeppelin-contracts/` foundry
/// prefix). It is the exact common-library import SET a solmate-stack ERC4626
/// vault uses, modelled target-literal-free with deliberately different
/// identifiers (no real-target identity literal anywhere).
///
/// The bug shape is the donation / share-price-inflation (first-depositor) CLASS
/// the converter already routes: the vault reads a RAW live token balance as its
/// share-mint denominator (`totalAssets()` -> `asset.balanceOf(address(this))`),
/// and its `deposit()` mints shares via a rounding-DOWN integer division with NO
/// virtual-offset / dead-shares / minimum-first-deposit guard. A first depositor
/// seeds 1 wei -> 1 share, DONATES assets directly to the vault (raw transfer) to
/// inflate the live denominator, then a later victim deposit rounds DOWN to ZERO
/// shares (its assets stay in the pool, redeemable by the attacker's 1 share).
///
/// This fixture exists ONLY to prove the COMMON-LIBRARY vendoring works end to
/// end: it CANNOT compile unless solmate + OZ resolve. The vault's own share math
/// is pre-mitigation (silent round-to-zero) so the converter's existing
/// donation-inflation template drives + asserts it without modification. The
/// constructor takes a plain `address` asset (the converter's well-supported
/// single-asset deploy shape); the COMMON-LIBRARY symbols are exercised in the
/// vault body (solmate ERC20 share-token base + SafeTransferLib pull +
/// FixedPointMathLib + OZ Address), which is what the vendoring must resolve.

import {ERC20} from "solmate/tokens/ERC20.sol";
import {SafeTransferLib} from "solmate/utils/SafeTransferLib.sol";
import {FixedPointMathLib} from "solmate/utils/FixedPointMathLib.sol";
// bare `openzeppelin-contracts/` prefix (the foundry-install default used by the
// solmate stack) - the converter must remap this to the SAME OZ contracts/ root.
import {Address} from "openzeppelin-contracts/utils/Address.sol";

// minimal asset read-surface (balanceOf) - the donation denominator read.
interface IAssetLike {
    function balanceOf(address who) external view returns (uint256);
}

// The vault IS its own ERC20 share token (solmate ERC20 base provides
// `balanceOf` / `_mint` / `totalSupply`).
contract LibVault is ERC20 {
    using SafeTransferLib for ERC20;
    using FixedPointMathLib for uint256;
    using Address for address;

    address public immutable asset;

    constructor(address _asset)
        ERC20("Lib Yield Share", "lyYLD", 18)
    {
        asset = _asset;
    }

    /// @dev DONATION LEVER: reads the LIVE vault balance, so a raw transfer into
    /// the vault inflates it without minting shares -> share price inflates and a
    /// later victim deposit rounds DOWN to zero. No virtual offset.
    function totalAssets() public view returns (uint256) {
        return IAssetLike(asset).balanceOf(address(this));
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
        // real solmate SafeTransferLib pull (a COMMON-LIBRARY call site): cast the
        // asset address to the solmate ERC20 type the library extends.
        ERC20(asset).safeTransferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares_);
    }
}

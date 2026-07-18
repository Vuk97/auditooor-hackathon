// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice UNSEEN fixture (codex95 OBL2) for the constant-dep + ctor-time
/// external-call deploy shape that the iter17 share-inflation author missed.
///
/// This is the scLiquity-class convert gap, modelled target-literal-free with
/// deliberately different identifiers. The vault:
///   (1) takes the asset as its SINGLE constructor arg (so the iter17 single-
///       asset detector would have ACCEPTED it),
///   (2) but references a HARDCODED-CONSTANT external dependency address
///       (`yieldPool`) and CALLS A METHOD ON IT *INSIDE THE CONSTRUCTOR*
///       (`asset.approve(yieldPool, max)` + `yieldPool.register(...)`).
///
/// Because `yieldPool` is a fixed mainnet literal with no code under test, a
/// naive `new PoolVault(address(token))` deploy REVERTS in the constructor (the
/// call on an EOA-with-no-code yieldPool fails / returns garbage). The fix is to
/// vm.etch a synthesized mock at the constant address BEFORE deploy so the REAL
/// constructor's external calls succeed and the REAL deposit() entrypoint can be
/// driven to the donation/share-price-inflation impact.
///
/// Bug class: first-depositor / share-price inflation (donation). Root cause:
/// `convertToShares` uses the live `asset.balanceOf(address(this))` denominator,
/// inflatable by a raw donation, so a later victim deposit rounds DOWN to ZERO
/// shares. No virtual-offset / dead-shares mitigation is present.
contract PoolVault {
    IERC20 public immutable asset;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    /// @dev HARDCODED-CONSTANT external dependency the constructor calls into.
    /// A naive deploy reverts here because the literal address has no code.
    IYieldPool public constant yieldPool =
        IYieldPool(0x9999999999999999999999999999999999999999);

    constructor(address _asset) {
        asset = IERC20(_asset);
        // CTOR-TIME EXTERNAL CALLS on the constant dep: these revert under a
        // naive deploy because `yieldPool` (a fixed literal) has no code.
        asset.approve(address(yieldPool), type(uint256).max);
        yieldPool.register(address(this));
    }

    /// @dev DENOMINATOR uses the live vault balance -> inflatable by donation.
    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalShares;
        if (supply == 0) {
            return assets;
        }
        uint256 totalAssets = asset.balanceOf(address(this));
        return (assets * supply) / totalAssets;
    }

    function convertToAssets(uint256 shareAmount) public view returns (uint256) {
        uint256 supply = totalShares;
        if (supply == 0) {
            return shareAmount;
        }
        uint256 totalAssets = asset.balanceOf(address(this));
        return (shareAmount * totalAssets) / supply;
    }

    /// @notice REAL entrypoint the harness drives.
    function deposit(uint256 assets, address receiver) external returns (uint256 mintedShares) {
        mintedShares = convertToShares(assets);
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer fail");
        totalShares += mintedShares;
        shares[receiver] += mintedShares;
    }

    function redeem(uint256 shareAmount, address receiver) external returns (uint256 assetsOut) {
        assetsOut = convertToAssets(shareAmount);
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        require(asset.transfer(receiver, assetsOut), "transfer fail");
    }
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

interface IYieldPool {
    function register(address vault) external;
}

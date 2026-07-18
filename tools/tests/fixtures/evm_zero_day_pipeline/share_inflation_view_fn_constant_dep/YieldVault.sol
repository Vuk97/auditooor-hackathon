// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice UNSEEN fixture (GAP B) for the const-dep-READ-IN-VIEW-FN surface the
/// obl2 ctor-only etch path missed.
///
/// This is the `C.stabilityPool` / `C.usd2eth`-style constant-dependency shape,
/// modelled target-literal-free with deliberately different identifiers. Unlike
/// PoolVault.sol (obl2), the hardcoded-constant dependency is NOT a constructor
/// arg and is NOT touched in the constructor. Instead the vault:
///   (1) takes the asset as its SINGLE constructor arg (so the single-asset
///       detector ACCEPTS it) and the constructor touches NO external dep, so
///       `new YieldVault(asset)` deploys cleanly, but
///   (2) reads a HARDCODED-CONSTANT external dependency address (`stabilityPool`)
///       INSIDE the exploited `totalAssets()` view fn body
///       (`stabilityPool.deposited(address(this))`).
///
/// Because `stabilityPool` is a fixed mainnet literal with no code under test,
/// the deploy succeeds but the FIRST `deposit()` / `totalAssets()` call REVERTS
/// reading the un-etched constant address. The obl2 ctor-relevance check skips
/// `stabilityPool` (it never appears in the ctor body), so the exploit reverts.
/// The fix (GAP B) extends the same etch machinery to const deps READ in the
/// exploited share-price view fn: synthesize a permissive-fallback mock and
/// vm.etch it at the constant address in setUp BEFORE deploy, so the REAL
/// totalAssets() read succeeds (returns 0 from the safe-default mock) and the
/// REAL deposit() entrypoint drives the donation/share-price-inflation impact.
///
/// Bug class: first-depositor / share-price inflation (donation). Root cause:
/// `convertToShares` divides by the live `totalAssets()` which includes the raw
/// `asset.balanceOf(address(this))` term, inflatable by a raw donation, so a
/// later victim deposit rounds DOWN to ZERO shares. No virtual-offset /
/// dead-shares mitigation is present.
contract YieldVault {
    IERC20 public immutable asset;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    /// @dev HARDCODED-CONSTANT external dependency read ONLY inside totalAssets()
    /// (NOT a ctor arg, NOT touched in the constructor). A naive deploy succeeds,
    /// but the first totalAssets() read reverts because the literal has no code.
    IStabilityPool public constant stabilityPool =
        IStabilityPool(0x7777777777777777777777777777777777777777);

    constructor(address _asset) {
        // No external dep is touched here: deploy is clean. The const dep only
        // surfaces inside the exploited view fn below.
        asset = IERC20(_asset);
    }

    /// @dev DENOMINATOR = local balance + assets parked in the external pool.
    /// The const dep is READ HERE (the view-fn-relevant case GAP B handles). The
    /// local `asset.balanceOf(this)` term is donation-inflatable.
    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this))
            + stabilityPool.deposited(address(this));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalShares;
        if (supply == 0) {
            return assets;
        }
        return (assets * supply) / totalAssets();
    }

    function convertToAssets(uint256 shareAmount) public view returns (uint256) {
        uint256 supply = totalShares;
        if (supply == 0) {
            return shareAmount;
        }
        return (shareAmount * totalAssets()) / supply;
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

interface IStabilityPool {
    function deposited(address vault) external view returns (uint256);
}

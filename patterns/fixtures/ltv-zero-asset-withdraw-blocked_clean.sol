// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
///
/// Every LTV-dependent entry branches on `ltv == 0` (or equivalently
/// `ltv != 0` / `ltv > 0`) and falls back to a policy that preserves the
/// Aave semantics: `pure supply` is withdrawable, borrow is denied, and
/// liquidation defers to the upstream `getUserAccountData` view.
///
/// Because every matching function body contains a zero-LTV guard, the
/// negative predicate `body_not_contains_regex` evaluates to true and
/// the detector does not fire.

interface ILendingPool {
    struct ReserveConfigurationMap { uint256 data; }
    struct ReserveData {
        ReserveConfigurationMap configuration;
        uint128 liquidityIndex;
    }
    function getReserveData(address asset) external view returns (ReserveData memory);
    function getUserAccountData(address user) external view returns (
        uint256 totalCollateral, uint256 totalDebt,
        uint256 availableBorrow, uint256 ltv,
        uint256 currentLiquidationThreshold, uint256 healthFactor
    );
}

contract LtvZeroAssetWithdrawBlockedClean {
    ILendingPool public pool;
    address public aave;
    mapping(address => uint256) public userCollateral;
    mapping(address => uint256) public userDebt;

    constructor(ILendingPool _pool, address _aave) {
        pool = _pool;
        aave = _aave;
    }

    function healthFactor(address user, address asset) public view returns (uint256) {
        ILendingPool.ReserveData memory d = pool.getReserveData(asset);
        uint256 ltv = d.configuration.data & 0xffff;
        uint256 coll = userCollateral[user];
        uint256 debt = userDebt[user];
        if (debt == 0) return type(uint256).max;
        // CLEAN: explicit `if (ltv == 0)` branch.
        if (ltv == 0) {
            // Pure-supply semantics: treat the asset as contributing zero
            // weighted collateral but let the caller drive the rest of
            // the solvency check from the upstream pool view.
            (, , , , , uint256 upstreamHf) = pool.getUserAccountData(user);
            return upstreamHf;
        }
        return (coll * ltv * 1e18) / (debt * 10000);
    }

    // CLEAN: withdraw. Reads LTV but explicitly guards `ltv == 0`, so
    // `body_not_contains_regex` is satisfied and the detector skips.
    function withdraw(address asset, uint256 amount) external {
        ILendingPool.ReserveData memory d = pool.getReserveData(asset);
        uint256 ltv = d.configuration.data & 0xffff;
        if (ltv == 0) {
            // Pure supply remains withdrawable even when the asset is
            // turned off as collateral.
            userCollateral[msg.sender] -= amount;
            return;
        }
        uint256 hf = (userCollateral[msg.sender] * ltv * 1e18)
            / (userDebt[msg.sender] * 10000 + 1);
        require(hf >= 1e18, "unhealthy");
        userCollateral[msg.sender] -= amount;
    }

    // CLEAN: borrow. Rejects when ltv == 0 (asset not usable as
    // collateral); does not divide by zero.
    function borrow(address asset, uint256 amount) external {
        ILendingPool.ReserveData memory d = pool.getReserveData(asset);
        uint256 ltv = d.configuration.data & 0xffff;
        require(ltv != 0, "asset not collateral");
        uint256 newDebt = userDebt[msg.sender] + amount;
        uint256 maxBorrow = (userCollateral[msg.sender] * ltv) / 10000;
        require(newDebt <= maxBorrow, "over LTV");
        userDebt[msg.sender] = newDebt;
    }

    // CLEAN: liquidate. Falls back to the upstream protocol's
    // `getUserAccountData` when the asset is disabled as collateral,
    // matching Aave's own GenericLogic handling.
    function liquidate(address user, address asset, uint256 repay) external {
        ILendingPool.ReserveData memory d = pool.getReserveData(asset);
        uint256 ltv = d.configuration.data & 0xffff;
        uint256 hf;
        if (ltv > 0) {
            hf = (userCollateral[user] * ltv * 1e18) / (userDebt[user] * 10000 + 1);
        } else {
            (, , , , , hf) = pool.getUserAccountData(user);
        }
        require(hf < 1e18, "not liquidatable");
        userDebt[user] -= repay;
    }
}

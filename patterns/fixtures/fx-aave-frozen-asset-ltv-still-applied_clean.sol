// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

// Fixture: fixed — frozen reserve gets ltv=0 in active config, pending stores intended value.
// Source: aave-dao/aave-v3-origin@d13aef0 (Cantina-31 fix)

contract PoolConfigurator {
    mapping(address => uint256) private _pendingLtv;
    mapping(address => uint256) private _ltv;
    mapping(address => bool) private _frozen;

    event PendingLtvChanged(address asset, uint256 ltv);
    event CollateralConfigurationChanged(address asset, uint256 ltv, uint256 threshold, uint256 bonus);

    // FIXED: frozen assets get ltv=0 in active config; intended ltv stored as pending
    function configureReserveAsCollateral(
        address asset,
        uint256 ltv,
        uint256 liquidationThreshold,
        uint256 liquidationBonus
    ) external {
        uint256 newLtv = ltv;

        if (_frozen[asset]) {
            _pendingLtv[asset] = ltv;
            newLtv = 0;
            emit PendingLtvChanged(asset, ltv);
        } else {
            _ltv[asset] = ltv;
        }

        emit CollateralConfigurationChanged(asset, newLtv, liquidationThreshold, liquidationBonus);
    }
}

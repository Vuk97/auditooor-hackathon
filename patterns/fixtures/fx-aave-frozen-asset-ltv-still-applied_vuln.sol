// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

// Fixture: vulnerable — frozen reserve still gets non-zero LTV applied.
// Source: aave-dao/aave-v3-origin@d13aef0 (Cantina-31 fix)

contract PoolConfigurator {
    mapping(address => uint256) private _pendingLtv;
    mapping(address => uint256) private _ltv;
    mapping(address => bool) private _frozen;

    event PendingLtvChanged(address asset, uint256 ltv);
    event CollateralConfigurationChanged(address asset, uint256 ltv, uint256 threshold, uint256 bonus);

    // VULNERABLE: setLtv called unconditionally even when frozen
    function configureReserveAsCollateral(
        address asset,
        uint256 ltv,
        uint256 liquidationThreshold,
        uint256 liquidationBonus
    ) external {
        if (_frozen[asset]) {
            _pendingLtv[asset] = ltv;
            emit PendingLtvChanged(asset, ltv);
        }

        // BUG: setLtv called regardless of frozen status
        _ltv[asset] = ltv;

        emit CollateralConfigurationChanged(asset, ltv, liquidationThreshold, liquidationBonus);
    }
}

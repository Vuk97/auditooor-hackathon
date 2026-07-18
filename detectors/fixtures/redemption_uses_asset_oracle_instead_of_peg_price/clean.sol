// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOracle {
    function getPrice(address asset) external view returns (uint256);
}

contract RedemptionAssetOracleInsteadOfPegClean {
    uint256 internal constant ONE_USD = 1e18;
    IOracle public immutable oracle;
    address public immutable collateral;

    constructor(IOracle oracle_, address collateral_) {
        oracle = oracle_;
        collateral = collateral_;
    }

    function redeemCollateral(uint256 stableAmount) external view returns (uint256 collateralOut) {
        uint256 collateralUsd = oracle.getPrice(collateral);
        collateralOut = (stableAmount * ONE_USD) / collateralUsd;
    }
}

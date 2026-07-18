// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOracle {
    function getPrice(address asset) external view returns (uint256);
}

contract RedemptionAssetOracleInsteadOfPegPositive {
    IOracle public immutable oracle;
    address public immutable dUSD;
    address public immutable collateral;
    uint256 public lastRedemptionQuote;

    constructor(IOracle oracle_, address dUSD_, address collateral_) {
        oracle = oracle_;
        dUSD = dUSD_;
        collateral = collateral_;
    }

    function getOraclePrice(address asset) public view returns (uint256) {
        return oracle.getPrice(asset);
    }

    function proposeRedemption(uint256 stableAmount) external returns (uint256 collateralOut) {
        uint256 stableUsd = getOraclePrice(dUSD);
        collateralOut = (stableAmount * stableUsd) / oracle.getPrice(collateral);
        lastRedemptionQuote = collateralOut;
    }
}

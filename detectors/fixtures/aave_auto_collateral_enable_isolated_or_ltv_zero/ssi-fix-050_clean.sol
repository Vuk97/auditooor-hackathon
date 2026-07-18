// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library ReserveConfiguration {
    function getLtv(AaveAutoCollateralEnableClean.ReserveConfig memory reserveConfig)
        internal
        pure
        returns (uint256)
    {
        return reserveConfig.ltv;
    }
}

contract AaveAutoCollateralEnableClean {
    using ReserveConfiguration for ReserveConfig;

    bytes32 internal constant ISOLATED_COLLATERAL_SUPPLIER = keccak256("ISOLATED_COLLATERAL_SUPPLIER");

    struct ReserveConfig {
        uint256 ltv;
        uint256 debtCeiling;
    }

    struct ReserveData {
        uint256 id;
        ReserveConfig configuration;
    }

    mapping(address => mapping(uint256 => bool)) public collateralUsage;

    function executeSupply(ReserveData memory reserve, address onBehalfOf, bool isFirstSupply) public {
        if (isFirstSupply && validateAutomaticUseAsCollateral(reserve.configuration, onBehalfOf)) {
            setUsingAsCollateral(reserve.id, true);
            collateralUsage[onBehalfOf][reserve.id] = true;
        }
    }

    function validateAutomaticUseAsCollateral(ReserveConfig memory reserveConfig, address supplier)
        public
        pure
        returns (bool)
    {
        if (reserveConfig.getLtv() == 0) {
            return false;
        }
        if (reserveConfig.debtCeiling != 0 && supplier == address(0)) {
            return false;
        }
        return true;
    }

    function setUsingAsCollateral(uint256 reserveId, bool useAsCollateral) public {
        collateralUsage[msg.sender][reserveId] = useAsCollateral;
    }
}

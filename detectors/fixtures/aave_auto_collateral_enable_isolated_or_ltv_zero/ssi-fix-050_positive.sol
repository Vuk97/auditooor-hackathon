// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AaveAutoCollateralEnablePositive {
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
        if (isFirstSupply) {
            setUsingAsCollateral(reserve.id, true);
            collateralUsage[onBehalfOf][reserve.id] = true;
        }
    }

    function setUsingAsCollateral(uint256 reserveId, bool useAsCollateral) public {
        collateralUsage[msg.sender][reserveId] = useAsCollateral;
    }
}

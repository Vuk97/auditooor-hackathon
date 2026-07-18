// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract PerpLiquidationEnginePositive {
    uint256 public maintenanceMargin;
    mapping(address => uint256) internal marginRateByAccount;

    constructor() {
        maintenanceMargin = 500;
    }

    function setMarginRate(address account, uint256 nextMarginRate) external {
        marginRateByAccount[account] = nextMarginRate;
    }

    function getMarginRate(address account) public view returns (uint256) {
        return marginRateByAccount[account];
    }

    function maintenanceMarginRate(address) public view returns (uint256) {
        return maintenanceMargin;
    }

    function liquidate(address account) external returns (bool) {
        require(
            getMarginRate(account) >= maintenanceMarginRate(account),
            "MarginUnsafe"
        );
        return true;
    }
}

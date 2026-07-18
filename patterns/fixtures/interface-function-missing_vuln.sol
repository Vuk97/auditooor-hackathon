// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStakingRouter {
    function getStakingModuleSummary(uint256) external view returns (uint256);
}

contract InterfaceFunctionMissingVuln {
    address public router;

    function setRouter(address r) external {
        router = r;
    }

    function accrue(uint256 id) external returns (uint256) {
        uint256 summary = IStakingRouter(router).getStakingModuleSummary(id);
        return summary + 1;
    }
}

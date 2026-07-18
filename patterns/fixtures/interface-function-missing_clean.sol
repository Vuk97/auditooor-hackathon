// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStakingRouter {
    function getStakingModuleSummary(uint256) external view returns (uint256);
}

contract InterfaceFunctionMissingClean {
    address public router;

    function setRouter(address r) external {
        router = r;
    }

    function accrue(uint256 id) external returns (uint256) {
        try IStakingRouter(router).getStakingModuleSummary(id) returns (uint256 s) {
            return s + 1;
        } catch {
            return 0;
        }
    }
}

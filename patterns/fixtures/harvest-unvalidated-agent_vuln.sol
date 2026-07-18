// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAgent { function harvest() external returns (uint256); }

contract StrategyVuln {
    function harvest(address agent) external returns (uint256 profit) {
        // VULN: no whitelist check
        (bool ok, bytes memory data) = agent.call(abi.encodeWithSignature("harvest()"));
        require(ok);
        profit = abi.decode(data, (uint256));
    }
}

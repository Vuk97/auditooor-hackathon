// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StrategyClean {
    mapping(address => bool) public isAgent;

    function harvest(address agent) external returns (uint256 profit) {
        require(isAgent[agent], "not an agent");
        (bool ok, bytes memory data) = agent.call(abi.encodeWithSignature("harvest()"));
        require(ok);
        profit = abi.decode(data, (uint256));
    }
}

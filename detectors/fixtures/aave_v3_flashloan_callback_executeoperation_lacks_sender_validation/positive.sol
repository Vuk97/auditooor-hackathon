// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Positive {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract AaveV3ExecuteOperationMissingSenderValidationPositive {
    address public immutable POOL;

    constructor(address pool) {
        POOL = pool;
    }

    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        premiums;
        initiator;
        params;
        IERC20Positive(assets[0]).transfer(msg.sender, amounts[0]);
        return true;
    }
}

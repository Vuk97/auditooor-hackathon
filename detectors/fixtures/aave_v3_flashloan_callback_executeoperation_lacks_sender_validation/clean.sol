// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Clean {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract AaveV3ExecuteOperationSenderValidationClean {
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
        require(msg.sender == POOL, "caller not pool");
        IERC20Clean(assets[0]).transfer(POOL, amounts[0]);
        return true;
    }
}

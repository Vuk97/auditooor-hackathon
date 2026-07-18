// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20FlashloanCallbackClean {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract FlashloanCallbackMissingCallerValidationClean {
    address public immutable POOL;
    uint256 public lastAmount;

    constructor(address pool) {
        POOL = pool;
    }

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 fee,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        initiator;
        params;
        require(msg.sender == POOL, "caller not pool");
        lastAmount = amount + fee;
        IERC20FlashloanCallbackClean(asset).transfer(POOL, amount);
        return true;
    }
}
